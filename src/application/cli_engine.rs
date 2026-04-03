use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;

use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::application::credential_resolver::{CredentialResolver, RegistryCredentials};
use crate::application::semantic_gate::{SemanticDecision, SemanticGate};
use crate::domain::{CredentialResolutionPath, EphemeralCliToolRepository, GatewayEvent};
use crate::infrastructure::config::GatewayConfig;
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::persistence::EventStore;

#[derive(Clone)]
pub struct CliEngine {
    cli_tools: Arc<dyn EphemeralCliToolRepository>,
    credential_resolver: CredentialResolver,
    semantic_gate: SemanticGate,
    event_store: Arc<dyn EventStore>,
    container_cli: String,
    nfs_server_host: String,
    nfs_port: u16,
    nfs_mount_port: u16,
}

pub struct CliInvocation {
    pub execution_id: String,
    pub security_context: String,
    pub tool_name: String,
    pub command: String,
    pub args: Vec<String>,
    pub fsal_mounts: Vec<CliFsalMount>,
    pub tenant_id: Option<String>,
    pub zaru_user_token: Option<String>,
    pub allow_human_delegated_credentials: bool,
}

#[derive(Clone, Debug)]
pub struct CliFsalMount {
    pub volume_id: String,
    pub mount_path: String,
    pub read_only: bool,
}

impl CliEngine {
    pub fn new(
        cli_tools: Arc<dyn EphemeralCliToolRepository>,
        credential_resolver: CredentialResolver,
        semantic_gate: SemanticGate,
        event_store: Arc<dyn EventStore>,
        config: GatewayConfig,
    ) -> Self {
        Self {
            cli_tools,
            credential_resolver,
            semantic_gate,
            event_store,
            container_cli: config.container_cli,
            nfs_server_host: config.nfs_server_host,
            nfs_port: config.nfs_port,
            nfs_mount_port: config.nfs_mount_port,
        }
    }

    pub async fn invoke(
        &self,
        invocation: CliInvocation,
    ) -> Result<serde_json::Value, GatewayError> {
        let tool = self
            .cli_tools
            .find_by_name(&invocation.tool_name)
            .await?
            .ok_or_else(|| GatewayError::NotFound("CLI tool not found".to_string()))?;

        match self
            .semantic_gate
            .evaluate(
                &tool,
                &invocation.command,
                &invocation.args,
                &invocation.security_context,
            )
            .await?
        {
            SemanticDecision::Rejected(reason) => {
                self.event_store
                    .append_event(
                        "CliToolSemanticRejected",
                        &serde_json::to_value(GatewayEvent::CliToolSemanticRejected {
                            execution_id: invocation.execution_id,
                            tool_name: tool.name,
                            requested_subcommand: invocation.command,
                            rejection_reason: reason.clone(),
                            security_context: invocation.security_context,
                            rejected_at: chrono::Utc::now(),
                        })?,
                    )
                    .await?;
                return Err(GatewayError::Forbidden);
            }
            SemanticDecision::Allowed => {}
        }

        let registry_for_logout = if let Some(path) = &tool.registry_credential_path {
            let resolution_path_label = credential_path_label(path);
            let target_service = credential_path_target_service(path);
            let creds = match self
                .credential_resolver
                .resolve_registry_credentials(
                    path,
                    invocation.zaru_user_token.as_deref(),
                    invocation.allow_human_delegated_credentials,
                )
                .await
            {
                Ok(credentials) => {
                    self.event_store
                        .append_event(
                            "CredentialExchangeCompleted",
                            &serde_json::to_value(GatewayEvent::CredentialExchangeCompleted {
                                execution_id: invocation.execution_id.clone(),
                                resolution_path: resolution_path_label.to_string(),
                                target_service: target_service.to_string(),
                                completed_at: chrono::Utc::now(),
                            })?,
                        )
                        .await?;
                    credentials
                }
                Err(err) => {
                    self.event_store
                        .append_event(
                            "CredentialExchangeFailed",
                            &serde_json::to_value(GatewayEvent::CredentialExchangeFailed {
                                execution_id: invocation.execution_id.clone(),
                                resolution_path: resolution_path_label.to_string(),
                                reason: err.to_string(),
                                failed_at: chrono::Utc::now(),
                            })?,
                        )
                        .await?;
                    return Err(err);
                }
            };

            container_login(&self.container_cli, &creds).await?;
            Some(creds.registry)
        } else {
            None
        };

        self.event_store
            .append_event(
                "CliToolInvocationStarted",
                &serde_json::to_value(GatewayEvent::CliToolInvocationStarted {
                    execution_id: invocation.execution_id.clone(),
                    tool_name: tool.name.clone(),
                    docker_image: tool.docker_image.clone(),
                    command: invocation.command.clone(),
                    args: invocation.args.clone(),
                    tenant_id: invocation.tenant_id.clone(),
                    started_at: chrono::Utc::now(),
                })?,
            )
            .await?;

        let mut cmd = Command::new(&self.container_cli);
        cmd.arg("run")
            .arg("--rm")
            .arg("--network")
            .arg("none")
            .arg("--read-only")
            .arg("--security-opt")
            .arg("no-new-privileges")
            .arg("--cap-drop")
            .arg("ALL");
        if invocation.fsal_mounts.is_empty() {
            return Err(GatewayError::Validation(
                "CLI invocation requires at least one fsal mount".to_string(),
            ));
        }
        for mount in &invocation.fsal_mounts {
            let volume_source = sanitize_volume_name(
                &format!("aegis-cli-{}-{}", invocation.execution_id, mount.volume_id),
                "aegis-cli-workspace",
            );
            let readonly_suffix = if mount.read_only { ",ro" } else { "" };
            cmd.arg("--mount").arg(format!(
                "type=volume,src={volume_source},dst={},volume-driver=local,volume-opt=type=nfs,volume-opt=o=addr={},nfsvers=3,proto=tcp,port={},mountport={},soft,timeo=10,nolock{},volume-opt=device=:/{}/{}",
                mount.mount_path,
                self.nfs_server_host,
                self.nfs_port,
                self.nfs_mount_port,
                readonly_suffix,
                invocation.execution_id,
                mount.volume_id
            ));
        }
        cmd.arg("-w").arg("/workspace");

        cmd.arg(&tool.docker_image)
            .arg(&invocation.command)
            .args(&invocation.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let start = Instant::now();
        let mut child = cmd
            .spawn()
            .map_err(|e| GatewayError::Internal(format!("failed to spawn container cli: {e}")))?;

        let timeout = std::time::Duration::from_secs(tool.default_timeout_seconds as u64);
        let run_output = tokio::time::timeout(timeout, async move {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut out) = child.stdout.take() {
                let _ = out.read_to_end(&mut stdout).await;
            }
            if let Some(mut err) = child.stderr.take() {
                let _ = err.read_to_end(&mut stderr).await;
            }
            let status = child.wait().await;
            (stdout, stderr, status)
        })
        .await
        .map_err(|_| GatewayError::Internal("cli invocation timeout".to_string()))?;

        if let Some(registry) = registry_for_logout.as_deref() {
            if let Err(err) = container_logout(&self.container_cli, registry).await {
                tracing::warn!(
                    "container logout failed for registry '{}': {}",
                    registry,
                    err
                );
            }
        }

        let (mut stdout, mut stderr, status_res) = run_output;
        if stdout.len() > 1_048_576 {
            stdout.truncate(1_048_576);
        }
        if stderr.len() > 1_048_576 {
            stderr.truncate(1_048_576);
        }

        let status = status_res
            .map_err(|e| GatewayError::Internal(format!("failed to wait process: {e}")))?;
        let code = status.code().unwrap_or(-1);

        self.event_store
            .append_event(
                "CliToolInvocationCompleted",
                &serde_json::to_value(GatewayEvent::CliToolInvocationCompleted {
                    execution_id: invocation.execution_id,
                    tool_name: tool.name,
                    exit_code: code,
                    stdout_bytes: stdout.len(),
                    stderr_bytes: stderr.len(),
                    duration_ms: start.elapsed().as_millis() as u64,
                    completed_at: chrono::Utc::now(),
                })?,
            )
            .await?;

        Ok(json!({
            "exit_code": code,
            "stdout": String::from_utf8_lossy(&stdout).to_string(),
            "stderr": String::from_utf8_lossy(&stderr).to_string()
        }))
    }
}

fn credential_path_label(path: &CredentialResolutionPath) -> &'static str {
    match path {
        CredentialResolutionPath::SystemJit { .. } => "system_jit",
        CredentialResolutionPath::HumanDelegated { .. } => "human_delegated",
        CredentialResolutionPath::Auto { .. } => "auto",
        CredentialResolutionPath::StaticRef(_) => "static_ref",
    }
}

fn credential_path_target_service(path: &CredentialResolutionPath) -> &str {
    match path {
        CredentialResolutionPath::HumanDelegated { target_service }
        | CredentialResolutionPath::Auto { target_service, .. } => target_service,
        _ => "container_registry",
    }
}

fn sanitize_volume_name(candidate: &str, fallback: &str) -> String {
    let mut value = candidate
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    if value.is_empty() {
        value = fallback.to_string();
    }
    value
}

async fn container_login(
    container_cli: &str,
    credentials: &RegistryCredentials,
) -> Result<(), GatewayError> {
    let mut cmd = Command::new(container_cli);
    cmd.arg("login")
        .arg(&credentials.registry)
        .arg("--username")
        .arg(credentials.username.expose())
        .arg("--password-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| GatewayError::Internal(format!("failed to spawn container login: {e}")))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(credentials.password.expose().as_bytes())
            .await
            .map_err(|e| {
                GatewayError::Internal(format!("failed to write container login stdin: {e}"))
            })?;
        stdin.write_all(b"\n").await.map_err(|e| {
            GatewayError::Internal(format!("failed to finalize container login stdin: {e}"))
        })?;
    } else {
        return Err(GatewayError::Internal(
            "container login stdin unavailable".to_string(),
        ));
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| GatewayError::Internal(format!("failed to wait container login: {e}")))?;
    if !output.status.success() {
        return Err(GatewayError::Internal(format!(
            "container login failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

async fn container_logout(container_cli: &str, registry: &str) -> Result<(), GatewayError> {
    let output = Command::new(container_cli)
        .arg("logout")
        .arg(registry)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| GatewayError::Internal(format!("failed to spawn container logout: {e}")))?;
    if !output.status.success() {
        return Err(GatewayError::Internal(format!(
            "container logout failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    use crate::domain::{
        CredentialResolutionPath, EphemeralCliTool, EphemeralCliToolRepository,
        EphemeralCliToolSummary,
    };
    use crate::infrastructure::persistence::EventStore;

    #[derive(Default)]
    struct InMemoryCliToolRepo {
        tools: RwLock<HashMap<String, EphemeralCliTool>>,
    }

    #[async_trait]
    impl EphemeralCliToolRepository for InMemoryCliToolRepo {
        async fn save(&self, tool: EphemeralCliTool) -> Result<(), GatewayError> {
            self.tools.write().await.insert(tool.name.clone(), tool);
            Ok(())
        }

        async fn find_by_name(&self, name: &str) -> Result<Option<EphemeralCliTool>, GatewayError> {
            Ok(self.tools.read().await.get(name).cloned())
        }

        async fn list_all(&self) -> Result<Vec<EphemeralCliToolSummary>, GatewayError> {
            Ok(self
                .tools
                .read()
                .await
                .values()
                .map(|tool| EphemeralCliToolSummary {
                    name: tool.name.clone(),
                    description: tool.description.clone(),
                    docker_image: tool.docker_image.clone(),
                    allowed_subcommands: tool.allowed_subcommands.clone(),
                    require_semantic_judge: tool.require_semantic_judge,
                })
                .collect())
        }

        async fn delete(&self, name: &str) -> Result<(), GatewayError> {
            self.tools.write().await.remove(name);
            Ok(())
        }
    }

    struct NoopEventStore;

    #[async_trait]
    impl EventStore for NoopEventStore {
        async fn append_event(
            &self,
            _event_type: &str,
            _payload: &serde_json::Value,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
    }

    fn test_config() -> GatewayConfig {
        GatewayConfig {
            bind_addr: "127.0.0.1:8089".to_string(),
            grpc_bind_addr: "127.0.0.1:50055".to_string(),
            database_url: "sqlite::memory:".to_string(),
            operator_jwt_public_key_pem: String::new(),
            operator_jwt_issuer: "issuer".to_string(),
            operator_jwt_audience: "audience".to_string(),
            auth_disabled: true,
            seal_jwt_public_key_pem: String::new(),
            seal_jwt_issuer: "seal-issuer".to_string(),
            seal_jwt_audience: "seal-audience".to_string(),
            openbao_addr: None,
            openbao_token: None,
            openbao_kv_mount: "secret".to_string(),
            keycloak_token_exchange_url: None,
            keycloak_client_id: None,
            keycloak_client_secret: None,
            semantic_judge_url: None,
            ui_enabled: true,
            container_cli: "docker".to_string(),
            nfs_server_host: "127.0.0.1".to_string(),
            nfs_port: 2049,
            nfs_mount_port: 20048,
        }
    }

    #[tokio::test]
    async fn cli_registry_human_delegated_rejected_without_context_capability() {
        let repo = Arc::new(InMemoryCliToolRepo::default());
        repo.save(EphemeralCliTool {
            name: "terraform".to_string(),
            description: "infra cli".to_string(),
            docker_image: "mcp/terraform:1.9".to_string(),
            allowed_subcommands: vec!["plan".to_string()],
            require_semantic_judge: false,
            default_timeout_seconds: 30,
            registry_credential_path: Some(CredentialResolutionPath::HumanDelegated {
                target_service: "ghcr.io".to_string(),
            }),
        })
        .await
        .expect("seed tool");

        let engine = CliEngine::new(
            repo,
            CredentialResolver::new(test_config()),
            SemanticGate::new(None),
            Arc::new(NoopEventStore),
            test_config(),
        );

        let result = engine
            .invoke(CliInvocation {
                execution_id: "exec-1".to_string(),
                security_context: "zaru-free".to_string(),
                tool_name: "terraform".to_string(),
                command: "plan".to_string(),
                args: vec![],
                fsal_mounts: vec![CliFsalMount {
                    volume_id: "vol-1".to_string(),
                    mount_path: "/workspace".to_string(),
                    read_only: false,
                }],
                zaru_user_token: Some("user-token".to_string()),
                allow_human_delegated_credentials: false,
            })
            .await;

        assert!(matches!(result, Err(GatewayError::Forbidden)));
    }
}
