use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;

use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::application::credential_resolver::{CredentialResolver, RegistryCredentials};
use crate::application::semantic_gate::{SemanticDecision, SemanticGate};
use crate::domain::{EphemeralCliToolRepository, GatewayEvent};
use crate::infrastructure::config::GatewayConfig;
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::persistence::EventStore;

#[derive(Clone)]
pub struct CliEngine {
    cli_tools: Arc<dyn EphemeralCliToolRepository>,
    credential_resolver: CredentialResolver,
    semantic_gate: SemanticGate,
    event_store: Arc<dyn EventStore>,
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
    pub fsal_volume_id: String,
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

        let registry_for_logout = if let Some(registry_ref) = &tool.registry_credentials_ref {
            let creds = match self
                .credential_resolver
                .resolve_registry_credentials(registry_ref)
                .await
            {
                Ok(credentials) => {
                    self.event_store
                        .append_event(
                            "CredentialExchangeCompleted",
                            &serde_json::to_value(GatewayEvent::CredentialExchangeCompleted {
                                execution_id: invocation.execution_id.clone(),
                                resolution_path: "static_ref".to_string(),
                                target_service: "container_registry".to_string(),
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
                                resolution_path: "static_ref".to_string(),
                                reason: err.to_string(),
                                failed_at: chrono::Utc::now(),
                            })?,
                        )
                        .await?;
                    return Err(err);
                }
            };

            docker_login(&creds).await?;
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
                    started_at: chrono::Utc::now(),
                })?,
            )
            .await?;

        let mut cmd = Command::new("docker");
        cmd.arg("run")
            .arg("--rm")
            .arg("--network")
            .arg("none")
            .arg("--read-only")
            .arg("--security-opt")
            .arg("no-new-privileges")
            .arg("--cap-drop")
            .arg("ALL");
        let volume_source = sanitize_volume_name(
            &format!(
                "aegis-cli-{}-{}",
                invocation.execution_id, invocation.fsal_volume_id
            ),
            "aegis-cli-workspace",
        );
        cmd.arg("--mount")
            .arg(format!(
                "type=volume,src={volume_source},dst=/workspace,volume-driver=local,volume-opt=type=nfs,volume-opt=o=addr={},nfsvers=3,proto=tcp,port={},mountport={},soft,timeo=10,nolock,volume-opt=device=:/{}/{}",
                self.nfs_server_host,
                self.nfs_port,
                self.nfs_mount_port,
                invocation.execution_id,
                invocation.fsal_volume_id
            ))
            .arg("-w")
            .arg("/workspace");

        cmd.arg(&tool.docker_image)
            .arg(&invocation.command)
            .args(&invocation.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let start = Instant::now();
        let mut child = cmd
            .spawn()
            .map_err(|e| GatewayError::Internal(format!("failed to spawn docker: {e}")))?;

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
            if let Err(err) = docker_logout(registry).await {
                tracing::warn!("docker logout failed for registry '{}': {}", registry, err);
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

async fn docker_login(credentials: &RegistryCredentials) -> Result<(), GatewayError> {
    let mut cmd = Command::new("docker");
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
        .map_err(|e| GatewayError::Internal(format!("failed to spawn docker login: {e}")))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(credentials.password.expose().as_bytes())
            .await
            .map_err(|e| {
                GatewayError::Internal(format!("failed to write docker login stdin: {e}"))
            })?;
        stdin.write_all(b"\n").await.map_err(|e| {
            GatewayError::Internal(format!("failed to finalize docker login stdin: {e}"))
        })?;
    } else {
        return Err(GatewayError::Internal(
            "docker login stdin unavailable".to_string(),
        ));
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| GatewayError::Internal(format!("failed to wait docker login: {e}")))?;
    if !output.status.success() {
        return Err(GatewayError::Internal(format!(
            "docker login failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

async fn docker_logout(registry: &str) -> Result<(), GatewayError> {
    let output = Command::new("docker")
        .arg("logout")
        .arg(registry)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| GatewayError::Internal(format!("failed to spawn docker logout: {e}")))?;
    if !output.status.success() {
        return Err(GatewayError::Internal(format!(
            "docker logout failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}
