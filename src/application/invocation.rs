use std::sync::Arc;

use base64::Engine;
use serde_json::Value;

use crate::application::{
    CliEngine, CliFsalMount, CliInvocation, NativeToolEngine, WorkflowEngine,
};
use crate::domain::SealEnvelope;
use crate::domain::{
    EphemeralCliToolRepository, JtiRepository, SealSessionRepository, SealSessionStatus,
    SecurityContextRepository, ToolWorkflow, WorkflowId,
};
use crate::infrastructure::config::GatewayConfig;
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::persistence::EventStore;
use crate::infrastructure::seal::verify_and_extract;

#[derive(Clone)]
pub struct InvocationService {
    workflow_engine: WorkflowEngine,
    cli_engine: CliEngine,
    /// Present only when `orchestrator_url` is configured; enables native tools.
    native_tool_engine: Option<NativeToolEngine>,
    cli_tools: Arc<dyn EphemeralCliToolRepository>,
    seal_sessions: Arc<dyn SealSessionRepository>,
    security_contexts: Arc<dyn SecurityContextRepository>,
    jti_repo: Arc<dyn JtiRepository>,
    event_store: Arc<dyn EventStore>,
    config: GatewayConfig,
}

impl InvocationService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workflow_engine: WorkflowEngine,
        cli_engine: CliEngine,
        native_tool_engine: Option<NativeToolEngine>,
        cli_tools: Arc<dyn EphemeralCliToolRepository>,
        seal_sessions: Arc<dyn SealSessionRepository>,
        security_contexts: Arc<dyn SecurityContextRepository>,
        jti_repo: Arc<dyn JtiRepository>,
        event_store: Arc<dyn EventStore>,
        config: GatewayConfig,
    ) -> Self {
        Self {
            workflow_engine,
            cli_engine,
            native_tool_engine,
            cli_tools,
            seal_sessions,
            security_contexts,
            jti_repo,
            event_store,
            config,
        }
    }

    pub async fn invoke_seal(
        &self,
        envelope: SealEnvelope,
        zaru_user_token: Option<&str>,
    ) -> Result<Value, GatewayError> {
        let unsecured_claims: serde_json::Value = decode_unverified(&envelope.security_token)?;
        let execution_id = unsecured_claims
            .get("exec_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GatewayError::Seal("security token missing exec_id".to_string()))?;

        let session = self
            .seal_sessions
            .find_by_execution_id(execution_id)
            .await?
            .ok_or(GatewayError::Unauthorized)?;

        let call = verify_and_extract(
            &envelope,
            &session.public_key_b64,
            &self.config.seal_jwt_public_key_pem,
            &self.config.seal_jwt_issuer,
            &self.config.seal_jwt_audience,
        )?;

        // JTI is REQUIRED — absence indicates a forged/legacy token (SEAL spec §9.1).
        let jti = call
            .jti
            .as_deref()
            .ok_or_else(|| GatewayError::Seal("security token missing jti".to_string()))?;

        // JTI deduplication — reject replayed tokens within the 30s freshness window (SEAL spec §9.1).
        let jti_expiry = session
            .expires_at
            .min(chrono::Utc::now() + chrono::Duration::seconds(30));
        let is_new = self.jti_repo.record_jti(jti, jti_expiry).await?;
        if !is_new {
            return Err(GatewayError::Seal(
                "duplicate JTI — replay detected".to_string(),
            ));
        }

        // scp claim must match the session's security context (SEAL spec §4.2.2).
        if call.scp != session.security_context {
            return Err(GatewayError::Seal(
                "security context mismatch: scp claim does not match session security_context"
                    .to_string(),
            ));
        }

        if call.exec_id != session.execution_id {
            return Err(GatewayError::Unauthorized);
        }
        if call.sub != session.agent_id {
            return Err(GatewayError::Unauthorized);
        }
        if session.session_status != SealSessionStatus::Active {
            return Err(GatewayError::Unauthorized);
        }
        if session.expires_at <= chrono::Utc::now() {
            return Err(GatewayError::Unauthorized);
        }
        if !session
            .allowed_tool_patterns
            .iter()
            .any(|pattern| tool_pattern_matches(pattern, &call.tool_name))
        {
            return Err(GatewayError::Seal(format!(
                "tool not allowed: {}",
                call.tool_name
            )));
        }
        let security_context = self
            .security_contexts
            .find_by_name(&session.security_context)
            .await?
            .ok_or(GatewayError::Forbidden)?;

        // Evaluate the security context against the tool call (ADR-088 A1)
        security_context.evaluate(&call.tool_name, &call.arguments)?;

        // Publish ToolCallAuthorized event (Gap 035-7)
        if let Ok(event_val) =
            serde_json::to_value(crate::domain::GatewayEvent::ToolCallAuthorized {
                execution_id: call.exec_id.clone(),
                agent_id: call.sub.clone(),
                tool_name: call.tool_name.clone(),
                security_context: call.scp.clone(),
                tenant_id: call.tenant_id.clone(),
                authorized_at: chrono::Utc::now(),
            })
        {
            let _ = self
                .event_store
                .append_event("ToolCallAuthorized", &event_val)
                .await;
        }

        let allow_human_delegated = security_context.allows_human_delegated_credentials();

        if crate::application::native_tools::is_native_tool(&call.tool_name) {
            let engine = self.native_tool_engine.as_ref().ok_or_else(|| {
                GatewayError::Internal(
                    "orchestrator_url is not configured; native tools are unavailable".to_string(),
                )
            })?;
            return engine
                .invoke(&call.tool_name, &call.arguments, &envelope.security_token)
                .await;
        }

        if self
            .cli_tools
            .find_by_name(&call.tool_name)
            .await?
            .is_some()
        {
            let command = call
                .arguments
                .get("subcommand")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    GatewayError::Validation("CLI invocation requires subcommand".to_string())
                })?
                .to_string();
            let args = call
                .arguments
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(ToString::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let fsal_mounts = parse_fsal_mounts(&call.arguments)?;

            self.cli_engine
                .invoke(CliInvocation {
                    execution_id: call.exec_id,
                    security_context: session.security_context,
                    tool_name: call.tool_name,
                    command,
                    args,
                    fsal_mounts,
                    tenant_id: Some(call.tenant_id),
                    zaru_user_token: zaru_user_token.map(ToString::to_string),
                    allow_human_delegated_credentials: allow_human_delegated,
                })
                .await
        } else {
            let tenant_id_opt = if call.tenant_id.is_empty() {
                None
            } else {
                Some(call.tenant_id.as_str())
            };
            self.workflow_engine
                .invoke_by_name(
                    &call.exec_id,
                    &call.tool_name,
                    call.arguments,
                    zaru_user_token,
                    allow_human_delegated,
                    tenant_id_opt,
                )
                .await
        }
    }

    pub async fn invoke_internal(
        &self,
        execution_id: &str,
        tool_name: &str,
        args: Value,
        zaru_user_token: Option<&str>,
    ) -> Result<Value, GatewayError> {
        let security_context = self
            .security_contexts
            .find_by_name("internal")
            .await?
            .ok_or_else(|| {
                GatewayError::Internal("missing required security context 'internal'".to_string())
            })?;
        // Evaluate the security context against the tool call (ADR-088 A1)
        security_context.evaluate(tool_name, &args)?;

        let allow_human_delegated = security_context.allows_human_delegated_credentials();

        if crate::application::native_tools::is_native_tool(tool_name) {
            let engine = self.native_tool_engine.as_ref().ok_or_else(|| {
                GatewayError::Internal(
                    "orchestrator_url is not configured; native tools are unavailable".to_string(),
                )
            })?;
            let bearer = zaru_user_token.unwrap_or("");
            return engine.invoke(tool_name, &args, bearer).await;
        }

        if self.cli_tools.find_by_name(tool_name).await?.is_some() {
            let command = args
                .get("subcommand")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    GatewayError::Validation("CLI invocation requires subcommand".to_string())
                })?
                .to_string();
            let cli_args = args
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(ToString::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let fsal_mounts = parse_fsal_mounts(&args)?;

            self.cli_engine
                .invoke(CliInvocation {
                    execution_id: execution_id.to_string(),
                    security_context: "internal".to_string(),
                    tool_name: tool_name.to_string(),
                    command,
                    args: cli_args,
                    fsal_mounts,
                    tenant_id: None,
                    zaru_user_token: zaru_user_token.map(ToString::to_string),
                    allow_human_delegated_credentials: allow_human_delegated,
                })
                .await
        } else {
            self.workflow_engine
                .invoke_by_name(
                    execution_id,
                    tool_name,
                    args,
                    zaru_user_token,
                    allow_human_delegated,
                    None,
                )
                .await
        }
    }

    pub async fn find_workflow_by_id(
        &self,
        id: WorkflowId,
    ) -> Result<Option<ToolWorkflow>, GatewayError> {
        self.workflow_engine.find_workflow_by_id(id).await
    }
}

fn tool_pattern_matches(pattern: &str, tool_name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return tool_name.starts_with(prefix) && tool_name.ends_with(suffix);
    }
    pattern == tool_name
}

fn decode_unverified(token: &str) -> Result<serde_json::Value, GatewayError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(GatewayError::Seal("invalid JWT".to_string()));
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| GatewayError::Seal(format!("invalid JWT payload encoding: {e}")))?;
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    Ok(value)
}

fn parse_fsal_mounts(args: &Value) -> Result<Vec<CliFsalMount>, GatewayError> {
    let mounts = args
        .get("fsal_mounts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            GatewayError::Validation("CLI invocation requires fsal_mounts array".to_string())
        })?;
    let parsed = mounts
        .iter()
        .map(|entry| {
            let volume_id = entry
                .get("volume_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    GatewayError::Validation("fsal_mounts[].volume_id is required".to_string())
                })?;
            let mount_path = entry
                .get("mount_path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    GatewayError::Validation("fsal_mounts[].mount_path is required".to_string())
                })?;
            let read_only = entry
                .get("read_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(CliFsalMount {
                volume_id: volume_id.to_string(),
                mount_path: mount_path.to_string(),
                read_only,
            })
        })
        .collect::<Result<Vec<CliFsalMount>, GatewayError>>()?;
    if parsed.is_empty() {
        return Err(GatewayError::Validation(
            "CLI invocation requires at least one fsal mount".to_string(),
        ));
    }
    Ok(parsed)
}
