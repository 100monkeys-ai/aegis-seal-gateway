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
use crate::infrastructure::auth::IdentityKind;
use crate::infrastructure::config::GatewayConfig;
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::metrics::{
    record_attestation, record_policy_violation, record_tool_invocation,
};
use crate::infrastructure::persistence::EventStore;
use crate::infrastructure::seal::verify_and_extract;
use std::time::Instant;

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
        authenticated_identity_kind: IdentityKind,
    ) -> Result<Value, GatewayError> {
        let unsecured_claims: serde_json::Value = decode_unverified(&envelope.security_token)
            .map_err(|e| {
                record_attestation("malformed");
                e
            })?;
        let execution_id = unsecured_claims
            .get("exec_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                record_attestation("malformed");
                GatewayError::Seal("security token missing exec_id".to_string())
            })?;

        let session = self
            .seal_sessions
            .find_by_execution_id(execution_id)
            .await?
            .ok_or_else(|| {
                record_attestation("unauthorized");
                GatewayError::Unauthorized
            })?;

        let call = verify_and_extract(
            &envelope,
            &session.public_key_b64,
            &self.config.seal_jwt_public_key_pem,
            &self.config.seal_jwt_issuer,
            &self.config.seal_jwt_audience,
        )
        .map_err(|e| {
            // Signature-related rejection emits a dedicated outcome label;
            // `aegis_seal_signature_failures_total` is incremented inside
            // `verify_and_extract` itself.
            match &e {
                GatewayError::Seal(msg)
                    if msg.contains("signature") || msg.contains("public key") =>
                {
                    record_attestation("signature_invalid");
                }
                _ => record_attestation("malformed"),
            }
            e
        })?;

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
            record_attestation("replay");
            return Err(GatewayError::Seal(
                "duplicate JTI — replay detected".to_string(),
            ));
        }

        // scp claim must match the session's security context (SEAL spec §4.2.2).
        if call.scp != session.security_context {
            record_attestation("context_mismatch");
            return Err(GatewayError::Seal(
                "security context mismatch: scp claim does not match session security_context"
                    .to_string(),
            ));
        }

        if call.exec_id != session.execution_id {
            record_attestation("unauthorized");
            return Err(GatewayError::Unauthorized);
        }
        if call.sub != session.agent_id {
            record_attestation("unauthorized");
            return Err(GatewayError::Unauthorized);
        }
        if session.session_status != SealSessionStatus::Active {
            record_attestation("unauthorized");
            return Err(GatewayError::Unauthorized);
        }
        if session.expires_at <= chrono::Utc::now() {
            record_attestation("expired");
            return Err(GatewayError::Unauthorized);
        }
        if !session
            .allowed_tool_patterns
            .iter()
            .any(|pattern| tool_pattern_matches(pattern, &call.tool_name))
        {
            record_attestation("tool_not_allowed");
            return Err(GatewayError::Seal(format!(
                "tool not allowed: {}",
                call.tool_name
            )));
        }
        let security_context = self
            .security_contexts
            .find_by_name(&session.security_context)
            .await?
            .ok_or_else(|| {
                record_attestation("forbidden");
                GatewayError::Forbidden
            })?;

        // Evaluate the security context against the tool call (ADR-088 A1).
        // Policy violations are recorded with a stable, low-cardinality label
        // before propagation.
        if let Err(violation) = security_context.evaluate(&call.tool_name, &call.arguments) {
            record_policy_violation(&violation);
            record_attestation("forbidden");
            return Err(GatewayError::from(violation));
        }

        // Attestation succeeded: the SEAL envelope and policy evaluation both
        // accepted this call. Subsequent failures are tool-execution failures,
        // not attestation failures.
        record_attestation("ok");

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
            let started = Instant::now();
            let result = engine
                .invoke(&call.tool_name, &call.arguments, &envelope.security_token)
                .await;
            let status = if result.is_ok() { "ok" } else { "error" };
            record_tool_invocation(
                &call.tool_name,
                "native",
                status,
                started.elapsed().as_secs_f64(),
            );
            return result;
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

            // The SEAL session's tenant_id is the authenticated tenant
            // (it is the verified JWT claim, equal to `call.tenant_id`).
            // We pass it explicitly so cli_engine can enforce the
            // tenant-arg match per ADR-097 / ADR-100.
            let authenticated_tenant = if call.tenant_id.is_empty() {
                None
            } else {
                Some(call.tenant_id.clone())
            };
            let tool_name_for_metric = call.tool_name.clone();
            let started = Instant::now();
            let result = self
                .cli_engine
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
                    authenticated_tenant,
                    // Per ADR-100, the identity kind is derived from the
                    // verified JWT claims by the SEAL middleware
                    // (`inject_seal_tenant_context`) and propagated here so
                    // service-account callers may delegate `tenant_id` while
                    // consumer callers remain bound to their authenticated
                    // tenant.
                    authenticated_identity_kind,
                })
                .await;
            let status = if result.is_ok() { "ok" } else { "error" };
            record_tool_invocation(
                &tool_name_for_metric,
                "cli",
                status,
                started.elapsed().as_secs_f64(),
            );
            result
        } else {
            let tenant_id_opt = if call.tenant_id.is_empty() {
                None
            } else {
                Some(call.tenant_id.as_str())
            };
            let started = Instant::now();
            let result = self
                .workflow_engine
                .invoke_by_name(
                    &call.exec_id,
                    &call.tool_name,
                    call.arguments,
                    zaru_user_token,
                    allow_human_delegated,
                    tenant_id_opt,
                )
                .await;
            let status = if result.is_ok() { "ok" } else { "error" };
            record_tool_invocation(
                &call.tool_name,
                "workflow",
                status,
                started.elapsed().as_secs_f64(),
            );
            result
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
                    // Internal inner-loop invocations do not have an
                    // external authenticated tenant — they run with
                    // service-internal trust, so no tenant-arg gate
                    // applies (the arg is None anyway).
                    authenticated_tenant: None,
                    authenticated_identity_kind:
                        crate::infrastructure::auth::IdentityKind::ServiceAccount,
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
            let remote_path = entry
                .get("remote_path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    GatewayError::Validation("fsal_mounts[].remote_path is required".to_string())
                })?;
            Ok(CliFsalMount {
                volume_id: volume_id.to_string(),
                mount_path: mount_path.to_string(),
                read_only,
                remote_path: remote_path.to_string(),
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
