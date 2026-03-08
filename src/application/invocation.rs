use std::sync::Arc;

use base64::Engine;
use serde_json::Value;

use crate::application::{CliEngine, CliInvocation, WorkflowEngine};
use crate::domain::SmcpEnvelope;
use crate::domain::{EphemeralCliToolRepository, SmcpSessionRepository, ToolWorkflow, WorkflowId};
use crate::infrastructure::config::GatewayConfig;
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::smcp::verify_and_extract;

#[derive(Clone)]
pub struct InvocationService {
    workflow_engine: WorkflowEngine,
    cli_engine: CliEngine,
    cli_tools: Arc<dyn EphemeralCliToolRepository>,
    smcp_sessions: Arc<dyn SmcpSessionRepository>,
    config: GatewayConfig,
}

impl InvocationService {
    pub fn new(
        workflow_engine: WorkflowEngine,
        cli_engine: CliEngine,
        cli_tools: Arc<dyn EphemeralCliToolRepository>,
        smcp_sessions: Arc<dyn SmcpSessionRepository>,
        config: GatewayConfig,
    ) -> Self {
        Self {
            workflow_engine,
            cli_engine,
            cli_tools,
            smcp_sessions,
            config,
        }
    }

    pub async fn invoke_smcp(
        &self,
        envelope: SmcpEnvelope,
        zaru_user_token: Option<&str>,
    ) -> Result<Value, GatewayError> {
        let unsecured_claims: serde_json::Value = decode_unverified(&envelope.security_token)?;
        let execution_id = unsecured_claims
            .get("execution_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GatewayError::Smcp("security token missing execution_id".to_string()))?;

        let session = self
            .smcp_sessions
            .find_by_execution_id(execution_id)
            .await?
            .ok_or(GatewayError::Unauthorized)?;

        let call = verify_and_extract(
            &envelope,
            &session.public_key_b64,
            &self.config.smcp_token_secret,
        )?;

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

            self.cli_engine
                .invoke(CliInvocation {
                    execution_id: call.execution_id,
                    tool_name: call.tool_name,
                    command,
                    args,
                    workspace_path: call
                        .arguments
                        .get("workspace_path")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string),
                })
                .await
        } else {
            self.workflow_engine
                .invoke_by_name(
                    &call.execution_id,
                    &call.tool_name,
                    call.arguments,
                    zaru_user_token,
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

            self.cli_engine
                .invoke(CliInvocation {
                    execution_id: execution_id.to_string(),
                    tool_name: tool_name.to_string(),
                    command,
                    args: cli_args,
                    workspace_path: args
                        .get("workspace_path")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string),
                })
                .await
        } else {
            self.workflow_engine
                .invoke_by_name(execution_id, tool_name, args, zaru_user_token)
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

fn decode_unverified(token: &str) -> Result<serde_json::Value, GatewayError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(GatewayError::Smcp("invalid JWT".to_string()));
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| GatewayError::Smcp(format!("invalid JWT payload encoding: {e}")))?;
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    Ok(value)
}
