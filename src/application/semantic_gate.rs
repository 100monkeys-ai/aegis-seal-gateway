use serde::{Deserialize, Serialize};

use crate::domain::EphemeralCliTool;
use crate::infrastructure::errors::GatewayError;

#[derive(Debug, Clone)]
pub enum SemanticDecision {
    Allowed,
    Rejected(String),
}

#[derive(Clone)]
pub struct SemanticGate {
    judge_url: Option<String>,
    http_client: reqwest::Client,
}

#[derive(Debug, Serialize)]
struct SemanticJudgeRequest<'a> {
    tool_name: &'a str,
    subcommand: &'a str,
    args: &'a [String],
    security_context: &'a str,
}

#[derive(Debug, Deserialize)]
struct SemanticJudgeResponse {
    allowed: bool,
    reason: Option<String>,
}

impl SemanticGate {
    pub fn new(judge_url: Option<String>) -> Self {
        Self {
            judge_url,
            http_client: reqwest::Client::new(),
        }
    }

    pub async fn evaluate(
        &self,
        tool: &EphemeralCliTool,
        subcommand: &str,
        args: &[String],
        security_context: &str,
    ) -> Result<SemanticDecision, GatewayError> {
        if !tool
            .allowed_subcommands
            .iter()
            .any(|allowed| allowed == subcommand)
        {
            return Ok(SemanticDecision::Rejected(format!(
                "subcommand '{subcommand}' is not in allowed_subcommands"
            )));
        }

        if !tool.require_semantic_judge {
            return Ok(SemanticDecision::Allowed);
        }

        let judge_url = self.judge_url.as_ref().ok_or_else(|| {
            GatewayError::Internal(
                "semantic judge is required for this tool but SEAL_GATEWAY_SEMANTIC_JUDGE_URL is not configured".to_string(),
            )
        })?;

        let response = self
            .http_client
            .post(judge_url)
            .json(&SemanticJudgeRequest {
                tool_name: &tool.name,
                subcommand,
                args,
                security_context,
            })
            .send()
            .await
            .map_err(|err| {
                GatewayError::Internal(format!("failed to call semantic judge endpoint: {err}"))
            })?;

        if !response.status().is_success() {
            return Err(GatewayError::Internal(format!(
                "semantic judge endpoint returned {}",
                response.status()
            )));
        }

        let verdict: SemanticJudgeResponse = response.json().await.map_err(|err| {
            GatewayError::Internal(format!("failed to parse semantic judge response: {err}"))
        })?;

        if verdict.allowed {
            Ok(SemanticDecision::Allowed)
        } else {
            Ok(SemanticDecision::Rejected(verdict.reason.unwrap_or_else(
                || "semantic judge rejected command intent".to_string(),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::EphemeralCliTool;

    #[tokio::test]
    async fn allowlist_rejects_non_permitted_subcommand() {
        let gate = SemanticGate::new(None);
        let tool = EphemeralCliTool {
            name: "terraform".to_string(),
            description: "infra".to_string(),
            docker_image: "mcp/terraform:1.9".to_string(),
            allowed_subcommands: vec!["plan".to_string()],
            require_semantic_judge: false,
            default_timeout_seconds: 60,
            registry_credential_path: None,
        };

        let verdict = gate
            .evaluate(&tool, "destroy", &[], "zaru-free")
            .await
            .expect("evaluation should succeed");

        assert!(matches!(verdict, SemanticDecision::Rejected(_)));
    }
}
