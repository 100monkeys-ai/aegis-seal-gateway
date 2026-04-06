use serde::{Deserialize, Serialize};

use crate::domain::CredentialResolutionPath;
use crate::infrastructure::errors::GatewayError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralCliTool {
    pub name: String,
    pub description: String,
    pub docker_image: String,
    pub allowed_subcommands: Vec<String>,
    pub require_semantic_judge: bool,
    pub default_timeout_seconds: u32,
    pub registry_credential_path: Option<CredentialResolutionPath>,
    /// Tenant that owns this CLI tool. `None` = system-global (visible to all tenants).
    pub tenant_id: Option<String>,
}

impl EphemeralCliTool {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.name.trim().is_empty() {
            return Err(GatewayError::Validation(
                "EphemeralCliTool.name cannot be empty".to_string(),
            ));
        }
        if self.allowed_subcommands.is_empty() {
            return Err(GatewayError::Validation(
                "EphemeralCliTool.allowed_subcommands cannot be empty".to_string(),
            ));
        }
        if self.default_timeout_seconds > 300 {
            return Err(GatewayError::Validation(
                "EphemeralCliTool.default_timeout_seconds must be <= 300".to_string(),
            ));
        }
        if self.docker_image.trim().is_empty() {
            return Err(GatewayError::Validation(
                "EphemeralCliTool.docker_image cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralCliToolSummary {
    pub name: String,
    pub description: String,
    pub docker_image: String,
    pub allowed_subcommands: Vec<String>,
    pub require_semantic_judge: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_tool_timeout_must_be_bounded() {
        let tool = EphemeralCliTool {
            name: "terraform".to_string(),
            description: "infra".to_string(),
            docker_image: "mcp/terraform:1.9".to_string(),
            allowed_subcommands: vec!["plan".to_string()],
            require_semantic_judge: true,
            default_timeout_seconds: 301,
            registry_credential_path: None,
            tenant_id: None,
        };
        assert!(tool.validate().is_err());
    }

    #[test]
    fn cli_tool_requires_subcommands() {
        let tool = EphemeralCliTool {
            name: "terraform".to_string(),
            description: "infra".to_string(),
            docker_image: "mcp/terraform:1.9".to_string(),
            allowed_subcommands: Vec::new(),
            require_semantic_judge: true,
            default_timeout_seconds: 60,
            registry_credential_path: None,
            tenant_id: None,
        };
        assert!(tool.validate().is_err());
    }
}
