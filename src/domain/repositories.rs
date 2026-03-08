use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::{
    ApiSpec, ApiSpecId, ApiSpecSummary, EphemeralCliTool, EphemeralCliToolSummary, ToolWorkflow,
    ToolWorkflowSummary, WorkflowId,
};
use crate::infrastructure::errors::GatewayError;

#[async_trait]
pub trait ToolWorkflowRepository: Send + Sync {
    async fn save(&self, workflow: ToolWorkflow) -> Result<(), GatewayError>;
    async fn find_by_id(&self, id: WorkflowId) -> Result<Option<ToolWorkflow>, GatewayError>;
    async fn find_by_name(&self, name: &str) -> Result<Option<ToolWorkflow>, GatewayError>;
    async fn list_all(&self) -> Result<Vec<ToolWorkflowSummary>, GatewayError>;
    async fn delete(&self, id: WorkflowId) -> Result<(), GatewayError>;
}

#[async_trait]
pub trait ApiSpecRepository: Send + Sync {
    async fn save(&self, spec: ApiSpec) -> Result<(), GatewayError>;
    async fn find_by_id(&self, id: ApiSpecId) -> Result<Option<ApiSpec>, GatewayError>;
    async fn find_by_source_url(&self, url: &str) -> Result<Option<ApiSpec>, GatewayError>;
    async fn list_all(&self) -> Result<Vec<ApiSpecSummary>, GatewayError>;
    async fn delete(&self, id: ApiSpecId) -> Result<(), GatewayError>;
}

#[async_trait]
pub trait EphemeralCliToolRepository: Send + Sync {
    async fn save(&self, tool: EphemeralCliTool) -> Result<(), GatewayError>;
    async fn find_by_name(&self, name: &str) -> Result<Option<EphemeralCliTool>, GatewayError>;
    async fn list_all(&self) -> Result<Vec<EphemeralCliToolSummary>, GatewayError>;
    async fn delete(&self, name: &str) -> Result<(), GatewayError>;
}

#[async_trait]
pub trait SmcpSessionRepository: Send + Sync {
    async fn save(&self, session: SmcpSessionRecord) -> Result<(), GatewayError>;
    async fn find_by_execution_id(
        &self,
        execution_id: &str,
    ) -> Result<Option<SmcpSessionRecord>, GatewayError>;
}

#[derive(Debug, Clone)]
pub struct SmcpSessionRecord {
    pub execution_id: String,
    pub agent_id: String,
    pub security_context: String,
    pub public_key_b64: String,
    pub security_token: String,
    pub session_status: SmcpSessionStatus,
    pub expires_at: DateTime<Utc>,
    pub allowed_tool_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SmcpSessionStatus {
    Active,
    Expired,
    Revoked,
}
