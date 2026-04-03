use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::SecurityContext;
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
pub trait SealSessionRepository: Send + Sync {
    async fn save(&self, session: SealSessionRecord) -> Result<(), GatewayError>;
    async fn find_by_execution_id(
        &self,
        execution_id: &str,
    ) -> Result<Option<SealSessionRecord>, GatewayError>;
    async fn list_active(&self) -> Result<Vec<SealSessionRecord>, GatewayError>;
    async fn delete_by_execution_id(&self, execution_id: &str) -> Result<bool, GatewayError>;
}

#[async_trait]
pub trait SecurityContextRepository: Send + Sync {
    async fn save(&self, context: SecurityContext) -> Result<(), GatewayError>;
    async fn find_by_name(&self, name: &str) -> Result<Option<SecurityContext>, GatewayError>;
    async fn list_all(&self) -> Result<Vec<SecurityContext>, GatewayError>;
}

#[async_trait]
pub trait JtiRepository: Send + Sync {
    /// Record a JTI. Returns `true` if this is the first time seeing it.
    /// Returns `false` if it's a duplicate (replay).
    async fn record_jti(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<bool, GatewayError>;

    /// Remove expired JTI entries (called by periodic maintenance).
    async fn cleanup_expired(&self) -> Result<u64, GatewayError>;
}

#[derive(Debug, Clone, Serialize)]
pub struct SealSessionRecord {
    pub execution_id: String,
    pub agent_id: String,
    pub security_context: String,
    pub public_key_b64: String,
    pub security_token: String,
    pub session_status: SealSessionStatus,
    pub expires_at: DateTime<Utc>,
    pub allowed_tool_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum SealSessionStatus {
    Active,
    Expired,
    Revoked,
}
