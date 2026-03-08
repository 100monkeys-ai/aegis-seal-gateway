use std::sync::Arc;

use crate::application::{ExplorerService, InvocationService};
use crate::domain::{
    ApiSpecRepository, EphemeralCliToolRepository, SmcpSessionRepository, ToolWorkflowRepository,
};
use crate::infrastructure::persistence::sqlite::SqliteStore;

#[derive(Clone)]
pub struct AppState {
    pub specs: Arc<dyn ApiSpecRepository>,
    pub workflows: Arc<dyn ToolWorkflowRepository>,
    pub cli_tools: Arc<dyn EphemeralCliToolRepository>,
    pub smcp_sessions: Arc<dyn SmcpSessionRepository>,
    pub audit_store: SqliteStore,
    pub invocation_service: InvocationService,
    pub explorer_service: ExplorerService,
}
