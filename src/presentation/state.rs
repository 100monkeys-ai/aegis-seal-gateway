use std::sync::Arc;

use crate::application::{ExplorerService, InvocationService};
use crate::domain::{
    ApiSpecRepository, EphemeralCliToolRepository, SealSessionRepository,
    SecurityContextRepository, ToolWorkflowRepository,
};
use crate::infrastructure::config::GatewayConfig;
use crate::infrastructure::persistence::EventStore;

#[derive(Clone)]
pub struct AppState {
    pub config: GatewayConfig,
    pub specs: Arc<dyn ApiSpecRepository>,
    pub workflows: Arc<dyn ToolWorkflowRepository>,
    pub cli_tools: Arc<dyn EphemeralCliToolRepository>,
    pub seal_sessions: Arc<dyn SealSessionRepository>,
    pub security_contexts: Arc<dyn SecurityContextRepository>,
    pub audit_store: Arc<dyn EventStore>,
    pub invocation_service: InvocationService,
    pub explorer_service: ExplorerService,
}
