mod application;
mod domain;
mod infrastructure;
mod presentation;

use std::sync::Arc;

use axum::middleware;
use axum::{
    routing::{delete, get, post},
    Router,
};
use tracing_subscriber::EnvFilter;

use application::{
    CliEngine, CredentialResolver, ExplorerService, InvocationService, SemanticGate, WorkflowEngine,
};
use domain::{
    ApiSpecRepository, EphemeralCliToolRepository, SmcpSessionRecord, SmcpSessionRepository,
    ToolWorkflowRepository,
};
use infrastructure::auth::require_operator;
use infrastructure::config::GatewayConfig;
use infrastructure::http_client::HttpClient;
use infrastructure::persistence::sqlite::SqliteStore;
use presentation::control_plane::*;
use presentation::invocation::*;
use presentation::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = GatewayConfig::from_env();
    let store = SqliteStore::new(&config.database_url).await?;

    if std::env::var("SMCP_GATEWAY_BOOTSTRAP_SESSION").is_ok() {
        let session_repo: Arc<dyn SmcpSessionRepository> = Arc::new(store.clone());
        session_repo
            .save(SmcpSessionRecord {
                execution_id: "dev-execution".to_string(),
                agent_id: "dev-agent".to_string(),
                security_context: "default".to_string(),
                public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                security_token: "dev".to_string(),
            })
            .await?;
    }

    let specs: Arc<dyn ApiSpecRepository> = Arc::new(store.clone());
    let workflows: Arc<dyn ToolWorkflowRepository> = Arc::new(store.clone());
    let cli_tools: Arc<dyn EphemeralCliToolRepository> = Arc::new(store.clone());
    let smcp_sessions: Arc<dyn SmcpSessionRepository> = Arc::new(store.clone());

    let http_client = HttpClient::new()?;
    let credential_resolver = CredentialResolver::new();
    let semantic_gate = SemanticGate::new();

    let workflow_engine = WorkflowEngine::new(
        workflows.clone(),
        specs.clone(),
        http_client.clone(),
        credential_resolver.clone(),
        store.clone(),
    );
    let cli_engine = CliEngine::new(cli_tools.clone(), semantic_gate, store.clone());
    let explorer = ExplorerService::new(
        specs.clone(),
        http_client,
        credential_resolver,
        store.clone(),
    );
    let invocation = InvocationService::new(
        workflow_engine,
        cli_engine,
        cli_tools.clone(),
        smcp_sessions,
        config.clone(),
    );

    let state = AppState {
        specs,
        workflows,
        cli_tools,
        smcp_sessions: Arc::new(store.clone()),
        audit_store: store.clone(),
        invocation_service: invocation,
        explorer_service: explorer,
    };

    let operator_routes = Router::new()
        .route("/v1/specs", post(register_spec).get(list_specs))
        .route("/v1/specs/{id}", get(get_spec).delete(delete_spec))
        .route("/v1/workflows", post(register_workflow).get(list_workflows))
        .route(
            "/v1/workflows/{id}",
            get(get_workflow)
                .put(update_workflow)
                .delete(delete_workflow),
        )
        .route("/v1/cli-tools", post(register_cli_tool).get(list_cli_tools))
        .route("/v1/cli-tools/{name}", delete(delete_cli_tool))
        .route("/v1/smcp/sessions", post(upsert_smcp_session))
        .route("/v1/tools", get(list_tools))
        .route("/v1/explorer", post(explore_api))
        .layer(middleware::from_fn_with_state(
            config.clone(),
            require_operator,
        ));

    let app = Router::new()
        .merge(operator_routes)
        .route("/v1/invoke", post(invoke_smcp))
        .route("/v1/invoke/internal", post(invoke_internal))
        .route("/health", get(|| async { "ok" }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!("aegis-smcp-gateway listening on {}", config.bind_addr);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn update_workflow(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Json(req): axum::Json<RegisterWorkflowRequest>,
) -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, axum::Json<serde_json::Value>)>
{
    let workflow_id = uuid::Uuid::parse_str(&id)
        .map(crate::domain::WorkflowId)
        .map_err(|e| {
            error_response(crate::infrastructure::errors::GatewayError::Validation(
                format!("invalid workflow id: {e}"),
            ))
        })?;

    let api_spec_id = uuid::Uuid::parse_str(&req.api_spec_id)
        .map(crate::domain::ApiSpecId)
        .map_err(|e| {
            error_response(crate::infrastructure::errors::GatewayError::Validation(
                format!("invalid api spec id: {e}"),
            ))
        })?;

    let mut workflow = crate::domain::ToolWorkflow::new(
        req.name,
        req.description,
        req.input_schema,
        api_spec_id,
        req.steps,
    )
    .map_err(error_response)?;
    workflow.id = workflow_id;

    state
        .workflows
        .save(workflow)
        .await
        .map_err(error_response)?;
    Ok(axum::Json(serde_json::json!({"updated": true})))
}
