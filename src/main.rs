mod application;
mod domain;
mod infrastructure;
mod presentation;

use chrono::{Duration, Utc};
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
    ApiSpecRepository, EphemeralCliToolRepository, SecurityContextRepository, SmcpSessionRecord,
    SmcpSessionRepository, ToolWorkflowRepository,
};
use infrastructure::auth::require_operator;
use infrastructure::config::GatewayConfig;
use infrastructure::http_client::HttpClient;
use infrastructure::persistence::postgres::PostgresStore;
use infrastructure::persistence::sqlite::SqliteStore;
use infrastructure::persistence::EventStore;
use infrastructure::security_contexts::default_security_contexts;
use presentation::control_plane::*;
use presentation::grpc::proto::gateway_invocation_service_server::GatewayInvocationServiceServer;
use presentation::grpc::proto::tool_workflow_service_server::ToolWorkflowServiceServer;
use presentation::grpc::GatewayGrpcService;
use presentation::invocation::*;
use presentation::state::AppState;

type RepositoryBundle = (
    Arc<dyn ApiSpecRepository>,
    Arc<dyn ToolWorkflowRepository>,
    Arc<dyn EphemeralCliToolRepository>,
    Arc<dyn SmcpSessionRepository>,
    Arc<dyn SecurityContextRepository>,
    Arc<dyn EventStore>,
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = GatewayConfig::from_env();
    let (specs, workflows, cli_tools, smcp_sessions, security_contexts, event_store): RepositoryBundle =
        if config.database_url.starts_with("postgres://")
            || config.database_url.starts_with("postgresql://")
        {
            let store = PostgresStore::new(&config.database_url).await?;
            (
                Arc::new(store.clone()),
                Arc::new(store.clone()),
                Arc::new(store.clone()),
                Arc::new(store.clone()),
                Arc::new(store.clone()),
                Arc::new(store),
            )
        } else {
            let store = SqliteStore::new(&config.database_url).await?;
            (
                Arc::new(store.clone()),
                Arc::new(store.clone()),
                Arc::new(store.clone()),
                Arc::new(store.clone()),
                Arc::new(store.clone()),
                Arc::new(store),
            )
        };

    if security_contexts.list_all().await?.is_empty() {
        for context in default_security_contexts() {
            security_contexts.save(context).await?;
        }
    }

    if std::env::var("SMCP_GATEWAY_BOOTSTRAP_SESSION").is_ok() {
        smcp_sessions
            .save(SmcpSessionRecord {
                execution_id: "dev-execution".to_string(),
                agent_id: "dev-agent".to_string(),
                security_context: "default".to_string(),
                public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                security_token: "dev".to_string(),
                session_status: domain::SmcpSessionStatus::Active,
                expires_at: Utc::now() + Duration::hours(1),
                allowed_tool_patterns: vec!["*".to_string()],
            })
            .await?;
    }

    let http_client = HttpClient::new()?;
    let credential_resolver = CredentialResolver::new(config.clone());
    let semantic_gate = SemanticGate::new(config.semantic_judge_url.clone());

    let workflow_engine = WorkflowEngine::new(
        workflows.clone(),
        specs.clone(),
        http_client.clone(),
        credential_resolver.clone(),
        event_store.clone(),
    );
    let cli_engine = CliEngine::new(
        cli_tools.clone(),
        credential_resolver.clone(),
        semantic_gate,
        event_store.clone(),
        config.clone(),
    );
    let explorer = ExplorerService::new(
        specs.clone(),
        http_client,
        credential_resolver,
        event_store.clone(),
    );
    let invocation = InvocationService::new(
        workflow_engine,
        cli_engine,
        cli_tools.clone(),
        smcp_sessions.clone(),
        security_contexts.clone(),
        config.clone(),
    );

    let state = AppState {
        config: config.clone(),
        specs,
        workflows,
        cli_tools,
        smcp_sessions: smcp_sessions.clone(),
        security_contexts: security_contexts.clone(),
        audit_store: event_store,
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
        .route(
            "/v1/security-contexts",
            post(upsert_security_context).get(list_security_contexts),
        )
        .route("/v1/security-contexts/{name}", get(get_security_context))
        .route("/v1/tools", get(list_tools))
        .route("/v1/explorer", post(explore_api))
        .layer(middleware::from_fn_with_state(
            config.clone(),
            require_operator,
        ));

    let app = Router::new()
        .merge(operator_routes)
        .route("/v1/invoke", post(invoke_smcp))
        .route("/health", get(|| async { "ok" }))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!("aegis-smcp-gateway listening on {}", config.bind_addr);

    let grpc_addr: std::net::SocketAddr = config.grpc_bind_addr.parse()?;
    let grpc_service = GatewayGrpcService::new(state);
    tracing::info!(
        "aegis-smcp-gateway gRPC listening on {}",
        config.grpc_bind_addr
    );

    let (http_result, grpc_result) = tokio::join!(
        axum::serve(listener, app),
        tonic::transport::Server::builder()
            .add_service(ToolWorkflowServiceServer::new(grpc_service.clone()))
            .add_service(GatewayInvocationServiceServer::new(grpc_service))
            .serve(grpc_addr),
    );
    http_result?;
    grpc_result?;

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
    let spec = state
        .specs
        .find_by_id(api_spec_id)
        .await
        .map_err(error_response)?
        .ok_or_else(|| {
            error_response(crate::infrastructure::errors::GatewayError::Validation(
                "api_spec_id does not reference a registered ApiSpec".to_string(),
            ))
        })?;
    for step in &workflow.steps {
        if !spec.operations.contains_key(&step.operation_id) {
            return Err(error_response(
                crate::infrastructure::errors::GatewayError::Validation(format!(
                    "workflow step '{}' references unknown operation_id '{}'",
                    step.name, step.operation_id
                )),
            ));
        }
    }
    workflow.id = workflow_id;

    state
        .workflows
        .save(workflow)
        .await
        .map_err(error_response)?;
    Ok(axum::Json(serde_json::json!({"updated": true})))
}
