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
    CliEngine, CredentialResolver, ExplorerService, InvocationService, NativeToolEngine,
    SemanticGate, WorkflowEngine,
};
use domain::{
    ApiSpecRepository, EphemeralCliToolRepository, JtiRepository, SealSessionRecord,
    SealSessionRepository, SecurityContextRepository, ToolWorkflowRepository,
};
use infrastructure::auth::{inject_seal_tenant_context, require_operator};
use infrastructure::config::GatewayConfig;
use infrastructure::http_client::HttpClient;
use infrastructure::metrics::{init_metrics, spawn_session_gauge_task};
use infrastructure::persistence::postgres::PostgresStore;
use infrastructure::persistence::sqlite::SqliteStore;
use infrastructure::persistence::EventStore;
use infrastructure::security_contexts::default_security_contexts;
use presentation::control_plane::*;
use presentation::grpc::proto::gateway_invocation_service_server::GatewayInvocationServiceServer;
use presentation::grpc::proto::tool_workflow_service_server::ToolWorkflowServiceServer;
use presentation::grpc::GatewayGrpcService;
use presentation::invocation::*;
use presentation::metrics_middleware::{http_metrics_middleware, GrpcMetricsLayer};
use presentation::openapi::openapi_spec;
use presentation::state::AppState;
use presentation::ui;
use utoipa_swagger_ui::SwaggerUi;

type RepositoryBundle = (
    Arc<dyn ApiSpecRepository>,
    Arc<dyn ToolWorkflowRepository>,
    Arc<dyn EphemeralCliToolRepository>,
    Arc<dyn SealSessionRepository>,
    Arc<dyn SecurityContextRepository>,
    Arc<dyn JtiRepository>,
    Arc<dyn EventStore>,
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Install the Prometheus exporter before any metric is emitted (ADR-058).
    init_metrics()?;

    let config = GatewayConfig::load_or_default()?;
    let (state, jti_repo) = build_state(config.clone()).await?;
    let seal_sessions = state.seal_sessions.clone();

    if std::env::var("SEAL_GATEWAY_BOOTSTRAP_SESSION").is_ok() {
        seal_sessions
            .save(SealSessionRecord {
                execution_id: "dev-execution".to_string(),
                agent_id: "dev-agent".to_string(),
                security_context: "aegis-system-default".to_string(),
                public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                security_token: "dev".to_string(),
                session_status: domain::SealSessionStatus::Active,
                expires_at: Utc::now() + Duration::hours(1),
                allowed_tool_patterns: vec!["*".to_string()],
                tenant_id: None,
            })
            .await?;
    }

    // Periodic refresh of the active SEAL session gauge.
    spawn_session_gauge_task(seal_sessions.clone());

    // Periodic JTI cleanup — purge expired entries every 30 seconds.
    {
        let jti_cleanup = jti_repo.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                if let Err(e) = jti_cleanup.cleanup_expired().await {
                    tracing::warn!("JTI cleanup failed: {e}");
                }
            }
        });
    }

    let app = build_http_router(state.clone());

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!("aegis-seal-gateway listening on {}", config.bind_addr);

    let grpc_addr: std::net::SocketAddr = config.grpc_bind_addr.parse()?;
    let grpc_service = GatewayGrpcService::new(state);
    let grpc_server = grpc_server_builder(config.grpc_tls.as_ref())?;
    tracing::info!(
        tls = config.grpc_tls.is_some(),
        "aegis-seal-gateway gRPC listening on {}",
        config.grpc_bind_addr
    );

    let (http_result, grpc_result) = tokio::join!(
        axum::serve(listener, app),
        grpc_server
            .layer(GrpcMetricsLayer)
            .add_service(ToolWorkflowServiceServer::new(grpc_service.clone()))
            .add_service(GatewayInvocationServiceServer::new(grpc_service))
            .serve(grpc_addr),
    );
    http_result?;
    grpc_result?;

    Ok(())
}

/// The gRPC server, over TLS when `tls` names a certificate and key (AEGIS
/// ADR-132 H8). A file that cannot be read stops the gateway at start rather
/// than serving plaintext in its place.
fn grpc_server_builder(
    tls: Option<&domain::GatewayGrpcTlsConfig>,
) -> anyhow::Result<tonic::transport::Server> {
    let builder = tonic::transport::Server::builder();
    let Some(tls) = tls else {
        return Ok(builder);
    };
    let cert = std::fs::read(&tls.cert_path)
        .map_err(|e| anyhow::anyhow!("spec.network.grpc_tls.cert_path {}: {e}", tls.cert_path))?;
    let key = std::fs::read(&tls.key_path)
        .map_err(|e| anyhow::anyhow!("spec.network.grpc_tls.key_path {}: {e}", tls.key_path))?;
    let identity = tonic::transport::Identity::from_pem(cert, key);
    Ok(builder.tls_config(tonic::transport::ServerTlsConfig::new().identity(identity))?)
}

/// Build every repository, engine and service the gateway serves from, as
/// `config` describes them. Returns the application state and the JTI
/// repository, whose cleanup task `main` owns.
async fn build_state(config: GatewayConfig) -> anyhow::Result<(AppState, Arc<dyn JtiRepository>)> {
    build_state_dialling(
        config,
        application::remote_mcp::transport::AddressPolicy::PublicOnly,
    )
    .await
}

/// [`build_state`], with the address rule the remote MCP client dials under
/// (production: public addresses only; the tests: their loopback server).
async fn build_state_dialling(
    config: GatewayConfig,
    address_policy: application::remote_mcp::transport::AddressPolicy,
) -> anyhow::Result<(AppState, Arc<dyn JtiRepository>)> {
    let (specs, workflows, cli_tools, seal_sessions, security_contexts, jti_repo, event_store): RepositoryBundle =
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
                Arc::new(store.clone()),
                Arc::new(store),
            )
        };

    if security_contexts.list_for_tenant(None).await?.is_empty() {
        for context in default_security_contexts() {
            security_contexts.save(context).await?;
        }
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
    let native_tool_engine = config
        .orchestrator_url
        .as_deref()
        .map(|url| NativeToolEngine::new(http_client.clone(), url.to_string()));
    let explorer = ExplorerService::new(
        specs.clone(),
        http_client,
        credential_resolver,
        event_store.clone(),
    );
    let remote_mcp = Arc::new(application::RemoteMcpEngine::new(
        config.mcp_servers.clone(),
        application::remote_mcp::transport::McpHttpClient::new(address_policy)?,
    ));
    let invocation = InvocationService::new(
        workflow_engine,
        cli_engine,
        native_tool_engine,
        remote_mcp,
        cli_tools.clone(),
        seal_sessions.clone(),
        security_contexts.clone(),
        jti_repo.clone(),
        event_store.clone(),
        config.clone(),
    );

    let state = AppState {
        config,
        specs,
        workflows,
        cli_tools,
        seal_sessions,
        security_contexts,
        audit_store: event_store,
        invocation_service: invocation,
        explorer_service: explorer,
    };
    Ok((state, jti_repo))
}

/// The HTTP surface. Every route requires an operator token except the paths
/// `infrastructure::auth::is_public_path` names; a route added here is behind
/// the operator check unless it is added to that list as well.
fn build_http_router(state: AppState) -> Router {
    let seal_invoke_routes = Router::new()
        .route("/v1/invoke", post(invoke_seal))
        .route("/v1/seal/invoke", post(invoke_seal))
        .layer(middleware::from_fn(inject_seal_tenant_context));

    let mut app = Router::new()
        .merge(SwaggerUi::new("/api-docs").url("/openapi.json", openapi_spec()))
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
        .route(
            "/v1/seal/sessions",
            post(upsert_seal_session).get(list_seal_sessions),
        )
        .route(
            "/v1/seal/sessions/{execution_id}",
            get(get_seal_session).delete(delete_seal_session),
        )
        .route(
            "/v1/security-contexts",
            post(upsert_security_context).get(list_security_contexts),
        )
        .route("/v1/security-contexts/{name}", get(get_security_context))
        .route("/v1/tools", get(list_tools))
        .route("/v1/explorer", post(explore_api))
        .merge(seal_invoke_routes)
        .route("/health", get(|| async { "ok" }));
    if state.config.ui_enabled {
        app = app
            .route("/", get(ui::index))
            .route("/ui/app.js", get(ui::app_js))
            .route("/ui/styles.css", get(ui::styles_css));
    }

    // Default deny: the operator check wraps every route above, and the
    // fallback, and lets through only the public paths.
    let app = app
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_operator,
        ))
        .with_state(state);

    // HTTP metrics middleware is applied last so `MatchedPath` is populated
    // for every route by the time the middleware runs (ADR-058 §HTTP labels).
    app.layer(middleware::from_fn(http_metrics_middleware))
}

#[utoipa::path(
    put,
    path = "/v1/workflows/{id}",
    tag = "Workflows",
    params(("id" = String, Path, description = "Workflow UUID")),
    request_body = RegisterWorkflowRequest,
    responses(
        (status = 200, description = "Workflow updated"),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_jwt" = [])),
)]
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

#[cfg(test)]
mod operator_plane_tests {
    //! The operator plane refuses every caller but an operator, on every route
    //! and every RPC. Routes are enumerated from the OpenAPI document the
    //! router serves, RPCs from the service definition the gRPC server is
    //! generated from, so a new one is covered the moment it exists.

    use super::*;
    use crate::infrastructure::test_tokens::{gateway_config_trusting_test_keys, OperatorCaller};
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt;

    async fn test_state() -> (AppState, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("gw-op-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let url = format!("sqlite://{}", dir.join("gateway.db").display());
        let (state, _jti) = build_state(gateway_config_trusting_test_keys(&url))
            .await
            .expect("build state");
        (state, dir)
    }

    /// Every (method, path) the OpenAPI document declares, with path
    /// parameters filled in.
    fn documented_operations() -> Vec<(Method, String)> {
        let spec = openapi_spec();
        let mut operations = Vec::new();
        for (path, item) in &spec.paths.paths {
            let concrete = path
                .split('/')
                .map(|segment| {
                    if segment.starts_with('{') {
                        uuid::Uuid::new_v4().to_string()
                    } else {
                        segment.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            for (method, present) in [
                (Method::GET, item.get.is_some()),
                (Method::POST, item.post.is_some()),
                (Method::PUT, item.put.is_some()),
                (Method::DELETE, item.delete.is_some()),
                (Method::PATCH, item.patch.is_some()),
            ] {
                if present {
                    operations.push((method, concrete.clone()));
                }
            }
        }
        operations
    }

    async fn status_of(
        app: &Router,
        method: Method,
        path: &str,
        caller: &OperatorCaller,
    ) -> StatusCode {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(value) = caller.authorization() {
            request = request.header("authorization", value);
        }
        let request = request.body(Body::from("{}")).expect("request");
        app.clone()
            .oneshot(request)
            .await
            .expect("oneshot")
            .status()
    }

    #[tokio::test]
    async fn every_operator_route_refuses_all_but_an_operator() {
        let (state, dir) = test_state().await;
        let app = build_http_router(state);
        let operations = documented_operations();
        assert!(
            operations.len() >= 20,
            "the OpenAPI document lists {} operations; the router serves at least 20",
            operations.len()
        );
        let mut wrong = Vec::new();
        for (method, path) in &operations {
            if crate::infrastructure::auth::is_public_path(path) {
                continue;
            }
            for caller in &OperatorCaller::ALL {
                let status = status_of(&app, method.clone(), path, caller).await;
                let refused = status == StatusCode::UNAUTHORIZED;
                let authorized =
                    status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN;
                let right = if caller.must_be_accepted() {
                    authorized
                } else {
                    refused
                };
                if !right {
                    wrong.push(format!("{method} {path} with {}: {status}", caller.name()));
                }
            }
        }
        let _ = std::fs::remove_dir_all(dir);
        assert!(
            wrong.is_empty(),
            "operator routes answered wrongly:\n{}",
            wrong.join("\n")
        );
    }

    // A path nobody documented is refused before it is routed, so a route
    // added to the router without an entry in the public list is behind the
    // operator check by construction.
    #[tokio::test]
    async fn an_undocumented_path_is_refused_without_an_operator_token() {
        let (state, dir) = test_state().await;
        let app = build_http_router(state);
        let status = status_of(
            &app,
            Method::GET,
            "/v1/not-a-route",
            &OperatorCaller::NoToken,
        )
        .await;
        let _ = std::fs::remove_dir_all(dir);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_is_served_without_a_token() {
        let (state, dir) = test_state().await;
        let app = build_http_router(state);
        let status = status_of(&app, Method::GET, "/health", &OperatorCaller::NoToken).await;
        let _ = std::fs::remove_dir_all(dir);
        assert_eq!(status, StatusCode::OK);
    }

    /// The RPC names the service definition declares, read from the same
    /// `.proto` file `build.rs` compiles.
    fn declared_rpcs() -> Vec<String> {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let candidates = [
            manifest.join("../aegis-proto/proto/seal_gateway.proto"),
            manifest.join("proto-vendor/aegis/seal_gateway.proto"),
        ];
        let proto = candidates
            .iter()
            .find(|p| p.exists())
            .map(|p| std::fs::read_to_string(p).expect("read proto"))
            .expect("seal_gateway.proto next to the build");
        proto
            .lines()
            .filter_map(|line| line.trim().strip_prefix("rpc "))
            .map(|rest| {
                rest.split('(')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            })
            .collect()
    }

    async fn call_rpc(
        service: &GatewayGrpcService,
        rpc: &str,
        caller: &OperatorCaller,
    ) -> Option<Result<(), tonic::Status>> {
        use presentation::grpc::proto;
        use presentation::grpc::proto::gateway_invocation_service_server::GatewayInvocationService;
        use presentation::grpc::proto::tool_workflow_service_server::ToolWorkflowService;
        fn request<T>(message: T, caller: &OperatorCaller) -> tonic::Request<T> {
            let mut request = tonic::Request::new(message);
            if let Some(value) = caller.authorization() {
                request
                    .metadata_mut()
                    .insert("authorization", value.parse().expect("metadata"));
            }
            request
        }
        let id = uuid::Uuid::new_v4().to_string();
        Some(match rpc {
            "CreateWorkflow" => service
                .create_workflow(request(proto::CreateWorkflowRequest::default(), caller))
                .await
                .map(|_| ()),
            "GetWorkflow" => service
                .get_workflow(request(
                    proto::GetWorkflowRequest { workflow_id: id },
                    caller,
                ))
                .await
                .map(|_| ()),
            "ListWorkflows" => service
                .list_workflows(request(proto::ListWorkflowsRequest::default(), caller))
                .await
                .map(|_| ()),
            "UpdateWorkflow" => service
                .update_workflow(request(proto::UpdateWorkflowRequest::default(), caller))
                .await
                .map(|_| ()),
            "DeleteWorkflow" => service
                .delete_workflow(request(
                    proto::DeleteWorkflowRequest { workflow_id: id },
                    caller,
                ))
                .await
                .map(|_| ()),
            "InvokeWorkflow" => service
                .invoke_workflow(request(
                    proto::InvokeWorkflowRequest {
                        execution_id: id,
                        workflow_name: "not-a-workflow".to_string(),
                        input_json: "{}".to_string(),
                        ..Default::default()
                    },
                    caller,
                ))
                .await
                .map(|_| ()),
            "InvokeCli" => service
                .invoke_cli(request(
                    proto::InvokeCliRequest {
                        execution_id: id,
                        tool_name: "not-a-tool".to_string(),
                        ..Default::default()
                    },
                    caller,
                ))
                .await
                .map(|_| ()),
            "ExploreApi" => service
                .explore_api(request(
                    proto::ExploreApiRequest {
                        api_spec_id: id,
                        parameters_json: "{}".to_string(),
                        ..Default::default()
                    },
                    caller,
                ))
                .await
                .map(|_| ()),
            "InvokeTool" => service
                .invoke_tool(request(
                    proto::InvokeToolRequest {
                        execution_id: id,
                        server: "not-a-server".to_string(),
                        tool: "not-a-tool".to_string(),
                        arguments_json: "{}".to_string(),
                        ..Default::default()
                    },
                    caller,
                ))
                .await
                .map(|_| ()),
            "ListTools" => service
                .list_tools(request(proto::ListToolsRequest::default(), caller))
                .await
                .map(|_| ()),
            _ => return None,
        })
    }

    #[tokio::test]
    async fn every_rpc_refuses_all_but_an_operator() {
        let (state, dir) = test_state().await;
        let service = GatewayGrpcService::new(state);
        let rpcs = declared_rpcs();
        assert!(rpcs.len() >= 9, "the service definition declares {rpcs:?}");
        let mut wrong = Vec::new();
        for rpc in &rpcs {
            for caller in &OperatorCaller::ALL {
                let Some(result) = call_rpc(&service, rpc, caller).await else {
                    wrong.push(format!("{rpc}: no case in this test; add one"));
                    break;
                };
                let code = result.err().map(|s| s.code());
                let refused = code == Some(tonic::Code::Unauthenticated);
                let authorized = !matches!(
                    code,
                    Some(tonic::Code::Unauthenticated) | Some(tonic::Code::PermissionDenied)
                );
                let right = if caller.must_be_accepted() {
                    authorized
                } else {
                    refused
                };
                if !right {
                    wrong.push(format!("{rpc} with {}: {code:?}", caller.name()));
                }
            }
        }
        let _ = std::fs::remove_dir_all(dir);
        assert!(
            wrong.is_empty(),
            "RPCs answered wrongly:\n{}",
            wrong.join("\n")
        );
    }
}

#[cfg(test)]
mod grpc_tls_tests {
    //! AEGIS ADR-132 H8: a person's credential rides the call only over TLS.
    //! The gateway's real gRPC server is started here, over TLS with a
    //! throwaway certificate generated in the test and over plaintext, and
    //! called through a real tonic client.

    use super::*;
    use crate::infrastructure::test_tokens::{gateway_config_trusting_test_keys, OperatorCaller};
    // The gateway generates no client (build.rs); the orchestrator's, from
    // the same .proto, speaks the same wire.
    use aegis_orchestrator_proto::aegis::seal_gateway::v1 as proto;
    use proto::gateway_invocation_service_client::GatewayInvocationServiceClient;

    struct Running {
        client: GatewayInvocationServiceClient<tonic::transport::Channel>,
        dir: std::path::PathBuf,
        database_url: String,
    }

    /// Start the gateway's gRPC server on a loopback port, over TLS when
    /// `tls` is set, and connect a client that trusts the throwaway CA.
    async fn start(tls: bool) -> Running {
        start_with(tls, Vec::new()).await
    }

    /// [`start`], with remote MCP servers registered (dialled under the
    /// tests' loopback address rule).
    async fn start_with(tls: bool, mcp_servers: Vec<domain::RemoteMcpServer>) -> Running {
        let dir = std::env::temp_dir().join(format!("gw-tls-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let url = format!("sqlite://{}", dir.join("gateway.db").display());
        let mut config = gateway_config_trusting_test_keys(&url);
        config.mcp_servers = mcp_servers;
        let ca = if tls {
            let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("throwaway certificate");
            let cert_path = dir.join("grpc.crt");
            let key_path = dir.join("grpc.key");
            std::fs::write(&cert_path, generated.cert.pem()).expect("write cert");
            std::fs::write(&key_path, generated.signing_key.serialize_pem()).expect("write key");
            config.grpc_tls = Some(domain::GatewayGrpcTlsConfig {
                cert_path: cert_path.display().to_string(),
                key_path: key_path.display().to_string(),
            });
            Some(generated.cert.pem())
        } else {
            None
        };
        let (state, _jti) = build_state_dialling(
            config.clone(),
            application::remote_mcp::transport::AddressPolicy::LoopbackForTests,
        )
        .await
        .expect("build state");
        let mut server = grpc_server_builder(config.grpc_tls.as_ref()).expect("grpc server");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("addr").port();
        let incoming = tonic::transport::server::TcpIncoming::from(listener);
        let service = GatewayGrpcService::new(state);
        tokio::spawn(async move {
            let _ = server
                .add_service(GatewayInvocationServiceServer::new(service))
                .serve_with_incoming(incoming)
                .await;
        });

        let endpoint = match &ca {
            Some(pem) => {
                tonic::transport::Endpoint::from_shared(format!("https://localhost:{port}"))
                    .expect("endpoint")
                    .tls_config(
                        tonic::transport::ClientTlsConfig::new()
                            .ca_certificate(tonic::transport::Certificate::from_pem(pem))
                            .domain_name("localhost"),
                    )
                    .expect("client tls")
            }
            None => tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
                .expect("endpoint"),
        };
        let channel = endpoint.connect().await.expect("connect");
        Running {
            client: GatewayInvocationServiceClient::new(channel),
            dir,
            database_url: url,
        }
    }

    fn operator<T>(message: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(message);
        let value = OperatorCaller::Orchestrator
            .authorization()
            .expect("operator token")
            .parse()
            .expect("metadata");
        request.metadata_mut().insert("authorization", value);
        request
    }

    fn credential() -> proto::ResolvedCredential {
        proto::ResolvedCredential {
            kind: proto::CredentialKind::BearerToken as i32,
            value: "Mk7-channel-test-credential".to_string(),
        }
    }

    fn tool_call(credential: Option<proto::ResolvedCredential>) -> proto::InvokeToolRequest {
        proto::InvokeToolRequest {
            execution_id: "exec-tls".to_string(),
            tenant_id: "tenant-a".to_string(),
            server: "not-registered".to_string(),
            tool: "anything".to_string(),
            arguments_json: "{}".to_string(),
            credential,
            ..Default::default()
        }
    }

    fn refusal_code(status: &tonic::Status) -> Option<String> {
        status
            .metadata()
            .get(crate::infrastructure::errors::REFUSAL_CODE_METADATA)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string)
    }

    #[tokio::test]
    async fn a_credential_on_a_plaintext_listener_is_refused() {
        let mut running = start(false).await;
        let status = running
            .client
            .invoke_tool(operator(tool_call(Some(credential()))))
            .await
            .expect_err("refused");
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(
            refusal_code(&status).as_deref(),
            Some("CREDENTIAL_CHANNEL_NOT_CONFIDENTIAL")
        );
        assert_eq!(status.message(), "This tool is not available right now.");

        let status = running
            .client
            .list_tools(operator(proto::ListToolsRequest {
                bound_servers: vec![proto::BoundServer {
                    server: "not-registered".to_string(),
                    credential: Some(credential()),
                }],
                ..Default::default()
            }))
            .await
            .expect_err("refused");
        assert_eq!(
            refusal_code(&status).as_deref(),
            Some("CREDENTIAL_CHANNEL_NOT_CONFIDENTIAL")
        );
        let _ = std::fs::remove_dir_all(running.dir);
    }

    #[tokio::test]
    async fn a_call_without_a_credential_on_a_plaintext_listener_behaves_as_before() {
        let mut running = start(false).await;
        let tools = running
            .client
            .list_tools(operator(proto::ListToolsRequest::default()))
            .await
            .expect("listed");
        assert!(tools.into_inner().tools.is_empty());
        let status = running
            .client
            .invoke_tool(operator(tool_call(None)))
            .await
            .expect_err("no such server");
        assert_eq!(refusal_code(&status).as_deref(), Some("NOT_FOUND"));
        let _ = std::fs::remove_dir_all(running.dir);
    }

    #[tokio::test]
    async fn a_credential_over_tls_is_accepted_by_the_channel_check() {
        let mut running = start(true).await;
        let status = running
            .client
            .invoke_tool(operator(tool_call(Some(credential()))))
            .await
            .expect_err("no such server");
        assert_eq!(refusal_code(&status).as_deref(), Some("NOT_FOUND"));
        let _ = std::fs::remove_dir_all(running.dir);
    }

    #[test]
    fn an_unreadable_certificate_stops_the_gateway_at_start() {
        let missing = domain::GatewayGrpcTlsConfig {
            cert_path: "/nonexistent/grpc.crt".to_string(),
            key_path: "/nonexistent/grpc.key".to_string(),
        };
        let err = grpc_server_builder(Some(&missing))
            .err()
            .expect("refuses to start");
        assert!(err.to_string().contains("cert_path"), "{err}");
    }

    // The remote MCP source end to end: the orchestrator's client, the
    // gateway's TLS gRPC server, a loopback MCP server.

    use crate::application::remote_mcp::tests::loopback::Loopback;
    use crate::application::remote_mcp::tests::CapturedLogs;

    const MARKER: &str = "Mk7-end-to-end-credential-marker";

    async fn with_loopback() -> (Loopback, Running) {
        let loopback = Loopback::default();
        loopback.accept(MARKER, &["echo", "custom-fail"]);
        let url = loopback.start().await;
        let server = domain::RemoteMcpServer::new("loop", &url, None).expect("server");
        (loopback, start_with(true, vec![server]).await)
    }

    fn marker_credential() -> proto::ResolvedCredential {
        proto::ResolvedCredential {
            kind: proto::CredentialKind::BearerToken as i32,
            value: MARKER.to_string(),
        }
    }

    fn acting() -> proto::ActingIdentity {
        proto::ActingIdentity {
            user_id: "user-9".to_string(),
            agent_id: "6c1f0e2a-0000-4000-8000-000000000009".to_string(),
            workflow_id: String::new(),
        }
    }

    fn call(tool: &str, credential: Option<proto::ResolvedCredential>) -> proto::InvokeToolRequest {
        proto::InvokeToolRequest {
            execution_id: "exec-e2e".to_string(),
            tenant_id: "tenant-a".to_string(),
            acting: Some(acting()),
            server: "loop".to_string(),
            tool: tool.to_string(),
            arguments_json: r#"{"q":"hello"}"#.to_string(),
            credential,
        }
    }

    async fn audit_text(url: &str) -> String {
        let pool = sqlx::SqlitePool::connect(url).await.expect("audit db");
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT event_type, payload FROM gateway_events ORDER BY id")
                .fetch_all(&pool)
                .await
                .expect("audit rows");
        rows.into_iter()
            .map(|(kind, payload)| format!("{kind} {payload}\n"))
            .collect()
    }

    #[tokio::test]
    async fn a_call_with_the_users_credential_is_served() {
        let (loopback, mut running) = with_loopback().await;
        let response = running
            .client
            .invoke_tool(operator(call("echo", Some(marker_credential()))))
            .await
            .expect("served")
            .into_inner();
        let result: serde_json::Value = serde_json::from_str(&response.result_json).expect("json");
        assert_eq!(result["content"][0]["text"], r#"{"q":"hello"}"#);
        assert_eq!(loopback.count("tools/call"), 1);
        let audit = audit_text(&running.database_url).await;
        assert!(audit.contains("RemoteToolInvoked"), "{audit}");
        assert!(audit.contains("\"outcome\":\"ok\""), "{audit}");
        assert!(audit.contains("user-9"), "{audit}");
        let _ = std::fs::remove_dir_all(running.dir);
    }

    #[tokio::test]
    async fn a_call_without_a_credential_is_refused_before_any_request() {
        // The orchestrator sends no credential when the user holds no binding
        // granted to the acting agent (ADR-132 G3): the ungranted agent.
        let (loopback, mut running) = with_loopback().await;
        let status = running
            .client
            .invoke_tool(operator(call("echo", None)))
            .await
            .expect_err("refused");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            refusal_code(&status).as_deref(),
            Some("CREDENTIAL_BINDING_REQUIRED")
        );
        assert!(loopback.seen().is_empty(), "no request reached the server");
        let _ = std::fs::remove_dir_all(running.dir);
    }

    #[tokio::test]
    async fn the_listing_adds_each_bound_servers_tools_as_mcp() {
        let (_loopback, mut running) = with_loopback().await;
        let tools = running
            .client
            .list_tools(operator(proto::ListToolsRequest {
                tenant_id: "tenant-a".to_string(),
                acting: Some(acting()),
                bound_servers: vec![proto::BoundServer {
                    server: "loop".to_string(),
                    credential: Some(marker_credential()),
                }],
            }))
            .await
            .expect("listed")
            .into_inner()
            .tools;
        let names: Vec<(String, String)> = tools
            .iter()
            .map(|t| (t.name.clone(), t.kind.clone()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("loop.echo".to_string(), "mcp".to_string()),
                ("loop.custom-fail".to_string(), "mcp".to_string())
            ]
        );
        let unbound = running
            .client
            .list_tools(operator(proto::ListToolsRequest {
                acting: Some(acting()),
                ..Default::default()
            }))
            .await
            .expect("listed")
            .into_inner()
            .tools;
        assert!(unbound.is_empty(), "no binding, no remote tools");
        let _ = std::fs::remove_dir_all(running.dir);
    }

    #[tokio::test]
    async fn the_credential_is_absent_from_logs_errors_and_audit_rows() {
        let logs = CapturedLogs::default();
        let _guard = tracing::subscriber::set_default(logs.subscriber());
        let (_loopback, mut running) = with_loopback().await;

        let mut seen = Vec::new();
        for tool in ["echo", "custom-fail", "missing"] {
            match running
                .client
                .invoke_tool(operator(call(tool, Some(marker_credential()))))
                .await
            {
                Ok(response) => seen.push(response.into_inner().result_json),
                Err(status) => seen.push(format!("{status:?}")),
            }
        }
        let _ = running
            .client
            .list_tools(operator(proto::ListToolsRequest {
                acting: Some(acting()),
                bound_servers: vec![proto::BoundServer {
                    server: "loop".to_string(),
                    credential: Some(marker_credential()),
                }],
                ..Default::default()
            }))
            .await;
        let audit = audit_text(&running.database_url).await;
        tracing::info!("capture marker: the logs were captured");
        let log_text = logs.text();

        assert!(log_text.contains("capture marker"), "the capture works");
        assert!(audit.contains("RemoteToolInvoked"), "the audit was written");
        assert!(!log_text.contains("Mk7-"), "a credential reached the log");
        assert!(!audit.contains("Mk7-"), "a credential reached an audit row");
        for output in &seen {
            assert!(!output.contains("Mk7-"), "a credential reached {output}");
        }
        let _ = std::fs::remove_dir_all(running.dir);
    }

    // AEGIS ADR-132 H9: the gateway keeps no session to a remote server, so
    // two gateways that share nothing serve one person's calls in any order,
    // each call its own initialize, notifications/initialized, tools/call.
    #[tokio::test]
    async fn two_gateways_with_no_shared_state_each_serve_calls_over_grpc() {
        let loopback = Loopback::default();
        loopback.accept(MARKER, &["echo"]);
        let url = loopback.start().await;
        let server = || domain::RemoteMcpServer::new("loop", &url, None).expect("server");
        let mut a = start_with(true, vec![server()]).await;
        let mut b = start_with(true, vec![server()]).await;

        for n in 0..4 {
            let running = if n % 2 == 0 { &mut a } else { &mut b };
            let response = running
                .client
                .invoke_tool(operator(call("echo", Some(marker_credential()))))
                .await;
            assert!(response.is_ok(), "call {n} was served: {response:?}");
        }

        let mut shapes: Vec<Vec<String>> = Vec::new();
        for seen in loopback.seen() {
            if seen.method == "initialize" || shapes.is_empty() {
                shapes.push(Vec::new());
            }
            shapes.last_mut().unwrap().push(seen.method);
        }
        let one_call = ["initialize", "notifications/initialized", "tools/call"].map(String::from);
        assert_eq!(
            shapes,
            vec![one_call.to_vec(); 4],
            "each call is its own initialize, notifications/initialized, tools/call"
        );
        let _ = std::fs::remove_dir_all(a.dir);
        let _ = std::fs::remove_dir_all(b.dir);
    }

    // AEGIS ADR-132 H9a: the `_grounding` a remote server answers on the
    // call's `initialize` reaches the caller as `grounding_json`, never
    // inside `result_json`.
    #[tokio::test]
    async fn the_grounding_an_initialize_answers_reaches_invoke_tool_as_grounding_json() {
        let (loopback, mut running) = with_loopback().await;
        let grounding = serde_json::json!({"you": {"instances": [{"slug": "acme", "id": "i-1"}]}});
        loopback.answer_grounding(MARKER, grounding.clone());
        let response = running
            .client
            .invoke_tool(operator(call("echo", Some(marker_credential()))))
            .await
            .expect("served")
            .into_inner();
        println!("grounding_json: {}", response.grounding_json);
        println!("result_json: {}", response.result_json);
        assert!(
            !response.grounding_json.is_empty(),
            "grounding_json carries the initialize's _grounding, got it empty"
        );
        let carried: serde_json::Value =
            serde_json::from_str(&response.grounding_json).expect("grounding_json is JSON");
        assert_eq!(
            carried, grounding,
            "grounding_json carries the initialize's _grounding"
        );
        assert!(
            !response.result_json.contains("_grounding"),
            "result_json never carries _grounding: {}",
            response.result_json
        );
        let result: serde_json::Value = serde_json::from_str(&response.result_json).expect("json");
        assert_eq!(result["content"][0]["text"], r#"{"q":"hello"}"#);
        let _ = std::fs::remove_dir_all(running.dir);
    }

    #[tokio::test]
    async fn no_grounding_or_a_null_one_leaves_grounding_json_empty() {
        let (loopback, mut running) = with_loopback().await;
        let none = running
            .client
            .invoke_tool(operator(call("echo", Some(marker_credential()))))
            .await
            .expect("served")
            .into_inner();
        println!("none answered: grounding_json {:?}", none.grounding_json);
        assert_eq!(
            none.grounding_json, "",
            "no grounding answered leaves grounding_json empty"
        );
        loopback.answer_grounding(MARKER, serde_json::Value::Null);
        let null = running
            .client
            .invoke_tool(operator(call("echo", Some(marker_credential()))))
            .await
            .expect("served")
            .into_inner();
        println!("null answered: grounding_json {:?}", null.grounding_json);
        assert_eq!(
            null.grounding_json, "",
            "a null grounding leaves grounding_json empty"
        );
        assert!(
            !none.result_json.contains("_grounding"),
            "{}",
            none.result_json
        );
        assert!(
            !null.result_json.contains("_grounding"),
            "{}",
            null.result_json
        );
        let _ = std::fs::remove_dir_all(running.dir);
    }
}
