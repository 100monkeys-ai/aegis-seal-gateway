use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::domain::{
    ApiSpec, ApiSpecId, CredentialResolutionPath, EphemeralCliTool, GatewayEvent,
    SecurityCapabilities, SecurityContext, SmcpSessionRecord, ToolWorkflow, WorkflowId,
};
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::openapi::parse_operations;
use crate::presentation::state::AppState;

#[derive(Deserialize)]
pub struct RegisterSpecRequest {
    pub name: String,
    pub base_url: String,
    pub source_url: Option<String>,
    pub inline_json: Option<Value>,
    pub source_fetch_url: Option<String>,
    pub credential_path: CredentialResolutionPath,
}

pub async fn register_spec(
    State(state): State<AppState>,
    Json(req): Json<RegisterSpecRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Some(source_url) = req.source_url.as_ref() {
        let existing = state
            .specs
            .find_by_source_url(source_url)
            .await
            .map_err(error_response)?;
        if let Some(spec) = existing {
            return Ok(Json(
                json!({"id": spec.id.0.to_string(), "deduplicated": true}),
            ));
        }
    }

    let raw_spec = if let Some(inline) = req.inline_json {
        inline
    } else if let Some(url) = req.source_fetch_url {
        let body = reqwest::get(&url)
            .await
            .map_err(|e| error_response(GatewayError::Http(e.to_string())))?
            .json::<Value>()
            .await
            .map_err(|e| error_response(GatewayError::Http(e.to_string())))?;
        body
    } else {
        return Err(error_response(GatewayError::Validation(
            "provide inline_json or source_fetch_url".to_string(),
        )));
    };

    let operations = parse_operations(&raw_spec).map_err(error_response)?;
    let spec = ApiSpec::new(
        req.name,
        req.base_url,
        req.source_url,
        raw_spec,
        operations,
        req.credential_path,
    )
    .map_err(error_response)?;

    let id = spec.id;
    let name = spec.name.clone();
    state.specs.save(spec).await.map_err(error_response)?;
    state
        .audit_store
        .append_event(
            "ApiSpecRegistered",
            &serde_json::to_value(GatewayEvent::ApiSpecRegistered {
                spec_id: id,
                name,
                registered_by: "operator".to_string(),
                registered_at: chrono::Utc::now(),
            })
            .map_err(|e| error_response(GatewayError::Serialization(e.to_string())))?,
        )
        .await
        .map_err(error_response)?;

    Ok(Json(json!({"id": id.0.to_string()})))
}

pub async fn list_specs(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let specs = state.specs.list_all().await.map_err(error_response)?;
    Ok(Json(json!(specs)))
}

pub async fn get_spec(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let parsed = parse_api_spec_id(&id).map_err(error_response)?;
    let spec = state
        .specs
        .find_by_id(parsed)
        .await
        .map_err(error_response)?;
    match spec {
        Some(s) => Ok(Json(json!(s))),
        None => Err(error_response(GatewayError::NotFound(
            "spec not found".to_string(),
        ))),
    }
}

pub async fn delete_spec(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let parsed = parse_api_spec_id(&id).map_err(error_response)?;
    state.specs.delete(parsed).await.map_err(error_response)?;
    Ok(Json(json!({"deleted": true})))
}

#[derive(Deserialize)]
pub struct RegisterWorkflowRequest {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub api_spec_id: String,
    pub steps: Vec<crate::domain::WorkflowStep>,
}

pub async fn register_workflow(
    State(state): State<AppState>,
    Json(req): Json<RegisterWorkflowRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let api_spec_id = parse_api_spec_id(&req.api_spec_id).map_err(error_response)?;
    validate_workflow_steps_against_spec(&state, api_spec_id, &req.steps).await?;
    let workflow = ToolWorkflow::new(
        req.name,
        req.description,
        req.input_schema,
        api_spec_id,
        req.steps,
    )
    .map_err(error_response)?;
    let id = workflow.id;
    let step_count = workflow.steps.len();
    let name = workflow.name.clone();
    state
        .workflows
        .save(workflow)
        .await
        .map_err(error_response)?;
    state
        .audit_store
        .append_event(
            "WorkflowRegistered",
            &serde_json::to_value(GatewayEvent::WorkflowRegistered {
                workflow_id: id,
                name,
                step_count,
                registered_by: "operator".to_string(),
                registered_at: chrono::Utc::now(),
            })
            .map_err(|e| error_response(GatewayError::Serialization(e.to_string())))?,
        )
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"id": id.0.to_string()})))
}

pub async fn list_workflows(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let list = state.workflows.list_all().await.map_err(error_response)?;
    Ok(Json(json!(list)))
}

pub async fn get_workflow(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let parsed = parse_workflow_id(&id).map_err(error_response)?;
    let wf = state
        .invocation_service
        .find_workflow_by_id(parsed)
        .await
        .map_err(error_response)?;
    match wf {
        Some(v) => Ok(Json(json!(v))),
        None => Err(error_response(GatewayError::NotFound(
            "workflow not found".to_string(),
        ))),
    }
}

pub async fn delete_workflow(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let parsed = parse_workflow_id(&id).map_err(error_response)?;
    state
        .workflows
        .delete(parsed)
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"deleted": true})))
}

#[derive(Deserialize)]
pub struct RegisterCliToolRequest {
    pub name: String,
    pub description: String,
    pub docker_image: String,
    pub allowed_subcommands: Vec<String>,
    pub require_semantic_judge: bool,
    pub default_timeout_seconds: u32,
    pub registry_credential_path: Option<crate::domain::CredentialResolutionPath>,
}

pub async fn register_cli_tool(
    State(state): State<AppState>,
    Json(req): Json<RegisterCliToolRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let tool = EphemeralCliTool {
        name: req.name,
        description: req.description,
        docker_image: req.docker_image,
        allowed_subcommands: req.allowed_subcommands,
        require_semantic_judge: req.require_semantic_judge,
        default_timeout_seconds: req.default_timeout_seconds,
        registry_credential_path: req.registry_credential_path,
    };
    tool.validate().map_err(error_response)?;
    let event_name = tool.name.clone();
    let event_image = tool.docker_image.clone();
    state.cli_tools.save(tool).await.map_err(error_response)?;
    state
        .audit_store
        .append_event(
            "CliToolRegistered",
            &serde_json::to_value(GatewayEvent::CliToolRegistered {
                name: event_name,
                docker_image: event_image,
                registered_at: chrono::Utc::now(),
            })
            .map_err(|e| error_response(GatewayError::Serialization(e.to_string())))?,
        )
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"saved": true})))
}

pub async fn list_cli_tools(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let list = state.cli_tools.list_all().await.map_err(error_response)?;
    Ok(Json(json!(list)))
}

pub async fn delete_cli_tool(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    state
        .cli_tools
        .delete(&name)
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"deleted": true})))
}

pub async fn list_tools(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let workflows = state.workflows.list_all().await.map_err(error_response)?;
    let cli_tools = state.cli_tools.list_all().await.map_err(error_response)?;

    let workflow_tools = workflows.into_iter().map(|workflow| {
        json!({
            "name": workflow.name,
            "description": workflow.description
        })
    });
    let cli_tools = cli_tools.into_iter().map(|tool| {
        json!({
            "name": tool.name,
            "description": tool.description
        })
    });

    let all = workflow_tools
        .into_iter()
        .chain(cli_tools)
        .collect::<Vec<_>>();
    Ok(Json(json!(all)))
}

#[derive(Deserialize)]
pub struct UpsertSmcpSessionRequest {
    pub execution_id: String,
    pub agent_id: String,
    pub security_context: String,
    pub public_key_b64: String,
    pub security_token: String,
    pub session_status: Option<crate::domain::SmcpSessionStatus>,
    pub expires_at: Option<String>,
    pub allowed_tool_patterns: Option<Vec<String>>,
}

pub async fn upsert_smcp_session(
    State(state): State<AppState>,
    Json(req): Json<UpsertSmcpSessionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    state
        .smcp_sessions
        .save(SmcpSessionRecord {
            execution_id: req.execution_id,
            agent_id: req.agent_id,
            security_context: req.security_context,
            public_key_b64: req.public_key_b64,
            security_token: req.security_token,
            session_status: req
                .session_status
                .unwrap_or(crate::domain::SmcpSessionStatus::Active),
            expires_at: req
                .expires_at
                .as_deref()
                .map(|value| {
                    chrono::DateTime::parse_from_rfc3339(value)
                        .map(|ts| ts.with_timezone(&chrono::Utc))
                        .map_err(|err| {
                            error_response(GatewayError::Validation(format!(
                                "invalid expires_at RFC3339 timestamp: {err}"
                            )))
                        })
                })
                .transpose()?
                .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(1)),
            allowed_tool_patterns: req
                .allowed_tool_patterns
                .filter(|patterns| !patterns.is_empty())
                .unwrap_or_else(|| vec!["*".to_string()]),
        })
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"saved": true})))
}

#[derive(Deserialize)]
pub struct UpsertSecurityContextRequest {
    pub name: String,
    pub allow_workflow_tools: bool,
    pub allow_cli_tools: bool,
    pub allow_explorer: bool,
    pub allow_human_delegated_credentials: bool,
}

pub async fn upsert_security_context(
    State(state): State<AppState>,
    Json(req): Json<UpsertSecurityContextRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if req.name.trim().is_empty() {
        return Err(error_response(GatewayError::Validation(
            "security context name cannot be empty".to_string(),
        )));
    }
    state
        .security_contexts
        .save(SecurityContext {
            name: req.name,
            capabilities: SecurityCapabilities {
                allow_workflow_tools: req.allow_workflow_tools,
                allow_cli_tools: req.allow_cli_tools,
                allow_explorer: req.allow_explorer,
                allow_human_delegated_credentials: req.allow_human_delegated_credentials,
            },
        })
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"saved": true})))
}

pub async fn list_security_contexts(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let list = state
        .security_contexts
        .list_all()
        .await
        .map_err(error_response)?;
    Ok(Json(json!(list)))
}

pub async fn get_security_context(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let context = state
        .security_contexts
        .find_by_name(&name)
        .await
        .map_err(error_response)?;
    match context {
        Some(value) => Ok(Json(json!(value))),
        None => Err(error_response(GatewayError::NotFound(
            "security context not found".to_string(),
        ))),
    }
}

async fn validate_workflow_steps_against_spec(
    state: &AppState,
    api_spec_id: ApiSpecId,
    steps: &[crate::domain::WorkflowStep],
) -> Result<(), (StatusCode, Json<Value>)> {
    let spec = state
        .specs
        .find_by_id(api_spec_id)
        .await
        .map_err(error_response)?
        .ok_or_else(|| {
            error_response(GatewayError::Validation(
                "api_spec_id does not reference a registered ApiSpec".to_string(),
            ))
        })?;

    for step in steps {
        if !spec.operations.contains_key(&step.operation_id) {
            return Err(error_response(GatewayError::Validation(format!(
                "workflow step '{}' references unknown operation_id '{}'",
                step.name, step.operation_id
            ))));
        }
    }

    Ok(())
}

fn parse_api_spec_id(input: &str) -> Result<ApiSpecId, GatewayError> {
    let id = uuid::Uuid::parse_str(input)
        .map_err(|e| GatewayError::Validation(format!("invalid api spec id: {e}")))?;
    Ok(ApiSpecId(id))
}

fn parse_workflow_id(input: &str) -> Result<WorkflowId, GatewayError> {
    let id = uuid::Uuid::parse_str(input)
        .map_err(|e| GatewayError::Validation(format!("invalid workflow id: {e}")))?;
    Ok(WorkflowId(id))
}

pub fn error_response(err: GatewayError) -> (StatusCode, Json<Value>) {
    match err {
        GatewayError::Validation(msg) => (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))),
        GatewayError::NotFound(msg) => (StatusCode::NOT_FOUND, Json(json!({"error": msg}))),
        GatewayError::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        ),
        GatewayError::Forbidden => (StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"}))),
        other => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": other.to_string()})),
        ),
    }
}
