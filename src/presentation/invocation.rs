use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use crate::application::ApiExplorerRequest;
use crate::domain::SealEnvelope;
use crate::presentation::control_plane::error_response;
use crate::presentation::state::AppState;

#[utoipa::path(
    post,
    path = "/v1/invoke",
    tag = "Invocation",
    request_body = SealEnvelope,
    responses(
        (status = 200, description = "Invocation result"),
        (status = 400, description = "Validation / policy error"),
        (status = 401, description = "SEAL signature verification failed"),
    ),
)]
pub async fn invoke_seal(
    State(state): State<AppState>,
    Json(envelope): Json<SealEnvelope>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let result = state
        .invocation_service
        .invoke_seal(envelope, None)
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"result": result})))
}

#[utoipa::path(
    post,
    path = "/v1/explorer",
    tag = "Explorer",
    request_body = ApiExplorerRequest,
    responses(
        (status = 200, description = "Sliced API exploration response"),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_jwt" = [])),
)]
pub async fn explore_api(
    State(state): State<AppState>,
    Json(req): Json<ApiExplorerRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let result = state
        .explorer_service
        .explore(req, None)
        .await
        .map_err(error_response)?;
    Ok(Json(json!(result)))
}
