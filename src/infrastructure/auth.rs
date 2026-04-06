use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::Engine;

use crate::infrastructure::config::GatewayConfig;
use crate::infrastructure::jwks_validator::JwtClaims;
use crate::presentation::state::AppState;

pub async fn require_operator(
    State(app_state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if app_state.config.auth_disabled {
        return Ok(next.run(request).await);
    }

    let auth = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let tenant_id = verify_operator_token(&app_state.config, token).await?;

    // Inject tenant context into request extensions for downstream handlers (ADR-056).
    let mut request = request;
    request.extensions_mut().insert(TenantContext(tenant_id));

    Ok(next.run(request).await)
}

/// Middleware for `/v1/invoke` and `/v1/seal/invoke`.
///
/// Reads the SEAL envelope body, extracts the `tenant_id` claim from the
/// `security_token` JWT (without cryptographic verification — full verification
/// happens inside `InvocationService::invoke_seal`), injects `TenantContext`
/// into the request extensions, and re-assembles the body so the downstream
/// handler can deserialize it normally.
pub async fn inject_seal_tenant_context(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let (parts, body) = request.into_parts();

    // Buffer the entire request body so it can be deserialized and re-injected.
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Best-effort extraction: if we cannot parse the envelope or the token,
    // we still allow the request through with an empty TenantContext — the
    // full SEAL verification in InvocationService will reject invalid requests.
    let tenant_id: Option<String> = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.get("security_token")
                .and_then(|t| t.as_str())
                .and_then(|token| decode_jwt_tenant_id_unverified(token))
        });

    let mut request = Request::from_parts(parts, Body::from(bytes));
    request
        .extensions_mut()
        .insert(TenantContext(tenant_id.filter(|s| !s.is_empty())));

    Ok(next.run(request).await)
}

/// Decode a JWT payload without signature verification and return the `tenant_id` claim.
///
/// This is intentionally unverified — it is used only for routing/context injection.
/// Cryptographic verification of the full SEAL token is performed later inside
/// `InvocationService::invoke_seal` via `verify_and_extract`.
fn decode_jwt_tenant_id_unverified(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    claims
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
}

/// Extracted tenant identity from an authenticated request (ADR-056).
#[derive(Debug, Clone)]
pub struct TenantContext(pub Option<String>);

pub async fn verify_operator_token(
    config: &GatewayConfig,
    token: &str,
) -> Result<Option<String>, StatusCode> {
    let claims: JwtClaims = config
        .jwks_validator
        .validate(
            token,
            &config.operator_jwt_issuer,
            &config.operator_jwt_audience,
        )
        .await?;
    match claims.aegis_role.as_deref() {
        Some("aegis:admin") | Some("aegis:operator") => Ok(claims.tenant_id),
        Some(role) => {
            tracing::warn!(role = %role, "Insufficient role for SEAL operator access");
            Err(StatusCode::FORBIDDEN)
        }
        None => {
            tracing::warn!("Missing aegis_role claim in operator JWT");
            Err(StatusCode::FORBIDDEN)
        }
    }
}
