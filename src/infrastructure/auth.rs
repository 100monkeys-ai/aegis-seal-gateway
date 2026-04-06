use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::infrastructure::config::GatewayConfig;
use crate::infrastructure::jwks_validator::JwtClaims;

pub async fn require_operator(
    State(config): State<GatewayConfig>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if config.auth_disabled {
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

    let tenant_id = verify_operator_token(&config, token).await?;

    // Inject tenant context into request extensions for downstream handlers (ADR-056).
    let mut request = request;
    request.extensions_mut().insert(TenantContext(tenant_id));

    Ok(next.run(request).await)
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
