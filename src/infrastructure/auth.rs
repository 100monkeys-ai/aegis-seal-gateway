use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::infrastructure::config::GatewayConfig;

#[derive(Debug, Clone, Deserialize)]
struct JwtClaims {
    aegis_role: Option<String>,
    /// Tenant slug from the operator's JWT (ADR-056).
    /// Used to scope admin operations to the caller's tenant.
    #[serde(default)]
    tenant_id: Option<String>,
}

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

    let tenant_id = verify_operator_token(&config, token)?;

    // Inject tenant context into request extensions for downstream handlers (ADR-056).
    let mut request = request;
    request.extensions_mut().insert(TenantContext(tenant_id));

    Ok(next.run(request).await)
}

/// Extracted tenant identity from an authenticated request (ADR-056).
#[derive(Debug, Clone)]
#[allow(dead_code)] // Field will be consumed once ADR-056 tenant routing is wired
pub struct TenantContext(pub Option<String>);

pub fn verify_operator_token(
    config: &GatewayConfig,
    token: &str,
) -> Result<Option<String>, StatusCode> {
    if config.operator_jwt_public_key_pem.trim().is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.set_issuer(&[config.operator_jwt_issuer.as_str()]);
    validation.set_audience(&[config.operator_jwt_audience.as_str()]);

    let claims = decode::<JwtClaims>(
        token,
        &DecodingKey::from_rsa_pem(config.operator_jwt_public_key_pem.as_bytes())
            .map_err(|_| StatusCode::UNAUTHORIZED)?,
        &validation,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?
    .claims;

    let role = claims.aegis_role.unwrap_or_default();
    if role != "aegis:admin" && role != "aegis:operator" {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(claims.tenant_id)
}
