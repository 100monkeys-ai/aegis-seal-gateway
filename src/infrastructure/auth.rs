use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::Engine;

use crate::infrastructure::config::GatewayConfig;
use crate::presentation::state::AppState;

pub async fn require_operator(
    State(app_state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if app_state.config.auth_disabled {
        let mut request = request;
        request
            .extensions_mut()
            .insert(TenantContext::new(None, IdentityKind::Consumer));
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

    let (tenant_id, identity_kind) = verify_operator_token(&app_state.config, token).await?;

    // Inject tenant context into request extensions for downstream handlers (ADR-056).
    let mut request = request;
    request
        .extensions_mut()
        .insert(TenantContext::new(tenant_id, identity_kind));

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

    // Fail closed: every authenticated SEAL request MUST carry a verifiable
    // tenant_id in its security token. A missing or unparseable claim is a
    // hard 401 — there is no legitimate path that produces an empty
    // TenantContext (the prior best-effort fallback was a tenant-isolation
    // leak: callers without a valid token would inherit `None` and bypass
    // tenant-scoped filtering downstream).
    let claims = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.get("security_token")
                .and_then(|t| t.as_str())
                .and_then(decode_jwt_claims_unverified)
        })
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let tenant_id = claims
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let identity_kind = identity_kind_from_claims(&claims);

    let mut request = Request::from_parts(parts, Body::from(bytes));
    request
        .extensions_mut()
        .insert(TenantContext::new(Some(tenant_id), identity_kind));

    Ok(next.run(request).await)
}

/// Decode a JWT payload without signature verification and return the full claims object.
///
/// This is intentionally unverified — it is used only for routing/context injection.
/// Cryptographic verification of the full SEAL token is performed later inside
/// `InvocationService::invoke_seal` via `verify_and_extract`.
fn decode_jwt_claims_unverified(token: &str) -> Option<serde_json::Value> {
    let payload_b64 = token.split('.').nth(1)?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    serde_json::from_slice(&payload_bytes).ok()
}

/// Determine the caller's identity kind from JWT claims.
///
/// Per ADR-100, only Keycloak service-account identities may delegate a tenant
/// via request arguments. Service accounts in Keycloak are identifiable by the
/// `service-account-` prefix on `preferred_username` (the canonical Keycloak
/// convention), or by an explicit `identity_kind` claim emitted by
/// upstream IAM mappers.
fn identity_kind_from_claims(claims: &serde_json::Value) -> IdentityKind {
    if let Some(kind) = claims.get("identity_kind").and_then(|v| v.as_str()) {
        if kind.eq_ignore_ascii_case("service_account")
            || kind.eq_ignore_ascii_case("service-account")
        {
            return IdentityKind::ServiceAccount;
        }
    }
    if let Some(name) = claims.get("preferred_username").and_then(|v| v.as_str()) {
        if name.starts_with("service-account-") {
            return IdentityKind::ServiceAccount;
        }
    }
    IdentityKind::Consumer
}

/// The kind of authenticated identity making a request.
///
/// Per ADR-100, `ServiceAccount` identities are permitted to delegate tenant
/// context via request arguments (e.g. `invocation.tenant_id`); `Consumer`
/// identities are bound strictly to their authenticated tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityKind {
    Consumer,
    ServiceAccount,
}

/// Extracted tenant identity from an authenticated request (ADR-056).
///
/// `tenant_id` is the authenticated tenant slug derived from the verified
/// JWT (or `None` when authentication is disabled in dev). `identity_kind`
/// records whether the caller is a human consumer or a service account, so
/// downstream tenant-arg validation can apply ADR-100 delegation rules.
#[derive(Debug, Clone)]
pub struct TenantContext {
    pub tenant_id: Option<String>,
    pub identity_kind: IdentityKind,
}

impl TenantContext {
    pub fn new(tenant_id: Option<String>, identity_kind: IdentityKind) -> Self {
        Self {
            tenant_id,
            identity_kind,
        }
    }

    pub fn is_service_account(&self) -> bool {
        matches!(self.identity_kind, IdentityKind::ServiceAccount)
    }
}

// Backwards-compatible accessor: many call sites still read `tenant.0`.
// Provide tuple-style access via Index-free helpers without breaking field
// access patterns. New code should use the named fields above.

fn check_operator_role(
    claims: &crate::infrastructure::jwks_validator::JwtClaims,
    claim_name: &str,
) -> Result<(Option<String>, IdentityKind), axum::http::StatusCode> {
    let identity_kind = identity_kind_from_jwt_claims(claims);
    match claims.get_claim(claim_name).as_deref() {
        Some("aegis:admin") | Some("aegis:operator") => {
            Ok((claims.tenant_id.clone(), identity_kind))
        }
        Some(role) => {
            tracing::warn!(role = %role, "Insufficient role for SEAL operator access");
            Err(axum::http::StatusCode::FORBIDDEN)
        }
        None => {
            tracing::warn!("Missing {} claim in operator JWT", claim_name);
            Err(axum::http::StatusCode::FORBIDDEN)
        }
    }
}

fn identity_kind_from_jwt_claims(
    claims: &crate::infrastructure::jwks_validator::JwtClaims,
) -> IdentityKind {
    if let Some(kind) = claims.get_claim("identity_kind").as_deref() {
        if kind.eq_ignore_ascii_case("service_account")
            || kind.eq_ignore_ascii_case("service-account")
        {
            return IdentityKind::ServiceAccount;
        }
    }
    if let Some(name) = claims.get_claim("preferred_username").as_deref() {
        if name.starts_with("service-account-") {
            return IdentityKind::ServiceAccount;
        }
    }
    IdentityKind::Consumer
}

pub async fn verify_operator_token(
    config: &GatewayConfig,
    token: &str,
) -> Result<(Option<String>, IdentityKind), StatusCode> {
    let claims = config
        .jwks_validator
        .validate(
            token,
            &config.operator_jwt_issuer,
            &config.operator_jwt_audience,
        )
        .await?;
    check_operator_role(&claims, &config.operator_role_claim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::jwks_validator::JwtClaims;
    use std::collections::HashMap;

    fn claims_with_role(claim_name: &str, role: &str) -> JwtClaims {
        let mut extra = HashMap::new();
        if claim_name != "aegis_role" {
            extra.insert(
                claim_name.to_owned(),
                serde_json::Value::String(role.to_owned()),
            );
            JwtClaims {
                aegis_role: None,
                tenant_id: Some("tenant-x".to_owned()),
                extra,
            }
        } else {
            JwtClaims {
                aegis_role: Some(role.to_owned()),
                tenant_id: Some("tenant-x".to_owned()),
                extra,
            }
        }
    }

    fn claims_without_role() -> JwtClaims {
        JwtClaims {
            aegis_role: None,
            tenant_id: None,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn test_role_check_admin() {
        let claims = claims_with_role("aegis_role", "aegis:admin");
        let result = check_operator_role(&claims, "aegis_role");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().1, IdentityKind::Consumer);
    }

    #[test]
    fn test_role_check_operator() {
        let claims = claims_with_role("aegis_role", "aegis:operator");
        let result = check_operator_role(&claims, "aegis_role");
        assert!(result.is_ok());
    }

    #[test]
    fn test_role_check_wrong_role() {
        let claims = claims_with_role("aegis_role", "aegis:viewer");
        let result = check_operator_role(&claims, "aegis_role");
        assert_eq!(result.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_role_check_missing_claim() {
        let claims = claims_without_role();
        let result = check_operator_role(&claims, "aegis_role");
        assert_eq!(result.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_role_check_custom_claim_name() {
        let claims = claims_with_role("my_role", "aegis:admin");
        let result = check_operator_role(&claims, "my_role");
        assert!(result.is_ok());
    }

    #[test]
    fn test_role_check_service_account_via_preferred_username() {
        let mut extra = HashMap::new();
        extra.insert(
            "preferred_username".to_string(),
            serde_json::Value::String("service-account-zaru".to_string()),
        );
        let claims = JwtClaims {
            aegis_role: Some("aegis:operator".to_string()),
            tenant_id: Some("tenant-x".to_string()),
            extra,
        };
        let (tenant, kind) = check_operator_role(&claims, "aegis_role").expect("ok");
        assert_eq!(tenant.as_deref(), Some("tenant-x"));
        assert_eq!(kind, IdentityKind::ServiceAccount);
    }

    fn build_seal_envelope_body(token: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "protocol": "seal/v1",
            "security_token": token,
            "payload": {},
            "signature": "",
            "timestamp": "2026-04-27T00:00:00Z"
        }))
        .expect("serialize envelope")
    }

    fn make_unsigned_jwt(claims: serde_json::Value) -> String {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).expect("serialize claims"));
        format!("{header}.{payload}.")
    }

    async fn run_seal_middleware(body_bytes: Vec<u8>) -> axum::http::StatusCode {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::post;
        use axum::Router;
        use tower::ServiceExt;

        // A trivial downstream handler — if the middleware allows the request
        // through, it returns 200; the regression tests assert the middleware
        // rejects with 401 before ever reaching this handler.
        async fn ok_handler() -> &'static str {
            "ok"
        }

        let app: Router = Router::new()
            .route("/v1/seal/invoke", post(ok_handler))
            .layer(axum::middleware::from_fn(inject_seal_tenant_context));

        let request = Request::builder()
            .method("POST")
            .uri("/v1/seal/invoke")
            .body(Body::from(body_bytes))
            .expect("build request");

        let response = app.oneshot(request).await.expect("router oneshot");
        response.status()
    }

    #[tokio::test]
    async fn inject_seal_tenant_context_returns_401_on_missing_jwt_tenant() {
        // JWT payload deliberately omits tenant_id.
        let token = make_unsigned_jwt(serde_json::json!({
            "sub": "agent-1",
            "exec_id": "exec-1"
        }));
        let body_bytes = build_seal_envelope_body(&token);
        let status = run_seal_middleware(body_bytes).await;
        assert_eq!(
            status,
            axum::http::StatusCode::UNAUTHORIZED,
            "middleware must fail closed when JWT lacks tenant_id"
        );
    }

    #[tokio::test]
    async fn inject_seal_tenant_context_returns_401_on_unparseable_token() {
        let body_bytes = build_seal_envelope_body("not-a-real-jwt");
        let status = run_seal_middleware(body_bytes).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn inject_seal_tenant_context_returns_401_on_empty_tenant_claim() {
        // Whitespace-only tenant_id must be treated as absent.
        let token = make_unsigned_jwt(serde_json::json!({
            "sub": "agent-1",
            "exec_id": "exec-1",
            "tenant_id": "   "
        }));
        let body_bytes = build_seal_envelope_body(&token);
        let status = run_seal_middleware(body_bytes).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    }
}
