use serde::Deserialize;
use std::collections::HashMap;

use crate::domain::{CredentialRef, CredentialResolutionPath, SensitiveString};
use crate::infrastructure::config::GatewayConfig;
use crate::infrastructure::errors::{GatewayError, RefusalCode};

#[derive(Clone)]
pub struct CredentialResolver {
    config: GatewayConfig,
    http_client: reqwest::Client,
}

#[derive(Clone)]
pub struct RegistryCredentials {
    pub registry: String,
    pub username: SensitiveString,
    pub password: SensitiveString,
}

#[derive(Debug, Deserialize)]
struct OpenBaoDynamicResponse {
    data: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct OpenBaoKvEnvelope {
    data: Option<OpenBaoKvInner>,
}

#[derive(Debug, Deserialize)]
struct OpenBaoKvInner {
    data: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct KeycloakTokenExchangeResponse {
    access_token: String,
}

impl CredentialResolver {
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }

    pub async fn resolve(
        &self,
        path: &CredentialResolutionPath,
        zaru_user_token: Option<&str>,
        tenant_id: Option<&str>,
    ) -> Result<Vec<(String, SensitiveString)>, GatewayError> {
        match path {
            CredentialResolutionPath::SystemJit {
                openbao_engine_path,
                role,
            } => {
                let scoped_path = tenant_scoped_engine_path(openbao_engine_path, tenant_id);
                self.resolve_system_jit(&scoped_path, role).await
            }
            CredentialResolutionPath::HumanDelegated { target_service } => {
                self.resolve_human_delegated(target_service, zaru_user_token)
                    .await
            }
            CredentialResolutionPath::Auto {
                system_jit_openbao_engine_path,
                system_jit_role,
                target_service,
            } => {
                if zaru_user_token.is_some() {
                    self.resolve_human_delegated(target_service, zaru_user_token)
                        .await
                } else {
                    let scoped_path =
                        tenant_scoped_engine_path(system_jit_openbao_engine_path, tenant_id);
                    self.resolve_system_jit(&scoped_path, system_jit_role).await
                }
            }
            CredentialResolutionPath::StaticRef(reference) => {
                self.resolve_static_ref(&reference.key).await
            }
            CredentialResolutionPath::UserBound { provider } => {
                Err(credential_binding_required(provider))
            }
        }
    }

    async fn resolve_system_jit(
        &self,
        openbao_engine_path: &str,
        role: &str,
    ) -> Result<Vec<(String, SensitiveString)>, GatewayError> {
        let openbao_addr = self.config.openbao_addr.as_deref().ok_or_else(|| {
            GatewayError::Internal("SEAL_GATEWAY_OPENBAO_ADDR is required".to_string())
        })?;
        let openbao_token = self.config.openbao_token.as_deref().ok_or_else(|| {
            GatewayError::Internal("SEAL_GATEWAY_OPENBAO_TOKEN is required".to_string())
        })?;

        if openbao_engine_path.trim().is_empty() || role.trim().is_empty() {
            return Err(GatewayError::Validation(
                "SystemJit requires non-empty openbao_engine_path and role".to_string(),
            ));
        }

        let path = format!(
            "{}/v1/{}/creds/{}",
            openbao_addr.trim_end_matches('/'),
            openbao_engine_path.trim_matches('/'),
            role
        );
        let response = self
            .http_client
            .get(path)
            .header("X-Vault-Token", openbao_token)
            .send()
            .await
            .map_err(|err| GatewayError::Http(format!("OpenBao JIT request failed: {err}")))?;

        if !response.status().is_success() {
            return Err(GatewayError::Http(format!(
                "OpenBao JIT request returned {}",
                response.status()
            )));
        }

        let payload: OpenBaoDynamicResponse = response.json().await.map_err(|err| {
            GatewayError::Serialization(format!("invalid OpenBao JIT response: {err}"))
        })?;

        let data = payload.data.ok_or_else(|| {
            GatewayError::Serialization("OpenBao JIT response missing data".to_string())
        })?;
        let token = data
            .get("token")
            .or_else(|| data.get("password"))
            .ok_or_else(|| {
                GatewayError::Serialization(
                    "OpenBao JIT response missing token/password field".to_string(),
                )
            })?;

        Ok(vec![(
            "Authorization".to_string(),
            SensitiveString::new(format!("Bearer {token}")),
        )])
    }

    async fn resolve_static_ref(
        &self,
        key: &str,
    ) -> Result<Vec<(String, SensitiveString)>, GatewayError> {
        let fields = self.fetch_kv_fields(key).await?;
        let token = fields
            .get("token")
            .cloned()
            .or_else(|| fields.get("value").cloned())
            .ok_or_else(|| {
                GatewayError::Serialization(
                    "OpenBao KV response missing token/value field".to_string(),
                )
            })?;

        Ok(vec![(
            "Authorization".to_string(),
            SensitiveString::new(format!("Bearer {token}")),
        )])
    }

    pub async fn resolve_registry_credentials(
        &self,
        path: &CredentialResolutionPath,
        zaru_user_token: Option<&str>,
        allow_human_delegated_credentials: bool,
        tenant_id: Option<&str>,
    ) -> Result<RegistryCredentials, GatewayError> {
        match path {
            CredentialResolutionPath::StaticRef(reference) => {
                self.resolve_registry_credentials_from_static_ref(reference)
                    .await
            }
            CredentialResolutionPath::SystemJit {
                openbao_engine_path,
                role,
            } => {
                let scoped_path = tenant_scoped_engine_path(openbao_engine_path, tenant_id);
                self.resolve_registry_credentials_from_system_jit(&scoped_path, role)
                    .await
            }
            CredentialResolutionPath::HumanDelegated { target_service } => {
                if !allow_human_delegated_credentials {
                    return Err(GatewayError::Forbidden);
                }
                let headers = self
                    .resolve_human_delegated(target_service, zaru_user_token)
                    .await?;
                let token_header = headers
                    .into_iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                    .ok_or_else(|| {
                        GatewayError::Serialization(
                            "human delegated response missing authorization header".to_string(),
                        )
                    })?;
                let token_value = token_header
                    .1
                    .expose()
                    .strip_prefix("Bearer ")
                    .or_else(|| token_header.1.expose().strip_prefix("bearer "))
                    .map(ToString::to_string)
                    .unwrap_or_else(|| token_header.1.expose().to_string());
                Ok(RegistryCredentials {
                    registry: target_service.clone(),
                    username: SensitiveString::new("oauth2accesstoken"),
                    password: SensitiveString::new(token_value),
                })
            }
            CredentialResolutionPath::Auto {
                system_jit_openbao_engine_path,
                system_jit_role,
                target_service,
            } => {
                if zaru_user_token.is_some() {
                    if !allow_human_delegated_credentials {
                        return Err(GatewayError::Forbidden);
                    }
                    let headers = self
                        .resolve_human_delegated(target_service, zaru_user_token)
                        .await?;
                    let token_header = headers
                        .into_iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                        .ok_or_else(|| {
                            GatewayError::Serialization(
                                "human delegated response missing authorization header".to_string(),
                            )
                        })?;
                    let token_value = token_header
                        .1
                        .expose()
                        .strip_prefix("Bearer ")
                        .or_else(|| token_header.1.expose().strip_prefix("bearer "))
                        .map(ToString::to_string)
                        .unwrap_or_else(|| token_header.1.expose().to_string());
                    Ok(RegistryCredentials {
                        registry: target_service.clone(),
                        username: SensitiveString::new("oauth2accesstoken"),
                        password: SensitiveString::new(token_value),
                    })
                } else {
                    let scoped_path =
                        tenant_scoped_engine_path(system_jit_openbao_engine_path, tenant_id);
                    self.resolve_registry_credentials_from_system_jit(&scoped_path, system_jit_role)
                        .await
                }
            }
            CredentialResolutionPath::UserBound { provider } => {
                Err(credential_binding_required(provider))
            }
        }
    }

    async fn resolve_registry_credentials_from_static_ref(
        &self,
        reference: &CredentialRef,
    ) -> Result<RegistryCredentials, GatewayError> {
        let fields = self.fetch_kv_fields(&reference.key).await?;
        self.registry_credentials_from_map(&fields, Some("index.docker.io"))
    }

    async fn resolve_registry_credentials_from_system_jit(
        &self,
        openbao_engine_path: &str,
        role: &str,
    ) -> Result<RegistryCredentials, GatewayError> {
        let openbao_addr = self.config.openbao_addr.as_deref().ok_or_else(|| {
            GatewayError::Internal("SEAL_GATEWAY_OPENBAO_ADDR is required".to_string())
        })?;
        let openbao_token = self.config.openbao_token.as_deref().ok_or_else(|| {
            GatewayError::Internal("SEAL_GATEWAY_OPENBAO_TOKEN is required".to_string())
        })?;

        if openbao_engine_path.trim().is_empty() || role.trim().is_empty() {
            return Err(GatewayError::Validation(
                "SystemJit requires non-empty openbao_engine_path and role".to_string(),
            ));
        }

        let path = format!(
            "{}/v1/{}/creds/{}",
            openbao_addr.trim_end_matches('/'),
            openbao_engine_path.trim_matches('/'),
            role
        );
        let response = self
            .http_client
            .get(path)
            .header("X-Vault-Token", openbao_token)
            .send()
            .await
            .map_err(|err| GatewayError::Http(format!("OpenBao JIT request failed: {err}")))?;

        if !response.status().is_success() {
            return Err(GatewayError::Http(format!(
                "OpenBao JIT request returned {}",
                response.status()
            )));
        }

        let payload: OpenBaoDynamicResponse = response.json().await.map_err(|err| {
            GatewayError::Serialization(format!("invalid OpenBao JIT response: {err}"))
        })?;
        let data = payload.data.ok_or_else(|| {
            GatewayError::Serialization("OpenBao JIT response missing data".to_string())
        })?;
        self.registry_credentials_from_map(&data, None)
    }

    fn registry_credentials_from_map(
        &self,
        fields: &HashMap<String, String>,
        default_registry: Option<&str>,
    ) -> Result<RegistryCredentials, GatewayError> {
        let registry = fields
            .get("registry")
            .cloned()
            .or_else(|| fields.get("server").cloned())
            .or_else(|| fields.get("host").cloned())
            .or_else(|| default_registry.map(ToString::to_string))
            .unwrap_or_else(|| "index.docker.io".to_string());
        let username = fields
            .get("username")
            .cloned()
            .or_else(|| fields.get("user").cloned())
            .or_else(|| fields.get("access_key").cloned())
            .ok_or_else(|| {
                GatewayError::Serialization(
                    "registry credential missing username/user/access_key field".to_string(),
                )
            })?;
        let password = fields
            .get("password")
            .cloned()
            .or_else(|| fields.get("secret_key").cloned())
            .or_else(|| fields.get("token").cloned())
            .or_else(|| fields.get("value").cloned())
            .ok_or_else(|| {
                GatewayError::Serialization(
                    "registry credential missing password/secret_key/token/value field".to_string(),
                )
            })?;

        Ok(RegistryCredentials {
            registry,
            username: SensitiveString::new(username),
            password: SensitiveString::new(password),
        })
    }

    async fn fetch_kv_fields(&self, key: &str) -> Result<HashMap<String, String>, GatewayError> {
        if key.trim().is_empty() {
            return Err(GatewayError::Validation(
                "StaticRef key cannot be empty".to_string(),
            ));
        }
        let openbao_addr = self.config.openbao_addr.as_deref().ok_or_else(|| {
            GatewayError::Internal("SEAL_GATEWAY_OPENBAO_ADDR is required".to_string())
        })?;
        let openbao_token = self.config.openbao_token.as_deref().ok_or_else(|| {
            GatewayError::Internal("SEAL_GATEWAY_OPENBAO_TOKEN is required".to_string())
        })?;

        let path = format!(
            "{}/v1/{}/data/{}",
            openbao_addr.trim_end_matches('/'),
            self.config.openbao_kv_mount.trim_matches('/'),
            key.trim_matches('/')
        );

        let response = self
            .http_client
            .get(path)
            .header("X-Vault-Token", openbao_token)
            .send()
            .await
            .map_err(|err| GatewayError::Http(format!("OpenBao KV request failed: {err}")))?;

        if !response.status().is_success() {
            return Err(GatewayError::Http(format!(
                "OpenBao KV request returned {}",
                response.status()
            )));
        }

        let payload: OpenBaoKvEnvelope = response.json().await.map_err(|err| {
            GatewayError::Serialization(format!("invalid OpenBao KV response: {err}"))
        })?;

        payload.data.and_then(|data| data.data).ok_or_else(|| {
            GatewayError::Serialization(
                "OpenBao KV response missing nested data object".to_string(),
            )
        })
    }

    async fn resolve_human_delegated(
        &self,
        target_service: &str,
        zaru_user_token: Option<&str>,
    ) -> Result<Vec<(String, SensitiveString)>, GatewayError> {
        if target_service.trim().is_empty() {
            return Err(GatewayError::Validation(
                "human delegated target_service cannot be empty".to_string(),
            ));
        }
        let subject_token = zaru_user_token.ok_or(GatewayError::Unauthorized)?;

        let exchange_url = self
            .config
            .keycloak_token_exchange_url
            .as_deref()
            .ok_or_else(|| {
                GatewayError::Internal(
                    "SEAL_GATEWAY_KEYCLOAK_TOKEN_EXCHANGE_URL is required".to_string(),
                )
            })?;
        let client_id = self.config.keycloak_client_id.as_deref().ok_or_else(|| {
            GatewayError::Internal("SEAL_GATEWAY_KEYCLOAK_CLIENT_ID is required".to_string())
        })?;
        let client_secret = self
            .config
            .keycloak_client_secret
            .as_deref()
            .ok_or_else(|| {
                GatewayError::Internal(
                    "SEAL_GATEWAY_KEYCLOAK_CLIENT_SECRET is required".to_string(),
                )
            })?;

        let form = [
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("subject_token", subject_token),
            ("audience", target_service),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ];

        let response = self
            .http_client
            .post(exchange_url)
            .form(&form)
            .send()
            .await
            .map_err(|err| GatewayError::Http(format!("Keycloak token exchange failed: {err}")))?;

        if !response.status().is_success() {
            return Err(GatewayError::Http(format!(
                "Keycloak token exchange returned {}",
                response.status()
            )));
        }

        let payload: KeycloakTokenExchangeResponse = response.json().await.map_err(|err| {
            GatewayError::Serialization(format!("invalid Keycloak token exchange response: {err}"))
        })?;

        Ok(vec![(
            "Authorization".to_string(),
            SensitiveString::new(format!("Bearer {}", payload.access_token)),
        )])
    }
}

/// A person's own credential is never read by the gateway: the orchestrator
/// resolves it for the acting user's binding, checks the binding's grant to
/// the acting agent or workflow where it reads the secret, and hands it over
/// on the call (AEGIS ADR-132 G2, G3 as settled by correction C1). A path that
/// asks for one here has none to use.
fn credential_binding_required(provider: &str) -> GatewayError {
    GatewayError::refused(
        RefusalCode::CredentialBindingRequired,
        format!("This tool needs your own '{provider}' credential, granted to this agent."),
    )
}

/// Prefix an OpenBao engine path with `tenant-{slug}/` when a tenant slug is provided.
///
/// For example, `aws/creds/my-role` under tenant `acme` becomes
/// `tenant-acme/aws/creds/my-role`. System-level calls (tenant_id = None)
/// use the engine path as-is.
fn tenant_scoped_engine_path(engine_path: &str, tenant_id: Option<&str>) -> String {
    match tenant_id {
        Some(slug) if !slug.trim().is_empty() => {
            format!("tenant-{}/{}", slug.trim(), engine_path.trim_matches('/'))
        }
        _ => engine_path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    //! A person's credential is never read here (AEGIS ADR-132 as settled by
    //! correction C1): the orchestrator resolves it, checks its grant and
    //! hands it over on the call. The other credential kinds are unchanged.
    use super::*;
    use crate::infrastructure::test_tokens::gateway_config_trusting_test_keys;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Serve `router` on a loopback port; answers its base URL.
    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{addr}")
    }

    /// A Keycloak token endpoint that counts the exchanges it is asked for.
    async fn counting_keycloak() -> (String, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let router = Router::new().route(
            "/token",
            post(move || {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({"access_token": "exchanged-token"}))
                }
            }),
        );
        (format!("{}/token", serve(router).await), calls)
    }

    fn resolver_with(keycloak_url: Option<String>, openbao: Option<String>) -> CredentialResolver {
        let mut config = gateway_config_trusting_test_keys("sqlite::memory:");
        config.keycloak_token_exchange_url = keycloak_url;
        config.keycloak_client_id = Some("aegis-seal-gateway".to_string());
        config.keycloak_client_secret = Some("client-secret".to_string());
        config.openbao_addr = openbao;
        config.openbao_token = Some("openbao-test-token".to_string());
        CredentialResolver::new(config)
    }

    /// A JWT-shaped user token; only its shape matters here.
    fn user_token() -> String {
        use base64::Engine as _;
        let enc = |v: serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
        };
        format!(
            "{}.{}.sig",
            enc(serde_json::json!({"alg": "none"})),
            enc(serde_json::json!({"sub": "user-1"}))
        )
    }

    #[tokio::test]
    async fn a_user_bound_path_is_refused_and_never_falls_back_to_a_token_exchange() {
        let (keycloak, exchanges) = counting_keycloak().await;
        let resolver = resolver_with(Some(keycloak), None);
        let path = CredentialResolutionPath::UserBound {
            provider: "example-provider".to_string(),
        };
        let token = user_token();

        let result = resolver
            .resolve(&path, Some(&token), Some("tenant-a"))
            .await;

        match result {
            Err(GatewayError::Refused { code, message }) => {
                assert_eq!(code, RefusalCode::CredentialBindingRequired);
                assert!(message.contains("example-provider"), "{message}");
            }
            other => panic!("expected CREDENTIAL_BINDING_REQUIRED, got {other:?}"),
        }
        assert_eq!(
            exchanges.load(Ordering::SeqCst),
            0,
            "no fallback to HumanDelegated"
        );
    }

    #[tokio::test]
    async fn a_user_bound_registry_credential_is_refused_without_a_lookup() {
        let resolver = resolver_with(None, None);
        let path = CredentialResolutionPath::UserBound {
            provider: "example-registry".to_string(),
        };
        let token = user_token();
        let result = resolver
            .resolve_registry_credentials(&path, Some(&token), true, Some("tenant-a"))
            .await;
        assert!(
            matches!(
                result,
                Err(GatewayError::Refused {
                    code: RefusalCode::CredentialBindingRequired,
                    ..
                })
            ),
            "{:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn a_static_ref_still_reads_its_token_from_openbao() {
        let router = Router::new().route(
            "/v1/secret/data/team/api",
            get(|| async {
                Json(serde_json::json!({"data": {"data": {"token": "static-token"}}}))
            }),
        );
        let resolver = resolver_with(None, Some(serve(router).await));
        let path = CredentialResolutionPath::StaticRef(CredentialRef {
            key: "team/api".to_string(),
        });
        let headers = resolver.resolve(&path, None, None).await.expect("resolved");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Authorization");
        assert_eq!(headers[0].1.expose(), "Bearer static-token");
    }

    #[tokio::test]
    async fn a_human_delegated_path_still_exchanges_the_users_token() {
        let (keycloak, exchanges) = counting_keycloak().await;
        let resolver = resolver_with(Some(keycloak), None);
        let path = CredentialResolutionPath::HumanDelegated {
            target_service: "example-audience".to_string(),
        };
        let token = user_token();
        let headers = resolver
            .resolve(&path, Some(&token), None)
            .await
            .expect("exchanged");
        assert_eq!(headers[0].1.expose(), "Bearer exchanged-token");
        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    }
}
