use serde::Deserialize;
use std::collections::HashMap;

use crate::domain::{CredentialRef, CredentialResolutionPath, SensitiveString};
use crate::infrastructure::config::GatewayConfig;
use crate::infrastructure::errors::GatewayError;

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
