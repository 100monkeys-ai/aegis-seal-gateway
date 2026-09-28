// Copyright (c) 2026 100monkeys.ai
// SPDX-License-Identifier: AGPL-3.0
//! Live JWKS validator for operator JWT authentication — ADR-041.

use axum::http::StatusCode;
use jsonwebtoken::{decode, decode_header, DecodingKey};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::infrastructure::token_validation::rs256_validation;

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct JwkKey {
    kty: String,
    kid: String,
    n: String,
    e: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(rename = "use", default)]
    key_use: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug)]
struct CachedJwks {
    keys: JwksResponse,
    fetched_at: Instant,
    ttl: Duration,
}

impl CachedJwks {
    fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() > self.ttl
    }
}

#[derive(Debug, Deserialize)]
pub struct JwtClaims {
    pub aegis_role: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Captures all other JWT claims for runtime-configurable lookups (ADR-088 S6).
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl JwtClaims {
    /// Returns the string value of a JWT claim by name.
    /// Checks typed fields first, then the extra map.
    pub fn get_claim(&self, name: &str) -> Option<String> {
        match name {
            "aegis_role" => self.aegis_role.clone(),
            "tenant_id" => self.tenant_id.clone(),
            other => self
                .extra
                .get(other)
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        }
    }
}

#[derive(Debug)]
pub struct JwksValidator {
    jwks_uri: String,
    ttl: Duration,
    cache: RwLock<Option<CachedJwks>>,
    http_client: Client,
}

impl JwksValidator {
    pub fn new(jwks_uri: String, ttl_secs: u64) -> Self {
        Self {
            jwks_uri,
            ttl: Duration::from_secs(ttl_secs),
            cache: RwLock::new(None),
            http_client: Client::new(),
        }
    }

    /// A validator whose key cache already holds `jwks`, as though it had just
    /// been fetched, so a test verifies tokens without an identity provider.
    #[cfg(test)]
    pub(crate) fn with_cached_jwks(jwks: Value) -> Self {
        let keys: JwksResponse = serde_json::from_value(jwks).expect("JWKS document");
        let ttl = Duration::from_secs(3600);
        Self {
            jwks_uri: String::new(),
            ttl,
            cache: RwLock::new(Some(CachedJwks {
                keys,
                fetched_at: Instant::now(),
                ttl,
            })),
            http_client: Client::new(),
        }
    }

    async fn fetch_jwks(&self) -> Result<JwksResponse, StatusCode> {
        debug!(jwks_uri = %self.jwks_uri, "Fetching JWKS");
        let resp = self
            .http_client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| {
                warn!(error = %e, "JWKS fetch failed");
                StatusCode::SERVICE_UNAVAILABLE
            })?;
        if !resp.status().is_success() {
            warn!(status = %resp.status(), "JWKS endpoint returned non-2xx");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        resp.json::<JwksResponse>().await.map_err(|e| {
            warn!(error = %e, "Failed to parse JWKS response");
            StatusCode::INTERNAL_SERVER_ERROR
        })
    }

    async fn get_keys(&self) -> Result<Vec<JwkKey>, StatusCode> {
        {
            let cache = self.cache.read().await;
            if let Some(c) = &*cache {
                if !c.is_expired() {
                    return Ok(c.keys.keys.clone());
                }
            }
        }
        let jwks = self.fetch_jwks().await?;
        let keys = jwks.keys.clone();
        let mut cache = self.cache.write().await;
        *cache = Some(CachedJwks {
            keys: jwks,
            fetched_at: Instant::now(),
            ttl: self.ttl,
        });
        Ok(keys)
    }

    async fn force_refresh(&self) -> Result<Vec<JwkKey>, StatusCode> {
        let jwks = self.fetch_jwks().await?;
        let keys = jwks.keys.clone();
        let mut cache = self.cache.write().await;
        *cache = Some(CachedJwks {
            keys: jwks,
            fetched_at: Instant::now(),
            ttl: self.ttl,
        });
        Ok(keys)
    }

    pub async fn validate(
        &self,
        token: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<JwtClaims, StatusCode> {
        let header = decode_header(token).map_err(|e| {
            warn!(error = %e, "Failed to decode JWT header");
            StatusCode::UNAUTHORIZED
        })?;

        let kid = header.kid.unwrap_or_default();
        let keys = self.get_keys().await?;

        let key = keys
            .iter()
            .find(|k| k.kid == kid && k.kty == "RSA")
            .cloned();

        let key = if key.is_none() {
            warn!(kid = %kid, "Key not found in cache, force-refreshing JWKS");
            let fresh = self.force_refresh().await?;
            fresh.into_iter().find(|k| k.kid == kid && k.kty == "RSA")
        } else {
            key
        };

        let key = key.ok_or_else(|| {
            warn!(kid = %kid, "Key not found in JWKS after refresh");
            StatusCode::UNAUTHORIZED
        })?;

        let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e).map_err(|e| {
            warn!(error = %e, "Failed to build DecodingKey");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let validation = rs256_validation(issuer, audience);

        // The reason names the failed check (a missing or mismatched claim, a
        // bad signature, expiry); the caller only ever sees 401.
        let token_data = decode::<JwtClaims>(token, &decoding_key, &validation).map_err(|e| {
            warn!(reason = %e, "Operator JWT refused");
            StatusCode::UNAUTHORIZED
        })?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_claims_default_aegis_role() {
        let json = r#"{"aegis_role": "aegis:admin", "tenant_id": "tenant-a"}"#;
        let claims: JwtClaims = serde_json::from_str(json).unwrap();
        assert_eq!(
            claims.get_claim("aegis_role"),
            Some("aegis:admin".to_owned())
        );
        assert_eq!(claims.get_claim("tenant_id"), Some("tenant-a".to_owned()));
    }

    #[test]
    fn test_jwt_claims_custom_role_claim() {
        let json = r#"{"my_role": "aegis:operator"}"#;
        let claims: JwtClaims = serde_json::from_str(json).unwrap();
        assert_eq!(
            claims.get_claim("my_role"),
            Some("aegis:operator".to_owned())
        );
        assert!(claims.aegis_role.is_none());
    }

    #[test]
    fn test_jwt_claims_get_claim_missing() {
        let json = r#"{}"#;
        let claims: JwtClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.get_claim("nonexistent"), None);
    }
}
