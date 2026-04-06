// Copyright (c) 2026 100monkeys.ai
// SPDX-License-Identifier: AGPL-3.0
//! Live JWKS validator for operator JWT authentication — ADR-041.

use axum::http::StatusCode;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

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

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);

        let token_data = decode::<JwtClaims>(token, &decoding_key, &validation).map_err(|e| {
            warn!(error = %e, "JWT validation failed");
            StatusCode::UNAUTHORIZED
        })?;

        Ok(token_data.claims)
    }
}
