use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;

use crate::domain::{SealEnvelope, SealToolCall, SealToolParams};
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::metrics::record_signature_failure;

#[derive(Debug, Clone, Deserialize)]
struct SealClaims {
    /// Subject — agent ID bound to the SEAL session (REQUIRED per spec §4.2.3).
    sub: String,
    /// Execution ID — primary lookup key for sessions.
    exec_id: String,
    /// Tenant slug for multi-tenant routing.
    #[serde(default)]
    tenant_id: String,
    /// JWT ID for replay detection (UUID v4).
    #[serde(default)]
    jti: Option<String>,
    /// Security context name (REQUIRED per spec §4.2.2).
    scp: String,
    /// Workload/container ID (REQUIRED per spec §4.2.2).
    wid: String,
}

pub struct SealVerifiedCall {
    /// Subject (agent ID) bound to the session — must match session.agent_id.
    pub sub: String,
    pub exec_id: String,
    pub tool_name: String,
    pub arguments: Value,
    /// Tenant slug extracted from the SEAL security token.
    pub tenant_id: String,
    /// JWT ID for replay detection.
    pub jti: Option<String>,
    /// Security context name from the token — validated against the session.
    pub scp: String,
}

pub fn verify_and_extract(
    envelope: &SealEnvelope,
    public_key_b64: &str,
    seal_jwt_public_key_pem: &str,
    seal_jwt_issuer: &str,
    seal_jwt_audience: &str,
) -> Result<SealVerifiedCall, GatewayError> {
    let pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|e| {
            record_signature_failure();
            GatewayError::Seal(format!("invalid public key b64: {e}"))
        })?;
    let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| {
        record_signature_failure();
        GatewayError::Seal("public key must be 32 bytes".to_string())
    })?;
    let key = VerifyingKey::from_bytes(&pk_arr).map_err(|e| {
        record_signature_failure();
        GatewayError::Seal(format!("invalid public key: {e}"))
    })?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&envelope.signature)
        .map_err(|e| {
            record_signature_failure();
            GatewayError::Seal(format!("invalid signature b64: {e}"))
        })?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        record_signature_failure();
        GatewayError::Seal("signature must be 64 bytes".to_string())
    })?;
    let sig = Signature::from_bytes(&sig_arr);

    let message = signed_message(envelope)?;
    key.verify(&message, &sig).map_err(|e| {
        record_signature_failure();
        GatewayError::Seal(format!("signature verify failed: {e}"))
    })?;

    if seal_jwt_public_key_pem.trim().is_empty() {
        return Err(GatewayError::Seal(
            "SEAL JWT public key is not configured".to_string(),
        ));
    }

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.set_issuer(&[seal_jwt_issuer]);
    validation.set_audience(&[seal_jwt_audience]);
    let claims = decode::<SealClaims>(
        &envelope.security_token,
        &DecodingKey::from_rsa_pem(seal_jwt_public_key_pem.as_bytes())
            .map_err(|e| GatewayError::Seal(format!("invalid SEAL JWT public key: {e}")))?,
        &validation,
    )
    .map_err(|e| GatewayError::Seal(format!("security token invalid: {e}")))?
    .claims;

    // wid is REQUIRED per spec §4.2.2 and must be non-empty (presence is enforced by
    // deserialization; emptiness is an additional validity check).
    if claims.wid.trim().is_empty() {
        return Err(GatewayError::Seal(
            "security token wid claim is empty".to_string(),
        ));
    }

    let tool_call: SealToolCall = serde_json::from_value(envelope.payload.clone())
        .map_err(|e| GatewayError::Seal(format!("invalid payload: {e}")))?;
    if tool_call.method != "tools/call" {
        return Err(GatewayError::Seal(
            "payload method must be tools/call".to_string(),
        ));
    }

    let params: SealToolParams = serde_json::from_value(tool_call.params)
        .map_err(|e| GatewayError::Seal(format!("invalid tools/call params: {e}")))?;

    Ok(SealVerifiedCall {
        sub: claims.sub,
        exec_id: claims.exec_id,
        tool_name: params.name,
        arguments: params.arguments,
        tenant_id: claims.tenant_id,
        jti: claims.jti,
        scp: claims.scp,
    })
}

fn signed_message(envelope: &SealEnvelope) -> Result<Vec<u8>, GatewayError> {
    if envelope.protocol != "seal/v1" {
        return Err(GatewayError::Seal(format!(
            "unsupported SEAL protocol '{}'",
            envelope.protocol
        )));
    }
    let age_seconds = (Utc::now() - envelope.timestamp).num_seconds().abs();
    if age_seconds > 30 {
        return Err(GatewayError::Seal(format!(
            "envelope timestamp is outside the 30 second freshness window ({age_seconds}s)"
        )));
    }
    canonical_message(
        &envelope.security_token,
        &envelope.payload,
        envelope.timestamp,
    )
}

fn canonical_message(
    security_token: &str,
    payload: &Value,
    timestamp: DateTime<Utc>,
) -> Result<Vec<u8>, GatewayError> {
    let canonical = serde_json::json!({
        "payload": payload,
        "security_token": security_token,
        "timestamp": timestamp.timestamp(),
    });
    serde_json::to_vec(&canonical)
        .map_err(|e| GatewayError::Seal(format!("failed to serialize canonical SEAL message: {e}")))
}
