use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jsonwebtoken::{decode, DecodingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::domain::{SealEnvelope, SealToolCall, SealToolParams};
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::metrics::record_signature_failure;
use crate::infrastructure::token_validation::rs256_validation;

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

    let validation = rs256_validation(seal_jwt_issuer, seal_jwt_audience);
    let claims = decode::<SealClaims>(
        &envelope.security_token,
        &DecodingKey::from_rsa_pem(seal_jwt_public_key_pem.as_bytes())
            .map_err(|e| GatewayError::Seal(format!("invalid SEAL JWT public key: {e}")))?,
        &validation,
    )
    .map_err(|e| {
        // The log names the failed check; the caller learns only that the
        // token was refused.
        tracing::warn!(reason = %e, "SEAL security token refused");
        GatewayError::Seal("security token invalid".to_string())
    })?
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::test_tokens::{
        assert_claim_matrix, now, sign_rs256, trusted_key, ACCEPTED_AUDIENCE, TRUSTED_ISSUER,
    };
    use ed25519_dalek::{Signer, SigningKey};

    /// A SEAL claim set valid in every respect for a gateway that trusts
    /// [`TRUSTED_ISSUER`] and accepts [`ACCEPTED_AUDIENCE`].
    fn valid_seal_claims() -> Value {
        serde_json::json!({
            "iss": TRUSTED_ISSUER,
            "aud": ACCEPTED_AUDIENCE,
            "exp": now() + 3600,
            "iat": now(),
            "jti": uuid::Uuid::new_v4().to_string(),
            "sub": "agent-1",
            "exec_id": "exec-1",
            "scp": "aegis-system-default",
            "wid": "container-1",
            "tenant_id": "tenant-a",
        })
    }

    /// An envelope carrying `security_token`, signed by a fresh Ed25519 key.
    /// Returns the envelope and that key's public half, base64.
    fn signed_envelope(security_token: String) -> (SealEnvelope, String) {
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        seed[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let signing_key = SigningKey::from_bytes(&seed);
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": { "name": "echo", "arguments": {} },
        });
        let timestamp = DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("timestamp");
        let message =
            canonical_message(&security_token, &payload, timestamp).expect("canonical message");
        let signature = signing_key.sign(&message);
        let envelope = SealEnvelope {
            protocol: "seal/v1".to_string(),
            security_token,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            payload,
            container_id: None,
            timestamp,
        };
        let public_key_b64 = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().to_bytes());
        (envelope, public_key_b64)
    }

    fn verify(security_token: String) -> Result<SealVerifiedCall, GatewayError> {
        let (envelope, public_key_b64) = signed_envelope(security_token);
        verify_and_extract(
            &envelope,
            &public_key_b64,
            &trusted_key().public_pem,
            TRUSTED_ISSUER,
            ACCEPTED_AUDIENCE,
        )
    }

    #[tokio::test]
    async fn seal_path_requires_and_validates_exp_iss_aud() {
        assert_claim_matrix("SEAL path", valid_seal_claims(), |token| async move {
            verify(token).is_ok()
        })
        .await;
    }

    #[test]
    fn seal_path_refusal_does_not_name_the_failed_check() {
        let mut claims = valid_seal_claims();
        claims["aud"] = serde_json::json!("aegis-orchestrator");
        let refusal = verify(sign_rs256(trusted_key(), &claims))
            .err()
            .expect("a token for another audience must be refused");
        assert_eq!(
            refusal.to_string(),
            "seal error: security token invalid",
            "the caller learns the token was refused, not which check refused it"
        );
    }
}
