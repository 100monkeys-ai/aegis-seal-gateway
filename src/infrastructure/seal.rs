use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;

use crate::domain::{MpcToolCall, MpcToolParams, SealEnvelope};
use crate::infrastructure::errors::GatewayError;

#[derive(Debug, Clone, Deserialize)]
struct SealClaims {
    execution_id: String,
    /// Tenant slug embedded in the SEAL security token (ADR-056).
    /// Empty string for pre-multi-tenancy tokens (treated as system tenant).
    #[serde(default)]
    tenant_id: String,
}

#[allow(dead_code)] // Consumed once SEAL tool routing is wired end-to-end
pub struct SealVerifiedCall {
    pub execution_id: String,
    pub tool_name: String,
    pub arguments: Value,
    /// Tenant slug extracted from the SEAL security token.
    pub tenant_id: String,
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
        .map_err(|e| GatewayError::Seal(format!("invalid public key b64: {e}")))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| GatewayError::Seal("public key must be 32 bytes".to_string()))?;
    let key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| GatewayError::Seal(format!("invalid public key: {e}")))?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&envelope.signature)
        .map_err(|e| GatewayError::Seal(format!("invalid signature b64: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| GatewayError::Seal("signature must be 64 bytes".to_string()))?;
    let sig = Signature::from_bytes(&sig_arr);

    key.verify(&envelope.inner_mcp, &sig)
        .map_err(|e| GatewayError::Seal(format!("signature verify failed: {e}")))?;

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

    let tool_call: MpcToolCall = serde_json::from_slice(&envelope.inner_mcp)
        .map_err(|e| GatewayError::Seal(format!("invalid inner MCP payload: {e}")))?;
    if tool_call.method != "tools/call" {
        return Err(GatewayError::Seal(
            "inner MCP method must be tools/call".to_string(),
        ));
    }

    let params: MpcToolParams = serde_json::from_value(tool_call.params)
        .map_err(|e| GatewayError::Seal(format!("invalid tools/call params: {e}")))?;

    Ok(SealVerifiedCall {
        execution_id: claims.execution_id,
        tool_name: params.name,
        arguments: params.arguments,
        tenant_id: claims.tenant_id,
    })
}
