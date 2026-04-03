use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SealEnvelope {
    /// Protocol version identifier. Must be "seal/v1" per SEAL spec.
    pub protocol: String,
    pub security_token: String,
    pub signature: String,
    /// MCP JSON-RPC payload.
    pub payload: serde_json::Value,
    /// ISO-8601 UTC timestamp for replay prevention.
    pub timestamp: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SealToolCall {
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SealToolParams {
    pub name: String,
    pub arguments: serde_json::Value,
}
