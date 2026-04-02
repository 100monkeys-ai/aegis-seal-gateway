use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SealEnvelope {
    /// Protocol version identifier. Must be "seal/v1" for spec-compliant envelopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    pub security_token: String,
    pub signature: String,
    /// Raw MCP JSON-RPC payload bytes.
    #[serde(alias = "inner_mcp")]
    pub payload: Vec<u8>,
    /// ISO-8601 UTC timestamp for replay prevention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
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
