use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SealEnvelope {
    pub security_token: String,
    pub signature: String,
    pub inner_mcp: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MpcToolCall {
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MpcToolParams {
    pub name: String,
    pub arguments: serde_json::Value,
}
