use chrono::Utc;
use serde::Serialize;
use thiserror::Error;

// ── SEAL Error Code Registry (ADR-088 §A5) ──

/// SEAL error code constants. Not all codes are used yet — the registry is
/// defined up-front per ADR-088 §A5 so that future call-sites can reference
/// them without a code change to the registry itself.
#[allow(dead_code)]
pub mod seal_codes {
    // Envelope errors (1000-series)
    pub const MALFORMED_ENVELOPE: u32 = 1000;
    pub const INVALID_SIGNATURE: u32 = 1001;
    pub const SIGNATURE_VERIFICATION_FAILED: u32 = 1002;
    pub const TOKEN_EXPIRED: u32 = 1003;
    pub const TOKEN_VERIFICATION_FAILED: u32 = 1004;
    pub const SESSION_NOT_FOUND: u32 = 1005;
    pub const SESSION_INACTIVE: u32 = 1006;

    // Policy violations (2000-series)
    pub const POLICY_VIOLATION_TOOL_NOT_ALLOWED: u32 = 2000;
    pub const POLICY_VIOLATION_TOOL_DENIED: u32 = 2001;
    pub const POLICY_VIOLATION_PATH_NOT_ALLOWED: u32 = 2002;
    pub const POLICY_VIOLATION_COMMAND_NOT_ALLOWED: u32 = 2003;
    pub const POLICY_VIOLATION_DOMAIN_NOT_ALLOWED: u32 = 2004;
    pub const POLICY_VIOLATION_RATE_LIMIT_EXCEEDED: u32 = 2005;
    pub const POLICY_VIOLATION_NO_MATCHING_CAPABILITY: u32 = 2006;

    // Attestation errors (3000-series)
    pub const ATTESTATION_WORKLOAD_VERIFICATION_FAILED: u32 = 3000;
    pub const ATTESTATION_SCOPE_NOT_FOUND: u32 = 3001;
    pub const ATTESTATION_FAILED: u32 = 3002;
}

/// Standardized SEAL protocol error response (ADR-088 §A5).
#[derive(Debug, Clone, Serialize)]
pub struct SealErrorResponse {
    pub protocol: &'static str,
    pub status: &'static str,
    pub error: SealErrorDetail,
}

#[derive(Debug, Clone, Serialize)]
pub struct SealErrorDetail {
    pub code: u32,
    pub message: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Optional structured details for richer error context (per spec).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl SealErrorResponse {
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            protocol: "seal/v1",
            status: "error",
            error: SealErrorDetail {
                code,
                message: message.into(),
                timestamp: Utc::now().to_rfc3339(),
                request_id: None,
                details: None,
            },
        }
    }

    #[allow(dead_code)]
    pub fn with_request_id(mut self, id: String) -> Self {
        self.error.request_id = Some(id);
        self
    }
}

/// Map a `GatewayError::Seal` message string to the appropriate SEAL error code.
pub fn classify_seal_error(msg: &str) -> u32 {
    use seal_codes::*;

    let lower = msg.to_lowercase();
    if lower.contains("signature") {
        SIGNATURE_VERIFICATION_FAILED
    } else if lower.contains("timestamp") || lower.contains("freshness") || lower.contains("replay")
    {
        TOKEN_EXPIRED
    } else if lower.contains("token invalid") || lower.contains("jwt") {
        TOKEN_VERIFICATION_FAILED
    } else if lower.contains("session not found") {
        SESSION_NOT_FOUND
    } else if lower.contains("session")
        && (lower.contains("expired") || lower.contains("revoked") || lower.contains("inactive"))
    {
        SESSION_INACTIVE
    } else {
        // Covers "malformed", "invalid", and any unrecognised message.
        MALFORMED_ENVELOPE
    }
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("database error: {0}")]
    Database(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("seal error: {0}")]
    Seal(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for GatewayError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value.to_string())
    }
}

impl From<reqwest::Error> for GatewayError {
    fn from(value: reqwest::Error) -> Self {
        Self::Http(value.to_string())
    }
}

impl From<serde_json::Error> for GatewayError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<handlebars::RenderError> for GatewayError {
    fn from(value: handlebars::RenderError) -> Self {
        Self::Internal(value.to_string())
    }
}

impl From<handlebars::TemplateError> for GatewayError {
    fn from(value: handlebars::TemplateError) -> Self {
        Self::Validation(value.to_string())
    }
}

impl From<crate::domain::PolicyViolation> for GatewayError {
    fn from(violation: crate::domain::PolicyViolation) -> Self {
        use crate::domain::PolicyViolation;
        match violation {
            PolicyViolation::ToolDenied { .. } | PolicyViolation::ToolNotAllowed { .. } => {
                Self::Forbidden
            }
            PolicyViolation::PathOutsideBoundary { .. } => Self::Forbidden,
            PolicyViolation::DomainNotAllowed { .. } => Self::Forbidden,
        }
    }
}
