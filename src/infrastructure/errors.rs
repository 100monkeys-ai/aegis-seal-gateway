use chrono::Utc;
use serde::Serialize;
use thiserror::Error;

// ── SEAL Error Code Registry (ADR-088 §A5) ──

/// SEAL error code constants. Not all codes are used yet — the registry is
/// defined up-front per ADR-088 §A5 so that future call-sites can reference
/// them without a code change to the registry itself.
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

    // Attestation errors (3000-series).
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

    pub fn with_request_id(mut self, id: String) -> Self {
        self.error.request_id = Some(id);
        self
    }
}

/// Map a `GatewayError::Seal` message string to the appropriate SEAL error code.
pub fn classify_seal_error(msg: &str) -> u32 {
    use seal_codes::*;

    let lower = msg.to_lowercase();
    if lower.contains("invalid signature")
        || lower.contains("bad signature")
        || lower.contains("signature b64")
        || lower.contains("signature must be")
    {
        INVALID_SIGNATURE
    } else if lower.contains("signature") {
        SIGNATURE_VERIFICATION_FAILED
    } else if lower.contains("timestamp")
        || lower.contains("freshness")
        || lower.contains("replay")
        || lower.contains("duplicate jti")
    {
        TOKEN_EXPIRED
    } else if lower.contains("token invalid")
        || lower.contains("jwt")
        || lower.contains("security token")
    {
        TOKEN_VERIFICATION_FAILED
    } else if lower.contains("session not found") {
        SESSION_NOT_FOUND
    } else if lower.contains("session")
        && (lower.contains("expired") || lower.contains("revoked") || lower.contains("inactive"))
    {
        SESSION_INACTIVE
    } else if lower.contains("tool denied") {
        POLICY_VIOLATION_TOOL_DENIED
    } else if lower.contains("tool not allowed") {
        POLICY_VIOLATION_TOOL_NOT_ALLOWED
    } else if lower.contains("path")
        && (lower.contains("boundary")
            || lower.contains("not allowed")
            || lower.contains("outside"))
    {
        POLICY_VIOLATION_PATH_NOT_ALLOWED
    } else if lower.contains("command") && lower.contains("not allowed") {
        POLICY_VIOLATION_COMMAND_NOT_ALLOWED
    } else if lower.contains("domain") && lower.contains("not allowed") {
        POLICY_VIOLATION_DOMAIN_NOT_ALLOWED
    } else if lower.contains("rate limit") {
        POLICY_VIOLATION_RATE_LIMIT_EXCEEDED
    } else if lower.contains("no matching capability") || lower.contains("capability") {
        POLICY_VIOLATION_NO_MATCHING_CAPABILITY
    } else if lower.contains("security context mismatch") || lower.contains("scp") {
        ATTESTATION_SCOPE_NOT_FOUND
    } else if lower.contains("workload") || lower.contains("wid") {
        ATTESTATION_WORKLOAD_VERIFICATION_FAILED
    } else if lower.contains("attestation") {
        ATTESTATION_FAILED
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
    #[error("database pool acquire timeout")]
    PoolTimeout,
    #[error("http error: {0}")]
    Http(String),
    #[error("seal error: {0}")]
    Seal(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("internal error: {0}")]
    Internal(String),
    /// A refusal the orchestrator relays to its caller in AEGIS ADR-035's
    /// shape: `code` is the R5 code, `message` the caller-facing text (R3),
    /// which never holds a credential.
    #[error("refused ({}): {message}", code.as_str())]
    Refused { code: RefusalCode, message: String },
}

/// The ADR-035 R5 codes a gateway refusal carries to the orchestrator in the
/// gRPC metadata [`REFUSAL_CODE_METADATA`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    /// The call needs the acting user's own credential and carries none.
    CredentialBindingRequired,
    /// The call carries a credential and the gRPC listener is plaintext
    /// (AEGIS ADR-132 H8): a deployment fault, never the caller's.
    CredentialChannelNotConfidential,
    NotFound,
}

/// The gRPC metadata key holding a refusal's [`RefusalCode`].
pub const REFUSAL_CODE_METADATA: &str = "seal-refusal-code";

impl RefusalCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CredentialBindingRequired => "CREDENTIAL_BINDING_REQUIRED",
            Self::CredentialChannelNotConfidential => "CREDENTIAL_CHANNEL_NOT_CONFIDENTIAL",
            Self::NotFound => "NOT_FOUND",
        }
    }

    pub fn grpc_code(&self) -> tonic::Code {
        match self {
            Self::CredentialBindingRequired => tonic::Code::PermissionDenied,
            Self::CredentialChannelNotConfidential => tonic::Code::Unavailable,
            Self::NotFound => tonic::Code::NotFound,
        }
    }
}

impl GatewayError {
    pub fn refused(code: RefusalCode, message: impl Into<String>) -> Self {
        Self::Refused {
            code,
            message: message.into(),
        }
    }
}

impl From<sqlx::Error> for GatewayError {
    fn from(value: sqlx::Error) -> Self {
        match value {
            sqlx::Error::PoolTimedOut => Self::PoolTimeout,
            other => Self::Database(other.to_string()),
        }
    }
}

impl GatewayError {
    /// Returns true if this error was caused by the database connection pool
    /// failing to hand out a connection within `acquire_timeout`. Used by
    /// request handlers to emit a structured `error!` log before propagating —
    /// pool starvation is otherwise invisible in the request path.
    pub fn is_pool_timeout(&self) -> bool {
        matches!(self, Self::PoolTimeout)
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
            PolicyViolation::ToolDenied { tool_name } => {
                Self::Seal(format!("tool denied: {tool_name}"))
            }
            PolicyViolation::ToolNotAllowed { tool_name, .. } => {
                Self::Seal(format!("tool not allowed: {tool_name}"))
            }
            PolicyViolation::PathOutsideBoundary { path, .. } => {
                Self::Seal(format!("path outside boundary: {}", path.display()))
            }
            PolicyViolation::DomainNotAllowed { domain, .. } => {
                Self::Seal(format!("domain not allowed: {domain}"))
            }
            PolicyViolation::CommandNotAllowed { command, .. } => {
                Self::Seal(format!("command not allowed: {command}"))
            }
            PolicyViolation::SubcommandNotAllowed {
                base_command,
                subcommand,
                ..
            } => Self::Seal(format!(
                "subcommand not allowed: {base_command} {subcommand}"
            )),
            PolicyViolation::ConcurrentExecLimitExceeded { limit } => {
                Self::Seal(format!("concurrent execution limit exceeded: {limit}"))
            }
            PolicyViolation::OutputSizeLimitExceeded {
                actual_bytes,
                max_bytes,
            } => Self::Seal(format!(
                "output size limit exceeded: {actual_bytes} bytes (max {max_bytes})"
            )),
        }
    }
}
