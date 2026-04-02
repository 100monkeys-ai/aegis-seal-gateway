use thiserror::Error;

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
