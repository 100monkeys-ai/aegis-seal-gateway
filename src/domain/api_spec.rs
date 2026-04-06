use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

use crate::infrastructure::errors::GatewayError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiSpecId(pub Uuid);

impl ApiSpecId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ApiSpecId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationSpec {
    pub operation_id: String,
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSpec {
    pub id: ApiSpecId,
    pub name: String,
    pub base_url: String,
    pub source_url: Option<String>,
    pub raw_spec: Value,
    pub operations: HashMap<String, OperationSpec>,
    pub credential_path: CredentialResolutionPath,
    pub created_at: DateTime<Utc>,
    /// Tenant that owns this spec. `None` = system-global (visible to all tenants).
    pub tenant_id: Option<String>,
}

impl ApiSpec {
    pub fn new(
        name: String,
        base_url: String,
        source_url: Option<String>,
        raw_spec: Value,
        operations: HashMap<String, OperationSpec>,
        credential_path: CredentialResolutionPath,
    ) -> Result<Self, GatewayError> {
        if name.trim().is_empty() {
            return Err(GatewayError::Validation(
                "ApiSpec.name cannot be empty".to_string(),
            ));
        }
        if base_url.trim().is_empty() {
            return Err(GatewayError::Validation(
                "ApiSpec.base_url cannot be empty".to_string(),
            ));
        }
        if operations.is_empty() {
            return Err(GatewayError::Validation(
                "ApiSpec.operations cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            id: ApiSpecId::new(),
            name,
            base_url,
            source_url,
            raw_spec,
            operations,
            credential_path,
            created_at: Utc::now(),
            tenant_id: None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSpecSummary {
    pub id: ApiSpecId,
    pub name: String,
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialRef {
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub enum CredentialResolutionPath {
    SystemJit {
        openbao_engine_path: String,
        role: String,
    },
    HumanDelegated {
        target_service: String,
    },
    Auto {
        system_jit_openbao_engine_path: String,
        system_jit_role: String,
        target_service: String,
    },
    StaticRef(CredentialRef),
}
