use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::application::credential_resolver::CredentialResolver;
use crate::domain::{ApiSpecId, ApiSpecRepository, GatewayEvent};
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::http_client::HttpClient;
use crate::infrastructure::persistence::EventStore;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ApiExplorerRequest {
    pub execution_id: String,
    #[schema(value_type = String, format = "uuid")]
    pub api_spec_id: ApiSpecId,
    pub operation_id: String,
    pub parameters: serde_json::Value,
    pub fields: Vec<String>,
    pub include_hateoas_hints: bool,
}

#[derive(Debug, Serialize)]
pub struct ApiExplorerResponse {
    pub sliced_data: Value,
    pub hints: Option<Value>,
    pub operation_metadata: Value,
}

#[derive(Clone)]
pub struct ExplorerService {
    specs: Arc<dyn ApiSpecRepository>,
    http_client: HttpClient,
    credential_resolver: CredentialResolver,
    event_store: Arc<dyn EventStore>,
}

impl ExplorerService {
    pub fn new(
        specs: Arc<dyn ApiSpecRepository>,
        http_client: HttpClient,
        credential_resolver: CredentialResolver,
        event_store: Arc<dyn EventStore>,
    ) -> Self {
        Self {
            specs,
            http_client,
            credential_resolver,
            event_store,
        }
    }

    pub async fn explore(
        &self,
        req: ApiExplorerRequest,
        zaru_user_token: Option<&str>,
    ) -> Result<ApiExplorerResponse, GatewayError> {
        let spec = self
            .specs
            .find_by_id(req.api_spec_id)
            .await?
            .ok_or_else(|| GatewayError::NotFound("api spec not found".to_string()))?;
        let operation = spec
            .operations
            .get(&req.operation_id)
            .ok_or_else(|| GatewayError::NotFound("operation not found".to_string()))?;

        let url = format!("{}{}", spec.base_url.trim_end_matches('/'), operation.path);
        let resolution_path_label = match &spec.credential_path {
            crate::domain::CredentialResolutionPath::SystemJit { .. } => "system_jit",
            crate::domain::CredentialResolutionPath::HumanDelegated { .. } => "human_delegated",
            crate::domain::CredentialResolutionPath::Auto { .. } => "auto",
            crate::domain::CredentialResolutionPath::StaticRef(_) => "static_ref",
        };
        let target_service = match &spec.credential_path {
            crate::domain::CredentialResolutionPath::HumanDelegated { target_service }
            | crate::domain::CredentialResolutionPath::Auto { target_service, .. } => {
                target_service.clone()
            }
            _ => "unknown".to_string(),
        };

        let headers = match self
            .credential_resolver
            .resolve(&spec.credential_path, zaru_user_token, None)
            .await
        {
            Ok(headers) => {
                self.event_store
                    .append_event(
                        "CredentialExchangeCompleted",
                        &serde_json::to_value(GatewayEvent::CredentialExchangeCompleted {
                            execution_id: req.execution_id.clone(),
                            resolution_path: resolution_path_label.to_string(),
                            target_service,
                            completed_at: chrono::Utc::now(),
                        })?,
                    )
                    .await?;
                headers
            }
            Err(err) => {
                self.event_store
                    .append_event(
                        "CredentialExchangeFailed",
                        &serde_json::to_value(GatewayEvent::CredentialExchangeFailed {
                            execution_id: req.execution_id.clone(),
                            resolution_path: resolution_path_label.to_string(),
                            reason: err.to_string(),
                            failed_at: chrono::Utc::now(),
                        })?,
                    )
                    .await?;
                return Err(err);
            }
        };
        let (status, response) = self
            .http_client
            .execute(&operation.method, &url, &headers, Some(req.parameters))
            .await?;

        let before = response.to_string().len();
        let mut sliced = serde_json::Map::new();
        for field in &req.fields {
            let selected = jsonpath_lib::select(&response, field).map_err(|e| {
                GatewayError::Validation(format!("invalid explorer field '{field}': {e}"))
            })?;
            sliced.insert(
                field.clone(),
                Value::Array(selected.into_iter().cloned().collect()),
            );
        }
        let sliced_data = Value::Object(sliced);
        let after = sliced_data.to_string().len();

        self.event_store
            .append_event(
                "ExplorerRequestExecuted",
                &serde_json::to_value(GatewayEvent::ExplorerRequestExecuted {
                    execution_id: req.execution_id,
                    api_spec_id: req.api_spec_id,
                    operation_id: req.operation_id.clone(),
                    fields_requested: req.fields.clone(),
                    response_bytes_before_slice: before,
                    response_bytes_after_slice: after,
                    executed_at: chrono::Utc::now(),
                })?,
            )
            .await?;

        let hints = if req.include_hateoas_hints {
            Some(json!({
                "related_operations": spec.operations.keys().cloned().collect::<Vec<_>>()
            }))
        } else {
            None
        };

        Ok(ApiExplorerResponse {
            sliced_data,
            hints,
            operation_metadata: json!({"status": status}),
        })
    }
}
