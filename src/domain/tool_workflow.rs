use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::domain::api_spec::ApiSpecId;
use crate::infrastructure::errors::GatewayError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkflowId(pub Uuid);

impl WorkflowId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for WorkflowId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolWorkflow {
    pub id: WorkflowId,
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub api_spec_id: ApiSpecId,
    pub steps: Vec<WorkflowStep>,
    pub created_at: DateTime<Utc>,
}

impl ToolWorkflow {
    pub fn new(
        name: String,
        description: String,
        input_schema: serde_json::Value,
        api_spec_id: ApiSpecId,
        steps: Vec<WorkflowStep>,
    ) -> Result<Self, GatewayError> {
        if name.trim().is_empty() {
            return Err(GatewayError::Validation(
                "ToolWorkflow.name cannot be empty".to_string(),
            ));
        }
        if steps.is_empty() {
            return Err(GatewayError::Validation(
                "ToolWorkflow.steps cannot be empty".to_string(),
            ));
        }
        if input_schema.get("type").and_then(|v| v.as_str()) != Some("object") {
            return Err(GatewayError::Validation(
                "ToolWorkflow.input_schema must be a JSON schema object".to_string(),
            ));
        }

        Ok(Self {
            id: WorkflowId::new(),
            name,
            description,
            input_schema,
            api_spec_id,
            steps,
            created_at: Utc::now(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WorkflowStep {
    pub name: String,
    pub operation_id: String,
    pub body_template: String,
    pub extractors: HashMap<String, String>,
    pub on_error: StepErrorPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub enum StepErrorPolicy {
    AbortWorkflow,
    Continue,
    RetryN(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolWorkflowSummary {
    pub id: WorkflowId,
    pub name: String,
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ApiSpecId;

    #[test]
    fn workflow_requires_non_empty_steps() {
        let result = ToolWorkflow::new(
            "name".to_string(),
            "desc".to_string(),
            serde_json::json!({"type":"object"}),
            ApiSpecId::new(),
            Vec::new(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn workflow_requires_object_schema() {
        let result = ToolWorkflow::new(
            "name".to_string(),
            "desc".to_string(),
            serde_json::json!({"type":"string"}),
            ApiSpecId::new(),
            vec![WorkflowStep {
                name: "s1".to_string(),
                operation_id: "op".to_string(),
                body_template: "{}".to_string(),
                extractors: std::collections::HashMap::new(),
                on_error: StepErrorPolicy::AbortWorkflow,
            }],
        );
        assert!(result.is_err());
    }
}
