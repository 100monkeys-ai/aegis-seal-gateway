use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use handlebars::Handlebars;
use serde_json::{json, Value};

use crate::application::credential_resolver::CredentialResolver;
use crate::domain::{
    ApiSpecRepository, GatewayEvent, StepErrorPolicy, ToolWorkflow, ToolWorkflowRepository,
    WorkflowId,
};
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::http_client::HttpClient;
use crate::infrastructure::persistence::EventStore;

#[derive(Clone)]
pub struct WorkflowEngine {
    workflows: Arc<dyn ToolWorkflowRepository>,
    specs: Arc<dyn ApiSpecRepository>,
    http_client: HttpClient,
    credential_resolver: CredentialResolver,
    event_store: Arc<dyn EventStore>,
}

impl WorkflowEngine {
    pub fn new(
        workflows: Arc<dyn ToolWorkflowRepository>,
        specs: Arc<dyn ApiSpecRepository>,
        http_client: HttpClient,
        credential_resolver: CredentialResolver,
        event_store: Arc<dyn EventStore>,
    ) -> Self {
        Self {
            workflows,
            specs,
            http_client,
            credential_resolver,
            event_store,
        }
    }

    pub async fn invoke_by_name(
        &self,
        execution_id: &str,
        name: &str,
        input: Value,
        zaru_user_token: Option<&str>,
    ) -> Result<Value, GatewayError> {
        let workflow = self
            .workflows
            .find_by_name(name)
            .await?
            .ok_or_else(|| GatewayError::NotFound(format!("workflow '{name}' not found")))?;
        self.invoke(execution_id, &workflow, input, zaru_user_token)
            .await
    }

    pub async fn invoke(
        &self,
        execution_id: &str,
        workflow: &ToolWorkflow,
        input: Value,
        zaru_user_token: Option<&str>,
    ) -> Result<Value, GatewayError> {
        let started = Instant::now();
        self.event_store
            .append_event(
                "WorkflowInvocationStarted",
                &serde_json::to_value(GatewayEvent::WorkflowInvocationStarted {
                    workflow_id: workflow.id,
                    execution_id: execution_id.to_string(),
                    name: workflow.name.clone(),
                    started_at: chrono::Utc::now(),
                })?,
            )
            .await?;

        let spec = self
            .specs
            .find_by_id(workflow.api_spec_id)
            .await?
            .ok_or_else(|| GatewayError::NotFound("api spec not found for workflow".to_string()))?;

        let resolution_path_label = match &spec.credential_path {
            crate::domain::CredentialResolutionPath::SystemJit { .. } => "system_jit",
            crate::domain::CredentialResolutionPath::HumanDelegated { .. } => "human_delegated",
            crate::domain::CredentialResolutionPath::StaticRef(_) => "static_ref",
        };
        let target_service = match &spec.credential_path {
            crate::domain::CredentialResolutionPath::HumanDelegated { target_service } => {
                target_service.clone()
            }
            _ => "unknown".to_string(),
        };
        let credential_headers = match self
            .credential_resolver
            .resolve(&spec.credential_path, zaru_user_token)
            .await
        {
            Ok(headers) => {
                self.event_store
                    .append_event(
                        "CredentialExchangeCompleted",
                        &serde_json::to_value(GatewayEvent::CredentialExchangeCompleted {
                            execution_id: execution_id.to_string(),
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
                            execution_id: execution_id.to_string(),
                            resolution_path: resolution_path_label.to_string(),
                            reason: err.to_string(),
                            failed_at: chrono::Utc::now(),
                        })?,
                    )
                    .await?;
                return Err(err);
            }
        };

        let mut state = HashMap::<String, Value>::new();
        state.insert("input".to_string(), input);

        let handlebars = Handlebars::new();
        let mut last_response = json!({});

        for step in &workflow.steps {
            let op = spec.operations.get(&step.operation_id).ok_or_else(|| {
                GatewayError::Validation(format!(
                    "operation '{}' not found in api spec",
                    step.operation_id
                ))
            })?;

            let step_start = Instant::now();

            let body_context = json!({ "state": state, "input": state.get("input").cloned().unwrap_or(json!({})) });
            let rendered_body = handlebars.render_template(&step.body_template, &body_context)?;
            let body_value: Value = serde_json::from_str(&rendered_body).map_err(|e| {
                GatewayError::Validation(format!(
                    "step '{}' template did not render valid JSON: {e}",
                    step.name
                ))
            })?;

            let url = format!("{}{}", spec.base_url.trim_end_matches('/'), op.path);
            let step_result = self
                .http_client
                .execute(
                    &op.method,
                    &url,
                    &credential_headers,
                    Some(body_value.clone()),
                )
                .await;

            match step_result {
                Ok((status, response)) => {
                    last_response = response.clone();
                    self.extract_state(
                        step.name.as_str(),
                        &response,
                        &step.extractors,
                        &mut state,
                    )?;

                    self.event_store
                        .append_event(
                            "WorkflowStepExecuted",
                            &serde_json::to_value(GatewayEvent::WorkflowStepExecuted {
                                workflow_id: workflow.id,
                                execution_id: execution_id.to_string(),
                                step_name: step.name.clone(),
                                http_status: status,
                                duration_ms: step_start.elapsed().as_millis() as u64,
                                executed_at: chrono::Utc::now(),
                            })?,
                        )
                        .await?;
                }
                Err(err) => {
                    let should_abort = match step.on_error {
                        StepErrorPolicy::AbortWorkflow => true,
                        StepErrorPolicy::Continue => false,
                        StepErrorPolicy::RetryN(retries) => {
                            let mut attempt = 0u8;
                            let mut success = false;
                            while attempt < retries {
                                attempt += 1;
                                if let Ok((_, response)) = self
                                    .http_client
                                    .execute(
                                        &op.method,
                                        &url,
                                        &credential_headers,
                                        Some(body_value.clone()),
                                    )
                                    .await
                                {
                                    last_response = response;
                                    success = true;
                                    break;
                                }
                            }
                            !success
                        }
                    };

                    if should_abort {
                        self.event_store
                            .append_event(
                                "WorkflowInvocationFailed",
                                &serde_json::to_value(GatewayEvent::WorkflowInvocationFailed {
                                    workflow_id: workflow.id,
                                    execution_id: execution_id.to_string(),
                                    failed_step: step.name.clone(),
                                    reason: err.to_string(),
                                    failed_at: chrono::Utc::now(),
                                })?,
                            )
                            .await?;
                        return Err(err);
                    }
                }
            }
        }

        self.event_store
            .append_event(
                "WorkflowInvocationCompleted",
                &serde_json::to_value(GatewayEvent::WorkflowInvocationCompleted {
                    workflow_id: workflow.id,
                    execution_id: execution_id.to_string(),
                    total_steps: workflow.steps.len(),
                    duration_ms: started.elapsed().as_millis() as u64,
                    completed_at: chrono::Utc::now(),
                })?,
            )
            .await?;

        Ok(json!({
            "workflow_id": workflow.id.0,
            "execution_id": execution_id,
            "result": last_response,
            "state": state
        }))
    }

    fn extract_state(
        &self,
        step_name: &str,
        response: &Value,
        extractors: &HashMap<String, String>,
        state: &mut HashMap<String, Value>,
    ) -> Result<(), GatewayError> {
        for (key, path) in extractors {
            let values = jsonpath_lib::select(response, path).map_err(|e| {
                GatewayError::Validation(format!("invalid extractor '{path}': {e}"))
            })?;
            if let Some(first) = values.first() {
                state.insert(format!("{step_name}.{key}"), (*first).clone());
            }
        }
        Ok(())
    }

    pub async fn find_workflow_by_id(
        &self,
        id: WorkflowId,
    ) -> Result<Option<ToolWorkflow>, GatewayError> {
        self.workflows.find_by_id(id).await
    }
}
