use serde_json::Value;
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};

use crate::application::ApiExplorerRequest;
use crate::domain::{StepErrorPolicy, ToolWorkflow, WorkflowStep};
use crate::infrastructure::auth::verify_operator_token;
use crate::presentation::state::AppState;

pub mod proto {
    tonic::include_proto!("aegis.smcp_gateway.v1");
}

#[derive(Clone)]
pub struct GatewayGrpcService {
    state: AppState,
}

impl GatewayGrpcService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    #[allow(clippy::result_large_err)]
    fn require_operator_metadata(&self, metadata: &MetadataMap) -> Result<(), Status> {
        require_operator_metadata_for_config(&self.state.config, metadata)
    }
}

#[allow(clippy::result_large_err)]
fn require_operator_metadata_for_config(
    config: &crate::infrastructure::config::GatewayConfig,
    metadata: &MetadataMap,
) -> Result<(), Status> {
    if config.auth_disabled {
        return Ok(());
    }

    let auth = metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .ok_or_else(|| Status::unauthenticated("invalid bearer metadata"))?;

    verify_operator_token(config, token).map_err(|status| match status {
        axum::http::StatusCode::UNAUTHORIZED => {
            Status::unauthenticated("operator token validation failed")
        }
        axum::http::StatusCode::FORBIDDEN => Status::permission_denied("operator role required"),
        _ => Status::internal("operator auth failure"),
    })?;

    Ok(())
}

#[tonic::async_trait]
impl proto::tool_workflow_service_server::ToolWorkflowService for GatewayGrpcService {
    async fn create_workflow(
        &self,
        request: Request<proto::CreateWorkflowRequest>,
    ) -> Result<Response<proto::CreateWorkflowResponse>, Status> {
        self.require_operator_metadata(request.metadata())?;
        let workflow = request
            .into_inner()
            .workflow
            .ok_or_else(|| Status::invalid_argument("workflow is required"))?;

        let api_spec_id = parse_uuid_wrapped(&workflow.api_spec_id).map_err(invalid)?;
        let steps = workflow
            .steps
            .into_iter()
            .map(parse_step)
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid)?;
        let schema: Value = serde_json::from_str(&workflow.input_schema_json)
            .map_err(|e| Status::invalid_argument(format!("invalid input_schema_json: {e}")))?;
        ensure_operations_exist(&self.state, api_spec_id, &steps)
            .await
            .map_err(invalid)?;

        let wf = ToolWorkflow::new(
            workflow.name,
            workflow.description,
            schema,
            api_spec_id,
            steps,
        )
        .map_err(invalid)?;
        let id = wf.id.0.to_string();
        self.state.workflows.save(wf).await.map_err(internal)?;

        Ok(Response::new(proto::CreateWorkflowResponse {
            workflow_id: id,
        }))
    }

    async fn get_workflow(
        &self,
        request: Request<proto::GetWorkflowRequest>,
    ) -> Result<Response<proto::GetWorkflowResponse>, Status> {
        self.require_operator_metadata(request.metadata())?;
        let id = parse_uuid_wrapped(&request.into_inner().workflow_id).map_err(invalid)?;
        let workflow = self
            .state
            .invocation_service
            .find_workflow_by_id(crate::domain::WorkflowId(id.0))
            .await
            .map_err(internal)?
            .ok_or_else(|| Status::not_found("workflow not found"))?;

        Ok(Response::new(proto::GetWorkflowResponse {
            workflow: Some(to_proto_workflow(&workflow)),
        }))
    }

    async fn list_workflows(
        &self,
        request: Request<proto::ListWorkflowsRequest>,
    ) -> Result<Response<proto::ListWorkflowsResponse>, Status> {
        self.require_operator_metadata(request.metadata())?;
        let workflows = self
            .state
            .workflows
            .list_all()
            .await
            .map_err(internal)?
            .into_iter()
            .map(|w| proto::WorkflowSummary {
                id: w.id.0.to_string(),
                name: w.name,
                description: w.description,
            })
            .collect();

        Ok(Response::new(proto::ListWorkflowsResponse { workflows }))
    }

    async fn update_workflow(
        &self,
        request: Request<proto::UpdateWorkflowRequest>,
    ) -> Result<Response<proto::UpdateWorkflowResponse>, Status> {
        self.require_operator_metadata(request.metadata())?;
        let workflow = request
            .into_inner()
            .workflow
            .ok_or_else(|| Status::invalid_argument("workflow is required"))?;

        let workflow_id = parse_uuid(&workflow.id).map_err(invalid)?;
        let api_spec_id = parse_uuid_wrapped(&workflow.api_spec_id).map_err(invalid)?;
        let steps = workflow
            .steps
            .into_iter()
            .map(parse_step)
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid)?;
        let schema: Value = serde_json::from_str(&workflow.input_schema_json)
            .map_err(|e| Status::invalid_argument(format!("invalid input_schema_json: {e}")))?;
        ensure_operations_exist(&self.state, api_spec_id, &steps)
            .await
            .map_err(invalid)?;

        let mut wf = ToolWorkflow::new(
            workflow.name,
            workflow.description,
            schema,
            api_spec_id,
            steps,
        )
        .map_err(invalid)?;
        wf.id = crate::domain::WorkflowId(workflow_id);

        self.state.workflows.save(wf).await.map_err(internal)?;

        Ok(Response::new(proto::UpdateWorkflowResponse {
            updated: true,
        }))
    }

    async fn delete_workflow(
        &self,
        request: Request<proto::DeleteWorkflowRequest>,
    ) -> Result<Response<proto::DeleteWorkflowResponse>, Status> {
        self.require_operator_metadata(request.metadata())?;
        let id = parse_uuid(&request.into_inner().workflow_id).map_err(invalid)?;
        self.state
            .workflows
            .delete(crate::domain::WorkflowId(id))
            .await
            .map_err(internal)?;
        Ok(Response::new(proto::DeleteWorkflowResponse {
            deleted: true,
        }))
    }
}

#[tonic::async_trait]
impl proto::gateway_invocation_service_server::GatewayInvocationService for GatewayGrpcService {
    async fn invoke_workflow(
        &self,
        request: Request<proto::InvokeWorkflowRequest>,
    ) -> Result<Response<proto::InvokeWorkflowResponse>, Status> {
        let req = request.into_inner();
        let input: Value = serde_json::from_str(&req.input_json)
            .map_err(|e| Status::invalid_argument(format!("invalid input_json: {e}")))?;

        let result = self
            .state
            .invocation_service
            .invoke_internal(
                &req.execution_id,
                &req.workflow_name,
                input,
                if req.zaru_user_token.is_empty() {
                    None
                } else {
                    Some(req.zaru_user_token.as_str())
                },
            )
            .await
            .map_err(internal)?;

        Ok(Response::new(proto::InvokeWorkflowResponse {
            result_json: serde_json::to_string(&result)
                .map_err(|e| Status::internal(e.to_string()))?,
        }))
    }

    async fn invoke_cli(
        &self,
        request: Request<proto::InvokeCliRequest>,
    ) -> Result<Response<proto::InvokeCliResponse>, Status> {
        let req = request.into_inner();
        let args = serde_json::json!({
            "subcommand": req.subcommand,
            "args": req.args,
            "fsal_volume_id": req.fsal_volume_id,
        });

        let result = self
            .state
            .invocation_service
            .invoke_internal(&req.execution_id, &req.tool_name, args, None)
            .await
            .map_err(internal)?;

        Ok(Response::new(proto::InvokeCliResponse {
            exit_code: result
                .get("exit_code")
                .and_then(|v| v.as_i64())
                .unwrap_or(-1) as i32,
            stdout: result
                .get("stdout")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            stderr: result
                .get("stderr")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }))
    }

    async fn explore_api(
        &self,
        request: Request<proto::ExploreApiRequest>,
    ) -> Result<Response<proto::ExploreApiResponse>, Status> {
        self.require_operator_metadata(request.metadata())?;
        let req = request.into_inner();
        let parameters: Value = serde_json::from_str(&req.parameters_json)
            .map_err(|e| Status::invalid_argument(format!("invalid parameters_json: {e}")))?;

        let result = self
            .state
            .explorer_service
            .explore(
                ApiExplorerRequest {
                    execution_id: req.execution_id,
                    api_spec_id: parse_uuid_wrapped(&req.api_spec_id).map_err(invalid)?,
                    operation_id: req.operation_id,
                    parameters,
                    fields: req.fields,
                    include_hateoas_hints: req.include_hateoas_hints,
                },
                None,
            )
            .await
            .map_err(internal)?;

        Ok(Response::new(proto::ExploreApiResponse {
            sliced_data_json: serde_json::to_string(&result.sliced_data)
                .map_err(|e| Status::internal(e.to_string()))?,
            hints_json: serde_json::to_string(&result.hints)
                .map_err(|e| Status::internal(e.to_string()))?,
            operation_metadata_json: serde_json::to_string(&result.operation_metadata)
                .map_err(|e| Status::internal(e.to_string()))?,
        }))
    }

    async fn list_tools(
        &self,
        _request: Request<proto::ListToolsRequest>,
    ) -> Result<Response<proto::ListToolsResponse>, Status> {
        let workflows = self
            .state
            .workflows
            .list_all()
            .await
            .map_err(internal)?
            .into_iter()
            .map(|w| proto::ToolSummary {
                name: w.name,
                description: w.description,
                kind: "workflow".to_string(),
            });

        let cli_tools = self
            .state
            .cli_tools
            .list_all()
            .await
            .map_err(internal)?
            .into_iter()
            .map(|t| proto::ToolSummary {
                name: t.name,
                description: t.description,
                kind: "cli".to_string(),
            });

        Ok(Response::new(proto::ListToolsResponse {
            tools: workflows.chain(cli_tools).collect(),
        }))
    }
}

fn parse_step(
    step: proto::WorkflowStep,
) -> Result<WorkflowStep, crate::infrastructure::errors::GatewayError> {
    let on_error = match step.on_error.as_str() {
        "AbortWorkflow" => StepErrorPolicy::AbortWorkflow,
        "Continue" => StepErrorPolicy::Continue,
        value if value.starts_with("RetryN(") && value.ends_with(')') => {
            let count = value
                .trim_start_matches("RetryN(")
                .trim_end_matches(')')
                .parse::<u8>()
                .map_err(|e| {
                    crate::infrastructure::errors::GatewayError::Validation(format!(
                        "invalid RetryN on_error value: {e}"
                    ))
                })?;
            StepErrorPolicy::RetryN(count)
        }
        _ => StepErrorPolicy::AbortWorkflow,
    };

    Ok(WorkflowStep {
        name: step.name,
        operation_id: step.operation_id,
        body_template: step.body_template,
        extractors: step.extractors,
        on_error,
    })
}

fn to_proto_workflow(workflow: &ToolWorkflow) -> proto::Workflow {
    let steps = workflow
        .steps
        .iter()
        .map(|step| proto::WorkflowStep {
            name: step.name.clone(),
            operation_id: step.operation_id.clone(),
            body_template: step.body_template.clone(),
            extractors: step.extractors.clone(),
            on_error: match step.on_error {
                StepErrorPolicy::AbortWorkflow => "AbortWorkflow".to_string(),
                StepErrorPolicy::Continue => "Continue".to_string(),
                StepErrorPolicy::RetryN(n) => format!("RetryN({n})"),
            },
        })
        .collect();

    proto::Workflow {
        id: workflow.id.0.to_string(),
        name: workflow.name.clone(),
        description: workflow.description.clone(),
        api_spec_id: workflow.api_spec_id.0.to_string(),
        input_schema_json: workflow.input_schema.to_string(),
        steps,
    }
}

fn parse_uuid(input: &str) -> Result<uuid::Uuid, crate::infrastructure::errors::GatewayError> {
    uuid::Uuid::parse_str(input).map_err(|e| {
        crate::infrastructure::errors::GatewayError::Validation(format!("invalid uuid: {e}"))
    })
}

fn parse_uuid_wrapped(
    input: &str,
) -> Result<crate::domain::ApiSpecId, crate::infrastructure::errors::GatewayError> {
    Ok(crate::domain::ApiSpecId(parse_uuid(input)?))
}

async fn ensure_operations_exist(
    state: &AppState,
    api_spec_id: crate::domain::ApiSpecId,
    steps: &[WorkflowStep],
) -> Result<(), crate::infrastructure::errors::GatewayError> {
    let spec = state.specs.find_by_id(api_spec_id).await?.ok_or_else(|| {
        crate::infrastructure::errors::GatewayError::Validation(
            "api_spec_id does not reference a registered ApiSpec".to_string(),
        )
    })?;
    for step in steps {
        if !spec.operations.contains_key(&step.operation_id) {
            return Err(crate::infrastructure::errors::GatewayError::Validation(
                format!(
                    "workflow step '{}' references unknown operation_id '{}'",
                    step.name, step.operation_id
                ),
            ));
        }
    }
    Ok(())
}

fn invalid(err: crate::infrastructure::errors::GatewayError) -> Status {
    Status::invalid_argument(err.to_string())
}

fn internal(err: crate::infrastructure::errors::GatewayError) -> Status {
    Status::internal(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::config::GatewayConfig;

    fn test_config(auth_disabled: bool) -> GatewayConfig {
        GatewayConfig {
            bind_addr: "127.0.0.1:8089".to_string(),
            grpc_bind_addr: "127.0.0.1:50055".to_string(),
            database_url: "sqlite::memory:".to_string(),
            operator_jwt_public_key_pem: String::new(),
            operator_jwt_issuer: "issuer".to_string(),
            operator_jwt_audience: "audience".to_string(),
            auth_disabled,
            smcp_jwt_public_key_pem: String::new(),
            smcp_jwt_issuer: "smcp-issuer".to_string(),
            smcp_jwt_audience: "smcp-audience".to_string(),
            openbao_addr: None,
            openbao_token: None,
            openbao_kv_mount: "secret".to_string(),
            keycloak_token_exchange_url: None,
            keycloak_client_id: None,
            keycloak_client_secret: None,
            semantic_judge_url: None,
            nfs_server_host: "127.0.0.1".to_string(),
            nfs_port: 2049,
            nfs_mount_port: 20048,
        }
    }

    #[test]
    fn operator_authz_rejects_missing_metadata() {
        let config = test_config(false);
        let metadata = MetadataMap::new();
        let result = require_operator_metadata_for_config(&config, &metadata);
        assert!(matches!(result, Err(status) if status.code() == tonic::Code::Unauthenticated));
    }

    #[test]
    fn operator_authz_bypasses_when_disabled() {
        let config = test_config(true);
        let metadata = MetadataMap::new();
        let result = require_operator_metadata_for_config(&config, &metadata);
        assert!(result.is_ok());
    }
}
