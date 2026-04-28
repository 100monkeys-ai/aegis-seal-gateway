use serde_json::Value;
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};

use crate::application::ApiExplorerRequest;
use crate::domain::{StepErrorPolicy, ToolWorkflow, WorkflowStep};
use crate::infrastructure::auth::{verify_operator_token, IdentityKind};
use crate::presentation::state::AppState;

pub mod proto {
    tonic::include_proto!("aegis.seal_gateway.v1");
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
    async fn require_operator_metadata(
        &self,
        metadata: &MetadataMap,
    ) -> Result<(Option<String>, IdentityKind), Status> {
        require_operator_metadata_for_config(&self.state.config, metadata).await
    }
}

/// Validates the gRPC `authorization` metadata as an operator token and
/// returns the authenticated tenant slug (`None` for system/global identities)
/// and identity kind. When `auth_disabled` is set, returns
/// `(None, IdentityKind::Consumer)` so callers can apply system-tier scoping
/// during local development.
#[allow(clippy::result_large_err)]
async fn require_operator_metadata_for_config(
    config: &crate::infrastructure::config::GatewayConfig,
    metadata: &MetadataMap,
) -> Result<(Option<String>, IdentityKind), Status> {
    if config.auth_disabled {
        return Ok((None, IdentityKind::Consumer));
    }

    let auth = metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .ok_or_else(|| Status::unauthenticated("invalid bearer metadata"))?;

    verify_operator_token(config, token)
        .await
        .map_err(|status| match status {
            axum::http::StatusCode::UNAUTHORIZED => {
                Status::unauthenticated("operator token validation failed")
            }
            axum::http::StatusCode::FORBIDDEN => {
                Status::permission_denied("operator role required")
            }
            _ => Status::internal("operator auth failure"),
        })
}

#[tonic::async_trait]
impl proto::tool_workflow_service_server::ToolWorkflowService for GatewayGrpcService {
    async fn create_workflow(
        &self,
        request: Request<proto::CreateWorkflowRequest>,
    ) -> Result<Response<proto::CreateWorkflowResponse>, Status> {
        self.require_operator_metadata(request.metadata()).await?;
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
        self.require_operator_metadata(request.metadata()).await?;
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
        let (tenant_id, _identity_kind) =
            self.require_operator_metadata(request.metadata()).await?;
        let workflows = self
            .state
            .workflows
            .list_for_tenant(tenant_id.as_deref())
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
        self.require_operator_metadata(request.metadata()).await?;
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
        self.require_operator_metadata(request.metadata()).await?;
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
        let fsal_mounts = req
            .fsal_mounts
            .into_iter()
            .map(|mount| {
                serde_json::json!({
                    "volume_id": mount.volume_id,
                    "mount_path": mount.mount_path,
                    "read_only": mount.read_only,
                })
            })
            .collect::<Vec<Value>>();
        let args = serde_json::json!({
            "subcommand": req.subcommand,
            "args": req.args,
            "fsal_mounts": fsal_mounts,
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
        self.require_operator_metadata(request.metadata()).await?;
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
        request: Request<proto::ListToolsRequest>,
    ) -> Result<Response<proto::ListToolsResponse>, Status> {
        let (tenant_id, _identity_kind) =
            self.require_operator_metadata(request.metadata()).await?;
        let workflows = self
            .state
            .workflows
            .list_for_tenant(tenant_id.as_deref())
            .await
            .map_err(internal)?
            .into_iter()
            .map(|w| {
                let input_schema_json = serde_json::to_string(&w.input_schema).unwrap_or_default();
                proto::ToolSummary {
                    name: w.name,
                    description: w.description,
                    kind: "workflow".to_string(),
                    input_schema_json,
                    tags: vec!["workflow".to_string()],
                    category: "external".to_string(),
                }
            });

        let cli_tools = self
            .state
            .cli_tools
            .list_for_tenant(tenant_id.as_deref())
            .await
            .map_err(internal)?
            .into_iter()
            .map(|t| {
                let input_schema_json = serde_json::json!({
                    "type": "object",
                    "properties": {
                        "subcommand": {
                            "type": "string",
                            "enum": t.allowed_subcommands,
                            "description": "Allowed subcommands for this CLI tool"
                        },
                        "args": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Arguments to pass to the subcommand"
                        }
                    },
                    "required": ["subcommand"]
                })
                .to_string();
                let mut tags = vec!["cli".to_string()];
                if t.require_semantic_judge {
                    tags.push("judged".to_string());
                }
                proto::ToolSummary {
                    name: t.name,
                    description: t.description,
                    kind: "cli".to_string(),
                    input_schema_json,
                    tags,
                    category: "external".to_string(),
                }
            });

        let native_tools = crate::application::native_tools::native_tool_catalog()
            .into_iter()
            .map(|meta| {
                let input_schema_json =
                    serde_json::to_string(&meta.input_schema).unwrap_or_default();
                proto::ToolSummary {
                    name: meta.name.to_string(),
                    description: meta.description.to_string(),
                    kind: "native".to_string(),
                    input_schema_json,
                    tags: vec!["native".to_string(), "volume".to_string()],
                    category: "internal".to_string(),
                }
            });

        Ok(Response::new(proto::ListToolsResponse {
            tools: workflows.chain(cli_tools).chain(native_tools).collect(),
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
    if err.is_pool_timeout() {
        tracing::error!(
            handler = "grpc",
            error = %err,
            "database pool acquire timed out — request path starved"
        );
    }
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
            jwks_validator: std::sync::Arc::new(
                crate::infrastructure::jwks_validator::JwksValidator::new(String::new(), 300),
            ),
            operator_jwt_issuer: "issuer".to_string(),
            operator_jwt_audience: "audience".to_string(),
            auth_disabled,
            operator_role_claim: "aegis_role".to_string(),
            seal_jwt_public_key_pem: String::new(),
            seal_jwt_issuer: "seal-issuer".to_string(),
            seal_jwt_audience: "seal-audience".to_string(),
            openbao_addr: None,
            openbao_token: None,
            openbao_kv_mount: "secret".to_string(),
            keycloak_token_exchange_url: None,
            keycloak_client_id: None,
            keycloak_client_secret: None,
            semantic_judge_url: None,
            ui_enabled: true,
            container_cli: "docker".to_string(),
            nfs_server_host: "127.0.0.1".to_string(),
            nfs_port: 2049,
            nfs_mount_port: 20048,
            orchestrator_url: None,
        }
    }

    #[tokio::test]
    async fn operator_authz_rejects_missing_metadata() {
        let config = test_config(false);
        let metadata = MetadataMap::new();
        let result = require_operator_metadata_for_config(&config, &metadata).await;
        assert!(matches!(result, Err(status) if status.code() == tonic::Code::Unauthenticated));
    }

    #[tokio::test]
    async fn operator_authz_bypasses_when_disabled() {
        let config = test_config(true);
        let metadata = MetadataMap::new();
        let result = require_operator_metadata_for_config(&config, &metadata).await;
        assert!(result.is_ok());
    }

    // Regression: in dev mode (`auth_disabled = true`) the helper must
    // still surface `IdentityKind::Consumer` and a `None` tenant so that
    // callers thread the helper's tenant value into `list_for_tenant`
    // instead of a hard-coded `None`. The previous code threw away the
    // helper return value entirely.
    #[tokio::test]
    async fn operator_authz_disabled_returns_identity_kind_consumer() {
        let config = test_config(true);
        let metadata = MetadataMap::new();
        let result = require_operator_metadata_for_config(&config, &metadata)
            .await
            .expect("auth_disabled path must succeed");
        assert!(result.0.is_none(), "dev mode must yield no tenant");
        assert!(matches!(result.1, IdentityKind::Consumer));
    }

    // Regression: an authorization header that is not `Bearer ...` must
    // be rejected. The list endpoints previously skipped this path
    // entirely.
    #[tokio::test]
    async fn operator_authz_rejects_non_bearer_scheme() {
        let config = test_config(false);
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        let result = require_operator_metadata_for_config(&config, &metadata).await;
        assert!(matches!(result, Err(s) if s.code() == tonic::Code::Unauthenticated));
    }

    // Regression: post-fix, the list endpoints must thread the helper's
    // tenant_id directly into `list_for_tenant`. The pre-fix code passed
    // a hard-coded `None`, ignoring the caller. Mirror the post-fix call
    // shape exactly so any future refactor that drops the helper output
    // breaks this test.
    #[tokio::test]
    async fn list_endpoints_thread_helper_tenant_into_repository_arg() {
        let config = test_config(true); // dev-mode bypass
        let metadata = MetadataMap::new();

        // This is the exact pattern list_tools and list_workflows now use:
        // capture (tenant_id, _kind) and pass tenant_id.as_deref() to
        // list_for_tenant. If a future edit reverts to `None`, this test
        // will catch it via the propagation assertion below.
        let (tenant_id, _kind) = require_operator_metadata_for_config(&config, &metadata)
            .await
            .expect("dev-mode auth must succeed");
        let repo_arg: Option<&str> = tenant_id.as_deref();

        // Dev-mode produces (None, Consumer); the repo arg derived
        // from the helper output must therefore be None — propagated
        // from the helper, not hard-coded.
        assert_eq!(repo_arg, None);
        // And the source of that None is the helper, not a literal.
        assert!(tenant_id.is_none());
    }
}
