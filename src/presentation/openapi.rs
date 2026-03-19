use utoipa::OpenApi;

use crate::application::ApiExplorerRequest;
use crate::domain::api_spec::{CredentialRef, CredentialResolutionPath};
use crate::domain::repositories::SmcpSessionStatus;
use crate::domain::smcp::SmcpEnvelope;
use crate::domain::tool_workflow::{StepErrorPolicy, WorkflowStep};
use crate::presentation::control_plane::{
    RegisterCliToolRequest, RegisterSpecRequest, RegisterWorkflowRequest,
    UpsertSecurityContextRequest, UpsertSmcpSessionRequest,
};

#[derive(OpenApi)]
#[openapi(
    info(title = "AEGIS SMCP Tooling Gateway"),
    paths(
        crate::presentation::control_plane::register_spec,
        crate::presentation::control_plane::list_specs,
        crate::presentation::control_plane::get_spec,
        crate::presentation::control_plane::delete_spec,
        crate::presentation::control_plane::register_workflow,
        crate::presentation::control_plane::list_workflows,
        crate::presentation::control_plane::get_workflow,
        crate::presentation::control_plane::delete_workflow,
        crate::presentation::control_plane::register_cli_tool,
        crate::presentation::control_plane::list_cli_tools,
        crate::presentation::control_plane::delete_cli_tool,
        crate::presentation::control_plane::list_tools,
        crate::presentation::control_plane::upsert_smcp_session,
        crate::presentation::control_plane::upsert_security_context,
        crate::presentation::control_plane::list_security_contexts,
        crate::presentation::control_plane::get_security_context,
        crate::presentation::invocation::invoke_smcp,
        crate::presentation::invocation::explore_api,
        crate::update_workflow,
    ),
    components(schemas(
        RegisterSpecRequest,
        RegisterWorkflowRequest,
        RegisterCliToolRequest,
        UpsertSmcpSessionRequest,
        UpsertSecurityContextRequest,
        SmcpEnvelope,
        ApiExplorerRequest,
        CredentialResolutionPath,
        CredentialRef,
        WorkflowStep,
        StepErrorPolicy,
        SmcpSessionStatus,
    )),
    tags(
        (name = "API Specs", description = "Register and manage OpenAPI specifications"),
        (name = "Workflows", description = "Register and manage ToolWorkflow macro-tools"),
        (name = "CLI Tools", description = "Register and manage ephemeral CLI tools"),
        (name = "Tools", description = "LLM-facing tool listing"),
        (name = "SMCP Sessions", description = "Manage SMCP agent sessions"),
        (name = "Security Contexts", description = "Manage named security permission boundaries"),
        (name = "Invocation", description = "SMCP-verified tool invocation"),
        (name = "Explorer", description = "API exploration with response slicing"),
    ),
    modifiers(&SecurityAddon),
)]
pub struct GatewayApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_jwt",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

pub fn openapi_spec() -> utoipa::openapi::OpenApi {
    let mut doc = GatewayApiDoc::openapi();
    doc.info.version = env!("CARGO_PKG_VERSION").to_string();
    doc.info.description = Some(env!("CARGO_PKG_DESCRIPTION").to_string());
    doc
}
