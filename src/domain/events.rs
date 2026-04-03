use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::{ApiSpecId, WorkflowId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GatewayEvent {
    ApiSpecRegistered {
        spec_id: ApiSpecId,
        name: String,
        registered_by: String,
        registered_at: DateTime<Utc>,
    },
    WorkflowRegistered {
        workflow_id: WorkflowId,
        name: String,
        step_count: usize,
        registered_by: String,
        registered_at: DateTime<Utc>,
    },
    CliToolRegistered {
        name: String,
        docker_image: String,
        registered_at: DateTime<Utc>,
    },
    WorkflowInvocationStarted {
        workflow_id: WorkflowId,
        execution_id: String,
        name: String,
        started_at: DateTime<Utc>,
    },
    WorkflowStepExecuted {
        workflow_id: WorkflowId,
        execution_id: String,
        step_name: String,
        http_status: u16,
        duration_ms: u64,
        executed_at: DateTime<Utc>,
    },
    WorkflowInvocationCompleted {
        workflow_id: WorkflowId,
        execution_id: String,
        total_steps: usize,
        duration_ms: u64,
        completed_at: DateTime<Utc>,
    },
    WorkflowInvocationFailed {
        workflow_id: WorkflowId,
        execution_id: String,
        failed_step: String,
        reason: String,
        failed_at: DateTime<Utc>,
    },
    ExplorerRequestExecuted {
        execution_id: String,
        api_spec_id: ApiSpecId,
        operation_id: String,
        fields_requested: Vec<String>,
        response_bytes_before_slice: usize,
        response_bytes_after_slice: usize,
        executed_at: DateTime<Utc>,
    },
    CliToolInvocationStarted {
        execution_id: String,
        tool_name: String,
        docker_image: String,
        command: String,
        args: Vec<String>,
        tenant_id: Option<String>,
        started_at: DateTime<Utc>,
    },
    CliToolInvocationCompleted {
        execution_id: String,
        tool_name: String,
        exit_code: i32,
        stdout_bytes: usize,
        stderr_bytes: usize,
        duration_ms: u64,
        completed_at: DateTime<Utc>,
    },
    CliToolSemanticRejected {
        execution_id: String,
        tool_name: String,
        requested_subcommand: String,
        rejection_reason: String,
        security_context: String,
        rejected_at: DateTime<Utc>,
    },
    CredentialExchangeCompleted {
        execution_id: String,
        resolution_path: String,
        target_service: String,
        completed_at: DateTime<Utc>,
    },
    CredentialExchangeFailed {
        execution_id: String,
        resolution_path: String,
        reason: String,
        failed_at: DateTime<Utc>,
    },
}
