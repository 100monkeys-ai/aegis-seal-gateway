use serde::{Deserialize, Serialize};

/// Who a gateway call acts for (AEGIS ADR-132 G2): the execution's initiating
/// user and the calling agent, set by the orchestrator from the execution and
/// carried on its operator-authenticated call. Used for audit; a person's
/// credential, when the call needs one, comes resolved on the call itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActingIdentity {
    pub user_id: String,
    pub agent_id: String,
    /// Present when the execution runs inside a workflow.
    pub workflow_id: Option<String>,
}

impl ActingIdentity {
    pub fn new(user_id: String, agent_id: String, workflow_id: String) -> Self {
        Self {
            user_id,
            agent_id,
            workflow_id: if workflow_id.is_empty() {
                None
            } else {
                Some(workflow_id)
            },
        }
    }
}
