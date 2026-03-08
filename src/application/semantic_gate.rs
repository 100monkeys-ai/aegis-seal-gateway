use crate::domain::EphemeralCliTool;

#[derive(Debug, Clone)]
pub enum SemanticDecision {
    Allowed,
    Rejected(String),
}

#[derive(Clone)]
pub struct SemanticGate;

impl SemanticGate {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(
        &self,
        tool: &EphemeralCliTool,
        subcommand: &str,
        args: &[String],
    ) -> SemanticDecision {
        if !tool.allowed_subcommands.iter().any(|s| s == subcommand) {
            return SemanticDecision::Rejected(format!(
                "subcommand '{subcommand}' is not in allowed_subcommands"
            ));
        }

        if tool.require_semantic_judge {
            let joined = args.join(" ");
            if joined.contains("-destroy") || joined.contains(" destroy ") {
                return SemanticDecision::Rejected(
                    "semantic judge rejected destructive command intent".to_string(),
                );
            }
        }

        SemanticDecision::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::EphemeralCliTool;

    #[test]
    fn rejects_destroy_intent_when_judge_enabled() {
        let gate = SemanticGate::new();
        let tool = EphemeralCliTool {
            name: "terraform".to_string(),
            description: "infra".to_string(),
            docker_image: "mcp/terraform:1.9".to_string(),
            allowed_subcommands: vec!["apply".to_string()],
            require_semantic_judge: true,
            default_timeout_seconds: 60,
            registry_credentials_ref: None,
        };
        let decision = gate.evaluate(
            &tool,
            "apply",
            &["-destroy".to_string(), "-auto-approve".to_string()],
        );
        assert!(matches!(decision, SemanticDecision::Rejected(_)));
    }
}
