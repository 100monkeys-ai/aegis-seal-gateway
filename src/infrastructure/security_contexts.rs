use crate::domain::{Capability, SecurityContext};

pub fn default_security_contexts() -> Vec<SecurityContext> {
    vec![
        SecurityContext {
            name: "default".to_string(),
            capabilities: vec![Capability {
                tool_pattern: "*".to_string(),
                path_allowlist: None,
                command_allowlist: None,
                subcommand_allowlist: None,
                domain_allowlist: None,
                max_response_size: None,
                rate_limit: None,
            }],
            deny_list: vec![],
            description: "Unrestricted default context allowing all tools".to_string(),
            tenant_id: None,
        },
        SecurityContext {
            name: "internal".to_string(),
            capabilities: vec![
                Capability {
                    tool_pattern: "*".to_string(),
                    path_allowlist: None,
                    command_allowlist: None,
                    subcommand_allowlist: None,
                    domain_allowlist: None,
                    max_response_size: None,
                    rate_limit: None,
                },
                Capability {
                    tool_pattern: "credentials.*".to_string(),
                    path_allowlist: None,
                    command_allowlist: None,
                    subcommand_allowlist: None,
                    domain_allowlist: None,
                    max_response_size: None,
                    rate_limit: None,
                },
            ],
            deny_list: vec![],
            description: "Internal platform context with full tool and credential access"
                .to_string(),
            tenant_id: None,
        },
        SecurityContext {
            name: "zaru-free".to_string(),
            capabilities: vec![
                Capability {
                    tool_pattern: "*".to_string(),
                    path_allowlist: None,
                    command_allowlist: None,
                    subcommand_allowlist: None,
                    domain_allowlist: None,
                    max_response_size: None,
                    rate_limit: None,
                },
                Capability {
                    tool_pattern: "credentials.*".to_string(),
                    path_allowlist: None,
                    command_allowlist: None,
                    subcommand_allowlist: None,
                    domain_allowlist: None,
                    max_response_size: None,
                    rate_limit: None,
                },
            ],
            deny_list: vec![],
            description: "Zaru free-tier context with all tools and human-delegated credentials"
                .to_string(),
            tenant_id: None,
        },
    ]
}
