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
            }],
            deny_list: vec![],
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
                },
                Capability {
                    tool_pattern: "credentials.*".to_string(),
                    path_allowlist: None,
                    command_allowlist: None,
                    subcommand_allowlist: None,
                    domain_allowlist: None,
                    max_response_size: None,
                },
            ],
            deny_list: vec![],
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
                },
                Capability {
                    tool_pattern: "credentials.*".to_string(),
                    path_allowlist: None,
                    command_allowlist: None,
                    subcommand_allowlist: None,
                    domain_allowlist: None,
                    max_response_size: None,
                },
            ],
            deny_list: vec![],
            tenant_id: None,
        },
    ]
}
