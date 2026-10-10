// Copyright (c) 2026 100monkeys.ai
// SPDX-License-Identifier: AGPL-3.0
//! # SecurityContext & Capability Model (BC-4, ADR-035, ADR-088 A1)
//!
//! Ported from the orchestrator's `domain::security_context` module.
//! The gateway enforces the same deny-list -> capability-scan -> default-deny
//! evaluation algorithm as the orchestrator.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

// ── PolicyViolation ──

/// Describes why a tool invocation was rejected by security policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyViolation {
    ToolNotAllowed {
        tool_name: String,
        allowed_tools: Vec<String>,
    },
    ToolDenied {
        tool_name: String,
    },
    PathOutsideBoundary {
        path: PathBuf,
        allowed_paths: Vec<PathBuf>,
    },
    DomainNotAllowed {
        domain: String,
        allowed_domains: Vec<String>,
    },
    CommandNotAllowed {
        command: String,
        allowed_commands: Vec<String>,
    },
    SubcommandNotAllowed {
        base_command: String,
        subcommand: String,
        allowed_subcommands: Vec<String>,
    },
    ConcurrentExecLimitExceeded {
        limit: u32,
    },
    OutputSizeLimitExceeded {
        actual_bytes: u64,
        max_bytes: u64,
    },
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyViolation::ToolNotAllowed {
                tool_name,
                allowed_tools,
            } => write!(
                f,
                "tool '{}' not allowed (permitted: {:?})",
                tool_name, allowed_tools
            ),
            PolicyViolation::ToolDenied { tool_name } => {
                write!(f, "tool '{}' explicitly denied", tool_name)
            }
            PolicyViolation::PathOutsideBoundary {
                path,
                allowed_paths,
            } => write!(
                f,
                "path '{}' outside allowed boundaries {:?}",
                path.display(),
                allowed_paths
            ),
            PolicyViolation::DomainNotAllowed {
                domain,
                allowed_domains,
            } => write!(
                f,
                "domain '{}' not in allowed domains {:?}",
                domain, allowed_domains
            ),
            PolicyViolation::CommandNotAllowed {
                command,
                allowed_commands,
            } => write!(
                f,
                "command '{}' not allowed; allowed: {:?}",
                command, allowed_commands
            ),
            PolicyViolation::SubcommandNotAllowed {
                base_command,
                subcommand,
                allowed_subcommands,
            } => write!(
                f,
                "subcommand '{}' not allowed for '{}'; allowed: {:?}",
                subcommand, base_command, allowed_subcommands
            ),
            PolicyViolation::ConcurrentExecLimitExceeded { limit } => {
                write!(f, "concurrent execution limit of {} exceeded", limit)
            }
            PolicyViolation::OutputSizeLimitExceeded {
                actual_bytes,
                max_bytes,
            } => write!(
                f,
                "output size {} bytes exceeds limit of {} bytes",
                actual_bytes, max_bytes
            ),
        }
    }
}

impl std::error::Error for PolicyViolation {}

// ── Capability ──

/// Per-capability rate limit configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RateLimit {
    /// Maximum number of calls allowed within the window.
    pub calls: u32,
    /// Window duration in seconds.
    pub per_seconds: u32,
}

/// Fine-grained MCP tool permission with optional constraints.
///
/// A value object within [`SecurityContext`]. Multiple capabilities can be
/// defined per context; the first one that matches a tool call grants access.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Capability {
    /// Tool name pattern. Supports `"*"`, prefix wildcard (`"fs.*"`), or exact match.
    pub tool_pattern: String,
    /// If set, `fs.*` / `filesystem.*` tool calls must have their `path` argument
    /// fall under one of these prefixes.
    #[schema(value_type = Option<Vec<String>>)]
    pub path_allowlist: Option<Vec<PathBuf>>,
    /// If set, `cmd.run` tool calls must use a command whose base executable name
    /// is in this list.
    pub command_allowlist: Option<Vec<String>>,
    /// If set, `cmd.run` tool calls must have the subcommand in the mapped Vec for the base command.
    pub subcommand_allowlist: Option<HashMap<String, Vec<String>>>,
    /// If set, `web.*` tool calls must target a URL whose domain suffix matches
    /// one of these entries.
    pub domain_allowlist: Option<Vec<String>>,
    /// Maximum allowed response body size in bytes. `None` means unlimited.
    pub max_response_size: Option<u64>,
    /// Optional per-capability rate limit. Enforcement is deferred to a later phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
}

impl Capability {
    /// Check whether a tool name matches this capability's tool pattern.
    pub fn matches_tool_name(&self, tool_name: &str) -> bool {
        self.matches_tool(tool_name)
    }

    /// Evaluate whether `tool_name` with `args` is permitted by this capability.
    ///
    /// Returns `Ok(())` if the call is allowed. On any constraint violation,
    /// returns an `Err(PolicyViolation)`.
    pub fn allows(&self, tool_name: &str, args: &Value) -> Result<(), PolicyViolation> {
        if !self.matches_tool(tool_name) {
            return Err(PolicyViolation::ToolNotAllowed {
                tool_name: tool_name.to_string(),
                allowed_tools: vec![self.tool_pattern.clone()],
            });
        }

        // Path constraints for filesystem tools
        if tool_name.starts_with("fs.") || tool_name.starts_with("filesystem.") {
            if let Some(ref allowlist) = self.path_allowlist {
                if let Some(path) = args.get("path").and_then(|p| p.as_str()) {
                    if !self.path_in_allowlist(path, allowlist) {
                        return Err(PolicyViolation::PathOutsideBoundary {
                            path: PathBuf::from(path),
                            allowed_paths: allowlist.clone(),
                        });
                    }
                }
            }
        }

        // Command constraints for cmd.run
        if tool_name == "cmd.run" {
            if let Some(cmd) = args.get("command").and_then(|c| c.as_str()) {
                let cmd_parts: Vec<&str> = cmd.split_whitespace().collect();
                let cmd_base = cmd_parts.first().copied().unwrap_or("");
                let subcommand = cmd_parts.get(1).copied();

                if let Some(ref allowlist) = self.command_allowlist {
                    if !allowlist.contains(&cmd_base.to_string()) {
                        return Err(PolicyViolation::CommandNotAllowed {
                            command: cmd_base.to_string(),
                            allowed_commands: allowlist.clone(),
                        });
                    }
                }

                if let Some(ref sub_map) = self.subcommand_allowlist {
                    if !sub_map.contains_key(cmd_base) {
                        return Err(PolicyViolation::CommandNotAllowed {
                            command: cmd_base.to_string(),
                            allowed_commands: sub_map.keys().cloned().collect(),
                        });
                    }
                    let allowed_subs = &sub_map[cmd_base];
                    if !allowed_subs.is_empty() {
                        match subcommand {
                            Some(sub) => {
                                if !allowed_subs.contains(&sub.to_string()) {
                                    return Err(PolicyViolation::SubcommandNotAllowed {
                                        base_command: cmd_base.to_string(),
                                        subcommand: sub.to_string(),
                                        allowed_subcommands: allowed_subs.clone(),
                                    });
                                }
                            }
                            None => {
                                return Err(PolicyViolation::SubcommandNotAllowed {
                                    base_command: cmd_base.to_string(),
                                    subcommand: String::new(),
                                    allowed_subcommands: allowed_subs.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Domain constraints for web tools
        if tool_name.starts_with("web.") || tool_name.starts_with("web-search.") {
            if let Some(ref allowlist) = self.domain_allowlist {
                if let Some(url) = args.get("url").and_then(|u| u.as_str()) {
                    let domain = Self::extract_domain(url);
                    if !allowlist.iter().any(|d| domain.ends_with(d)) {
                        return Err(PolicyViolation::DomainNotAllowed {
                            domain,
                            allowed_domains: allowlist.clone(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn matches_tool(&self, tool_name: &str) -> bool {
        matches_pattern(&self.tool_pattern, tool_name)
    }

    fn path_in_allowlist(&self, path: &str, allowlist: &[PathBuf]) -> bool {
        let path = PathBuf::from(path);
        for allowed_path in allowlist {
            if path.starts_with(allowed_path) {
                return true;
            }
        }
        false
    }

    fn extract_domain(url: &str) -> String {
        if let Ok(parsed_url) = url::Url::parse(url) {
            parsed_url.host_str().unwrap_or("").to_string()
        } else {
            "".to_string()
        }
    }
}

// ── SecurityContext ──

/// Named permission boundary for agent MCP tool access (BC-4, ADR-035).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// Unique name identifying this context (e.g. `"aegis-system-default"`, `"zaru-free"`).
    pub name: String,
    /// Permitted tool capabilities. Evaluated in order; first match wins.
    pub capabilities: Vec<Capability>,
    /// Tool name patterns explicitly denied regardless of any matching capability.
    pub deny_list: Vec<String>,
    /// Human-readable description of this security context's purpose (REQUIRED per spec).
    #[serde(default)]
    pub description: String,
    /// Optional tenant slug that owns this security context (ADR-056).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl SecurityContext {
    /// Evaluate whether a tool call is permitted by this `SecurityContext`.
    ///
    /// Applies the three-step policy algorithm:
    /// 1. Deny list check (explicit denies win over any capability)
    /// 2. Linear capability scan (first accepting capability returns `Ok(())`)
    /// 3. Default-deny (no capability matched -> `ToolNotAllowed`)
    pub fn evaluate(&self, tool_name: &str, args: &Value) -> Result<(), PolicyViolation> {
        // 1. Deny list (supports patterns via matches_pattern)
        for pattern in &self.deny_list {
            if matches_pattern(pattern, tool_name) {
                return Err(PolicyViolation::ToolDenied {
                    tool_name: tool_name.to_string(),
                });
            }
        }

        // 2. Capability scan
        for cap in &self.capabilities {
            if cap.matches_tool_name(tool_name) {
                return cap.allows(tool_name, args);
            }
        }

        // 3. Default deny
        Err(PolicyViolation::ToolNotAllowed {
            tool_name: tool_name.to_string(),
            allowed_tools: self
                .capabilities
                .iter()
                .map(|c| c.tool_pattern.clone())
                .collect(),
        })
    }

    /// Check whether a `credentials.*` capability exists (used for human-delegated
    /// credential resolution in the CLI and workflow engines).
    pub fn allows_human_delegated_credentials(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.tool_pattern == "*" || c.tool_pattern == "credentials.*")
    }
}

/// Tool-name pattern matching, shared by capabilities and deny-list entries.
///
/// `*` matches every name; `<prefix>.*` matches `<prefix>`, a dot, then at
/// least one more character (so `fs.*` admits `fs.read` and refuses
/// `fsx.read`, `fs.` and `fs`), as the orchestrator's matcher does; any other
/// pattern matches only the identical name.
pub(crate) fn matches_pattern(pattern: &str, tool_name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix(".*") {
        Some(prefix) => tool_name
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('.'))
            .is_some_and(|tool| !tool.is_empty()),
        None => pattern == tool_name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_capability_wildcard() {
        let cap = Capability {
            tool_pattern: "*".to_string(),
            path_allowlist: None,
            command_allowlist: None,
            subcommand_allowlist: None,
            domain_allowlist: None,
            max_response_size: None,
            rate_limit: None,
        };
        assert!(cap.allows("anything", &json!({})).is_ok());
    }

    #[test]
    fn test_capability_prefix_match() {
        let cap = Capability {
            tool_pattern: "fs.*".to_string(),
            path_allowlist: Some(vec!["/workspace".into()]),
            command_allowlist: None,
            subcommand_allowlist: None,
            domain_allowlist: None,
            max_response_size: None,
            rate_limit: None,
        };
        assert!(cap
            .allows("fs.read", &json!({"path": "/workspace/test.txt"}))
            .is_ok());
        assert!(cap
            .allows("fs.read", &json!({"path": "/etc/passwd"}))
            .is_err());
        assert!(cap.allows("cmd.run", &json!({})).is_err());
    }

    #[test]
    fn test_cmd_run_subcommand_allowlist() {
        let cap = Capability {
            tool_pattern: "cmd.run".to_string(),
            path_allowlist: None,
            command_allowlist: None,
            subcommand_allowlist: Some(HashMap::from([(
                "cargo".to_string(),
                vec!["build".to_string(), "check".to_string()],
            )])),
            domain_allowlist: None,
            max_response_size: None,
            rate_limit: None,
        };
        assert!(cap
            .allows("cmd.run", &json!({"command": "cargo build"}))
            .is_ok());
        assert!(cap
            .allows("cmd.run", &json!({"command": "cargo check"}))
            .is_ok());
        // npm is not a key in the subcommand_allowlist map
        assert!(matches!(
            cap.allows("cmd.run", &json!({"command": "npm install"})),
            Err(PolicyViolation::CommandNotAllowed { .. })
        ));
        // cargo publish — cargo is a valid key but publish is not in the allowed subs
        assert!(matches!(
            cap.allows("cmd.run", &json!({"command": "cargo publish"})),
            Err(PolicyViolation::SubcommandNotAllowed { .. })
        ));
        // cargo with no subcommand
        assert!(matches!(
            cap.allows("cmd.run", &json!({"command": "cargo"})),
            Err(PolicyViolation::SubcommandNotAllowed { .. })
        ));
    }

    #[test]
    fn test_security_context_evaluate_deny_list() {
        let ctx = SecurityContext {
            name: "test".to_string(),
            capabilities: vec![Capability {
                tool_pattern: "fs.*".to_string(),
                path_allowlist: Some(vec!["/workspace".into()]),
                command_allowlist: None,
                subcommand_allowlist: None,
                domain_allowlist: None,
                max_response_size: None,
                rate_limit: None,
            }],
            deny_list: vec!["fs.delete".to_string()],
            description: String::new(),
            tenant_id: None,
        };

        assert!(ctx
            .evaluate("fs.read", &json!({"path": "/workspace/test.txt"}))
            .is_ok());
        assert!(matches!(
            ctx.evaluate("fs.delete", &json!({"path": "/workspace/test.txt"})),
            Err(PolicyViolation::ToolDenied { .. })
        ));
    }

    #[test]
    fn test_family_pattern_refuses_a_name_sharing_its_prefix_without_the_dot() {
        let cap = Capability {
            tool_pattern: "fs.*".to_string(),
            path_allowlist: None,
            command_allowlist: None,
            subcommand_allowlist: None,
            domain_allowlist: None,
            max_response_size: None,
            rate_limit: None,
        };
        assert!(cap.matches_tool_name("fs.read"));
        assert!(cap.allows("fs.read", &json!({})).is_ok());
        assert!(!cap.matches_tool_name("fsx.read"));
        assert!(!cap.matches_tool_name("fs."));
        assert!(!cap.matches_tool_name("fs"));
        assert!(matches!(
            cap.allows("fsx.read", &json!({})),
            Err(PolicyViolation::ToolNotAllowed { .. })
        ));
    }

    #[test]
    fn test_deny_list_family_pattern_refuses_only_names_past_its_dot() {
        let ctx = SecurityContext {
            name: "test".to_string(),
            capabilities: vec![Capability {
                tool_pattern: "*".to_string(),
                path_allowlist: None,
                command_allowlist: None,
                subcommand_allowlist: None,
                domain_allowlist: None,
                max_response_size: None,
                rate_limit: None,
            }],
            deny_list: vec!["fs.*".to_string()],
            description: String::new(),
            tenant_id: None,
        };

        assert!(matches!(
            ctx.evaluate("fs.read", &json!({})),
            Err(PolicyViolation::ToolDenied { .. })
        ));
        assert!(ctx.evaluate("fsx.read", &json!({})).is_ok());
        assert!(ctx.evaluate("fs.", &json!({})).is_ok());
        assert!(ctx.evaluate("fs", &json!({})).is_ok());
    }

    #[test]
    fn test_security_context_evaluate_default_deny() {
        let ctx = SecurityContext {
            name: "test".to_string(),
            capabilities: vec![Capability {
                tool_pattern: "fs.read".to_string(),
                path_allowlist: None,
                command_allowlist: None,
                subcommand_allowlist: None,
                domain_allowlist: None,
                max_response_size: None,
                rate_limit: None,
            }],
            deny_list: vec![],
            description: String::new(),
            tenant_id: None,
        };

        assert!(ctx.evaluate("fs.read", &json!({})).is_ok());
        assert!(matches!(
            ctx.evaluate("cmd.run", &json!({})),
            Err(PolicyViolation::ToolNotAllowed { .. })
        ));
    }

    #[test]
    fn test_allows_human_delegated_credentials() {
        let ctx_with_wildcard = SecurityContext {
            name: "a".to_string(),
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
            description: String::new(),
            tenant_id: None,
        };
        assert!(ctx_with_wildcard.allows_human_delegated_credentials());

        let ctx_with_cred = SecurityContext {
            name: "b".to_string(),
            capabilities: vec![Capability {
                tool_pattern: "credentials.*".to_string(),
                path_allowlist: None,
                command_allowlist: None,
                subcommand_allowlist: None,
                domain_allowlist: None,
                max_response_size: None,
                rate_limit: None,
            }],
            deny_list: vec![],
            description: String::new(),
            tenant_id: None,
        };
        assert!(ctx_with_cred.allows_human_delegated_credentials());

        let ctx_without = SecurityContext {
            name: "c".to_string(),
            capabilities: vec![Capability {
                tool_pattern: "fs.*".to_string(),
                path_allowlist: None,
                command_allowlist: None,
                subcommand_allowlist: None,
                domain_allowlist: None,
                max_response_size: None,
                rate_limit: None,
            }],
            deny_list: vec![],
            description: String::new(),
            tenant_id: None,
        };
        assert!(!ctx_without.allows_human_delegated_credentials());
    }
}
