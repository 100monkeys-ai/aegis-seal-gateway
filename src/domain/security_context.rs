// Copyright (c) 2026 100monkeys.ai
// SPDX-License-Identifier: AGPL-3.0
//! # SecurityContext & Capability Model (BC-4, ADR-035, ADR-088 A1)
//!
//! Ported from the orchestrator's `domain::security_context` module.
//! The gateway enforces the same deny-list -> capability-scan -> default-deny
//! evaluation algorithm as the orchestrator.

use serde::{Deserialize, Serialize};
use serde_json::Value;
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
        }
    }
}

impl std::error::Error for PolicyViolation {}

// ── Capability ──

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
    /// If set, `cmd.run` tool calls must have the subcommand in this list.
    pub subcommand_allowlist: Option<Vec<String>>,
    /// If set, `web.*` tool calls must target a URL whose domain suffix matches
    /// one of these entries.
    pub domain_allowlist: Option<Vec<String>>,
    /// Maximum allowed response body size in bytes. `None` means unlimited.
    pub max_response_size: Option<u64>,
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
                let cmd_base = cmd_parts.first().unwrap_or(&"");

                if let Some(ref allowlist) = self.command_allowlist {
                    if !allowlist.contains(&cmd_base.to_string()) {
                        return Err(PolicyViolation::ToolNotAllowed {
                            tool_name: format!("cmd.run (command: {cmd})"),
                            allowed_tools: allowlist.clone(),
                        });
                    }
                }

                if let Some(ref sub_allowlist) = self.subcommand_allowlist {
                    if cmd_parts.len() > 1 {
                        let subcommand = cmd_parts[1];
                        if !sub_allowlist.contains(&subcommand.to_string()) {
                            return Err(PolicyViolation::ToolNotAllowed {
                                tool_name: format!("cmd.run (subcommand: {subcommand})"),
                                allowed_tools: sub_allowlist.clone(),
                            });
                        }
                    } else if !sub_allowlist.is_empty() {
                        return Err(PolicyViolation::ToolNotAllowed {
                            tool_name: format!("cmd.run (missing subcommand: {cmd})"),
                            allowed_tools: sub_allowlist.clone(),
                        });
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
        if self.tool_pattern == "*" {
            return true;
        }
        if self.tool_pattern.ends_with(".*") {
            let prefix = self.tool_pattern.trim_end_matches(".*");
            return tool_name.starts_with(prefix);
        }
        tool_name == self.tool_pattern
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
    /// Unique name identifying this context (e.g. `"default"`, `"zaru-free"`).
    pub name: String,
    /// Permitted tool capabilities. Evaluated in order; first match wins.
    pub capabilities: Vec<Capability>,
    /// Tool name patterns explicitly denied regardless of any matching capability.
    pub deny_list: Vec<String>,
    /// Human-readable description of this security context's purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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

/// Pattern matching for deny-list entries.
fn matches_pattern(pattern: &str, tool_name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.ends_with(".*") {
        let prefix = pattern.trim_end_matches(".*");
        return tool_name.starts_with(prefix);
    }
    pattern == tool_name
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
            command_allowlist: Some(vec!["cargo".to_string()]),
            subcommand_allowlist: Some(vec!["build".to_string(), "check".to_string()]),
            domain_allowlist: None,
            max_response_size: None,
        };
        assert!(cap
            .allows("cmd.run", &json!({"command": "cargo build"}))
            .is_ok());
        assert!(cap
            .allows("cmd.run", &json!({"command": "cargo check"}))
            .is_ok());
        assert!(cap
            .allows("cmd.run", &json!({"command": "npm install"}))
            .is_err());
        assert!(cap
            .allows("cmd.run", &json!({"command": "cargo publish"}))
            .is_err());
        assert!(cap.allows("cmd.run", &json!({"command": "cargo"})).is_err());
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
            }],
            deny_list: vec!["fs.delete".to_string()],
            description: None,
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
            }],
            deny_list: vec![],
            description: None,
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
            }],
            deny_list: vec![],
            description: None,
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
            }],
            deny_list: vec![],
            description: None,
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
            }],
            deny_list: vec![],
            description: None,
            tenant_id: None,
        };
        assert!(!ctx_without.allows_human_delegated_credentials());
    }
}
