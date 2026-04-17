//! Native built-in tools that proxy directly to the orchestrator REST API.
//!
//! These tools are statically compiled into the gateway and require no
//! database registration. They forward calls to the orchestrator `/v1/volumes`
//! endpoints, attaching the caller's bearer token (user JWT or SEAL-issued
//! token) so the orchestrator can enforce per-tenant authorization.

use serde_json::{json, Value};

use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::http_client::HttpClient;

/// Metadata for a single native tool, used by the tool-listing endpoints.
#[derive(Debug, Clone)]
pub struct NativeToolMeta {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

/// Static catalog of every native tool exposed by this gateway.
pub fn native_tool_catalog() -> Vec<NativeToolMeta> {
    vec![
        NativeToolMeta {
            name: "aegis.volume.create",
            description: "Create a persistent user volume with a specified storage quota",
            input_schema: json!({
                "type": "object",
                "required": ["label", "size_limit_bytes"],
                "properties": {
                    "label": {
                        "type": "string",
                        "description": "Human-readable volume name"
                    },
                    "size_limit_bytes": {
                        "type": "integer",
                        "description": "Storage quota in bytes"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.volume.list",
            description: "List all persistent volumes owned by the current user",
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        NativeToolMeta {
            name: "aegis.volume.delete",
            description: "Delete a persistent user volume",
            input_schema: json!({
                "type": "object",
                "required": ["volume_id"],
                "properties": {
                    "volume_id": {
                        "type": "string",
                        "description": "Volume ID to delete"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.volume.quota",
            description: "Get storage quota usage for the current user",
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        NativeToolMeta {
            name: "aegis.file.list",
            description: "List directory contents in a user volume",
            input_schema: json!({
                "type": "object",
                "required": ["volume_id", "path"],
                "properties": {
                    "volume_id": { "type": "string" },
                    "path": {
                        "type": "string",
                        "description": "Path within the volume"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.file.read",
            description: "Read the contents of a file in a user volume",
            input_schema: json!({
                "type": "object",
                "required": ["volume_id", "path"],
                "properties": {
                    "volume_id": { "type": "string" },
                    "path": {
                        "type": "string",
                        "description": "Path within the volume"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.file.write",
            description: "Write content to a file in a user volume",
            input_schema: json!({
                "type": "object",
                "required": ["volume_id", "path", "content"],
                "properties": {
                    "volume_id": { "type": "string" },
                    "path": { "type": "string" },
                    "content": {
                        "type": "string",
                        "description": "File content (base64 encoded for binary)"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.file.delete",
            description: "Delete a file or directory in a user volume",
            input_schema: json!({
                "type": "object",
                "required": ["volume_id", "path"],
                "properties": {
                    "volume_id": { "type": "string" },
                    "path": {
                        "type": "string",
                        "description": "Path within the volume"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.file.mkdir",
            description: "Create a directory in a user volume",
            input_schema: json!({
                "type": "object",
                "required": ["volume_id", "path"],
                "properties": {
                    "volume_id": { "type": "string" },
                    "path": {
                        "type": "string",
                        "description": "Path within the volume"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.git.clone",
            description: "Create a git repo binding and trigger asynchronous clone into a workspace volume. Returns the binding immediately in `Pending`/`Cloning` status.",
            input_schema: json!({
                "type": "object",
                "required": ["repo_url", "label"],
                "properties": {
                    "repo_url": {
                        "type": "string",
                        "description": "Repository URL (https://... or git@...)"
                    },
                    "credential_binding_id": {
                        "type": "string",
                        "description": "Optional UUID of a credential binding (SshKey or ApiKey) for private repos"
                    },
                    "git_ref": {
                        "type": "object",
                        "description": "Git ref to check out. Defaults to {kind:branch, value:main}.",
                        "required": ["kind", "value"],
                        "properties": {
                            "kind": {
                                "type": "string",
                                "enum": ["branch", "tag", "commit"]
                            },
                            "value": { "type": "string" }
                        }
                    },
                    "sparse_paths": {
                        "type": "array",
                        "description": "Optional list of sparse checkout paths",
                        "items": { "type": "string" }
                    },
                    "label": {
                        "type": "string",
                        "description": "Human-readable binding name; mounted at /workspace/{label}"
                    },
                    "auto_refresh": {
                        "type": "boolean",
                        "description": "Enable webhook-driven auto-refresh (default false)"
                    },
                    "shallow": {
                        "type": "boolean",
                        "description": "Perform a shallow clone (default true)"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.git.list",
            description: "List the caller's git repo bindings.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "page": { "type": "integer" },
                    "limit": { "type": "integer" }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.git.status",
            description: "Get clone/refresh status for a git repo binding. Returns the binding with current status, last commit SHA, last_cloned_at.",
            input_schema: json!({
                "type": "object",
                "required": ["binding_id"],
                "properties": {
                    "binding_id": {
                        "type": "string",
                        "description": "UUID of the git repo binding"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.git.refresh",
            description: "Trigger a fetch + checkout to update the bound volume to the latest remote HEAD (for Branch refs) or re-verify (for Tag/Commit refs).",
            input_schema: json!({
                "type": "object",
                "required": ["binding_id"],
                "properties": {
                    "binding_id": {
                        "type": "string",
                        "description": "UUID of the git repo binding"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.git.delete",
            description: "Delete a git repo binding and cascade-delete the associated volume.",
            input_schema: json!({
                "type": "object",
                "required": ["binding_id"],
                "properties": {
                    "binding_id": {
                        "type": "string",
                        "description": "UUID of the git repo binding"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.git.commit",
            description: "Stage all changes in the bound volume and commit with the given message. Returns the new commit SHA. Fails if there are no changes to commit.",
            input_schema: json!({
                "type": "object",
                "required": ["binding_id", "message"],
                "properties": {
                    "binding_id": {
                        "type": "string",
                        "description": "UUID of the git repo binding"
                    },
                    "message": {
                        "type": "string",
                        "description": "Commit message"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.git.push",
            description: "Push committed changes to the remote. Requires a credential_binding_id set on the binding for authenticated remotes.",
            input_schema: json!({
                "type": "object",
                "required": ["binding_id"],
                "properties": {
                    "binding_id": {
                        "type": "string",
                        "description": "UUID of the git repo binding"
                    },
                    "remote": {
                        "type": "string",
                        "description": "Remote name (default 'origin')"
                    },
                    "ref": {
                        "type": "string",
                        "description": "Ref to push (defaults to current branch)"
                    }
                }
            }),
        },
        NativeToolMeta {
            name: "aegis.git.diff",
            description: "Return the unified diff of the bound volume's working tree (or index, if staged=true). Read-only.",
            input_schema: json!({
                "type": "object",
                "required": ["binding_id"],
                "properties": {
                    "binding_id": {
                        "type": "string",
                        "description": "UUID of the git repo binding"
                    },
                    "staged": {
                        "type": "boolean",
                        "description": "If true, return the diff of the index against HEAD (default false)"
                    }
                }
            }),
        },
    ]
}

/// Returns `true` if `name` matches a native tool in the catalog.
pub fn is_native_tool(name: &str) -> bool {
    native_tool_catalog().iter().any(|meta| meta.name == name)
}

/// Engine that dispatches native tool invocations to the orchestrator REST API.
#[derive(Clone)]
pub struct NativeToolEngine {
    http_client: HttpClient,
    orchestrator_url: String,
}

impl NativeToolEngine {
    pub fn new(http_client: HttpClient, orchestrator_url: String) -> Self {
        Self {
            http_client,
            orchestrator_url,
        }
    }

    /// Invoke a native tool by name. `bearer_token` is forwarded as-is to the
    /// orchestrator so it can enforce per-tenant authorization.
    pub async fn invoke(
        &self,
        tool_name: &str,
        args: &Value,
        bearer_token: &str,
    ) -> Result<Value, GatewayError> {
        let auth_header = (
            "Authorization".to_string(),
            crate::domain::SensitiveString::new(format!("Bearer {bearer_token}")),
        );
        let headers = vec![auth_header];
        let base = self.orchestrator_url.trim_end_matches('/');

        match tool_name {
            "aegis.volume.create" => {
                let label = require_str(args, "label")?;
                let size_limit_bytes = require_i64(args, "size_limit_bytes")?;
                let body = json!({
                    "label": label,
                    "size_limit_bytes": size_limit_bytes,
                });
                let (status, response) = self
                    .http_client
                    .execute("POST", &format!("{base}/v1/volumes"), &headers, Some(body))
                    .await?;
                wrap_response(status, response)
            }

            "aegis.volume.list" => {
                let (status, response) = self
                    .http_client
                    .execute("GET", &format!("{base}/v1/volumes"), &headers, None)
                    .await?;
                wrap_response(status, response)
            }

            "aegis.volume.delete" => {
                let volume_id = require_str(args, "volume_id")?;
                let (status, response) = self
                    .http_client
                    .execute(
                        "DELETE",
                        &format!("{base}/v1/volumes/{volume_id}"),
                        &headers,
                        None,
                    )
                    .await?;
                wrap_response(status, response)
            }

            "aegis.volume.quota" => {
                let (status, response) = self
                    .http_client
                    .execute("GET", &format!("{base}/v1/volumes/quota"), &headers, None)
                    .await?;
                wrap_response(status, response)
            }

            "aegis.file.list" => {
                let volume_id = require_str(args, "volume_id")?;
                let path = require_str(args, "path")?;
                let url = format!(
                    "{base}/v1/volumes/{volume_id}/files?path={path}",
                    path = urlencoded(path)
                );
                let (status, response) = self
                    .http_client
                    .execute("GET", &url, &headers, None)
                    .await?;
                wrap_response(status, response)
            }

            "aegis.file.read" => {
                let volume_id = require_str(args, "volume_id")?;
                let path = require_str(args, "path")?;
                let url = format!(
                    "{base}/v1/volumes/{volume_id}/files/download?path={path}",
                    path = urlencoded(path)
                );
                let (status, response) = self
                    .http_client
                    .execute("GET", &url, &headers, None)
                    .await?;
                wrap_response(status, response)
            }

            "aegis.file.write" => {
                let volume_id = require_str(args, "volume_id")?;
                let path = require_str(args, "path")?;
                let content = require_str(args, "content")?;
                let url = format!(
                    "{base}/v1/volumes/{volume_id}/files/upload?path={path}",
                    path = urlencoded(path)
                );
                let body = json!({ "content": content });
                let (status, response) = self
                    .http_client
                    .execute("POST", &url, &headers, Some(body))
                    .await?;
                wrap_response(status, response)
            }

            "aegis.file.delete" => {
                let volume_id = require_str(args, "volume_id")?;
                let path = require_str(args, "path")?;
                let url = format!(
                    "{base}/v1/volumes/{volume_id}/files?path={path}",
                    path = urlencoded(path)
                );
                let (status, response) = self
                    .http_client
                    .execute("DELETE", &url, &headers, None)
                    .await?;
                wrap_response(status, response)
            }

            "aegis.file.mkdir" => {
                let volume_id = require_str(args, "volume_id")?;
                let path = require_str(args, "path")?;
                let url = format!(
                    "{base}/v1/volumes/{volume_id}/files/mkdir?path={path}",
                    path = urlencoded(path)
                );
                let (status, response) = self
                    .http_client
                    .execute("POST", &url, &headers, None)
                    .await?;
                wrap_response(status, response)
            }

            "aegis.git.clone" => {
                // Forward the input JSON as-is to the orchestrator. The
                // orchestrator validates required fields and defaults optional
                // ones (git_ref → main, auto_refresh → false, shallow → true).
                let body = args.clone();
                let (status, response) = self
                    .http_client
                    .execute(
                        "POST",
                        &format!("{base}/v1/storage/git"),
                        &headers,
                        Some(body),
                    )
                    .await?;
                wrap_response(status, response)
            }

            "aegis.git.list" => {
                let mut query_parts: Vec<String> = Vec::new();
                if let Some(page) = args.get("page").and_then(|v| v.as_i64()) {
                    query_parts.push(format!("page={page}"));
                }
                if let Some(limit) = args.get("limit").and_then(|v| v.as_i64()) {
                    query_parts.push(format!("limit={limit}"));
                }
                let url = if query_parts.is_empty() {
                    format!("{base}/v1/storage/git")
                } else {
                    format!("{base}/v1/storage/git?{}", query_parts.join("&"))
                };
                let (status, response) = self
                    .http_client
                    .execute("GET", &url, &headers, None)
                    .await?;
                wrap_response(status, response)
            }

            "aegis.git.status" => {
                let binding_id = require_str(args, "binding_id")?;
                let (status, response) = self
                    .http_client
                    .execute(
                        "GET",
                        &format!("{base}/v1/storage/git/{binding_id}"),
                        &headers,
                        None,
                    )
                    .await?;
                wrap_response(status, response)
            }

            "aegis.git.refresh" => {
                let binding_id = require_str(args, "binding_id")?;
                let (status, response) = self
                    .http_client
                    .execute(
                        "POST",
                        &format!("{base}/v1/storage/git/{binding_id}/refresh"),
                        &headers,
                        None,
                    )
                    .await?;
                wrap_response(status, response)
            }

            "aegis.git.delete" => {
                let binding_id = require_str(args, "binding_id")?;
                let (status, response) = self
                    .http_client
                    .execute(
                        "DELETE",
                        &format!("{base}/v1/storage/git/{binding_id}"),
                        &headers,
                        None,
                    )
                    .await?;
                wrap_response(status, response)
            }

            "aegis.git.commit" => {
                let binding_id = require_str(args, "binding_id")?;
                let message = require_str(args, "message")?;
                let body = json!({ "message": message });
                let (status, response) = self
                    .http_client
                    .execute(
                        "POST",
                        &format!("{base}/v1/storage/git/{binding_id}/commit"),
                        &headers,
                        Some(body),
                    )
                    .await?;
                wrap_response(status, response)
            }

            "aegis.git.push" => {
                let binding_id = require_str(args, "binding_id")?;
                let mut body = serde_json::Map::new();
                if let Some(remote) = args.get("remote").and_then(|v| v.as_str()) {
                    body.insert("remote".to_string(), Value::String(remote.to_string()));
                }
                if let Some(ref_val) = args.get("ref").and_then(|v| v.as_str()) {
                    body.insert("ref".to_string(), Value::String(ref_val.to_string()));
                }
                let (status, response) = self
                    .http_client
                    .execute(
                        "POST",
                        &format!("{base}/v1/storage/git/{binding_id}/push"),
                        &headers,
                        Some(Value::Object(body)),
                    )
                    .await?;
                wrap_response(status, response)
            }

            "aegis.git.diff" => {
                let binding_id = require_str(args, "binding_id")?;
                let staged = args
                    .get("staged")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let url = format!("{base}/v1/storage/git/{binding_id}/diff?staged={staged}");
                let (status, response) = self
                    .http_client
                    .execute("GET", &url, &headers, None)
                    .await?;
                wrap_response(status, response)
            }

            other => Err(GatewayError::NotFound(format!(
                "native tool '{other}' not found"
            ))),
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, GatewayError> {
    args.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
        GatewayError::Validation(format!("required field '{key}' is missing or not a string"))
    })
}

fn require_i64(args: &Value, key: &str) -> Result<i64, GatewayError> {
    args.get(key).and_then(|v| v.as_i64()).ok_or_else(|| {
        GatewayError::Validation(format!(
            "required field '{key}' is missing or not an integer"
        ))
    })
}

/// Percent-encode a path component for inclusion in a query string.
fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(byte as char);
            }
            b => {
                out.push('%');
                out.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((b & 0xf) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// Convert an orchestrator HTTP response into a `Result<Value, GatewayError>`.
///
/// 2xx → `Ok(response_body)`
/// 4xx → `GatewayError::Validation`
/// 5xx → `GatewayError::Internal`
fn wrap_response(status: u16, body: Value) -> Result<Value, GatewayError> {
    match status {
        200..=299 => Ok(body),
        400..=499 => Err(GatewayError::Validation(
            body.get("error")
                .or_else(|| body.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("orchestrator rejected the request")
                .to_string(),
        )),
        _ => Err(GatewayError::Internal(format!(
            "orchestrator returned status {status}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_contains_all_native_tools() {
        // 9 volume/file tools + 8 git tools = 17
        assert_eq!(native_tool_catalog().len(), 17);
    }

    #[test]
    fn catalog_contains_all_git_tools() {
        let names: Vec<&str> = native_tool_catalog().iter().map(|m| m.name).collect();
        for expected in [
            "aegis.git.clone",
            "aegis.git.list",
            "aegis.git.status",
            "aegis.git.refresh",
            "aegis.git.delete",
            "aegis.git.commit",
            "aegis.git.push",
            "aegis.git.diff",
        ] {
            assert!(
                names.contains(&expected),
                "catalog missing git tool '{expected}'"
            );
        }
    }

    #[test]
    fn git_clone_schema_requires_repo_url_and_label() {
        let meta = native_tool_catalog()
            .into_iter()
            .find(|m| m.name == "aegis.git.clone")
            .expect("aegis.git.clone must be registered");
        let required = meta
            .input_schema
            .get("required")
            .and_then(|v| v.as_array())
            .expect("aegis.git.clone schema must declare required fields");
        let required_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_names.contains(&"repo_url"));
        assert!(required_names.contains(&"label"));
    }

    #[test]
    fn git_commit_schema_requires_binding_id_and_message() {
        let meta = native_tool_catalog()
            .into_iter()
            .find(|m| m.name == "aegis.git.commit")
            .expect("aegis.git.commit must be registered");
        let required = meta
            .input_schema
            .get("required")
            .and_then(|v| v.as_array())
            .expect("aegis.git.commit schema must declare required fields");
        let required_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_names.contains(&"binding_id"));
        assert!(required_names.contains(&"message"));
    }

    #[test]
    fn git_status_schema_requires_binding_id_only() {
        for name in ["aegis.git.status", "aegis.git.refresh", "aegis.git.delete"] {
            let meta = native_tool_catalog()
                .into_iter()
                .find(|m| m.name == name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            let required = meta
                .input_schema
                .get("required")
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("{name} schema must declare required fields"));
            let required_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
            assert_eq!(required_names, vec!["binding_id"], "{name} required");
        }
    }

    #[test]
    fn git_list_schema_has_no_required_fields() {
        let meta = native_tool_catalog()
            .into_iter()
            .find(|m| m.name == "aegis.git.list")
            .expect("aegis.git.list must be registered");
        assert!(
            meta.input_schema.get("required").is_none(),
            "aegis.git.list should have no required fields"
        );
        // But it should still allow page/limit as optional properties.
        let props = meta
            .input_schema
            .get("properties")
            .and_then(|v| v.as_object())
            .expect("aegis.git.list must define properties");
        assert!(props.contains_key("page"));
        assert!(props.contains_key("limit"));
    }

    #[test]
    fn git_push_schema_only_requires_binding_id() {
        let meta = native_tool_catalog()
            .into_iter()
            .find(|m| m.name == "aegis.git.push")
            .expect("aegis.git.push must be registered");
        let required = meta
            .input_schema
            .get("required")
            .and_then(|v| v.as_array())
            .expect("aegis.git.push schema must declare required fields");
        let required_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(required_names, vec!["binding_id"]);
        let props = meta
            .input_schema
            .get("properties")
            .and_then(|v| v.as_object())
            .expect("aegis.git.push must define properties");
        assert!(props.contains_key("remote"));
        assert!(props.contains_key("ref"));
    }

    #[test]
    fn git_diff_schema_has_staged_boolean() {
        let meta = native_tool_catalog()
            .into_iter()
            .find(|m| m.name == "aegis.git.diff")
            .expect("aegis.git.diff must be registered");
        let props = meta
            .input_schema
            .get("properties")
            .and_then(|v| v.as_object())
            .expect("aegis.git.diff must define properties");
        let staged = props
            .get("staged")
            .expect("aegis.git.diff must allow optional 'staged' field");
        assert_eq!(
            staged.get("type").and_then(|v| v.as_str()),
            Some("boolean"),
            "'staged' must be a boolean"
        );
    }

    #[test]
    fn is_native_tool_matches_git_tools() {
        assert!(is_native_tool("aegis.git.clone"));
        assert!(is_native_tool("aegis.git.list"));
        assert!(is_native_tool("aegis.git.status"));
        assert!(is_native_tool("aegis.git.refresh"));
        assert!(is_native_tool("aegis.git.delete"));
        assert!(is_native_tool("aegis.git.commit"));
        assert!(is_native_tool("aegis.git.push"));
        assert!(is_native_tool("aegis.git.diff"));
        // Negatives
        assert!(!is_native_tool("aegis.git"));
        assert!(!is_native_tool("aegis.git.unknown"));
    }

    #[test]
    fn is_native_tool_matches_all_catalog_entries() {
        for meta in native_tool_catalog() {
            assert!(
                is_native_tool(meta.name),
                "is_native_tool should match catalog entry '{}'",
                meta.name
            );
        }
    }

    #[test]
    fn is_native_tool_rejects_unknown_names() {
        assert!(!is_native_tool("aegis.workflow.run"));
        assert!(!is_native_tool(""));
        assert!(!is_native_tool("aegis.volume"));
    }

    #[test]
    fn catalog_schemas_are_valid_objects() {
        for meta in native_tool_catalog() {
            assert_eq!(
                meta.input_schema.get("type").and_then(|v| v.as_str()),
                Some("object"),
                "tool '{}' input_schema must have type=object",
                meta.name
            );
        }
    }

    #[test]
    fn urlencoded_passes_safe_chars_unchanged() {
        assert_eq!(urlencoded("/foo/bar"), "/foo/bar");
        assert_eq!(urlencoded("foo.txt"), "foo.txt");
    }

    #[test]
    fn urlencoded_encodes_spaces_and_special_chars() {
        let result = urlencoded("my file.txt");
        assert!(result.contains("%20"), "space should be percent-encoded");
    }

    #[test]
    fn wrap_response_ok_on_2xx() {
        let body = json!({"id": "vol-1"});
        assert!(wrap_response(200, body.clone()).is_ok());
        assert!(wrap_response(201, body.clone()).is_ok());
    }

    #[test]
    fn wrap_response_validation_on_4xx() {
        let body = json!({"error": "not found"});
        let err = wrap_response(404, body).unwrap_err();
        assert!(matches!(err, GatewayError::Validation(_)));
    }

    #[test]
    fn wrap_response_internal_on_5xx() {
        let body = json!({});
        let err = wrap_response(500, body).unwrap_err();
        assert!(matches!(err, GatewayError::Internal(_)));
    }
}
