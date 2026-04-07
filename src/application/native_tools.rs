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
    fn catalog_contains_nine_tools() {
        assert_eq!(native_tool_catalog().len(), 9);
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
