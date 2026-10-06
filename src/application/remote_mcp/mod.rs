//! Remote MCP servers as a tool source (AEGIS ADR-132 G1, G5, G6).
//!
//! **No session is kept (ADR-132 H9).** The gateway holds nothing about a
//! remote server between calls: each tool call, and each listing, is its own
//! handshake (`initialize`, then `notifications/initialized`) followed by the
//! request, and everything the handshake answered is dropped when the call
//! returns. The `MCP-Session-Id` the server answers on `initialize` is sent on
//! that call's later messages and then forgotten, and so is the protocol
//! version it answered. Gateway replicas therefore share no state and are
//! balanced blindly. A per-replica cache may only ever be an optimisation
//! that correctness never needs; there is none.
//!
//! **The credential.** It arrives on each call, resolved by the orchestrator,
//! and lives only as long as that call: it is a parameter here, sent as
//! `Authorization: Bearer` and dropped when the call returns. Nothing here
//! logs, stores or relays it: a server's error text is relayed with any
//! occurrence of it replaced.

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::domain::{RemoteMcpServer, SensitiveString};
use crate::infrastructure::errors::{GatewayError, RefusalCode};
pub mod transport;

use self::transport::{McpHttpClient, McpReply, McpTransportError};

const MAX_LIST_PAGES: usize = 50;
const MAX_RELAYED_MESSAGE: usize = 1000;

/// A remote tool as `tools/list` described it, under its exposed name.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteTool {
    /// `<server>.<tool>`.
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub server: String,
}

/// What one call's handshake answered; it lives only as long as that call.
struct Handshake {
    session_id: Option<String>,
    protocol_version: String,
    /// The JSON-RPC id of the next request on this handshake (`initialize`
    /// is 1).
    next_id: u64,
}

impl Handshake {
    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

pub struct RemoteMcpEngine {
    servers: HashMap<String, RemoteMcpServer>,
    client: McpHttpClient,
}

impl RemoteMcpEngine {
    pub fn new(servers: Vec<RemoteMcpServer>, client: McpHttpClient) -> Self {
        Self {
            servers: servers
                .into_iter()
                .map(|server| (server.name.clone(), server))
                .collect(),
            client,
        }
    }

    pub fn is_registered(&self, server: &str) -> bool {
        self.servers.contains_key(server)
    }

    /// The tools `server` shows the holder of `credential` (its list depends
    /// on the credential), named `<server>.<tool>`: one handshake, its pages
    /// on it.
    pub async fn list_tools(
        &self,
        server: &str,
        credential: &SensitiveString,
    ) -> Result<Vec<RemoteTool>, GatewayError> {
        let registered = self.server(server)?;
        let mut handshake = self.handshake(registered, credential).await?;
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_LIST_PAGES {
            let params = match &cursor {
                Some(c) => json!({ "cursor": c }),
                None => json!({}),
            };
            let result = self
                .request(registered, &mut handshake, credential, "tools/list", params)
                .await?;
            for tool in result
                .get("tools")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(name) = tool.get("name").and_then(Value::as_str) else {
                    continue;
                };
                tools.push(RemoteTool {
                    name: registered.tool_name(name),
                    description: tool
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    input_schema: tool
                        .get("inputSchema")
                        .cloned()
                        .unwrap_or_else(|| json!({"type": "object"})),
                    server: registered.name.clone(),
                });
            }
            cursor = result
                .get("nextCursor")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            if cursor.is_none() {
                break;
            }
        }
        Ok(tools)
    }

    /// Call `tool` on `server` with `arguments` unchanged, on a handshake of
    /// its own; answers the `tools/call` result unchanged (an `isError`
    /// result included).
    pub async fn call_tool(
        &self,
        server: &str,
        credential: &SensitiveString,
        tool: &str,
        arguments: Value,
    ) -> Result<Value, GatewayError> {
        let registered = self.server(server)?;
        let mut handshake = self.handshake(registered, credential).await?;
        self.request(
            registered,
            &mut handshake,
            credential,
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )
        .await
    }

    fn server(&self, name: &str) -> Result<&RemoteMcpServer, GatewayError> {
        self.servers.get(name).ok_or_else(|| {
            GatewayError::refused(
                RefusalCode::NotFound,
                format!("Not found: server '{name}'."),
            )
        })
    }

    /// One request on `handshake`. A 404 is the server's answer, relayed as
    /// a refusal: nothing is retried, since nothing was kept to go stale.
    async fn request(
        &self,
        server: &RemoteMcpServer,
        handshake: &mut Handshake,
        credential: &SensitiveString,
        method: &str,
        params: Value,
    ) -> Result<Value, GatewayError> {
        let message = json!({
            "jsonrpc": "2.0",
            "id": handshake.next_id(),
            "method": method,
            "params": params,
        });
        let reply = self
            .client
            .send(
                &server.url,
                handshake.session_id.as_deref(),
                Some(&handshake.protocol_version),
                credential,
                &message,
            )
            .await
            .map_err(|e| transport_refusal(server, &e))?;
        answer(server, credential, reply)
    }

    /// `initialize` and `notifications/initialized`, for one call.
    async fn handshake(
        &self,
        server: &RemoteMcpServer,
        credential: &SensitiveString,
    ) -> Result<Handshake, GatewayError> {
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": self::transport::MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "aegis-seal-gateway",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            },
        });
        let reply = self
            .client
            .send(&server.url, None, None, credential, &initialize)
            .await
            .map_err(|e| transport_refusal(server, &e))?;
        let session_id = reply.session_id.clone();
        let result = answer(server, credential, reply)?;
        let version = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if version != self::transport::MCP_PROTOCOL_VERSION {
            tracing::error!(
                server = %server.name,
                version,
                "remote MCP server speaks a protocol version this gateway does not"
            );
            return Err(GatewayError::refused(
                RefusalCode::ServiceUnavailable,
                "This tool is not available right now.",
            ));
        }
        let handshake = Handshake {
            session_id,
            protocol_version: version.to_string(),
            next_id: 2,
        };
        let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let ack = self
            .client
            .send(
                &server.url,
                handshake.session_id.as_deref(),
                Some(&handshake.protocol_version),
                credential,
                &initialized,
            )
            .await
            .map_err(|e| transport_refusal(server, &e))?;
        if !(200..300).contains(&ack.status) {
            answer(server, credential, ack)?;
        }
        Ok(handshake)
    }
}

/// The JSON-RPC result of `reply`, or the refusal it amounts to (ADR-035
/// R5, the rows correction C1 names).
fn answer(
    server: &RemoteMcpServer,
    credential: &SensitiveString,
    reply: McpReply,
) -> Result<Value, GatewayError> {
    let status = reply.status;
    if status == 401 || status == 403 {
        tracing::warn!(server = %server.name, status, "remote MCP server refused the credential");
        return Err(GatewayError::refused(
            RefusalCode::CredentialRejected,
            format!(
                "The '{}' server refused your stored credential.",
                server.name
            ),
        ));
    }
    if status == 429 {
        let retry = reply
            .retry_after
            .map(|s| format!(", retry after {s}s"))
            .unwrap_or_default();
        return Err(GatewayError::refused(
            RefusalCode::RateLimitExceeded,
            format!("The '{}' server is limiting requests{retry}.", server.name),
        ));
    }
    if status >= 500 {
        tracing::warn!(server = %server.name, status, "remote MCP server failed");
        return Err(upstream_unavailable());
    }
    let message = reply.message.unwrap_or(Value::Null);
    if let Some(error) = message.get("error") {
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
        let text = relayed(
            error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("The server refused the call."),
            credential,
        );
        let refusal = match code {
            -32601 => RefusalCode::NotFound,
            -32602 => RefusalCode::InvalidArguments,
            _ => RefusalCode::RemoteToolError,
        };
        return Err(GatewayError::refused(refusal, text));
    }
    if !(200..300).contains(&status) {
        tracing::warn!(server = %server.name, status, "remote MCP server answered an error status");
        return Err(GatewayError::refused(
            RefusalCode::RemoteToolError,
            format!(
                "The '{}' server refused the request (HTTP {status}).",
                server.name
            ),
        ));
    }
    match message.get("result") {
        Some(result) => Ok(result.clone()),
        None => {
            tracing::warn!(server = %server.name, "remote MCP server answered no JSON-RPC result");
            Err(upstream_unavailable())
        }
    }
}

fn transport_refusal(server: &RemoteMcpServer, err: &McpTransportError) -> GatewayError {
    match err {
        McpTransportError::AddressRefused(why) => {
            tracing::error!(
                server = %server.name,
                why = %why,
                "a registered MCP server's address is refused by the address rule"
            );
            GatewayError::refused(
                RefusalCode::ServiceUnavailable,
                "This tool is not available right now.",
            )
        }
        McpTransportError::Unreachable(why) | McpTransportError::Protocol(why) => {
            tracing::warn!(server = %server.name, why = %why, "remote MCP server unreachable");
            upstream_unavailable()
        }
    }
}

fn upstream_unavailable() -> GatewayError {
    GatewayError::refused(
        RefusalCode::UpstreamUnavailable,
        "A service this tool depends on did not answer. Try again in a moment.",
    )
}

/// A server's own error text, as relayed to the caller: the credential, if
/// the server echoed it, replaced; bounded in length.
fn relayed(text: &str, credential: &SensitiveString) -> String {
    let secret = credential.expose();
    let cleaned = if secret.is_empty() {
        text.to_string()
    } else {
        text.replace(secret, "[redacted]")
    };
    cleaned.chars().take(MAX_RELAYED_MESSAGE).collect()
}

#[cfg(test)]
pub(crate) mod tests;
