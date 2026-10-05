//! Remote MCP servers as a tool source (AEGIS ADR-132 G1, G5, G6).
//!
//! **Sessions.** One MCP session per binding: per (server, acting user). It
//! is initialized once (`initialize`, then `notifications/initialized`), its
//! `MCP-Session-Id` kept and sent on every later call, so consecutive calls
//! reuse it (ADR-132 G1's "batch", read under correction C3: MCP 2025-11-25
//! has no JSON-RPC batching). A session is dropped, and the next call
//! initializes a new one, when it has been idle for [`SESSION_IDLE`], when the
//! server answers 404 to its id (the specification's "start a new session"),
//! or when the call brings a different credential for the same binding.
//!
//! **The credential.** It arrives on each call, resolved by the orchestrator,
//! and lives only as long as that call: it is a parameter here, sent as
//! `Authorization: Bearer` and dropped when the call returns. The session
//! keeps no copy of it, only a 64-bit digest under a key chosen at random
//! when the gateway starts, to tell a changed credential; the digest goes
//! with the session. Nothing here logs, stores or relays it: a server's
//! error text is relayed with any occurrence of it replaced.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::domain::{RemoteMcpServer, SensitiveString};
use crate::infrastructure::errors::{GatewayError, RefusalCode};
pub mod transport;

use self::transport::{McpHttpClient, McpReply, McpTransportError};

/// How long an unused session is kept.
pub const SESSION_IDLE: Duration = Duration::from_secs(15 * 60);
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SessionKey {
    server: String,
    user_id: String,
}

struct Session {
    id: Option<String>,
    credential_digest: u64,
    last_used: Instant,
}

pub struct RemoteMcpEngine {
    servers: HashMap<String, RemoteMcpServer>,
    client: McpHttpClient,
    sessions: Mutex<HashMap<SessionKey, Session>>,
    digest_key: std::collections::hash_map::RandomState,
    next_id: AtomicU64,
    idle: Duration,
}

impl RemoteMcpEngine {
    pub fn new(servers: Vec<RemoteMcpServer>, client: McpHttpClient) -> Self {
        Self::with_idle(servers, client, SESSION_IDLE)
    }

    pub fn with_idle(servers: Vec<RemoteMcpServer>, client: McpHttpClient, idle: Duration) -> Self {
        Self {
            servers: servers
                .into_iter()
                .map(|server| (server.name.clone(), server))
                .collect(),
            client,
            sessions: Mutex::new(HashMap::new()),
            digest_key: Default::default(),
            next_id: AtomicU64::new(1),
            idle,
        }
    }

    pub fn is_registered(&self, server: &str) -> bool {
        self.servers.contains_key(server)
    }

    /// The tools `server` shows this user (its list depends on the user's
    /// credential), named `<server>.<tool>`.
    pub async fn list_tools(
        &self,
        server: &str,
        user_id: &str,
        credential: &SensitiveString,
    ) -> Result<Vec<RemoteTool>, GatewayError> {
        let registered = self.server(server)?;
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_LIST_PAGES {
            let params = match &cursor {
                Some(c) => json!({ "cursor": c }),
                None => json!({}),
            };
            let result = self
                .request(registered, user_id, credential, "tools/list", params)
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

    /// Call `tool` on `server` with `arguments` unchanged; answers the
    /// `tools/call` result unchanged (an `isError` result included).
    pub async fn call_tool(
        &self,
        server: &str,
        user_id: &str,
        credential: &SensitiveString,
        tool: &str,
        arguments: Value,
    ) -> Result<Value, GatewayError> {
        let registered = self.server(server)?;
        self.request(
            registered,
            user_id,
            credential,
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )
        .await
    }

    /// Sessions currently held; for tests of when a session is dropped.
    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }

    fn server(&self, name: &str) -> Result<&RemoteMcpServer, GatewayError> {
        self.servers.get(name).ok_or_else(|| {
            GatewayError::refused(
                RefusalCode::NotFound,
                format!("Not found: server '{name}'."),
            )
        })
    }

    fn message_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// One request on the binding's session; a session the server no longer
    /// knows (404) is replaced once.
    async fn request(
        &self,
        server: &RemoteMcpServer,
        user_id: &str,
        credential: &SensitiveString,
        method: &str,
        params: Value,
    ) -> Result<Value, GatewayError> {
        let key = SessionKey {
            server: server.name.clone(),
            user_id: user_id.to_string(),
        };
        let mut replaced = false;
        loop {
            let session_id = self.ensure_session(server, &key, credential).await?;
            let message = json!({
                "jsonrpc": "2.0",
                "id": self.message_id(),
                "method": method,
                "params": params,
            });
            let reply = self
                .client
                .send(
                    &server.url,
                    session_id.as_deref(),
                    true,
                    credential,
                    &message,
                )
                .await
                .map_err(|e| transport_refusal(server, &e))?;
            if reply.status == 404 && session_id.is_some() && !replaced {
                self.drop_session(&key);
                replaced = true;
                continue;
            }
            self.touch(&key);
            return answer(server, credential, reply);
        }
    }

    /// The binding's session id, initializing a session when there is none
    /// to reuse.
    async fn ensure_session(
        &self,
        server: &RemoteMcpServer,
        key: &SessionKey,
        credential: &SensitiveString,
    ) -> Result<Option<String>, GatewayError> {
        let digest = self.digest_key.hash_one(credential.expose());
        {
            let mut sessions = self.lock_sessions();
            let idle = self.idle;
            sessions.retain(|_, session| session.last_used.elapsed() < idle);
            if let Some(session) = sessions.get(key) {
                if session.credential_digest == digest {
                    return Ok(session.id.clone());
                }
            }
            sessions.remove(key);
        }

        let initialize = json!({
            "jsonrpc": "2.0",
            "id": self.message_id(),
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
            .send(&server.url, None, false, credential, &initialize)
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
        let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let ack = self
            .client
            .send(
                &server.url,
                session_id.as_deref(),
                true,
                credential,
                &initialized,
            )
            .await
            .map_err(|e| transport_refusal(server, &e))?;
        if !(200..300).contains(&ack.status) {
            answer(server, credential, ack)?;
        }

        self.lock_sessions().insert(
            key.clone(),
            Session {
                id: session_id.clone(),
                credential_digest: digest,
                last_used: Instant::now(),
            },
        );
        Ok(session_id)
    }

    fn touch(&self, key: &SessionKey) {
        if let Some(session) = self.lock_sessions().get_mut(key) {
            session.last_used = Instant::now();
        }
    }

    fn drop_session(&self, key: &SessionKey) {
        self.lock_sessions().remove(key);
    }

    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, HashMap<SessionKey, Session>> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
