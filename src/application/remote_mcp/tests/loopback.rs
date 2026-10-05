//! A loopback MCP server speaking Streamable HTTP as MCP 2025-11-25 states
//! it, for the remote MCP source's tests. It knows nothing of any product:
//! each accepted bearer token has its own tool list, as a server whose list
//! depends on the caller's scope would.
//!
//! Tools: `echo` (answers its arguments as text), `stream-echo` (the same,
//! as an event stream with a notification first), `soft-fail` (an `isError`
//! result), `bad-args` (JSON-RPC -32602), `custom-fail` (JSON-RPC -32042, its
//! message echoing the caller's token), `limited` (HTTP 429), `crash`
//! (HTTP 500). An unknown tool answers -32601.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

/// One request the server received, as the tests read it back.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub session_id: Option<String>,
    pub protocol_version: Option<String>,
    /// The bearer token presented, compared by the tests against the tokens
    /// they configured; never printed.
    pub token: Option<String>,
    pub params: Value,
}

#[derive(Default)]
struct Inner {
    /// token -> the tool names that token sees.
    tools_by_token: HashMap<String, Vec<String>>,
    sessions: HashSet<String>,
    next_session: u64,
    seen: Vec<Seen>,
}

#[derive(Clone, Default)]
pub struct Loopback {
    inner: Arc<Mutex<Inner>>,
}

impl Loopback {
    /// Accept `token`, showing it `tools`.
    pub fn accept(&self, token: &str, tools: &[&str]) {
        self.inner.lock().unwrap().tools_by_token.insert(
            token.to_string(),
            tools.iter().map(|t| t.to_string()).collect(),
        );
    }

    /// Forget every session: the next request carrying one answers 404.
    pub fn forget_sessions(&self) {
        self.inner.lock().unwrap().sessions.clear();
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.inner.lock().unwrap().seen.clone()
    }

    pub fn count(&self, method: &str) -> usize {
        self.seen().iter().filter(|s| s.method == method).count()
    }

    /// Serve on a loopback port; answers the MCP endpoint's URL.
    pub async fn start(&self) -> String {
        let router = Router::new()
            .route("/mcp", post(handle))
            .with_state(self.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{addr}/mcp")
    }
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Response {
    Json(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}))
        .into_response()
}

fn text_result(id: &Value, text: String, is_error: bool) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"content": [{"type": "text", "text": text}], "isError": is_error},
    })
}

async fn handle(State(server): State<Loopback>, headers: HeaderMap, body: String) -> Response {
    let message: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if message.is_array() {
        // MCP 2025-11-25: a POST body is a single message.
        return StatusCode::BAD_REQUEST.into_response();
    }
    let method = message["method"].as_str().unwrap_or_default().to_string();
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let token = header(&headers, "authorization")
        .and_then(|v| v.strip_prefix("Bearer ").map(ToString::to_string));
    let session_id = header(&headers, "mcp-session-id");

    let mut inner = server.inner.lock().unwrap();
    inner.seen.push(Seen {
        method: method.clone(),
        session_id: session_id.clone(),
        protocol_version: header(&headers, "mcp-protocol-version"),
        token: token.clone(),
        params: message.get("params").cloned().unwrap_or(Value::Null),
    });

    let Some(tools) = token
        .as_ref()
        .and_then(|t| inner.tools_by_token.get(t))
        .cloned()
    else {
        return (StatusCode::UNAUTHORIZED, "invalid bearer token").into_response();
    };

    if method == "initialize" {
        inner.next_session += 1;
        let sid = format!("loopback-session-{}", inner.next_session);
        inner.sessions.insert(sid.clone());
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "loopback", "version": "0"},
            },
        });
        let mut response = Json(body).into_response();
        response
            .headers_mut()
            .insert("mcp-session-id", sid.parse().expect("header"));
        return response;
    }
    if let Some(sid) = &session_id {
        if !inner.sessions.contains(sid) {
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    drop(inner);

    match method.as_str() {
        "notifications/initialized" => StatusCode::ACCEPTED.into_response(),
        "tools/list" => {
            let listed: Vec<Value> = tools
                .iter()
                .map(|name| {
                    json!({
                        "name": name,
                        "description": format!("the {name} tool"),
                        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
                    })
                })
                .collect();
            Json(json!({"jsonrpc": "2.0", "id": id, "result": {"tools": listed}})).into_response()
        }
        "tools/call" => {
            let name = message["params"]["name"].as_str().unwrap_or_default();
            let arguments = message["params"]["arguments"].clone();
            if !tools.iter().any(|t| t == name) {
                return rpc_error(&id, -32601, &format!("Unknown tool: {name}"));
            }
            match name {
                "echo" => Json(text_result(&id, arguments.to_string(), false)).into_response(),
                "stream-echo" => {
                    let note = json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}});
                    let answer = text_result(&id, arguments.to_string(), false);
                    let stream = format!("id: e1\ndata:\n\ndata: {note}\n\ndata: {answer}\n\n");
                    ([("content-type", "text/event-stream")], stream).into_response()
                }
                "soft-fail" => {
                    Json(text_result(&id, "it did not work".to_string(), true)).into_response()
                }
                "bad-args" => rpc_error(&id, -32602, "Invalid arguments: q is required"),
                "custom-fail" => rpc_error(
                    &id,
                    -32042,
                    &format!("custom failure for token {}", token.unwrap_or_default()),
                ),
                "limited" => (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("retry-after", "7")],
                    "slow down",
                )
                    .into_response(),
                "crash" => (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response(),
                _ => rpc_error(&id, -32601, "Unknown tool"),
            }
        }
        _ => rpc_error(&id, -32601, "Method not found"),
    }
}
