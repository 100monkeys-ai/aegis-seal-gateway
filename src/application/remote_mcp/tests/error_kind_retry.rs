//! What the gateway logs when a remote MCP server cannot be reached, and the
//! one retry of a tool listing (the Zaru defect
//! `gateway-carbon-forge-upstream-unavailable-2026-10-21`: "request failed"
//! said nothing of why, and one failed listing cost the turn its tools).
//!
//! A front server stands between the gateway and the loopback MCP server and
//! decides, connection by connection, what the gateway meets: a connection
//! closed after the request was read (what reqwest reports as "request
//! failed"), a raw HTTP answer of the test's choosing, or the loopback server
//! itself. A connection the plan does not name is passed through.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::loopback::Loopback;
use super::*;
use crate::application::remote_mcp::transport::{AddressPolicy, McpHttpClient};

const TOKEN: &str = "Mk7-retry-credential-marker";

/// What the front does with one connection.
enum Plan {
    /// Read the request, then close the connection without a word.
    Close,
    /// Read the request, then write these bytes and close.
    Answer(String),
}

#[derive(Clone, Default)]
struct Front {
    plans: Arc<Mutex<VecDeque<Plan>>>,
}

impl Front {
    fn plan(plans: Vec<Plan>) -> Self {
        Self {
            plans: Arc::new(Mutex::new(plans.into())),
        }
    }

    fn left(&self) -> usize {
        self.plans.lock().unwrap().len()
    }

    /// Serve on a loopback port in front of `backend` (the loopback MCP
    /// server's URL); answers the MCP endpoint's URL through the front.
    async fn start(&self, backend: &str) -> String {
        let backend_addr = url::Url::parse(backend)
            .expect("backend url")
            .socket_addrs(|| None)
            .expect("backend addr")[0];
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind front");
        let addr = listener.local_addr().expect("addr");
        let plans = self.plans.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let plan = plans.lock().unwrap().pop_front();
                tokio::spawn(async move {
                    match plan {
                        Some(Plan::Close) => {
                            read_request(&mut stream).await;
                            drop(stream);
                        }
                        Some(Plan::Answer(raw)) => {
                            read_request(&mut stream).await;
                            let _ = stream.write_all(raw.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        }
                        None => {
                            let Ok(mut upstream) = TcpStream::connect(backend_addr).await else {
                                return;
                            };
                            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                        }
                    }
                });
            }
        });
        format!("http://{addr}/mcp")
    }
}

/// Read one HTTP/1.1 request whole: its headers and `Content-Length` bytes.
async fn read_request(stream: &mut TcpStream) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buffer.len() >= end + 4 + length {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
    }
}

fn raw_answer(status: &str, headers: &[&str], body: &str) -> String {
    let mut raw = format!("HTTP/1.1 {status}\r\n");
    for header in headers {
        raw.push_str(header);
        raw.push_str("\r\n");
    }
    raw.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    ));
    raw
}

/// A loopback MCP server that shows `TOKEN` one tool, behind a front
/// following `plans`.
async fn engine_behind(plans: Vec<Plan>) -> (RemoteMcpEngine, Loopback, Front) {
    let loopback = Loopback::default();
    loopback.accept(TOKEN, &["echo"]);
    let backend = loopback.start().await;
    let front = Front::plan(plans);
    let url = front.start(&backend).await;
    let engine = RemoteMcpEngine::new(
        vec![RemoteMcpServer::new("loop", &url, None).expect("server")],
        McpHttpClient::new(AddressPolicy::LoopbackForTests).expect("client"),
    );
    (engine, loopback, front)
}

fn lines_with<'a>(logs: &'a str, needle: &str) -> Vec<&'a str> {
    logs.lines().filter(|line| line.contains(needle)).collect()
}

#[tokio::test]
async fn a_listing_that_fails_once_is_retried_and_lists() {
    let logs = CapturedLogs::default();
    let _guard = tracing::subscriber::set_default(logs.subscriber());
    let (engine, loopback, front) = engine_behind(vec![Plan::Close]).await;

    let listed = engine
        .list_tools("loop", &SensitiveString::new(TOKEN))
        .await;

    let text = logs.text();
    let names: Vec<String> = listed
        .as_ref()
        .map(|tools| tools.iter().map(|t| t.name.clone()).collect())
        .unwrap_or_default();
    assert_eq!(
        names,
        vec!["loop.echo".to_string()],
        "the listing after one failed connection lists; it answered {listed:?}"
    );
    assert_eq!(front.left(), 0, "the failed connection was met");
    assert_eq!(
        loopback.count("initialize"),
        1,
        "one handshake reached the server"
    );
    let retried = lines_with(&text, "remote MCP server retried once");
    assert_eq!(retried.len(), 1, "one retry line; the log was:\n{text}");
    assert!(
        retried[0].contains("INFO"),
        "the retry is an info line: {}",
        retried[0]
    );
    assert!(
        retried[0].contains("server=loop"),
        "the retry names the server: {}",
        retried[0]
    );
    assert!(
        lines_with(&text, "remote MCP server unreachable").is_empty(),
        "a failure the retry saved is not logged as unreachable:\n{text}"
    );
}

#[tokio::test]
async fn a_listing_that_fails_twice_is_unreachable_with_the_detail() {
    let logs = CapturedLogs::default();
    let _guard = tracing::subscriber::set_default(logs.subscriber());
    let (engine, loopback, front) = engine_behind(vec![Plan::Close, Plan::Close]).await;

    let err = engine
        .list_tools("loop", &SensitiveString::new(TOKEN))
        .await
        .unwrap_err();

    let text = logs.text();
    assert_eq!(code_of(&err), Some(RefusalCode::UpstreamUnavailable));
    assert_eq!(
        err.to_string(),
        upstream_unavailable().to_string(),
        "the agent's sentence is unchanged"
    );
    assert_eq!(front.left(), 0, "both failed connections were met");
    assert_eq!(loopback.count("initialize"), 0, "no third attempt");
    assert_eq!(
        lines_with(&text, "remote MCP server retried once").len(),
        1,
        "one retry, no more:\n{text}"
    );
    let unreachable = lines_with(&text, "remote MCP server unreachable");
    assert_eq!(
        unreachable.len(),
        1,
        "the second failure is the one logged:\n{text}"
    );
    let line = unreachable[0];
    assert!(
        line.contains("why=request failed"),
        "the short kind stays: {line}"
    );
    assert!(
        line.contains("detail="),
        "the line carries the detail: {line}"
    );
    assert!(
        line.contains("error sending request"),
        "the detail carries reqwest's own description: {line}"
    );
    assert!(
        line.contains("connection closed"),
        "the detail carries the error's source chain: {line}"
    );
    assert!(
        line.contains("host: 127.0.0.1"),
        "the detail names the host: {line}"
    );
    assert!(
        line.contains("is: "),
        "the detail names reqwest's predicates: {line}"
    );
    // The request carried `Authorization: Bearer <TOKEN>`: no part of it, and
    // no part of the URL but its host, is in the log or the error.
    for leaked in ["Mk7-", "retry-credential", "Bearer", "/mcp"] {
        assert!(!text.contains(leaked), "the log holds {leaked:?}:\n{text}");
        assert!(
            !format!("{err} {err:?}").contains(leaked),
            "the error holds {leaked:?}"
        );
    }
}

#[tokio::test]
async fn a_server_error_is_logged_with_its_status_and_its_json_error() {
    let logs = CapturedLogs::default();
    let _guard = tracing::subscriber::set_default(logs.subscriber());
    let tail = "x".repeat(300);
    let body = format!(
        "{{\"error\":\"the worker threw for {TOKEN}: Durable Object reset {tail} END-OF-BODY\"}}"
    );
    let (engine, loopback, _front) = engine_behind(vec![Plan::Answer(raw_answer(
        "500 Internal Server Error",
        &["content-type: application/json"],
        &body,
    ))])
    .await;

    let listed = engine
        .list_tools("loop", &SensitiveString::new(TOKEN))
        .await;

    let text = logs.text();
    assert_eq!(loopback.count("initialize"), 0, "a 500 is not retried");
    let err = listed.unwrap_err();
    assert_eq!(code_of(&err), Some(RefusalCode::UpstreamUnavailable));
    let failed = lines_with(&text, "remote MCP server failed");
    assert_eq!(failed.len(), 1, "one failure line:\n{text}");
    let line = failed[0];
    assert!(line.contains("status=500"), "the status is logged: {line}");
    assert!(
        line.contains("the worker threw for [redacted]: Durable Object reset"),
        "the JSON error's text is logged, any echo of the credential replaced: {line}"
    );
    assert!(
        !line.contains("END-OF-BODY"),
        "no more than 200 bytes of the body: {line}"
    );
    assert!(
        !text.contains("Mk7-"),
        "the credential reached the log:\n{text}"
    );
}

#[tokio::test]
async fn a_server_error_without_a_json_error_is_logged_with_its_status_alone() {
    let logs = CapturedLogs::default();
    let _guard = tracing::subscriber::set_default(logs.subscriber());
    let (engine, loopback, _front) = engine_behind(vec![Plan::Answer(raw_answer(
        "502 Bad Gateway",
        &["content-type: text/html"],
        "<html>upstream page PLAIN-BODY</html>",
    ))])
    .await;

    let listed = engine
        .list_tools("loop", &SensitiveString::new(TOKEN))
        .await;

    let text = logs.text();
    assert_eq!(loopback.count("initialize"), 0, "a 502 is not retried");
    let err = listed.unwrap_err();
    assert_eq!(code_of(&err), Some(RefusalCode::UpstreamUnavailable));
    let failed = lines_with(&text, "remote MCP server failed");
    assert_eq!(failed.len(), 1, "one failure line:\n{text}");
    assert!(
        failed[0].contains("status=502"),
        "the status is logged: {}",
        failed[0]
    );
    assert!(
        !text.contains("PLAIN-BODY"),
        "a body that is not a JSON error is not logged:\n{text}"
    );
}

#[tokio::test]
async fn a_rate_limited_listing_is_not_retried() {
    let logs = CapturedLogs::default();
    let _guard = tracing::subscriber::set_default(logs.subscriber());
    let (engine, loopback, _front) = engine_behind(vec![Plan::Answer(raw_answer(
        "429 Too Many Requests",
        &["retry-after: 7", "content-type: text/plain"],
        "slow down",
    ))])
    .await;

    let listed = engine
        .list_tools("loop", &SensitiveString::new(TOKEN))
        .await;

    let text = logs.text();
    assert_eq!(loopback.count("initialize"), 0, "a 429 is not retried");
    let err = listed.unwrap_err();
    assert_eq!(code_of(&err), Some(RefusalCode::RateLimitExceeded));
    assert!(err.to_string().contains("retry after 7s"), "{err}");
    assert!(
        lines_with(&text, "retried once").is_empty(),
        "no retry line for a 429:\n{text}"
    );
}

#[tokio::test]
async fn an_answer_whose_body_was_partly_read_is_not_retried() {
    let logs = CapturedLogs::default();
    let _guard = tracing::subscriber::set_default(logs.subscriber());
    // Headers promising 500 bytes, ten of them sent, then the connection
    // closed.
    let raw = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 500\r\n\r\n{\"jsonrpc\"".to_string();
    let (engine, loopback, _front) = engine_behind(vec![Plan::Answer(raw)]).await;

    let listed = engine
        .list_tools("loop", &SensitiveString::new(TOKEN))
        .await;

    let text = logs.text();
    assert_eq!(
        loopback.count("initialize"),
        0,
        "a partly read answer is not retried"
    );
    let err = listed.unwrap_err();
    assert_eq!(code_of(&err), Some(RefusalCode::UpstreamUnavailable));
    assert!(
        lines_with(&text, "retried once").is_empty(),
        "no retry line for a partly read answer:\n{text}"
    );
    let unreachable = lines_with(&text, "remote MCP server unreachable");
    assert_eq!(unreachable.len(), 1, "the failure is logged:\n{text}");
    assert!(
        unreachable[0].contains("body"),
        "the detail says the body failed: {}",
        unreachable[0]
    );
}

#[tokio::test]
async fn a_tool_call_that_fails_is_not_retried() {
    let logs = CapturedLogs::default();
    let _guard = tracing::subscriber::set_default(logs.subscriber());
    let (engine, loopback, front) = engine_behind(vec![Plan::Close]).await;

    let err = engine
        .call_tool(
            "loop",
            &SensitiveString::new(TOKEN),
            "echo",
            serde_json::json!({}),
        )
        .await
        .unwrap_err();

    let text = logs.text();
    assert_eq!(code_of(&err), Some(RefusalCode::UpstreamUnavailable));
    assert_eq!(front.left(), 0);
    assert_eq!(
        loopback.count("initialize"),
        0,
        "a tool call is not retried"
    );
    assert!(lines_with(&text, "retried once").is_empty(), "{text}");
    let unreachable = lines_with(&text, "remote MCP server unreachable");
    assert_eq!(unreachable.len(), 1, "{text}");
    assert!(unreachable[0].contains("detail="), "{}", unreachable[0]);
}
