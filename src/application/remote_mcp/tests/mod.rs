//! The remote MCP source against a loopback MCP server (AEGIS ADR-132 G1,
//! H9): a handshake per call, listing, calling, error relay, the address
//! rule, and the credential absent from every log line, error and result.
//! What H9 adds (nothing kept between calls) is in `stateless`.

pub(crate) mod loopback;
mod stateless;

use std::io::Write;
use std::sync::{Arc, Mutex};

use serde_json::json;

use super::transport::{AddressPolicy, McpHttpClient};
use super::*;
use loopback::Loopback;

const ALICE: &str = "Mk7-alice-credential-marker";
const BOB: &str = "Mk7-bob-credential-marker";

fn cred(value: &str) -> SensitiveString {
    SensitiveString::new(value)
}

async fn engine_on(loopback: &Loopback) -> RemoteMcpEngine {
    let url = loopback.start().await;
    let server = RemoteMcpServer::new("loop", &url, None).expect("server");
    RemoteMcpEngine::new(
        vec![server],
        McpHttpClient::new(AddressPolicy::LoopbackForTests).expect("client"),
    )
}

fn code_of(err: &GatewayError) -> Option<RefusalCode> {
    match err {
        GatewayError::Refused { code, .. } => Some(*code),
        _ => None,
    }
}

#[tokio::test]
async fn each_call_initializes_its_own_session() {
    let loopback = Loopback::default();
    loopback.accept(ALICE, &["echo"]);
    let engine = engine_on(&loopback).await;

    for n in 0..3 {
        engine
            .call_tool("loop", &cred(ALICE), "echo", json!({"n": n}))
            .await
            .expect("called");
    }

    assert_eq!(loopback.count("initialize"), 3);
    assert_eq!(loopback.count("notifications/initialized"), 3);
    let seen = loopback.seen();
    for initialize in seen.iter().filter(|s| s.method == "initialize") {
        assert_eq!(initialize.session_id, None);
        assert_eq!(initialize.params["protocolVersion"], "2025-11-25");
    }
    let calls: Vec<_> = seen.iter().filter(|s| s.method == "tools/call").collect();
    assert_eq!(calls.len(), 3);
    for (n, later) in calls.into_iter().enumerate() {
        let session = format!("loopback-session-{}", n + 1);
        assert_eq!(later.session_id.as_deref(), Some(session.as_str()));
        assert_eq!(later.protocol_version.as_deref(), Some("2025-11-25"));
        assert_eq!(later.token.as_deref(), Some(ALICE));
    }
}

#[tokio::test]
async fn each_binding_lists_its_own_tools_under_the_servers_name() {
    let loopback = Loopback::default();
    loopback.accept(ALICE, &["echo", "pages.read"]);
    loopback.accept(BOB, &["echo"]);
    let engine = engine_on(&loopback).await;

    let alice = engine
        .list_tools("loop", &cred(ALICE))
        .await
        .expect("listed");
    let bob = engine.list_tools("loop", &cred(BOB)).await.expect("listed");

    let names = |tools: &[RemoteTool]| tools.iter().map(|t| t.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&alice), vec!["loop.echo", "loop.pages.read"]);
    assert_eq!(names(&bob), vec!["loop.echo"]);
    assert_eq!(alice[0].description, "the echo tool");
    assert_eq!(alice[0].input_schema["properties"]["q"]["type"], "string");
    assert_eq!(loopback.count("initialize"), 2, "one handshake per listing");
}

#[tokio::test]
async fn a_call_passes_its_arguments_and_result_through_unchanged() {
    let loopback = Loopback::default();
    loopback.accept(ALICE, &["echo"]);
    let engine = engine_on(&loopback).await;
    let arguments = json!({"q": "héllo", "nested": {"list": [1, 2.5, null, true]}});

    let result = engine
        .call_tool("loop", &cred(ALICE), "echo", arguments.clone())
        .await
        .expect("called");

    let call = loopback
        .seen()
        .into_iter()
        .find(|s| s.method == "tools/call")
        .unwrap();
    assert_eq!(call.params["name"], "echo");
    assert_eq!(call.params["arguments"], arguments);
    assert_eq!(
        result,
        json!({"content": [{"type": "text", "text": arguments.to_string()}], "isError": false})
    );
}

#[tokio::test]
async fn an_event_stream_answer_is_read() {
    let loopback = Loopback::default();
    loopback.accept(ALICE, &["stream-echo"]);
    let engine = engine_on(&loopback).await;
    let result = engine
        .call_tool("loop", &cred(ALICE), "stream-echo", json!({"q": 1}))
        .await
        .expect("called");
    assert_eq!(result["content"][0]["text"], json!({"q": 1}).to_string());
}

#[tokio::test]
async fn errors_are_relayed_as_refusals_and_an_is_error_result_is_a_result() {
    let loopback = Loopback::default();
    loopback.accept(
        ALICE,
        &["soft-fail", "bad-args", "custom-fail", "limited", "crash"],
    );
    let engine = engine_on(&loopback).await;
    let alice = cred(ALICE);
    let call = |tool: &'static str| engine.call_tool("loop", &alice, tool, json!({}));

    let soft = call("soft-fail").await.expect("a result");
    assert_eq!(soft["isError"], true);

    let missing = call("no-such-tool").await.unwrap_err();
    assert_eq!(code_of(&missing), Some(RefusalCode::NotFound));

    let bad = call("bad-args").await.unwrap_err();
    assert_eq!(code_of(&bad), Some(RefusalCode::InvalidArguments));
    assert!(bad.to_string().contains("Invalid arguments: q is required"));

    let custom = call("custom-fail").await.unwrap_err();
    assert_eq!(code_of(&custom), Some(RefusalCode::RemoteToolError));
    assert!(custom
        .to_string()
        .contains("custom failure for token [redacted]"));
    assert!(!custom.to_string().contains(ALICE));

    let limited = call("limited").await.unwrap_err();
    assert_eq!(code_of(&limited), Some(RefusalCode::RateLimitExceeded));
    assert!(limited.to_string().contains("retry after 7s"));

    let crash = call("crash").await.unwrap_err();
    assert_eq!(code_of(&crash), Some(RefusalCode::UpstreamUnavailable));
}

#[tokio::test]
async fn a_rejected_credential_is_refused_as_such() {
    let loopback = Loopback::default();
    loopback.accept(ALICE, &["echo"]);
    let engine = engine_on(&loopback).await;
    let err = engine
        .call_tool("loop", &cred(BOB), "echo", json!({}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Some(RefusalCode::CredentialRejected));
    assert_eq!(
        loopback.count("tools/call"),
        0,
        "no tools/call reached the server"
    );
}

#[tokio::test]
async fn a_private_address_is_refused_under_the_production_rule() {
    let loopback = Loopback::default();
    loopback.accept(ALICE, &["echo"]);
    let url = loopback.start().await;
    let engine = RemoteMcpEngine::new(
        vec![RemoteMcpServer::new("loop", &url, None).expect("server")],
        McpHttpClient::new(AddressPolicy::PublicOnly).expect("client"),
    );
    let err = engine
        .call_tool("loop", &cred(ALICE), "echo", json!({}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Some(RefusalCode::ServiceUnavailable));
    assert!(loopback.seen().is_empty(), "no request left the gateway");
}

#[tokio::test]
async fn an_unregistered_server_is_not_found() {
    let loopback = Loopback::default();
    let engine = engine_on(&loopback).await;
    let err = engine
        .call_tool("other", &cred(ALICE), "echo", json!({}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Some(RefusalCode::NotFound));
}

/// A `tracing` writer that keeps every line, so a test can read them back.
#[derive(Clone, Default)]
pub(crate) struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedLogs {
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).to_string()
    }

    pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        let writer = self.clone();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish()
    }
}

impl Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn the_credential_is_never_in_a_log_line_an_error_or_a_result() {
    let logs = CapturedLogs::default();
    let _guard = tracing::subscriber::set_default(logs.subscriber());

    let loopback = Loopback::default();
    loopback.accept(
        ALICE,
        &[
            "echo",
            "soft-fail",
            "bad-args",
            "custom-fail",
            "limited",
            "crash",
        ],
    );
    let engine = engine_on(&loopback).await;
    let mut outputs = Vec::new();
    for tool in [
        "echo",
        "soft-fail",
        "bad-args",
        "custom-fail",
        "limited",
        "crash",
        "nope",
    ] {
        match engine
            .call_tool("loop", &cred(ALICE), tool, json!({"q": "x"}))
            .await
        {
            Ok(result) => outputs.push(result.to_string()),
            Err(err) => outputs.push(format!("{err} {err:?}")),
        }
    }
    let listed = engine
        .list_tools("loop", &cred(ALICE))
        .await
        .expect("listed");
    outputs.push(format!("{listed:?}"));
    let rejected = engine
        .call_tool("loop", &cred(BOB), "echo", json!({}))
        .await
        .unwrap_err();
    outputs.push(format!("{rejected} {rejected:?}"));
    tracing::info!("capture marker: the logs were captured");

    let log_text = logs.text();
    assert!(log_text.contains("capture marker"), "the capture works");
    assert!(
        log_text.contains("refused the credential"),
        "a refusal was logged"
    );
    for marker in ["Mk7-"] {
        assert!(!log_text.contains(marker), "a credential reached the log");
        for output in &outputs {
            assert!(!output.contains(marker), "a credential reached {output}");
        }
    }
}
