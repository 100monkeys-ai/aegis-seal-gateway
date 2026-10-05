//! The remote MCP source against a loopback MCP server (AEGIS ADR-132 G1):
//! sessions per binding, listing, calling, error relay, the session dropped
//! and the credential forgotten, the address rule, and the credential absent
//! from every log line, error and result.

pub(crate) mod loopback;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;

use super::transport::{AddressPolicy, McpHttpClient};
use super::*;
use loopback::Loopback;

const ALICE: &str = "Mk7-alice-credential-marker";
const BOB: &str = "Mk7-bob-credential-marker";

fn cred(value: &str) -> SensitiveString {
    SensitiveString::new(value)
}

async fn engine_on(loopback: &Loopback, idle: Duration) -> RemoteMcpEngine {
    let url = loopback.start().await;
    let server = RemoteMcpServer::new("loop", &url, None).expect("server");
    RemoteMcpEngine::with_idle(
        vec![server],
        McpHttpClient::new(AddressPolicy::LoopbackForTests).expect("client"),
        idle,
    )
}

fn code_of(err: &GatewayError) -> Option<RefusalCode> {
    match err {
        GatewayError::Refused { code, .. } => Some(*code),
        _ => None,
    }
}

#[tokio::test]
async fn a_binding_initializes_once_and_reuses_its_session() {
    let loopback = Loopback::default();
    loopback.accept(ALICE, &["echo"]);
    let engine = engine_on(&loopback, SESSION_IDLE).await;

    for n in 0..3 {
        engine
            .call_tool("loop", "alice", &cred(ALICE), "echo", json!({"n": n}))
            .await
            .expect("called");
    }

    assert_eq!(loopback.count("initialize"), 1);
    assert_eq!(loopback.count("notifications/initialized"), 1);
    let seen = loopback.seen();
    let initialize = seen.iter().find(|s| s.method == "initialize").unwrap();
    assert_eq!(initialize.session_id, None);
    assert_eq!(initialize.params["protocolVersion"], "2025-11-25");
    for later in seen.iter().filter(|s| s.method != "initialize") {
        assert_eq!(later.session_id.as_deref(), Some("loopback-session-1"));
        assert_eq!(later.protocol_version.as_deref(), Some("2025-11-25"));
        assert_eq!(later.token.as_deref(), Some(ALICE));
    }
    assert_eq!(engine.session_count(), 1);
}

#[tokio::test]
async fn each_binding_lists_its_own_tools_under_the_servers_name() {
    let loopback = Loopback::default();
    loopback.accept(ALICE, &["echo", "pages.read"]);
    loopback.accept(BOB, &["echo"]);
    let engine = engine_on(&loopback, SESSION_IDLE).await;

    let alice = engine
        .list_tools("loop", "alice", &cred(ALICE))
        .await
        .expect("listed");
    let bob = engine
        .list_tools("loop", "bob", &cred(BOB))
        .await
        .expect("listed");

    let names = |tools: &[RemoteTool]| tools.iter().map(|t| t.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&alice), vec!["loop.echo", "loop.pages.read"]);
    assert_eq!(names(&bob), vec!["loop.echo"]);
    assert_eq!(alice[0].description, "the echo tool");
    assert_eq!(alice[0].input_schema["properties"]["q"]["type"], "string");
    assert_eq!(loopback.count("initialize"), 2, "one session per binding");
    assert_eq!(engine.session_count(), 2);
}

#[tokio::test]
async fn a_call_passes_its_arguments_and_result_through_unchanged() {
    let loopback = Loopback::default();
    loopback.accept(ALICE, &["echo"]);
    let engine = engine_on(&loopback, SESSION_IDLE).await;
    let arguments = json!({"q": "héllo", "nested": {"list": [1, 2.5, null, true]}});

    let result = engine
        .call_tool("loop", "alice", &cred(ALICE), "echo", arguments.clone())
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
    let engine = engine_on(&loopback, SESSION_IDLE).await;
    let result = engine
        .call_tool(
            "loop",
            "alice",
            &cred(ALICE),
            "stream-echo",
            json!({"q": 1}),
        )
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
    let engine = engine_on(&loopback, SESSION_IDLE).await;
    let alice = cred(ALICE);
    let call = |tool: &'static str| engine.call_tool("loop", "alice", &alice, tool, json!({}));

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
    let engine = engine_on(&loopback, SESSION_IDLE).await;
    let err = engine
        .call_tool("loop", "bob", &cred(BOB), "echo", json!({}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Some(RefusalCode::CredentialRejected));
    assert_eq!(
        engine.session_count(),
        0,
        "no session for a refused credential"
    );
}

#[tokio::test]
async fn a_session_the_server_forgot_is_replaced_once() {
    let loopback = Loopback::default();
    loopback.accept(ALICE, &["echo"]);
    let engine = engine_on(&loopback, SESSION_IDLE).await;
    engine
        .call_tool("loop", "alice", &cred(ALICE), "echo", json!({}))
        .await
        .expect("first");
    loopback.forget_sessions();
    engine
        .call_tool("loop", "alice", &cred(ALICE), "echo", json!({}))
        .await
        .expect("second, on a new session");
    assert_eq!(loopback.count("initialize"), 2);
    let last = loopback.seen().into_iter().last().unwrap();
    assert_eq!(last.session_id.as_deref(), Some("loopback-session-2"));
}

#[tokio::test]
async fn an_idle_session_is_dropped_and_a_changed_credential_starts_a_new_one() {
    let loopback = Loopback::default();
    loopback.accept(ALICE, &["echo"]);
    loopback.accept("Mk7-alice-rotated-credential", &["echo"]);
    let engine = engine_on(&loopback, Duration::from_millis(200)).await;

    engine
        .call_tool("loop", "alice", &cred(ALICE), "echo", json!({}))
        .await
        .expect("called");
    assert_eq!(engine.session_count(), 1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    engine
        .call_tool("loop", "alice", &cred(ALICE), "echo", json!({}))
        .await
        .expect("called after idle");
    assert_eq!(
        loopback.count("initialize"),
        2,
        "the idle session was dropped"
    );

    engine
        .call_tool(
            "loop",
            "alice",
            &cred("Mk7-alice-rotated-credential"),
            "echo",
            json!({}),
        )
        .await
        .expect("called with the new credential");
    assert_eq!(
        loopback.count("initialize"),
        3,
        "a changed credential re-initializes"
    );
    assert_eq!(engine.session_count(), 1, "the old session is gone");
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
        .call_tool("loop", "alice", &cred(ALICE), "echo", json!({}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), Some(RefusalCode::ServiceUnavailable));
    assert!(loopback.seen().is_empty(), "no request left the gateway");
}

#[tokio::test]
async fn an_unregistered_server_is_not_found() {
    let loopback = Loopback::default();
    let engine = engine_on(&loopback, SESSION_IDLE).await;
    let err = engine
        .call_tool("other", "alice", &cred(ALICE), "echo", json!({}))
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
    let engine = engine_on(&loopback, SESSION_IDLE).await;
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
            .call_tool("loop", "alice", &cred(ALICE), tool, json!({"q": "x"}))
            .await
        {
            Ok(result) => outputs.push(result.to_string()),
            Err(err) => outputs.push(format!("{err} {err:?}")),
        }
    }
    let listed = engine
        .list_tools("loop", "alice", &cred(ALICE))
        .await
        .expect("listed");
    outputs.push(format!("{listed:?}"));
    let rejected = engine
        .call_tool("loop", "bob", &cred(BOB), "echo", json!({}))
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
