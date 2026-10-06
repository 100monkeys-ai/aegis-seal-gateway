//! The gateway keeps no session to a remote MCP server (AEGIS ADR-132 H9):
//! each call is its own `initialize`, `notifications/initialized` and
//! `tools/call`, nothing is kept between calls, so two gateways with no
//! shared state serve the same person's calls in any order.

use serde_json::{json, Value};

use super::loopback::{Loopback, Seen};
use super::*;
use crate::application::remote_mcp::transport::{AddressPolicy, McpHttpClient};

const TOKEN: &str = "Mk7-stateless-credential-marker";
const ROTATED: &str = "Mk7-stateless-rotated-marker";

/// A gateway's remote MCP source with nothing shared with any other: its
/// own engine and its own HTTP client.
fn gateway(url: &str) -> RemoteMcpEngine {
    RemoteMcpEngine::new(
        vec![RemoteMcpServer::new("loop", url, None).expect("server")],
        McpHttpClient::new(AddressPolicy::LoopbackForTests).expect("client"),
    )
}

async fn call(engine: &RemoteMcpEngine, token: &str, tool: &str) -> Result<Value, GatewayError> {
    engine
        .call_tool(
            "loop",
            &SensitiveString::new(token),
            tool,
            json!({"q": "x"}),
        )
        .await
        .map(|answer| answer.result)
}

/// What the loopback server saw, split into calls: each call opens with its
/// `initialize`. Anything seen before the first `initialize` is a call that
/// opened none, and is its own group.
fn calls(seen: &[Seen]) -> Vec<Vec<Seen>> {
    let mut groups: Vec<Vec<Seen>> = Vec::new();
    for s in seen {
        if s.method == "initialize" || groups.is_empty() {
            groups.push(Vec::new());
        }
        groups.last_mut().unwrap().push(s.clone());
    }
    groups
}

fn methods(group: &[Seen]) -> Vec<&str> {
    group.iter().map(|s| s.method.as_str()).collect()
}

const ONE_CALL: [&str; 3] = ["initialize", "notifications/initialized", "tools/call"];

#[tokio::test]
async fn two_gateways_with_no_shared_state_each_serve_calls_with_the_same_token() {
    let loopback = Loopback::default();
    loopback.accept(TOKEN, &["echo"]);
    let url = loopback.start().await;
    let a = gateway(&url);
    let b = gateway(&url);

    for (n, engine) in [&a, &b, &a, &b].into_iter().enumerate() {
        let result = call(engine, TOKEN, "echo").await;
        assert!(result.is_ok(), "call {n} was served: {result:?}");
    }

    let groups = calls(&loopback.seen());
    let shapes: Vec<Vec<&str>> = groups.iter().map(|g| methods(g)).collect();
    assert_eq!(
        shapes,
        vec![ONE_CALL.to_vec(); 4],
        "each call is its own initialize, notifications/initialized, tools/call"
    );
}

#[tokio::test]
async fn a_second_call_sends_a_fresh_initialize_and_carries_another_session_id() {
    let loopback = Loopback::default();
    loopback.accept(TOKEN, &["echo"]);
    let engine = gateway(&loopback.start().await);

    call(&engine, TOKEN, "echo").await.expect("first");
    call(&engine, TOKEN, "echo").await.expect("second");

    assert_eq!(
        loopback.count("initialize"),
        2,
        "the second call sent a fresh initialize"
    );
    let ids: Vec<Option<String>> = loopback
        .seen()
        .into_iter()
        .filter(|s| s.method == "tools/call")
        .map(|s| s.session_id)
        .collect();
    assert_eq!(
        ids,
        vec![
            Some("loopback-session-1".to_string()),
            Some("loopback-session-2".to_string())
        ],
        "each tools/call carried its own initialize's session id"
    );
}

#[tokio::test]
async fn a_404_on_tools_call_is_refused_after_one_initialize_and_not_retried() {
    let loopback = Loopback::default();
    loopback.accept(TOKEN, &["lost-session"]);
    let engine = gateway(&loopback.start().await);

    let err = call(&engine, TOKEN, "lost-session").await.unwrap_err();

    assert!(
        matches!(
            err,
            GatewayError::Refused {
                code: RefusalCode::RemoteToolError,
                ..
            }
        ),
        "a 404 is answered REMOTE_TOOL_ERROR: {err:?}"
    );
    assert_eq!(
        methods(&loopback.seen()),
        ONE_CALL.to_vec(),
        "one initialize and no retry after the 404"
    );
}

#[tokio::test]
async fn each_call_presents_its_own_credential_on_all_three_posts() {
    let loopback = Loopback::default();
    loopback.accept(TOKEN, &["echo"]);
    loopback.accept(ROTATED, &["echo"]);
    let engine = gateway(&loopback.start().await);

    for token in [TOKEN, TOKEN, ROTATED] {
        call(&engine, token, "echo").await.expect("called");
    }

    let groups = calls(&loopback.seen());
    let expected = [TOKEN, TOKEN, ROTATED];
    assert_eq!(groups.len(), 3, "each call is its own handshake");
    for (group, token) in groups.iter().zip(expected) {
        assert_eq!(methods(group), ONE_CALL.to_vec(), "a whole call");
        for s in group {
            // Compared, never printed: a mismatch names the method only.
            assert!(
                s.token.as_deref() == Some(token),
                "{} presented another call's credential",
                s.method
            );
        }
    }
}

#[tokio::test]
async fn the_tools_call_carries_the_session_id_and_protocol_version_its_initialize_answered() {
    let loopback = Loopback::default();
    loopback.accept(TOKEN, &["echo"]);
    let engine = gateway(&loopback.start().await);

    call(&engine, TOKEN, "echo").await.expect("first");
    call(&engine, TOKEN, "echo").await.expect("second");

    let groups = calls(&loopback.seen());
    assert_eq!(groups.len(), 2, "each call is its own handshake");
    for (n, group) in groups.iter().enumerate() {
        let answered = format!("loopback-session-{}", n + 1);
        assert_eq!(methods(group), ONE_CALL.to_vec(), "a whole call");
        assert_eq!(group[0].session_id, None, "initialize carries no session");
        assert_eq!(group[0].protocol_version, None);
        assert_eq!(group[0].params["protocolVersion"], "2025-11-25");
        for later in &group[1..] {
            assert_eq!(
                later.session_id.as_deref(),
                Some(answered.as_str()),
                "{} carried the session id its initialize answered",
                later.method
            );
            assert_eq!(
                later.protocol_version.as_deref(),
                Some("2025-11-25"),
                "{} carried the protocol version its initialize answered",
                later.method
            );
        }
    }
}

#[tokio::test]
async fn a_listing_after_a_call_is_its_own_handshake() {
    let loopback = Loopback::default();
    loopback.accept(TOKEN, &["echo"]);
    let engine = gateway(&loopback.start().await);

    call(&engine, TOKEN, "echo").await.expect("called");
    let listed = engine
        .list_tools("loop", &SensitiveString::new(TOKEN))
        .await
        .expect("listed");

    assert_eq!(listed.len(), 1);
    let groups = calls(&loopback.seen());
    let shapes: Vec<Vec<&str>> = groups.iter().map(|g| methods(g)).collect();
    assert_eq!(
        shapes,
        vec![
            ONE_CALL.to_vec(),
            vec!["initialize", "notifications/initialized", "tools/list"]
        ],
        "the listing opened its own initialize"
    );
}
