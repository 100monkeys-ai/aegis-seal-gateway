//! The `_grounding` a remote server answers on a call's `initialize` reaches
//! the caller beside the `tools/call` result, never inside it (AEGIS ADR-132
//! H9a): Nuclear Notes answers the token's grounding there.

use serde_json::{json, Value};

use super::loopback::Loopback;
use super::*;
use crate::application::remote_mcp::transport::{AddressPolicy, McpHttpClient};

const TOKEN: &str = "Mk7-grounding-credential-marker";

async fn answer_with(grounding: Option<Value>) -> RemoteCallAnswer {
    let loopback = Loopback::default();
    loopback.accept(TOKEN, &["echo"]);
    if let Some(grounding) = grounding {
        loopback.answer_grounding(TOKEN, grounding);
    }
    let url = loopback.start().await;
    let engine = RemoteMcpEngine::new(
        vec![RemoteMcpServer::new("loop", &url, None).expect("server")],
        McpHttpClient::new(AddressPolicy::LoopbackForTests).expect("client"),
    );
    engine
        .call_tool(
            "loop",
            &SensitiveString::new(TOKEN),
            "echo",
            json!({"q": "x"}),
        )
        .await
        .expect("called")
}

#[tokio::test]
async fn the_grounding_an_initialize_answers_reaches_the_caller_beside_the_result() {
    let grounding = json!({"you": {"instances": [{"slug": "acme", "id": "i-1"}]}});
    let answer = answer_with(Some(grounding.clone())).await;
    assert_eq!(
        answer.grounding,
        Some(grounding),
        "the call answers the grounding its initialize answered"
    );
    assert_eq!(
        answer.result,
        json!({"content": [{"type": "text", "text": "{\"q\":\"x\"}"}], "isError": false}),
        "the tools/call result is unchanged"
    );
    assert!(
        !answer.result.to_string().contains("_grounding"),
        "the result never carries _grounding: {}",
        answer.result
    );
}

#[tokio::test]
async fn no_grounding_answered_answers_none() {
    let answer = answer_with(None).await;
    assert_eq!(answer.grounding, None, "no grounding was answered");
}

#[tokio::test]
async fn a_null_grounding_answers_none() {
    let answer = answer_with(Some(Value::Null)).await;
    assert_eq!(answer.grounding, None, "a null grounding is no grounding");
}
