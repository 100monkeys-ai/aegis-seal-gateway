//! The MCP Streamable HTTP transport, as the 2025-11-25 specification states
//! it for a client (AEGIS ADR-132 G1): every JSON-RPC message is its own POST
//! (the protocol has no batching since 2025-06-18), `Accept` lists both
//! `application/json` and `text/event-stream`, a request's answer is read from
//! either a JSON body or an event stream, `MCP-Session-Id` and
//! `MCP-Protocol-Version` are sent after initialization.
//!
//! The gateway dials these servers itself, so ADR-132 D5's address rule holds
//! here: only public addresses, only ports 443 and 80. A host name is resolved
//! through a resolver that answers only public addresses, so the connection
//! cannot be steered to a private one between the check and the dial;
//! redirects are not followed.
//!
//! The credential is a parameter of each send and is held nowhere here. No
//! log line or error built here carries it, the URL, or a response body.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::domain::SensitiveString;

pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Which addresses the client may dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressPolicy {
    /// ADR-132 D5: public addresses only, ports 443 and 80 only.
    PublicOnly,
    /// The tests' loopback MCP server: loopback addresses only, any port.
    #[cfg(test)]
    LoopbackForTests,
}

/// Why a send produced no JSON-RPC answer. None of these carries the URL, a
/// header or a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpTransportError {
    /// The address rule refused the server's address.
    AddressRefused(String),
    /// The connection failed or timed out.
    Unreachable(String),
    /// The server answered something that is not an MCP answer.
    Protocol(String),
}

/// What a POST answered.
#[derive(Debug)]
pub struct McpReply {
    pub status: u16,
    /// The `MCP-Session-Id` the server issued, if it issued one.
    pub session_id: Option<String>,
    /// `Retry-After` in seconds, when the server sent one.
    pub retry_after: Option<u64>,
    /// The JSON-RPC response to the request sent (a 2xx answer), or the
    /// JSON-RPC error object a non-2xx body held; `None` for a 202 or a body
    /// that held neither.
    pub message: Option<Value>,
}

#[derive(Clone)]
pub struct McpHttpClient {
    http: reqwest::Client,
    policy: AddressPolicy,
}

impl McpHttpClient {
    pub fn new(policy: AddressPolicy) -> anyhow::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30));
        if policy == AddressPolicy::PublicOnly {
            builder = builder.dns_resolver(Arc::new(PublicOnlyResolver));
        }
        Ok(Self {
            http: builder.build()?,
            policy,
        })
    }

    /// Check a server's URL against the address rule before any dial.
    pub fn check_url(&self, url: &url::Url) -> Result<(), McpTransportError> {
        let port = url
            .port_or_known_default()
            .ok_or_else(|| McpTransportError::AddressRefused("no port".to_string()))?;
        let host = url
            .host()
            .ok_or_else(|| McpTransportError::AddressRefused("no host".to_string()))?;
        match self.policy {
            AddressPolicy::PublicOnly => {
                if port != 443 && port != 80 {
                    return Err(McpTransportError::AddressRefused(format!(
                        "port {port} is not 443 or 80"
                    )));
                }
                let literal = match host {
                    url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
                    url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
                    url::Host::Domain(_) => None,
                };
                if let Some(ip) = literal {
                    if !is_public(ip) {
                        return Err(McpTransportError::AddressRefused(
                            "a private address".to_string(),
                        ));
                    }
                }
                Ok(())
            }
            #[cfg(test)]
            AddressPolicy::LoopbackForTests => match host {
                url::Host::Ipv4(ip) if ip.is_loopback() => Ok(()),
                url::Host::Ipv6(ip) if ip.is_loopback() => Ok(()),
                _ => Err(McpTransportError::AddressRefused(
                    "the tests dial loopback only".to_string(),
                )),
            },
        }
    }

    /// POST one JSON-RPC message. `negotiated` adds `MCP-Protocol-Version`
    /// (every message after `initialize`).
    pub async fn send(
        &self,
        url: &url::Url,
        session_id: Option<&str>,
        negotiated: bool,
        credential: &SensitiveString,
        message: &Value,
    ) -> Result<McpReply, McpTransportError> {
        self.check_url(url)?;
        let mut request = self
            .http
            .post(url.clone())
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .bearer_auth(credential.expose())
            .body(message.to_string());
        if negotiated {
            request = request.header("MCP-Protocol-Version", MCP_PROTOCOL_VERSION);
        }
        if let Some(id) = session_id {
            request = request.header("MCP-Session-Id", id);
        }
        let response = request.send().await.map_err(transport_error)?;

        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(ToString::to_string)
        };
        let session = header("mcp-session-id");
        let retry_after = header("retry-after").and_then(|v| v.trim().parse().ok());
        let event_stream = header("content-type")
            .map(|v| v.to_ascii_lowercase().starts_with("text/event-stream"))
            .unwrap_or(false);
        let request_id = message.get("id").cloned();

        let message = if status == 202 {
            None
        } else if event_stream {
            read_event_stream(response, request_id.as_ref()).await?
        } else {
            let body = read_capped(response).await?;
            if body.is_empty() {
                None
            } else {
                serde_json::from_slice::<Value>(&body).ok()
            }
        };
        Ok(McpReply {
            status,
            session_id: session,
            retry_after,
            message,
        })
    }
}

fn transport_error(err: reqwest::Error) -> McpTransportError {
    let kind = if err.is_timeout() {
        "timed out"
    } else if err.is_connect() {
        "could not connect"
    } else {
        "request failed"
    };
    McpTransportError::Unreachable(kind.to_string())
}

async fn read_capped(mut response: reqwest::Response) -> Result<Vec<u8>, McpTransportError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(McpTransportError::Protocol(
                "the answer is larger than the gateway reads".to_string(),
            ));
        }
    }
    Ok(body)
}

/// Read an SSE answer until the JSON-RPC response to `request_id` arrives.
/// Requests and notifications the server sends before it are skipped.
async fn read_event_stream(
    mut response: reqwest::Response,
    request_id: Option<&Value>,
) -> Result<Option<Value>, McpTransportError> {
    let mut buffer = String::new();
    let mut read = 0usize;
    loop {
        while let Some(end) = event_end(&buffer) {
            let event: String = buffer.drain(..end.0).collect();
            buffer.drain(..end.1);
            if let Some(found) = response_in_event(&event, request_id) {
                return Ok(Some(found));
            }
        }
        match response.chunk().await.map_err(transport_error)? {
            Some(chunk) => {
                read += chunk.len();
                if read > MAX_RESPONSE_BYTES {
                    return Err(McpTransportError::Protocol(
                        "the event stream is larger than the gateway reads".to_string(),
                    ));
                }
                buffer.push_str(&String::from_utf8_lossy(&chunk));
            }
            None => {
                // The stream ended: a last event may lack its blank line.
                return Ok(response_in_event(&buffer, request_id));
            }
        }
    }
}

/// The end of the first complete event in `buffer`: (event length, separator
/// length).
fn event_end(buffer: &str) -> Option<(usize, usize)> {
    let lf = buffer.find("\n\n").map(|i| (i, 2));
    let crlf = buffer.find("\r\n\r\n").map(|i| (i, 4));
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (a, b) => a.or(b),
    }
}

fn response_in_event(event: &str, request_id: Option<&Value>) -> Option<Value> {
    let data: Vec<&str> = event
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(|rest| rest.strip_prefix(' ').unwrap_or(rest))
        .collect();
    if data.is_empty() {
        return None;
    }
    let value: Value = serde_json::from_str(&data.join("\n")).ok()?;
    let is_response = value.get("result").is_some() || value.get("error").is_some();
    let matches = match request_id {
        Some(id) => value.get("id") == Some(id),
        None => true,
    };
    (is_response && matches).then_some(value)
}

/// Resolves a host name to its public addresses only (ADR-132 D5).
struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|address| is_public(address.ip()))
                .collect();
            if addresses.is_empty() {
                return Err("the host resolves to no public address".into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Whether `ip` is a public unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(v6),
        },
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || first == 0x2001 && ip.segments()[1] == 0x0db8
        || ip.segments()[..6] == [0, 0, 0, 0, 0, 0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_and_web_ports_are_dialled() {
        let client = McpHttpClient::new(AddressPolicy::PublicOnly).expect("client");
        for refused in [
            "https://127.0.0.1/mcp",
            "https://10.0.0.5/mcp",
            "https://192.168.1.10/mcp",
            "https://172.16.0.1/mcp",
            "https://169.254.169.254/mcp",
            "https://100.64.0.1/mcp",
            "https://[::1]/mcp",
            "https://[fd00::1]/mcp",
            "https://[fe80::1]/mcp",
            "https://[::ffff:10.0.0.1]/mcp",
            "https://mcp.example.test:8443/mcp",
        ] {
            let url = url::Url::parse(refused).expect("url");
            assert!(
                matches!(
                    client.check_url(&url),
                    Err(McpTransportError::AddressRefused(_))
                ),
                "{refused} must be refused"
            );
        }
        for allowed in [
            "https://93.184.216.34/mcp",
            "http://mcp.example.test/mcp",
            "https://mcp.example.test/mcp",
        ] {
            let url = url::Url::parse(allowed).expect("url");
            assert!(client.check_url(&url).is_ok(), "{allowed} must pass");
        }
    }

    #[test]
    fn an_event_stream_answer_is_found_among_other_messages() {
        let stream = "id: 1\ndata:\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\n\n";
        let mut buffer = stream.to_string();
        let mut found = None;
        while let Some(end) = event_end(&buffer) {
            let event: String = buffer.drain(..end.0).collect();
            buffer.drain(..end.1);
            if let Some(v) = response_in_event(&event, Some(&serde_json::json!(7))) {
                found = Some(v);
            }
        }
        assert!(found.is_none(), "an unparsable event is skipped");
        let event = "data: {\"jsonrpc\":\"2.0\",\"id\":7,\r\ndata: \"result\":{\"ok\":true}}";
        let value = response_in_event(event, Some(&serde_json::json!(7))).expect("the response");
        assert_eq!(value["result"]["ok"], true);
        assert!(response_in_event(event, Some(&serde_json::json!(8))).is_none());
    }
}
