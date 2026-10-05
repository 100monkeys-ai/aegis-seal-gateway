//! A remote MCP server: the gateway's third tool source (AEGIS ADR-132 G1).
//! Registered as data in the gateway's configuration; its tools are exposed
//! as `<server>.<tool>`, listed and called with the acting user's own
//! credential, which the orchestrator resolves and hands over on the call.

use crate::infrastructure::errors::GatewayError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMcpServer {
    /// The prefix of its tools' names: lowercase letters, digits and hyphens.
    pub name: String,
    /// The server's MCP Streamable HTTP endpoint.
    pub url: url::Url,
    pub description: Option<String>,
}

impl RemoteMcpServer {
    pub fn new(name: &str, url: &str, description: Option<String>) -> Result<Self, GatewayError> {
        let valid_name = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid_name {
            return Err(GatewayError::Validation(format!(
                "mcp_servers: name '{name}' must be lowercase letters, digits and hyphens"
            )));
        }
        let parsed = url::Url::parse(url).map_err(|e| {
            GatewayError::Validation(format!("mcp_servers.{name}: url is not a URL: {e}"))
        })?;
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(GatewayError::Validation(format!(
                "mcp_servers.{name}: url must be https or http"
            )));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(GatewayError::Validation(format!(
                "mcp_servers.{name}: url must not carry a user or password; \
                 the acting user's credential comes on each call"
            )));
        }
        if parsed.host_str().is_none() {
            return Err(GatewayError::Validation(format!(
                "mcp_servers.{name}: url has no host"
            )));
        }
        Ok(Self {
            name: name.to_string(),
            url: parsed,
            description,
        })
    }

    pub fn tool_name(&self, tool: &str) -> String {
        format!("{}.{tool}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_is_registered_by_name_and_url() {
        let server = RemoteMcpServer::new("notes-1", "https://mcp.example.test/api/mcp", None)
            .expect("valid");
        assert_eq!(server.tool_name("pages.read"), "notes-1.pages.read");
    }

    #[test]
    fn a_bad_registration_is_refused() {
        for (name, url) in [
            ("Notes", "https://mcp.example.test/mcp"),
            ("no.dots", "https://mcp.example.test/mcp"),
            ("", "https://mcp.example.test/mcp"),
            ("notes", "ftp://mcp.example.test/mcp"),
            ("notes", "https://user:secret@mcp.example.test/mcp"),
            ("notes", "not a url"),
        ] {
            assert!(
                RemoteMcpServer::new(name, url, None).is_err(),
                "{name} {url} must be refused"
            );
        }
    }
}
