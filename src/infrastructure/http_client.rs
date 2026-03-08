use reqwest::Method;
use serde_json::Value;

use crate::domain::SensitiveString;
use crate::infrastructure::errors::GatewayError;

#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new() -> Result<Self, GatewayError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| GatewayError::Http(e.to_string()))?;
        Ok(Self { client })
    }

    pub async fn execute(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, SensitiveString)],
        body: Option<Value>,
    ) -> Result<(u16, Value), GatewayError> {
        let parsed_method = Method::from_bytes(method.as_bytes())
            .map_err(|e| GatewayError::Validation(format!("invalid method: {e}")))?;

        let mut req = self.client.request(parsed_method, url);
        for (k, v) in headers {
            req = req.header(k, v.expose());
        }
        if let Some(payload) = body {
            req = req.json(&payload);
        }

        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await?;
        if bytes.is_empty() {
            Ok((status, serde_json::json!({})))
        } else {
            let value: Value = serde_json::from_slice(&bytes)?;
            Ok((status, value))
        }
    }
}
