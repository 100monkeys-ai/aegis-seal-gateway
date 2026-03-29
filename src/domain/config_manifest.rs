use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcpGatewayConfigManifest {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: ConfigMetadata,
    pub spec: SmcpGatewayConfigSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMetadata {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmcpGatewayConfigSpec {
    #[serde(default)]
    pub network: GatewayNetworkConfig,
    #[serde(default)]
    pub database: GatewayDatabaseConfig,
    #[serde(default)]
    pub auth: GatewayAuthConfig,
    #[serde(default)]
    pub credentials: GatewayCredentialsConfig,
    #[serde(default)]
    pub cli: GatewayCliConfig,
    #[serde(default)]
    pub ui: GatewayUiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayNetworkConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_grpc_bind_addr")]
    pub grpc_bind_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayDatabaseConfig {
    #[serde(default = "default_database_url")]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayAuthConfig {
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub operator_jwt_public_key_pem: String,
    #[serde(default = "default_operator_jwt_issuer")]
    pub operator_jwt_issuer: String,
    #[serde(default = "default_operator_jwt_audience")]
    pub operator_jwt_audience: String,
    #[serde(default)]
    pub smcp_jwt_public_key_pem: String,
    #[serde(default = "default_smcp_jwt_issuer")]
    pub smcp_jwt_issuer: String,
    #[serde(default = "default_smcp_jwt_audience")]
    pub smcp_jwt_audience: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayCredentialsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openbao_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openbao_token: Option<String>,
    #[serde(default = "default_openbao_kv_mount")]
    pub openbao_kv_mount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keycloak_token_exchange_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keycloak_client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keycloak_client_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayCliConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_cli: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_judge_url: Option<String>,
    #[serde(default = "default_nfs_server_host")]
    pub nfs_server_host: String,
    #[serde(default = "default_nfs_port")]
    pub nfs_port: u16,
    #[serde(default = "default_nfs_mount_port")]
    pub nfs_mount_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayUiConfig {
    #[serde(default = "default_ui_enabled")]
    pub enabled: bool,
}

impl Default for SmcpGatewayConfigManifest {
    fn default() -> Self {
        Self {
            api_version: "smcp.100monkeys.ai/v1".to_string(),
            kind: "SmcpGatewayConfig".to_string(),
            metadata: ConfigMetadata {
                name: "aegis-smcp-gateway".to_string(),
                version: Some("1.0.0".to_string()),
                labels: None,
            },
            spec: SmcpGatewayConfigSpec::default(),
        }
    }
}

impl Default for GatewayNetworkConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            grpc_bind_addr: default_grpc_bind_addr(),
        }
    }
}

impl Default for GatewayDatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_database_url(),
        }
    }
}

impl Default for GatewayAuthConfig {
    fn default() -> Self {
        Self {
            disabled: false,
            operator_jwt_public_key_pem: String::new(),
            operator_jwt_issuer: default_operator_jwt_issuer(),
            operator_jwt_audience: default_operator_jwt_audience(),
            smcp_jwt_public_key_pem: String::new(),
            smcp_jwt_issuer: default_smcp_jwt_issuer(),
            smcp_jwt_audience: default_smcp_jwt_audience(),
        }
    }
}

impl Default for GatewayCredentialsConfig {
    fn default() -> Self {
        Self {
            openbao_addr: None,
            openbao_token: None,
            openbao_kv_mount: default_openbao_kv_mount(),
            keycloak_token_exchange_url: None,
            keycloak_client_id: None,
            keycloak_client_secret: None,
        }
    }
}

impl Default for GatewayCliConfig {
    fn default() -> Self {
        Self {
            container_cli: None,
            semantic_judge_url: None,
            nfs_server_host: default_nfs_server_host(),
            nfs_port: default_nfs_port(),
            nfs_mount_port: default_nfs_mount_port(),
        }
    }
}

impl Default for GatewayUiConfig {
    fn default() -> Self {
        Self {
            enabled: default_ui_enabled(),
        }
    }
}

impl SmcpGatewayConfigManifest {
    pub fn from_yaml_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Self = serde_yaml::from_str(&content)?;
        config.resolve_env_refs();
        Ok(config)
    }

    /// Resolve `"env:VAR_NAME"` references in string fields.
    ///
    /// Any config field whose YAML value starts with `env:` is treated as a
    /// reference to an environment variable.  If the variable is set and
    /// non-empty the field is substituted in-place; if it is unset or empty the
    /// field is cleared to `""` / `None`.  `apply_env_overrides` then runs
    /// immediately after and can still fill required fields in from the same
    /// env vars (e.g. `SMCP_GATEWAY_DB` sets `database.url` in both paths).
    ///
    /// This mirrors the `env:` interpolation pattern used by `aegis-config.yaml`.
    pub fn resolve_env_refs(&mut self) {
        resolve_env_string(&mut self.spec.network.bind_addr);
        resolve_env_string(&mut self.spec.network.grpc_bind_addr);
        resolve_env_string(&mut self.spec.database.url);
        resolve_env_string(&mut self.spec.auth.operator_jwt_public_key_pem);
        resolve_env_string(&mut self.spec.auth.operator_jwt_issuer);
        resolve_env_string(&mut self.spec.auth.operator_jwt_audience);
        resolve_env_string(&mut self.spec.auth.smcp_jwt_public_key_pem);
        resolve_env_string(&mut self.spec.auth.smcp_jwt_issuer);
        resolve_env_string(&mut self.spec.auth.smcp_jwt_audience);
        resolve_env_option(&mut self.spec.credentials.openbao_addr);
        resolve_env_option(&mut self.spec.credentials.openbao_token);
        resolve_env_string(&mut self.spec.credentials.openbao_kv_mount);
        resolve_env_option(&mut self.spec.credentials.keycloak_token_exchange_url);
        resolve_env_option(&mut self.spec.credentials.keycloak_client_id);
        resolve_env_option(&mut self.spec.credentials.keycloak_client_secret);
        resolve_env_option(&mut self.spec.cli.container_cli);
        resolve_env_option(&mut self.spec.cli.semantic_judge_url);
        resolve_env_string(&mut self.spec.cli.nfs_server_host);
    }

    pub fn discover_config() -> Option<PathBuf> {
        if let Ok(path) = std::env::var("SMCP_GATEWAY_CONFIG_PATH") {
            let path = PathBuf::from(path);
            if path.exists() {
                return Some(path);
            }
        }

        let cwd = PathBuf::from("./smcp-gateway-config.yaml");
        if cwd.exists() {
            return Some(cwd);
        }

        if let Some(home) = dirs::home_dir() {
            let user_config = home.join(".aegis").join("smcp-gateway-config.yaml");
            if user_config.exists() {
                return Some(user_config);
            }
        }

        #[cfg(unix)]
        let system_config = PathBuf::from("/etc/aegis/smcp-gateway-config.yaml");
        #[cfg(windows)]
        let system_config = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("Aegis")
            .join("smcp-gateway-config.yaml");

        if system_config.exists() {
            return Some(system_config);
        }

        None
    }

    pub fn load_or_default() -> anyhow::Result<Self> {
        let mut manifest = if let Some(path) = Self::discover_config() {
            tracing::info!("Loading SMCP gateway config from {:?}", path);
            Self::from_yaml_file(path)?
        } else {
            tracing::warn!("No smcp-gateway-config.yaml found; using defaults");
            Self::default()
        };
        manifest.apply_env_overrides();
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn apply_env_overrides(&mut self) {
        if let Ok(value) = std::env::var("SMCP_GATEWAY_BIND") {
            if !value.trim().is_empty() {
                self.spec.network.bind_addr = value;
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_GRPC_BIND") {
            if !value.trim().is_empty() {
                self.spec.network.grpc_bind_addr = value;
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_DB") {
            if !value.trim().is_empty() {
                self.spec.database.url = value;
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_AUTH_DISABLED") {
            self.spec.auth.disabled = value.eq_ignore_ascii_case("true");
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_OPERATOR_JWT_PUBLIC_KEY_PEM") {
            self.spec.auth.operator_jwt_public_key_pem = value;
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_OPERATOR_JWT_ISSUER") {
            if !value.trim().is_empty() {
                self.spec.auth.operator_jwt_issuer = value;
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_OPERATOR_JWT_AUDIENCE") {
            if !value.trim().is_empty() {
                self.spec.auth.operator_jwt_audience = value;
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_SMCP_JWT_PUBLIC_KEY_PEM") {
            self.spec.auth.smcp_jwt_public_key_pem = value;
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_SMCP_JWT_ISSUER") {
            if !value.trim().is_empty() {
                self.spec.auth.smcp_jwt_issuer = value;
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_SMCP_JWT_AUDIENCE") {
            if !value.trim().is_empty() {
                self.spec.auth.smcp_jwt_audience = value;
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_OPENBAO_ADDR") {
            self.spec.credentials.openbao_addr = Some(value);
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_OPENBAO_TOKEN") {
            self.spec.credentials.openbao_token = Some(value);
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_OPENBAO_KV_MOUNT") {
            if !value.trim().is_empty() {
                self.spec.credentials.openbao_kv_mount = value;
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_KEYCLOAK_TOKEN_EXCHANGE_URL") {
            self.spec.credentials.keycloak_token_exchange_url = Some(value);
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_KEYCLOAK_CLIENT_ID") {
            self.spec.credentials.keycloak_client_id = Some(value);
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_KEYCLOAK_CLIENT_SECRET") {
            self.spec.credentials.keycloak_client_secret = Some(value);
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_CONTAINER_CLI") {
            if !value.trim().is_empty() {
                self.spec.cli.container_cli = Some(value);
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_SEMANTIC_JUDGE_URL") {
            self.spec.cli.semantic_judge_url = Some(value);
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_NFS_HOST") {
            if !value.trim().is_empty() {
                self.spec.cli.nfs_server_host = value;
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_NFS_PORT") {
            if let Ok(parsed) = value.parse::<u16>() {
                self.spec.cli.nfs_port = parsed;
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_NFS_MOUNT_PORT") {
            if let Ok(parsed) = value.parse::<u16>() {
                self.spec.cli.nfs_mount_port = parsed;
            }
        }
        if let Ok(value) = std::env::var("SMCP_GATEWAY_UI_ENABLED") {
            self.spec.ui.enabled = !value.eq_ignore_ascii_case("false");
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.api_version != "smcp.100monkeys.ai/v1" {
            anyhow::bail!(
                "Invalid apiVersion: '{}'. Must be 'smcp.100monkeys.ai/v1'",
                self.api_version
            );
        }
        if self.kind != "SmcpGatewayConfig" {
            anyhow::bail!("Invalid kind: '{}'. Must be 'SmcpGatewayConfig'", self.kind);
        }
        if self.metadata.name.trim().is_empty() {
            anyhow::bail!("metadata.name cannot be empty");
        }
        if self.spec.network.bind_addr.trim().is_empty() {
            anyhow::bail!("spec.network.bind_addr cannot be empty");
        }
        if self.spec.network.grpc_bind_addr.trim().is_empty() {
            anyhow::bail!("spec.network.grpc_bind_addr cannot be empty");
        }
        if self.spec.database.url.trim().is_empty() {
            anyhow::bail!("spec.database.url cannot be empty");
        }
        Ok(())
    }
}

fn default_bind_addr() -> String {
    "0.0.0.0:8089".to_string()
}
fn default_grpc_bind_addr() -> String {
    "0.0.0.0:50055".to_string()
}
fn default_database_url() -> String {
    "sqlite://gateway.db".to_string()
}
fn default_operator_jwt_issuer() -> String {
    "aegis-keycloak".to_string()
}
fn default_operator_jwt_audience() -> String {
    "aegis-smcp-gateway".to_string()
}
fn default_smcp_jwt_issuer() -> String {
    "aegis-orchestrator".to_string()
}
fn default_smcp_jwt_audience() -> String {
    "aegis-agents".to_string()
}
fn default_openbao_kv_mount() -> String {
    "secret".to_string()
}
fn default_nfs_server_host() -> String {
    "127.0.0.1".to_string()
}
fn default_nfs_port() -> u16 {
    2049
}
fn default_nfs_mount_port() -> u16 {
    20048
}
fn default_ui_enabled() -> bool {
    true
}

/// Resolve an `"env:VAR_NAME"` reference inline, modifying `s` in place.
///
/// - If `s` starts with `"env:"` and the variable is set and non-empty: substitute.
/// - If `s` starts with `"env:"` and the variable is unset/empty: clear to `""`
///   so that `apply_env_overrides` (which runs after) can still fill it in from
///   the same variable, and so `validate()` catches genuinely missing required
///   fields with a useful error message.
/// - If `s` does not start with `"env:"`: leave unchanged.
///
/// This mirrors the `env:` interpolation pattern used by `aegis-config.yaml`.
fn resolve_env_string(s: &mut String) {
    if let Some(var_name) = s.strip_prefix("env:") {
        match std::env::var(var_name) {
            Ok(value) if !value.trim().is_empty() => *s = value,
            _ => s.clear(),
        }
    }
}

/// Same as `resolve_env_string` but for `Option<String>` fields.
/// A YAML `"env:VAR_NAME"` value becomes `Some(resolved)` when the variable is
/// set, or `None` when the variable is unset/empty.
fn resolve_env_option(opt: &mut Option<String>) {
    if let Some(s) = opt.as_deref() {
        if let Some(var_name) = s.strip_prefix("env:") {
            match std::env::var(var_name) {
                Ok(value) if !value.trim().is_empty() => *opt = Some(value),
                _ => *opt = None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_manifest_headers() {
        let mut manifest = SmcpGatewayConfigManifest::default();
        manifest.api_version = "invalid/v1".to_string();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn parses_yaml_manifest() {
        let yaml = r#"
apiVersion: smcp.100monkeys.ai/v1
kind: SmcpGatewayConfig
metadata:
  name: test-gateway
spec:
  network:
    bind_addr: 127.0.0.1:8089
    grpc_bind_addr: 127.0.0.1:50055
  database:
    url: sqlite://gateway.db
  auth:
    disabled: true
    operator_jwt_public_key_pem: ""
    operator_jwt_issuer: issuer
    operator_jwt_audience: audience
    smcp_jwt_public_key_pem: ""
    smcp_jwt_issuer: smcp-issuer
    smcp_jwt_audience: smcp-audience
  credentials:
    openbao_kv_mount: secret
  cli:
    nfs_server_host: 127.0.0.1
    nfs_port: 2049
    nfs_mount_port: 20048
  ui:
    enabled: true
"#;
        let manifest: SmcpGatewayConfigManifest =
            serde_yaml::from_str(yaml).expect("parse manifest");
        assert_eq!(manifest.kind, "SmcpGatewayConfig");
        assert_eq!(manifest.metadata.name, "test-gateway");
    }
}
