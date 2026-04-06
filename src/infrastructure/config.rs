use crate::domain::SealGatewayConfigManifest;
use crate::infrastructure::container_cli;

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub bind_addr: String,
    pub grpc_bind_addr: String,
    pub database_url: String,
    pub jwks_validator: std::sync::Arc<crate::infrastructure::jwks_validator::JwksValidator>,
    pub operator_jwt_issuer: String,
    pub operator_jwt_audience: String,
    pub auth_disabled: bool,
    pub seal_jwt_public_key_pem: String,
    pub seal_jwt_issuer: String,
    pub seal_jwt_audience: String,
    pub openbao_addr: Option<String>,
    pub openbao_token: Option<String>,
    pub openbao_kv_mount: String,
    pub keycloak_token_exchange_url: Option<String>,
    pub keycloak_client_id: Option<String>,
    pub keycloak_client_secret: Option<String>,
    pub semantic_judge_url: Option<String>,
    pub ui_enabled: bool,
    pub container_cli: String,
    pub nfs_server_host: String,
    pub nfs_port: u16,
    pub nfs_mount_port: u16,
}

impl GatewayConfig {
    pub fn from_manifest(manifest: SealGatewayConfigManifest) -> anyhow::Result<Self> {
        let resolved_cli =
            container_cli::resolve_container_cli(manifest.spec.cli.container_cli.as_deref())?;
        let version = container_cli::validate_container_cli(&resolved_cli)?;
        tracing::info!(binary = %resolved_cli, version = %version, "Container CLI resolved");

        let jwks_validator =
            std::sync::Arc::new(crate::infrastructure::jwks_validator::JwksValidator::new(
                manifest.spec.auth.operator_jwks_uri.clone(),
                manifest.spec.auth.jwks_cache_ttl_secs,
            ));

        Ok(Self {
            bind_addr: manifest.spec.network.bind_addr,
            grpc_bind_addr: manifest.spec.network.grpc_bind_addr,
            database_url: manifest.spec.database.url,
            jwks_validator,
            operator_jwt_issuer: manifest.spec.auth.operator_jwt_issuer,
            operator_jwt_audience: manifest.spec.auth.operator_jwt_audience,
            auth_disabled: manifest.spec.auth.disabled,
            seal_jwt_public_key_pem: manifest.spec.auth.seal_jwt_public_key_pem,
            seal_jwt_issuer: manifest.spec.auth.seal_jwt_issuer,
            seal_jwt_audience: manifest.spec.auth.seal_jwt_audience,
            openbao_addr: manifest
                .spec
                .credentials
                .openbao_addr
                .filter(|value| !value.trim().is_empty()),
            openbao_token: manifest
                .spec
                .credentials
                .openbao_token
                .filter(|value| !value.trim().is_empty()),
            openbao_kv_mount: manifest.spec.credentials.openbao_kv_mount,
            keycloak_token_exchange_url: manifest
                .spec
                .credentials
                .keycloak_token_exchange_url
                .filter(|value| !value.trim().is_empty()),
            keycloak_client_id: manifest
                .spec
                .credentials
                .keycloak_client_id
                .filter(|value| !value.trim().is_empty()),
            keycloak_client_secret: manifest
                .spec
                .credentials
                .keycloak_client_secret
                .filter(|value| !value.trim().is_empty()),
            semantic_judge_url: manifest
                .spec
                .cli
                .semantic_judge_url
                .filter(|value| !value.trim().is_empty()),
            ui_enabled: manifest.spec.ui.enabled,
            container_cli: resolved_cli,
            nfs_server_host: manifest.spec.cli.nfs_server_host,
            nfs_port: manifest.spec.cli.nfs_port,
            nfs_mount_port: manifest.spec.cli.nfs_mount_port,
        })
    }

    pub fn load_or_default() -> anyhow::Result<Self> {
        let manifest = SealGatewayConfigManifest::load_or_default()?;
        Self::from_manifest(manifest)
    }
}
