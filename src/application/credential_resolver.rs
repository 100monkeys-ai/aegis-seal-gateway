use crate::domain::CredentialResolutionPath;
use crate::infrastructure::errors::GatewayError;

#[derive(Clone)]
pub struct CredentialResolver;

impl CredentialResolver {
    pub fn new() -> Self {
        Self
    }

    pub fn resolve(
        &self,
        path: &CredentialResolutionPath,
        zaru_user_token: Option<&str>,
    ) -> Result<Vec<(String, String)>, GatewayError> {
        match path {
            CredentialResolutionPath::SystemJit { role } => {
                let env_key = format!("OPENBAO_JIT_{}", role.to_ascii_uppercase());
                let secret = std::env::var(env_key).map_err(|_| {
                    GatewayError::NotFound(
                        "missing system JIT credential env var for configured role".to_string(),
                    )
                })?;
                Ok(vec![(
                    "Authorization".to_string(),
                    format!("Bearer {secret}"),
                )])
            }
            CredentialResolutionPath::HumanDelegated { target_service } => {
                let token = zaru_user_token.ok_or(GatewayError::Unauthorized)?;
                let header_name = format!("X-Delegated-{}-Token", target_service);
                Ok(vec![(header_name, token.to_string())])
            }
            CredentialResolutionPath::StaticRef(reference) => {
                let env_key = format!("OPENBAO_STATIC_{}", reference.key.to_ascii_uppercase());
                let token = std::env::var(env_key).map_err(|_| {
                    GatewayError::NotFound(
                        "missing static credential env var for configured reference".to_string(),
                    )
                })?;
                Ok(vec![(
                    "Authorization".to_string(),
                    format!("Bearer {token}"),
                )])
            }
            CredentialResolutionPath::None => Ok(Vec::new()),
        }
    }
}
