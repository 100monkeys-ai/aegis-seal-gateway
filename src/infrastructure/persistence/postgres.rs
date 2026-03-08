use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

use crate::domain::{
    ApiSpec, ApiSpecId, ApiSpecRepository, ApiSpecSummary, EphemeralCliTool,
    EphemeralCliToolRepository, EphemeralCliToolSummary, SmcpSessionRecord, SmcpSessionRepository,
    ToolWorkflow, ToolWorkflowRepository, ToolWorkflowSummary, WorkflowId,
};
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::persistence::EventStore;

#[derive(Clone)]
pub struct PostgresStore {
    pool: sqlx::PgPool,
}

impl PostgresStore {
    pub async fn new(database_url: &str) -> Result<Self, GatewayError> {
        let pool = sqlx::PgPool::connect(database_url).await?;
        sqlx::query(include_str!("schema_postgres.sql"))
            .execute(&pool)
            .await?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl EventStore for PostgresStore {
    async fn append_event(
        &self,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<(), GatewayError> {
        sqlx::query(
            "INSERT INTO gateway_events(event_type, payload, created_at) VALUES ($1, $2, $3)",
        )
        .bind(event_type)
        .bind(payload.to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl ApiSpecRepository for PostgresStore {
    async fn save(&self, spec: ApiSpec) -> Result<(), GatewayError> {
        sqlx::query(
            r#"INSERT INTO api_specs
            (id, name, base_url, source_url, raw_spec, operations, credential_path, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (id) DO UPDATE SET
              name = EXCLUDED.name,
              base_url = EXCLUDED.base_url,
              source_url = EXCLUDED.source_url,
              raw_spec = EXCLUDED.raw_spec,
              operations = EXCLUDED.operations,
              credential_path = EXCLUDED.credential_path,
              created_at = EXCLUDED.created_at"#,
        )
        .bind(spec.id.0.to_string())
        .bind(spec.name)
        .bind(spec.base_url)
        .bind(spec.source_url)
        .bind(spec.raw_spec.to_string())
        .bind(serde_json::to_string(&spec.operations)?)
        .bind(serde_json::to_string(&spec.credential_path)?)
        .bind(spec.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_id(&self, id: ApiSpecId) -> Result<Option<ApiSpec>, GatewayError> {
        let row = sqlx::query(
            "SELECT id,name,base_url,source_url,raw_spec,operations,credential_path,created_at FROM api_specs WHERE id=$1",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(api_spec_from_row).transpose()
    }

    async fn find_by_source_url(&self, url: &str) -> Result<Option<ApiSpec>, GatewayError> {
        let row = sqlx::query(
            "SELECT id,name,base_url,source_url,raw_spec,operations,credential_path,created_at FROM api_specs WHERE source_url=$1",
        )
        .bind(url)
        .fetch_optional(&self.pool)
        .await?;
        row.map(api_spec_from_row).transpose()
    }

    async fn list_all(&self) -> Result<Vec<ApiSpecSummary>, GatewayError> {
        let rows = sqlx::query("SELECT id,name,source_url FROM api_specs ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(ApiSpecSummary {
                    id: ApiSpecId(
                        Uuid::parse_str(&row.try_get::<String, _>("id")?)
                            .map_err(|e| GatewayError::Serialization(e.to_string()))?,
                    ),
                    name: row.try_get("name")?,
                    source_url: row.try_get("source_url")?,
                })
            })
            .collect()
    }

    async fn delete(&self, id: ApiSpecId) -> Result<(), GatewayError> {
        sqlx::query("DELETE FROM api_specs WHERE id=$1")
            .bind(id.0.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn api_spec_from_row(row: sqlx::postgres::PgRow) -> Result<ApiSpec, GatewayError> {
    let id_raw: String = row.try_get("id")?;
    let raw_spec_str: String = row.try_get("raw_spec")?;
    let operations_str: String = row.try_get("operations")?;
    let credential_path_str: String = row.try_get("credential_path")?;
    let created_at_str: String = row.try_get("created_at")?;

    Ok(ApiSpec {
        id: ApiSpecId(
            Uuid::parse_str(&id_raw).map_err(|e| GatewayError::Serialization(e.to_string()))?,
        ),
        name: row.try_get("name")?,
        base_url: row.try_get("base_url")?,
        source_url: row.try_get("source_url")?,
        raw_spec: serde_json::from_str(&raw_spec_str)?,
        operations: serde_json::from_str(&operations_str)?,
        credential_path: serde_json::from_str(&credential_path_str)?,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| GatewayError::Serialization(e.to_string()))?
            .with_timezone(&Utc),
    })
}

#[async_trait]
impl ToolWorkflowRepository for PostgresStore {
    async fn save(&self, workflow: ToolWorkflow) -> Result<(), GatewayError> {
        sqlx::query(
            r#"INSERT INTO workflows
            (id, name, description, input_schema, api_spec_id, steps, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (id) DO UPDATE SET
              name = EXCLUDED.name,
              description = EXCLUDED.description,
              input_schema = EXCLUDED.input_schema,
              api_spec_id = EXCLUDED.api_spec_id,
              steps = EXCLUDED.steps,
              created_at = EXCLUDED.created_at"#,
        )
        .bind(workflow.id.0.to_string())
        .bind(workflow.name)
        .bind(workflow.description)
        .bind(workflow.input_schema.to_string())
        .bind(workflow.api_spec_id.0.to_string())
        .bind(serde_json::to_string(&workflow.steps)?)
        .bind(workflow.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_id(&self, id: WorkflowId) -> Result<Option<ToolWorkflow>, GatewayError> {
        let row = sqlx::query(
            "SELECT id,name,description,input_schema,api_spec_id,steps,created_at FROM workflows WHERE id=$1",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(workflow_from_row).transpose()
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<ToolWorkflow>, GatewayError> {
        let row = sqlx::query(
            "SELECT id,name,description,input_schema,api_spec_id,steps,created_at FROM workflows WHERE name=$1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        row.map(workflow_from_row).transpose()
    }

    async fn list_all(&self) -> Result<Vec<ToolWorkflowSummary>, GatewayError> {
        let rows = sqlx::query("SELECT id,name,description FROM workflows ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(ToolWorkflowSummary {
                    id: WorkflowId(
                        Uuid::parse_str(&row.try_get::<String, _>("id")?)
                            .map_err(|e| GatewayError::Serialization(e.to_string()))?,
                    ),
                    name: row.try_get("name")?,
                    description: row.try_get("description")?,
                })
            })
            .collect()
    }

    async fn delete(&self, id: WorkflowId) -> Result<(), GatewayError> {
        sqlx::query("DELETE FROM workflows WHERE id=$1")
            .bind(id.0.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn workflow_from_row(row: sqlx::postgres::PgRow) -> Result<ToolWorkflow, GatewayError> {
    let id_raw: String = row.try_get("id")?;
    let api_spec_id_raw: String = row.try_get("api_spec_id")?;
    let input_schema_str: String = row.try_get("input_schema")?;
    let steps_str: String = row.try_get("steps")?;
    let created_at_str: String = row.try_get("created_at")?;

    Ok(ToolWorkflow {
        id: WorkflowId(
            Uuid::parse_str(&id_raw).map_err(|e| GatewayError::Serialization(e.to_string()))?,
        ),
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        input_schema: serde_json::from_str(&input_schema_str)?,
        api_spec_id: ApiSpecId(
            Uuid::parse_str(&api_spec_id_raw)
                .map_err(|e| GatewayError::Serialization(e.to_string()))?,
        ),
        steps: serde_json::from_str(&steps_str)?,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| GatewayError::Serialization(e.to_string()))?
            .with_timezone(&Utc),
    })
}

#[async_trait]
impl EphemeralCliToolRepository for PostgresStore {
    async fn save(&self, tool: EphemeralCliTool) -> Result<(), GatewayError> {
        tool.validate()?;
        sqlx::query(
            r#"INSERT INTO cli_tools
            (name, description, docker_image, allowed_subcommands, require_semantic_judge, default_timeout_seconds, registry_credentials_ref)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (name) DO UPDATE SET
              description = EXCLUDED.description,
              docker_image = EXCLUDED.docker_image,
              allowed_subcommands = EXCLUDED.allowed_subcommands,
              require_semantic_judge = EXCLUDED.require_semantic_judge,
              default_timeout_seconds = EXCLUDED.default_timeout_seconds,
              registry_credentials_ref = EXCLUDED.registry_credentials_ref"#,
        )
        .bind(tool.name)
        .bind(tool.description)
        .bind(tool.docker_image)
        .bind(serde_json::to_string(&tool.allowed_subcommands)?)
        .bind(tool.require_semantic_judge)
        .bind(i64::from(tool.default_timeout_seconds))
        .bind(
            tool.registry_credentials_ref
                .map(|value| serde_json::to_string(&value))
                .transpose()?,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<EphemeralCliTool>, GatewayError> {
        let row = sqlx::query(
            "SELECT name,description,docker_image,allowed_subcommands,require_semantic_judge,default_timeout_seconds,registry_credentials_ref FROM cli_tools WHERE name=$1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        row.map(cli_tool_from_row).transpose()
    }

    async fn list_all(&self) -> Result<Vec<EphemeralCliToolSummary>, GatewayError> {
        let rows = sqlx::query(
            "SELECT name,description,docker_image,allowed_subcommands FROM cli_tools ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(EphemeralCliToolSummary {
                    name: row.try_get("name")?,
                    description: row.try_get("description")?,
                    docker_image: row.try_get("docker_image")?,
                    allowed_subcommands: serde_json::from_str(
                        &row.try_get::<String, _>("allowed_subcommands")?,
                    )?,
                })
            })
            .collect()
    }

    async fn delete(&self, name: &str) -> Result<(), GatewayError> {
        sqlx::query("DELETE FROM cli_tools WHERE name=$1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn cli_tool_from_row(row: sqlx::postgres::PgRow) -> Result<EphemeralCliTool, GatewayError> {
    let registry_ref: Option<String> = row.try_get("registry_credentials_ref")?;
    Ok(EphemeralCliTool {
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        docker_image: row.try_get("docker_image")?,
        allowed_subcommands: serde_json::from_str(
            &row.try_get::<String, _>("allowed_subcommands")?,
        )?,
        require_semantic_judge: row.try_get("require_semantic_judge")?,
        default_timeout_seconds: row.try_get::<i64, _>("default_timeout_seconds")? as u32,
        registry_credentials_ref: registry_ref
            .map(|value| serde_json::from_str(&value))
            .transpose()?,
    })
}

#[async_trait]
impl SmcpSessionRepository for PostgresStore {
    async fn save(&self, session: SmcpSessionRecord) -> Result<(), GatewayError> {
        sqlx::query(
            r#"INSERT INTO smcp_sessions(execution_id, agent_id, security_context, public_key_b64, security_token, session_status, expires_at, allowed_tool_patterns)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (execution_id) DO UPDATE SET
                 agent_id = EXCLUDED.agent_id,
                 security_context = EXCLUDED.security_context,
                 public_key_b64 = EXCLUDED.public_key_b64,
                 security_token = EXCLUDED.security_token,
                 session_status = EXCLUDED.session_status,
                 expires_at = EXCLUDED.expires_at,
                 allowed_tool_patterns = EXCLUDED.allowed_tool_patterns"#,
        )
        .bind(session.execution_id)
        .bind(session.agent_id)
        .bind(session.security_context)
        .bind(session.public_key_b64)
        .bind(session.security_token)
        .bind(serde_json::to_string(&session.session_status)?)
        .bind(session.expires_at.to_rfc3339())
        .bind(serde_json::to_string(&session.allowed_tool_patterns)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_execution_id(
        &self,
        execution_id: &str,
    ) -> Result<Option<SmcpSessionRecord>, GatewayError> {
        let row = sqlx::query(
            "SELECT execution_id,agent_id,security_context,public_key_b64,security_token,session_status,expires_at,allowed_tool_patterns FROM smcp_sessions WHERE execution_id=$1",
        )
        .bind(execution_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|record| {
            Ok(SmcpSessionRecord {
                execution_id: record.try_get("execution_id")?,
                agent_id: record.try_get("agent_id")?,
                security_context: record.try_get("security_context")?,
                public_key_b64: record.try_get("public_key_b64")?,
                security_token: record.try_get("security_token")?,
                session_status: serde_json::from_str(
                    &record.try_get::<String, _>("session_status")?,
                )?,
                expires_at: chrono::DateTime::parse_from_rfc3339(
                    &record.try_get::<String, _>("expires_at")?,
                )
                .map_err(|e| GatewayError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
                allowed_tool_patterns: serde_json::from_str(
                    &record.try_get::<String, _>("allowed_tool_patterns")?,
                )?,
            })
        })
        .transpose()
    }
}
