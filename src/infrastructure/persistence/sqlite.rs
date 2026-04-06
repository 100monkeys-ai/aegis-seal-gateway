use async_trait::async_trait;
use chrono::Utc;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::Row;
use std::str::FromStr;
use uuid::Uuid;

use crate::domain::{
    ApiSpec, ApiSpecId, ApiSpecRepository, ApiSpecSummary, EphemeralCliTool,
    EphemeralCliToolRepository, EphemeralCliToolSummary, JtiRepository, SealSessionRecord,
    SealSessionRepository, SecurityContext, SecurityContextRepository, ToolWorkflow,
    ToolWorkflowRepository, ToolWorkflowSummary, WorkflowId,
};
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::persistence::EventStore;

#[derive(Clone)]
pub struct SqliteStore {
    pool: sqlx::SqlitePool,
}

impl SqliteStore {
    pub async fn new(database_url: &str) -> Result<Self, GatewayError> {
        // Ensure the parent directory exists before connecting.
        // SQLite cannot create intermediate directories itself; a missing parent
        // causes SQLITE_CANTOPEN (error code 14) even with create_if_missing.
        let db_path_str = database_url
            .strip_prefix("sqlite://")
            .unwrap_or(database_url);
        if let Some(parent) = std::path::Path::new(db_path_str).parent() {
            if parent.components().count() > 0 {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    GatewayError::Internal(format!(
                        "failed to create database directory '{}': {e}",
                        parent.display()
                    ))
                })?;
            }
        }

        let connect_options = SqliteConnectOptions::from_str(database_url)
            .map_err(|e| GatewayError::Database(e.to_string()))?
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(connect_options).await?;
        sqlx::query(include_str!("schema.sql"))
            .execute(&pool)
            .await?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl EventStore for SqliteStore {
    async fn append_event(
        &self,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<(), GatewayError> {
        sqlx::query("INSERT INTO gateway_events(event_type, payload, created_at) VALUES (?, ?, ?)")
            .bind(event_type)
            .bind(payload.to_string())
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ApiSpecRepository for SqliteStore {
    async fn save(&self, spec: ApiSpec) -> Result<(), GatewayError> {
        sqlx::query(
            r#"INSERT OR REPLACE INTO api_specs
            (id, name, base_url, source_url, raw_spec, operations, credential_path, created_at, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(spec.id.0.to_string())
        .bind(spec.name)
        .bind(spec.base_url)
        .bind(spec.source_url)
        .bind(spec.raw_spec.to_string())
        .bind(serde_json::to_string(&spec.operations)?)
        .bind(serde_json::to_string(&spec.credential_path)?)
        .bind(spec.created_at.to_rfc3339())
        .bind(spec.tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_id(&self, id: ApiSpecId) -> Result<Option<ApiSpec>, GatewayError> {
        let row = sqlx::query(
            "SELECT id,name,base_url,source_url,raw_spec,operations,credential_path,created_at,tenant_id FROM api_specs WHERE id=?",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await?;

        row.map(api_spec_from_row).transpose()
    }

    async fn find_by_source_url(&self, url: &str) -> Result<Option<ApiSpec>, GatewayError> {
        let row = sqlx::query(
            "SELECT id,name,base_url,source_url,raw_spec,operations,credential_path,created_at,tenant_id FROM api_specs WHERE source_url=?",
        )
        .bind(url)
        .fetch_optional(&self.pool)
        .await?;

        row.map(api_spec_from_row).transpose()
    }

    async fn list_for_tenant(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<ApiSpecSummary>, GatewayError> {
        let rows = if let Some(tid) = tenant_id {
            sqlx::query(
                "SELECT id,name,source_url FROM api_specs WHERE tenant_id=? OR tenant_id IS NULL ORDER BY name",
            )
            .bind(tid)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id,name,source_url FROM api_specs WHERE tenant_id IS NULL ORDER BY name",
            )
            .fetch_all(&self.pool)
            .await?
        };
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
        sqlx::query("DELETE FROM api_specs WHERE id=?")
            .bind(id.0.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn api_spec_from_row(row: sqlx::sqlite::SqliteRow) -> Result<ApiSpec, GatewayError> {
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
        tenant_id: row.try_get("tenant_id")?,
    })
}

#[async_trait]
impl ToolWorkflowRepository for SqliteStore {
    async fn save(&self, workflow: ToolWorkflow) -> Result<(), GatewayError> {
        sqlx::query(
            r#"INSERT OR REPLACE INTO workflows
            (id, name, description, input_schema, api_spec_id, steps, created_at, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(workflow.id.0.to_string())
        .bind(workflow.name)
        .bind(workflow.description)
        .bind(workflow.input_schema.to_string())
        .bind(workflow.api_spec_id.0.to_string())
        .bind(serde_json::to_string(&workflow.steps)?)
        .bind(workflow.created_at.to_rfc3339())
        .bind(workflow.tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_id(&self, id: WorkflowId) -> Result<Option<ToolWorkflow>, GatewayError> {
        let row = sqlx::query(
            "SELECT id,name,description,input_schema,api_spec_id,steps,created_at,tenant_id FROM workflows WHERE id=?",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(workflow_from_row).transpose()
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<ToolWorkflow>, GatewayError> {
        let row = sqlx::query(
            "SELECT id,name,description,input_schema,api_spec_id,steps,created_at,tenant_id FROM workflows WHERE name=?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        row.map(workflow_from_row).transpose()
    }

    async fn list_for_tenant(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<ToolWorkflowSummary>, GatewayError> {
        let rows = if let Some(tid) = tenant_id {
            sqlx::query(
                "SELECT id,name,description,input_schema FROM workflows WHERE tenant_id=? OR tenant_id IS NULL ORDER BY name",
            )
            .bind(tid)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id,name,description,input_schema FROM workflows WHERE tenant_id IS NULL ORDER BY name",
            )
            .fetch_all(&self.pool)
            .await?
        };
        rows.into_iter()
            .map(|row| {
                Ok(ToolWorkflowSummary {
                    id: WorkflowId(
                        Uuid::parse_str(&row.try_get::<String, _>("id")?)
                            .map_err(|e| GatewayError::Serialization(e.to_string()))?,
                    ),
                    name: row.try_get("name")?,
                    description: row.try_get("description")?,
                    input_schema: serde_json::from_str(&row.try_get::<String, _>("input_schema")?)?,
                })
            })
            .collect()
    }

    async fn delete(&self, id: WorkflowId) -> Result<(), GatewayError> {
        sqlx::query("DELETE FROM workflows WHERE id=?")
            .bind(id.0.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn workflow_from_row(row: sqlx::sqlite::SqliteRow) -> Result<ToolWorkflow, GatewayError> {
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
        tenant_id: row.try_get("tenant_id")?,
    })
}

#[async_trait]
impl EphemeralCliToolRepository for SqliteStore {
    async fn save(&self, tool: EphemeralCliTool) -> Result<(), GatewayError> {
        tool.validate()?;
        sqlx::query(
            r#"INSERT OR REPLACE INTO cli_tools
            (name, description, docker_image, allowed_subcommands, require_semantic_judge, default_timeout_seconds, registry_credential_path, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(tool.name)
        .bind(tool.description)
        .bind(tool.docker_image)
        .bind(serde_json::to_string(&tool.allowed_subcommands)?)
        .bind(i64::from(tool.require_semantic_judge))
        .bind(i64::from(tool.default_timeout_seconds))
        .bind(
            tool.registry_credential_path
                .map(|v| serde_json::to_string(&v))
                .transpose()?,
        )
        .bind(tool.tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<EphemeralCliTool>, GatewayError> {
        let row = sqlx::query(
            "SELECT name,description,docker_image,allowed_subcommands,require_semantic_judge,default_timeout_seconds,registry_credential_path,tenant_id FROM cli_tools WHERE name=?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        row.map(cli_tool_from_row).transpose()
    }

    async fn list_for_tenant(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<EphemeralCliToolSummary>, GatewayError> {
        let rows = if let Some(tid) = tenant_id {
            sqlx::query(
                "SELECT name,description,docker_image,allowed_subcommands,require_semantic_judge FROM cli_tools WHERE tenant_id=? OR tenant_id IS NULL ORDER BY name",
            )
            .bind(tid)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT name,description,docker_image,allowed_subcommands,require_semantic_judge FROM cli_tools WHERE tenant_id IS NULL ORDER BY name",
            )
            .fetch_all(&self.pool)
            .await?
        };
        rows.into_iter()
            .map(|row| {
                Ok(EphemeralCliToolSummary {
                    name: row.try_get("name")?,
                    description: row.try_get("description")?,
                    docker_image: row.try_get("docker_image")?,
                    allowed_subcommands: serde_json::from_str(
                        &row.try_get::<String, _>("allowed_subcommands")?,
                    )?,
                    require_semantic_judge: row.try_get("require_semantic_judge")?,
                })
            })
            .collect()
    }

    async fn delete(&self, name: &str) -> Result<(), GatewayError> {
        sqlx::query("DELETE FROM cli_tools WHERE name=?")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn cli_tool_from_row(row: sqlx::sqlite::SqliteRow) -> Result<EphemeralCliTool, GatewayError> {
    let registry_path: Option<String> = row.try_get("registry_credential_path")?;
    Ok(EphemeralCliTool {
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        docker_image: row.try_get("docker_image")?,
        allowed_subcommands: serde_json::from_str(
            &row.try_get::<String, _>("allowed_subcommands")?,
        )?,
        require_semantic_judge: row.try_get::<i64, _>("require_semantic_judge")? != 0,
        default_timeout_seconds: row.try_get::<i64, _>("default_timeout_seconds")? as u32,
        registry_credential_path: registry_path
            .map(|v| serde_json::from_str(&v))
            .transpose()?,
        tenant_id: row.try_get("tenant_id")?,
    })
}

#[async_trait]
impl SealSessionRepository for SqliteStore {
    async fn save(&self, session: SealSessionRecord) -> Result<(), GatewayError> {
        sqlx::query(
            "INSERT OR REPLACE INTO seal_sessions(execution_id, agent_id, security_context, public_key_b64, security_token, session_status, expires_at, allowed_tool_patterns, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(session.execution_id)
        .bind(session.agent_id)
        .bind(session.security_context)
        .bind(session.public_key_b64)
        .bind(session.security_token)
        .bind(serde_json::to_string(&session.session_status)?)
        .bind(session.expires_at.to_rfc3339())
        .bind(serde_json::to_string(&session.allowed_tool_patterns)?)
        .bind(session.tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_execution_id(
        &self,
        execution_id: &str,
    ) -> Result<Option<SealSessionRecord>, GatewayError> {
        let row = sqlx::query(
            "SELECT execution_id,agent_id,security_context,public_key_b64,security_token,session_status,expires_at,allowed_tool_patterns,tenant_id FROM seal_sessions WHERE execution_id=?",
        )
        .bind(execution_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(seal_session_from_sqlite_row).transpose()
    }

    async fn list_active_for_tenant(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<SealSessionRecord>, GatewayError> {
        let rows = if let Some(tid) = tenant_id {
            sqlx::query(
                "SELECT execution_id,agent_id,security_context,public_key_b64,security_token,session_status,expires_at,allowed_tool_patterns,tenant_id FROM seal_sessions WHERE session_status='\"Active\"' AND (tenant_id=? OR tenant_id IS NULL)",
            )
            .bind(tid)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT execution_id,agent_id,security_context,public_key_b64,security_token,session_status,expires_at,allowed_tool_patterns,tenant_id FROM seal_sessions WHERE session_status='\"Active\"'",
            )
            .fetch_all(&self.pool)
            .await?
        };
        rows.into_iter().map(seal_session_from_sqlite_row).collect()
    }

    async fn delete_by_execution_id(&self, execution_id: &str) -> Result<bool, GatewayError> {
        let result = sqlx::query(
            "UPDATE seal_sessions SET session_status='\"Revoked\"' WHERE execution_id=? AND session_status='\"Active\"'",
        )
        .bind(execution_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

fn seal_session_from_sqlite_row(
    r: sqlx::sqlite::SqliteRow,
) -> Result<SealSessionRecord, GatewayError> {
    Ok(SealSessionRecord {
        execution_id: r.try_get("execution_id")?,
        agent_id: r.try_get("agent_id")?,
        security_context: r.try_get("security_context")?,
        public_key_b64: r.try_get("public_key_b64")?,
        security_token: r.try_get("security_token")?,
        session_status: serde_json::from_str(&r.try_get::<String, _>("session_status")?)?,
        expires_at: chrono::DateTime::parse_from_rfc3339(&r.try_get::<String, _>("expires_at")?)
            .map_err(|e| GatewayError::Serialization(e.to_string()))?
            .with_timezone(&Utc),
        allowed_tool_patterns: serde_json::from_str(
            &r.try_get::<String, _>("allowed_tool_patterns")?,
        )?,
        tenant_id: r.try_get("tenant_id")?,
    })
}

#[async_trait]
impl SecurityContextRepository for SqliteStore {
    async fn save(&self, context: SecurityContext) -> Result<(), GatewayError> {
        sqlx::query(
            "INSERT OR REPLACE INTO security_contexts(name, capabilities, deny_list, description, tenant_id) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(context.name)
        .bind(serde_json::to_string(&context.capabilities)?)
        .bind(serde_json::to_string(&context.deny_list)?)
        .bind(context.description)
        .bind(context.tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<SecurityContext>, GatewayError> {
        let row = sqlx::query(
            "SELECT name, capabilities, deny_list, description, tenant_id FROM security_contexts WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| {
            Ok(SecurityContext {
                name: r.try_get("name")?,
                capabilities: serde_json::from_str(&r.try_get::<String, _>("capabilities")?)?,
                deny_list: serde_json::from_str(&r.try_get::<String, _>("deny_list")?)?,
                description: r.try_get("description")?,
                tenant_id: r.try_get("tenant_id")?,
            })
        })
        .transpose()
    }

    async fn list_for_tenant(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<SecurityContext>, GatewayError> {
        let rows = if let Some(tid) = tenant_id {
            sqlx::query(
                "SELECT name, capabilities, deny_list, description, tenant_id FROM security_contexts WHERE tenant_id=? OR tenant_id IS NULL ORDER BY name",
            )
            .bind(tid)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT name, capabilities, deny_list, description, tenant_id FROM security_contexts WHERE tenant_id IS NULL ORDER BY name",
            )
            .fetch_all(&self.pool)
            .await?
        };
        rows.into_iter()
            .map(|row| {
                Ok(SecurityContext {
                    name: row.try_get("name")?,
                    capabilities: serde_json::from_str(&row.try_get::<String, _>("capabilities")?)?,
                    deny_list: serde_json::from_str(&row.try_get::<String, _>("deny_list")?)?,
                    description: row.try_get("description")?,
                    tenant_id: row.try_get("tenant_id")?,
                })
            })
            .collect()
    }
}

#[async_trait]
impl JtiRepository for SqliteStore {
    async fn record_jti(
        &self,
        jti: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<bool, GatewayError> {
        let result = sqlx::query("INSERT OR IGNORE INTO seen_jtis (jti, expires_at) VALUES (?, ?)")
            .bind(jti)
            .bind(expires_at.to_rfc3339())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn cleanup_expired(&self) -> Result<u64, GatewayError> {
        let result = sqlx::query("DELETE FROM seen_jtis WHERE expires_at < ?")
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
