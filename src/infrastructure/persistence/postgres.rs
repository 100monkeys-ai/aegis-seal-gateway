use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
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
pub struct PostgresStore {
    pool: sqlx::PgPool,
}

impl PostgresStore {
    pub async fn new(database_url: &str) -> Result<Self, GatewayError> {
        let pool = build_pool(database_url).await?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| GatewayError::Database(e.to_string()))?;
        Ok(Self { pool })
    }

    /// Construct a `PostgresStore` from an externally-supplied pool. Used by
    /// integration tests that need to control pool sizing (e.g. forcing a
    /// small pool to verify the cleanup batching releases connections between
    /// iterations).
    #[cfg(test)]
    pub fn from_pool(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

/// Build a Postgres connection pool with explicit limits and a short
/// `acquire_timeout` so that pool starvation surfaces as a fast error rather
/// than a silent 30 s hang on the request path.
///
/// All Postgres pools constructed by the gateway MUST go through this helper
/// to ensure consistent sizing across the main store and the credential pool
/// exposed to `CredentialResolver` (`main.rs`).
pub async fn build_pool(database_url: &str) -> Result<sqlx::PgPool, GatewayError> {
    Ok(PgPoolOptions::new()
        .max_connections(50)
        .min_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Some(Duration::from_secs(600)))
        .connect(database_url)
        .await?)
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
            (id, name, base_url, source_url, raw_spec, operations, credential_path, created_at, tenant_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (id) DO UPDATE SET
              name = EXCLUDED.name,
              base_url = EXCLUDED.base_url,
              source_url = EXCLUDED.source_url,
              raw_spec = EXCLUDED.raw_spec,
              operations = EXCLUDED.operations,
              credential_path = EXCLUDED.credential_path,
              created_at = EXCLUDED.created_at,
              tenant_id = EXCLUDED.tenant_id"#,
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
            "SELECT id,name,base_url,source_url,raw_spec,operations,credential_path,created_at,tenant_id FROM api_specs WHERE id=$1",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(api_spec_from_row).transpose()
    }

    async fn find_by_source_url(&self, url: &str) -> Result<Option<ApiSpec>, GatewayError> {
        let row = sqlx::query(
            "SELECT id,name,base_url,source_url,raw_spec,operations,credential_path,created_at,tenant_id FROM api_specs WHERE source_url=$1",
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
                "SELECT id,name,source_url FROM api_specs WHERE tenant_id=$1 OR tenant_id IS NULL ORDER BY name",
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
        tenant_id: row.try_get("tenant_id")?,
    })
}

#[async_trait]
impl ToolWorkflowRepository for PostgresStore {
    async fn save(&self, workflow: ToolWorkflow) -> Result<(), GatewayError> {
        sqlx::query(
            r#"INSERT INTO workflows
            (id, name, description, input_schema, api_spec_id, steps, created_at, tenant_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (id) DO UPDATE SET
              name = EXCLUDED.name,
              description = EXCLUDED.description,
              input_schema = EXCLUDED.input_schema,
              api_spec_id = EXCLUDED.api_spec_id,
              steps = EXCLUDED.steps,
              created_at = EXCLUDED.created_at,
              tenant_id = EXCLUDED.tenant_id"#,
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
            "SELECT id,name,description,input_schema,api_spec_id,steps,created_at,tenant_id FROM workflows WHERE id=$1",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(workflow_from_row).transpose()
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<ToolWorkflow>, GatewayError> {
        let row = sqlx::query(
            "SELECT id,name,description,input_schema,api_spec_id,steps,created_at,tenant_id FROM workflows WHERE name=$1",
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
                "SELECT id,name,description,input_schema FROM workflows WHERE tenant_id=$1 OR tenant_id IS NULL ORDER BY name",
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
        tenant_id: row.try_get("tenant_id")?,
    })
}

#[async_trait]
impl EphemeralCliToolRepository for PostgresStore {
    async fn save(&self, tool: EphemeralCliTool) -> Result<(), GatewayError> {
        tool.validate()?;
        sqlx::query(
            r#"INSERT INTO cli_tools
            (name, description, docker_image, allowed_subcommands, require_semantic_judge, default_timeout_seconds, registry_credential_path, tenant_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (name) DO UPDATE SET
              description = EXCLUDED.description,
              docker_image = EXCLUDED.docker_image,
              allowed_subcommands = EXCLUDED.allowed_subcommands,
              require_semantic_judge = EXCLUDED.require_semantic_judge,
              default_timeout_seconds = EXCLUDED.default_timeout_seconds,
              registry_credential_path = EXCLUDED.registry_credential_path,
              tenant_id = EXCLUDED.tenant_id"#,
        )
        .bind(tool.name)
        .bind(tool.description)
        .bind(tool.docker_image)
        .bind(serde_json::to_string(&tool.allowed_subcommands)?)
        .bind(tool.require_semantic_judge)
        .bind(i64::from(tool.default_timeout_seconds))
        .bind(
            tool.registry_credential_path
                .map(|value| serde_json::to_string(&value))
                .transpose()?,
        )
        .bind(tool.tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<EphemeralCliTool>, GatewayError> {
        let row = sqlx::query(
            "SELECT name,description,docker_image,allowed_subcommands,require_semantic_judge,default_timeout_seconds,registry_credential_path,tenant_id FROM cli_tools WHERE name=$1",
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
                "SELECT name,description,docker_image,allowed_subcommands,require_semantic_judge FROM cli_tools WHERE tenant_id=$1 OR tenant_id IS NULL ORDER BY name",
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
        sqlx::query("DELETE FROM cli_tools WHERE name=$1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn cli_tool_from_row(row: sqlx::postgres::PgRow) -> Result<EphemeralCliTool, GatewayError> {
    let registry_path: Option<String> = row.try_get("registry_credential_path")?;
    Ok(EphemeralCliTool {
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        docker_image: row.try_get("docker_image")?,
        allowed_subcommands: serde_json::from_str(
            &row.try_get::<String, _>("allowed_subcommands")?,
        )?,
        require_semantic_judge: row.try_get("require_semantic_judge")?,
        default_timeout_seconds: row.try_get::<i64, _>("default_timeout_seconds")? as u32,
        registry_credential_path: registry_path
            .map(|value| serde_json::from_str(&value))
            .transpose()?,
        tenant_id: row.try_get("tenant_id")?,
    })
}

#[async_trait]
impl SealSessionRepository for PostgresStore {
    async fn save(&self, session: SealSessionRecord) -> Result<(), GatewayError> {
        sqlx::query(
            r#"INSERT INTO seal_sessions(execution_id, agent_id, security_context, public_key_b64, security_token, session_status, expires_at, allowed_tool_patterns, tenant_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               ON CONFLICT (execution_id) DO UPDATE SET
                 agent_id = EXCLUDED.agent_id,
                 security_context = EXCLUDED.security_context,
                 public_key_b64 = EXCLUDED.public_key_b64,
                 security_token = EXCLUDED.security_token,
                 session_status = EXCLUDED.session_status,
                 expires_at = EXCLUDED.expires_at,
                 allowed_tool_patterns = EXCLUDED.allowed_tool_patterns,
                 tenant_id = EXCLUDED.tenant_id"#,
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
            "SELECT execution_id,agent_id,security_context,public_key_b64,security_token,session_status,expires_at,allowed_tool_patterns,tenant_id FROM seal_sessions WHERE execution_id=$1",
        )
        .bind(execution_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(seal_session_from_pg_row).transpose()
    }

    async fn list_active_for_tenant(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<SealSessionRecord>, GatewayError> {
        let rows = if let Some(tid) = tenant_id {
            sqlx::query(
                "SELECT execution_id,agent_id,security_context,public_key_b64,security_token,session_status,expires_at,allowed_tool_patterns,tenant_id FROM seal_sessions WHERE session_status='\"Active\"' AND (tenant_id=$1 OR tenant_id IS NULL)",
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
        rows.into_iter().map(seal_session_from_pg_row).collect()
    }

    async fn delete_by_execution_id(&self, execution_id: &str) -> Result<bool, GatewayError> {
        let result = sqlx::query(
            "UPDATE seal_sessions SET session_status='\"Revoked\"' WHERE execution_id=$1 AND session_status='\"Active\"'",
        )
        .bind(execution_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

fn seal_session_from_pg_row(
    record: sqlx::postgres::PgRow,
) -> Result<SealSessionRecord, GatewayError> {
    Ok(SealSessionRecord {
        execution_id: record.try_get("execution_id")?,
        agent_id: record.try_get("agent_id")?,
        security_context: record.try_get("security_context")?,
        public_key_b64: record.try_get("public_key_b64")?,
        security_token: record.try_get("security_token")?,
        session_status: serde_json::from_str(&record.try_get::<String, _>("session_status")?)?,
        expires_at: chrono::DateTime::parse_from_rfc3339(
            &record.try_get::<String, _>("expires_at")?,
        )
        .map_err(|e| GatewayError::Serialization(e.to_string()))?
        .with_timezone(&Utc),
        allowed_tool_patterns: serde_json::from_str(
            &record.try_get::<String, _>("allowed_tool_patterns")?,
        )?,
        tenant_id: record.try_get("tenant_id")?,
    })
}

#[async_trait]
impl SecurityContextRepository for PostgresStore {
    async fn save(&self, context: SecurityContext) -> Result<(), GatewayError> {
        sqlx::query(
            r#"INSERT INTO security_contexts(name, capabilities, deny_list, description, tenant_id)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (name) DO UPDATE SET
                 capabilities = EXCLUDED.capabilities,
                 deny_list = EXCLUDED.deny_list,
                 description = EXCLUDED.description,
                 tenant_id = EXCLUDED.tenant_id"#,
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
            "SELECT name, capabilities, deny_list, description, tenant_id FROM security_contexts WHERE name = $1",
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
                "SELECT name, capabilities, deny_list, description, tenant_id FROM security_contexts WHERE tenant_id=$1 OR tenant_id IS NULL ORDER BY name",
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
impl JtiRepository for PostgresStore {
    async fn record_jti(
        &self,
        jti: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<bool, GatewayError> {
        let result = sqlx::query(
            "INSERT INTO seen_jtis (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn cleanup_expired(&self) -> Result<u64, GatewayError> {
        let mut total = 0u64;
        loop {
            let result = sqlx::query(
                "DELETE FROM seen_jtis WHERE jti IN (\
                     SELECT jti FROM seen_jtis WHERE expires_at < $1 LIMIT 1000\
                 )",
            )
            .bind(Utc::now())
            .execute(&self.pool)
            .await?;
            let n = result.rows_affected();
            total += n;
            if n < 1000 {
                break;
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    //! Regression test for the JTI-cleanup pool-starvation incident.
    //!
    //! Before the fix (`fix/seal-gateway-pool-starvation`), `cleanup_expired`
    //! issued a single unbounded `DELETE FROM seen_jtis WHERE expires_at < $1`
    //! against a shared connection pool. With 100k+ expired rows on an
    //! unindexed `TEXT` column the delete held its connection for seconds at a
    //! time; on the production sqlx-default 10-connection pool every
    //! concurrent request competing for the pool would starve.
    //!
    //! This test reproduces that scenario by:
    //!
    //!   1. constraining the pool to a single connection (the same starvation
    //!      shape as production at peak),
    //!   2. seeding 100 000 expired `seen_jtis` rows,
    //!   3. spawning the new batched `cleanup_expired()` and a concurrent
    //!      `pool.acquire()` representing a request handler,
    //!   4. asserting the concurrent acquire completes within 2 s.
    //!
    //! Without batching the test would hang until cleanup finishes (≫ 2 s
    //! with 100 000 rows on a single connection). With the batched loop
    //! cleanup releases the connection between every 1 000-row batch, so the
    //! concurrent acquire interleaves and returns promptly.

    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use sqlx::Row;
    use std::time::{Duration as StdDuration, Instant};

    /// Build a single-connection pool against the same database as
    /// `seed_pool`. We can't reuse `seed_pool` directly because we need to
    /// cap connections at 1 to reproduce the starvation shape — the
    /// production pool is 50 after the fix, but the *batching* property of
    /// the cleanup loop is what matters and is most clearly observable when
    /// the pool is fully saturated by cleanup.
    async fn one_connection_pool(seed_pool: &sqlx::PgPool) -> sqlx::PgPool {
        let connect_options = seed_pool.connect_options().as_ref().clone();
        PgPoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .acquire_timeout(StdDuration::from_secs(10))
            .connect_with(connect_options)
            .await
            .expect("failed to build single-connection pool")
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn cleanup_does_not_starve_request_path(seed_pool: sqlx::PgPool) {
        // Insert 100 000 already-expired rows in one bulk statement. Doing
        // this via `record_jti` would issue 100k round-trips; we want the
        // test to be about cleanup behaviour, not seeding throughput.
        let expired = Utc::now() - chrono::Duration::hours(1);
        sqlx::query(
            "INSERT INTO seen_jtis (jti, expires_at) \
             SELECT 'jti-' || g::text, $1 FROM generate_series(1, 100000) AS g",
        )
        .bind(expired)
        .execute(&seed_pool)
        .await
        .expect("seeding expired JTIs failed");

        let row_count: i64 = sqlx::query("SELECT COUNT(*) FROM seen_jtis")
            .fetch_one(&seed_pool)
            .await
            .expect("count query failed")
            .try_get(0)
            .expect("count column missing");
        assert_eq!(row_count, 100_000, "seeding produced wrong row count");

        // Constrain the pool to one connection to reproduce the starvation
        // shape from production.
        let pool = one_connection_pool(&seed_pool).await;
        let store = PostgresStore::from_pool(pool.clone());

        // Spawn cleanup; concurrently attempt to acquire a connection. With
        // the unbatched DELETE the cleanup would hold the only connection
        // for the full table delete and the observer would block ≥
        // acquire_timeout.
        let cleanup_handle = tokio::spawn(async move {
            let started = Instant::now();
            let removed = store
                .cleanup_expired()
                .await
                .expect("cleanup_expired failed");
            (removed, started.elapsed())
        });

        // Give cleanup a moment to start and grab the connection at least
        // once, so the acquire below is genuinely contending.
        tokio::time::sleep(StdDuration::from_millis(50)).await;

        let acquire_start = Instant::now();
        let acquire_result =
            tokio::time::timeout(StdDuration::from_secs(2), async { pool.acquire().await }).await;
        let acquire_elapsed = acquire_start.elapsed();

        let conn = acquire_result.expect(
            "pool.acquire() exceeded 2s — cleanup is starving the request path (regression)",
        );
        let conn = conn.expect("pool.acquire() returned an error");
        drop(conn);

        let (removed, cleanup_elapsed) = cleanup_handle.await.expect("cleanup task panicked");

        assert!(
            acquire_elapsed < StdDuration::from_secs(2),
            "concurrent acquire took {acquire_elapsed:?} — batching did not release the \
             connection between iterations (regression)"
        );

        assert_eq!(
            removed, 100_000,
            "cleanup_expired drained {removed} rows; expected 100000"
        );

        let remaining: i64 = sqlx::query("SELECT COUNT(*) FROM seen_jtis")
            .fetch_one(&seed_pool)
            .await
            .expect("post-cleanup count failed")
            .try_get(0)
            .expect("count column missing");
        assert_eq!(remaining, 0, "expired rows not fully drained");

        eprintln!(
            "cleanup drained 100k rows in {cleanup_elapsed:?}; concurrent acquire returned in {acquire_elapsed:?}"
        );
    }
}
