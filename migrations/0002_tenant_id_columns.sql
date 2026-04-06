-- Wave 5: Add tenant_id columns for full tenant isolation (gap 056)
--
-- NULL tenant_id = system-global row, visible to all tenants.
-- Non-NULL tenant_id = tenant-owned row, visible only to that tenant.

ALTER TABLE api_specs ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE cli_tools ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE seal_sessions ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE security_contexts ADD COLUMN IF NOT EXISTS tenant_id TEXT;

CREATE INDEX IF NOT EXISTS idx_api_specs_tenant_id ON api_specs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_workflows_tenant_id ON workflows(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cli_tools_tenant_id ON cli_tools(tenant_id);
CREATE INDEX IF NOT EXISTS idx_seal_sessions_tenant_id ON seal_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_contexts_tenant_id ON security_contexts(tenant_id);
