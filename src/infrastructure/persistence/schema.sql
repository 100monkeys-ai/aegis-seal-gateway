CREATE TABLE IF NOT EXISTS api_specs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  base_url TEXT NOT NULL,
  source_url TEXT,
  raw_spec TEXT NOT NULL,
  operations TEXT NOT NULL,
  credential_path TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workflows (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL,
  input_schema TEXT NOT NULL,
  api_spec_id TEXT NOT NULL,
  steps TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cli_tools (
  name TEXT PRIMARY KEY,
  description TEXT NOT NULL,
  docker_image TEXT NOT NULL,
  allowed_subcommands TEXT NOT NULL,
  require_semantic_judge INTEGER NOT NULL,
  default_timeout_seconds INTEGER NOT NULL,
  registry_credential_path TEXT
);

CREATE TABLE IF NOT EXISTS seal_sessions (
  execution_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  security_context TEXT NOT NULL,
  public_key_b64 TEXT NOT NULL,
  security_token TEXT NOT NULL,
  session_status TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  allowed_tool_patterns TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_contexts (
  name TEXT PRIMARY KEY,
  capabilities TEXT NOT NULL,
  deny_list TEXT NOT NULL DEFAULT '[]',
  description TEXT
);

CREATE TABLE IF NOT EXISTS seen_jtis (
  jti TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);
