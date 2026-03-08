# aegis-smcp-gateway

Standalone SMCP tooling gateway implementing ADR-053.

## Features

- Workflow-first macro tools (`ToolWorkflow`) backed by OpenAPI operation resolution
- SMCP envelope verification for invocation endpoint
- Control-plane CRUD for API specs, workflows, and ephemeral CLI tools
- API Explorer with JSONPath response slicing
- Ephemeral CLI invocation in Docker with semantic gating
- SQLite-first persistence for standalone deployment

## API

- `POST /v1/specs`
- `GET /v1/specs`
- `GET /v1/specs/{id}`
- `DELETE /v1/specs/{id}`
- `POST /v1/workflows`
- `GET /v1/workflows`
- `GET /v1/workflows/{id}`
- `PUT /v1/workflows/{id}`
- `DELETE /v1/workflows/{id}`
- `POST /v1/cli-tools`
- `GET /v1/cli-tools`
- `DELETE /v1/cli-tools/{name}`
- `POST /v1/smcp/sessions`
- `GET /v1/tools`
- `POST /v1/explorer`
- `POST /v1/invoke`
- `POST /v1/invoke/internal`

## Configuration

Environment variables:

- `SMCP_GATEWAY_BIND` (default: `0.0.0.0:8089`)
- `SMCP_GATEWAY_DB` (default: `sqlite://gateway.db`)
- `SMCP_GATEWAY_JWT_SECRET` (default: `dev-secret`)
- `SMCP_GATEWAY_SMCP_TOKEN_SECRET` (default: `smcp-dev-secret`)
- `SMCP_GATEWAY_AUTH_DISABLED` (default: `false`)

## Run

```bash
cargo run
```
