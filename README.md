# aegis-smcp-gateway

Standalone SMCP tooling gateway.

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
- `POST /v1/security-contexts`
- `GET /v1/security-contexts`
- `GET /v1/security-contexts/{name}`
- `GET /v1/tools`
- `POST /v1/explorer`
- `POST /v1/invoke`
- `GET /` (optional built-in web UI)

## Configuration

The gateway uses a Kubernetes-style YAML manifest:

- File name: `smcp-gateway-config.yaml`
- API version: `smcp.100monkeys.ai/v1`
- Kind: `SmcpGatewayConfig`

Discovery order:

1. `SMCP_GATEWAY_CONFIG_PATH`
2. `./smcp-gateway-config.yaml`
3. `~/.aegis/smcp-gateway-config.yaml`
4. `/etc/aegis/smcp-gateway-config.yaml` (Unix) or `ProgramData\\Aegis\\smcp-gateway-config.yaml` (Windows)

Environment variables are supported as runtime overrides (same names as before).

### YAML Example

```yaml
apiVersion: smcp.100monkeys.ai/v1
kind: SmcpGatewayConfig
metadata:
  name: aegis-smcp-gateway
  version: "1.0.0"
spec:
  network:
    bind_addr: "0.0.0.0:8089"
    grpc_bind_addr: "0.0.0.0:50055"
  database:
    url: "sqlite://gateway.db"
  auth:
    disabled: false
    operator_jwt_public_key_pem: ""
    operator_jwt_issuer: "aegis-keycloak"
    operator_jwt_audience: "aegis-smcp-gateway"
    smcp_jwt_public_key_pem: ""
    smcp_jwt_issuer: "aegis-orchestrator"
    smcp_jwt_audience: "aegis-agents"
  credentials:
    openbao_addr: null
    openbao_token: null
    openbao_kv_mount: "secret"
    keycloak_token_exchange_url: null
    keycloak_client_id: null
    keycloak_client_secret: null
  cli:
    semantic_judge_url: null
    nfs_server_host: "127.0.0.1"
    nfs_port: 2049
    nfs_mount_port: 20048
  ui:
    enabled: true
```

### Environment Overrides

- `SMCP_GATEWAY_BIND` (default: `0.0.0.0:8089`)
- `SMCP_GATEWAY_GRPC_BIND` (default: `0.0.0.0:50055`)
- `SMCP_GATEWAY_DB` (default: `sqlite://gateway.db`)
- `SMCP_GATEWAY_OPERATOR_JWT_PUBLIC_KEY_PEM` (required unless `SMCP_GATEWAY_AUTH_DISABLED=true`)
- `SMCP_GATEWAY_OPERATOR_JWT_ISSUER` (default: `aegis-keycloak`)
- `SMCP_GATEWAY_OPERATOR_JWT_AUDIENCE` (default: `aegis-smcp-gateway`)
- `SMCP_GATEWAY_SMCP_JWT_PUBLIC_KEY_PEM` (required)
- `SMCP_GATEWAY_SMCP_JWT_ISSUER` (default: `aegis-orchestrator`)
- `SMCP_GATEWAY_SMCP_JWT_AUDIENCE` (default: `aegis-agents`)
- `SMCP_GATEWAY_AUTH_DISABLED` (default: `false`)
- `SMCP_GATEWAY_OPENBAO_ADDR` (required for `SystemJit`/`StaticRef` credential paths)
- `SMCP_GATEWAY_OPENBAO_TOKEN` (required for `SystemJit`/`StaticRef` credential paths)
- `SMCP_GATEWAY_OPENBAO_KV_MOUNT` (default: `secret`)
- `SMCP_GATEWAY_KEYCLOAK_TOKEN_EXCHANGE_URL` (required for `HumanDelegated` credential path)
- `SMCP_GATEWAY_KEYCLOAK_CLIENT_ID` (required for `HumanDelegated` credential path)
- `SMCP_GATEWAY_KEYCLOAK_CLIENT_SECRET` (required for `HumanDelegated` credential path)
- `SMCP_GATEWAY_SEMANTIC_JUDGE_URL` (optional; required when invoking CLI tools with `require_semantic_judge=true`)
- `SMCP_GATEWAY_UI_ENABLED` (default: `true`; set to `false` to disable built-in web UI routes)
- `SMCP_GATEWAY_NFS_HOST` (default: `127.0.0.1`)
- `SMCP_GATEWAY_NFS_PORT` (default: `2049`)
- `SMCP_GATEWAY_NFS_MOUNT_PORT` (default: `20048`)
- `SMCP_GATEWAY_CONFIG_PATH` (optional explicit path to YAML manifest)

## Run

```bash
cargo run
```

The binary serves:

- HTTP control/invocation API on `SMCP_GATEWAY_BIND`
- gRPC `ToolWorkflowService` + `GatewayInvocationService` on `SMCP_GATEWAY_GRPC_BIND`

## License

AGPL-3.0. See [LICENSE](LICENSE) for details.
