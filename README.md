# authgate

Minimal B2C OAuth2/OIDC authentication gateway built with [zitadel/oidc v3](https://github.com/zitadel/oidc).

authgate embeds the OAuth/OIDC provider in-process, delegates user authentication to an upstream OIDC IdP, and owns:

- browser login and automatic signup
- device authorization approval (RFC 8628)
- MCP login routing
- token rotation and revocation
- account deletion and cleanup

Authgate is a pure authentication service. Business logic such as terms of service, privacy consent, and role management is the responsibility of each consuming application.

## Architecture

```text
             upstream OIDC IdP
                    │
                    │ code exchange / userinfo
                    v
┌─────────────────────────────────────────────┐
│                  authgate                   │
│                                             │
│  handler  ->  service  ->  storage -> sqlc  │
│    │             │            │         │    │
│    │             │            │         └─ PostgreSQL │
│    │             └─ upstream                 │
│    └─ pages                                  │
│                                             │
│  zitadel/oidc provider is embedded here     │
└─────────────────────────────────────────────┘
```

## Login Channels

| Channel | Endpoints | Purpose |
|---------|-----------|---------|
| Browser | `/login`, `/login/callback` | Web app login and signup |
| Device | `/device`, `/device/approve`, `/device/auth/callback` | CLI device flow approval |
| MCP | `/mcp/login`, `/mcp/callback` | MCP OAuth login |

## Endpoints

| Path | Description |
|------|-------------|
| `/.well-known/openid-configuration` | OIDC discovery |
| `/keys` | JWKS |
| `/authorize` | Authorization endpoint |
| `/oauth/token` | Token endpoint |
| `/oauth/revoke` | Token revocation (RFC 7009) |
| `/oauth/device/authorize` | Device authorization (RFC 8628) |
| `/end_session` | RP-Initiated Logout |
| `/userinfo` | UserInfo endpoint |
| `/health` | Liveness check |
| `/ready` | Readiness check (DB ping) |

## Project Structure

```text
cmd/authgate/         main entrypoint
internal/
  config/             environment loading and validation
  db/
    queries/          handwritten SQL source (*.sql)
    storeq/           sqlc generated query layer (runtime DB contract)
  storage/            zitadel storage implementation + sqlc adapter orchestration
  service/            login, device, account, cleanup orchestration + access rules
  handler/            HTTP binding layer
  telemetry/          optional Go runtime/process Prometheus metrics
  upstream/           upstream OIDC provider integration (rp-based)
  pages/              embedded HTML templates (device, error, result)
  clock/              time abstraction
  idgen/              UUID and opaque token generation
  integration/        httptest integration server helpers
  testutil/           testcontainers PostgreSQL helper
examples/
  webapp/             sample web app (BFF pattern, PKCE, JWT verification)
  cli/                device flow CLI test tool
migrations/           schema SQL (apply in order)
docs/
  adr/                architecture decisions
  architecture/       package boundaries and code navigation
  spec/               product and protocol contracts
  security/           audit and compliance evidence mapping
  tests/              test design documents
```

See [Code Structure](docs/architecture/README.md) for package responsibilities and authentication invariants.

## Quick Start (Docker Compose)

```bash
# Start infrastructure (DB + mock OIDC IdP)
make infra

# Start authgate (terminal 1)
make dev-authgate

# Start sample webapp (terminal 2)
make dev-sample-app

# Open http://localhost:9090 in browser
# Device flow: cd examples/cli && go run .
```

## Running (manual)

Prerequisites:

- PostgreSQL
- an upstream OIDC provider (or mock-idp via Docker)
- schema applied: `001_init.sql`

```bash
# Migrations run automatically on startup (golang-migrate + schema_migrations
# state table + Postgres advisory lock). No manual psql step.

# Start server
export DATABASE_URL='postgres://...'
export SESSION_SECRET='replace-with-32+-chars'
export PUBLIC_URL='http://localhost:8080'
export OIDC_ISSUER_URL='http://localhost:8082'
export OIDC_CLIENT_ID='authgate'
export OIDC_CLIENT_SECRET='replace-me'
export DEV_MODE=true
export MIGRATIONS_PATH=./migrations

go run ./cmd/authgate
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | required | PostgreSQL connection string |
| `DB_MAX_OPEN_CONNS` | `25` | DB pool `MaxOpenConns` (`0` means unlimited) |
| `DB_MAX_IDLE_CONNS` | `25` | DB pool `MaxIdleConns` (clamped to `DB_MAX_OPEN_CONNS` when needed) |
| `DB_CONN_MAX_LIFETIME_SEC` | `300` | DB pool `ConnMaxLifetime` in seconds |
| `DB_CONN_MAX_IDLE_TIME_SEC` | `120` | DB pool `ConnMaxIdleTime` in seconds |
| `SESSION_SECRET` | required | provider crypto key source (>=32 chars in prod) |
| `PUBLIC_URL` | required | external authgate URL |
| `OIDC_ISSUER_URL` | `http://localhost:8082` | upstream OIDC issuer |
| `OIDC_INTERNAL_URL` | empty | internal URL for server-to-server OIDC calls (Docker/K8s) |
| `OIDC_HTTP_TIMEOUT_SEC` | `10` | outbound HTTP timeout for upstream OIDC discovery/token/userinfo calls |
| `OIDC_CLIENT_ID` | `authgate` | upstream OIDC client ID |
| `OIDC_CLIENT_SECRET` | empty | upstream OIDC client secret |
| `PORT` | `8080` | listen port |
| `DEV_MODE` | `false` | allows insecure local development mode |
| `SESSION_TTL` | `86400` | session TTL in seconds |
| `ACCESS_TOKEN_TTL` | `900` | access token TTL in seconds |
| `REFRESH_TOKEN_TTL` | `2592000` | refresh token TTL in seconds |
| `BRAND_LOGO_PATH` | – | Path to an SVG mark inlined into the device-flow pages. Unset renders the name alone. |
| `BRAND_PRIMARY_COLOR` | – | Accent colour for buttons and focus. Hex only; anything else refuses to start. |
| `AUDIT_LOG_PII_RETENTION_DAYS` | `90` | Days before **end-user** activity PII (`user_id`, IP, User-Agent) is anonymized. Minimum `30`. |
| `ADMIN_AUDIT_LOG_PII_RETENTION_DAYS` | `730` | Days before **operator action** (`admin.*`) PII is anonymized. Minimum `365`: these are the statutory access records. |
| `SIGNING_KEY_PATH` | `signing_key.pem` | Legacy RSA signing key path. Mount a persistent secret/volume in production. Mutually exclusive with a nonempty bundle path when explicitly set to a nonempty value. |
| `SIGNING_KEY_BUNDLE_PATH` | empty | Startup-loaded signing-key bundle: one active private key and separate published/hint public keys. Missing or invalid bundles refuse startup; no generation or legacy fallback. See [key rotation](docs/spec/009-operations.md#키-로테이션). |
| `HTTP_READ_HEADER_TIMEOUT_SEC` | `5` | HTTP server `ReadHeaderTimeout` in seconds |
| `HTTP_READ_TIMEOUT_SEC` | `15` | HTTP server `ReadTimeout` in seconds |
| `HTTP_WRITE_TIMEOUT_SEC` | `30` | HTTP server `WriteTimeout` in seconds |
| `HTTP_IDLE_TIMEOUT_SEC` | `60` | HTTP server `IdleTimeout` in seconds |
| `SHUTDOWN_TIMEOUT_SEC` | `10` | graceful shutdown timeout in seconds before forced close |
| `METRICS_ADDR` | empty | Optional internal metrics listener address. Empty disables metrics; when set, only Go runtime/process Prometheus metrics are exposed on this separate listener. |
| `ENABLE_MCP` | `true` | enable MCP optional adapter routes/policies (`/mcp/*`, CIMD/resource binding) |
| `CLIENT_CONFIG` | `/etc/authgate/clients.yaml` | YAML path for client metadata preload |

`ENABLE_MCP=false`일 때는 `clients.yaml`의 `login_channel: mcp` 클라이언트가 허용되지 않으며 서버 시작 시 실패합니다.

Production guards when `DEV_MODE=false`:

- `SESSION_SECRET` must be at least 32 characters
- `OIDC_ISSUER_URL` must start with `https://`
- `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` are required
- session cookies are issued with `Secure=true`

## Testing

```bash
# unit tests
go test ./internal/config ./internal/clock ./internal/idgen

# integration tests (requires Docker for testcontainers-go)
go test -tags integration ./internal/storage ./internal/service ./internal/integration
```

## Specs

- Service specs: [docs/spec/](docs/spec/README.md)
- Security evidence docs: [docs/security/](docs/security/README.md)
- Test design docs: [docs/tests/](docs/tests/README.md)

## License

Apache 2.0 — see [LICENSE](LICENSE)
