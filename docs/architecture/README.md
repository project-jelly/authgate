# Code Structure

AuthGate uses the existing zitadel OIDC provider and sqlc query layer. Package
boundaries are deliberately small; the application does not need another
framework or a generic workflow engine.

The [issuer signing-key rotation design](issuer-signing-key-rotation.md) records
the optional startup-loaded key bundle under [ADR-003](../adr/003-issuer-signing-key-rotation.md).
`signing` validates the bundle and owns one active private key plus public-only
verification sets; `app` selects the mode and wires a separate ID-token-hint key
set. The bundle remains fixed until process exit. The legacy single-key mode,
bundle contract and remaining deployment gates are documented in
[Operations](../spec/009-operations.md#키-로테이션).

## Package responsibilities

| Package | Responsibility |
|---|---|
| `app` | Composition root: configuration, crypto, provider/storage wiring, routes and server lifecycle |
| `handler` | HTTP binding, cookies, CSRF and rendering; delegates account decisions to services |
| `service` | Browser, MCP and device workflows, account access rules and lifecycle auditing |
| `storage` | zitadel storage adapter, persistence orchestration and transaction ownership |
| `signing` | Immutable signing-key bundle, legacy PEM loading, signing key selection and public JWKS |
| `client` | OAuth client model, YAML validation, static registry and resolution/resource policy contracts |
| `db/queries`, `db/storeq` | SQL source and generated queries; runtime storage does not execute handwritten SQL |
| `upstream` | Upstream OIDC integration, including state/PKCE verification before callback completion |
| `adapter/mcp` | MCP resource policy and CIMD client metadata fetching/validation |
| `clientaccess`, `middleware` | Client access policy and HTTP cross-cutting concerns |
| `crypto`, `clock`, `idgen` | Cryptographic primitives and injectable time/identifier sources |

Services use storage models through their store interfaces for persistence and
`client.Model` for OAuth client profiles. Each model has one owning package; the
component extraction does not introduce a second model hierarchy.

`app/metadata.go` serves both OIDC Discovery and OAuth authorization-server
metadata from `op.CreateDiscoveryConfig`. The library owns the complete OIDC
fields, provider endpoints and signing algorithms; AuthGate narrows response/grant
types and advertises its issuer-response and MCP/CIMD policies. `app/routes.go`
keeps `middleware.NoStore` outside the token rate limiter and response adapter,
so app-owned rejections and rewritten tokens share the cache prohibition.

## Component dependencies

`app` constructs and connects components. `storage` delegates its OIDC signing
methods to `signing.Provider`; the signing component does not import storage,
services, SQL or the composition root. Its private key models and validated bundle
remain private to that component. The compiler rejects import cycles, and the
component-boundary check in CI also guards this narrower ownership rule.

`client` owns its models and policy contracts. `storage`, services and the MCP
adapter depend on those contracts; the client component depends only on the
existing account-access policy package. Its static lookup methods never invoke
the configured resolver: code/refresh/device operations may hold DB locks, so
those paths must not fetch CIMD metadata. `Storage.CoreClientResolver` exposes
the static resolver for composition, while `Storage.ResolveClient` maps a client
lookup miss back to the storage sentinel used by OIDC error handling.

```text
internal/signing/
  provider.go     signing key selection and public key sets
  bundle.go       immutable validated bundle and hint-only public keys
  pem.go          legacy key file loading
  models.go       private OIDC key representations
internal/client/
  model.go        OAuth client representation and protocol methods
  config.go       YAML parsing and validation
  registry.go     static table and resolver delegation
  policy.go       resolution/resource contracts and default policies
  cimd.go         metadata fetch contract and client ID validation
```

The dependency direction is `app -> storage -> signing/client`, with services
and `adapter/mcp` also using client contracts. Neither extracted component
imports storage, services, handlers, SQL or the composition root. Code consumption
and refresh issuance/revocation retain their existing transaction owner.

## Login navigation

| File | Responsibility |
|---|---|
| `handler/login.go`, `handler/mcp_login.go` | Channel-specific entrypoints and upstream callbacks |
| `handler/login_response.go` | Shared login/callback HTTP responses and HTML error rendering (also used by logout) |
| `service/login_contract.go` | Store interface, action enum and result contracts shared by browser/MCP |
| `service/login.go` | Browser entry, session reuse, inactive-account and recovery decisions |
| `service/login_callback.go` | Browser callback, signup and account recovery |
| `service/login_request.go` | Channel binding, reused-session completion and callback request lookup |
| `service/prompt.go` | Login request lookup, prompt/max_age rules and authorization error redirects |
| `service/mcp_login.go` | MCP entry/callback; no signup or recovery |
| `service/device.go`, `handler/device.go` | Device flow and its explicit approval step |

The common HTTP response helpers do not decide access policy. They set a session
cookie only for a successful callback with a nonempty session ID. Unknown actions
remain channel-owned: MCP renders its existing error; browser behavior is unchanged.

Entry and callback request lookup intentionally retain different expired-request
responses: entry returns `auth_request_expired`/400, callback returns
`internal_error`/500. Changing that contract is separate from structural refactoring.

## Storage navigation

| File | Responsibility |
|---|---|
| `auth_requests.go` | Authorization request persistence, code lookup/validation, row mapping and max_age encoding |
| `token_issuance.go` | Access/refresh issuance and rotation transaction |
| `refresh_redemption.go` | Refresh lookup, redemption, account/resource/access validation and reuse handling |
| `refresh_grace.go` | Grace eligibility, per-parent child cap, locked recheck and grace audit |
| `refresh_revocation.go` | RFC 7009 grant revocation, family tombstones and transactional reuse audit |
| `sessions.go` | Session creation, lookup, auth_time and logout/session termination |
| `users.go` | User signup, identity lookup, hosted-domain updates and auth-request completion |
| `user_lifecycle.go` | Account deletion/recovery, disable/enable and user-wide credential revocation |
| `storage_oidc_device.go` | zitadel device authorization storage contract |

These are files within one package, not new abstraction layers. Transaction
ownership remains in the existing methods; moving a helper must not move a
`BeginTx`, row lock, commit, rollback or audit outside its original boundary.

## Invariants to preserve

- Only browser login can sign up or recover a pending-deletion account. Device,
  MCP and refresh do not acquire those capabilities from shared code.
- Session reuse retains the original `auth_time`; `prompt=none` never redirects
  upstream or recovers an account. MCP resource/channel binding remains enforced.
- Client access checks precede signup/recovery and are re-evaluated at token
  exchange. Refusals do not consume tokens or trigger reuse detection.
- Refresh issuance keeps its row-lock recheck, three-child cap, family tombstone
  checks and existing audit/transaction ordering.
- Logout ends browser sessions, not refresh grants; RFC 7009 revocation ends the
  refresh grant. Session and CSRF cookie policies remain distinct.
- Audit names, metadata and counts are contracts. See the
  [audit evidence matrix](../security/001-audit-evidence-matrix.md).

## Verification

Use the existing [GitHub Actions CI](../../.github/workflows/ci.yml) on a pull
request targeting `main` as the default verification path. It runs the build,
unit/integration tests with coverage, integration-enabled race detector, gofmt,
vet, lint, sqlc generation/vet, and runtime vulnerability checks.
Do not install local Go/Docker/C toolchains or repeat these checks locally just
to reproduce CI; inspect the failed job logs and push fixes to rerun the checks.
Local reproduction is reserved for an explicit request.
Compiling integration tests with `-run '^$'` does **not** execute those tests.
See [test documentation](../tests/README.md) for the regression cases.
