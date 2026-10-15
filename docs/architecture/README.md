# Code Structure

AuthGate uses the existing zitadel OIDC provider and sqlc query layer. Package
boundaries are deliberately small; the application does not need another
framework or a generic workflow engine.

The [issuer signing-key rotation design](issuer-signing-key-rotation.md) records
the optional startup-loaded key bundle under [ADR-003](../adr/003-issuer-signing-key-rotation.md).
`storage` validates the bundle and owns one active private key plus public-only
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
| `db/queries`, `db/storeq` | SQL source and generated queries; runtime storage does not execute handwritten SQL |
| `upstream` | Upstream OIDC integration, including state/PKCE verification before callback completion |
| `adapter/mcp` | MCP resource policy and CIMD client metadata fetching/validation |
| `clientaccess`, `middleware` | Client access policy and HTTP cross-cutting concerns |
| `crypto`, `clock`, `idgen` | Cryptographic primitives and injectable time/identifier sources |

Services still use storage models through their store interfaces. The file
boundaries below improve navigation without changing package APIs or introducing
a second model hierarchy.

`app/metadata.go` serves both OIDC Discovery and OAuth authorization-server
metadata from `op.CreateDiscoveryConfig`. The library owns the complete OIDC
fields, provider endpoints and signing algorithms; AuthGate narrows response/grant
types and advertises its issuer-response and MCP/CIMD policies. `app/routes.go`
keeps `middleware.NoStore` outside the token rate limiter and response adapter,
so app-owned rejections and rewritten tokens share the cache prohibition.

`middleware/access_token_typ.go` adapts the trusted provider's token response:
it normalizes the access-token profile and rebinds the ID token's `at_hash`.
Its only storage dependency is the `SigningKey(ctx)` contract; key selection
and ownership remain in `storage`. The verified access-claims context used by
UserInfo/introspection stays private to `storage`. Response rewriting happens
after the provider's grant transaction and does not undo a committed grant on
signing or HTTP failure.

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
