# ADR-003: Resource-Bound Device Tokens (MCP CLI/Device)

## Status

Accepted (2026-09-23)

## Context

authgate has three login channels:

- Browser (`authorization_code` + PKCE)
- Device (`urn:ietf:params:oauth:grant-type:device_code`, RFC 8628)
- MCP (`authorization_code` + PKCE + RFC 8707 `resource` indicators)

MCP access tokens are audience-bound to a protected resource (`aud = resource`) so that an MCP server can reject tokens minted for a different resource. Device tokens historically were always audience-bound to the OAuth `client_id` (`aud = client_id`).

A previous attempt (#357) bound the MCP `resource` across the Device flow, but it was reverted (#359) because it overloaded `login_channel: mcp` as the opt-in signal. That conflated two independent dimensions:

1. The **login channel** determines which browser callback path and PKCE policy apply.
2. **Resource binding** is a separate authorization decision about whether a client may request audience-bound tokens for a specific protected resource.

After #357/#359, the `device_codes.resource` column and migration 016 were intentionally left in place as a reserved nullable column ([Spec 007](../spec/007-data-model.md), [Spec 010](../spec/010-upgrade-compatibility.md)).

Issue #184/#196 closed a boundary-confusion attack where a browser-channel client could request `resource=` and mint an MCP-audience token. The fix gated `resource` by `login_channel`:

- `mcp` channel: `resource` required.
- `browser` channel: `resource` forbidden.

That left Device grants with no safe path to request resource-bound tokens. We need an opt-in policy that is independent of `login_channel` and backward-compatible with existing clients.

## Decision

Introduce a per-client **`allowed_resources`** allowlist in `clients.yaml`. It is the explicit opt-in for RFC 8707 resource binding on the Device channel.

Rules:

1. **Empty `allowed_resources`** (the default) means the client is **not resource-bound**. Device grants behave as before: `aud = client_id`.
2. **Non-empty `allowed_resources`** means the client may request **exactly one** resource, and the value must match an entry in the allowlist.
3. `allowed_resources` is only meaningful for Device grants (`device_code` + `refresh_token`). A client with `allowed_resources` must include the `device_code` grant and must **not** include `authorization_code`.
4. The `mcp` channel retains its existing behavior for browser/MCP authorization-code flows (resource required, allowlist not enforced there; CIMD clients remain unrestricted by channel policy).
5. Resource-bound Device access tokens have `aud = resource`. The ID token keeps `aud = client_id` per OIDC Core.
6. The resource is bound at `/oauth/device/authorize`, stored in `device_codes.resource`, verified on every poll, inherited by the refresh token, and preserved across refresh.
7. A poll whose `resource` parameter is missing, duplicated, or mismatched is rejected **without consuming** the device code.
8. Resource-bound access tokens are rejected by `/userinfo` and `/oauth/introspect` unless the calling client owns the token. This keeps the existing access-token profile boundary (#392).

This design deliberately does not reuse `login_channel: mcp` for Device resource binding. A CLI-only client can stay on the Device grant while obtaining resource-bound tokens for a specific MCP server.

## Consequences

### Security

- #184's channel × resource matrix is preserved. Browser clients cannot request `resource=`.
- Resource-bound Device clients cannot be downgraded to `client_id` audience: the device code stores the bound resource and the token endpoint verifies it.
- A missing or mismatched resource at poll time does not consume the device code, so the user can retry with the correct resource.
- Per-client allowlists prevent client A from minting tokens for client B's resource, even if both are MCP servers.

### Backward Compatibility

- Existing Device clients without `allowed_resources` continue to issue `aud = client_id` tokens.
- Existing MCP authorization-code clients are unaffected.
- The unused `device_codes.resource` column (migration 016) is activated without a new migration.

### Operational Impact

- Operators must add `allowed_resources` explicitly for each CLI/Device client that needs resource-bound tokens.
- `clients.yaml` validation rejects misconfigurations (browser channel with `allowed_resources`, `allowed_resources` without `device_code`, mixed `authorization_code` + `allowed_resources`).

## Alternatives Considered

1. **Reuse `login_channel: mcp` for Device grants** — rejected in #359. It mixes channel policy with audience policy and forces Device clients into the MCP browser callback path.
2. **A global `ENABLE_MCP_DEVICE_RESOURCE` flag** — rejected. It is too coarse and does not let operators restrict which resources each client may target.
3. **Allow multiple `resource` parameters** — rejected. RFC 8707 permits multiple resource parameters, but authgate enforces a single-audience policy to prevent audience smuggling (#184).

## Related

- #184 / #196: channel × resource gating
- #357 / #359: previous MCP Device resource binding and revert
- [Spec 003: Device Login](../spec/003-device-login.md)
- [Spec 004: MCP Login](../spec/004-mcp-login.md)
- [Spec 005: Token Lifecycle](../spec/005-token-lifecycle.md)
- [Spec 007: Data Model](../spec/007-data-model.md)
- [Spec 009: Operations](../spec/009-operations.md)
- [Spec 010: Upgrade Compatibility](../spec/010-upgrade-compatibility.md)
