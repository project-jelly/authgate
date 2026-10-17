package client

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/clientaccess"
)

func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "clients.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write clients.yaml: %v", err)
	}
	return p
}

// #190: a URL-form static client_id (i.e. one that satisfies IsCIMDClientID)
// must be rejected at config-load time. Otherwise an operator can register
// a CIMD-shaped client_id in the static map, where ResolveClient hits the
// in-memory hit before the CIMD fallback ever runs — bypassing every
// HTTPS / content-type / redirect / size validation that CIMDFetcher
// applies on dynamic resolution. Two cases pinned: a typical CIMD URL
// and the canonical RFC example shape.
func TestLoadConfig_RejectsCIMDShapedClientID(t *testing.T) {
	cases := []struct {
		name     string
		clientID string
	}{
		{"https path", "https://app.example.com/oauth/client.json"},
		{"https deep path", "https://example.com/.well-known/oauth-client"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfigFile(t, `
clients:
  - client_id: `+tc.clientID+`
    client_type: public
    login_channel: mcp
    name: CIMD-shaped
    redirect_uris: ["https://app.example.com/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)
			_, err := LoadConfig(path)
			if err == nil {
				t.Fatalf("expected URL-form client_id to be rejected, got nil")
			}
			if !strings.Contains(err.Error(), "CIMD") && !strings.Contains(err.Error(), "URL-form") {
				t.Fatalf("expected CIMD rejection error, got: %v", err)
			}
		})
	}
}

// #190 / Codex NIT-1: leading/trailing whitespace on client_id is rejected
// up front so the IsCIMDClientID guard — which delegates to
// url.ParseRequestURI and fails on space — cannot be tricked into admitting
// a CIMD-shaped value as an opaque static ID.
func TestLoadConfig_RejectsWhitespaceClientID(t *testing.T) {
	cases := []struct {
		name     string
		clientID string
	}{
		{"leading", " https-shaped"},
		{"trailing", "my-app "},
		{"both", " my-app "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfigFile(t, `
clients:
  - client_id: "`+tc.clientID+`"
    client_type: public
    login_channel: browser
    name: Whitespace
    redirect_uris: ["https://app.example.com/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)
			_, err := LoadConfig(path)
			if err == nil {
				t.Fatalf("expected whitespace client_id to be rejected, got nil")
			}
			if !strings.Contains(err.Error(), "whitespace") {
				t.Fatalf("expected whitespace rejection error, got: %v", err)
			}
		})
	}
}

func TestLoadConfig_DuplicateClientID(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App B
    redirect_uris: ["http://localhost:3001/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate client_id") {
		t.Fatalf("expected duplicate client_id error, got: %v", err)
	}
}

func TestLoadConfig_ConfidentialRequiresSecret(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: my-app
    client_type: confidential
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "requires client_secret_hash") {
		t.Fatalf("expected confidential secret error, got: %v", err)
	}
}

func TestLoadConfig_UnsupportedGrantType(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [client_credentials]
`)

	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported allowed_grant_type") {
		t.Fatalf("expected unsupported allowed_grant_type error, got: %v", err)
	}
}

func TestLoadConfig_NameTooLong(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: `+strings.Repeat("a", maxYAMLClientNameLength+1)+`
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "name exceeds") {
		t.Fatalf("expected name exceeds error, got: %v", err)
	}
}

func TestLoadConfig_TooManyRedirectURIs(t *testing.T) {
	var b strings.Builder
	b.WriteString("clients:\n")
	b.WriteString("  - client_id: my-app\n")
	b.WriteString("    client_type: public\n")
	b.WriteString("    login_channel: browser\n")
	b.WriteString("    name: App A\n")
	b.WriteString("    redirect_uris:\n")
	for i := 0; i < maxYAMLRedirectURICount+1; i++ {
		b.WriteString("      - \"http://localhost:3000/callback")
		b.WriteString(strings.Repeat("a", i))
		b.WriteString("\"\n")
	}
	b.WriteString("    allowed_scopes: [openid]\n")
	b.WriteString("    allowed_grant_types: [authorization_code]\n")

	path := writeConfigFile(t, b.String())

	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "redirect_uris exceeds") {
		t.Fatalf("expected redirect_uris exceeds error, got: %v", err)
	}
}

func TestLoadConfig_TooManyGrantTypes(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code, refresh_token, "urn:ietf:params:oauth:grant-type:device_code", refresh_token]
`)

	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "allowed_grant_types exceeds") {
		t.Fatalf("expected allowed_grant_types exceeds error, got: %v", err)
	}
}

func TestValidateChannels_MCPDisabledRejectsMCPClient(t *testing.T) {
	clients := []ConfigEntry{
		{
			ClientID:     "browser-client",
			LoginChannel: "browser",
		},
		{
			ClientID:     "mcp-client",
			LoginChannel: "mcp",
		},
	}

	err := ValidateChannels(clients, false)
	if err == nil || !strings.Contains(err.Error(), "requires ENABLE_MCP=true") {
		t.Fatalf("expected MCP disabled validation error, got: %v", err)
	}
}

func TestValidateChannels_MCPEnabledAllowsMCPClient(t *testing.T) {
	clients := []ConfigEntry{
		{
			ClientID:     "mcp-client",
			LoginChannel: "mcp",
		},
	}

	if err := ValidateChannels(clients, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// #190 / Codex NIT-3: LoadClients itself is a setter normally fed by the
// validated output of LoadConfig. As a belt-and-suspenders, the
// setter must drop URL-form client_ids if a future caller bypasses
// LoadConfig — otherwise the static-vs-dynamic invariant breaks
// silently for whatever test or admin path constructed the slice.
func TestLoadClients_DropsCIMDShapedClientID(t *testing.T) {
	r := NewRegistry()
	r.Load([]ConfigEntry{
		{ClientID: "static-ok", LoginChannel: "browser"},
		{ClientID: "https://app.example.com/oauth/client.json", LoginChannel: "mcp"},
	})

	if _, ok := r.clients.Load("static-ok"); !ok {
		t.Errorf("non-URL static-ok client should be loaded")
	}
	if _, ok := r.clients.Load("https://app.example.com/oauth/client.json"); ok {
		t.Errorf("URL-form client_id should NOT be loaded into static registry")
	}
}

func TestLoadConfig_SkipPKCERejectedForPublic(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    skip_pkce: true
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "skip_pkce is only allowed for confidential") {
		t.Fatalf("expected skip_pkce error, got: %v", err)
	}
}

func TestLoadConfig_SkipPKCEAllowedForConfidential(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: my-app
    client_type: confidential
    client_secret_hash: "$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"
    skip_pkce: true
    login_channel: browser
    name: App A
    redirect_uris: ["https://app.example.com/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}
	if !cfg.Clients[0].SkipPKCE {
		t.Fatal("expected SkipPKCE to be true")
	}
}

func TestLoadConfig_SkipPKCEDefaultsToFalse(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}
	if cfg.Clients[0].SkipPKCE {
		t.Fatal("expected SkipPKCE to default to false")
	}
}

func TestLoadConfig_IDTokenUserinfoAssertionOptIn(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: cloudflare-access
    client_type: confidential
    client_secret_hash: "$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"
    id_token_userinfo_assertion: true
    login_channel: browser
    name: Cloudflare Access
    redirect_uris: ["https://example.cloudflareaccess.com/cdn-cgi/access/callback"]
    allowed_scopes: [openid, profile, email]
    allowed_grant_types: [authorization_code]
`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}
	if !cfg.Clients[0].IDTokenUserinfoAssertion {
		t.Fatal("expected IDTokenUserinfoAssertion to be true")
	}

	r := NewRegistry()
	r.Load(cfg.Clients)
	loaded, ok := r.clients.Load("cloudflare-access")
	if !ok {
		t.Fatal("expected cloudflare-access client to be loaded")
	}
	if !loaded.(*Model).IDTokenUserinfoClaimsAssertion() {
		t.Fatal("expected client model to enable ID token UserInfo claims")
	}
}

func TestLoadConfig_IDTokenUserinfoAssertionDefaultsToFalse(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid, email]
    allowed_grant_types: [authorization_code]
`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}
	if cfg.Clients[0].IDTokenUserinfoAssertion {
		t.Fatal("expected IDTokenUserinfoAssertion to default to false")
	}
}

// skip_pkce must not reach the MCP channel. PKCE S256 is part of the MCP
// contract (spec 004), and the client_type guard alone does not cover it: a
// confidential client on login_channel: mcp would otherwise load fine and
// waive PKCE for a channel that requires it.
func TestLoadConfig_SkipPKCERejectedForMCPChannel(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: mcp-app
    client_type: confidential
    client_secret_hash: "$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"
    skip_pkce: true
    login_channel: mcp
    name: MCP App
    redirect_uris: ["https://app.example.com/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "skip_pkce is not allowed on the mcp channel") {
		t.Fatalf("expected mcp channel rejection, got: %v", err)
	}
}

// The browser channel is the one skip_pkce exists for, and it still loads when
// the channel is left implicit (login_channel defaults to browser). This pins
// the ordering: the guard reads the normalized value, so an omitted channel
// must not be mistaken for something other than browser.
func TestLoadConfig_SkipPKCEAllowedWithImplicitBrowserChannel(t *testing.T) {
	path := writeConfigFile(t, `
clients:
  - client_id: gitea
    client_type: confidential
    client_secret_hash: "$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"
    skip_pkce: true
    name: Gitea
    redirect_uris: ["https://git.example.com/user/oauth2/authgate/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}
	if !cfg.Clients[0].SkipPKCE {
		t.Fatal("expected SkipPKCE to be true")
	}
	if cfg.Clients[0].LoginChannel != "browser" {
		t.Fatalf("LoginChannel = %q, want browser", cfg.Clients[0].LoginChannel)
	}
}

// A misspelled or unknown key is rejected instead of silently ignored, at the
// top level and inside a client.
func TestLoadConfig_RejectsUnknownFields(t *testing.T) {
	for name, body := range map[string]string{
		"client field": `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
    skip_pcke: true
`,
		"top-level field": `
client:
  - client_id: my-app
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeConfigFile(t, body)); err == nil {
				t.Fatal("expected an error for an unknown field")
			}
		})
	}
}

// An empty file is an empty configuration, as before strict decoding. That
// includes a file whose clients are all commented out.
func TestLoadConfig_EmptyFileIsEmptyConfig(t *testing.T) {
	for name, body := range map[string]string{
		"empty":         "",
		"comments only": "# no clients yet\n",
		"separator":     "---\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadConfig(writeConfigFile(t, body))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(cfg.Clients) != 0 {
				t.Fatalf("clients = %d, want 0", len(cfg.Clients))
			}
		})
	}
}

// Content after a document separator would be dropped unparsed, so a second
// document is rejected, including the case where the first one is empty.
func TestLoadConfig_RejectsMultipleDocuments(t *testing.T) {
	client := `clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`
	for name, body := range map[string]string{
		"empty first document": "---\n---\n" + client,
		"second document":      client + "---\nskip_pcke: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeConfigFile(t, body)); err == nil {
				t.Fatal("expected an error for multiple YAML documents")
			}
		})
	}
}

// Every field in use by the production deployment still loads under strict
// decoding. Secret hashes are placeholders. Keep this in step with the
// deployed authgate-clients ConfigMap whenever it gains a key.
func TestLoadConfig_ProductionShapeStillLoads(t *testing.T) {
	body := `
clients:
  - client_id: opsgate-mcp
    client_type: public
    login_channel: mcp
    name: Opsgate MCP
    url: https://opsgate.example.com
    redirect_uris: [http://localhost/callback, http://127.0.0.1/callback]
    allowed_scopes: [openid, profile, email, offline_access]
    allowed_grant_types: [authorization_code, refresh_token]
  - client_id: notegate-cli
    client_type: public
    login_channel: browser
    name: Notegate CLI
    url: https://notegate.example.com
    redirect_uris: [http://127.0.0.1/callback]
    allowed_scopes: [openid, profile, email, offline_access]
    allowed_grant_types: ["urn:ietf:params:oauth:grant-type:device_code", refresh_token]
  - client_id: gitea
    client_type: confidential
    client_secret_hash: "$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"
    skip_pkce: true
    login_channel: browser
    name: Gitea
    url: https://gitea.example.com
    redirect_uris: [https://gitea.example.com/user/oauth2/authgate/callback]
    allowed_scopes: [openid, profile, email]
    allowed_grant_types: [authorization_code]
  - client_id: cloudflare-access
    client_type: confidential
    client_secret_hash: "$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"
    id_token_userinfo_assertion: true
    login_channel: browser
    name: Cloudflare Access
    url: https://example.cloudflareaccess.com
    redirect_uris: [https://example.cloudflareaccess.com/cdn-cgi/access/callback]
    allowed_scopes: [openid, profile, email]
    allowed_grant_types: [authorization_code]
`
	cfg, err := LoadConfig(writeConfigFile(t, body))
	if err != nil {
		t.Fatalf("production-shaped config no longer loads: %v", err)
	}
	if len(cfg.Clients) != 4 {
		t.Fatalf("clients = %d, want 4", len(cfg.Clients))
	}
}

// The repository's own sample configuration loads.
func TestLoadConfig_RepositorySampleLoads(t *testing.T) {
	if _, err := LoadConfig("../../clients.yaml"); err != nil {
		t.Fatalf("clients.yaml: %v", err)
	}
}

const accessClientPrefix = `
clients:
  - client_id: gitea
    client_type: public
    login_channel: browser
    name: Gitea
    redirect_uris: ["https://git.example.com/callback"]
    allowed_scopes: [openid, email]
    allowed_grant_types: [authorization_code, refresh_token]
`

// client-access-030: an access block loads into a restricted policy that
// ResolveClient hands to every channel, and "access: public" loads as the
// explicit public policy.
func TestLoadConfig_AccessPolicy(t *testing.T) {
	cfg, err := LoadConfig(writeConfigFile(t, accessClientPrefix+`    access:
      allow:
        google_workspace_domains: [corp.example]
        email_domains: [partner.example, "*.partner.example"]
        emails: [someone@gmail.com]
      deny:
        emails: [former@corp.example]
  - client_id: open
    client_type: public
    name: Open
    redirect_uris: ["https://open.example.com/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
    access: public
  - client_id: legacy
    client_type: public
    name: Legacy
    redirect_uris: ["https://legacy.example.com/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.Clients[0].Access.Restricted() {
		t.Fatal("gitea access policy not restricted")
	}
	if cfg.Clients[1].Access == nil || cfg.Clients[1].Access.Restricted() {
		t.Fatalf("access: public = %+v, want explicit public policy", cfg.Clients[1].Access)
	}
	if cfg.Clients[2].Access != nil {
		t.Fatalf("omitted access = %+v, want nil", cfg.Clients[2].Access)
	}

	r := NewRegistry()
	r.Load(cfg.Clients)
	client, err := r.Resolve(context.Background(), "gitea")
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if client.Access != cfg.Clients[0].Access {
		t.Fatal("ResolveClient did not carry the access policy")
	}
	if d := client.Access.Evaluate(clientaccess.Subject{Email: "x@eu.partner.example", EmailVerified: true}); !d.Allowed {
		t.Fatalf("loaded policy refused an allowed subject: %+v", d)
	}
	if d := client.Access.Evaluate(clientaccess.Subject{Email: "former@corp.example", HostedDomain: "corp.example"}); d.Allowed {
		t.Fatal("loaded policy ignored the deny list")
	}
	if got := r.StaticAccess("gitea"); got != client.Access {
		t.Fatal("staticAccess did not return the loaded policy")
	}
	if got := r.StaticAccess("unknown"); got != nil {
		t.Fatal("staticAccess returned a policy for an unregistered client")
	}
}

// client-access-031: a malformed access block stops startup. Unknown keys
// inside access are refused under the file's strict decoding, and an empty
// access key, including an alias that resolves to null, is refused instead of
// reading as public.
func TestLoadConfig_RejectsBadAccess(t *testing.T) {
	for name, tc := range map[string]struct{ access, want string }{
		"unknown key in access": {"    access:\n      alow:\n        emails: [a@b.example]\n", "alow"},
		"unknown key in allow":  {"    access:\n      allow:\n        email_domain: [b.example]\n", "email_domain"},
		"empty allow":           {"    access:\n      allow: {}\n", "at least one"},
		"missing allow":         {"    access:\n      deny:\n        emails: [a@b.example]\n", "allow is required"},
		"bad domain":            {"    access:\n      allow:\n        email_domains: [\"*.com\"]\n", "no dot"},
		"bad email":             {"    access:\n      allow:\n        emails: [someone]\n", "single address"},
		"empty access":          {"    access:\n", "access is empty"},
		"null access":           {"    access: null\n", "access is empty"},
		"alias to null":         {"    skip_pkce: &nul ~\n    access: *nul\n", "access is empty"},
		"other scalar":          {"    access: everyone\n", "public"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(writeConfigFile(t, accessClientPrefix+tc.access))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}
