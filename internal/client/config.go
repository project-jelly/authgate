package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kangheeyong/authgate/internal/clientaccess"
)

// ConfigFile represents the YAML client configuration file.
type ConfigFile struct {
	Clients []ConfigEntry `yaml:"clients"`
}

// ConfigEntry represents a single OAuth client in the YAML config.
type ConfigEntry struct {
	ClientID         string  `yaml:"client_id"`
	ClientSecretHash *string `yaml:"client_secret_hash,omitempty"`
	ClientType       string  `yaml:"client_type"`
	// SkipPKCE waives the PKCE S256 requirement for this client. Zero value
	// (false) keeps PKCE mandatory, so any client that forgets the field —
	// or is built on another code path, e.g. CIMD — stays protected.
	// Only confidential clients may set it: a public client has no secret,
	// so PKCE is its only defense against authorization code interception.
	SkipPKCE bool `yaml:"skip_pkce,omitempty"`
	// IDTokenUserinfoAssertion copies requested UserInfo claims into the ID token
	// for clients that do not call the UserInfo endpoint. It is opt-in because
	// the default OIDC code flow returns these claims from UserInfo.
	IDTokenUserinfoAssertion bool     `yaml:"id_token_userinfo_assertion,omitempty"`
	LoginChannel             string   `yaml:"login_channel"`
	Name                     string   `yaml:"name"`
	URL                      string   `yaml:"url,omitempty"`
	RedirectURIs             []string `yaml:"redirect_uris"`
	AllowedScopes            []string `yaml:"allowed_scopes"`
	AllowedGrantTypes        []string `yaml:"allowed_grant_types"`
	// Access restricts which accounts may use the client. nil (no access key)
	// admits every account; so does the explicit "access: public".
	Access *clientaccess.Policy `yaml:"access,omitempty"`
}

const (
	maxYAMLClientIDLength    = 2048
	maxYAMLClientNameLength  = 256
	maxYAMLRedirectURICount  = 10
	maxYAMLRedirectURILength = 2048
	maxYAMLGrantTypeCount    = 3
)

// LoadConfig reads and parses a clients.yaml file.
func LoadConfig(path string) (*ConfigFile, error) {
	//nolint:gosec // Path is operator-controlled CLIENT_CONFIG, not user input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Unknown fields are an error, not ignored. A misspelled key would
	// otherwise vanish without a trace, and for a security setting that means
	// the protection silently does not apply ("skip_pcke: false" is harmless,
	// but a misspelled restriction is not).
	var cfg ConfigFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	} else {
		// Only one document is read, so anything after a "---" separator would
		// be dropped unparsed, and an empty first document ("---\n---\nclients:")
		// would load no clients at all. Reject a second document instead.
		var extra yaml.Node
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse %s: multiple YAML documents are not supported", path)
		}
	}
	if err := rejectEmptyAccess(data); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	seen := make(map[string]bool, len(cfg.Clients))
	allowedGrants := map[string]bool{
		"authorization_code": true,
		"refresh_token":      true,
		"urn:ietf:params:oauth:grant-type:device_code": true,
	}
	for i, c := range cfg.Clients {
		if c.ClientID == "" {
			return nil, fmt.Errorf("client[%d]: client_id is required", i)
		}
		// #190: surrounding whitespace is rejected up front so the
		// IsCIMDClientID check below — which delegates to url.ParseRequestURI
		// and fails on leading/trailing space — cannot be tricked into
		// admitting a CIMD-shaped value as an opaque static ID.
		if strings.TrimSpace(c.ClientID) != c.ClientID {
			return nil, fmt.Errorf("client[%d] %q: client_id must not have leading or trailing whitespace", i, c.ClientID)
		}
		if len(c.ClientID) > maxYAMLClientIDLength {
			return nil, fmt.Errorf("client[%d] %q: client_id exceeds %d chars", i, c.ClientID, maxYAMLClientIDLength)
		}
		// #190: a URL-form (CIMD-shaped) client_id MUST NOT be registered
		// statically. ResolveClient consults the in-memory map before the
		// CIMD fetcher fallback, so a static URL-form entry would bypass
		// every HTTPS / content-type / redirect / size validation that
		// CIMDFetcher applies on dynamic resolution. The check runs before
		// the duplicate-id guard so the actionable "use dynamic CIMD"
		// message wins over the generic "duplicate" error.
		if IsCIMDClientID(c.ClientID) {
			return nil, fmt.Errorf("client[%d] %q: URL-form (CIMD-shaped) client_id cannot be registered statically; remove this entry and rely on dynamic CIMD resolution", i, c.ClientID)
		}
		if seen[c.ClientID] {
			return nil, fmt.Errorf("client[%d] %q: duplicate client_id", i, c.ClientID)
		}
		seen[c.ClientID] = true
		if c.ClientType != "public" && c.ClientType != "confidential" {
			return nil, fmt.Errorf("client[%d] %q: client_type must be public or confidential", i, c.ClientID)
		}
		if c.ClientType == "confidential" && (c.ClientSecretHash == nil || strings.TrimSpace(*c.ClientSecretHash) == "") {
			return nil, fmt.Errorf("client[%d] %q: confidential client requires client_secret_hash", i, c.ClientID)
		}
		if c.LoginChannel == "" {
			cfg.Clients[i].LoginChannel = "browser"
		} else if c.LoginChannel != "browser" && c.LoginChannel != "mcp" {
			return nil, fmt.Errorf("client[%d] %q: login_channel must be browser or mcp", i, c.ClientID)
		}
		// skip_pkce is an escape hatch for OIDC libraries that cannot send a
		// code_challenge. It is not a way to relax a channel's contract, so two
		// cases stay out of reach. Checked after the login_channel default is
		// applied, and against cfg.Clients[i] rather than the loop copy, so the
		// normalized value is what gets tested.
		if c.SkipPKCE {
			if c.ClientType != "confidential" {
				return nil, fmt.Errorf("client[%d] %q: skip_pkce is only allowed for confidential clients", i, c.ClientID)
			}
			// MCP requires PKCE S256 as part of its own contract (spec 004).
			// CIMD-registered clients are public and so already excluded; a
			// confidential mcp client declared in YAML is the one path that
			// could otherwise have waived it.
			if cfg.Clients[i].LoginChannel == "mcp" {
				return nil, fmt.Errorf("client[%d] %q: skip_pkce is not allowed on the mcp channel; PKCE S256 is part of the MCP contract", i, c.ClientID)
			}
		}
		if c.Name == "" {
			return nil, fmt.Errorf("client[%d] %q: name is required", i, c.ClientID)
		}
		if len(c.Name) > maxYAMLClientNameLength {
			return nil, fmt.Errorf("client[%d] %q: name exceeds %d chars", i, c.ClientID, maxYAMLClientNameLength)
		}
		if len(c.RedirectURIs) == 0 {
			return nil, fmt.Errorf("client[%d] %q: at least one redirect_uri is required", i, c.ClientID)
		}
		if len(c.RedirectURIs) > maxYAMLRedirectURICount {
			return nil, fmt.Errorf("client[%d] %q: redirect_uris exceeds %d entries", i, c.ClientID, maxYAMLRedirectURICount)
		}
		for _, uri := range c.RedirectURIs {
			if strings.TrimSpace(uri) == "" {
				return nil, fmt.Errorf("client[%d] %q: redirect_uri cannot be empty", i, c.ClientID)
			}
			if len(uri) > maxYAMLRedirectURILength {
				return nil, fmt.Errorf("client[%d] %q: redirect_uri exceeds %d chars", i, c.ClientID, maxYAMLRedirectURILength)
			}
		}
		if len(c.AllowedScopes) == 0 {
			return nil, fmt.Errorf("client[%d] %q: at least one allowed_scope is required", i, c.ClientID)
		}
		if len(c.AllowedGrantTypes) == 0 {
			return nil, fmt.Errorf("client[%d] %q: at least one allowed_grant_type is required", i, c.ClientID)
		}
		if len(c.AllowedGrantTypes) > maxYAMLGrantTypeCount {
			return nil, fmt.Errorf("client[%d] %q: allowed_grant_types exceeds %d entries", i, c.ClientID, maxYAMLGrantTypeCount)
		}
		for _, gt := range c.AllowedGrantTypes {
			if !allowedGrants[gt] {
				return nil, fmt.Errorf("client[%d] %q: unsupported allowed_grant_type %q", i, c.ClientID, gt)
			}
		}
	}

	return &cfg, nil
}

// rejectEmptyAccess refuses an access key with no value. yaml.v3 decodes a null
// into a nil pointer without calling the policy's unmarshaler, so "access:"
// would otherwise read as no access key at all: a client the operator meant to
// restrict — say, with every rule commented out — would silently be public.
func rejectEmptyAccess(data []byte) error {
	var raw struct {
		Clients []struct {
			ClientID string    `yaml:"client_id"`
			Access   yaml.Node `yaml:"access"`
		} `yaml:"clients"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}
	for i, c := range raw.Clients {
		// An alias ("access: *nul") is decoded as whatever it points at, so
		// follow it before looking for the null it may stand for.
		node := &c.Access
		for node.Kind == yaml.AliasNode && node.Alias != nil {
			node = node.Alias
		}
		if node.Kind == yaml.ScalarNode && node.ShortTag() == "!!null" {
			return fmt.Errorf("client[%d] %q: access is empty; remove it or write access: public", i, c.ClientID)
		}
	}
	return nil
}

// ValidateChannels enforces runtime channel constraints against loaded clients.
func ValidateChannels(clients []ConfigEntry, enableMCP bool) error {
	if enableMCP {
		return nil
	}
	for i, c := range clients {
		if c.LoginChannel == "mcp" {
			return fmt.Errorf("client[%d] %q: login_channel=mcp requires ENABLE_MCP=true", i, c.ClientID)
		}
	}
	return nil
}
