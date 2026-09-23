package integration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	mcpadapter "github.com/kangheeyong/authgate/internal/adapter/mcp"
	"github.com/kangheeyong/authgate/internal/clientaccess"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/crypto"
	"github.com/kangheeyong/authgate/internal/handler"
	"github.com/kangheeyong/authgate/internal/idgen"
	"golang.org/x/time/rate"

	"github.com/kangheeyong/authgate/internal/middleware"
	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/testutil"
	"github.com/kangheeyong/authgate/internal/upstream"
)

// devicePollInterval mirrors the production constant in cmd/authgate/main.go
// so the integration server advertises and enforces the same RFC 8628 §3.5
// poll cadence the binary ships with.
const devicePollInterval = 5 * time.Second

// skipPKCEClientSecretHash is bcrypt("skip-pkce-secret"). Only the authorize
// leg is exercised, so the value never has to round-trip a token request.
var skipPKCEClientSecretHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy" // #nosec G101 -- test fixture

// TestServer holds everything needed for integration tests.
type TestServer struct {
	Server  *httptest.Server
	Store   *storage.Storage
	DB      *sql.DB
	Clock   *clock.FixedClock
	BaseURL string
	// Upstream is the fake IdP. Swapping its User signs the next login in as
	// someone else.
	Upstream *upstream.FakeProvider
}

// SetupTestServer creates a full authgate server with testcontainers PostgreSQL.
func SetupTestServer(t *testing.T) *TestServer {
	return SetupTestServerWithOptions(t, SetupOptions{EnableMCP: true})
}

type SetupOptions struct {
	EnableMCP                bool
	IDTokenUserinfoAssertion bool
	// RefreshReuseGrace mirrors REFRESH_TOKEN_REUSE_GRACE_SEC. Zero keeps the
	// strict reuse detection the rest of the suite asserts.
	RefreshReuseGrace time.Duration
	// RestrictedClientAccess, when set, registers RestrictedClientID: a
	// browser client like test-client that only admits accounts this access
	// policy allows. test-client itself stays public.
	RestrictedClientAccess *clientaccess.Policy
}

// RestrictedClientID is the browser client registered with
// SetupOptions.RestrictedClientAccess.
const RestrictedClientID = "restricted-client"

// setupCryptoKeys derives test crypto keys and registers their epochs.
func setupCryptoKeys(t *testing.T, store *storage.Storage) {
	t.Helper()
	mk := func(b byte) []byte {
		s := make([]byte, crypto.KeySize)
		for i := range s {
			s[i] = b
		}
		return s
	}
	enc, err := crypto.NewRoot(crypto.DomainEnc, "enc-test-1", mk(0x31))
	if err != nil {
		t.Fatalf("enc root: %v", err)
	}
	lookup, err := crypto.NewRoot(crypto.DomainLookup, "lkp-test-1", mk(0x32))
	if err != nil {
		t.Fatalf("lookup root: %v", err)
	}
	keys, err := crypto.NewKeys(enc, lookup)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	store.SetKeys(keys)
	if err := store.EnsureCryptoEpochs(context.Background()); err != nil {
		t.Fatalf("ensure epochs: %v", err)
	}
}

// SetupTestServerWithOptions creates a full authgate server with selectable optional adapters.
func SetupTestServerWithOptions(t *testing.T, opts SetupOptions) *TestServer {
	t.Helper()

	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}

	stateChecker := func(user *storage.User) error {
		if user.Status != "active" {
			return fmt.Errorf("account not active: %s", user.Status)
		}
		return nil
	}

	store := storage.New(db, clk, gen, stateChecker, 15*time.Minute, 30*24*time.Hour)
	store.SetDevicePollInterval(devicePollInterval)
	store.SetRefreshReuseGrace(opts.RefreshReuseGrace)
	// PII at-rest encryption keys are mandatory after the plaintext-PII cleanup
	// (ADR-002): signup/lookup require them, so every test server wires them.
	setupCryptoKeys(t, store)
	if opts.EnableMCP {
		hostPolicy, err := mcpadapter.NewCIMDHostPolicy(mcpadapter.DefaultCIMDHosts)
		if err != nil {
			t.Fatalf("cimd host policy: %v", err)
		}
		cimdFetcher := mcpadapter.NewHTTPCIMDFetcher(hostPolicy)
		clientPolicy := mcpadapter.NewClientResolutionPolicy(storage.NewCoreClientResolutionPolicy(store), cimdFetcher)
		store.SetClientResolutionPolicy(clientPolicy)
		store.SetResourceBindingPolicy(mcpadapter.NewResourceBindingPolicy(storage.NewCoreResourceBindingPolicy(), clientPolicy))
	}

	// Generate signing key
	key, err := storage.LoadOrGenerateKey(t.TempDir() + "/signing_key.pem")
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	store.SetSigningKey(key, "test-key-1")

	// We need to create the server first to know the URL, then set the issuer.
	// Use a 2-pass approach: create mux, wrap in httptest, then set issuer.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Register test clients in memory
	store.LoadClients([]storage.ClientConfigEntry{
		{
			ClientID:                 "test-client",
			ClientType:               "public",
			IDTokenUserinfoAssertion: opts.IDTokenUserinfoAssertion,
			LoginChannel:             "browser",
			Name:                     "Test",
			RedirectURIs:             []string{srv.URL + "/callback"},
			AllowedScopes:            []string{"openid", "profile", "email", "offline_access"},
			AllowedGrantTypes:        []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		},
		{
			// Confidential client that opted out of PKCE. Mirrors an OIDC
			// library that cannot send code_challenge (e.g. Gitea's goth
			// openidConnect provider).
			ClientID:          "skip-pkce-client",
			ClientType:        "confidential",
			ClientSecretHash:  &skipPKCEClientSecretHash,
			SkipPKCE:          true,
			LoginChannel:      "browser",
			Name:              "Skip PKCE Test",
			RedirectURIs:      []string{srv.URL + "/callback"},
			AllowedScopes:     []string{"openid", "profile", "email"},
			AllowedGrantTypes: []string{"authorization_code"},
		},
	})
	if opts.RestrictedClientAccess != nil {
		store.LoadClients([]storage.ClientConfigEntry{RestrictedClientEntry(srv.URL, opts.RestrictedClientAccess)})
	}
	if opts.EnableMCP {
		store.LoadClients([]storage.ClientConfigEntry{
			{
				ClientID:          "mcp-client",
				ClientType:        "public",
				LoginChannel:      "mcp",
				Name:              "MCP Test",
				RedirectURIs:      []string{srv.URL + "/callback"},
				AllowedScopes:     []string{"openid", "profile", "email", "offline_access"},
				AllowedGrantTypes: []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
			},
			{
				ClientID:          "mcp-device-client",
				ClientType:        "public",
				LoginChannel:      "mcp",
				Name:              "MCP Device Test",
				AllowedScopes:     []string{"openid", "profile", "email", "offline_access"},
				AllowedGrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
				AllowedResources:  []string{srv.URL + "/mcp"},
			},
		})
	}

	// zitadel OP
	cryptoKey := sha256.Sum256([]byte("test-secret-32-chars-long-enough!"))
	opConfig := &op.Config{
		CryptoKey:             cryptoKey,
		CodeMethodS256:        true,
		AuthMethodPost:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       []string{"openid", "profile", "email", "offline_access"},
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: devicePollInterval,
			UserFormPath: "/device",
			// Must mirror newOPConfig in internal/app/oidc.go. Leaving this
			// zero makes op issue empty user codes, which no real client would
			// ever see and which quietly puts /device?user_code= out of reach
			// of the integration suite.
			UserCode: op.UserCodeConfig{
				CharSet:      "BCDFGHJKLMNPQRSTVWXZ",
				CharAmount:   8,
				DashInterval: 4,
			},
		},
	}

	provider, err := op.NewProvider(opConfig, store, op.StaticIssuer(srv.URL),
		op.WithAllowInsecure(),
		op.WithCustomTokenEndpoint(op.NewEndpoint("oauth/token")),
		op.WithCustomRevocationEndpoint(op.NewEndpoint("oauth/revoke")),
		op.WithCustomDeviceAuthorizationEndpoint(op.NewEndpoint("oauth/device/authorize")),
	)
	if err != nil {
		t.Fatalf("oidc provider: %v", err)
	}

	// Fake upstream that auto-approves
	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{Sub: "test-google-sub", Email: "test@example.com", EmailVerified: true, Name: "Test User"},
	}

	// Services
	loginSvc := service.NewLoginService(store, fakeProvider.Name(), srv.URL, 24*time.Hour)
	deviceSvc := service.NewDeviceService(store, fakeProvider.Name(), srv.URL, 24*time.Hour, clk)

	// Handlers
	loginHandler := handler.NewLoginHandler(loginSvc, fakeProvider, true, pages.Brand{Name: "authgate"})
	deviceHandler := handler.NewDeviceHandler(deviceSvc, fakeProvider, true, pages.Brand{Name: "authgate"})
	logoutHandler := handler.NewLogoutHandler(provider, store, true, pages.Brand{Name: "authgate"})
	var mcpLoginHandler *handler.MCPLoginHandler
	if opts.EnableMCP {
		mcpLoginSvc := service.NewMCPLoginService(store, fakeProvider.Name(), srv.URL, 24*time.Hour)
		mcpLoginHandler = handler.NewMCPLoginHandler(mcpLoginSvc, fakeProvider, true, pages.Brand{Name: "authgate"})
	}

	// Routes
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]any{
			"issuer":                           srv.URL,
			"authorization_endpoint":           srv.URL + "/authorize",
			"token_endpoint":                   srv.URL + "/oauth/token",
			"revocation_endpoint":              srv.URL + "/oauth/revoke",
			"introspection_endpoint":           srv.URL + "/oauth/introspect",
			"device_authorization_endpoint":    srv.URL + "/oauth/device/authorize",
			"userinfo_endpoint":                srv.URL + "/userinfo",
			"end_session_endpoint":             srv.URL + "/end_session",
			"jwks_uri":                         srv.URL + "/keys",
			"response_types_supported":         []string{"code"},
			"grant_types_supported":            []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
			"code_challenge_methods_supported": []string{"S256"},
			// Mirror the production metadata contract: advertise every auth
			// method the underlying op accepts (#189 / RFC 8414 §2).
			// Introspection only authenticates via Basic (see comment in
			// cmd/authgate/main.go), so its set is narrower.
			"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post"},
			"revocation_endpoint_auth_methods_supported":     []string{"none", "client_secret_basic", "client_secret_post"},
			"introspection_endpoint_auth_methods_supported":  []string{"client_secret_basic"},
			"scopes_supported":                               []string{"openid", "profile", "email", "offline_access"},
			"authorization_response_iss_parameter_supported": true,
			"client_id_metadata_document_supported":          opts.EnableMCP,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})
	authorize := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource, err := storage.ResourceFromRequestStrict(r)
		if err != nil {
			writeInvalidTargetError(w, err)
			return
		}
		provider.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	})
	mux.Handle("/authorize", middleware.AuthorizationResponseIssuer(srv.URL, authorize))
	mux.Handle("/authorize/callback", middleware.AuthorizationResponseIssuer(srv.URL, provider))
	tokenRateLimiter := middleware.NewRateLimiter(rate.Limit(5), 5)
	tokenWithAtJWT := storage.WrapAccessTokenJWTType(provider, store)
	mux.Handle("/oauth/token", tokenRateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource, err := storage.ResourceFromRequestStrict(r)
		if err != nil {
			writeInvalidTargetError(w, err)
			return
		}
		tokenWithAtJWT.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	})))
	deviceAuthorize := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource, err := storage.ResourceFromRequestStrict(r)
		if err != nil {
			writeInvalidTargetError(w, err)
			return
		}
		clientID := strings.TrimSpace(r.Form.Get("client_id"))
		if clientID != "" && store != nil {
			if err := store.ValidateAuthorizationResource(r.Context(), clientID, resource); err != nil {
				if !errors.Is(err, storage.ErrNotFound) {
					writeInvalidTargetError(w, err)
					return
				}
			}
		}
		provider.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	})
	mux.Handle("/oauth/device/authorize", tokenRateLimiter(middleware.TokenLogContext(deviceAuthorize)))
	mux.Handle("/oauth/revoke", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !opts.EnableMCP {
			provider.ServeHTTP(w, r)
			return
		}
		if err := r.ParseForm(); err == nil {
			clientID := strings.TrimSpace(r.Form.Get("client_id"))
			if storage.IsCIMDClientID(clientID) {
				if _, err := store.GetClientByClientID(r.Context(), clientID); err != nil {
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}
		provider.ServeHTTP(w, r)
	}))
	mux.Handle("/", storage.WrapVerifiedAccessToken(provider, srv.URL))
	mux.HandleFunc("/login", loginHandler.HandleLogin)
	mux.HandleFunc("/login/callback", loginHandler.HandleCallback)
	if opts.EnableMCP {
		mux.HandleFunc("/mcp/login", mcpLoginHandler.HandleLogin)
		mux.HandleFunc("/mcp/callback", mcpLoginHandler.HandleCallback)
	}
	mux.HandleFunc("/device", deviceHandler.HandleDevicePage)
	mux.HandleFunc("/device/approve", deviceHandler.HandleDeviceApprove)
	mux.HandleFunc("/device/auth/callback", deviceHandler.HandleDeviceCallback)
	mux.HandleFunc("/end_session", logoutHandler.HandleEndSession)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// Apply CORS middleware: allowed origin is derived from the test client's redirect URI (srv.URL).
	corsOrigins := middleware.OriginsFromRedirectURIs([]string{srv.URL + "/callback"})
	corsMW := middleware.NewCORSMiddleware(corsOrigins)
	srv.Config.Handler = middleware.RequestIDMiddleware(corsMW(mux))

	return &TestServer{
		Server:   srv,
		Store:    store,
		DB:       db,
		Clock:    clk,
		BaseURL:  srv.URL,
		Upstream: fakeProvider,
	}
}

// RestrictedClientEntry is the registration of RestrictedClientID with the
// given access policy. Loading it again with another policy stands in for a
// restart with an edited clients.yaml.
func RestrictedClientEntry(baseURL string, access *clientaccess.Policy) storage.ClientConfigEntry {
	return storage.ClientConfigEntry{
		ClientID:          RestrictedClientID,
		ClientType:        "public",
		LoginChannel:      "browser",
		Name:              "Restricted Test",
		RedirectURIs:      []string{baseURL + "/callback"},
		AllowedScopes:     []string{"openid", "profile", "email", "offline_access"},
		AllowedGrantTypes: []string{"authorization_code", "refresh_token"},
		Access:            access,
	}
}

// writeInvalidTargetError writes the canonical OAuth invalid_target error
// JSON body for HTTP-layer rejections (e.g. duplicate resource params).
func writeInvalidTargetError(w http.ResponseWriter, cause error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "invalid_target",
		"error_description": cause.Error(),
	})
}
