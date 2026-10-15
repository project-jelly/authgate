package upstream

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	testClientID     = "test-client"
	testClientSecret = "test-secret"
	testRedirectURI  = "http://localhost/callback"
)

// fakeIdP is an in-process OIDC IdP for testing OIDCProvider without external dependencies.
// Uses httptest.Server so no network, no Docker, no build tags required.
type fakeIdP struct {
	srv            *httptest.Server
	key            *rsa.PrivateKey
	keyID          string
	userInfoResp   map[string]any
	tokenStatus    int            // non-zero overrides token endpoint HTTP status
	userinfoStatus int            // non-zero overrides userinfo endpoint HTTP status
	nonce          string         // echoed into the id_token's nonce claim (set by the test from the authorize request)
	idTokenExtra   map[string]any // extra claims signed into the id_token
	tokenRequests  atomic.Int32
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	idp := &fakeIdP{
		key:   key,
		keyID: "test-key-1",
		userInfoResp: map[string]any{
			"sub":            "test-sub",
			"email":          "test@example.com",
			"email_verified": true,
			"name":           "Test User",
		},
	}

	mux := http.NewServeMux()
	var srvURL string // set after server starts; handlers close over it

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srvURL,
			"authorization_endpoint":                srvURL + "/authorize",
			"token_endpoint":                        srvURL + "/token",
			"jwks_uri":                              srvURL + "/keys",
			"userinfo_endpoint":                     srvURL + "/userinfo",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       &idp.key.PublicKey,
					KeyID:     idp.keyID,
					Algorithm: string(jose.RS256),
					Use:       "sig",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.tokenRequests.Add(1)
		if idp.tokenStatus != 0 {
			http.Error(w, "token error", idp.tokenStatus)
			return
		}

		sig, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: idp.key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", idp.keyID),
		)
		if err != nil {
			http.Error(w, "signer error", http.StatusInternalServerError)
			return
		}

		sub, _ := idp.userInfoResp["sub"].(string)
		now := time.Now()
		claims := map[string]any{
			"iss":   srvURL,
			"sub":   sub,
			"aud":   testClientID,
			"exp":   now.Add(5 * time.Minute).Unix(),
			"iat":   now.Unix(),
			"nonce": idp.nonce,
		}
		for k, v := range idp.idTokenExtra {
			claims[k] = v
		}
		idToken, err := jwt.Signed(sig).Claims(claims).Serialize()
		if err != nil {
			http.Error(w, "sign error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"id_token":     idToken,
			"expires_in":   300,
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if idp.userinfoStatus != 0 {
			http.Error(w, "userinfo error", idp.userinfoStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(idp.userInfoResp)
	})

	idp.srv = httptest.NewServer(mux)
	srvURL = idp.srv.URL
	t.Cleanup(idp.srv.Close)

	return idp
}

func (idp *fakeIdP) newProvider(t *testing.T) *OIDCProvider {
	t.Helper()
	p, err := NewOIDCProvider(context.Background(), idp.srv.URL, testClientID, testClientSecret, testRedirectURI,
		WithCookieSecret("test-cookie-secret", false))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	return p
}

// authURLForTest drives p.Redirect and returns the upstream authorization URL
// the high-level handler redirected to (the value of the Location header).
func authURLForTest(t *testing.T, p *OIDCProvider, state string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	p.Redirect(rec, req, state)
	loc := rec.Result().Header.Get("Location")
	if loc == "" {
		t.Fatalf("Redirect did not set Location header (status %d)", rec.Code)
	}
	return loc
}

// exchangeForTest drives the full Redirect→Callback round-trip against the fake
// IdP, replaying the state/PKCE cookies the redirect set, and returns the
// UserInfo delivered to the onSuccess callback (or an error if onSuccess was
// never invoked, mirroring the old Exchange error contract).
func exchangeForTest(t *testing.T, idp *fakeIdP, p *OIDCProvider, code string) (*UserInfo, error) {
	t.Helper()

	// First leg: Redirect to capture the state + PKCE + nonce cookies.
	redirectRec := httptest.NewRecorder()
	redirectReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	p.Redirect(redirectRec, redirectReq, "test-state")

	loc := redirectRec.Result().Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	state := u.Query().Get("state")
	// The IdP echoes the authorize-request nonce into the id_token; mirror that
	// so the RP's nonce verifier sees a matching value.
	idp.nonce = u.Query().Get("nonce")

	// Second leg: Callback with the captured cookies + the IdP-issued code/state.
	cbReq := httptest.NewRequest(http.MethodGet, "/login/callback?code="+code+"&state="+state, nil)
	for _, c := range redirectRec.Result().Cookies() {
		cbReq.AddCookie(c)
	}
	cbRec := httptest.NewRecorder()

	var got *UserInfo
	p.Callback(cbRec, cbReq, func(_ http.ResponseWriter, _ *http.Request, _ string, info *UserInfo) {
		got = info
	})
	if got == nil {
		return nil, fmt.Errorf("callback did not succeed (status %d)", cbRec.Code)
	}
	return got, nil
}

// ── oidc-name-001~003: deriveProviderName ────────────────────────────────────

func TestDeriveProviderName_Google(t *testing.T) {
	if got := deriveProviderName("https://accounts.google.com"); got != "google" {
		t.Errorf("got %q, want %q", got, "google")
	}
}

func TestDeriveProviderName_Localhost(t *testing.T) {
	if got := deriveProviderName("http://localhost:8082"); got != "localhost" {
		t.Errorf("got %q, want %q", got, "localhost")
	}
}

func TestDeriveProviderName_Microsoft(t *testing.T) {
	if got := deriveProviderName("https://login.microsoftonline.com"); got != "microsoftonline" {
		t.Errorf("got %q, want %q", got, "microsoftonline")
	}
}

func TestDeriveProviderName_InvalidURL(t *testing.T) {
	if got := deriveProviderName("not-a-url"); got != "unknown" {
		t.Errorf("got %q, want %q", got, "unknown")
	}
}

// ── oidc-disc-001: Discovery success ─────────────────────────────────────────

func TestOIDCProvider_Discovery_Success(t *testing.T) {
	idp := newFakeIdP(t)
	p, err := NewOIDCProvider(context.Background(), idp.srv.URL, testClientID, testClientSecret, testRedirectURI,
		WithCookieSecret("test-cookie-secret", false))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	if p.Name() == "" {
		t.Error("Name() is empty after successful Discovery")
	}
	if authURLForTest(t, p, "state-001") == "" {
		t.Error("Redirect produced empty auth URL after successful Discovery")
	}
}

// ── oidc-disc-002: Discovery server unreachable ───────────────────────────────

func TestOIDCProvider_Discovery_Unreachable(t *testing.T) {
	_, err := NewOIDCProvider(context.Background(), "http://127.0.0.1:1", testClientID, testClientSecret, testRedirectURI)
	if err == nil {
		t.Error("expected error for unreachable server, got nil")
	}
}

// ── oidc-disc-003: Discovery server returns non-200 ──────────────────────────

func TestOIDCProvider_Discovery_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := NewOIDCProvider(context.Background(), srv.URL, testClientID, testClientSecret, testRedirectURI)
	if err == nil {
		t.Error("expected error for 500 discovery response, got nil")
	}
}

// ── oidc-auth-001: AuthURL contains required OAuth2 parameters ────────────────

func TestOIDCProvider_AuthURL_ContainsRequiredParams(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.newProvider(t)
	u := authURLForTest(t, p, "req-state-123")
	for _, param := range []string{"client_id", "redirect_uri", "response_type", "state"} {
		if !strings.Contains(u, param) {
			t.Errorf("AuthURL missing param %q: %s", param, u)
		}
	}
}

// ── oidc-auth-002: WithPrompt sets the upstream prompt parameter ─────────────

func TestOIDCProvider_AuthURL_Prompt(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.newProvider(t)

	plain, err := url.Parse(authURLForTest(t, p, "req-state-plain"))
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	if plain.Query().Has("prompt") {
		t.Errorf("AuthURL without WithPrompt has prompt: %s", plain)
	}

	rec := httptest.NewRecorder()
	p.Redirect(rec, httptest.NewRequest(http.MethodGet, "/login", nil), "req-state-prompt", WithPrompt("select_account"))
	withPrompt, err := url.Parse(rec.Result().Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	if got := withPrompt.Query().Get("prompt"); got != "select_account" {
		t.Errorf("prompt = %q, want select_account: %s", got, withPrompt)
	}
	if withPrompt.Query().Get("nonce") == "" || withPrompt.Query().Get("state") == "" {
		t.Errorf("WithPrompt dropped state or nonce: %s", withPrompt)
	}
}

// ── oidc-exchange-001: normal code exchange ───────────────────────────────────

func TestOIDCProvider_Exchange_Success(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.newProvider(t)
	info, err := exchangeForTest(t, idp, p, "fake-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if info.Sub != "test-sub" {
		t.Errorf("Sub = %q, want test-sub", info.Sub)
	}
	if info.Email != "test@example.com" {
		t.Errorf("Email = %q", info.Email)
	}
	if info.Name != "Test User" {
		t.Errorf("Name = %q", info.Name)
	}
}

// ── oidc-exchange-002: token endpoint error ───────────────────────────────────

func TestOIDCProvider_Exchange_TokenEndpointError(t *testing.T) {
	idp := newFakeIdP(t)
	idp.tokenStatus = http.StatusUnauthorized
	p := idp.newProvider(t)
	_, err := exchangeForTest(t, idp, p, "any-code")
	if err == nil {
		t.Error("expected error for token endpoint 401, got nil")
	}
}

// ── oidc-exchange-003: userinfo endpoint error ────────────────────────────────

func TestOIDCProvider_Exchange_UserInfoError(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userinfoStatus = http.StatusUnauthorized
	p := idp.newProvider(t)
	_, err := exchangeForTest(t, idp, p, "fake-code")
	if err == nil {
		t.Error("expected error for userinfo endpoint 401, got nil")
	}
}

// ── oidc-map-001: all fields mapped correctly ─────────────────────────────────

func TestOIDCProvider_UserInfoMapping_AllFields(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userInfoResp = map[string]any{
		"sub":            "map-sub",
		"email":          "map@example.com",
		"email_verified": true,
		"name":           "Map User",
	}
	p := idp.newProvider(t)
	info, err := exchangeForTest(t, idp, p, "fake-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if info.Sub != "map-sub" {
		t.Errorf("Sub = %q, want map-sub", info.Sub)
	}
	if info.Email != "map@example.com" {
		t.Errorf("Email = %q", info.Email)
	}
	if !info.EmailVerified {
		t.Error("EmailVerified = false, want true")
	}
	if info.Name != "Map User" {
		t.Errorf("Name = %q", info.Name)
	}
}

// ── oidc-map-002 (P0): email_verified=true regression ────────────────────────
// Guards against the prior bug where email_verified was always false due to
// missing JSON tags on the old upstream.UserInfo struct.

func TestOIDCProvider_EmailVerified_True(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userInfoResp["email_verified"] = true
	p := idp.newProvider(t)
	info, err := exchangeForTest(t, idp, p, "fake-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !info.EmailVerified {
		t.Error("email_verified=true returned by IdP but UserInfo.EmailVerified=false (regression)")
	}
}

// ── oidc-map-003: email_verified=false ───────────────────────────────────────

func TestOIDCProvider_EmailVerified_False(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userInfoResp["email_verified"] = false
	p := idp.newProvider(t)
	info, err := exchangeForTest(t, idp, p, "fake-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if info.EmailVerified {
		t.Error("email_verified=false returned by IdP but UserInfo.EmailVerified=true")
	}
}

// ── oidc-map-004: email_verified absent → defaults to false ──────────────────

func TestOIDCProvider_EmailVerified_Absent(t *testing.T) {
	idp := newFakeIdP(t)
	delete(idp.userInfoResp, "email_verified")
	p := idp.newProvider(t)
	info, err := exchangeForTest(t, idp, p, "fake-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if info.EmailVerified {
		t.Error("email_verified absent in IdP response but UserInfo.EmailVerified=true")
	}
}

// ── oidc-map-005: Google hosted domain (hd) ──────────────────────────────────
// Client access policies match google_workspace_domains against hd, so it has
// to survive the mapping, and it is read only from the verified ID token: the
// unsigned userinfo response is never a source.

func TestOIDCProvider_HostedDomain(t *testing.T) {
	tests := []struct {
		name         string
		idTokenHD    any
		userinfoHD   any
		wantHostedDN string
	}{
		{name: "from id token", idTokenHD: "corp.example", wantHostedDN: "corp.example"},
		{name: "id token wins over userinfo", idTokenHD: "corp.example", userinfoHD: "other.example", wantHostedDN: "corp.example"},
		{name: "userinfo alone ignored", userinfoHD: "corp.example", wantHostedDN: ""},
		{name: "absent", wantHostedDN: ""},
		{name: "non-string ignored", idTokenHD: 42, wantHostedDN: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			if tt.idTokenHD != nil {
				idp.idTokenExtra = map[string]any{"hd": tt.idTokenHD}
			}
			if tt.userinfoHD != nil {
				idp.userInfoResp["hd"] = tt.userinfoHD
			}
			info, err := exchangeForTest(t, idp, idp.newProvider(t), "fake-code")
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if info.HostedDomain != tt.wantHostedDN {
				t.Errorf("HostedDomain = %q, want %q", info.HostedDomain, tt.wantHostedDN)
			}
		})
	}
}

// ── oidc-e2e-001: full path Discovery → AuthURL → Exchange → UserInfo ─────────

func TestOIDCProvider_FullPath(t *testing.T) {
	idp := newFakeIdP(t)

	p, err := NewOIDCProvider(context.Background(), idp.srv.URL, testClientID, testClientSecret, testRedirectURI,
		WithCookieSecret("test-cookie-secret", false))
	if err != nil {
		t.Fatalf("Discovery: %v", err)
	}

	authURL := authURLForTest(t, p, "full-path-state")
	if !strings.Contains(authURL, "full-path-state") {
		t.Errorf("AuthURL does not contain state: %s", authURL)
	}

	info, err := exchangeForTest(t, idp, p, "full-path-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if info.Sub == "" || info.Email == "" {
		t.Errorf("incomplete UserInfo after full path: sub=%q email=%q", info.Sub, info.Email)
	}
}

// ── oidc-nonce-001: id_token nonce mismatch is rejected ──────────────────────
// Proves the per-login nonce binding: an id_token whose nonce does not match
// the value bound to this login (cookie) must fail verification.
func TestOIDCProvider_NonceMismatch_Rejected(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.newProvider(t)

	// Drive Redirect to set the state/PKCE/nonce cookies.
	redirectRec := httptest.NewRecorder()
	p.Redirect(redirectRec, httptest.NewRequest(http.MethodGet, "/login", nil), "test-state")
	u, err := url.Parse(redirectRec.Result().Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	state := u.Query().Get("state")

	// Tamper: make the IdP issue an id_token with a DIFFERENT nonce than the
	// one bound to this login.
	idp.nonce = "attacker-supplied-nonce"

	cbReq := httptest.NewRequest(http.MethodGet, "/login/callback?code=fake-code&state="+state, nil)
	for _, c := range redirectRec.Result().Cookies() {
		cbReq.AddCookie(c)
	}
	cbRec := httptest.NewRecorder()

	called := false
	p.Callback(cbRec, cbReq, func(http.ResponseWriter, *http.Request, string, *UserInfo) { called = true })
	if called {
		t.Error("onSuccess invoked despite id_token nonce mismatch — replay/injection not rejected")
	}
	if cbRec.Code != http.StatusUnauthorized || idp.tokenRequests.Load() != 1 {
		t.Fatalf("status = %d, token requests = %d, want 401 after one exchange to verify the returned nonce", cbRec.Code, idp.tokenRequests.Load())
	}
}

func TestOIDCProvider_MultiRedirectURIs(t *testing.T) {
	idp := newFakeIdP(t)

	tests := []struct {
		name        string
		redirectURI string
	}{
		{name: "browser", redirectURI: "http://localhost:8080/login/callback"},
		{name: "mcp", redirectURI: "http://localhost:8080/mcp/callback"},
		{name: "device", redirectURI: "http://localhost:8080/device/auth/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewOIDCProvider(context.Background(), idp.srv.URL, testClientID, testClientSecret, tt.redirectURI,
				WithCookieSecret("test-cookie-secret", false))
			if err != nil {
				t.Fatalf("NewOIDCProvider: %v", err)
			}

			authURL := authURLForTest(t, p, "state-"+tt.name)
			u, err := url.Parse(authURL)
			if err != nil {
				t.Fatalf("parse authURL: %v", err)
			}
			if got := u.Query().Get("redirect_uri"); got != tt.redirectURI {
				t.Fatalf("redirect_uri = %q, want %q", got, tt.redirectURI)
			}
		})
	}
}
