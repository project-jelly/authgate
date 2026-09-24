//go:build integration

package integration

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type jwtClaims struct {
	Aud   any    `json:"aud"`
	Scope string `json:"scope"`
}

func decodeJWTClaims(t *testing.T, token string) jwtClaims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal JWT claims: %v", err)
	}
	return claims
}

func audienceContains(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			s, ok := item.(string)
			if ok && s == expected {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == expected {
				return true
			}
		}
	}
	return false
}

func audienceEquals(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		return len(v) == 1 && v[0] == expected
	case []string:
		return len(v) == 1 && v[0] == expected
	}
	return false
}

// Helper: complete the full browser login flow (authorize → login → callback → token)
func completeLoginFlow(t *testing.T, ts *TestServer) *TokenResponse {
	t.Helper()
	client := NewOAuthClient(t, ts.BaseURL)
	code := completeLoginFlowToCode(t, ts, client)
	return client.ExchangeCode(code)
}

// completeLoginFlowToCode runs the browser flow until the relying-party redirect returns an auth code.
func completeLoginFlowToCode(t *testing.T, ts *TestServer, client *OAuthClient) string {
	t.Helper()

	// Use a client that stops at ALL redirects so we can inspect each hop
	noFollowClient := *client.Client
	noFollowClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// 1. Start authorize → 302 to /login?authRequestID=xxx
	resp, err := noFollowClient.Get(client.AuthorizeURL())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()

	loginLoc := resp.Header.Get("Location")
	if loginLoc == "" {
		t.Fatalf("authorize did not redirect, status=%d", resp.StatusCode)
	}

	// 2. GET /login → 302 to FakeProvider AuthURL (state=authRequestID)
	loginURL := ts.BaseURL + loginLoc
	resp2, err := noFollowClient.Get(loginURL)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp2.Body.Close()

	idpLoc := resp2.Header.Get("Location")
	if idpLoc == "" {
		t.Fatalf("login did not redirect to IdP, status=%d", resp2.StatusCode)
	}

	// Extract authRequestID from the IdP redirect URL (it's in the state parameter)
	idpURL, _ := url.Parse(idpLoc)
	authRequestID := idpURL.Query().Get("state")
	if authRequestID == "" {
		t.Fatalf("no state/authRequestID in IdP redirect: %s", idpLoc)
	}

	// 3. Simulate IdP callback → new user is immediately active, so 302 redirect
	callbackURL := ts.BaseURL + client.AuthgateCallbackPath + "?code=fake-code&state=" + authRequestID
	cbResp, err := noFollowClient.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	body, _ := io.ReadAll(cbResp.Body)
	cbResp.Body.Close()

	// Should be 302 redirect (auto-approve, no terms page)
	if cbResp.StatusCode == http.StatusFound {
		return followRedirectsToCode(t, &noFollowClient, cbResp, client.BaseURL)
	}

	t.Fatalf("unexpected callback status=%d body=%s", cbResp.StatusCode, string(body))
	return ""
}

// followRedirectsToCode follows 302 redirects until it finds a code parameter.
func followRedirectsToCode(t *testing.T, client *http.Client, resp *http.Response, baseURL string) string {
	t.Helper()
	maxRedirects := 10
	for i := 0; i < maxRedirects; i++ {
		loc := resp.Header.Get("Location")
		if loc == "" {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("redirect %d: no Location header, status=%d body=%s", i, resp.StatusCode, string(body))
		}

		// Check if this redirect contains a code
		u, _ := url.Parse(loc)
		if code := u.Query().Get("code"); code != "" {
			if issuer := u.Query().Get("iss"); issuer != baseURL {
				t.Fatalf("authorization response iss = %q, want %q", issuer, baseURL)
			}
			return code
		}

		// Make absolute URL if relative
		if !strings.HasPrefix(loc, "http") {
			loc = baseURL + loc
		}

		var err error
		resp, err = client.Get(loc)
		if err != nil {
			t.Fatalf("redirect %d: %v", i, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
			break
		}
	}
	t.Fatal("could not extract code from redirect chain")
	return ""
}

// browser-token-001: full authorize → callback → token exchange

type deviceAuthorizeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

func startDeviceAuthorization(t *testing.T, ts *TestServer) *deviceAuthorizeResponse {
	return startDeviceAuthorizationFor(t, ts, "test-client", "")
}

func startDeviceAuthorizationFor(t *testing.T, ts *TestServer, clientID, resource string) *deviceAuthorizeResponse {
	t.Helper()

	data := url.Values{
		"client_id": {clientID},
		"scope":     {"openid profile email offline_access"},
	}
	if resource != "" {
		data.Set("resource", resource)
	}
	resp, err := http.Post(ts.BaseURL+"/oauth/device/authorize", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("device authorize failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var out deviceAuthorizeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode device authorize response: %v", err)
	}
	return &out
}

func pollDeviceToken(t *testing.T, ts *TestServer, deviceCode string) *TokenResponse {
	return pollDeviceTokenFor(t, ts, "test-client", deviceCode, "")
}

func pollDeviceTokenFor(t *testing.T, ts *TestServer, clientID, deviceCode, resource string) *TokenResponse {
	t.Helper()
	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {clientID},
	}
	if resource != "" {
		data.Set("resource", resource)
	}
	resp, err := http.Post(ts.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("device token poll: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	tr := &TokenResponse{StatusCode: resp.StatusCode, RawBody: string(body)}
	if resp.StatusCode == http.StatusOK {
		_ = json.Unmarshal(body, tr)
	}
	return tr
}

// createMCPAuthRequest drives a real /authorize request through the MCP channel
// and returns the authRequestID that the MCP login handler assigned.
// It uses client_id=mcp-client with valid PKCE S256 params and stops at the
// first redirect so it can extract the authRequestID before any IdP interaction.
func createMCPAuthRequest(t *testing.T, ts *TestServer, resource string) string {
	t.Helper()

	// Generate PKCE S256 challenge.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("createMCPAuthRequest: generate random bytes: %v", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	params := url.Values{
		"client_id":             {"mcp-client"},
		"response_type":         {"code"},
		"redirect_uri":          {ts.BaseURL + "/callback"},
		"scope":                 {"openid profile email offline_access"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if resource != "" {
		params.Set("resource", resource)
	}

	noFollow := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: GET /authorize → 302 to /mcp/login?authRequestID=xxx
	resp1, err := noFollow.Get(ts.BaseURL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("createMCPAuthRequest: authorize: %v", err)
	}
	resp1.Body.Close()

	loginLoc := resp1.Header.Get("Location")
	if loginLoc == "" {
		t.Fatalf("createMCPAuthRequest: /authorize did not redirect, status=%d", resp1.StatusCode)
	}

	// Make absolute if relative.
	if !strings.HasPrefix(loginLoc, "http") {
		loginLoc = ts.BaseURL + loginLoc
	}

	// Step 2: GET /mcp/login?authRequestID=xxx → 302 to IdP with state=authRequestID
	resp2, err := noFollow.Get(loginLoc)
	if err != nil {
		t.Fatalf("createMCPAuthRequest: mcp/login: %v", err)
	}
	resp2.Body.Close()

	idpLoc := resp2.Header.Get("Location")
	if idpLoc == "" {
		t.Fatalf("createMCPAuthRequest: /mcp/login did not redirect, status=%d", resp2.StatusCode)
	}

	idpURL, err := url.Parse(idpLoc)
	if err != nil {
		t.Fatalf("createMCPAuthRequest: parse idp redirect: %v", err)
	}
	authRequestID := idpURL.Query().Get("state")
	if authRequestID == "" {
		t.Fatalf("createMCPAuthRequest: no state/authRequestID in IdP redirect: %s", idpLoc)
	}
	return authRequestID
}
