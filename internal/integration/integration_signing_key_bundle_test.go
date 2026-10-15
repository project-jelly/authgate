//go:build integration

package integration

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/kangheeyong/authgate/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

// The files contain only keys generated for this test. Each setup loads the
// persisted production format before constructing its real OIDC provider.
func TestIntegration_SigningKeyBundle_GrantsAndRotationBoundaries(t *testing.T) {
	old := newBundleTestKey(t, "authgate-key-1")
	next := newBundleTestKey(t, "")
	future := newBundleTestKey(t, "")
	historical := newBundleTestKey(t, "")
	keys := []bundleTestKey{old, next, future, historical}
	path := filepath.Join(t.TempDir(), "signing-keys.json")
	writeBundleTestFile(t, path, "prepublish", old, keys, map[string]bool{
		old.id: true, next.id: true, future.id: true,
	})

	a := SetupTestServerWithOptions(t, SetupOptions{EnableMCP: true, SigningKeyBundlePath: path})
	a.Clock.T = time.Now().UTC()
	jwks := bundleHTTPKeySet(t, a, []string{old.id, next.id, future.id})

	browser := NewOAuthClient(t, a.BaseURL)
	first := browser.ExchangeCode(completeLoginFlowToCode(t, a, browser))
	assertBundleTokenResponse(t, "browser", first, old.id, jwks)
	assertBundleUserinfo(t, a, first.AccessToken, http.StatusOK)

	user, err := a.Store.GetUserByProviderIdentity(context.Background(), "google", "test-google-sub")
	if err != nil {
		t.Fatalf("browser user: %v", err)
	}
	device := bundleDeviceGrant(t, a, user.ID)
	assertBundleTokenResponse(t, "device", device, old.id, jwks)

	mcp := NewOAuthClientFor(t, a.BaseURL, "mcp-client", "/mcp/callback")
	mcpTokens := mcp.ExchangeCode(completeLoginFlowToCode(t, a, mcp))
	assertBundleTokenResponse(t, "mcp", mcpTokens, old.id, jwks)
	if !audienceContains(decodeJWTClaims(t, mcpTokens.AccessToken).Aud, a.BaseURL+"/mcp") {
		t.Fatal("bundle changed MCP resource audience")
	}

	refreshed := browser.RefreshToken(first.RefreshToken)
	assertBundleTokenResponse(t, "refresh", refreshed, old.id, jwks)

	// A new process loading the same material can verify an existing token
	// against the same issuer and database. It owns no DB cleanup.
	restarted := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP: true, SigningKeyBundlePath: path, SharedDB: a.DB, IssuerURL: a.BaseURL,
	})
	restarted.Clock.T = time.Now().UTC()
	bundleHTTPKeySet(t, restarted, []string{old.id, next.id, future.id})
	assertBundleUserinfo(t, restarted, first.AccessToken, http.StatusOK)
	restartedTokens := bundleDeviceGrant(t, restarted, user.ID)
	assertBundleTokenResponse(t, "same-bundle restart", restartedTokens, old.id, jwks)
	assertBundleUserinfo(t, a, restartedTokens.AccessToken, http.StatusOK)

	// Replacing the file does not mutate either running provider. A newly
	// created process selects the new active key, while both publish A+B+C.
	writeBundleTestFile(t, path, "activate", next, keys, map[string]bool{
		old.id: true, next.id: true, future.id: true,
	})
	stillOld := browser.RefreshToken(refreshed.RefreshToken)
	assertBundleTokenResponse(t, "existing process after file replacement", stillOld, old.id, jwks)
	stillOldRestart := bundleDeviceGrant(t, restarted, user.ID)
	assertBundleTokenResponse(t, "other existing process after file replacement", stillOldRestart, old.id, jwks)
	restarted.Server.Close()

	b := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP: true, SigningKeyBundlePath: path, SharedDB: a.DB, IssuerURL: a.BaseURL,
	})
	b.Clock.T = time.Now().UTC()
	bundleHTTPKeySet(t, b, []string{old.id, next.id, future.id})
	newTokens := bundleDeviceGrant(t, b, user.ID)
	assertBundleTokenResponse(t, "new active process", newTokens, next.id, jwks)
	assertBundleUserinfo(t, b, first.AccessToken, http.StatusOK)
	assertBundleUserinfo(t, a, newTokens.AccessToken, http.StatusOK)
	if got := jwtPayloadMap(t, newTokens.AccessToken)["iss"]; got != a.BaseURL {
		t.Fatalf("overlapping process issuer = %v, want %q", got, a.BaseURL)
	}

	// A historical key has no access-token authority even for an unexpired
	// token with a valid database jti, issuer, audience and signature. Its
	// expired ID token is still accepted by both hint entry points.
	historicalAccess := resignBundleTestToken(t, first.AccessToken, historical, "at+jwt", nil)
	assertBundleUserinfo(t, b, historicalAccess, http.StatusUnauthorized)
	historicalHint := expiredBundleTestHint(t, first.IDToken, historical)
	assertBundleHintHTTP(t, b, historicalHint, true)
	oldHint := expiredBundleTestHint(t, first.IDToken, old)
	assertBundleHintHTTP(t, b, oldHint, true)

	// Public retirement removes old access verification without changing
	// the existing unlimited-age hint contract. This is a controlled test
	// transition; it deliberately skips the operational lifetime gates.
	writeBundleTestFile(t, path, "unpublish-old", next, keys, map[string]bool{
		next.id: true, future.id: true,
	})
	retired := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP: true, SigningKeyBundlePath: path, SharedDB: a.DB, IssuerURL: a.BaseURL,
	})
	retired.Clock.T = time.Now().UTC()
	bundleHTTPKeySet(t, retired, []string{next.id, future.id})
	assertBundleUserinfo(t, retired, first.AccessToken, http.StatusUnauthorized)
	assertBundleUserinfo(t, retired, newTokens.AccessToken, http.StatusOK)
	assertBundleHintHTTP(t, retired, oldHint, true)
	assertBundleHintHTTP(t, retired, historicalHint, true)

	// Explicit removal (for example, incident response) also removes hint
	// authority. Existing processes retain their already loaded snapshot.
	writeBundleTestFile(t, path, "remove-old", next, []bundleTestKey{next, future}, map[string]bool{
		next.id: true, future.id: true,
	})
	removed := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP: true, SigningKeyBundlePath: path, SharedDB: a.DB, IssuerURL: a.BaseURL,
	})
	removed.Clock.T = time.Now().UTC()
	assertBundleUserinfo(t, removed, first.AccessToken, http.StatusUnauthorized)
	assertBundleUserinfo(t, removed, historicalAccess, http.StatusUnauthorized)
	assertBundleHintHTTP(t, removed, oldHint, false)
	assertBundleHintHTTP(t, removed, historicalHint, false)
	assertBundleHintHTTP(t, retired, oldHint, true)

	// Replace the client registration only after all authorize/logout checks:
	// introspection requires client authentication, including for an invalid
	// or unpublished token. Both endpoint adapters must use published keys.
	const introspectionSecret = "bundle-introspection-test-secret" // #nosec G101 -- test credential
	hash, err := bcrypt.GenerateFromPassword([]byte(introspectionSecret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash introspection credential: %v", err)
	}
	secretHash := string(hash)
	for _, node := range []struct {
		name      string
		server    *TestServer
		oldActive bool
	}{
		{"prepublish", a, true},
		{"active", b, true},
		{"retired", retired, false},
		{"removed", removed, false},
	} {
		node.server.Store.LoadClients([]storage.ClientConfigEntry{{
			ClientID: "test-client", ClientType: "confidential", ClientSecretHash: &secretHash,
		}})
		t.Run(node.name+"_introspection", func(t *testing.T) {
			for _, token := range []struct {
				name, value string
				active      bool
			}{
				{"old", first.AccessToken, node.oldActive},
				{"new", newTokens.AccessToken, true},
				{"hint_only", historicalAccess, false},
			} {
				t.Run(token.name, func(t *testing.T) {
					status, result := bundleIntrospection(t, node.server, token.value, introspectionSecret)
					if status != http.StatusOK || result["active"] != token.active {
						t.Fatalf("introspection status=%d active=%v, want 200 active=%v", status, result["active"], token.active)
					}
					if token.active && (result["client_id"] != "test-client" || result["scope"] == nil || result["exp"] == nil) {
						t.Fatal("active introspection is missing verified client/scope/expiry")
					}
				})
			}
			status, _ := bundleIntrospection(t, node.server, historicalAccess, "wrong-secret")
			if status == http.StatusOK {
				t.Fatal("inactive token bypassed introspection client authentication")
			}
		})
	}
}

type bundleTestKey struct {
	id      string
	private *rsa.PrivateKey
	public  jose.JSONWebKey
}

func newBundleTestKey(t *testing.T, id string) bundleTestKey {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test signing key: %v", err)
	}
	public := jose.JSONWebKey{Key: &private.PublicKey, Algorithm: string(jose.RS256), Use: "sig"}
	if id == "" {
		thumbprint, err := public.Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatalf("public thumbprint: %v", err)
		}
		id = base64.RawURLEncoding.EncodeToString(thumbprint)
	}
	public.KeyID = id
	return bundleTestKey{id: id, private: private, public: public}
}

func writeBundleTestFile(t *testing.T, path, revision string, active bundleTestKey, keys []bundleTestKey, published map[string]bool) {
	t.Helper()
	verification := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		verification = append(verification, map[string]any{"jwk": key.public, "publish": published[key.id]})
	}
	bundle := map[string]any{
		"schema_version":         1,
		"revision":               revision,
		"active_kid":             active.id,
		"active_private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(active.private)})),
		"verification_keys":      verification,
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal test bundle: %v", err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatalf("persist test bundle: %v", err)
	}
}

func bundleHTTPKeySet(t *testing.T, ts *TestServer, expected []string) jose.JSONWebKeySet {
	t.Helper()
	resp, err := http.Get(ts.BaseURL + "/keys")
	if err != nil {
		t.Fatalf("GET /keys: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /keys: status=%d read=%v", resp.StatusCode, err)
	}
	var raw struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("parse /keys: %v", err)
	}
	if len(raw.Keys) != len(expected) {
		t.Fatalf("published keys = %d, want %d", len(raw.Keys), len(expected))
	}
	for _, key := range raw.Keys {
		for _, field := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
			if _, present := key[field]; present {
				t.Fatalf("JWKS exposed private RSA field %q", field)
			}
		}
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("decode /keys: %v", err)
	}
	for _, id := range expected {
		if len(set.Key(id)) != 1 {
			t.Fatalf("published key %q must occur exactly once", id)
		}
	}
	return set
}

func assertBundleTokenResponse(t *testing.T, label string, tokens *TokenResponse, kid string, keys jose.JSONWebKeySet) {
	t.Helper()
	if tokens.StatusCode != http.StatusOK || tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatalf("%s: expected access/ID tokens, status=%d error=%q", label, tokens.StatusCode, tokens.Error)
	}
	for _, token := range []struct{ value, typ string }{{tokens.AccessToken, "at+jwt"}, {tokens.IDToken, "JWT"}} {
		signed, err := jose.ParseSigned(token.value, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil || len(signed.Signatures) != 1 {
			t.Fatalf("%s: expected single RS256 signature: %v", label, err)
		}
		header := signed.Signatures[0].Protected
		if header.KeyID != kid || header.ExtraHeaders[jose.HeaderType] != token.typ {
			t.Fatalf("%s: kid=%q typ=%v, want kid=%q typ=%q", label, header.KeyID, header.ExtraHeaders[jose.HeaderType], kid, token.typ)
		}
		if _, err := signed.Verify(keys.Key(kid)[0].Key); err != nil {
			t.Fatalf("%s: published key rejected issued token: %v", label, err)
		}
	}
	assertAtHashBinds(t, tokens.IDToken, tokens.AccessToken)
}

func bundleDeviceGrant(t *testing.T, ts *TestServer, userID string) *TokenResponse {
	t.Helper()
	authz := startDeviceAuthorization(t, ts)
	if err := ts.Store.ApproveDeviceCode(context.Background(), authz.UserCode, userID, time.Time{}); err != nil {
		t.Fatalf("approve bundle device grant: %v", err)
	}
	return pollDeviceToken(t, ts, authz.DeviceCode)
}

func assertBundleUserinfo(t *testing.T, ts *TestServer, token string, status int) {
	t.Helper()
	if got, _ := userinfoRequest(t, ts, token); got != status {
		t.Fatalf("userinfo status=%d, want %d", got, status)
	}
}

func bundleIntrospection(t *testing.T, ts *TestServer, token, secret string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.BaseURL+"/oauth/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatalf("introspection request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test-client", secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspection: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]any
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("introspection response: %v", err)
		}
	}
	return resp.StatusCode, result
}

func resignBundleTestToken(t *testing.T, token string, key bundleTestKey, typ string, change func(map[string]any)) string {
	t.Helper()
	claims := jwtPayloadMap(t, token)
	if change != nil {
		change(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal test token: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{Key: key.private, KeyID: key.id}}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatalf("test token signer: %v", err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	result, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize test token: %v", err)
	}
	return result
}

func expiredBundleTestHint(t *testing.T, token string, key bundleTestKey) string {
	t.Helper()
	return resignBundleTestToken(t, token, key, "JWT", func(claims map[string]any) {
		claims["iat"] = time.Now().Add(-3 * time.Hour).Unix()
		claims["exp"] = time.Now().Add(-2 * time.Hour).Unix()
	})
}

func assertBundleHintHTTP(t *testing.T, ts *TestServer, hint string, accepted bool) {
	t.Helper()
	client := NewOAuthClient(t, ts.BaseURL)
	authorizeURL, err := url.Parse(client.AuthorizeURL())
	if err != nil {
		t.Fatalf("authorize URL: %v", err)
	}
	query := authorizeURL.Query()
	query.Set("id_token_hint", hint)
	authorizeURL.RawQuery = query.Encode()
	noFollow := noFollowCopy(client)
	resp, err := noFollow.Get(authorizeURL.String())
	if err != nil {
		t.Fatalf("authorize with historical hint: %v", err)
	}
	resp.Body.Close()
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize hint status=%d location=%q parse=%v", resp.StatusCode, resp.Header.Get("Location"), err)
	}
	if accepted {
		if location.Path != "/login" || location.Query().Get("authRequestID") == "" {
			t.Fatalf("accepted hint should reach login, location=%q", location.String())
		}
	} else if location.Query().Get("error") != "login_required" {
		t.Fatalf("removed hint should fail authorize, location=%q", location.String())
	}
	logout := getEndSession(t, noFollow, ts, url.Values{"id_token_hint": {hint}})
	if accepted {
		if logout.status != http.StatusOK || !strings.Contains(logout.body, "You are signed out") || logout.isConfirmPage() {
			t.Fatalf("historical hint logout status=%d, want signed-out page", logout.status)
		}
	} else if logout.status != http.StatusBadRequest {
		t.Fatalf("removed hint logout status=%d, want 400", logout.status)
	}
}
