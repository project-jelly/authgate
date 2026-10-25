//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/bcrypt"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
)

func userinfoRequest(t *testing.T, ts *TestServer, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.BaseURL+"/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var claims map[string]any
	if resp.StatusCode == 200 {
		if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, claims
}

func resignAccessToken(t *testing.T, ts *TestServer, token, typ string, change func(map[string]any)) string {
	t.Helper()
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	change(claims)
	payload, err = json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ts.Store.SigningKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: key.SignatureAlgorithm(), Key: &jose.JSONWebKey{Key: key.Key(), KeyID: key.ID()}}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	result, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestIntegration_UserinfoAccessTokenProfile(t *testing.T) {
	ts := SetupTestServer(t)
	ts.Clock.T = time.Now().UTC()
	c := NewOAuthClient(t, ts.BaseURL)
	tokens := c.ExchangeCode(completeLoginFlowToCode(t, ts, c))
	if tokens.StatusCode != 200 {
		t.Fatal(tokens.RawBody)
	}
	if code, claims := userinfoRequest(t, ts, tokens.AccessToken); code != 200 || claims["email"] == nil || claims["name"] == nil {
		t.Fatalf("valid access token: %d %v", code, claims)
	}
	if code, _ := userinfoRequest(t, ts, tokens.IDToken); code != 401 {
		t.Fatalf("ID token status %d", code)
	}
	for _, field := range []string{"iss", "sub", "aud", "exp", "iat", "jti", "client_id"} {
		t.Run("missing_"+field, func(t *testing.T) {
			token := resignAccessToken(t, ts, tokens.AccessToken, "at+jwt", func(m map[string]any) { delete(m, field) })
			if code, _ := userinfoRequest(t, ts, token); code != 401 {
				t.Fatalf("missing %s status %d", field, code)
			}
		})
	}
	for _, tc := range []struct {
		name, typ string
		change    func(map[string]any)
	}{
		{"wrong_type", "JWT", func(map[string]any) {}},
		{"wrong_issuer", "at+jwt", func(m map[string]any) { m["iss"] = "https://other.example" }},
		{"resource_audience", "at+jwt", func(m map[string]any) { m["aud"] = []string{"https://api.example"} }},
		{"expired", "at+jwt", func(m map[string]any) { m["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"future_iat", "at+jwt", func(m map[string]any) { m["iat"] = time.Now().Add(time.Hour).Unix() }},
		{"future_nbf", "at+jwt", func(m map[string]any) { m["nbf"] = time.Now().Add(time.Hour).Unix() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := resignAccessToken(t, ts, tokens.AccessToken, tc.typ, tc.change)
			if code, _ := userinfoRequest(t, ts, token); code != 401 {
				t.Fatalf("status %d", code)
			}
		})
	}
	parts := strings.Split(tokens.AccessToken, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	if code, _ := userinfoRequest(t, ts, strings.Join(parts, ".")); code != 401 {
		t.Fatalf("bad signature status %d", code)
	}
	token := resignAccessToken(t, ts, tokens.AccessToken, "application/at+jwt", func(map[string]any) {})
	if code, _ := userinfoRequest(t, ts, token); code != 200 {
		t.Fatalf("long media type status %d", code)
	}
	token = resignAccessToken(t, ts, tokens.AccessToken, "at+jwt", func(m map[string]any) { m["scope"] = "email" })
	if code, _ := userinfoRequest(t, ts, token); code != 403 {
		t.Fatalf("missing openid status %d", code)
	}
}

func TestIntegration_UserinfoUsesRefreshedScopes(t *testing.T) {
	for _, scope := range []string{"openid", "openid email", "openid profile", "openid email profile"} {
		t.Run(scope, func(t *testing.T) {
			ts := SetupTestServer(t)
			ts.Clock.T = time.Now().UTC()
			c := NewOAuthClient(t, ts.BaseURL)
			tokens := c.ExchangeCode(completeLoginFlowToCode(t, ts, c))
			if tokens.StatusCode != 200 {
				t.Fatal(tokens.RawBody)
			}
			form := url.Values{"grant_type": {"refresh_token"}, "client_id": {c.ClientID}, "refresh_token": {tokens.RefreshToken}, "scope": {scope}}
			resp, err := http.Post(ts.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var refreshed TokenResponse
			if err := json.NewDecoder(resp.Body).Decode(&refreshed); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("refresh status %d: %s", resp.StatusCode, refreshed.Error)
			}
			code, claims := userinfoRequest(t, ts, refreshed.AccessToken)
			if code != 200 || claims["sub"] == nil {
				t.Fatalf("userinfo %d %v", code, claims)
			}
			for field, required := range map[string]string{"email": "email", "email_verified": "email", "name": "profile"} {
				_, present := claims[field]
				if present != strings.Contains(scope, required) {
					t.Errorf("%s present=%v for scope %q", field, present, scope)
				}
			}
		})
	}
}

func TestIntegration_IntrospectionRequiresAccessTokenAndOwningClient(t *testing.T) {
	ts := SetupTestServer(t)
	ts.Clock.T = time.Now().UTC()
	c := NewOAuthClient(t, ts.BaseURL)
	tokens := c.ExchangeCode(completeLoginFlowToCode(t, ts, c))
	if tokens.StatusCode != 200 {
		t.Fatal(tokens.RawBody)
	}
	// Introspection requires client authentication even for public-client grants.
	hash, err := bcrypt.GenerateFromPassword([]byte("introspection-test-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	secretHash := string(hash)
	ts.Store.LoadClients([]oauthclient.ConfigEntry{
		{ClientID: c.ClientID, ClientType: "confidential", ClientSecretHash: &secretHash},
		{ClientID: "observer", ClientType: "confidential", ClientSecretHash: &secretHash},
	})
	for _, tc := range []struct {
		name, token, client, secret string
		active                      bool
	}{
		{"own_access", tokens.AccessToken, c.ClientID, "introspection-test-secret", true},
		{"id_token", tokens.IDToken, c.ClientID, "introspection-test-secret", false},
		{"other_client", tokens.AccessToken, "observer", "introspection-test-secret", false},
		{"invalid_unauthenticated", tokens.IDToken, c.ClientID, "wrong", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.BaseURL+"/oauth/introspect", strings.NewReader(url.Values{"token": {tc.token}}.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(tc.client, tc.secret)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if tc.secret == "wrong" {
				if resp.StatusCode == 200 {
					t.Fatal("invalid token bypassed client authentication")
				}
				return
			}
			var result map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 || result["active"] != tc.active {
				t.Fatalf("introspection: %d %v", resp.StatusCode, result)
			}
			if tc.active && (result["client_id"] != c.ClientID || result["scope"] == nil || result["exp"] == nil) {
				t.Fatalf("missing verified metadata: %v", result)
			}
		})
	}
}
