//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
)

func refreshFormRequest(t *testing.T, ts *TestServer, form url.Values) *TokenResponse {
	t.Helper()
	resp, err := http.Post(ts.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	result := &TokenResponse{StatusCode: resp.StatusCode}
	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestIntegration_InvalidRefreshRequestPreservesGrant(t *testing.T) {
	for _, field := range []string{"scope", "client_id", "unknown_client"} {
		t.Run(field, func(t *testing.T) {
			ts := SetupTestServerWithOptions(t, SetupOptions{RefreshReuseGrace: 5 * time.Second})
			ts.Clock.T = time.Now().UTC()
			client := NewOAuthClient(t, ts.BaseURL)
			tokens := completeLoginFlow(t, ts)
			if tokens.StatusCode != 200 {
				t.Fatal(tokens.RawBody)
			}
			form := url.Values{"grant_type": {"refresh_token"}, "client_id": {client.ClientID}, "refresh_token": {tokens.RefreshToken}}
			form.Set(field, "ungranted-value")
			if field == "unknown_client" {
				form.Del(field)
				form.Set("client_id", "unregistered-client")
			}
			if field == "client_id" {
				ts.Store.LoadClients([]oauthclient.ConfigEntry{{ClientID: "other-client", ClientType: "public", AllowedGrantTypes: []string{"refresh_token"}}})
				form.Set(field, "other-client")
			}
			r := refreshFormRequest(t, ts, form)
			wantStatus := http.StatusBadRequest
			wantError := "invalid_scope"
			if field == "client_id" {
				wantError = "invalid_grant"
			}
			if field == "unknown_client" {
				wantError = "invalid_client"
				wantStatus = http.StatusUnauthorized
			}
			if r.StatusCode != wantStatus || r.Error != wantError {
				t.Fatalf("invalid request: %+v, want %s", r, wantError)
			}
			// Retry outside the configured grace: success must not depend on grace.
			ts.Clock.T = ts.Clock.T.Add(6 * time.Second)
			if r := client.RefreshToken(tokens.RefreshToken); r.StatusCode != 200 {
				t.Fatalf("valid retry lost token: %s", r.RawBody)
			}
		})
	}
}

func TestIntegration_RefreshNarrowingPreservesOriginalGrantScope(t *testing.T) {
	ts := SetupTestServer(t)
	ts.Clock.T = time.Now().UTC()
	client := NewOAuthClient(t, ts.BaseURL)
	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != 200 {
		t.Fatal(tokens.RawBody)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {client.ClientID}, "refresh_token": {tokens.RefreshToken}, "scope": {"openid"}}
	narrowed := refreshFormRequest(t, ts, form)
	if narrowed.StatusCode != 200 {
		t.Fatalf("narrow refresh: %+v", narrowed)
	}
	if scope := jwtPayloadMap(t, narrowed.AccessToken)["scope"]; scope != "openid" {
		t.Fatalf("access scope: %v", scope)
	}
	var stored []string
	if err := ts.DB.QueryRowContext(context.Background(), `SELECT scopes FROM refresh_tokens WHERE token_hash=$1`, ts.Store.Keys().RefreshHash(narrowed.RefreshToken)).Scan(pq.Array(&stored)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(stored, " ") != "openid profile email offline_access" {
		t.Fatalf("replacement refresh scope: %v", stored)
	}
	restored := client.RefreshToken(narrowed.RefreshToken)
	if restored.StatusCode != 200 {
		t.Fatal(restored.RawBody)
	}
	if scope := jwtPayloadMap(t, restored.AccessToken)["scope"]; scope != "openid profile email offline_access" {
		t.Fatalf("subsequent default scope: %v", scope)
	}
}

func TestIntegration_RefreshInsertFailureRollsBackConsumption(t *testing.T) {
	ts := SetupTestServer(t)
	ts.Clock.T = time.Now().UTC()
	client := NewOAuthClient(t, ts.BaseURL)
	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != 200 {
		t.Fatal(tokens.RawBody)
	}
	ctx := context.Background()
	if _, err := ts.DB.ExecContext(ctx, `ALTER TABLE refresh_tokens ADD CONSTRAINT test_reject_child CHECK(parent_id IS NULL) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if r := client.RefreshToken(tokens.RefreshToken); r.StatusCode != 500 {
		t.Fatalf("insert failure: %d %s", r.StatusCode, r.RawBody)
	}
	if _, err := ts.DB.ExecContext(ctx, `ALTER TABLE refresh_tokens DROP CONSTRAINT test_reject_child`); err != nil {
		t.Fatal(err)
	}
	if r := client.RefreshToken(tokens.RefreshToken); r.StatusCode != 200 {
		t.Fatalf("rollback lost grant: %s", r.RawBody)
	}
}

func TestIntegration_RevokeBackendFailureIsNotSuccess(t *testing.T) {
	ts := SetupTestServer(t)
	ts.Clock.T = time.Now().UTC()
	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != 200 {
		t.Fatal(tokens.RawBody)
	}
	ctx := context.Background()
	// Preserve token lookup but fail the revoke UPDATE inside Storage.
	if _, err := ts.DB.ExecContext(ctx, `ALTER TABLE refresh_tokens ADD CONSTRAINT test_reject_revoke CHECK(revoked_at IS NULL) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"client_id": {"test-client"}, "token": {tokens.RefreshToken}, "token_type_hint": {"refresh_token"}}
	resp, err := http.Post(ts.BaseURL+"/oauth/revoke", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Fatalf("failed revoke status %d, want 500", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "server_error" {
		t.Fatalf("failed revoke body: %v", body)
	}
	var tombstones int
	if err := ts.DB.QueryRowContext(ctx, `SELECT count(*) FROM refresh_token_families`).Scan(&tombstones); err != nil {
		t.Fatal(err)
	}
	if tombstones != 0 {
		t.Fatal("failed revoke left partial tombstone")
	}
}

func TestIntegration_ConfidentialRefreshGraceRequiresClientAuthentication(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{RefreshReuseGrace: 5 * time.Second})
	ts.Clock.T = time.Now().UTC()
	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != 200 {
		t.Fatal(tokens.RawBody)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("refresh-test-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	secretHash := string(hash)
	ts.Store.LoadClients([]oauthclient.ConfigEntry{{ClientID: "test-client", ClientType: "confidential", ClientSecretHash: &secretHash, AllowedGrantTypes: []string{"refresh_token"}, AllowedScopes: []string{"openid", "profile", "email", "offline_access"}}})
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"test-client"}, "refresh_token": {tokens.RefreshToken}}
	// Knowing the token without the confidential client's secret is not enough.
	if r := refreshFormRequest(t, ts, form); r.StatusCode == 200 {
		t.Fatal("unauthenticated confidential refresh accepted")
	}
	form.Set("client_secret", "refresh-test-secret")
	for i := 0; i < 2; i++ {
		if r := refreshFormRequest(t, ts, form); r.StatusCode != 200 {
			t.Fatalf("authenticated grace attempt %d: %+v", i, r)
		}
	}
	ts.Clock.T = ts.Clock.T.Add(6 * time.Second)
	if r := refreshFormRequest(t, ts, form); r.StatusCode != 400 || r.Error != "invalid_grant" {
		t.Fatalf("outside grace: %+v", r)
	}
	var live int
	if err := ts.DB.QueryRowContext(context.Background(), `SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatal("replay outside confidential grace did not revoke children")
	}
}
