//go:build integration

package integration

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clientaccess"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

func mustPolicy(t *testing.T, allow clientaccess.Rules, deny clientaccess.DenyRules) *clientaccess.Policy {
	t.Helper()
	p, err := clientaccess.New(allow, deny)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return p
}

// browserLoginUntilCallbackResponse runs /authorize → /login → the fake IdP
// callback for client and returns the callback's Location without following
// it.
func browserLoginUntilCallbackResponse(t *testing.T, ts *TestServer, client *OAuthClient) (int, string) {
	t.Helper()
	noFollow := noFollowCopy(client)
	loc := authorizeToLoginRedirect(t, ts, client)
	idp, err := url.Parse(loc)
	if err != nil || idp.Path != "/fake-auth" {
		t.Fatalf("login Location = %q, want upstream IdP redirect", loc)
	}
	resp, err := noFollow.Get(ts.BaseURL + "/login/callback?code=fake-code&state=" + url.QueryEscape(idp.Query().Get("state")))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

// assertAccessDeniedRedirect checks an authorization error response to the
// client: its redirect_uri with error=access_denied, the request state and iss.
func assertAccessDeniedRedirect(t *testing.T, ts *TestServer, status int, location string) {
	t.Helper()
	if status != http.StatusFound {
		t.Fatalf("status = %d, want 302", status)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location %q: %v", location, err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != ts.BaseURL+"/callback" {
		t.Fatalf("redirect target = %q, want the client's redirect_uri", got)
	}
	q := u.Query()
	if q.Get("error") != "access_denied" || q.Get("state") != "test-state" || q.Get("iss") != ts.BaseURL {
		t.Fatalf("redirect query = %v, want error=access_denied state=test-state iss=%s", q, ts.BaseURL)
	}
	if q.Get("code") != "" {
		t.Fatalf("access_denied redirect carries a code: %s", location)
	}
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// client-access-100: a person the client's policy refuses is sent back to the
// client with access_denied and no account is created.
func TestIntegration_ClientAccess_DeniedSignup(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP:              true,
		RestrictedClientAccess: mustPolicy(t, clientaccess.Rules{Emails: []string{"someone@allowed.test"}}, clientaccess.DenyRules{}),
	})

	status, loc := browserLoginUntilCallbackResponse(t, ts, NewOAuthClientFor(t, ts.BaseURL, RestrictedClientID, "/login/callback"))
	assertAccessDeniedRedirect(t, ts, status, loc)

	if n := countRows(t, ts.DB, `SELECT count(*) FROM users`); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM sessions`); n != 0 {
		t.Fatalf("sessions = %d, want 0", n)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.signup'`); n != 0 {
		t.Fatalf("auth.signup = %d, want 0", n)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.access_denied'`); n != 1 {
		t.Fatalf("auth.access_denied = %d, want 1", n)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log
		WHERE event_type = 'auth.access_denied' AND user_id IS NULL
		  AND metadata->>'client_id' = $1 AND metadata->>'client_name' = 'Restricted Test'
		  AND metadata->>'channel' = 'browser' AND metadata->>'reason' = 'not_allowed'
		  AND metadata->>'domain' = 'example.com' AND metadata->>'signup' = 'true'
		  AND metadata::text NOT LIKE '%test@example.com%'`, RestrictedClientID); n != 1 {
		t.Fatalf("auth.access_denied row with the expected metadata = %d, want 1", n)
	}
}

// client-access-101: an allowed email signs up and gets tokens.
func TestIntegration_ClientAccess_AllowedEmailIssuesTokens(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP:              true,
		RestrictedClientAccess: mustPolicy(t, clientaccess.Rules{Emails: []string{"Test@Example.com"}}, clientaccess.DenyRules{}),
	})
	client := NewOAuthClientFor(t, ts.BaseURL, RestrictedClientID, "/login/callback")
	tokens := client.ExchangeCode(completeLoginFlowToCode(t, ts, client))
	if tokens.StatusCode != http.StatusOK || tokens.AccessToken == "" {
		t.Fatalf("token exchange status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.access_denied'`); n != 0 {
		t.Fatalf("auth.access_denied = %d, want 0", n)
	}
}

// client-access-102: the Google hosted domain from the login is persisted and
// matched by google_workspace_domains, even when the email itself would not be.
func TestIntegration_ClientAccess_HostedDomainPersistedAndMatched(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP:              true,
		RestrictedClientAccess: mustPolicy(t, clientaccess.Rules{GoogleWorkspaceDomains: []string{"corp.test"}}, clientaccess.DenyRules{}),
	})
	ts.Upstream.User = &upstream.UserInfo{Sub: "hd-sub", Email: "person@example.com", EmailVerified: true, Name: "HD", HostedDomain: "corp.test"}

	client := NewOAuthClientFor(t, ts.BaseURL, RestrictedClientID, "/login/callback")
	tokens := client.ExchangeCode(completeLoginFlowToCode(t, ts, client))
	if tokens.StatusCode != http.StatusOK {
		t.Fatalf("token exchange status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM user_identities WHERE hosted_domain = 'corp.test'`); n != 1 {
		t.Fatalf("identities with hosted_domain corp.test = %d, want 1", n)
	}

	// The account leaves the workspace: the next login records no hd, and the
	// client refuses it.
	ts.Upstream.User = &upstream.UserInfo{Sub: "hd-sub", Email: "person@example.com", EmailVerified: true, Name: "HD"}
	status, loc := browserLoginUntilCallbackResponse(t, ts, NewOAuthClientFor(t, ts.BaseURL, RestrictedClientID, "/login/callback"))
	assertAccessDeniedRedirect(t, ts, status, loc)
	if n := countRows(t, ts.DB, `SELECT count(*) FROM user_identities WHERE hosted_domain IS NULL`); n != 1 {
		t.Fatalf("identities with hosted_domain cleared = %d, want 1", n)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.access_denied' AND user_id IS NOT NULL AND metadata->>'signup' = 'false'`); n != 1 {
		t.Fatalf("auth.access_denied for the existing account = %d, want 1", n)
	}
}

// client-access-103: an existing session is not reused for a client that
// refuses the account, and is still reused for a public client.
func TestIntegration_ClientAccess_SessionReuse(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP:              true,
		RestrictedClientAccess: mustPolicy(t, clientaccess.Rules{EmailDomains: []string{"allowed.test"}}, clientaccess.DenyRules{}),
	})

	// Sign up through the public client; the jar now holds the session.
	public := NewOAuthClient(t, ts.BaseURL)
	completeLoginFlowToCode(t, ts, public)

	restricted := NewOAuthClientFor(t, ts.BaseURL, RestrictedClientID, "/login/callback")
	restricted.Client.Jar = public.Client.Jar
	for _, prompt := range []string{"", "none"} {
		t.Run("prompt="+prompt, func(t *testing.T) {
			restricted.Prompt = prompt
			noFollow := noFollowCopy(restricted)
			resp, err := noFollow.Get(restricted.AuthorizeURL())
			if err != nil {
				t.Fatalf("authorize: %v", err)
			}
			resp.Body.Close()
			resp, err = noFollow.Get(ts.BaseURL + resp.Header.Get("Location"))
			if err != nil {
				t.Fatalf("login: %v", err)
			}
			resp.Body.Close()
			assertAccessDeniedRedirect(t, ts, resp.StatusCode, resp.Header.Get("Location"))
		})
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.access_denied' AND user_id IS NOT NULL AND metadata->>'channel' = 'browser'`); n != 2 {
		t.Fatalf("auth.access_denied = %d, want 2", n)
	}

	// The same session still works for the public client.
	public.Prompt = "none"
	loc := authorizeToLoginRedirect(t, ts, public)
	if !strings.Contains(loc, "/authorize/callback?id=") {
		t.Fatalf("public client session reuse Location = %q, want auto-approve", loc)
	}
}

// client-access-104: a refresh for an account the client's policy no longer
// admits is refused with invalid_grant.
func TestIntegration_ClientAccess_RefreshDeniedAfterPolicyChange(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP:              true,
		RestrictedClientAccess: mustPolicy(t, clientaccess.Rules{EmailDomains: []string{"example.com"}}, clientaccess.DenyRules{}),
	})
	client := NewOAuthClientFor(t, ts.BaseURL, RestrictedClientID, "/login/callback")
	tokens := client.ExchangeCode(completeLoginFlowToCode(t, ts, client))
	if tokens.StatusCode != http.StatusOK || tokens.RefreshToken == "" {
		t.Fatalf("token exchange status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}

	// Still allowed: the refresh succeeds.
	refreshed := client.RefreshToken(tokens.RefreshToken)
	if refreshed.StatusCode != http.StatusOK {
		t.Fatalf("refresh while allowed status=%d body=%s", refreshed.StatusCode, refreshed.RawBody)
	}

	// The operator narrows the policy (a restart with an edited clients.yaml).
	ts.Store.LoadClients([]oauthclient.ConfigEntry{RestrictedClientEntry(ts.BaseURL, mustPolicy(t,
		clientaccess.Rules{EmailDomains: []string{"example.com"}},
		clientaccess.DenyRules{Emails: []string{"test@example.com"}},
	))})

	denied := client.RefreshToken(refreshed.RefreshToken)
	if denied.StatusCode != http.StatusBadRequest || !strings.Contains(denied.RawBody, "invalid_grant") {
		t.Fatalf("refresh after policy change status=%d body=%s, want 400 invalid_grant", denied.StatusCode, denied.RawBody)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.access_denied' AND user_id IS NOT NULL AND metadata->>'channel' = 'refresh' AND metadata->>'reason' = 'deny_listed'`); n != 1 {
		t.Fatalf("auth.access_denied for the refresh = %d, want 1", n)
	}
	// Refused, not revoked as a reuse: the family is not tombstoned.
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.refresh_reuse_detected'`); n != 0 {
		t.Fatalf("auth.refresh_reuse_detected = %d, want 0", n)
	}
}

// client-access-105: the deny list wins over a matching allow rule.
func TestIntegration_ClientAccess_DenyOverridesAllow(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP: true,
		RestrictedClientAccess: mustPolicy(t,
			clientaccess.Rules{EmailDomains: []string{"example.com"}},
			clientaccess.DenyRules{Emails: []string{"test@example.com"}},
		),
	})
	status, loc := browserLoginUntilCallbackResponse(t, ts, NewOAuthClientFor(t, ts.BaseURL, RestrictedClientID, "/login/callback"))
	assertAccessDeniedRedirect(t, ts, status, loc)
	if n := countRows(t, ts.DB, `SELECT count(*) FROM users`); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.access_denied' AND metadata->>'reason' = 'deny_listed'`); n != 1 {
		t.Fatalf("auth.access_denied deny_listed = %d, want 1", n)
	}
}

// client-access-106: a code issued while the policy admitted the account is not
// exchanged for tokens once the policy refuses it: the exchange re-evaluates
// the policy and answers 400 invalid_grant.
func TestIntegration_ClientAccess_CodeExchangeDeniedAfterPolicyChange(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP:              true,
		RestrictedClientAccess: mustPolicy(t, clientaccess.Rules{EmailDomains: []string{"example.com"}}, clientaccess.DenyRules{}),
	})
	client := NewOAuthClientFor(t, ts.BaseURL, RestrictedClientID, "/login/callback")
	code := completeLoginFlowToCode(t, ts, client)

	// The operator deny-lists the account between the callback and the exchange.
	ts.Store.LoadClients([]oauthclient.ConfigEntry{RestrictedClientEntry(ts.BaseURL, mustPolicy(t,
		clientaccess.Rules{EmailDomains: []string{"example.com"}},
		clientaccess.DenyRules{Emails: []string{"test@example.com"}},
	))})

	tokens := client.ExchangeCode(code)
	if tokens.StatusCode != http.StatusBadRequest || !strings.Contains(tokens.RawBody, "invalid_grant") || tokens.AccessToken != "" {
		t.Fatalf("code exchange after policy change status=%d body=%s, want 400 invalid_grant", tokens.StatusCode, tokens.RawBody)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.access_denied'`); n != 1 {
		t.Fatalf("auth.access_denied = %d, want 1", n)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.access_denied'
		AND user_id IS NOT NULL AND metadata->>'client_id' = $1 AND metadata->>'channel' = 'browser'
		AND metadata->>'reason' = 'deny_listed' AND metadata->>'signup' = 'false'`, RestrictedClientID); n != 1 {
		t.Fatalf("auth.access_denied row with the expected metadata = %d, want 1", n)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM refresh_tokens`); n != 0 {
		t.Fatalf("refresh_tokens = %d, want 0", n)
	}
	// The response must not say why. zitadel runs this check before it
	// verifies PKCE and authenticates the client, so the caller here has
	// proven nothing yet: the body has to read like any other bad code.
	// zitadel currently masks storage errors at this endpoint anyway
	// (pkg/op/token_code.go), so this also pins that we do not start
	// depending on the library to keep our reasons out of the response.
	for _, leak := range []string{"not allowed", "policy", "denied", "account", "client"} {
		if strings.Contains(strings.ToLower(tokens.RawBody), leak) {
			t.Errorf("code exchange body leaks %q to an unauthenticated caller: %s", leak, tokens.RawBody)
		}
	}
	if body := sameShapeBody(t, ts, client); body != tokens.RawBody {
		t.Errorf("refused exchange body = %s, want it identical to an unknown code: %s", tokens.RawBody, body)
	}
}

// sameShapeBody exchanges a code that never existed, so the caller cannot tell
// a refused account from a bad code by comparing responses.
func sameShapeBody(t *testing.T, ts *TestServer, client *OAuthClient) string {
	t.Helper()
	_ = ts
	return client.ExchangeCode("not-a-real-authorization-code").RawBody
}

// client-access-107: an approved device code is not exchanged for tokens once
// the client's policy refuses the approving account. The poll is refused, the
// code stays approved, and relaxing the policy lets the next poll succeed.
func TestIntegration_ClientAccess_DevicePollDeniedAfterPolicyChange(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email: "device-user@example.com", EmailVerified: true, Name: "Device User",
		Provider: "google", ProviderUserID: "device-access-sub",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	authz := startDeviceAuthorization(t, ts)
	if err := ts.Store.ApproveDeviceCode(ctx, authz.UserCode, user.ID, time.Time{}); err != nil {
		t.Fatalf("approve device code: %v", err)
	}

	deviceClient := func(access *clientaccess.Policy) oauthclient.ConfigEntry {
		return oauthclient.ConfigEntry{
			ClientID:          "test-client",
			ClientType:        "public",
			LoginChannel:      "browser",
			Name:              "Test",
			RedirectURIs:      []string{ts.BaseURL + "/callback"},
			AllowedScopes:     []string{"openid", "profile", "email", "offline_access"},
			AllowedGrantTypes: []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
			Access:            access,
		}
	}
	// The operator deny-lists the account after approval, before the poll.
	ts.Store.LoadClients([]oauthclient.ConfigEntry{deviceClient(mustPolicy(t,
		clientaccess.Rules{EmailDomains: []string{"example.com"}},
		clientaccess.DenyRules{Emails: []string{"device-user@example.com"}},
	))})

	result := pollDeviceToken(t, ts, authz.DeviceCode)
	// zitadel/oidc reports every storage error on the device grant as
	// access_denied (400); the storage layer returns invalid_grant.
	if result.StatusCode != http.StatusBadRequest || result.AccessToken != "" ||
		(!strings.Contains(result.RawBody, "access_denied") && !strings.Contains(result.RawBody, "invalid_grant")) {
		t.Fatalf("device poll after policy change status=%d body=%s, want 400 refusal", result.StatusCode, result.RawBody)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.access_denied'`); n != 1 {
		t.Fatalf("auth.access_denied = %d, want 1", n)
	}
	if n := countRows(t, ts.DB, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.access_denied'
		AND user_id = $1 AND metadata->>'client_id' = 'test-client' AND metadata->>'channel' = 'device'
		AND metadata->>'reason' = 'deny_listed'`, user.ID); n != 1 {
		t.Fatalf("auth.access_denied row with the expected metadata = %d, want 1", n)
	}
	dc, err := ts.Store.GetDeviceCodeByUserCode(ctx, authz.UserCode)
	if err != nil {
		t.Fatalf("re-read device code: %v", err)
	}
	if dc.State != "approved" {
		t.Fatalf("device code state = %q, want approved", dc.State)
	}

	// Relaxing the policy again lets the approved code be exchanged.
	ts.Store.LoadClients([]oauthclient.ConfigEntry{deviceClient(nil)})
	if ok := pollDeviceToken(t, ts, authz.DeviceCode); ok.StatusCode != http.StatusOK || ok.AccessToken == "" {
		t.Fatalf("device poll after relaxing the policy status=%d body=%s, want 200", ok.StatusCode, ok.RawBody)
	}
}
