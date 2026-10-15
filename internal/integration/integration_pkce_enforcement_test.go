//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestPKCEEnforcement(t *testing.T) {
	t.Run("authorize without code_challenge returns invalid_request", func(t *testing.T) {
		ts := SetupTestServer(t)
		client := NewOAuthClient(t, ts.BaseURL)

		noFollow := *client.Client
		noFollow.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		resp, err := noFollow.Get(client.AuthorizeURLNoPKCE())
		if err != nil {
			t.Fatalf("authorize without pkce: %v", err)
		}
		defer resp.Body.Close()

		if loc := resp.Header.Get("Location"); loc != "" {
			u, parseErr := url.Parse(loc)
			if parseErr != nil {
				t.Fatalf("parse location: %v", parseErr)
			}
			if got := u.Query().Get("error"); got != "invalid_request" {
				t.Fatalf("expected error=invalid_request in redirect, got %q (location=%s)", got, loc)
			}
			if got := u.Query().Get("iss"); got != ts.BaseURL {
				t.Fatalf("authorization response iss = %q, want %q", got, ts.BaseURL)
			}
			return
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "invalid_request") {
			t.Fatalf("expected invalid_request in response body, status=%d body=%s", resp.StatusCode, string(body))
		}
	})

	t.Run("authorize with S256 code_challenge succeeds", func(t *testing.T) {
		ts := SetupTestServer(t)
		client := NewOAuthClient(t, ts.BaseURL)

		code := completeLoginFlowToCode(t, ts, client)
		if code == "" {
			t.Fatal("expected authorization code from redirect without error")
		}
	})
}

// A confidential client may waive PKCE via skip_pkce. This exists for OIDC
// libraries that cannot send code_challenge — Gitea's goth openidConnect
// provider has no PKCE support at all.
func TestPKCESkipForConfidentialClient(t *testing.T) {
	t.Run("authorize without code_challenge is accepted", func(t *testing.T) {
		ts := SetupTestServer(t)
		client := NewOAuthClientFor(t, ts.BaseURL, "skip-pkce-client", "/login/callback")

		noFollow := *client.Client
		noFollow.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		resp, err := noFollow.Get(client.AuthorizeURLNoPKCE())
		if err != nil {
			t.Fatalf("authorize without pkce: %v", err)
		}
		defer resp.Body.Close()

		// Assert the success shape, not the absence of one error string. A
		// waived request that still failed — for any reason, with any body —
		// has to fail this test, so the only accepted outcome is the redirect
		// into the login flow that an authorized request produces.
		if resp.StatusCode != http.StatusFound {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 302: skip_pkce client was not authorized (body=%s)", resp.StatusCode, string(body))
		}

		loc := resp.Header.Get("Location")
		if loc == "" {
			t.Fatal("302 with no Location header")
		}
		u, err := url.Parse(loc)
		if err != nil {
			t.Fatalf("parse location %q: %v", loc, err)
		}
		// An error is reported by redirecting back to the client's redirect_uri
		// with ?error=…, so a bare check of the query would not distinguish it
		// from the login redirect. Pin the path instead.
		if u.Path != "/login" {
			t.Fatalf("Location path = %q, want /login (location=%s)", u.Path, loc)
		}
		if got := u.Query().Get("error"); got != "" {
			t.Fatalf("authorization returned error=%q (location=%s)", got, loc)
		}
		if u.Query().Get("authRequestID") == "" {
			t.Fatalf("no authRequestID in login redirect (location=%s)", loc)
		}
	})
}

// Pin the HTTP and persistence boundary together: a skip_pkce exception may
// waive the challenge, but must not store a method the verifier interprets as
// plain merely because it is not S256.
func TestAuthorizePKCEMethodValidation(t *testing.T) {
	ts := SetupTestServer(t)
	for _, client := range []struct {
		id           string
		callbackPath string
		loginPath    string
		skipPKCE     bool
	}{
		{"test-client", "/login/callback", "/login", false},
		{"mcp-client", "/mcp/callback", "/mcp/login", false},
		{"skip-pkce-client", "/login/callback", "/login", true},
	} {
		t.Run(client.id, func(t *testing.T) {
			for _, tc := range []struct {
				name      string
				challenge bool
				method    string
			}{
				{"no PKCE", false, ""},
				{"S256", true, "S256"},
				{"explicit plain", true, "plain"},
				{"implicit plain", true, ""},
				{"unknown S512", true, "S512"},
				{"lowercase s256", true, "s256"},
				{"uppercase PLAIN", true, "PLAIN"},
				{"method only S256", false, "S256"},
				{"method only unknown", false, "S512"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					oauth := NewOAuthClientFor(t, ts.BaseURL, client.id, client.callbackPath)
					u, err := url.Parse(oauth.AuthorizeURL())
					if err != nil {
						t.Fatalf("parse authorize URL: %v", err)
					}
					params := u.Query()
					// Use a unique state to check the exact request's DB effect.
					params.Set("state", t.Name())
					params.Set("scope", "openid")
					challenge := ""
					if tc.challenge {
						challenge = oauth.CodeChallenge
						params.Set("code_challenge", challenge)
					} else {
						params.Del("code_challenge")
					}
					if tc.method == "" {
						params.Del("code_challenge_method")
					} else {
						params.Set("code_challenge_method", tc.method)
					}
					u.RawQuery = params.Encode()
					noFollow := *oauth.Client
					noFollow.CheckRedirect = func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					}
					resp, err := noFollow.Get(u.String())
					if err != nil {
						t.Fatalf("authorize: %v", err)
					}
					defer resp.Body.Close()
					if resp.StatusCode != http.StatusFound {
						body, _ := io.ReadAll(resp.Body)
						t.Fatalf("status = %d, want 302 (body=%s)", resp.StatusCode, body)
					}
					loc, err := url.Parse(resp.Header.Get("Location"))
					if err != nil {
						t.Fatalf("parse redirect: %v", err)
					}
					accepted := tc.challenge && tc.method == "S256"
					if client.skipPKCE {
						accepted = !tc.challenge || tc.method == "" || tc.method == "plain" || tc.method == "S256"
					}
					var storedCount int
					if err := ts.DB.QueryRowContext(context.Background(),
						`SELECT COUNT(*) FROM auth_requests WHERE client_id = $1 AND state = $2`,
						client.id, t.Name(),
					).Scan(&storedCount); err != nil {
						t.Fatalf("count auth requests: %v", err)
					}
					if !accepted {
						if loc.Path != "/callback" || loc.Query().Get("error") != "invalid_request" ||
							loc.Query().Get("state") != t.Name() || loc.Query().Get("iss") != ts.BaseURL {
							t.Fatalf("expected invalid_request callback with state and issuer, got %s", loc)
						}
						if storedCount != 0 {
							t.Fatalf("rejected request persisted %d rows, want 0", storedCount)
						}
						if client.skipPKCE && loc.Query().Get("error_description") != "unsupported code_challenge_method" {
							t.Fatalf("expected unsupported method error, got %s", loc)
						}
						return
					}
					if loc.Path != client.loginPath || loc.Query().Get("error") != "" || loc.Query().Get("authRequestID") == "" {
						t.Fatalf("expected redirect into %s, got %s", client.loginPath, loc)
					}
					if storedCount != 1 {
						t.Fatalf("accepted request persisted %d rows, want 1", storedCount)
					}
					stored, err := ts.Store.GetAuthRequestModel(context.Background(), loc.Query().Get("authRequestID"))
					if err != nil {
						t.Fatalf("load auth request: %v", err)
					}
					if stored.CodeChallenge != challenge || stored.CodeChallengeMethod != tc.method || stored.State != t.Name() {
						t.Fatalf("stored challenge/method/state = %q/%q/%q, want %q/%q/%q",
							stored.CodeChallenge, stored.CodeChallengeMethod, stored.State, challenge, tc.method, t.Name())
					}
				})
			}
		})
	}
}
