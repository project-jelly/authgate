package upstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
)

func nonceCookieForTest(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q not set", name)
	return nil
}

// The same provider implementation protects all three entry points, in both
// HTTPS production and explicit HTTP development mode. Keep the library's
// state and PKCE handlers, and exercise a complete exchange after the change.
func TestOIDCProvider_NonceCookieSharedFlows(t *testing.T) {
	for _, path := range []string{"/login/callback", "/device/auth/callback", "/mcp/callback"} {
		for _, secure := range []bool{true, false} {
			mode := "development"
			nonceName := "nonce"
			scheme := "http"
			if secure {
				mode = "production"
				nonceName = "__Host-authgate_nonce"
				scheme = "https"
			}
			t.Run(path+"/"+mode, func(t *testing.T) {
				idp := newFakeIdP(t)
				redirectURI := scheme + "://authgate.example" + path
				p, err := NewOIDCProvider(context.Background(), idp.srv.URL, testClientID, testClientSecret, redirectURI,
					WithCookieSecret("test-cookie-secret", secure))
				if err != nil {
					t.Fatalf("NewOIDCProvider: %v", err)
				}
				redirect := httptest.NewRecorder()
				p.Redirect(redirect, httptest.NewRequest(http.MethodGet, scheme+"://authgate.example/login", nil), "login-state")
				if redirect.Code != http.StatusFound {
					t.Fatalf("redirect status = %d, want 302", redirect.Code)
				}
				u, err := url.Parse(redirect.Header().Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				if u.Query().Get("redirect_uri") != redirectURI || u.Query().Get("nonce") == "" {
					t.Fatalf("authorization URL = %s, want correct callback and nonce", u)
				}
				idp.nonce = u.Query().Get("nonce")
				issued := nonceCookieForTest(t, redirect.Result().Cookies(), nonceName)
				if issued.Secure != secure || issued.Path != "/" || issued.Domain != "" || !issued.HttpOnly || issued.SameSite != http.SameSiteLaxMode {
					t.Fatalf("nonce cookie attributes = %+v", issued)
				}
				req := httptest.NewRequest(http.MethodGet, redirectURI+"?code=valid-code&state=login-state", nil)
				if secure {
					// Even a correctly signed legacy cookie ordered before the
					// host-bound cookie must not replace the expected nonce.
					legacy, err := p.ch.CreateCookie("nonce", "injected-nonce")
					if err != nil {
						t.Fatal(err)
					}
					req.AddCookie(legacy)
				}
				for _, cookie := range redirect.Result().Cookies() {
					req.AddCookie(cookie)
				}
				rec := httptest.NewRecorder()
				called := false
				p.Callback(rec, req, func(_ http.ResponseWriter, _ *http.Request, state string, info *UserInfo) {
					called = true
					if state != "login-state" || info.Sub != "test-sub" {
						t.Errorf("state = %q, user = %+v", state, info)
					}
				})
				if !called || idp.tokenRequests.Load() != 1 {
					t.Fatalf("callback called = %t, token requests = %d, want successful exchange", called, idp.tokenRequests.Load())
				}
				deleted := nonceCookieForTest(t, rec.Result().Cookies(), nonceName)
				if deleted.Value != "" || deleted.MaxAge >= 0 || deleted.Secure != issued.Secure || deleted.Path != issued.Path || deleted.Domain != issued.Domain || deleted.HttpOnly != issued.HttpOnly || deleted.SameSite != issued.SameSite {
					t.Fatalf("nonce deletion = %+v, want matching attributes and expiration", deleted)
				}
			})
		}
	}
}

func TestOIDCProvider_InvalidNonceCookieStopsBeforeExchange(t *testing.T) {
	for _, variant := range []string{"missing", "tampered", "authenticated empty", "legacy only", "renamed legacy"} {
		t.Run(variant, func(t *testing.T) {
			idp := newFakeIdP(t)
			p, err := NewOIDCProvider(context.Background(), idp.srv.URL, testClientID, testClientSecret, testRedirectURI,
				WithCookieSecret("test-cookie-secret", true))
			if err != nil {
				t.Fatal(err)
			}
			redirect := httptest.NewRecorder()
			p.Redirect(redirect, httptest.NewRequest(http.MethodGet, "/login", nil), "login-state")
			if redirect.Code != http.StatusFound {
				t.Fatalf("redirect status = %d, want 302", redirect.Code)
			}
			req := httptest.NewRequest(http.MethodGet, "/login/callback?code=valid-code&state=login-state", nil)
			// Leave the token's nonce empty as well: the application must
			// require its own cookie before even requesting that ID token.
			for _, cookie := range redirect.Result().Cookies() {
				if cookie.Name != "__Host-authgate_nonce" {
					req.AddCookie(cookie)
				}
			}
			switch variant {
			case "tampered":
				req.AddCookie(&http.Cookie{Name: "__Host-authgate_nonce", Value: "not-authenticated"})
			case "authenticated empty":
				cookie, err := p.ch.CreateCookie("__Host-authgate_nonce", "")
				if err != nil {
					t.Fatal(err)
				}
				req.AddCookie(cookie)
			case "legacy only", "renamed legacy":
				cookie, err := p.ch.CreateCookie("nonce", "legacy-nonce")
				if err != nil {
					t.Fatal(err)
				}
				if variant == "renamed legacy" {
					cookie.Name = "__Host-authgate_nonce"
				}
				req.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()
			called := false
			p.Callback(rec, req, func(http.ResponseWriter, *http.Request, string, *UserInfo) { called = true })
			if called || rec.Code != http.StatusUnauthorized || idp.tokenRequests.Load() != 0 {
				t.Fatalf("callback = %t, status = %d, token requests = %d; want no callback or exchange, 401", called, rec.Code, idp.tokenRequests.Load())
			}
			if rec.Body.String() != "authentication failed\n" {
				t.Fatalf("error response leaked cookie details: %q", rec.Body.String())
			}
			deleted := nonceCookieForTest(t, rec.Result().Cookies(), "__Host-authgate_nonce")
			if deleted.Value != "" || deleted.MaxAge >= 0 || !deleted.Secure || deleted.Path != "/" || deleted.Domain != "" {
				t.Fatalf("nonce was not cleared safely: %+v", deleted)
			}
		})
	}
}

func TestOIDCProvider_NonceCookieFailureStopsRedirect(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.newProvider(t)
	// Invalid hash key makes the existing cookie handler's encoder fail.
	p.ch = httphelper.NewCookieHandler(nil, nil)
	rec := httptest.NewRecorder()
	p.Redirect(rec, httptest.NewRequest(http.MethodGet, "/login", nil), "login-state")
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("status = %d, Location = %q, cookies = %+v; want 500 with no redirect or cookies", rec.Code, rec.Header().Get("Location"), rec.Result().Cookies())
	}
	if rec.Body.String() != "authentication failed\n" || idp.tokenRequests.Load() != 0 {
		t.Fatal("cookie failure disclosed details or exchanged a code")
	}
}
