package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/storage"
)

// ── Fakes ────────────────────────────────────────────────────────────────────

// fakeEndSessionProvider stands in for *op.Provider. The tests below never
// send an id_token_hint, so the hint verifier is never exercised here; hint
// handling is covered end to end in internal/integration.
type fakeEndSessionProvider struct {
	storage fakeOPStorage
}

func (p *fakeEndSessionProvider) Decoder() httphelper.Decoder { return endSessionDecoder{} }
func (p *fakeEndSessionProvider) Storage() op.Storage         { return p.storage }
func (p *fakeEndSessionProvider) IDTokenHintVerifier(context.Context) *op.IDTokenHintVerifier {
	return op.NewIDTokenHintVerifier("http://issuer.test", nil)
}
func (p *fakeEndSessionProvider) DefaultLogoutRedirectURI() string       { return "" }
func (p *fakeEndSessionProvider) Logger() *slog.Logger                   { return slog.Default() }
func (p *fakeEndSessionProvider) IssuerFromRequest(*http.Request) string { return "http://issuer.test" }

type endSessionDecoder struct{}

func (endSessionDecoder) Decode(dst any, src map[string][]string) error {
	req := dst.(*oidc.EndSessionRequest)
	get := func(k string) string { return url.Values(src).Get(k) }
	req.IdTokenHint = get("id_token_hint")
	req.LogoutHint = get("logout_hint")
	req.ClientID = get("client_id")
	req.PostLogoutRedirectURI = get("post_logout_redirect_uri")
	req.State = get("state")
	return nil
}

// fakeOPStorage knows exactly one client, "rp", which registered
// https://rp.test/signed-out as its post-logout redirect.
type fakeOPStorage struct {
	op.Storage
}

func (fakeOPStorage) GetClientByClientID(_ context.Context, clientID string) (op.Client, error) {
	if clientID != "rp" {
		return nil, storage.ErrNotFound
	}
	return fakeOPClient{}, nil
}

type fakeOPClient struct {
	op.Client
}

func (fakeOPClient) GetID() string                       { return "rp" }
func (fakeOPClient) PostLogoutRedirectURIs() []string    { return []string{"https://rp.test/signed-out"} }
func (fakeOPClient) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }

type fakeLogoutStore struct {
	sessions   map[string]string // session id → user id
	lookupErr  error
	terminated []string
	lookups    []string
}

func (s *fakeLogoutStore) GetValidSession(_ context.Context, sessionID string) (*storage.User, error) {
	s.lookups = append(s.lookups, sessionID)
	if s.lookupErr != nil {
		return nil, s.lookupErr
	}
	userID, ok := s.sessions[sessionID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return &storage.User{ID: userID, Status: "active"}, nil
}

func (s *fakeLogoutStore) TerminateSession(_ context.Context, userID, _ string) error {
	s.terminated = append(s.terminated, userID)
	return nil
}

func newTestLogoutHandler() (*LogoutHandler, *fakeLogoutStore) {
	store := &fakeLogoutStore{sessions: map[string]string{"sess-1": "user-1"}}
	return NewLogoutHandler(&fakeEndSessionProvider{}, store, false, pages.Brand{Name: "authgate"}), store
}

func postEndSession(form url.Values, cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/end_session", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

var browserSession = &http.Cookie{Name: sessionCookieName(false), Value: "sess-1"}

// ── Confirmation requirement ─────────────────────────────────────────────────

// logout-unit-001: a signed-in browser with no id_token_hint gets a
// confirmation page, not a logout. Without it any site could sign a visitor
// out with a plain link (RP-Initiated Logout 1.0 §2).
func TestEndSession_SessionWithoutHint_AsksForConfirmation(t *testing.T) {
	h, store := newTestLogoutHandler()
	req := httptest.NewRequest(http.MethodGet, "/end_session?state=abc", nil)
	req.AddCookie(browserSession)
	rec := httptest.NewRecorder()

	h.HandleEndSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(store.terminated) != 0 {
		t.Fatalf("terminated %v before the user confirmed", store.terminated)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="csrf_token"`) || !strings.Contains(body, `name="state" value="abc"`) {
		t.Fatalf("confirmation page is missing the csrf token or the carried state:\n%s", body)
	}
	c := findCookie(t, rec.Result().Cookies(), csrfCookieName(logoutCSRFCookie, false))
	// __Host- is only honored with Path=/ and Secure, and the browser refuses
	// a Domain attribute on it, which is what keeps a sibling subdomain from
	// writing this cookie.
	if c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteStrictMode || !c.HttpOnly || !c.Secure {
		t.Errorf("csrf cookie = %+v, want Path=/, no Domain, Strict, HttpOnly, Secure", c)
	}
	if !strings.Contains(body, `value="`+c.Value+`"`) {
		t.Error("csrf form value does not match the csrf cookie")
	}
}

// ── CSRF guard ───────────────────────────────────────────────────────────────

// logout-unit-002: a confirmation POST without a matching double-submit token
// is rejected and ends nothing.
func TestEndSession_ConfirmWithoutValidCSRF_Forbidden(t *testing.T) {
	cases := map[string]struct {
		formToken string
		cookie    *http.Cookie
	}{
		"missing form token": {formToken: "", cookie: &http.Cookie{Name: csrfCookieName(logoutCSRFCookie, false), Value: "tok"}},
		"missing cookie":     {formToken: "tok"},
		"mismatch":           {formToken: "tok", cookie: &http.Cookie{Name: csrfCookieName(logoutCSRFCookie, false), Value: "other"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h, store := newTestLogoutHandler()
			cookies := []*http.Cookie{browserSession}
			if tc.cookie != nil {
				cookies = append(cookies, tc.cookie)
			}
			rec := httptest.NewRecorder()

			h.HandleEndSession(rec, postEndSession(url.Values{"confirm": {"yes"}, "csrf_token": {tc.formToken}}, cookies...))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			if len(store.terminated) != 0 {
				t.Fatalf("terminated %v without a valid csrf token", store.terminated)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == sessionCookieName(false) {
					t.Fatalf("session cookie was touched on a rejected confirmation: %+v", c)
				}
			}
		})
	}
}

// logout-unit-003: a confirmed POST ends the browser user's sessions and
// expires the session and csrf cookies.
func TestEndSession_ConfirmedWithValidCSRF_EndsSessionAndClearsCookies(t *testing.T) {
	h, store := newTestLogoutHandler()
	rec := httptest.NewRecorder()

	h.HandleEndSession(rec, postEndSession(
		url.Values{"confirm": {"yes"}, "csrf_token": {"tok"}},
		browserSession, &http.Cookie{Name: csrfCookieName(logoutCSRFCookie, false), Value: "tok"},
	))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 signed-out page; body=%s", rec.Code, rec.Body.String())
	}
	if len(store.terminated) != 1 || store.terminated[0] != "user-1" {
		t.Fatalf("terminated = %v, want [user-1]", store.terminated)
	}
	cookies := rec.Result().Cookies()
	if c := findCookie(t, cookies, sessionCookieName(false)); c.MaxAge >= 0 || c.Value != "" {
		t.Errorf("session cookie = %+v, want it expired", c)
	}
	if c := findCookie(t, cookies, csrfCookieName(logoutCSRFCookie, false)); c.MaxAge >= 0 {
		t.Errorf("csrf cookie = %+v, want it expired", c)
	}
}

// ── Post-logout redirect ─────────────────────────────────────────────────────

// logout-unit-004: a post_logout_redirect_uri registered for the client is
// followed, with state appended (§3).
func TestEndSession_RegisteredPostLogoutRedirect_Redirects(t *testing.T) {
	h, _ := newTestLogoutHandler()
	req := httptest.NewRequest(http.MethodGet, "/end_session?client_id=rp&post_logout_redirect_uri="+url.QueryEscape("https://rp.test/signed-out")+"&state=xyz", nil)
	rec := httptest.NewRecorder()

	h.HandleEndSession(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://rp.test/signed-out?state=xyz" {
		t.Fatalf("Location = %q", loc)
	}
}

// logout-unit-005: a post_logout_redirect_uri that no client vouches for is
// never followed. Without client_id the OP cannot validate it, and zitadel
// leaves only "?state=…" as the redirect target.
func TestEndSession_UnvalidatedPostLogoutRedirect_RendersSignedOut(t *testing.T) {
	h, _ := newTestLogoutHandler()
	req := httptest.NewRequest(http.MethodGet, "/end_session?post_logout_redirect_uri="+url.QueryEscape("https://evil.test/")+"&state=xyz", nil)
	rec := httptest.NewRecorder()

	h.HandleEndSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 signed-out page", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("redirected to %q", loc)
	}
}

// logout-unit-006: an unregistered post_logout_redirect_uri for a known client
// is dropped, never followed; the request continues as a logout without it.
func TestEndSession_UnregisteredPostLogoutRedirect_IsIgnored(t *testing.T) {
	h, store := newTestLogoutHandler()
	req := httptest.NewRequest(http.MethodGet, "/end_session?client_id=rp&post_logout_redirect_uri="+url.QueryEscape("https://evil.test/"), nil)
	req.AddCookie(browserSession)
	rec := httptest.NewRecorder()

	h.HandleEndSession(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="confirm"`) {
		t.Fatalf("status = %d, want 200 confirmation page; body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("redirected to %q", loc)
	}
	if len(store.terminated) != 0 {
		t.Fatalf("terminated %v before confirmation", store.terminated)
	}
}

// logout-unit-007: when the session cannot be looked up, the user can still
// sign this browser out after confirming: the cookie is cleared.
func TestEndSession_SessionLookupError_ConfirmThenClearsCookie(t *testing.T) {
	h, store := newTestLogoutHandler()
	store.lookupErr = errors.New("database unavailable")

	rec := httptest.NewRecorder()
	get := httptest.NewRequest(http.MethodGet, "/end_session", nil)
	get.AddCookie(browserSession)
	h.HandleEndSession(rec, get)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="confirm"`) {
		t.Fatalf("status = %d, want 200 confirmation page; body=%s", rec.Code, rec.Body.String())
	}

	csrf := &http.Cookie{Name: csrfCookieName(logoutCSRFCookie, false), Value: "tok"}
	rec = httptest.NewRecorder()
	h.HandleEndSession(rec, postEndSession(url.Values{"csrf_token": {"tok"}, "confirm": {"yes"}}, browserSession, csrf))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName(false) && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("the session cookie was not cleared")
	}
}

// logout-unit-008: a request that carried no cookies gets no deleting
// Set-Cookie headers.
func TestEndSession_NoCookies_SetsNoCookies(t *testing.T) {
	h, _ := newTestLogoutHandler()
	rec := httptest.NewRecorder()

	h.HandleEndSession(rec, postEndSession(url.Values{}))

	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("set cookies %v on a request that carried none", cookies)
	}
}

func TestEndSession_OtherMethods_NotAllowed(t *testing.T) {
	h, _ := newTestLogoutHandler()
	rec := httptest.NewRecorder()
	h.HandleEndSession(rec, httptest.NewRequest(http.MethodPut, "/end_session", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// Exercise the handler as well as the cookie helper: a legacy cookie alone
// cannot resolve a production session or trigger its logout confirmation.
func TestEndSession_ProductionIgnoresLegacySessionCookie(t *testing.T) {
	for _, withHostCookie := range []bool{false, true} {
		t.Run(fmt.Sprintf("host cookie=%t", withHostCookie), func(t *testing.T) {
			h, store := newTestLogoutHandler()
			store.sessions["injected-session"] = "attacker"
			req := httptest.NewRequest(http.MethodGet, "/end_session", nil)
			// Put the legacy name first, as a longer-path parent-domain cookie
			// could appear before the real cookie in the browser's header.
			req.AddCookie(&http.Cookie{Name: "authgate_session", Value: "injected-session"})
			if withHostCookie {
				req.AddCookie(&http.Cookie{Name: "__Host-authgate_session", Value: "sess-1"})
			}
			rec := httptest.NewRecorder()
			h.HandleEndSession(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			cookies := rec.Result().Cookies()
			if withHostCookie {
				findCookie(t, cookies, "__Host-end_session_csrf")
				if len(store.lookups) != 1 || store.lookups[0] != "sess-1" {
					t.Fatalf("session lookups = %v, want only the host-bound session", store.lookups)
				}
			} else if len(cookies) != 0 || len(store.lookups) != 0 {
				t.Fatalf("legacy cookie triggered session lookup or response: lookups=%v, cookies=%+v", store.lookups, cookies)
			}
			if len(store.terminated) != 0 {
				t.Fatalf("terminated sessions without confirmation: %v", store.terminated)
			}
		})
	}
}
