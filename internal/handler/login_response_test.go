package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/upstream"
)

func TestLoginResponse_PreservesUpstreamStateAndPrompt(t *testing.T) {
	for _, prompt := range []string{"", "select_account"} {
		t.Run("prompt="+prompt, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/login", nil)
			result := &service.LoginResult{Action: service.ActionRedirectToIdP, AuthRequestID: "request-1", UpstreamPrompt: prompt}
			if !writeLoginResult(w, r, result, &upstream.FakeProvider{}, pages.Brand{}) {
				t.Fatal("login redirect was not handled")
			}
			target, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusFound || target.Query().Get("state") != "request-1" || target.Query().Get("prompt") != prompt {
				t.Fatalf("status=%d location=%s", w.Code, target)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("sending someone upstream must not establish a session")
			}
		})
	}
}

func TestCallbackResponse_SessionCookieOnlyOnSuccess(t *testing.T) {
	for _, tc := range []struct {
		name       string
		result     service.CallbackResult
		wantStatus int
		wantCookie bool
		location   string
	}{
		{"success", service.CallbackResult{Action: service.ActionAutoApprove, AuthRequestID: "ar-1", SessionID: "session-1"}, http.StatusFound, true, "/authorize/callback?id=ar-1"},
		{"success without session", service.CallbackResult{Action: service.ActionAutoApprove, AuthRequestID: "ar-1"}, http.StatusFound, false, "/authorize/callback?id=ar-1"},
		{"access denied", service.CallbackResult{Action: service.ActionRedirectToClient, RedirectURL: "https://client.example/cb?error=access_denied&state=s&iss=issuer", SessionID: "must-not-be-set"}, http.StatusFound, false, "https://client.example/cb?error=access_denied&state=s&iss=issuer"},
		{"error page", service.CallbackResult{Action: service.ActionError, ErrorCode: http.StatusForbidden, Error: "account_inactive", SessionID: "must-not-be-set"}, http.StatusForbidden, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/login/callback", nil)
			if !writeCallbackResult(w, r, &tc.result, false, pages.Brand{Name: "authgate"}) {
				t.Fatal("callback was not handled")
			}
			if w.Code != tc.wantStatus || w.Header().Get("Location") != tc.location {
				t.Fatalf("status=%d location=%q", w.Code, w.Header().Get("Location"))
			}
			cookies := w.Result().Cookies()
			if !tc.wantCookie {
				if len(cookies) != 0 {
					t.Fatal("response unexpectedly established a session")
				}
			} else if len(cookies) != 1 || cookies[0].Name != "__Host-authgate_session" || cookies[0].Path != "/" || cookies[0].Domain != "" || cookies[0].Value != "session-1" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
				t.Fatalf("incorrect production session cookie: %+v", cookies)
			}
			if tc.result.Action == service.ActionError && (!strings.Contains(w.Body.String(), "account_inactive") || w.Header().Get("Content-Type") != "text/html; charset=utf-8") {
				t.Fatal("error response lost its HTML content type or message")
			}
		})
	}
}

func TestLoginResponses_LeaveUnknownActionsToChannelHandler(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	if writeLoginResult(w, r, &service.LoginResult{Action: service.LoginAction(99)}, nil, pages.Brand{}) {
		t.Fatal("unknown login action was handled")
	}
	if writeCallbackResult(w, r, &service.CallbackResult{Action: service.ActionRedirectToIdP, SessionID: "must-not-be-set"}, false, pages.Brand{}) {
		t.Fatal("callback accepted a login-only action")
	}
	if w.Body.Len() != 0 || len(w.Header()) != 0 {
		t.Fatal("unhandled action wrote a response")
	}
}
