package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/upstream"
)

func newTestLoginHandler(devMode bool) *LoginHandler {
	svc := service.NewLoginService(nil, "", "", 0)
	// FakeProvider.Callback delivers the (empty) state to CompleteBrowserLogin,
	// which returns the 400 "missing code or state" the callback test asserts.
	provider := &upstream.FakeProvider{User: &upstream.UserInfo{Sub: "sub"}}
	return NewLoginHandler(svc, provider, devMode, pages.Brand{Name: "authgate"})
}

func TestLogin_MissingAuthRequestID_ReturnsBadRequest(t *testing.T) {
	h := newTestLoginHandler(true)
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()

	h.HandleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
}

func TestLoginCallback_MissingCodeOrState_ReturnsBadRequest(t *testing.T) {
	h := newTestLoginHandler(true)
	req := httptest.NewRequest(http.MethodGet, "/login/callback", nil)
	w := httptest.NewRecorder()

	h.HandleCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestSetSessionCookie_SecureDependsOnDevMode(t *testing.T) {
	t.Run("prod mode uses Secure", func(t *testing.T) {
		w := httptest.NewRecorder()
		setSessionCookie(w, "sess-prod", false)

		resp := w.Result()
		cookies := resp.Cookies()
		if len(cookies) != 1 {
			t.Fatalf("cookies = %d, want 1", len(cookies))
		}
		c := cookies[0]
		if !c.Secure {
			t.Fatalf("Secure = false, want true")
		}
		if !c.HttpOnly {
			t.Fatalf("HttpOnly = false, want true")
		}
		if c.Path != "/" {
			t.Fatalf("Path = %q, want /", c.Path)
		}
	})

	t.Run("dev mode disables Secure", func(t *testing.T) {
		w := httptest.NewRecorder()
		setSessionCookie(w, "sess-dev", true)

		resp := w.Result()
		cookies := resp.Cookies()
		if len(cookies) != 1 {
			t.Fatalf("cookies = %d, want 1", len(cookies))
		}
		if cookies[0].Secure {
			t.Fatalf("Secure = true, want false")
		}
	})
}

func TestGetSessionCookie_UsesOnlyTheConfiguredName(t *testing.T) {
	for _, tt := range []struct {
		name    string
		devMode bool
		cookies []*http.Cookie
		want    string
	}{
		{name: "production ignores legacy", cookies: []*http.Cookie{{Name: "authgate_session", Value: "injected"}}},
		{name: "production ignores legacy ordered first", cookies: []*http.Cookie{{Name: "authgate_session", Value: "injected"}, {Name: "__Host-authgate_session", Value: "real"}}, want: "real"},
		{name: "development reads legacy", devMode: true, cookies: []*http.Cookie{{Name: "authgate_session", Value: "dev"}}, want: "dev"},
		{name: "development ignores production", devMode: true, cookies: []*http.Cookie{{Name: "__Host-authgate_session", Value: "prod"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			for _, cookie := range tt.cookies {
				req.AddCookie(cookie)
			}
			if got := getSessionCookie(req, tt.devMode); got != tt.want {
				t.Fatalf("cookie value = %q, want %q", got, tt.want)
			}
		})
	}
}
