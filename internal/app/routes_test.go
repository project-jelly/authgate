package app

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/handler"
	"github.com/kangheeyong/authgate/internal/logctx"
	"github.com/kangheeyong/authgate/internal/middleware"
	"github.com/kangheeyong/authgate/internal/pages"
)

func TestAuthorizationResponseIssuer_AppendsIssuerOnlyToClientRedirects(t *testing.T) {
	tests := []struct {
		name       string
		location   string
		wantIssuer bool
	}{
		{
			name:       "successful authorization response",
			location:   "http://localhost/callback?code=code-1&state=state-1",
			wantIssuer: true,
		},
		{
			name:       "error authorization response",
			location:   "http://localhost/callback?error=access_denied&state=state-1",
			wantIssuer: true,
		},
		{
			name:       "internal login redirect",
			location:   "/mcp/login?authRequestID=request-1",
			wantIssuer: false,
		},
		{
			name:       "absolute internal login redirect",
			location:   "https://auth.example.com/mcp/login?authRequestID=request-1",
			wantIssuer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", tt.location)
				w.WriteHeader(http.StatusFound)
			})
			handler := middleware.AuthorizationResponseIssuer("https://auth.example.com", next)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize", nil))

			location, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			got := location.Query().Get("iss")
			if tt.wantIssuer && got != "https://auth.example.com" {
				t.Fatalf("iss = %q, want https://auth.example.com", got)
			}
			if !tt.wantIssuer && got != "" {
				t.Fatalf("internal redirect iss = %q, want empty", got)
			}
		})
	}
}

func rateLimitTestConfig() *config.Config {
	return &config.Config{
		EnableMCP:           true,
		RateLimitAuthRPS:    1,
		RateLimitAuthBurst:  1,
		RateLimitTokenRPS:   1,
		RateLimitTokenBurst: 1,
	}
}

func TestRegisterHealthRoutes_DoesNotExposeMetricsOnPublicMux(t *testing.T) {
	mux := http.NewServeMux()
	registerHealthRoutes(mux, nil, &atomic.Bool{})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /metrics status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func assertRateLimited(t *testing.T, mux http.Handler, method, target string) {
	t.Helper()

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(method, target, nil)
		rec := httptest.NewRecorder()
		panicked := serveHTTPRecovering(mux, rec, req)

		if i == 0 {
			if rec.Code == http.StatusTooManyRequests {
				t.Fatalf("%s %s first request was unexpectedly rate limited", method, target)
			}
			continue
		}
		if panicked {
			t.Fatalf("%s %s second request reached handler instead of being rate limited", method, target)
		}
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("%s %s second request status = %d, want %d", method, target, rec.Code, http.StatusTooManyRequests)
		}
		if got := rec.Header().Get("Retry-After"); got != "1" {
			t.Fatalf("%s %s Retry-After = %q, want 1", method, target, got)
		}
	}
}

func serveHTTPRecovering(h http.Handler, rec *httptest.ResponseRecorder, req *http.Request) (panicked bool) {
	// The first request intentionally consumes a realistic burst token and may
	// reach nil-backed handlers in this route-wiring test. The second request
	// must be rejected by the limiter before any handler code runs.
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	h.ServeHTTP(rec, req)
	return false
}

func TestRegisterProviderRoutes_RateLimitsSensitiveOAuthEndpoints(t *testing.T) {
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/oauth/token"},
		{http.MethodPost, "/oauth/revoke"},
		{http.MethodPost, "/oauth/introspect"},
		{http.MethodPost, "/oauth/device/authorize"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			mux := http.NewServeMux()
			provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			cfg := rateLimitTestConfig()
			registerProviderRoutes(mux, cfg, nil, provider, newRouteLimiters(cfg))

			assertRateLimited(t, mux, tt.method, tt.path)
		})
	}
}

// zitadel/oidc logs a failed grant with the request context. Every token-style
// route must put the client into that context, or the server log cannot say
// which client failed.
func TestRegisterProviderRoutes_TokenEndpointsLogClient(t *testing.T) {
	for _, path := range []string{"/oauth/token", "/oauth/revoke", "/oauth/introspect", "/oauth/device/authorize"} {
		t.Run(path, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(logctx.NewHandler(slog.NewTextHandler(&buf, nil)))
			provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logger.WarnContext(r.Context(), "request error")
				w.WriteHeader(http.StatusBadRequest)
			})
			mux := http.NewServeMux()
			cfg := rateLimitTestConfig()
			registerProviderRoutes(mux, cfg, nil, provider, newRouteLimiters(cfg))

			form := url.Values{"client_id": {"gitea"}, "grant_type": {"authorization_code"}}
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			mux.ServeHTTP(httptest.NewRecorder(), req)

			if got := buf.String(); !strings.Contains(got, "client_id=gitea") {
				t.Fatalf("%s: log line %q is missing client_id", path, got)
			}
		})
	}
}

func TestRegisterAuthgateRoutes_RateLimitsSensitiveAuthgateEndpoints(t *testing.T) {
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/login"},
		{http.MethodGet, "/login/callback"},
		{http.MethodGet, "/mcp/login"},
		{http.MethodGet, "/mcp/callback"},
		{http.MethodGet, "/device"},
		{http.MethodPost, "/device/approve"},
		{http.MethodGet, "/device/auth/callback"},
		{http.MethodGet, "/end_session"},
		{http.MethodPost, "/end_session"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			mux := http.NewServeMux()
			cfg := rateLimitTestConfig()
			registerAuthgateRoutes(
				mux,
				cfg,
				handler.NewLoginHandler(nil, nil, true, pages.Brand{Name: "authgate"}),
				handler.NewDeviceHandler(nil, nil, true, pages.Brand{Name: "authgate"}),
				handler.NewLogoutHandler(nil, nil, true, pages.Brand{Name: "authgate"}),
				handler.NewMCPLoginHandler(nil, nil, true, pages.Brand{Name: "authgate"}),
				newRouteLimiters(cfg),
			)

			assertRateLimited(t, mux, tt.method, tt.path)
		})
	}
}

func TestRegisterProviderRoutes_UserinfoFailsWithoutTokenVerifier(t *testing.T) {
	mux := http.NewServeMux()
	reached := false
	provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })
	cfg := rateLimitTestConfig()
	registerProviderRoutes(mux, cfg, nil, provider, newRouteLimiters(cfg))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/userinfo", nil))
	if rec.Code != http.StatusUnauthorized || reached {
		t.Fatalf("userinfo bypassed access-token adapter: %d, reached=%v", rec.Code, reached)
	}
}
