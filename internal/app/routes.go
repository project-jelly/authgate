package app

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/time/rate"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/handler"
	"github.com/kangheeyong/authgate/internal/middleware"
	"github.com/kangheeyong/authgate/internal/storage"
)

func registerRoutes(
	mux *http.ServeMux,
	cfg *config.Config,
	db *sql.DB,
	store *storage.Storage,
	provider op.OpenIDProvider,
	loginHandler *handler.LoginHandler,
	deviceHandler *handler.DeviceHandler,
	logoutHandler *handler.LogoutHandler,
	mcpLoginHandler *handler.MCPLoginHandler,
	isShuttingDown *atomic.Bool,
) {
	// Build the per-IP rate limiters once and share them across both route
	// groups. Building them per-registrar would give each group its own bucket
	// map, so a single IP would get the configured burst separately on, e.g.,
	// /authorize (provider) and /login (authgate) — silently doubling the
	// effective limit and spawning duplicate cleanup goroutines.
	lim := newRouteLimiters(cfg)

	registerOAuthMetadataRoutes(mux, cfg, provider, store)
	registerProviderRoutes(mux, cfg, store, provider, lim)
	registerAuthgateRoutes(mux, cfg, loginHandler, deviceHandler, logoutHandler, mcpLoginHandler, lim)
	registerHealthRoutes(mux, db, isShuttingDown)
}

// routeLimiters holds the shared rate-limiting middlewares: strict for token
// endpoints, moderate for auth/login endpoints.
type routeLimiters struct {
	token func(http.Handler) http.Handler
	auth  func(http.Handler) http.Handler
}

func newRouteLimiters(cfg *config.Config) routeLimiters {
	return routeLimiters{
		token: middleware.NewRateLimiter(rate.Limit(cfg.RateLimitTokenRPS), cfg.RateLimitTokenBurst),
		auth:  middleware.NewRateLimiter(rate.Limit(cfg.RateLimitAuthRPS), cfg.RateLimitAuthBurst),
	}
}

func registerProviderRoutes(mux *http.ServeMux, cfg *config.Config, store *storage.Storage, provider http.Handler, lim routeLimiters) {
	tokenLimiter, authLimiter := lim.token, lim.auth
	provider = storage.WrapVerifiedAccessToken(provider, cfg.PublicURL)

	authorize := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource, err := storage.ResourceFromRequestStrict(r)
		if err != nil {
			writeInvalidTargetError(w, err)
			return
		}
		provider.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	})
	mux.Handle("/authorize", authLimiter(middleware.AuthorizationResponseIssuer(cfg.PublicURL, authorize)))
	mux.Handle("/authorize/callback", middleware.AuthorizationResponseIssuer(cfg.PublicURL, provider))
	tokenWithAtJWT := middleware.WrapAccessTokenJWTType(provider, store)
	mux.Handle("/oauth/token", middleware.NoStore(tokenLimiter(middleware.TokenLogContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource, err := storage.ResourceFromRequestStrict(r)
		if err != nil {
			writeInvalidTargetError(w, err)
			return
		}
		tokenWithAtJWT.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	})))))
	mux.Handle("/oauth/revoke", tokenLimiter(middleware.TokenLogContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.EnableMCP {
			provider.ServeHTTP(w, r)
			return
		}
		if err := r.ParseForm(); err == nil {
			clientID := strings.TrimSpace(r.Form.Get("client_id"))
			if oauthclient.IsCIMDClientID(clientID) {
				if _, err := store.GetClientByClientID(r.Context(), clientID); err != nil {
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}
		provider.ServeHTTP(w, r)
	}))))
	mux.Handle("/oauth/introspect", tokenLimiter(middleware.TokenLogContext(provider)))
	mux.Handle("/oauth/device/authorize", tokenLimiter(middleware.TokenLogContext(provider)))
	mux.Handle("/", provider)
}

func registerAuthgateRoutes(
	mux *http.ServeMux,
	cfg *config.Config,
	loginHandler *handler.LoginHandler,
	deviceHandler *handler.DeviceHandler,
	logoutHandler *handler.LogoutHandler,
	mcpLoginHandler *handler.MCPLoginHandler,
	lim routeLimiters,
) {
	tokenLimiter, authLimiter := lim.token, lim.auth

	mux.Handle("/login", authLimiter(http.HandlerFunc(loginHandler.HandleLogin)))
	mux.Handle("/login/callback", authLimiter(http.HandlerFunc(loginHandler.HandleCallback)))
	if cfg.EnableMCP {
		mux.Handle("/mcp/login", authLimiter(http.HandlerFunc(mcpLoginHandler.HandleLogin)))
		mux.Handle("/mcp/callback", authLimiter(http.HandlerFunc(mcpLoginHandler.HandleCallback)))
	}
	mux.Handle("/device", authLimiter(http.HandlerFunc(deviceHandler.HandleDevicePage)))
	mux.Handle("/device/approve", tokenLimiter(http.HandlerFunc(deviceHandler.HandleDeviceApprove)))
	mux.Handle("/device/auth/callback", authLimiter(http.HandlerFunc(deviceHandler.HandleDeviceCallback)))
	// Takes precedence over the provider catch-all: zitadel's own end_session
	// cannot end a session without id_token_hint, never clears the session
	// cookie and never asks the user to confirm.
	mux.Handle("/end_session", authLimiter(http.HandlerFunc(logoutHandler.HandleEndSession)))
}

func registerHealthRoutes(mux *http.ServeMux, db *sql.DB, isShuttingDown *atomic.Bool) {
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if isShuttingDown.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"shutting down"}`))
			return
		}
		if err := db.PingContext(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not ready"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
}

// writeInvalidTargetError writes the canonical OAuth invalid_target error
// JSON body for HTTP-layer rejections (e.g. duplicate resource params per
// authgate's single-audience policy under RFC 8707 §2.2).
func writeInvalidTargetError(w http.ResponseWriter, cause error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "invalid_target",
		"error_description": cause.Error(),
	})
}
