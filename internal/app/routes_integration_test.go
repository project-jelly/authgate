//go:build integration

package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/integration"
	"github.com/kangheeyong/authgate/internal/storage"
)

// Use the actual app registration with a real provider and storage. The
// integration helper's separate route assembly must not hide a wiring bypass.
func TestProviderRoutes_UserinfoWithRealProvider(t *testing.T) {
	ts := integration.SetupTestServer(t)
	ctx := context.Background()
	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "route@test.example", EmailVerified: true, Name: "Route", Provider: "google", ProviderUserID: "route-sub"})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := op.NewProvider(&op.Config{CryptoKey: sha256.Sum256([]byte("route-test-encryption"))}, ts.Store, op.StaticIssuer(ts.BaseURL), op.WithAllowInsecure())
	if err != nil {
		t.Fatal(err)
	}
	cfg := rateLimitTestConfig()
	cfg.PublicURL = ts.BaseURL
	mux := http.NewServeMux()
	registerProviderRoutes(mux, cfg, ts.Store, provider, newRouteLimiters(cfg))
	claims := oidc.NewAccessTokenClaims(ts.BaseURL, user.ID, []string{"test-client"}, time.Now().Add(time.Minute), "route-jti", "test-client", 0)
	claims.Scopes = []string{"openid"}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ts.Store.SigningKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"at+jwt", "JWT"} {
		t.Run(typ, func(t *testing.T) {
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: key.SignatureAlgorithm(), Key: &jose.JSONWebKey{Key: key.Key(), KeyID: key.ID()}}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			token, err := signed.CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if typ == "JWT" {
				if rec.Code != 401 {
					t.Fatalf("ID-token type status %d", rec.Code)
				}
				return
			}
			var info map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
				t.Fatalf("userinfo %d: %s", rec.Code, rec.Body.String())
			}
			if rec.Code != 200 || info["sub"] != user.ID || len(info) != 1 {
				t.Fatalf("userinfo status=%d claims=%v", rec.Code, info)
			}
		})
	}
}

func TestProviderRoutes_TokenResponsesAreNotCacheable(t *testing.T) {
	ts := integration.SetupTestServer(t)
	// Token verification uses wall time; issuance and persisted grants must
	// use the same current time rather than the harness's fixed past date.
	ts.Clock.T = time.Now().UTC()
	ctx := context.Background()
	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email: "cache@test.example", EmailVerified: true, Name: "Token Cache",
		Provider: "google", ProviderUserID: "cache-sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := rateLimitTestConfig()
	cfg.PublicURL, cfg.DevMode = ts.BaseURL, true
	cfg.RateLimitTokenRPS, cfg.RateLimitTokenBurst = 1000, 100
	provider, err := op.NewProvider(buildOPConfig(cfg), ts.Store, op.StaticIssuer(cfg.PublicURL), buildOPOptions(cfg)...)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerRoutes(mux, cfg, ts.DB, ts.Store, provider, nil, nil, nil, nil, &atomic.Bool{})
	post := func(target http.Handler, form url.Values, wantStatus int, wantError string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		target.ServeHTTP(rec, req)
		if rec.Code != wantStatus {
			t.Fatalf("token status = %d, want %d: %s", rec.Code, wantStatus, rec.Body.String())
		}
		for name, want := range map[string]string{"Cache-Control": "no-store", "Pragma": "no-cache"} {
			if got := rec.Header().Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if wantError != "" && body["error"] != wantError {
			t.Fatalf("token error = %v, want %s", body["error"], wantError)
		}
		if wantStatus == http.StatusOK {
			token, _ := body["access_token"].(string)
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Fatalf("missing JWT access token: %v", body)
			}
			headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				t.Fatal(err)
			}
			var header map[string]any
			if err := json.Unmarshal(headerJSON, &header); err != nil {
				t.Fatal(err)
			}
			if header["typ"] != "at+jwt" {
				t.Fatalf("token rewrite was bypassed: %v", header)
			}
		}
		return body
	}

	// Seed approved credentials through Storage, then redeem them at the
	// actual production route. The response must pass through the real
	// provider, grant transaction and at+jwt/at_hash response adapter.
	verifier := strings.Repeat("v", 43)
	challenge := sha256.Sum256([]byte(verifier))
	request, err := ts.Store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: "test-client", RedirectURI: ts.BaseURL + "/callback", ResponseType: oidc.ResponseTypeCode,
		Scopes: []string{"openid", "offline_access"}, CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]),
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Store.CompleteAuthRequest(ctx, request.GetID(), user.ID, ts.Clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ts.Store.SaveAuthCode(ctx, request.GetID(), "cache-code"); err != nil {
		t.Fatal(err)
	}
	codeForm := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"test-client"}, "code": {"cache-code"},
		"redirect_uri": {ts.BaseURL + "/callback"}, "code_verifier": {verifier},
	}
	tokens := post(mux, codeForm, http.StatusOK, "")
	refreshToken, _ := tokens["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("code exchange omitted refresh token")
	}
	post(mux, url.Values{"grant_type": {"refresh_token"}, "client_id": {"test-client"}, "refresh_token": {refreshToken}}, http.StatusOK, "")
	if err := ts.Store.StoreDeviceAuthorization(ctx, "test-client", "cache-device", "CACH-CODE", ts.Clock.Now().Add(time.Minute), []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	if err := ts.Store.ApproveDeviceCode(ctx, "CACH-CODE", user.ID, ts.Clock.Now()); err != nil {
		t.Fatal(err)
	}
	post(mux, url.Values{"grant_type": {string(oidc.GrantTypeDeviceCode)}, "client_id": {"test-client"}, "device_code": {"cache-device"}}, http.StatusOK, "")

	// Provider errors and app-owned early rejections share the same policy.
	post(mux, nil, http.StatusBadRequest, "invalid_request")
	post(mux, url.Values{"resource": {"https://api.example/one", "https://api.example/two"}}, http.StatusBadRequest, "invalid_target")
	cfg.RateLimitTokenRPS, cfg.RateLimitTokenBurst = 0, 1
	limited := http.NewServeMux()
	registerProviderRoutes(limited, cfg, ts.Store, provider, newRouteLimiters(cfg))
	post(limited, nil, http.StatusBadRequest, "invalid_request")
	post(limited, nil, http.StatusTooManyRequests, "rate_limit_exceeded")
}
