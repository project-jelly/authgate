package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/storage"
)

type appBundleKey struct {
	key *rsa.PrivateKey
	kid string
}

func newAppBundleKey(t *testing.T) appBundleKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := (&jose.JSONWebKey{Key: &key.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return appBundleKey{key: key, kid: base64.RawURLEncoding.EncodeToString(thumbprint)}
}

func appBundlePath(t *testing.T, active, archived appBundleKey) string {
	t.Helper()
	publicJWK := func(key appBundleKey) jose.JSONWebKey {
		return jose.JSONWebKey{Key: &key.key.PublicKey, KeyID: key.kid, Algorithm: "RS256", Use: "sig"}
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(active.key)})
	data, err := json.Marshal(map[string]any{
		"schema_version":         1,
		"revision":               "app-wiring-test",
		"active_kid":             active.kid,
		"active_private_key_pem": string(privatePEM),
		"verification_keys": []map[string]any{
			{"jwk": publicJWK(active), "publish": true},
			{"jwk": publicJWK(archived), "publish": false},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing-keys.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func appSigningStore() *storage.Storage {
	return storage.New(nil, clock.RealClock{}, idgen.CryptoGenerator{}, nil, 15*time.Minute, 24*time.Hour)
}

func captureAppSigningLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func TestConfigureSigningKey_LegacyPreservesKeyAndHintDefaults(t *testing.T) {
	cfg := &config.Config{
		PublicURL: "https://auth.example.test", SessionSecret: "test-secret-32-chars-long-enough!",
		SigningKeyPath: filepath.Join(t.TempDir(), "legacy.pem"),
	}
	store := appSigningStore()
	if err := configureSigningKey(cfg, store); err != nil {
		t.Fatal(err)
	}
	first, err := store.SigningKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != "authgate-key-1" || store.IDTokenHintKeySet() != nil {
		t.Fatal("legacy signing key ID or default hint verifier changed")
	}
	restarted := appSigningStore()
	if err := configureSigningKey(cfg, restarted); err != nil {
		t.Fatal(err)
	}
	second, err := restarted.SigningKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Key().(*rsa.PrivateKey).N.Cmp(second.Key().(*rsa.PrivateKey).N) != 0 {
		t.Fatal("legacy restart generated a different key")
	}
	provider, err := buildOIDCProvider(cfg, restarted)
	if err != nil {
		t.Fatal(err)
	}
	ctx := op.ContextWithIssuer(context.Background(), cfg.PublicURL)
	verifier := provider.IDTokenHintVerifier(ctx)
	if len(verifier.SupportedSignAlgs) != 0 {
		t.Fatal("bundle-only hint algorithm option changed legacy provider defaults")
	}
	raw := appExpiredHint(t, cfg.PublicURL, second.Key().(*rsa.PrivateKey), second.ID(), jose.RS256)
	claims, err := op.VerifyIDTokenHint[*oidc.IDTokenClaims](ctx, raw, verifier)
	var expired op.IDTokenHintExpiredError
	if !errors.As(err, &expired) || claims == nil || claims.Subject != "test-user" {
		t.Fatalf("legacy provider lost expired hint compatibility: %v", err)
	}
}

func TestConfigureSigningKey_BundleErrorsDoNotConfigureFallback(t *testing.T) {
	directory := t.TempDir()
	malformed := filepath.Join(directory, "malformed.json")
	if err := os.WriteFile(malformed, []byte("not a bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  config.Config
	}{
		{"missing bundle", config.Config{SigningKeyBundlePath: filepath.Join(directory, "missing.json")}},
		{"malformed bundle", config.Config{SigningKeyBundlePath: malformed}},
		{"directory", config.Config{SigningKeyBundlePath: directory}},
		{"conflicting paths", config.Config{SigningKeyPath: filepath.Join(directory, "unused.pem"), SigningKeyBundlePath: malformed}},
		{"whitespace bundle", config.Config{SigningKeyBundlePath: " \t"}},
		{"whitespace legacy", config.Config{SigningKeyPath: " \t"}},
		{"no path", config.Config{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := appSigningStore()
			if err := configureSigningKey(&tc.cfg, store); err == nil {
				t.Fatal("invalid key configuration was accepted")
			}
			if _, err := store.SigningKey(context.Background()); err == nil {
				t.Fatal("invalid bundle configured a fallback signing key")
			}
		})
	}
	if _, err := os.Stat(filepath.Join(directory, "unused.pem")); !os.IsNotExist(err) {
		t.Fatalf("conflicting configuration touched the legacy path: %v", err)
	}
}

func TestSigningKeyHistoryWarningBoundary(t *testing.T) {
	logs := captureAppSigningLogs(t)
	warnSigningKeyHistory(95)
	if logs.Len() != 0 {
		t.Fatal("warned below the history threshold")
	}
	warnSigningKeyHistory(96)
	warnSigningKeyHistory(128)
	if strings.Count(logs.String(), `"level":"WARN"`) != 2 || !strings.Contains(logs.String(), `"key_limit":128`) {
		t.Fatalf("history capacity warnings missing: %s", logs.String())
	}
}

func TestBuildOIDCProvider_BundleWiresArchivedHintKeys(t *testing.T) {
	active, archived := newAppBundleKey(t), newAppBundleKey(t)
	path := appBundlePath(t, active, archived)
	cfg := &config.Config{
		PublicURL: "https://auth.example.test", SessionSecret: "test-secret-32-chars-long-enough!",
		SigningKeyBundlePath: path,
	}
	store := appSigningStore()
	logs := captureAppSigningLogs(t)
	if err := configureSigningKey(cfg, store); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "app-wiring-test") || !strings.Contains(logs.String(), active.kid) ||
		strings.Contains(logs.String(), "PRIVATE KEY") || strings.Contains(logs.String(), "active_private_key_pem") {
		t.Fatalf("bundle startup metadata is missing or includes private material: %s", logs.String())
	}
	provider, err := buildOIDCProvider(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := op.ContextWithIssuer(context.Background(), cfg.PublicURL)
	verifier := provider.IDTokenHintVerifier(ctx)
	if len(verifier.SupportedSignAlgs) != 1 || verifier.SupportedSignAlgs[0] != "RS256" {
		t.Fatalf("hint algorithms = %v, want explicit RS256", verifier.SupportedSignAlgs)
	}
	for _, tc := range []struct {
		name string
		key  appBundleKey
		kid  string
		alg  jose.SignatureAlgorithm
		ok   bool
	}{
		{"archived expired hint", archived, archived.kid, jose.RS256, true},
		{"active expired hint", active, active.kid, jose.RS256, true},
		{"unknown kid", archived, "unknown", jose.RS256, false},
		{"missing kid", archived, "", jose.RS256, false},
		{"wrong key for known kid", active, archived.kid, jose.RS256, false},
		{"unsupported algorithm", archived, archived.kid, jose.RS512, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := appExpiredHint(t, cfg.PublicURL, tc.key.key, tc.kid, tc.alg)
			claims, err := op.VerifyIDTokenHint[*oidc.IDTokenClaims](ctx, raw, verifier)
			var expired op.IDTokenHintExpiredError
			if tc.ok {
				if !errors.As(err, &expired) || claims == nil || claims.Subject != "test-user" {
					t.Fatalf("hint did not pass signature verification before expiry: claims=%v, error=%v", claims, err)
				}
			} else if err == nil || errors.As(err, &expired) {
				t.Fatalf("invalid hint reached expiry acceptance: %v", err)
			}
		})
	}
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, cfg.PublicURL+"/keys", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("JWKS status = %d", rec.Code)
	}
	var published jose.JSONWebKeySet
	if err := json.Unmarshal(rec.Body.Bytes(), &published); err != nil {
		t.Fatal(err)
	}
	if len(published.Keys) != 1 || published.Keys[0].KeyID != active.kid || !published.Keys[0].IsPublic() {
		t.Fatal("provider JWKS exposed an archived or private key")
	}
	keys, err := store.KeySet(ctx)
	if err != nil || len(keys) != 1 || keys[0].ID() != active.kid {
		t.Fatalf("access verification key set includes archived keys: %v", err)
	}
}

func appExpiredHint(t *testing.T, issuer string, key *rsa.PrivateKey, kid string, alg jose.SignatureAlgorithm) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": issuer, "sub": "test-user", "aud": "test-client",
		"iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix(),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
