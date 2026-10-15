package config

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func clearEnv() {
	for _, key := range []string{
		"PORT", "DATABASE_URL", "SESSION_SECRET", "PUBLIC_URL",
		"OIDC_ISSUER_URL", "OIDC_ISSUER_HOST_ALLOWLIST",
		"OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET",
		"OIDC_HTTP_TIMEOUT_SEC",
		"SESSION_TTL", "ACCESS_TOKEN_TTL", "REFRESH_TOKEN_TTL", "REFRESH_TOKEN_REUSE_GRACE_SEC",
		"AUDIT_LOG_PII_RETENTION_DAYS", "ADMIN_AUDIT_LOG_PII_RETENTION_DAYS",
		"DEV_MODE", "ENABLE_MCP", "MCP_CIMD_HOST_ALLOWLIST",
		"PII_ENC_ROOT_KEY_ID", "PII_ENC_ROOT_SECRET",
		"PII_LOOKUP_ROOT_KEY_ID", "PII_LOOKUP_ROOT_SECRET",
		"SIGNING_KEY_PATH", "SIGNING_KEY_BUNDLE_PATH",
		"DB_MAX_OPEN_CONNS", "DB_MAX_IDLE_CONNS",
		"DB_CONN_MAX_LIFETIME_SEC", "DB_CONN_MAX_IDLE_TIME_SEC",
		"HTTP_READ_HEADER_TIMEOUT_SEC", "HTTP_READ_TIMEOUT_SEC",
		"HTTP_WRITE_TIMEOUT_SEC", "HTTP_IDLE_TIMEOUT_SEC",
		"SHUTDOWN_TIMEOUT_SEC", "METRICS_ADDR",
	} {
		os.Unsetenv(key)
	}
}

func setMinimal() {
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "test-secret-32-chars-long-enough!")
	os.Setenv("PUBLIC_URL", "http://localhost:8080")
	os.Setenv("DEV_MODE", "true")
}

func TestLoad_SigningKeyPathSelection(t *testing.T) {
	for _, tc := range []struct {
		name        string
		legacy      string
		bundle      string
		setLegacy   bool
		setBundle   bool
		wantLegacy  string
		wantBundle  string
		wantErrPart string
	}{
		{name: "unset uses legacy default", wantLegacy: "signing_key.pem"},
		{name: "empty legacy uses default", setLegacy: true, wantLegacy: "signing_key.pem"},
		{name: "explicit legacy", setLegacy: true, legacy: "/keys/legacy.pem", wantLegacy: "/keys/legacy.pem"},
		{name: "empty bundle uses legacy default", setBundle: true, wantLegacy: "signing_key.pem"},
		{name: "bundle suppresses legacy default", setBundle: true, bundle: "/keys/bundle.json", wantBundle: "/keys/bundle.json"},
		{name: "empty legacy does not conflict", setLegacy: true, setBundle: true, bundle: "/keys/bundle.json", wantBundle: "/keys/bundle.json"},
		{name: "explicit paths conflict", setLegacy: true, legacy: "/keys/legacy.pem", setBundle: true, bundle: "/keys/bundle.json", wantErrPart: "cannot both be set"},
		{name: "explicit default still conflicts", setLegacy: true, legacy: "signing_key.pem", setBundle: true, bundle: "/keys/bundle.json", wantErrPart: "cannot both be set"},
		{name: "whitespace legacy rejected", setLegacy: true, legacy: " \t", wantErrPart: "SIGNING_KEY_PATH must not contain only whitespace"},
		{name: "whitespace legacy with bundle rejected", setLegacy: true, legacy: " \t", setBundle: true, bundle: "/keys/bundle.json", wantErrPart: "SIGNING_KEY_PATH must not contain only whitespace"},
		{name: "whitespace bundle rejected", setBundle: true, bundle: " \n", wantErrPart: "SIGNING_KEY_BUNDLE_PATH must not contain only whitespace"},
		{name: "nonempty paths are not trimmed", setBundle: true, bundle: " /keys/a bundle.json ", wantBundle: " /keys/a bundle.json "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv()
			t.Cleanup(clearEnv)
			setMinimal()
			if tc.setLegacy {
				t.Setenv("SIGNING_KEY_PATH", tc.legacy)
			}
			if tc.setBundle {
				t.Setenv("SIGNING_KEY_BUNDLE_PATH", tc.bundle)
			}
			cfg, err := Load()
			if tc.wantErrPart != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrPart) {
					t.Fatalf("error = %v, want %q", err, tc.wantErrPart)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.SigningKeyPath != tc.wantLegacy || cfg.SigningKeyBundlePath != tc.wantBundle {
				t.Fatalf("selected paths = %q/%q, want %q/%q", cfg.SigningKeyPath, cfg.SigningKeyBundlePath, tc.wantLegacy, tc.wantBundle)
			}
		})
	}
}

func TestLoad_MissingDatabaseURL(t *testing.T) {
	clearEnv()
	os.Setenv("SESSION_SECRET", "secret")
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "true")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing DATABASE_URL")
	}
}

func TestLoad_MissingSessionSecret(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "true")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing SESSION_SECRET")
	}
}

func TestLoad_MissingPublicURL(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "secret")
	os.Setenv("DEV_MODE", "true")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing PUBLIC_URL")
	}
}

func TestLoad_DevModeFalseRequiresPublicURLHTTPS(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "test-secret-32-chars-long-enough!")
	os.Setenv("PUBLIC_URL", "http://authgate.example.com")
	os.Setenv("DEV_MODE", "false")
	os.Setenv("OIDC_ISSUER_URL", "https://accounts.google.com")
	os.Setenv("OIDC_CLIENT_ID", "id")
	os.Setenv("OIDC_CLIENT_SECRET", "secret")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: DEV_MODE=false requires https:// PUBLIC_URL")
	}
}

func TestLoad_DevModeFalseRequiresHTTPS(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "test-secret-32-chars-long-enough!")
	os.Setenv("PUBLIC_URL", "https://authgate.example.com")
	os.Setenv("DEV_MODE", "false")
	os.Setenv("OIDC_ISSUER_URL", "http://localhost:8082")
	os.Setenv("OIDC_CLIENT_ID", "id")
	os.Setenv("OIDC_CLIENT_SECRET", "secret")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: DEV_MODE=false requires https:// OIDC_ISSUER_URL")
	}
}

func TestLoad_DevModeFalseRequiresOIDCCredentials(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "test-secret-32-chars-long-enough!")
	os.Setenv("PUBLIC_URL", "https://authgate.example.com")
	os.Setenv("DEV_MODE", "false")
	os.Setenv("OIDC_ISSUER_URL", "https://accounts.google.com")
	// Missing OIDC_CLIENT_SECRET

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: DEV_MODE=false requires OIDC credentials")
	}
}

func TestLoad_DevModeFalseRequiresPIIRoots(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "test-secret-32-chars-long-enough!")
	os.Setenv("PUBLIC_URL", "https://authgate.example.com")
	os.Setenv("DEV_MODE", "false")
	os.Setenv("OIDC_ISSUER_URL", "https://accounts.google.com")
	os.Setenv("OIDC_CLIENT_ID", "authgate")
	os.Setenv("OIDC_CLIENT_SECRET", "secret")
	// Missing PII_*_ROOT_* → must fail in production.

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: DEV_MODE=false requires PII encryption roots")
	}
	if !strings.Contains(err.Error(), "PII_ENC_ROOT_KEY_ID") {
		t.Errorf("error = %v, want one mentioning PII roots", err)
	}
}

func TestLoad_RejectsNonBase64RootSecret(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("PII_ENC_ROOT_KEY_ID", "enc-1")
	os.Setenv("PII_ENC_ROOT_SECRET", "not!base64!!!")
	os.Setenv("PII_LOOKUP_ROOT_KEY_ID", "lkp-1")
	os.Setenv("PII_LOOKUP_ROOT_SECRET", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") // 32 bytes

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "PII_ENC_ROOT_SECRET must be base64") {
		t.Fatalf("err = %v, want base64 error for PII_ENC_ROOT_SECRET", err)
	}
}

func TestLoad_RejectsTooShortRootSecret(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("PII_ENC_ROOT_KEY_ID", "enc-1")
	os.Setenv("PII_ENC_ROOT_SECRET", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") // 32 bytes, ok
	os.Setenv("PII_LOOKUP_ROOT_KEY_ID", "lkp-1")
	os.Setenv("PII_LOOKUP_ROOT_SECRET", "c2hvcnQ=") // "short" → 5 bytes

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "PII_LOOKUP_ROOT_SECRET must decode to >=") {
		t.Fatalf("err = %v, want too-short error for PII_LOOKUP_ROOT_SECRET", err)
	}
}

func TestLoad_AcceptsValidRootSecrets(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("PII_ENC_ROOT_KEY_ID", "enc-1")
	os.Setenv("PII_ENC_ROOT_SECRET", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	os.Setenv("PII_LOOKUP_ROOT_KEY_ID", "lkp-1")
	os.Setenv("PII_LOOKUP_ROOT_SECRET", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")

	if _, err := Load(); err != nil {
		t.Fatalf("valid root secrets rejected: %v", err)
	}
}

func TestLoad_Defaults(t *testing.T) {
	clearEnv()
	setMinimal()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.OIDCIssuerURL != "http://localhost:8082" {
		t.Errorf("OIDCIssuerURL = %q, want http://localhost:8082", cfg.OIDCIssuerURL)
	}
	if cfg.OIDCHTTPTimeout.Seconds() != 10 {
		t.Errorf("OIDCHTTPTimeout = %v, want 10s", cfg.OIDCHTTPTimeout)
	}
	if cfg.OIDCClientID != "authgate" {
		t.Errorf("OIDCClientID = %q, want authgate", cfg.OIDCClientID)
	}
	if cfg.SessionTTL.Seconds() != 86400 {
		t.Errorf("SessionTTL = %v, want 86400s", cfg.SessionTTL)
	}
	if cfg.AccessTokenTTL.Seconds() != 900 {
		t.Errorf("AccessTokenTTL = %v, want 900s", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL.Seconds() != 2592000 {
		t.Errorf("RefreshTokenTTL = %v, want 2592000s", cfg.RefreshTokenTTL)
	}
	if cfg.RefreshTokenReuseGrace.Seconds() != 5 {
		t.Errorf("RefreshTokenReuseGrace = %v, want 5s", cfg.RefreshTokenReuseGrace)
	}
	if cfg.AuditLogPIIRetention.Hours() != 90*24 {
		t.Errorf("AuditLogPIIRetention = %v, want 90 days", cfg.AuditLogPIIRetention)
	}
	if cfg.AdminAuditLogPIIRetention.Hours() != 730*24 {
		t.Errorf("AdminAuditLogPIIRetention = %v, want 730 days", cfg.AdminAuditLogPIIRetention)
	}
	if cfg.SigningKeyPath != "signing_key.pem" {
		t.Errorf("SigningKeyPath = %q, want signing_key.pem", cfg.SigningKeyPath)
	}
	if !cfg.EnableMCP {
		t.Error("EnableMCP = false, want true by default")
	}
	if cfg.HTTPReadHeaderTimeout.Seconds() != 5 {
		t.Errorf("HTTPReadHeaderTimeout = %v, want 5s", cfg.HTTPReadHeaderTimeout)
	}
	if cfg.HTTPReadTimeout.Seconds() != 15 {
		t.Errorf("HTTPReadTimeout = %v, want 15s", cfg.HTTPReadTimeout)
	}
	if cfg.HTTPWriteTimeout.Seconds() != 30 {
		t.Errorf("HTTPWriteTimeout = %v, want 30s", cfg.HTTPWriteTimeout)
	}
	if cfg.HTTPIdleTimeout.Seconds() != 60 {
		t.Errorf("HTTPIdleTimeout = %v, want 60s", cfg.HTTPIdleTimeout)
	}
	if cfg.ShutdownTimeout.Seconds() != 10 {
		t.Errorf("ShutdownTimeout = %v, want 10s", cfg.ShutdownTimeout)
	}
	if cfg.MetricsAddr != "" {
		t.Errorf("MetricsAddr = %q, want empty default", cfg.MetricsAddr)
	}
	if cfg.DBMaxOpenConns != 25 {
		t.Errorf("DBMaxOpenConns = %d, want 25", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != 25 {
		t.Errorf("DBMaxIdleConns = %d, want 25", cfg.DBMaxIdleConns)
	}
	if cfg.DBConnMaxLifetime.Seconds() != 300 {
		t.Errorf("DBConnMaxLifetime = %v, want 300s", cfg.DBConnMaxLifetime)
	}
	if cfg.DBConnMaxIdleTime.Seconds() != 120 {
		t.Errorf("DBConnMaxIdleTime = %v, want 120s", cfg.DBConnMaxIdleTime)
	}
}

func TestLoad_MetricsAddrOptIn(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("METRICS_ADDR", "127.0.0.1:9090")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MetricsAddr != "127.0.0.1:9090" {
		t.Fatalf("MetricsAddr = %q, want 127.0.0.1:9090", cfg.MetricsAddr)
	}
}

func TestLoad_InvalidMetricsAddrFails(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("METRICS_ADDR", "127.0.0.1")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid METRICS_ADDR")
	}
	if !strings.Contains(err.Error(), "METRICS_ADDR") {
		t.Errorf("error = %v, want one mentioning METRICS_ADDR", err)
	}
}

func TestLoad_InvalidNumericEnvFails(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("PORT", "not-a-number")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid PORT")
	}
	if !strings.Contains(err.Error(), "PORT") {
		t.Errorf("error = %v, want one mentioning PORT", err)
	}
}

func TestLoad_InvalidBoolEnvFails(t *testing.T) {
	for _, key := range []string{"ENABLE_MCP"} {
		t.Run(key, func(t *testing.T) {
			clearEnv()
			setMinimal()
			os.Setenv(key, "sometimes")

			_, err := Load()
			if err == nil {
				t.Fatalf("expected error for invalid %s", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error = %v, want one mentioning %s", err, key)
			}
		})
	}
}

func TestLoad_AuditLogPIIRetentionMinimum(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("AUDIT_LOG_PII_RETENTION_DAYS", "29")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for short audit log PII retention")
	}
	if !strings.Contains(err.Error(), "AUDIT_LOG_PII_RETENTION_DAYS") {
		t.Errorf("error = %v, want one mentioning AUDIT_LOG_PII_RETENTION_DAYS", err)
	}
}

// Operator actions are the statutory access records, so their retention floor
// stays at one year even though end-user activity may be anonymized sooner.
func TestLoad_AdminAuditLogPIIRetentionMinimum(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("ADMIN_AUDIT_LOG_PII_RETENTION_DAYS", "364")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for short admin audit log PII retention")
	}
	if !strings.Contains(err.Error(), "ADMIN_AUDIT_LOG_PII_RETENTION_DAYS") {
		t.Errorf("error = %v, want one mentioning ADMIN_AUDIT_LOG_PII_RETENTION_DAYS", err)
	}
}

// End-user activity may be anonymized well below the statutory floor that
// applies to operator records; 30 days is the accepted minimum.
func TestLoad_AuditLogPIIRetentionAllowsShortUserWindow(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("AUDIT_LOG_PII_RETENTION_DAYS", "30")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AuditLogPIIRetention.Hours() != 30*24 {
		t.Errorf("AuditLogPIIRetention = %v, want 30 days", cfg.AuditLogPIIRetention)
	}
}

func TestLoad_OIDCIssuerHostAllowlist_Match(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("OIDC_ISSUER_URL", "https://accounts.google.com")
	os.Setenv("OIDC_ISSUER_HOST_ALLOWLIST", "accounts.google.com,login.microsoftonline.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.OIDCIssuerHostAllowlist; len(got) != 2 || got[0] != "accounts.google.com" || got[1] != "login.microsoftonline.com" {
		t.Errorf("OIDCIssuerHostAllowlist = %v, want [accounts.google.com login.microsoftonline.com]", got)
	}
}

func TestLoad_OIDCIssuerHostAllowlist_Mismatch(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("OIDC_ISSUER_URL", "https://attacker.example.com")
	os.Setenv("OIDC_ISSUER_HOST_ALLOWLIST", "accounts.google.com")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: issuer host not in allowlist")
	}
	if !strings.Contains(err.Error(), "OIDC_ISSUER_HOST_ALLOWLIST") {
		t.Errorf("error = %v, want one mentioning OIDC_ISSUER_HOST_ALLOWLIST", err)
	}
}

func TestLoad_OIDCIssuerHostAllowlist_EmptyDisablesCheck(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("OIDC_ISSUER_URL", "https://anything.example.com")
	// OIDC_ISSUER_HOST_ALLOWLIST unset

	cfg, err := Load()
	if err != nil {
		t.Fatalf("empty allowlist should not enforce: %v", err)
	}
	if len(cfg.OIDCIssuerHostAllowlist) != 0 {
		t.Errorf("OIDCIssuerHostAllowlist = %v, want empty", cfg.OIDCIssuerHostAllowlist)
	}
}

func TestLoad_DevModeFalseShortSessionSecret(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "short") // < 32 chars
	os.Setenv("PUBLIC_URL", "https://authgate.example.com")
	os.Setenv("DEV_MODE", "false")
	os.Setenv("OIDC_ISSUER_URL", "https://accounts.google.com")
	os.Setenv("OIDC_CLIENT_ID", "id")
	os.Setenv("OIDC_CLIENT_SECRET", "secret")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: SESSION_SECRET < 32 chars in production")
	}
}

func TestLoad_DevModeTrueAllowsShortSecret(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "short")
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "true")

	_, err := Load()
	if err != nil {
		t.Fatalf("dev mode should allow short secret: %v", err)
	}
}

func TestLoad_Success(t *testing.T) {
	clearEnv()
	setMinimal()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.DevMode {
		t.Error("DevMode should be true")
	}
}

func TestLoad_EnableMCPFalse(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("ENABLE_MCP", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EnableMCP {
		t.Fatal("EnableMCP should be false")
	}
}

func TestLoad_HTTPTimeoutsFromEnv(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("HTTP_READ_HEADER_TIMEOUT_SEC", "7")
	os.Setenv("HTTP_READ_TIMEOUT_SEC", "20")
	os.Setenv("HTTP_WRITE_TIMEOUT_SEC", "40")
	os.Setenv("HTTP_IDLE_TIMEOUT_SEC", "120")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.HTTPReadHeaderTimeout.Seconds() != 7 {
		t.Errorf("HTTPReadHeaderTimeout = %v, want 7s", cfg.HTTPReadHeaderTimeout)
	}
	if cfg.HTTPReadTimeout.Seconds() != 20 {
		t.Errorf("HTTPReadTimeout = %v, want 20s", cfg.HTTPReadTimeout)
	}
	if cfg.HTTPWriteTimeout.Seconds() != 40 {
		t.Errorf("HTTPWriteTimeout = %v, want 40s", cfg.HTTPWriteTimeout)
	}
	if cfg.HTTPIdleTimeout.Seconds() != 120 {
		t.Errorf("HTTPIdleTimeout = %v, want 120s", cfg.HTTPIdleTimeout)
	}
}

func TestLoad_OIDCHTTPTimeoutFromEnv(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("OIDC_HTTP_TIMEOUT_SEC", "25")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OIDCHTTPTimeout.Seconds() != 25 {
		t.Errorf("OIDCHTTPTimeout = %v, want 25s", cfg.OIDCHTTPTimeout)
	}
}

func TestLoad_OIDCHTTPTimeoutInvalid(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("OIDC_HTTP_TIMEOUT_SEC", "0")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: OIDC_HTTP_TIMEOUT_SEC must be > 0")
	}
}

func TestLoad_ShutdownTimeoutFromEnv(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("SHUTDOWN_TIMEOUT_SEC", "20")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ShutdownTimeout.Seconds() != 20 {
		t.Errorf("ShutdownTimeout = %v, want 20s", cfg.ShutdownTimeout)
	}
}

func TestLoad_ShutdownTimeoutInvalid(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("SHUTDOWN_TIMEOUT_SEC", "0")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: SHUTDOWN_TIMEOUT_SEC must be > 0")
	}
}

func TestLoad_DBPoolFromEnv(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("DB_MAX_OPEN_CONNS", "40")
	os.Setenv("DB_MAX_IDLE_CONNS", "12")
	os.Setenv("DB_CONN_MAX_LIFETIME_SEC", "600")
	os.Setenv("DB_CONN_MAX_IDLE_TIME_SEC", "90")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DBMaxOpenConns != 40 {
		t.Errorf("DBMaxOpenConns = %d, want 40", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != 12 {
		t.Errorf("DBMaxIdleConns = %d, want 12", cfg.DBMaxIdleConns)
	}
	if cfg.DBConnMaxLifetime.Seconds() != 600 {
		t.Errorf("DBConnMaxLifetime = %v, want 600s", cfg.DBConnMaxLifetime)
	}
	if cfg.DBConnMaxIdleTime.Seconds() != 90 {
		t.Errorf("DBConnMaxIdleTime = %v, want 90s", cfg.DBConnMaxIdleTime)
	}
}

func TestLoad_DBPoolClampIdleToOpen(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("DB_MAX_OPEN_CONNS", "10")
	os.Setenv("DB_MAX_IDLE_CONNS", "30")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DBMaxIdleConns != 10 {
		t.Errorf("DBMaxIdleConns = %d, want clamped 10", cfg.DBMaxIdleConns)
	}
}

// setValidProd sets a complete, valid DEV_MODE=false environment so Load()
// succeeds; individual tests then tweak one variable.
func setValidProd() {
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "test-secret-32-chars-long-enough!")
	os.Setenv("PUBLIC_URL", "https://auth.example.com")
	os.Setenv("OIDC_ISSUER_URL", "https://accounts.google.com")
	os.Setenv("OIDC_CLIENT_ID", "authgate")
	os.Setenv("OIDC_CLIENT_SECRET", "secret")
	os.Setenv("PII_ENC_ROOT_KEY_ID", "enc-1")
	os.Setenv("PII_ENC_ROOT_SECRET", "ISA5aviCx54GVBxSHvU8nqcYwC5JKOj5OFUj7uwzuUA=")
	os.Setenv("PII_LOOKUP_ROOT_KEY_ID", "lookup-1")
	os.Setenv("PII_LOOKUP_ROOT_SECRET", "/lXaqOM5dvoYzptzzEJ5oF3n+OyEQ/etgXmCDb5bJLI=")
	os.Setenv("DEV_MODE", "false")
}

func captureWarnLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestLoad_ProdEmptyAllowlist_Warns(t *testing.T) {
	clearEnv()
	setValidProd()
	// OIDC_ISSUER_HOST_ALLOWLIST unset

	logs := captureWarnLogs(t)
	if _, err := Load(); err != nil {
		t.Fatalf("valid prod config with empty allowlist should load: %v", err)
	}
	if !strings.Contains(logs.String(), "OIDC_ISSUER_HOST_ALLOWLIST is empty") {
		t.Errorf("expected empty-allowlist warning in production; logs = %q", logs.String())
	}
}

func TestLoad_ProdWithAllowlist_NoWarn(t *testing.T) {
	clearEnv()
	setValidProd()
	os.Setenv("OIDC_ISSUER_HOST_ALLOWLIST", "accounts.google.com")

	logs := captureWarnLogs(t)
	if _, err := Load(); err != nil {
		t.Fatalf("valid prod config with allowlist should load: %v", err)
	}
	if strings.Contains(logs.String(), "OIDC_ISSUER_HOST_ALLOWLIST is empty") {
		t.Errorf("did not expect empty-allowlist warning when allowlist set; logs = %q", logs.String())
	}
}

func TestLoad_DevModeEmptyAllowlist_NoWarn(t *testing.T) {
	clearEnv()
	setMinimal() // DEV_MODE=true
	os.Setenv("OIDC_ISSUER_URL", "https://accounts.google.com")

	logs := captureWarnLogs(t)
	if _, err := Load(); err != nil {
		t.Fatalf("dev config should load: %v", err)
	}
	if strings.Contains(logs.String(), "OIDC_ISSUER_HOST_ALLOWLIST is empty") {
		t.Errorf("dev mode should not warn about allowlist; logs = %q", logs.String())
	}
}

func TestLoad_RefreshTokenReuseGraceBounds(t *testing.T) {
	for _, tc := range []struct {
		value   string
		wantErr bool
	}{
		{"0", false},
		{"60", false},
		{"-1", true},
		{"61", true},
		{"abc", true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			clearEnv()
			setMinimal()
			os.Setenv("REFRESH_TOKEN_REUSE_GRACE_SEC", tc.value)

			_, err := Load()
			if tc.wantErr && err == nil {
				t.Fatalf("REFRESH_TOKEN_REUSE_GRACE_SEC=%s: expected an error", tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("REFRESH_TOKEN_REUSE_GRACE_SEC=%s: unexpected error %v", tc.value, err)
			}
			if err != nil && !strings.Contains(err.Error(), "REFRESH_TOKEN_REUSE_GRACE_SEC") {
				t.Errorf("error = %v, want one mentioning REFRESH_TOKEN_REUSE_GRACE_SEC", err)
			}
		})
	}
}

func TestLoad_MCPCIMDHostAllowlist(t *testing.T) {
	clearEnv()
	setMinimal()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MCPCIMDHostAllowlist != nil {
		t.Errorf("unset MCPCIMDHostAllowlist = %v, want nil (built-in default)", cfg.MCPCIMDHostAllowlist)
	}

	os.Setenv("MCP_CIMD_HOST_ALLOWLIST", " claude.ai , chatgpt.com ,")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.MCPCIMDHostAllowlist; len(got) != 2 || got[0] != "claude.ai" || got[1] != "chatgpt.com" {
		t.Errorf("MCPCIMDHostAllowlist = %v, want [claude.ai chatgpt.com]", got)
	}
}
