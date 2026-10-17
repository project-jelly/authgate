//go:build integration

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/testutil"
)

func TestAudit010And011_RefreshReuseAndFamilyRevoke(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	store := withTestKeys(t, New(db, clk, gen, func(user *User) error { return nil }, 15*time.Minute, 30*24*time.Hour))
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{Email: "audit-refresh@test.com", EmailVerified: true, Name: "Refresh Audit", Provider: "google", ProviderUserID: "audit-refresh-sub"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := clk.Now()
	familyID := gen.NewUUID()
	reusedToken := "audit-reused-token"
	currentToken := "audit-current-token"
	reusedHash := store.Keys().RefreshHash(reusedToken)
	currentHash := store.Keys().RefreshHash(currentToken)

	if _, err := db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, revoked_at, used_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test-client', '{openid}', $4, $5, $5, $6)`,
		reusedHash, familyID, user.ID, now.Add(30*24*time.Hour), now, now,
	); err != nil {
		t.Fatalf("insert reused token: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test-client', '{openid}', $4, $5)`,
		currentHash, familyID, user.ID, now.Add(30*24*time.Hour), now,
	); err != nil {
		t.Fatalf("insert current token: %v", err)
	}

	if _, err := redeemRefreshForTest(ctx, store, reusedToken); err == nil {
		t.Fatal("expected invalid refresh token error")
	}

	reuseEvent := requireStorageAuditEvent(t, db, user.ID, "auth.refresh_reuse_detected")
	if reuseEvent["family_id"] != familyID {
		t.Fatalf("reuse family_id = %v, want %s", reuseEvent["family_id"], familyID)
	}

	familyEvent := requireStorageAuditEvent(t, db, user.ID, "auth.refresh_family_revoked")
	if familyEvent["family_id"] != familyID {
		t.Fatalf("family revoke family_id = %v, want %s", familyEvent["family_id"], familyID)
	}
}

// A reuse incident revokes the family once, but every reuse is evidence. In a
// theft the victim usually trips detection first and the attacker presents its
// own (now revoked) token afterwards, so the later presenter's IP must still be
// recorded. Only the family revoke is not repeated.
func TestAudit010And011_ReuseOfRevokedFamilyRecordsEachPresenter(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	store := withTestKeys(t, New(db, clk, gen, func(user *User) error { return nil }, 15*time.Minute, 30*24*time.Hour))

	user, err := store.CreateUserWithIdentity(context.Background(), CreateUserWithIdentityInput{Email: "audit-reuse-each@test.com", EmailVerified: true, Name: "Reuse Each", Provider: "google", ProviderUserID: "audit-reuse-each-sub"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := clk.Now()
	familyID := gen.NewUUID()
	victimToken := "reuse-each-victim-token"     // already redeemed by the attacker
	attackerToken := "reuse-each-attacker-token" // the child the attacker holds
	if _, err := db.Exec(
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, revoked_at, used_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test-client', '{openid}', $4, $5, $5, $5)`,
		store.Keys().RefreshHash(victimToken), familyID, user.ID, now.Add(30*24*time.Hour), now,
	); err != nil {
		t.Fatalf("insert victim token: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test-client', '{openid}', $4, $5)`,
		store.Keys().RefreshHash(attackerToken), familyID, user.ID, now.Add(30*24*time.Hour), now,
	); err != nil {
		t.Fatalf("insert attacker token: %v", err)
	}

	presenters := []struct {
		token string
		ip    string
	}{
		{victimToken, "198.51.100.10"},  // trips detection, revokes the family
		{attackerToken, "203.0.113.66"}, // revoked by then
		{attackerToken, "203.0.113.66"}, // retry
	}
	for _, p := range presenters {
		ctx := clientinfo.WithContext(context.Background(), clientinfo.Info{IP: p.ip, UserAgent: "ua-" + p.ip})
		if _, err := redeemRefreshForTest(ctx, store, p.token); err == nil {
			t.Fatalf("expected invalid refresh token error for presenter %s", p.ip)
		}
	}

	countRows := func(eventType, ip string) int {
		t.Helper()
		query := `SELECT count(*) FROM audit_log WHERE user_id = $1 AND event_type = $2`
		args := []any{user.ID, eventType}
		if ip != "" {
			query += ` AND host(ip_address) = $3`
			args = append(args, ip)
		}
		var n int
		if err := db.QueryRow(query, args...).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", eventType, err)
		}
		return n
	}

	if got := countRows("auth.refresh_family_revoked", ""); got != 1 {
		t.Errorf("auth.refresh_family_revoked rows = %d, want 1 for one incident", got)
	}
	if got := countRows("auth.refresh_reuse_detected", ""); got != len(presenters) {
		t.Errorf("auth.refresh_reuse_detected rows = %d, want %d (one per presentation)", got, len(presenters))
	}
	if got := countRows("auth.refresh_reuse_detected", "203.0.113.66"); got == 0 {
		t.Error("the later presenter's IP is missing from the audit log")
	}

	var live int
	if err := db.QueryRow(`SELECT count(*) FROM refresh_tokens WHERE family_id = $1 AND revoked_at IS NULL`, familyID).Scan(&live); err != nil {
		t.Fatalf("count live tokens: %v", err)
	}
	if live != 0 {
		t.Fatalf("live tokens in revoked family = %d, want 0", live)
	}
}

func TestAuditLog_AppendOnlyGuardAllowsPIIRedactionOnly(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	store := withTestKeys(t, New(db, clk, idgen.CryptoGenerator{}, func(user *User) error { return nil }, 15*time.Minute, 30*24*time.Hour))
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{Email: "audit-guard@test.com", EmailVerified: true, Name: "Audit Guard", Provider: "google", ProviderUserID: "audit-guard-sub"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	store.AuditLog(ctx, &user.ID, "auth.login", "198.51.100.9", "guard-agent", map[string]any{"session_id": "sess-1"})

	if _, err := db.ExecContext(ctx, `UPDATE audit_log SET metadata = '{}'::jsonb WHERE user_id = $1`, user.ID); err == nil {
		t.Fatal("expected immutable metadata update to fail")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM audit_log WHERE user_id = $1`, user.ID); err == nil {
		t.Fatal("expected audit_log delete to fail")
	}

	redacted, err := NewCleanupRunner(db).RedactAuditLogPIIByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("redact audit PII: %v", err)
	}
	if redacted != 1 {
		t.Fatalf("redacted rows = %d, want 1", redacted)
	}

	var ip, ua sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT ip_address::text, user_agent FROM audit_log WHERE user_id = $1`, user.ID).Scan(&ip, &ua); err != nil {
		t.Fatalf("query redacted audit row: %v", err)
	}
	if ip.Valid || ua.Valid {
		t.Fatalf("PII not redacted: ip=%v ua=%v", ip, ua)
	}
}

func TestAuditLogIndexes(t *testing.T) {
	db := testutil.SetupPostgres(t)
	ctx := context.Background()

	wantIndexes := map[string]string{
		"audit_log_user_created_idx":  "btree (user_id, created_at DESC)",
		"audit_log_event_created_idx": "btree (event_type, created_at DESC)",
		"audit_log_created_brin_idx":  "brin (created_at)",
	}

	rows, err := db.QueryContext(ctx,
		`SELECT indexname, indexdef
		 FROM pg_indexes
		 WHERE schemaname = 'public'
		   AND tablename = 'audit_log'
		   AND indexname IN (
		       'audit_log_user_created_idx',
		       'audit_log_event_created_idx',
		       'audit_log_created_brin_idx'
		   )`,
	)
	if err != nil {
		t.Fatalf("query audit_log indexes: %v", err)
	}
	defer rows.Close()

	found := map[string]string{}
	for rows.Next() {
		var name, def string
		if err := rows.Scan(&name, &def); err != nil {
			t.Fatalf("scan index: %v", err)
		}
		found[name] = def
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate indexes: %v", err)
	}

	for name, fragment := range wantIndexes {
		def, ok := found[name]
		if !ok {
			t.Fatalf("missing index %s; found %#v", name, found)
		}
		if !strings.Contains(def, fragment) {
			t.Fatalf("index %s definition = %q, want fragment %q", name, def, fragment)
		}
	}

	assertPlanUsesIndex(t, db,
		`SELECT * FROM audit_log
		 WHERE user_id = '00000000-0000-0000-0000-000000000001'::uuid
		 ORDER BY created_at DESC
		 LIMIT 50`,
		"audit_log_user_created_idx",
	)
	assertPlanUsesIndex(t, db,
		`SELECT * FROM audit_log
		 WHERE event_type = 'auth.login'
		 ORDER BY created_at DESC
		 LIMIT 50`,
		"audit_log_event_created_idx",
	)
}

func TestAuditDeviceCodeIssued(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	store := withTestKeys(t, New(db, clk, idgen.CryptoGenerator{}, func(user *User) error { return nil }, 15*time.Minute, 30*24*time.Hour))
	store.LoadClients([]oauthclient.ConfigEntry{{
		ClientID: "device-client",
		Name:     "Device Client",
	}})
	ctx := clientinfo.WithContext(context.Background(), clientinfo.Info{IP: "198.51.100.31", UserAgent: "device-cli/1.0"})

	if err := store.StoreDeviceAuthorization(ctx, "device-client", "secret-device-code", "USER-CODE", clk.Now().Add(5*time.Minute), []string{"openid"}); err != nil {
		t.Fatalf("store device authorization: %v", err)
	}

	var userID sql.NullString
	var ip sql.NullString
	var ua sql.NullString
	var raw []byte
	if err := db.QueryRowContext(context.Background(),
		`SELECT user_id::text, host(ip_address), user_agent, metadata
		 FROM audit_log
		 WHERE event_type = $1`,
		EventAuthDeviceCodeIssued,
	).Scan(&userID, &ip, &ua, &raw); err != nil {
		t.Fatalf("query device code audit: %v", err)
	}
	if userID.Valid {
		t.Fatalf("user_id valid = true, want NULL before user approval")
	}
	if !ip.Valid || ip.String != "198.51.100.31" {
		t.Fatalf("ip = %v, want 198.51.100.31", ip)
	}
	if !ua.Valid || ua.String != "device-cli/1.0" {
		t.Fatalf("user_agent = %v, want device-cli/1.0", ua)
	}

	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if metadata["client_id"] != "device-client" || metadata["client_name"] != "Device Client" {
		t.Fatalf("metadata = %#v, want client identity", metadata)
	}
	if _, ok := metadata["device_code"]; ok {
		t.Fatalf("metadata must not include device_code: %#v", metadata)
	}
	if _, ok := metadata["user_code"]; ok {
		t.Fatalf("metadata must not include user_code: %#v", metadata)
	}
}

func assertPlanUsesIndex(t *testing.T, db *sql.DB, query, indexName string) {
	t.Helper()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin explain tx: %v", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(context.Background(), `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatalf("disable seqscan: %v", err)
	}

	rows, err := tx.QueryContext(context.Background(), "EXPLAIN (ANALYZE, COSTS OFF) "+query)
	if err != nil {
		t.Fatalf("explain query: %v", err)
	}
	defer rows.Close()

	var plan []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan explain: %v", err)
		}
		plan = append(plan, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate explain: %v", err)
	}

	joined := strings.Join(plan, "\n")
	if !strings.Contains(joined, indexName) {
		t.Fatalf("plan did not use %s:\n%s", indexName, joined)
	}
}

func requireStorageAuditEvent(t *testing.T, db *sql.DB, userID, eventType string) map[string]any {
	t.Helper()

	var raw []byte
	err := db.QueryRowContext(context.Background(),
		`SELECT metadata FROM audit_log WHERE user_id = $1 AND event_type = $2`,
		userID, eventType,
	).Scan(&raw)
	if err != nil {
		t.Fatalf("query audit event %s: %v", eventType, err)
	}

	var metadata map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &metadata); err != nil {
			t.Fatalf("decode metadata: %v", err)
		}
	}
	return metadata
}
