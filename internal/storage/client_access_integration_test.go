//go:build integration

package storage

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clientaccess"
)

// client-access-300: the hosted domain is stored on signup, returned by every
// user read an access check uses, and replaced or cleared by later logins. An
// unchanged value is not rewritten, and a cleared value is not replaced by an
// older identity's stale one.
func TestHostedDomain_PersistedAndUpdated(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "hd@corp.example", EmailVerified: true, Name: "HD", Provider: "google", ProviderUserID: "hd-sub", HostedDomain: "corp.example",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	plain, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "plain@gmail.example", EmailVerified: true, Name: "P", Provider: "google", ProviderUserID: "plain-sub",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessionID, err := s.CreateSession(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	readAll := func(t *testing.T, userID, sub, session string) map[string]string {
		t.Helper()
		got := map[string]string{}
		u, err := s.GetUserByProviderIdentity(ctx, "google", sub)
		if err != nil {
			t.Fatalf("GetUserByProviderIdentity: %v", err)
		}
		got["provider identity"] = u.HostedDomain
		if u, err = s.GetUserByID(ctx, userID); err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		got["by id"] = u.HostedDomain
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if u, err = s.getUserByID(ctx, tx, userID); err != nil {
			t.Fatalf("getUserByID: %v", err)
		}
		got["in tx"] = u.HostedDomain
		if session != "" {
			if u, err = s.GetValidSession(ctx, session); err != nil {
				t.Fatalf("GetValidSession: %v", err)
			}
			got["session"] = u.HostedDomain
		}
		return got
	}
	expect := func(t *testing.T, got map[string]string, want string) {
		t.Helper()
		for read, hd := range got {
			if hd != want {
				t.Errorf("%s: HostedDomain = %q, want %q", read, hd, want)
			}
		}
	}

	expect(t, readAll(t, user.ID, "hd-sub", sessionID), "corp.example")
	expect(t, readAll(t, plain.ID, "plain-sub", ""), "")

	if err := s.SetIdentityHostedDomain(ctx, "google", "hd-sub", "new.example"); err != nil {
		t.Fatalf("SetIdentityHostedDomain: %v", err)
	}
	expect(t, readAll(t, user.ID, "hd-sub", sessionID), "new.example")
	// The other account is untouched.
	expect(t, readAll(t, plain.ID, "plain-sub", ""), "")

	if err := s.SetIdentityHostedDomain(ctx, "google", "hd-sub", ""); err != nil {
		t.Fatalf("SetIdentityHostedDomain clear: %v", err)
	}
	expect(t, readAll(t, user.ID, "hd-sub", sessionID), "")
	var stored sql.NullString
	if err := s.DB().QueryRowContext(ctx, `SELECT hosted_domain FROM user_identities WHERE user_id = $1`, user.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored.Valid {
		t.Fatalf("hosted_domain = %q, want NULL after clearing", stored.String)
	}

	// An unchanged value writes nothing: the row version (xmin) stays put, for
	// a repeated NULL and a repeated domain alike.
	identityXmin := func(t *testing.T) string {
		t.Helper()
		var xmin string
		if err := s.DB().QueryRowContext(ctx, `SELECT xmin::text FROM user_identities WHERE user_id = $1 AND provider = 'google'`, user.ID).Scan(&xmin); err != nil {
			t.Fatal(err)
		}
		return xmin
	}
	for _, hd := range []string{"", "again.example"} {
		if err := s.SetIdentityHostedDomain(ctx, "google", "hd-sub", hd); err != nil {
			t.Fatalf("SetIdentityHostedDomain(%q): %v", hd, err)
		}
		before := identityXmin(t)
		if err := s.SetIdentityHostedDomain(ctx, "google", "hd-sub", hd); err != nil {
			t.Fatalf("SetIdentityHostedDomain(%q) again: %v", hd, err)
		}
		if after := identityXmin(t); after != before {
			t.Fatalf("unchanged hosted_domain %q rewrote the row (xmin %s -> %s)", hd, before, after)
		}
	}

	// The newest identity's value is the account's, even when it is NULL: an
	// older identity's stale domain must not stand in for a cleared one.
	if err := s.SetIdentityHostedDomain(ctx, "google", "hd-sub", ""); err != nil {
		t.Fatalf("SetIdentityHostedDomain clear: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO user_identities (
			id, user_id, provider,
			provider_sub_hash, provider_sub_hash_key_id, provider_sub_hash_version,
			provider_sub_ciphertext, provider_sub_nonce, provider_sub_enc_key_id, provider_sub_enc_version,
			created_at, hosted_domain)
		SELECT uuid_generate_v4(), user_id, 'legacy',
			provider_sub_hash, provider_sub_hash_key_id, provider_sub_hash_version,
			provider_sub_ciphertext, provider_sub_nonce, provider_sub_enc_key_id, provider_sub_enc_version,
			created_at - interval '1 day', 'stale.example'
		FROM user_identities WHERE user_id = $1 AND provider = 'google'`, user.ID); err != nil {
		t.Fatalf("insert older identity: %v", err)
	}
	got := readAll(t, user.ID, "hd-sub", sessionID)
	delete(got, "provider identity") // reads the identity's own column
	expect(t, got, "")
}

func loadTestClientAccess(t *testing.T, s *Storage, allow clientaccess.Rules, deny clientaccess.DenyRules) {
	t.Helper()
	p, err := clientaccess.New(allow, deny)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	s.LoadClients([]oauthclient.ConfigEntry{{ClientID: "test-client", Name: "Test Client", LoginChannel: "browser", Access: p}})
}

func assertInvalidGrant(t *testing.T, err error) {
	t.Helper()
	var oerr *oidc.Error
	if !errors.As(err, &oerr) || oerr.ErrorType != oidc.InvalidGrant {
		t.Fatalf("err = %v, want invalid_grant", err)
	}
}

// client-access-301: a refresh for an account the client no longer admits is
// refused with invalid_grant and audited once; the token is neither consumed
// nor treated as reuse, so restoring the policy restores the grant.
func TestRefresh_DeniedByClientAccess(t *testing.T) {
	f, child := newGraceFixture(t, 0)
	loadTestClientAccess(t, f.store, clientaccess.Rules{EmailDomains: []string{"other.example"}}, clientaccess.DenyRules{})

	_, err := f.redeem(t, child)
	assertInvalidGrant(t, err)
	if got := f.count(t, `SELECT count(*) FROM audit_log WHERE user_id = (SELECT user_id FROM refresh_tokens WHERE family_id = $1 LIMIT 1)
		AND event_type = 'auth.access_denied' AND metadata->>'channel' = 'refresh' AND metadata->>'reason' = 'not_allowed'
		AND metadata->>'client_id' = 'test-client' AND metadata->>'domain' = 'test.com' AND metadata->>'signup' = 'false'`); got != 1 {
		t.Fatalf("auth.access_denied rows = %d, want 1", got)
	}
	if f.tombstoned(t) || f.reuseAudits(t) != 0 {
		t.Fatal("a refused refresh was treated as reuse")
	}

	loadTestClientAccess(t, f.store, clientaccess.Rules{EmailDomains: []string{"test.com"}}, clientaccess.DenyRules{})
	if _, err := f.redeem(t, child); err != nil {
		t.Fatalf("refresh after restoring the policy: %v", err)
	}
}

// client-access-305: the policy applies on refresh even when storage has no
// account state checker, which otherwise skips loading the user.
func TestRefresh_DeniedByClientAccessWithoutStateChecker(t *testing.T) {
	f, child := newGraceFixture(t, 0)
	f.store.stateChecker = nil
	loadTestClientAccess(t, f.store, clientaccess.Rules{EmailDomains: []string{"other.example"}}, clientaccess.DenyRules{})
	_, err := f.redeem(t, child)
	assertInvalidGrant(t, err)
}

// client-access-302: the hosted domain stored for the account is what refresh
// evaluates, so a workspace rule keeps working without an IdP round trip and
// stops once a login records that the account left.
func TestRefresh_ClientAccessUsesStoredHostedDomain(t *testing.T) {
	f, child := newGraceFixture(t, 0)
	ctx := context.Background()
	if _, err := f.store.DB().ExecContext(ctx, `UPDATE user_identities SET hosted_domain = 'corp.example' WHERE user_id = $1`, f.userID); err != nil {
		t.Fatal(err)
	}
	loadTestClientAccess(t, f.store, clientaccess.Rules{GoogleWorkspaceDomains: []string{"corp.example"}}, clientaccess.DenyRules{})

	next, err := f.redeem(t, child)
	if err != nil {
		t.Fatalf("refresh for a workspace member: %v", err)
	}

	if _, err := f.store.DB().ExecContext(ctx, `UPDATE user_identities SET hosted_domain = NULL WHERE user_id = $1`, f.userID); err != nil {
		t.Fatal(err)
	}
	_, err = f.redeem(t, next)
	assertInvalidGrant(t, err)
}

// client-access-303: inside the reuse grace a sibling redemption for a refused
// account is refused like any other refresh, with one audit row and no grace
// child.
func TestRefresh_DeniedByClientAccessInsideReuseGrace(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(time.Second)
	loadTestClientAccess(t, f.store, clientaccess.Rules{Emails: []string{"someone@other.example"}}, clientaccess.DenyRules{})

	_, err := f.redeem(t, f.first)
	assertInvalidGrant(t, err)
	if got := f.graceAudits(t, "issued"); got != 0 {
		t.Fatalf("grace children issued = %d, want 0", got)
	}
	if got := f.liveTokens(t); got != 1 {
		t.Fatalf("live tokens = %d, want 1 (the child only)", got)
	}
	if got := countAuditEvents(t, f.store, "auth.access_denied"); got != 1 {
		t.Fatalf("auth.access_denied rows = %d, want 1", got)
	}
}

// client-access-304: the grace child is decided again under the row lock, so a
// policy that changes between the two halves of the grant still refuses it.
func TestRefresh_DeniedByClientAccessUnderGraceLock(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(time.Second)
	ctx := context.Background()

	rt, err := f.store.TokenRequestByRefreshToken(ctx, f.first)
	if err != nil {
		t.Fatalf("grace redemption while allowed: %v", err)
	}
	loadTestClientAccess(t, f.store, clientaccess.Rules{Emails: []string{"someone@other.example"}}, clientaccess.DenyRules{})

	_, _, _, err = f.store.CreateAccessAndRefreshTokens(ctx, rt, f.first)
	assertInvalidGrant(t, err)
	if got := f.liveTokens(t); got != 1 {
		t.Fatalf("live tokens = %d, want 1 (no grace child)", got)
	}
	if got := countAuditEvents(t, f.store, "auth.access_denied"); got != 1 {
		t.Fatalf("auth.access_denied rows = %d, want 1", got)
	}
}

func countAuditEvents(t *testing.T, s *Storage, eventType string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRowContext(context.Background(), `SELECT count(*) FROM audit_log WHERE event_type = $1`, eventType).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
