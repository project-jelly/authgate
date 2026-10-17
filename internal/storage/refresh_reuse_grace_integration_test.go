//go:build integration

package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/clock"
)

const testReuseGrace = 5 * time.Second

type graceFixture struct {
	store    *Storage
	clk      *clock.FixedClock
	userID   string
	familyID string
	first    string // the family's first token
}

// newGraceFixture creates a user with one live refresh token and redeems it
// once through the real rotation path, so the first token is exactly what a
// concurrent sibling request would present a moment later.
func newGraceFixture(t *testing.T, grace time.Duration) (*graceFixture, string) {
	t.Helper()
	store, clk, gen := newTombstoneStore(t)
	store.SetRefreshReuseGrace(grace)
	secretHash := "fixture-only"
	store.LoadClients([]oauthclient.ConfigEntry{{ClientID: "test-client", ClientType: "confidential", ClientSecretHash: &secretHash}})
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "grace-" + gen.NewUUID() + "@test.com", EmailVerified: true, Name: "G", Provider: "google", ProviderUserID: "grace-" + gen.NewUUID(),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	f := &graceFixture{store: store, clk: clk, userID: user.ID, familyID: gen.NewUUID(), first: "grace-first-token"}
	if _, err := store.DB().ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test-client', '{openid}', $4, $5)`,
		store.Keys().RefreshHash(f.first), f.familyID, user.ID, clk.Now().Add(30*24*time.Hour), clk.Now(),
	); err != nil {
		t.Fatalf("insert first token: %v", err)
	}

	child, err := f.redeem(t, f.first)
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	return f, child
}

// redeem runs both halves of a refresh grant the way zitadel/oidc does.
func (f *graceFixture) redeem(t *testing.T, token string) (string, error) {
	t.Helper()
	ctx := context.Background()
	rt, err := f.store.TokenRequestByRefreshToken(ctx, token)
	if err != nil {
		return "", err
	}
	_, next, _, err := f.store.CreateAccessAndRefreshTokens(ctx, rt, token)
	return next, err
}

func (f *graceFixture) count(t *testing.T, query string) int {
	t.Helper()
	var n int
	if err := f.store.DB().QueryRowContext(context.Background(), query, f.familyID).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

func (f *graceFixture) tombstoned(t *testing.T) bool {
	return f.count(t, `SELECT count(*) FROM refresh_token_families WHERE family_id = $1`) > 0
}

func (f *graceFixture) liveTokens(t *testing.T) int {
	return f.count(t, `SELECT count(*) FROM refresh_tokens WHERE family_id = $1 AND revoked_at IS NULL`)
}

func (f *graceFixture) graceAudits(t *testing.T, outcome string) int {
	return f.count(t, `SELECT count(*) FROM audit_log WHERE metadata->>'family_id' = $1::text AND event_type = 'auth.refresh_reuse_grace' AND metadata->>'outcome' = '`+outcome+`'`)
}

func (f *graceFixture) reuseAudits(t *testing.T) int {
	return f.count(t, `SELECT count(*) FROM audit_log WHERE metadata->>'family_id' = $1::text AND event_type = 'auth.refresh_reuse_detected'`)
}

// The 2026-09-11 incident: a second session presents the token a sibling just
// redeemed. Inside the grace both sessions keep a working token.
func TestRefreshReuseGrace_SiblingRedemptionIssuesIntoSameFamily(t *testing.T) {
	f, child := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(2 * time.Second)

	sibling, err := f.redeem(t, f.first)
	if err != nil {
		t.Fatalf("redemption inside the grace was refused: %v", err)
	}
	if sibling == "" || sibling == child {
		t.Fatalf("expected a distinct sibling token, got %q (child %q)", sibling, child)
	}
	if f.tombstoned(t) {
		t.Fatal("family was tombstoned for a redemption inside the grace")
	}
	if got := f.liveTokens(t); got != 2 {
		t.Fatalf("live tokens = %d, want 2 (child and sibling)", got)
	}
	if got := f.reuseAudits(t); got != 0 {
		t.Fatalf("reuse audit rows = %d, want 0", got)
	}
	if got := f.graceAudits(t, "issued"); got != 1 {
		t.Fatalf("grace issued audit rows = %d, want 1", got)
	}
	// Both sessions can keep rotating.
	for name, token := range map[string]string{"child": child, "sibling": sibling} {
		if _, err := f.redeem(t, token); err != nil {
			t.Fatalf("%s token no longer rotates: %v", name, err)
		}
	}
}

// Past the grace a redeemed token is a replay again.
func TestRefreshReuseGrace_AfterWindowDetectsReuse(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(testReuseGrace + time.Second)

	if _, err := f.redeem(t, f.first); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken", err)
	}
	if !f.tombstoned(t) {
		t.Fatal("expected reuse detection to tombstone the family")
	}
	if got := f.liveTokens(t); got != 0 {
		t.Fatalf("live tokens = %d, want 0", got)
	}
}

// A token revoked through /oauth/revoke gets no grace even a moment after the
// revocation.
func TestRefreshReuseGrace_RevokedTokenGetsNoGrace(t *testing.T) {
	f, child := newGraceFixture(t, testReuseGrace)
	ctx := context.Background()

	if oerr := f.store.RevokeToken(ctx, child, f.userID, "test-client"); oerr != nil {
		t.Fatalf("revoke: %v", oerr)
	}
	f.clk.T = f.clk.T.Add(time.Second)

	if _, err := f.redeem(t, child); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken for a revoked token", err)
	}
	if !f.tombstoned(t) {
		t.Fatal("expected reuse detection for a revoked token presented again")
	}
}

// One redemption can yield at most refreshReuseGraceMaxIssued tokens. Past the
// cap the request is refused, but the family the other sessions use survives.
func TestRefreshReuseGrace_CapRefusesWithoutRevokingFamily(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(time.Second)

	for i := 1; i < refreshReuseGraceMaxIssued; i++ {
		if _, err := f.redeem(t, f.first); err != nil {
			t.Fatalf("grace redemption %d refused: %v", i, err)
		}
	}
	if _, err := f.redeem(t, f.first); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken past the cap", err)
	}
	if f.tombstoned(t) {
		t.Fatal("reaching the cap must not tombstone the family")
	}
	if got := f.liveTokens(t); got != refreshReuseGraceMaxIssued {
		t.Fatalf("live tokens = %d, want %d", got, refreshReuseGraceMaxIssued)
	}
	if got := f.graceAudits(t, "refused"); got != 1 {
		t.Fatalf("grace refused audit rows = %d, want 1", got)
	}
}

// The cap must hold when requests interleave: every presentation passes the
// provisional check before any of them inserts its child. This is the order
// concurrent requests take, made deterministic.
func TestRefreshReuseGrace_CapHoldsWhenRequestsInterleave(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(time.Second)
	ctx := context.Background()

	const requests = 10
	var granted []op.RefreshTokenRequest
	for i := 0; i < requests; i++ {
		rt, err := f.store.TokenRequestByRefreshToken(ctx, f.first)
		if err != nil {
			t.Fatalf("provisional grace check %d refused: %v", i, err)
		}
		granted = append(granted, rt)
	}
	issued := 0
	for _, rt := range granted {
		if _, _, _, err := f.store.CreateAccessAndRefreshTokens(ctx, rt, f.first); err == nil {
			issued++
		} else if !errors.Is(err, op.ErrInvalidRefreshToken) {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// The first redemption already made one child, so the cap leaves room for
	// refreshReuseGraceMaxIssued-1 more.
	if want := refreshReuseGraceMaxIssued - 1; issued != want {
		t.Fatalf("grace children issued = %d, want %d", issued, want)
	}
	if got := f.liveTokens(t); got != refreshReuseGraceMaxIssued {
		t.Fatalf("live tokens = %d, want %d", got, refreshReuseGraceMaxIssued)
	}
	if f.tombstoned(t) {
		t.Fatal("reaching the cap must not tombstone the family")
	}
}

// Revoking a session must not be undone by replaying the token it was rotated
// from. zitadel's /oauth/revoke resolves the token and revokes it by id.
func TestRefreshReuseGrace_ParentReplayAfterChildRevokeIsReuse(t *testing.T) {
	f, child := newGraceFixture(t, testReuseGrace)
	ctx := context.Background()

	_, childID, err := f.store.GetRefreshTokenInfo(ctx, "test-client", child)
	if err != nil {
		t.Fatalf("resolve child: %v", err)
	}
	if oerr := f.store.RevokeToken(ctx, childID, f.userID, "test-client"); oerr != nil {
		t.Fatalf("revoke child by id: %v", oerr)
	}
	f.clk.T = f.clk.T.Add(time.Second)

	if _, err := f.redeem(t, f.first); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken when replaying the parent of a revoked token", err)
	}
	if got := f.liveTokens(t); got != 0 {
		t.Fatalf("live tokens = %d, want 0: the revoked session came back", got)
	}
	if !f.tombstoned(t) {
		t.Fatal("expected reuse detection to tombstone the family")
	}
}

// The same holds after every token of the user is revoked while the account
// stays active.
func TestRefreshReuseGrace_ParentReplayAfterUserWideRevokeIsReuse(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	ctx := context.Background()

	if _, err := f.store.DB().ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL`, f.clk.Now(), f.userID,
	); err != nil {
		t.Fatalf("revoke all tokens of the user: %v", err)
	}
	f.clk.T = f.clk.T.Add(time.Second)

	if _, err := f.redeem(t, f.first); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken", err)
	}
	if got := f.liveTokens(t); got != 0 {
		t.Fatalf("live tokens = %d, want 0", got)
	}
}

// Once reuse detection has revoked the family, the grace cannot revive it.
func TestRefreshReuseGrace_TombstonedFamilyGetsNoGrace(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	ctx := context.Background()
	if _, err := f.store.DB().ExecContext(ctx,
		`INSERT INTO refresh_token_families (family_id, user_id, reason, revoked_at) VALUES ($1, $2, 'reuse_detected', $3)`,
		f.familyID, f.userID, f.clk.Now(),
	); err != nil {
		t.Fatalf("tombstone family: %v", err)
	}
	f.clk.T = f.clk.T.Add(time.Second)

	if _, err := f.redeem(t, f.first); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken for a tombstoned family", err)
	}
	if got := f.liveTokens(t); got != 0 {
		t.Fatalf("live tokens = %d, want 0", got)
	}
}

// With the grace disabled, the sibling redemption is reuse, as before.
func TestRefreshReuseGrace_DisabledDetectsReuse(t *testing.T) {
	f, _ := newGraceFixture(t, 0)
	f.clk.T = f.clk.T.Add(time.Second)

	if _, err := f.redeem(t, f.first); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken with the grace disabled", err)
	}
	if !f.tombstoned(t) {
		t.Fatal("expected reuse detection with the grace disabled")
	}
}

// isInvalidGrant reports whether err reaches the client as 400 invalid_grant.
// zitadel/oidc turns any other error from CreateAccessAndRefreshTokens into a
// 500 server_error.
func isInvalidGrant(err error) bool {
	var oerr *oidc.Error
	return errors.As(err, &oerr) && oerr.ErrorType == oidc.InvalidGrant && errors.Is(err, op.ErrInvalidRefreshToken)
}

// Revoking a refresh token ends the grant, including a sibling another session
// received under the grace. Before, only the presented row was revoked and the
// sibling kept working for the rest of its lifetime.
func TestRefreshReuseGrace_RevokeEndsSiblingsToo(t *testing.T) {
	for _, byID := range []bool{false, true} {
		t.Run(fmt.Sprintf("by_id=%v", byID), func(t *testing.T) {
			f, child := newGraceFixture(t, testReuseGrace)
			ctx := context.Background()
			f.clk.T = f.clk.T.Add(time.Second)
			sibling, err := f.redeem(t, f.first)
			if err != nil {
				t.Fatalf("grace sibling: %v", err)
			}

			target := child
			if byID {
				if _, target, err = f.store.GetRefreshTokenInfo(ctx, "test-client", child); err != nil {
					t.Fatalf("resolve child: %v", err)
				}
			}
			if oerr := f.store.RevokeToken(ctx, target, f.userID, "test-client"); oerr != nil {
				t.Fatalf("revoke: %v", oerr)
			}

			f.clk.T = f.clk.T.Add(time.Hour)
			if _, err := f.redeem(t, sibling); err == nil {
				t.Fatal("the grace sibling still rotates after its grant was revoked")
			}
			if got := f.liveTokens(t); got != 0 {
				t.Fatalf("live tokens = %d, want 0", got)
			}
			var reason string
			if err := f.store.DB().QueryRowContext(ctx, `SELECT reason FROM refresh_token_families WHERE family_id = $1`, f.familyID).Scan(&reason); err != nil {
				t.Fatalf("expected a tombstone for the revoked grant: %v", err)
			}
			if reason != tombstoneReasonRevoked {
				t.Fatalf("tombstone reason = %q, want %q", reason, tombstoneReasonRevoked)
			}
		})
	}
}

// The grace audit names the request that actually consumes second. Lookup
// does not decide which concurrent request is the ordinary redemption.
func TestRefreshReuseGrace_AuditNamesTheGraceRequestWhateverTheOrder(t *testing.T) {
	f, child := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(time.Second)
	legit := clientinfo.WithContext(context.Background(), clientinfo.Info{IP: "198.51.100.1", UserAgent: "legit"})
	replay := clientinfo.WithContext(context.Background(), clientinfo.Info{IP: "203.0.113.9", UserAgent: "replay"})

	rtLegit, err := f.store.TokenRequestByRefreshToken(legit, child)
	if err != nil {
		t.Fatalf("ordinary redemption: %v", err)
	}
	rtReplay, err := f.store.TokenRequestByRefreshToken(replay, child)
	if err != nil {
		t.Fatalf("grace redemption: %v", err)
	}
	// The replay inserts first.
	if _, _, _, err := f.store.CreateAccessAndRefreshTokens(replay, rtReplay, child); err != nil {
		t.Fatalf("grace child: %v", err)
	}
	if _, _, _, err := f.store.CreateAccessAndRefreshTokens(legit, rtLegit, child); err != nil {
		t.Fatalf("ordinary child: %v", err)
	}

	rows, err := f.store.DB().QueryContext(context.Background(),
		`SELECT host(ip_address) FROM audit_log WHERE event_type = 'auth.refresh_reuse_grace' AND metadata->>'outcome' = 'issued'`)
	if err != nil {
		t.Fatalf("query grace audits: %v", err)
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			t.Fatalf("scan: %v", err)
		}
		ips = append(ips, ip)
	}
	if len(ips) != 1 || ips[0] != "198.51.100.1" {
		t.Fatalf("grace issued audits from %v, want the second committed request 198.51.100.1", ips)
	}
}

// Refusals while the tokens are being created must reach the client as 400
// invalid_grant, not 500.
func TestRefreshReuseGrace_RefusalAtInsertIsInvalidGrant(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(time.Second)
	ctx := context.Background()

	var granted []op.RefreshTokenRequest
	for i := 0; i < refreshReuseGraceMaxIssued+1; i++ {
		rt, err := f.store.TokenRequestByRefreshToken(ctx, f.first)
		if err != nil {
			t.Fatalf("provisional check %d: %v", i, err)
		}
		granted = append(granted, rt)
	}
	var last error
	for _, rt := range granted {
		_, _, _, last = f.store.CreateAccessAndRefreshTokens(ctx, rt, f.first)
	}
	if !isInvalidGrant(last) {
		t.Fatalf("refusal at insert = %#v, want invalid_grant wrapping ErrInvalidRefreshToken", last)
	}
}

// A redeemed token whose row vanished before its child is inserted (an account
// purge in between) must not mint a token into a new, unrelated family.
func TestRefreshReuseGrace_MissingRedeemedRowIsRefused(t *testing.T) {
	f, child := newGraceFixture(t, testReuseGrace)
	ctx := context.Background()

	rt, err := f.store.TokenRequestByRefreshToken(ctx, child)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := f.store.DB().ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token_hash = $1`, f.store.Keys().RefreshHash(child)); err != nil {
		t.Fatalf("delete redeemed row: %v", err)
	}
	var before int
	if err := f.store.DB().QueryRowContext(ctx, `SELECT count(*) FROM refresh_tokens`).Scan(&before); err != nil {
		t.Fatalf("count: %v", err)
	}

	if _, _, _, err := f.store.CreateAccessAndRefreshTokens(ctx, rt, child); !isInvalidGrant(err) {
		t.Fatalf("err = %v, want invalid_grant", err)
	}
	var after int
	if err := f.store.DB().QueryRowContext(ctx, `SELECT count(*) FROM refresh_tokens`).Scan(&after); err != nil {
		t.Fatalf("count: %v", err)
	}
	if after != before {
		t.Fatalf("a token was minted from a deleted row: %d -> %d", before, after)
	}
}

// Real concurrency: many requests present one unredeemed token at once. The
// cap must hold, every refusal must be a refresh token refusal, and nothing may
// deadlock.
func TestRefreshReuseGrace_ConcurrentRedemptionsRespectCap(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	ctx := context.Background()

	for round := 0; round < 5; round++ {
		token := fmt.Sprintf("concurrent-%d", round)
		if _, err := f.store.DB().ExecContext(ctx,
			`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
			 VALUES (uuid_generate_v4(), $1, gen_random_uuid(), $2, 'test-client', '{openid}', $3, $4)`,
			f.store.Keys().RefreshHash(token), f.userID, f.clk.Now().Add(24*time.Hour), f.clk.Now(),
		); err != nil {
			t.Fatalf("insert token: %v", err)
		}

		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			issued  int
			refused int
			others  []error
		)
		start := make(chan struct{})
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := f.redeem(t, token)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					issued++
				case errors.Is(err, op.ErrInvalidRefreshToken):
					refused++
				default:
					others = append(others, err)
				}
			}()
		}
		close(start)
		wg.Wait()

		var children int
		if err := f.store.DB().QueryRowContext(ctx,
			`SELECT count(*) FROM refresh_tokens c JOIN refresh_tokens p ON c.parent_id = p.id WHERE p.token_hash = $1`,
			f.store.Keys().RefreshHash(token),
		).Scan(&children); err != nil {
			t.Fatalf("count children: %v", err)
		}
		if len(others) > 0 {
			t.Fatalf("round %d: unexpected errors %v", round, others)
		}
		if children > refreshReuseGraceMaxIssued || issued != children {
			t.Fatalf("round %d: issued=%d children=%d refused=%d, want at most %d children", round, issued, children, refused, refreshReuseGraceMaxIssued)
		}
	}
}

// A client may revoke only its own tokens (RFC 7009 §2.1). Now that revoke ends
// the whole grant, another client presenting any token of the family, even an
// old redeemed one, must not end the owner's grant.
func TestRefreshReuseGrace_RevokeByAnotherClientLeavesGrantAlive(t *testing.T) {
	f, child := newGraceFixture(t, testReuseGrace)
	ctx := context.Background()

	_, childID, err := f.store.GetRefreshTokenInfo(ctx, "test-client", child)
	if err != nil {
		t.Fatalf("resolve child: %v", err)
	}
	for _, target := range []string{f.first, child, childID} {
		if oerr := f.store.RevokeToken(ctx, target, "", "other-client"); oerr != nil {
			t.Fatalf("revoke: %v", oerr)
		}
	}

	if f.tombstoned(t) {
		t.Fatal("another client's revoke tombstoned the grant")
	}
	if _, err := f.redeem(t, child); err != nil {
		t.Fatalf("the owner's live token stopped working after another client's revoke: %v", err)
	}
	if got := f.count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.token_revoked' AND $1::text IS NOT NULL`); got != 0 {
		t.Fatalf("token_revoked audit rows = %d, want 0 for a refused revoke", got)
	}
}

// zitadel/oidc passes an empty subject when it revokes by the raw token; the
// audit row must still name the grant's owner.
func TestRefreshReuseGrace_RevokeAuditNamesGrantOwner(t *testing.T) {
	f, child := newGraceFixture(t, testReuseGrace)
	ctx := context.Background()

	if oerr := f.store.RevokeToken(ctx, child, "", "test-client"); oerr != nil {
		t.Fatalf("revoke: %v", oerr)
	}
	var owner string
	if err := f.store.DB().QueryRowContext(ctx,
		`SELECT user_id::text FROM audit_log WHERE event_type = 'auth.token_revoked'`,
	).Scan(&owner); err != nil {
		t.Fatalf("expected one token_revoked audit row with a user: %v", err)
	}
	if owner != f.userID {
		t.Fatalf("token_revoked user_id = %q, want grant owner %q", owner, f.userID)
	}
}

// The re-check under the lock must re-validate the account: a user disabled
// between presenting the token and inserting the grace child gets nothing.
func TestRefreshReuseGrace_AccountDisabledBeforeInsertIsRefused(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	f.store.stateChecker = func(u *User) error {
		if u.Status != "active" {
			return fmt.Errorf("account not active: %s", u.Status)
		}
		return nil
	}
	f.clk.T = f.clk.T.Add(time.Second)
	ctx := context.Background()

	rt, err := f.store.TokenRequestByRefreshToken(ctx, f.first)
	if err != nil {
		t.Fatalf("grace redemption: %v", err)
	}
	if _, err := f.store.DB().ExecContext(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, f.userID); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	before := f.count(t, `SELECT count(*) FROM refresh_tokens WHERE family_id = $1`)

	_, _, _, err = f.store.CreateAccessAndRefreshTokens(ctx, rt, f.first)
	var oerr *oidc.Error
	if !errors.As(err, &oerr) || oerr.ErrorType != oidc.InvalidGrant {
		t.Fatalf("err = %v, want invalid_grant for a disabled account", err)
	}
	if after := f.count(t, `SELECT count(*) FROM refresh_tokens WHERE family_id = $1`); after != before {
		t.Fatalf("a grace child was inserted for a disabled account: %d -> %d", before, after)
	}
}

// Expiry found under the lock is still a 400, not a 500.
func TestRefreshReuseGrace_ExpiryBeforeInsertIsInvalidGrant(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(time.Second)
	ctx := context.Background()

	rt, err := f.store.TokenRequestByRefreshToken(ctx, f.first)
	if err != nil {
		t.Fatalf("grace redemption: %v", err)
	}
	if _, err := f.store.DB().ExecContext(ctx,
		`UPDATE refresh_tokens SET expires_at = $1 WHERE token_hash = $2`, f.clk.Now().Add(-time.Minute), f.store.Keys().RefreshHash(f.first),
	); err != nil {
		t.Fatalf("expire token: %v", err)
	}

	if _, _, _, err := f.store.CreateAccessAndRefreshTokens(ctx, rt, f.first); !isInvalidGrant(err) {
		t.Fatalf("err = %#v, want invalid_grant", err)
	}
}
