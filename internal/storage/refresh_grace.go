package storage

import (
	"context"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// refreshReuseGraceMaxIssued caps the children one redemption may have: the
// regular child plus grace children.
const refreshReuseGraceMaxIssued = 3

type refreshReuseGrace int

const (
	// graceNone: the grace does not apply; run reuse detection.
	graceNone refreshReuseGrace = iota
	// graceIssue: redeem the token again into the same family.
	graceIssue
	// graceRefuse: inside the window but the grace is exhausted or no longer
	// safe; refuse without revoking the family.
	graceRefuse
)

// refreshReuseGraceDecision decides how a redeemed refresh token presented
// again is handled. The grace applies only when all of these hold:
//
//   - the grace is enabled;
//   - the token was redeemed: used_at is set, and revoked in that same step.
//     Revocation (/oauth/revoke by hash or id, a user-wide revoke, account
//     deletion, a family revoke) never sets used_at, so a revoked token gets
//     no grace;
//   - the redemption was at most the grace ago;
//   - the family is not tombstoned by reuse detection.
//
// Inside the window the token is redeemed again (graceIssue) unless a token in
// the family has since been revoked on purpose, which would otherwise let a
// replay bring back a session its owner ended, or the redemption already has
// refreshReuseGraceMaxIssued children. Either refuses (graceRefuse).
//
// This runs only under the family and parent row locks during issuance.
func (s *Storage) refreshReuseGraceDecision(ctx context.Context, qtx *storeq.Queries, rt *RefreshTokenModel, now time.Time) (refreshReuseGrace, error) {
	if s.refreshReuseGrace <= 0 || rt.UsedAt == nil || rt.RevokedAt == nil || !rt.RevokedAt.Equal(*rt.UsedAt) {
		return graceNone, nil
	}
	// RFC 9700 §4.14.2: public clients must detect replay. Only clients
	// authenticated with a secret may opt into the bounded compatibility grace.
	if !s.ensureRegistry().StaticRefreshGraceAllowed(rt.ClientID) {
		return graceNone, nil
	}
	if now.Sub(*rt.UsedAt) > s.refreshReuseGrace {
		return graceNone, nil
	}
	tombstoned, err := qtx.IsRefreshFamilyRevoked(ctx, rt.FamilyID)
	if err != nil {
		return graceNone, err
	}
	if tombstoned {
		return graceNone, nil
	}
	revokedOnPurpose, err := qtx.HasRevokedUnredeemedRefreshTokenInFamily(ctx, rt.FamilyID)
	if err != nil {
		return graceNone, err
	}
	if revokedOnPurpose {
		return graceNone, nil
	}
	children, err := s.countRedemptionChildren(ctx, qtx, rt)
	if err != nil {
		return graceNone, err
	}
	if children >= refreshReuseGraceMaxIssued {
		return graceRefuse, nil
	}
	return graceIssue, nil
}

// countRedemptionChildren counts the tokens rotated from rt. Tokens issued
// before parent_id existed have no parent recorded and are not counted.
func (s *Storage) countRedemptionChildren(ctx context.Context, qtx *storeq.Queries, rt *RefreshTokenModel) (int64, error) {
	return qtx.CountRefreshTokenChildren(ctx, rt.ID)
}

// errRefreshGrantRefused is returned when a refresh token is refused while the
// new tokens are being created. zitadel/oidc maps only *oidc.Error values from
// that step to their own status; a plain storage error there becomes a 500
// server_error, which invites the retry that trips reuse detection.
func errRefreshGrantRefused() error {
	return oidc.ErrInvalidGrant().WithParent(op.ErrInvalidRefreshToken)
}

// auditRefreshReuseGrace records a redemption handled by the reuse grace with
// the presenter's IP and user agent. A replay inside the window is exactly what
// the grace lets through, so every grace child and every refusal is evidence.
func (s *Storage) auditRefreshReuseGrace(ctx context.Context, userID, familyID, outcome string) {
	info := clientinfo.FromContext(ctx)
	s.AuditLog(ctx, &userID, EventAuthRefreshReuseGrace, info.IP, info.UserAgent, map[string]any{
		"family_id": familyID,
		"outcome":   outcome,
	})
}
