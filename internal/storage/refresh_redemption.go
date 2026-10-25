package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	h := s.keys.RefreshHash(refreshToken)
	now := s.clock.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	qtx := storeq.New(tx)

	rt, err := loadRefreshTokenForUpdate(ctx, qtx, h)
	if err != nil {
		return nil, err
	}

	// The provider validates client binding and requested scopes after this
	// lookup. Do not consume or revoke anything until issuance, where state
	// is re-read under the same family lock used by explicit revocation.
	if err := s.validateRefreshTokenRequest(ctx, tx, rt, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return rt, nil
}

func loadRefreshTokenForUpdate(ctx context.Context, qtx *storeq.Queries, tokenHash string) (*RefreshTokenModel, error) {
	row, err := qtx.GetRefreshTokenForUpdateByHash(ctx, tokenHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, op.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}

	return &RefreshTokenModel{
		ID:        row.ID,
		TokenHash: row.TokenHash,
		FamilyID:  row.FamilyID,
		UserID:    row.UserID,
		ClientID:  row.ClientID,
		Resource:  row.Resource,
		Scopes:    StringArray(row.Scopes),
		ExpiresAt: row.ExpiresAt,
		RevokedAt: nullTimePtr(row.RevokedAt),
		UsedAt:    nullTimePtr(row.UsedAt),
	}, nil
}

func isRefreshTokenUsedOrRevoked(rt *RefreshTokenModel) bool {
	return rt.RevokedAt != nil || rt.UsedAt != nil
}

func (s *Storage) validateRefreshTokenRequest(ctx context.Context, tx *sql.Tx, rt *RefreshTokenModel, now time.Time) error {
	if !now.Before(rt.ExpiresAt) {
		return op.ErrInvalidRefreshToken
	}

	requestResource := ResourceFromContext(ctx)
	if err := s.resourcePolicy.ValidateTokenRequest(ctx, rt.ClientID, rt.Resource, requestResource); err != nil {
		return err
	}

	// The client's access policy is re-evaluated on every refresh so removing
	// an account from it takes effect within one access-token lifetime, not
	// only at the next interactive login.
	access := s.ensureRegistry().StaticAccess(rt.ClientID)
	if s.stateChecker == nil && !access.Restricted() {
		return nil
	}
	user, err := s.getUserByID(ctx, tx, rt.UserID)
	if err != nil {
		return op.ErrInvalidRefreshToken
	}
	if s.stateChecker != nil {
		if err := s.stateChecker(user); err != nil {
			return &oidc.Error{ErrorType: "invalid_grant", Description: err.Error()}
		}
	}
	return s.enforceStaticClientAccess(ctx, access, rt.ClientID, "refresh", user)
}
