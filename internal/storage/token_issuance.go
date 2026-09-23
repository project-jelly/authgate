package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	if err := s.consumeAuthCode(ctx, storeq.New(s.db), request); err != nil {
		return "", time.Time{}, err
	}
	tokenID := s.idgen.NewUUID()
	expiration := s.clock.Now().Add(s.accessTokenTTL)
	return tokenID, expiration, nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	tokenID := s.idgen.NewUUID()
	expiration := s.clock.Now().Add(s.accessTokenTTL)

	newRefresh, err := s.idgen.NewOpaqueToken()
	if err != nil {
		return "", "", time.Time{}, err
	}

	newHash := s.keys.RefreshHash(newRefresh)
	now := s.clock.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()
	qtx := storeq.New(tx)
	if err := s.consumeAuthCode(ctx, qtx, request); err != nil {
		return "", "", time.Time{}, err
	}

	derived := s.initialRefreshTokenAttributes(ctx, request)
	var parentID uuid.NullUUID
	graceChild := false
	if currentRefreshToken != "" {
		var parent string
		derived, parent, graceChild, err = s.consumeRefreshToken(ctx, tx, qtx, request, currentRefreshToken)
		if err != nil {
			return "", "", time.Time{}, err
		}
		id, err := uuid.Parse(parent)
		if err != nil {
			return "", "", time.Time{}, err
		}
		parentID = uuid.NullUUID{UUID: id, Valid: true}
	}

	err = qtx.InsertRefreshToken(ctx, storeq.InsertRefreshTokenParams{
		ID:        s.idgen.NewUUID(),
		TokenHash: newHash,
		FamilyID:  derived.familyID,
		UserID:    derived.userID,
		ClientID:  derived.clientID,
		Resource:  sql.NullString{String: derived.resource, Valid: true},
		Scopes:    derived.scopes,
		ExpiresAt: now.Add(s.refreshTokenTTL),
		CreatedAt: now,
		ParentID:  parentID,
	})
	if err != nil {
		return "", "", time.Time{}, err
	}

	if err = tx.Commit(); err != nil {
		return "", "", time.Time{}, err
	}
	if graceChild {
		s.auditRefreshReuseGrace(ctx, derived.userID, derived.familyID, "issued")
	}

	// A successful refresh grant is deliberately not audited. It is the highest
	// volume event by far and records nothing the system does not already hold:
	// refresh_tokens.used_at carries last-use per credential, auth.login carries
	// the authentication event, and replay, revocation and status changes are
	// each audited on their own. Logging every routine rotation would dominate
	// the audit log while adding no detection capability.

	return tokenID, newRefresh, expiration, nil
}

type refreshTokenAttributes struct {
	familyID string
	userID   string
	clientID string
	resource string
	scopes   []string
}

func (s *Storage) initialRefreshTokenAttributes(ctx context.Context, request op.TokenRequest) refreshTokenAttributes {
	derived := refreshTokenAttributes{familyID: s.idgen.NewUUID(), userID: request.GetSubject(), scopes: request.GetScopes()}
	switch r := request.(type) {
	case *AuthRequestModel:
		derived.clientID = r.GetClientID()
		derived.resource = r.Resource
	case *op.DeviceAuthorizationState:
		derived.clientID = r.ClientID
		// Resource-bound Device grants carry the RFC 8707 resource in the
		// request context. The token endpoint wraps it with WithResource
		// before calling CreateAccessAndRefreshTokens, so we read it here
		// rather than from DeviceAuthorizationState.Audience (which also
		// drives the ID token aud and must stay client_id).
		derived.resource = ResourceFromContext(ctx)
	}
	return derived
}
