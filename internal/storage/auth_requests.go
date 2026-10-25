package storage

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	resource := ResourceFromContext(ctx)
	// #184: validate the channel × resource matrix on every /authorize, not
	// only when resource is empty.
	client, err := s.ResolveClient(ctx, req.ClientID)
	if err == nil {
		if err := s.resourcePolicy.ValidateAuthorizeRequest(ctx, client, resource); err != nil {
			return nil, err
		}
	}

	// PKCE stays mandatory unless a confidential client opted out. An
	// unresolvable client keeps the requirement: never relax on a lookup
	// failure. zitadel rejects the unknown client_id right after this.
	if err != nil || !client.SkipPKCE {
		if req.CodeChallenge == "" || req.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
			err := oidc.ErrInvalidRequest()
			err.Description = "PKCE S256 required"
			return nil, err
		}
	}
	// Opting out of mandatory S256 does not make unknown methods valid.
	// Keep a Storage-level backstop before persisting a challenge; the provider
	// also rejects unsupported methods before calling Storage. An omitted
	// method keeps RFC 7636's implicit plain behavior for opted-out clients.
	if req.CodeChallenge != "" {
		switch req.CodeChallengeMethod {
		case "", oidc.CodeChallengeMethodPlain, oidc.CodeChallengeMethodS256:
		default:
			err := oidc.ErrInvalidRequest()
			err.Description = "unsupported code_challenge_method"
			return nil, err
		}
	}

	ar := &AuthRequestModel{
		ID:                  s.idgen.NewUUID(),
		ClientID:            req.ClientID,
		Resource:            resource,
		RedirectURI:         req.RedirectURI,
		Scopes:              StringArray(req.Scopes),
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: string(req.CodeChallengeMethod),
		Prompt:              append(StringArray{}, req.Prompt...), // never nil: a nil array encodes as NULL
		MaxAge:              req.MaxAge,
		ExpiresAt:           s.clock.Now().Add(10 * time.Minute),
		CreatedAt:           s.clock.Now(),
	}

	err = storeq.New(s.db).InsertAuthRequest(ctx, storeq.InsertAuthRequestParams{
		ID:                  ar.ID,
		ClientID:            ar.ClientID,
		Resource:            sql.NullString{String: ar.Resource, Valid: true},
		RedirectUri:         ar.RedirectURI,
		Scopes:              []string(ar.Scopes),
		State:               sql.NullString{String: ar.State, Valid: true},
		Nonce:               sql.NullString{String: ar.Nonce, Valid: true},
		CodeChallenge:       sql.NullString{String: ar.CodeChallenge, Valid: true},
		CodeChallengeMethod: sql.NullString{String: ar.CodeChallengeMethod, Valid: true},
		Prompt:              []string(ar.Prompt),
		MaxAge:              maxAgeToNullInt64(ar.MaxAge),
		ExpiresAt:           ar.ExpiresAt,
		CreatedAt:           ar.CreatedAt,
	})
	return ar, err
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	ar, err := s.GetAuthRequestModel(ctx, id)
	if err != nil {
		return nil, err
	}
	return ar, nil
}

// GetAuthRequestModel fetches the auth request by ID and returns the concrete model.
// It does not apply resource policy or state checks — callers use this for pre-completion validation.
func (s *Storage) GetAuthRequestModel(ctx context.Context, id string) (*AuthRequestModel, error) {
	row, err := storeq.New(s.db).GetAuthRequestByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ar := authRequestModelFromRowByID(row)
	if s.clock.Now().After(ar.ExpiresAt) {
		return nil, &oidc.Error{ErrorType: "invalid_request", Description: "auth request expired"}
	}
	return ar, nil
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	row, err := storeq.New(s.db).GetAuthRequestByCode(ctx, sql.NullString{String: s.codeAtRest(code), Valid: true})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ar := authRequestModelFromRowByCode(row)
	// Surface the plaintext code the caller supplied, not the stored hash.
	ar.Code = &code
	if s.clock.Now().After(ar.ExpiresAt) {
		return nil, oidc.ErrInvalidGrant()
	}
	requestResource := ResourceFromContext(ctx)
	if err := s.resourcePolicy.ValidateTokenRequest(ctx, ar.ClientID, ar.Resource, requestResource); err != nil {
		return nil, err
	}
	// The client's access policy is evaluated again here, not only at the
	// callback: a policy tightened between the callback and the exchange must
	// not still mint tokens from a code issued before it.
	//
	// zitadel runs this before it verifies the PKCE challenge and before it
	// authenticates the client (pkg/op/token_code.go AuthorizeCodeClient), so
	// whoever holds the code reaches it without proving anything. Every
	// refusal therefore answers with the same bare invalid_grant that an
	// unknown code gets: the account's status and whether it may use this
	// client are not facts to hand an unauthenticated caller. The reason is
	// kept server-side, in the log line and in the auth.access_denied audit
	// row.
	access := s.ensureRegistry().staticAccess(ar.ClientID)
	if (s.stateChecker != nil || access.Restricted()) && ar.Subject != nil && *ar.Subject != "" {
		user, err := s.GetUserByID(ctx, *ar.Subject)
		if err != nil {
			slog.WarnContext(ctx, "code exchange: subject lookup failed", "client_id", ar.ClientID, "error", err)
			return nil, oidc.ErrInvalidGrant()
		}
		if s.stateChecker != nil {
			if err := s.stateChecker(user); err != nil {
				slog.WarnContext(ctx, "code exchange refused: account state", "client_id", ar.ClientID, "reason", err.Error())
				return nil, oidc.ErrInvalidGrant()
			}
		}
		if err := s.enforceStaticClientAccess(ctx, access, ar.ClientID, s.ensureRegistry().staticLoginChannel(ar.ClientID), user); err != nil {
			slog.WarnContext(ctx, "code exchange refused: client access policy", "client_id", ar.ClientID)
			return nil, oidc.ErrInvalidGrant()
		}
	}
	return ar, err
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	return storeq.New(s.db).UpdateAuthRequestCode(ctx, storeq.UpdateAuthRequestCodeParams{
		Code: sql.NullString{String: s.codeAtRest(code), Valid: true},
		ID:   id,
	})
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return storeq.New(s.db).DeleteAuthRequestByID(ctx, id)
}

// CompleteAuthRequest marks the request done for userID. authTime is when that
// user actually authenticated with the upstream IdP — the session's creation
// time when an existing session is reused, not the moment the request was
// completed. OIDC Core 2 defines auth_time as the time of the End-User
// authentication, and RPs use it to judge freshness. A zero authTime falls
// back to now, which is correct only for a login that just happened.
func (s *Storage) CompleteAuthRequest(ctx context.Context, authRequestID, userID string, authTime time.Time) error {
	if authTime.IsZero() {
		authTime = s.clock.Now()
	}
	rows, err := storeq.New(s.db).CompleteAuthRequestByID(ctx, storeq.CompleteAuthRequestByIDParams{
		Subject:  sql.NullString{String: userID, Valid: true},
		AuthTime: sql.NullTime{Time: authTime, Valid: true},
		ID:       authRequestID,
	})
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func authRequestModelFromRowByID(row storeq.GetAuthRequestByIDRow) *AuthRequestModel {
	return &AuthRequestModel{
		ID:                  row.ID,
		ClientID:            row.ClientID,
		Resource:            row.Resource,
		RedirectURI:         row.RedirectUri,
		Scopes:              StringArray(row.Scopes),
		State:               row.State,
		Nonce:               row.Nonce,
		CodeChallenge:       row.CodeChallenge,
		CodeChallengeMethod: row.CodeChallengeMethod,
		Prompt:              StringArray(row.Prompt),
		MaxAge:              maxAgeFromNullInt64(row.MaxAge),
		Subject:             nullStringToPtr(row.Subject),
		AuthTime:            nullTimePtr(row.AuthTime),
		IsDone:              row.Done,
		Code:                nullStringToPtr(row.Code),
		ExpiresAt:           row.ExpiresAt,
		CreatedAt:           row.CreatedAt,
	}
}

func authRequestModelFromRowByCode(row storeq.GetAuthRequestByCodeRow) *AuthRequestModel {
	return &AuthRequestModel{
		ID:                  row.ID,
		ClientID:            row.ClientID,
		Resource:            row.Resource,
		RedirectURI:         row.RedirectUri,
		Scopes:              StringArray(row.Scopes),
		State:               row.State,
		Nonce:               row.Nonce,
		CodeChallenge:       row.CodeChallenge,
		CodeChallengeMethod: row.CodeChallengeMethod,
		Prompt:              StringArray(row.Prompt),
		MaxAge:              maxAgeFromNullInt64(row.MaxAge),
		Subject:             nullStringToPtr(row.Subject),
		AuthTime:            nullTimePtr(row.AuthTime),
		IsDone:              row.Done,
		Code:                nullStringToPtr(row.Code),
		ExpiresAt:           row.ExpiresAt,
		CreatedAt:           row.CreatedAt,
	}
}

// maxAgeToNullInt64 stores max_age as seconds; nil (not requested) stays NULL,
// which is not the same as 0 (re-authenticate now).
func maxAgeToNullInt64(maxAge *uint) sql.NullInt64 {
	if maxAge == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*maxAge), Valid: true}
}

func maxAgeFromNullInt64(v sql.NullInt64) *uint {
	if !v.Valid || v.Int64 < 0 {
		return nil
	}
	seconds := uint(v.Int64)
	return &seconds
}

// CreateTestAuthRequest creates a minimal auth request for testing purposes.
// Returns the UUID id assigned to the auth request.
//
// The auth_request is bound to client_id "test-app" (registered with
// login_channel="browser" so the channel-binding guard accepts it).
func (s *Storage) CreateTestAuthRequest(ctx context.Context, label string) (string, error) {
	s.LoadClients([]ClientConfigEntry{{ClientID: "test-app", Name: "Test App", LoginChannel: "browser"}})
	id := s.idgen.NewUUID()
	err := storeq.New(s.db).InsertTestAuthRequest(ctx, storeq.InsertTestAuthRequestParams{
		ID:        id,
		State:     sql.NullString{String: label, Valid: true},
		ExpiresAt: s.clock.Now().Add(10 * time.Minute),
		CreatedAt: s.clock.Now(),
	})
	return id, err
}

// CreateTestAuthRequestWithResource creates a minimal auth request with a resource field set,
// for testing MCP flows that require resource binding validation.
//
// The auth_request is bound to client_id "test-mcp-app" (registered with
// login_channel="mcp" so the channel-binding guard accepts it).
func (s *Storage) CreateTestAuthRequestWithResource(ctx context.Context, label, resource string) (string, error) {
	s.LoadClients([]ClientConfigEntry{{ClientID: "test-mcp-app", Name: "Test MCP App", LoginChannel: "mcp"}})
	id := s.idgen.NewUUID()
	now := s.clock.Now()
	err := storeq.New(s.db).InsertTestAuthRequestWithResource(ctx, storeq.InsertTestAuthRequestWithResourceParams{
		ID:        id,
		State:     sql.NullString{String: label, Valid: true},
		Resource:  sql.NullString{String: resource, Valid: true},
		ExpiresAt: now.Add(10 * time.Minute),
		CreatedAt: now,
	})
	return id, err
}
