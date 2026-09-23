package storage

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"errors"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/crypto"
	"github.com/kangheeyong/authgate/internal/idgen"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrEmailConflict = errors.New("email_conflict")

	// ErrUserAccountClosed is returned when a user lookup succeeds but the
	// account is in a terminal state (`disabled` or `deleted`). The user is
	// returned alongside the error so callers can emit the right audit
	// metadata (channel, IP, UA) before rejecting. `pending_deletion` is
	// passed through without an error because the channel × status policy
	// in service.CheckAccess permits browser-channel recovery.
	//
	// Defense-in-depth for #157: any new caller that does
	// `if err != nil { return err }` after a session/bearer lookup will
	// correctly reject closed accounts without needing to remember the
	// status check itself.
	ErrUserAccountClosed = errors.New("user account is closed")
)

// StateChecker validates that a user is still eligible for token issuance.
// It is applied on both authorization_code and refresh_token grant lookups.
// Injected from main.go — storage never imports service or guard packages.
type StateChecker func(user *User) error

// ClientResolutionPolicy resolves a client profile for client_id.
// It is invoked by storage methods that zitadel calls directly.
type ClientResolutionPolicy interface {
	ResolveClient(ctx context.Context, clientID string) (*ClientModel, error)
}

// ResourceBindingPolicy validates resource binding across authorize/token flows.
// Default policy preserves current behavior for browser/mcp resource checks.
type ResourceBindingPolicy interface {
	ValidateAuthorizeRequest(ctx context.Context, client *ClientModel, requestResource string) error
	ValidateTokenRequest(ctx context.Context, clientID, storedResource, requestResource string) error
}

type Storage struct {
	db              *sql.DB
	clock           clock.Clock
	idgen           idgen.IDGenerator
	stateChecker    StateChecker
	signing         signingKeyProvider
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	// devicePollInterval is the minimum gap between successive device-flow
	// token polls before the AS responds with `slow_down` (RFC 8628 §3.5).
	// Defaults to 5s in New() to match the value advertised in
	// `op.DeviceAuthorizationConfig.PollInterval`.
	devicePollInterval time.Duration
	// refreshReuseGrace is how long after a refresh token is redeemed the same
	// token is still accepted without tripping reuse detection. Zero (the
	// default in New) disables the grace; the app sets it from
	// REFRESH_TOKEN_REUSE_GRACE_SEC. See TokenRequestByRefreshToken.
	refreshReuseGrace time.Duration
	registry          *clientRegistry
	audit             *auditLogger
	resourcePolicy    ResourceBindingPolicy
	// keys holds the PII at-rest crypto subkeys (ADR-002). nil until SetKeys is
	// called at startup; while nil, encryption is inert. Required in production.
	keys *crypto.Keys
}

func New(db *sql.DB, clk clock.Clock, gen idgen.IDGenerator, checker StateChecker, accessTTL, refreshTTL time.Duration) *Storage {
	s := &Storage{
		db:                 db,
		clock:              clk,
		idgen:              gen,
		stateChecker:       checker,
		accessTokenTTL:     accessTTL,
		refreshTokenTTL:    refreshTTL,
		devicePollInterval: 5 * time.Second,
		registry:           newClientRegistry(),
	}
	s.audit = newAuditLogger(db, clk, s.sessionAtRest)
	s.resourcePolicy = NewCoreResourceBindingPolicy()
	return s
}

// ensureAudit lazily builds the audit logger so a Storage constructed directly
// (e.g. &Storage{} in tests) rather than through New() still records audits.
func (s *Storage) ensureAudit() *auditLogger {
	if s.audit == nil {
		s.audit = newAuditLogger(s.db, s.clock, s.sessionAtRest)
	}
	return s.audit
}

// SetDevicePollInterval overrides the device-flow poll interval used for
// `slow_down` enforcement. main.go calls this with the same value advertised
// in op.DeviceAuthorizationConfig.PollInterval so a single config flow drives
// both the response shape and the server-side throttle.
func (s *Storage) SetDevicePollInterval(d time.Duration) {
	s.devicePollInterval = d
}

// SetRefreshReuseGrace sets the refresh token reuse grace. Zero disables it.
func (s *Storage) SetRefreshReuseGrace(d time.Duration) {
	s.refreshReuseGrace = d
}

// RefreshReuseGrace reports the configured refresh token reuse grace.
func (s *Storage) RefreshReuseGrace() time.Duration {
	return s.refreshReuseGrace
}

// SetSigningKey sets the current RSA signing key used for JWT issuance.
func (s *Storage) SetSigningKey(key *rsa.PrivateKey, keyID string) {
	s.signing.SetCurrent(key, keyID)
}

// SetPreviousKey sets the previous signing key for 2-slot rotation.
// JWKS will return both keys; JWTs are signed with the current key only.
func (s *Storage) SetPreviousKey(key *rsa.PrivateKey, keyID string) {
	s.signing.SetPrevious(key, keyID)
}

// DB returns the underlying *sql.DB. For cross-package integration tests only
// (they assert on rows this package writes); no production caller.
func (s *Storage) DB() *sql.DB { return s.db }

// ValidateAuthorizationResource applies the configured resource-binding policy
// before an authorization grant is stored. The authorization_code path reaches
// the same policy through CreateAuthRequest; the device authorization adapter
// calls this explicitly because the upstream RFC 8628 request model does not
// carry RFC 8707 extension parameters.
func (s *Storage) ValidateAuthorizationResource(ctx context.Context, clientID, resource string) error {
	client, err := s.ResolveClient(ctx, clientID)
	if err != nil {
		return err
	}
	return s.resourcePolicy.ValidateAuthorizeRequest(ctx, client, resource)
}

// pii returns a codec bound to the current PII keys. It is a cheap value
// wrapper, constructed per call so it always reflects the latest SetKeys.
func (s *Storage) pii() piiCodec { return piiCodec{keys: s.keys} }
