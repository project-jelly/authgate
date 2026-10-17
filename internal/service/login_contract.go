package service

import (
	"context"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/storage"
)

type LoginStore interface {
	GetValidSession(ctx context.Context, sessionID string) (*storage.User, error)
	AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
	RecoverUser(ctx context.Context, userID string) error
	CompleteAuthRequest(ctx context.Context, authRequestID, userID string, authTime time.Time) error
	// SessionAuthTime is when the session's owner last authenticated upstream.
	SessionAuthTime(ctx context.Context, sessionID string) (time.Time, error)
	GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	CreateUserWithIdentity(ctx context.Context, input storage.CreateUserWithIdentityInput) (*storage.User, error)
	GetUserByID(ctx context.Context, userID string) (*storage.User, error)
	CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error)
	GetAuthRequestModel(ctx context.Context, id string) (*storage.AuthRequestModel, error)
	ResolveClient(ctx context.Context, clientID string) (*oauthclient.Model, error)
	SetIdentityHostedDomain(ctx context.Context, provider, providerUserID, hostedDomain string) error
}

// LoginResult describes what the handler should do after HandleLogin.
type LoginResult struct {
	Action        LoginAction
	RedirectURL   string
	AuthRequestID string
	// UpstreamPrompt is the prompt to send to the upstream IdP with
	// ActionRedirectToIdP; empty sends none.
	UpstreamPrompt string
	Error          string
	ErrorCode      int
}

type LoginAction int

const (
	ActionRedirectToIdP    LoginAction = iota // Redirect to upstream IdP
	ActionAutoApprove                         // Complete auth request immediately
	ActionError                               // Show error
	ActionRedirectToClient                    // Redirect to RedirectURL, an authorization error response for the client
)

// CallbackResult describes what the handler should do after HandleCallback.
type CallbackResult struct {
	Action        LoginAction
	RedirectURL   string
	AuthRequestID string
	SessionID     string
	Error         string
	ErrorCode     int
}
