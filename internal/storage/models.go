package storage

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// --- User ---

type User struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Status        string
	// HostedDomain is the Google hosted domain (hd) recorded at the account's
	// last upstream login; empty when there is none or none recorded yet.
	HostedDomain string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// --- AuthRequest Model ---

type AuthRequestModel struct {
	ID                  string
	ClientID            string
	Resource            string
	RedirectURI         string
	Scopes              StringArray
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              StringArray // OIDC prompt values from /authorize; read by the login handlers
	// MaxAge is OIDC Core 3.1.2.1 max_age in seconds: how old the End-User's
	// authentication may be. nil means the RP did not ask; 0 means
	// re-authenticate now (zitadel normalizes prompt=login to 0).
	MaxAge    *uint
	Subject   *string
	AuthTime  *time.Time
	IsDone    bool
	Code      *string
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (a *AuthRequestModel) GetID() string    { return a.ID }
func (a *AuthRequestModel) GetACR() string   { return "" }
func (a *AuthRequestModel) GetAMR() []string { return nil }
func (a *AuthRequestModel) GetAudience() []string {
	if a.Resource != "" {
		return []string{a.Resource}
	}
	return []string{a.ClientID}
}
func (a *AuthRequestModel) GetClientID() string { return a.ClientID }
func (a *AuthRequestModel) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: a.CodeChallenge,
		Method:    oidc.CodeChallengeMethod(a.CodeChallengeMethod),
	}
}
func (a *AuthRequestModel) GetNonce() string                   { return a.Nonce }
func (a *AuthRequestModel) GetRedirectURI() string             { return a.RedirectURI }
func (a *AuthRequestModel) GetResponseType() oidc.ResponseType { return oidc.ResponseTypeCode }
func (a *AuthRequestModel) GetResponseMode() oidc.ResponseMode { return "" }
func (a *AuthRequestModel) GetScopes() []string                { return a.Scopes }
func (a *AuthRequestModel) GetState() string                   { return a.State }
func (a *AuthRequestModel) Done() bool                         { return a.IsDone }

func (a *AuthRequestModel) GetAuthTime() time.Time {
	if a.AuthTime != nil {
		return *a.AuthTime
	}
	return time.Time{}
}

func (a *AuthRequestModel) GetSubject() string {
	if a.Subject != nil {
		return *a.Subject
	}
	return ""
}

// --- RefreshToken Model ---

type RefreshTokenModel struct {
	ID        string
	TokenHash string
	FamilyID  string
	UserID    string
	ClientID  string
	Resource  string
	Scopes    StringArray
	ExpiresAt time.Time
	RevokedAt *time.Time
	UsedAt    *time.Time
	// scopes are the original grant; currentScopes only narrows this access token.
	currentScopes []string
}

func (r *RefreshTokenModel) GetAMR() []string { return nil }
func (r *RefreshTokenModel) GetAudience() []string {
	if r.Resource != "" {
		return []string{r.Resource}
	}
	return []string{r.ClientID}
}
func (r *RefreshTokenModel) GetAuthTime() time.Time { return time.Time{} }
func (r *RefreshTokenModel) GetClientID() string    { return r.ClientID }
func (r *RefreshTokenModel) GetScopes() []string {
	if r.currentScopes != nil {
		return r.currentScopes
	}
	return r.Scopes
}
func (r *RefreshTokenModel) GetSubject() string { return r.UserID }
func (r *RefreshTokenModel) SetCurrentScopes(scopes []string) {
	r.currentScopes = append([]string{}, scopes...)
}

// --- DeviceCode Model ---

type DeviceCodeModel struct {
	ID         string
	DeviceCode string
	UserCode   string
	ClientID   string
	Scopes     StringArray
	State      string
	Subject    *string
	ExpiresAt  time.Time
	AuthTime   *time.Time
	// LastPolledAt is the timestamp of the last token-endpoint poll for
	// this device_code, used by GetDeviceAuthorizatonState to enforce
	// the RFC 8628 §3.5 `slow_down` cadence. NULL until the first poll.
	LastPolledAt *time.Time
}
