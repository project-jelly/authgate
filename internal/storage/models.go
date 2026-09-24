package storage

import (
	"crypto/rsa"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clientaccess"
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

// --- Client Model ---

type ClientModel struct {
	UUID             string
	ID               string
	SecretHash       *string
	Type             string
	LoginChannel     string
	Name             string
	URL              string
	RedirectURIList  StringArray
	AllowedScopeList StringArray
	// AllowedResourceList is the explicit opt-in allowlist for RFC 8707
	// protected resource indicators. Empty means no restriction.
	AllowedResourceList  StringArray
	AllowedGrantTypeList StringArray
	// SkipPKCE waives the PKCE S256 requirement. Zero value keeps it
	// mandatory so every construction path defaults to the safe behavior.
	SkipPKCE                 bool
	IDTokenUserinfoAssertion bool
	// Access restricts which accounts may use the client. nil admits every
	// account, which is what CIMD clients always get.
	Access *clientaccess.Policy
}

func (c *ClientModel) GetID() string                    { return c.ID }
func (c *ClientModel) RedirectURIs() []string           { return c.RedirectURIList }
func (c *ClientModel) PostLogoutRedirectURIs() []string { return nil }
func (c *ClientModel) ApplicationType() op.ApplicationType {
	if c.Type == "confidential" {
		return op.ApplicationTypeWeb
	}
	return op.ApplicationTypeNative
}
func (c *ClientModel) AuthMethod() oidc.AuthMethod {
	if c.SecretHash != nil {
		return oidc.AuthMethodBasic
	}
	return oidc.AuthMethodNone
}
func (c *ClientModel) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *ClientModel) GrantTypes() []oidc.GrantType {
	types := make([]oidc.GrantType, 0, len(c.AllowedGrantTypeList))
	for _, gt := range c.AllowedGrantTypeList {
		types = append(types, oidc.GrantType(gt))
	}
	return types
}
func (c *ClientModel) LoginURL(authRequestID string) string {
	if c.LoginChannel == "mcp" {
		return "/mcp/login?authRequestID=" + authRequestID
	}
	return "/login?authRequestID=" + authRequestID
}
func (c *ClientModel) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeJWT
}
func (c *ClientModel) IDTokenLifetime() time.Duration {
	return time.Hour
}
func (c *ClientModel) DevMode() bool { return false }
func (c *ClientModel) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *ClientModel) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *ClientModel) IsScopeAllowed(scope string) bool {
	for _, s := range c.AllowedScopeList {
		if s == scope {
			return true
		}
	}
	return false
}
func (c *ClientModel) IDTokenUserinfoClaimsAssertion() bool {
	return c.IDTokenUserinfoAssertion
}

// IsResourceAllowed reports whether the client has explicitly opted into the
// given protected resource. Empty allowlist means the client is not
// resource-restricted (backward-compatible behavior for legacy clients).
func (c *ClientModel) IsResourceAllowed(resource string) bool {
	if c == nil || len(c.AllowedResourceList) == 0 {
		return true
	}
	for _, r := range c.AllowedResourceList {
		if r == resource {
			return true
		}
	}
	return false
}
func (c *ClientModel) ClockSkew() time.Duration { return 0 }

// --- DeviceCode Model ---

type DeviceCodeModel struct {
	ID         string
	DeviceCode string
	UserCode   string
	ClientID   string
	// Resource is the RFC 8707 protected resource bound to this grant.
	// Empty for regular browser-channel Device grants; required for
	// resource-bound (mcp-channel) Device grants.
	Resource  string
	Scopes    StringArray
	State     string
	Subject   *string
	ExpiresAt time.Time
	AuthTime  *time.Time
	// LastPolledAt is the timestamp of the last token-endpoint poll for
	// this device_code, used by GetDeviceAuthorizatonState to enforce
	// the RFC 8628 §3.5 `slow_down` cadence. NULL until the first poll.
	LastPolledAt *time.Time
}

// --- Key Models ---

type signingKeyModel struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PrivateKey
}

func (k *signingKeyModel) SignatureAlgorithm() jose.SignatureAlgorithm { return k.algorithm }
func (k *signingKeyModel) Key() any                                    { return k.key }
func (k *signingKeyModel) ID() string                                  { return k.id }

type publicKeyModel struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PublicKey
}

func (k *publicKeyModel) ID() string                         { return k.id }
func (k *publicKeyModel) Algorithm() jose.SignatureAlgorithm { return k.algorithm }
func (k *publicKeyModel) Use() string                        { return "sig" }
func (k *publicKeyModel) Key() any                           { return k.key }
