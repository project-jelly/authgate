package client

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clientaccess"
)

// Model describes an OAuth client and implements the provider client contract.
type Model struct {
	UUID                 string
	ID                   string
	SecretHash           *string
	Type                 string
	LoginChannel         string
	Name                 string
	URL                  string
	RedirectURIList      []string
	AllowedScopeList     []string
	AllowedGrantTypeList []string
	// SkipPKCE waives the PKCE S256 requirement. Zero value keeps it
	// mandatory so every construction path defaults to the safe behavior.
	SkipPKCE                 bool
	IDTokenUserinfoAssertion bool
	// Access restricts which accounts may use the client. nil admits every
	// account, which is what CIMD clients always get.
	Access *clientaccess.Policy
}

func (c *Model) GetID() string                    { return c.ID }
func (c *Model) RedirectURIs() []string           { return c.RedirectURIList }
func (c *Model) PostLogoutRedirectURIs() []string { return nil }
func (c *Model) ApplicationType() op.ApplicationType {
	if c.Type == "confidential" {
		return op.ApplicationTypeWeb
	}
	return op.ApplicationTypeNative
}
func (c *Model) AuthMethod() oidc.AuthMethod {
	if c.SecretHash != nil {
		return oidc.AuthMethodBasic
	}
	return oidc.AuthMethodNone
}
func (c *Model) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *Model) GrantTypes() []oidc.GrantType {
	types := make([]oidc.GrantType, 0, len(c.AllowedGrantTypeList))
	for _, gt := range c.AllowedGrantTypeList {
		types = append(types, oidc.GrantType(gt))
	}
	return types
}
func (c *Model) LoginURL(authRequestID string) string {
	if c.LoginChannel == "mcp" {
		return "/mcp/login?authRequestID=" + authRequestID
	}
	return "/login?authRequestID=" + authRequestID
}
func (c *Model) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeJWT
}
func (c *Model) IDTokenLifetime() time.Duration {
	return time.Hour
}
func (c *Model) DevMode() bool { return false }
func (c *Model) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *Model) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *Model) IsScopeAllowed(scope string) bool {
	for _, s := range c.AllowedScopeList {
		if s == scope {
			return true
		}
	}
	return false
}
func (c *Model) IDTokenUserinfoClaimsAssertion() bool {
	return c.IDTokenUserinfoAssertion
}
func (c *Model) ClockSkew() time.Duration { return 0 }
