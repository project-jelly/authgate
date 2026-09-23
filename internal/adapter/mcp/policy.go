package mcp

import (
	"context"
	"errors"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/kangheeyong/authgate/internal/storage"
)

type clientResolutionPolicy struct {
	base    storage.ClientResolutionPolicy
	fetcher storage.CIMDFetcher
}

func (p *clientResolutionPolicy) ResolveClient(ctx context.Context, clientID string) (*storage.ClientModel, error) {
	client, err := p.base.ResolveClient(ctx, clientID)
	if err == nil {
		return client, nil
	}
	if p.fetcher != nil && storage.IsCIMDClientID(clientID) && errors.Is(err, storage.ErrNotFound) {
		return p.fetcher.FetchClient(ctx, clientID)
	}
	return nil, err
}

// resourceBindingPolicy enforces authgate's RFC 8707 §2.2 channel × resource
// matrix (spec 004): mcp clients REQUIRE a resource (the token's audience);
// browser clients MUST NOT carry one — a browser minting an MCP-audience token
// is a boundary-confusion attack (#184).
type resourceBindingPolicy struct {
	base     storage.ResourceBindingPolicy
	resolver storage.ClientResolutionPolicy
}

// ValidateAuthorizeRequest is the primary enforcement point for the matrix.
func (p *resourceBindingPolicy) ValidateAuthorizeRequest(ctx context.Context, client *storage.ClientModel, requestResource string) error {
	if client != nil {
		if client.LoginChannel == "mcp" {
			if requestResource == "" {
				return &oidc.Error{ErrorType: "invalid_target", Description: "missing resource"}
			}
			if !client.IsResourceAllowed(requestResource) {
				return &oidc.Error{ErrorType: "invalid_target", Description: "resource not allowed for this client"}
			}
		} else {
			if requestResource != "" {
				return &oidc.Error{ErrorType: "invalid_target", Description: "resource parameter not permitted for this client"}
			}
		}
	}
	return p.base.ValidateAuthorizeRequest(ctx, client, requestResource)
}

// ValidateTokenRequest re-checks the matrix at the token endpoint: a non-mcp
// client with a stored resource (legacy data) is rejected with invalid_grant so
// it fails closed on reuse, and a non-mcp client carrying a request resource is
// rejected too. resolver may be nil (test-only → base behavior).
func (p *resourceBindingPolicy) ValidateTokenRequest(ctx context.Context, clientID, storedResource, requestResource string) error {
	if (storedResource != "" || requestResource != "") && p.resolver != nil {
		client, err := p.resolver.ResolveClient(ctx, clientID)
		if err == nil && client != nil && client.LoginChannel != "mcp" {
			if storedResource != "" {
				return &oidc.Error{ErrorType: "invalid_grant", Description: "persisted resource binding invalid for client channel"}
			}
			return &oidc.Error{ErrorType: "invalid_target", Description: "resource parameter not permitted for this client"}
		}
		// Stored resource on an mcp client must still be in the allowlist.
		if err == nil && client != nil && client.LoginChannel == "mcp" && storedResource != "" {
			if !client.IsResourceAllowed(storedResource) {
				return &oidc.Error{ErrorType: "invalid_grant", Description: "persisted resource binding not allowed for this client"}
			}
		}
	}
	return p.base.ValidateTokenRequest(ctx, clientID, storedResource, requestResource)
}

func NewClientResolutionPolicy(base storage.ClientResolutionPolicy, fetcher storage.CIMDFetcher) storage.ClientResolutionPolicy {
	return &clientResolutionPolicy{base: base, fetcher: fetcher}
}

// NewResourceBindingPolicy returns the MCP-aware wrapper. `resolver` is used to
// look up the client's login_channel for the legacy-data and defense-in-depth
// checks at the token endpoint; it may be nil when the caller has no client
// registry (test-only). Pass a NON-fetching resolver (the core registry
// lookup), not the CIMD-augmented one: the token check only needs to catch a
// browser client carrying a resource, and browser clients are always locally
// registered, so the token endpoint must never trigger an outbound CIMD fetch.
func NewResourceBindingPolicy(base storage.ResourceBindingPolicy, resolver storage.ClientResolutionPolicy) storage.ResourceBindingPolicy {
	return &resourceBindingPolicy{base: base, resolver: resolver}
}
