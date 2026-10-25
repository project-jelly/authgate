package client

import (
	"context"
	"errors"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// ErrNotFound is returned when the core registry has no matching client.
var ErrNotFound = errors.New("not found")

// ResolutionPolicy resolves a client profile for client_id.
type ResolutionPolicy interface {
	ResolveClient(ctx context.Context, clientID string) (*Model, error)
}

// ResourceBindingPolicy validates resource binding across authorize/token flows.
type ResourceBindingPolicy interface {
	ValidateAuthorizeRequest(ctx context.Context, client *Model, requestResource string) error
	ValidateTokenRequest(ctx context.Context, clientID, storedResource, requestResource string) error
}

type coreClientResolutionPolicy struct {
	reg *Registry
}

func (p coreClientResolutionPolicy) ResolveClient(ctx context.Context, clientID string) (*Model, error) {
	if v, ok := p.reg.clients.Load(clientID); ok {
		return v.(*Model), nil
	}
	return nil, ErrNotFound
}

type coreResourceBindingPolicy struct{}

func (coreResourceBindingPolicy) ValidateAuthorizeRequest(ctx context.Context, client *Model, requestResource string) error {
	return nil
}

func (coreResourceBindingPolicy) ValidateTokenRequest(ctx context.Context, clientID, storedResource, requestResource string) error {
	if storedResource != "" {
		if requestResource == "" {
			return &oidc.Error{ErrorType: "invalid_target", Description: "missing resource"}
		}
		if requestResource != storedResource {
			return &oidc.Error{ErrorType: "invalid_target", Description: "resource mismatch"}
		}
		return nil
	}
	if requestResource != "" {
		return &oidc.Error{ErrorType: "invalid_target", Description: "unexpected resource"}
	}
	return nil
}

// NewCoreResourceBindingPolicy preserves the core resource binding checks.
func NewCoreResourceBindingPolicy() ResourceBindingPolicy {
	return coreResourceBindingPolicy{}
}
