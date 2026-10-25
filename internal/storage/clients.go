package storage

import (
	"context"
	"errors"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
)

// ensureRegistry lazily initializes the client component so a Storage built
// directly (e.g. in tests via &Storage{}) rather than through New still works.
func (s *Storage) ensureRegistry() *oauthclient.Registry {
	if s.registry == nil {
		s.registry = oauthclient.NewRegistry()
	}
	return s.registry
}

// LoadClients loads parsed client entries into the static registry.
func (s *Storage) LoadClients(clients []oauthclient.ConfigEntry) {
	s.ensureRegistry().Load(clients)
}

// SetClientResolutionPolicy overrides client resolution for op.Storage lookups.
func (s *Storage) SetClientResolutionPolicy(policy oauthclient.ResolutionPolicy) {
	s.ensureRegistry().SetPolicy(policy)
}

// CoreClientResolver exposes only the non-fetching static client lookup.
// Composition code may wrap it with CIMD resolution for authorization while
// keeping token resource checks independent of outbound requests. Unlike the
// Storage facade, this component policy retains client.ErrNotFound.
func (s *Storage) CoreClientResolver() oauthclient.ResolutionPolicy {
	return s.ensureRegistry().CoreResolver()
}

// SetResourceBindingPolicy overrides resource binding validation for authorize/token flows.
func (s *Storage) SetResourceBindingPolicy(policy oauthclient.ResourceBindingPolicy) {
	if policy == nil {
		s.resourcePolicy = oauthclient.NewCoreResourceBindingPolicy()
		return
	}
	s.resourcePolicy = policy
}

// ResolveClient resolves a client through the configured component policy.
// Preserve the Storage sentinel at this facade so OIDC and service callers
// retain their existing unknown-client handling.
func (s *Storage) ResolveClient(ctx context.Context, clientID string) (*oauthclient.Model, error) {
	model, err := s.ensureRegistry().Resolve(ctx, clientID)
	if errors.Is(err, oauthclient.ErrNotFound) {
		return model, ErrNotFound
	}
	return model, err
}

func (s *Storage) staticClientName(clientID string) string {
	return s.ensureRegistry().StaticName(clientID)
}
