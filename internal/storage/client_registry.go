package storage

import (
	"context"
	"log/slog"
	"sync"

	"github.com/kangheeyong/authgate/internal/clientaccess"
)

// clientRegistry owns the in-memory static client table and the active client
// resolution policy (the core in-memory lookup, optionally wrapped by the
// MCP/CIMD fallback). Storage holds one and delegates its client lookups here,
// keeping the registry out of the Storage adapter (#301).
type clientRegistry struct {
	clients sync.Map // client_id → *ClientModel
	policy  ClientResolutionPolicy
}

func newClientRegistry() *clientRegistry {
	r := &clientRegistry{}
	r.policy = coreClientResolutionPolicy{reg: r}
	return r
}

// Load populates the static registry from parsed client config entries.
// URL-form (CIMD-shaped) client_ids are rejected here: ResolveClient consults
// this map before the CIMD fetcher, so admitting a URL-form static entry would
// bypass every CIMDFetcher validation, so we log and skip rather than silently
// admit it.
func (r *clientRegistry) Load(clients []ClientConfigEntry) {
	for _, c := range clients {
		if IsCIMDClientID(c.ClientID) {
			slog.Warn("LoadClients: dropping URL-form client_id from static registry — use dynamic CIMD resolution instead",
				"client_id", c.ClientID)
			continue
		}
		cm := &ClientModel{
			ID:                       c.ClientID,
			SecretHash:               c.ClientSecretHash,
			Type:                     c.ClientType,
			LoginChannel:             c.LoginChannel,
			Name:                     c.Name,
			URL:                      c.URL,
			RedirectURIList:          StringArray(c.RedirectURIs),
			AllowedScopeList:         StringArray(c.AllowedScopes),
			AllowedGrantTypeList:     StringArray(c.AllowedGrantTypes),
			AllowedResourceList:      StringArray(c.AllowedResources),
			SkipPKCE:                 c.SkipPKCE,
			IDTokenUserinfoAssertion: c.IDTokenUserinfoAssertion,
			Access:                   c.Access,
		}
		r.clients.Store(c.ClientID, cm)
	}
}

// staticAccess returns the access policy of a statically registered client,
// or nil. It reads the in-memory table only: callers on the token path hold a
// row lock, and resolving through the policy could fetch a CIMD document over
// the network. CIMD clients are never in this table and have no policy.
func (r *clientRegistry) staticAccess(clientID string) *clientaccess.Policy {
	v, ok := r.clients.Load(clientID)
	if !ok {
		return nil
	}
	return v.(*ClientModel).Access
}

// staticLoginChannel returns the login channel of a statically registered
// client, or "".
func (r *clientRegistry) staticLoginChannel(clientID string) string {
	v, ok := r.clients.Load(clientID)
	if !ok {
		return ""
	}
	return v.(*ClientModel).LoginChannel
}

// staticName returns the display name of a statically registered client, or "".
func (r *clientRegistry) staticName(clientID string) string {
	v, ok := r.clients.Load(clientID)
	if !ok {
		return ""
	}
	return v.(*ClientModel).Name
}

// SetPolicy overrides the resolution policy; a nil policy restores the core
// in-memory lookup.
func (r *clientRegistry) SetPolicy(policy ClientResolutionPolicy) {
	if policy == nil {
		r.policy = coreClientResolutionPolicy{reg: r}
		return
	}
	r.policy = policy
}

// Resolve looks up a client through the active policy.
func (r *clientRegistry) Resolve(ctx context.Context, clientID string) (*ClientModel, error) {
	if r.policy == nil {
		r.policy = coreClientResolutionPolicy{reg: r}
	}
	return r.policy.ResolveClient(ctx, clientID)
}

func (s *Storage) staticClientName(clientID string) string {
	return s.ensureRegistry().staticName(clientID)
}

// staticRefreshGraceAllowed never resolves clients over the network while a
// grant transaction holds locks. Dynamic/public clients use strict rotation.
func (r *clientRegistry) staticRefreshGraceAllowed(clientID string) bool {
	value, ok := r.clients.Load(clientID)
	if !ok {
		return false
	}
	client := value.(*ClientModel)
	return client.Type == "confidential" && client.SecretHash != nil && *client.SecretHash != ""
}
