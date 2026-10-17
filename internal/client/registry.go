package client

import (
	"context"
	"log/slog"
	"sync"

	"github.com/kangheeyong/authgate/internal/clientaccess"
)

// Registry owns the in-memory static client table and the active client
// resolution policy (the core in-memory lookup, optionally wrapped by the
// MCP/CIMD fallback).
type Registry struct {
	clients sync.Map // client_id → *Model
	policy  ResolutionPolicy
}

// NewRegistry creates a registry with the core in-memory resolution policy.
func NewRegistry() *Registry {
	r := &Registry{}
	r.policy = coreClientResolutionPolicy{reg: r}
	return r
}

// Load populates the static registry from parsed client config entries.
// URL-form (CIMD-shaped) client_ids are rejected here: ResolveClient consults
// this map before the CIMD fetcher, so admitting a URL-form static entry would
// bypass every CIMDFetcher validation, so we log and skip rather than silently
// admit it.
func (r *Registry) Load(clients []ConfigEntry) {
	for _, c := range clients {
		if IsCIMDClientID(c.ClientID) {
			slog.Warn("LoadClients: dropping URL-form client_id from static registry — use dynamic CIMD resolution instead",
				"client_id", c.ClientID)
			continue
		}
		cm := &Model{
			ID:                       c.ClientID,
			SecretHash:               c.ClientSecretHash,
			Type:                     c.ClientType,
			LoginChannel:             c.LoginChannel,
			Name:                     c.Name,
			URL:                      c.URL,
			RedirectURIList:          c.RedirectURIs,
			AllowedScopeList:         c.AllowedScopes,
			AllowedGrantTypeList:     c.AllowedGrantTypes,
			SkipPKCE:                 c.SkipPKCE,
			IDTokenUserinfoAssertion: c.IDTokenUserinfoAssertion,
			Access:                   c.Access,
		}
		r.clients.Store(c.ClientID, cm)
	}
}

// StaticAccess returns the access policy of a statically registered client,
// or nil. It reads the in-memory table only: callers on the token path hold a
// row lock, and resolving through the policy could fetch a CIMD document over
// the network. CIMD clients are never in this table and have no policy.
func (r *Registry) StaticAccess(clientID string) *clientaccess.Policy {
	v, ok := r.clients.Load(clientID)
	if !ok {
		return nil
	}
	return v.(*Model).Access
}

// StaticLoginChannel returns the login channel of a statically registered
// client, or "".
func (r *Registry) StaticLoginChannel(clientID string) string {
	v, ok := r.clients.Load(clientID)
	if !ok {
		return ""
	}
	return v.(*Model).LoginChannel
}

// StaticName returns the display name of a statically registered client, or "".
func (r *Registry) StaticName(clientID string) string {
	v, ok := r.clients.Load(clientID)
	if !ok {
		return ""
	}
	return v.(*Model).Name
}

// SetPolicy overrides the resolution policy; a nil policy restores the core
// in-memory lookup.
func (r *Registry) SetPolicy(policy ResolutionPolicy) {
	if policy == nil {
		r.policy = coreClientResolutionPolicy{reg: r}
		return
	}
	r.policy = policy
}

// Resolve looks up a client through the active policy.
func (r *Registry) Resolve(ctx context.Context, clientID string) (*Model, error) {
	if r.policy == nil {
		r.policy = coreClientResolutionPolicy{reg: r}
	}
	return r.policy.ResolveClient(ctx, clientID)
}

// StaticRefreshGraceAllowed never resolves clients over the network while a
// grant transaction holds locks. Dynamic/public clients use strict rotation.
func (r *Registry) StaticRefreshGraceAllowed(clientID string) bool {
	value, ok := r.clients.Load(clientID)
	if !ok {
		return false
	}
	client := value.(*Model)
	return client.Type == "confidential" && client.SecretHash != nil && *client.SecretHash != ""
}

// CoreResolver returns a policy that reads only the static client table.
// It can be wrapped by an optional dynamic resolution policy without making
// that wrapper recurse through the active policy.
func (r *Registry) CoreResolver() ResolutionPolicy {
	return coreClientResolutionPolicy{reg: r}
}
