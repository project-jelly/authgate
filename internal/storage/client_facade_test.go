package storage

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
)

type clientResolutionPolicyFunc func(context.Context, string) (*oauthclient.Model, error)

func (f clientResolutionPolicyFunc) ResolveClient(ctx context.Context, clientID string) (*oauthclient.Model, error) {
	return f(ctx, clientID)
}

func TestClientFacadeLazilyInitializesAndPreservesOIDCError(t *testing.T) {
	ctx := context.Background()
	var store Storage
	if _, err := store.ResolveClient(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("ResolveClient = %v, want Storage ErrNotFound", err)
	}
	if store.registry == nil {
		t.Fatal("client registry was not initialized")
	}

	_, err := store.GetClientByClientID(ctx, "missing")
	var oidcErr *oidc.Error
	if !errors.As(err, &oidcErr) || oidcErr.ErrorType != "invalid_client" {
		t.Fatalf("GetClientByClientID = %v, want invalid_client", err)
	}

	store.LoadClients([]oauthclient.ConfigEntry{{ClientID: "static", Name: "Static client"}})
	model, err := store.ResolveClient(ctx, "static")
	if err != nil || model == nil || model.Name != "Static client" {
		t.Fatalf("loaded client = (%+v, %v)", model, err)
	}
}

func TestClientFacadeMapsOnlyComponentNotFound(t *testing.T) {
	otherErr := errors.New("client policy failed")
	for name, policyErr := range map[string]error{
		"not found":         oauthclient.ErrNotFound,
		"wrapped not found": fmt.Errorf("lookup: %w", oauthclient.ErrNotFound),
		"other failure":     otherErr,
	} {
		t.Run(name, func(t *testing.T) {
			var store Storage
			store.SetClientResolutionPolicy(clientResolutionPolicyFunc(func(context.Context, string) (*oauthclient.Model, error) {
				return nil, policyErr
			}))
			_, err := store.ResolveClient(context.Background(), "missing")
			if errors.Is(policyErr, oauthclient.ErrNotFound) {
				if err != ErrNotFound {
					t.Fatalf("ResolveClient = %v, want Storage ErrNotFound", err)
				}
			} else if err != policyErr {
				t.Fatalf("ResolveClient = %v, want original %v", err, policyErr)
			}
		})
	}
}

func TestClientFacadeCoreResolverNeverUsesActivePolicy(t *testing.T) {
	ctx := context.Background()
	var store Storage
	core := store.CoreClientResolver()
	store.LoadClients([]oauthclient.ConfigEntry{{ClientID: "static"}})
	calls := 0
	store.SetClientResolutionPolicy(clientResolutionPolicyFunc(func(context.Context, string) (*oauthclient.Model, error) {
		calls++
		return nil, errors.New("dynamic policy must not run")
	}))

	model, err := core.ResolveClient(ctx, "static")
	if err != nil || model == nil || model.ID != "static" {
		t.Fatalf("core static lookup = (%+v, %v)", model, err)
	}
	if _, err := core.ResolveClient(ctx, "https://dynamic.example/client.json"); err != oauthclient.ErrNotFound {
		t.Fatalf("core missing lookup = %v, want component ErrNotFound", err)
	}
	if calls != 0 {
		t.Fatalf("core resolver invoked the active policy %d times", calls)
	}
}
