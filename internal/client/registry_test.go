package client

import (
	"context"
	"errors"
	"testing"

	"github.com/kangheeyong/authgate/internal/clientaccess"
)

type resolutionPolicyFunc func(context.Context, string) (*Model, error)

func (f resolutionPolicyFunc) ResolveClient(ctx context.Context, clientID string) (*Model, error) {
	return f(ctx, clientID)
}

// Static lookups run while grant transactions hold row locks. A wrapped
// resolution policy must never send those calls to a dynamic client fetcher.
func TestRegistryStaticLookupsBypassResolutionPolicy(t *testing.T) {
	secret := "secret-hash"
	access := &clientaccess.Policy{}
	r := NewRegistry()
	r.Load([]ConfigEntry{
		{
			ClientID:         "static",
			ClientType:       "confidential",
			ClientSecretHash: &secret,
			LoginChannel:     "browser",
			Name:             "Static client",
			Access:           access,
		},
		{ClientID: "public", ClientType: "public"},
	})
	calls := 0
	r.SetPolicy(resolutionPolicyFunc(func(context.Context, string) (*Model, error) {
		calls++
		return nil, errors.New("dynamic lookup must not run")
	}))

	if got := r.StaticAccess("static"); got != access {
		t.Fatalf("StaticAccess = %p, want %p", got, access)
	}
	if got := r.StaticLoginChannel("static"); got != "browser" {
		t.Fatalf("StaticLoginChannel = %q, want browser", got)
	}
	if got := r.StaticName("static"); got != "Static client" {
		t.Fatalf("StaticName = %q, want Static client", got)
	}
	if !r.StaticRefreshGraceAllowed("static") {
		t.Fatal("confidential static client lost refresh reuse grace eligibility")
	}
	if r.StaticRefreshGraceAllowed("public") {
		t.Fatal("public client gained refresh reuse grace eligibility")
	}
	for _, clientID := range []string{"missing", "https://dynamic.example/client.json"} {
		if r.StaticAccess(clientID) != nil || r.StaticLoginChannel(clientID) != "" || r.StaticName(clientID) != "" || r.StaticRefreshGraceAllowed(clientID) {
			t.Fatalf("static lookup found unregistered client %q", clientID)
		}
	}
	if calls != 0 {
		t.Fatalf("static lookups invoked the active policy %d times", calls)
	}
}

// A dynamic wrapper needs a stable core lookup independent of the active
// policy; using Resolve itself here would recurse after SetPolicy.
func TestRegistryCoreResolverAndPolicyReset(t *testing.T) {
	ctx := context.Background()
	r := NewRegistry()
	r.Load([]ConfigEntry{{ClientID: "static"}})
	core := r.CoreResolver()
	calls := 0
	r.SetPolicy(resolutionPolicyFunc(func(ctx context.Context, clientID string) (*Model, error) {
		calls++
		return core.ResolveClient(ctx, clientID)
	}))

	resolved, err := r.Resolve(ctx, "static")
	if err != nil || resolved == nil || resolved.ID != "static" || calls != 1 {
		t.Fatalf("wrapped static lookup = (%+v, %v), calls = %d", resolved, err, calls)
	}
	if _, err := core.ResolveClient(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("missing core lookup = %v, want ErrNotFound", err)
	}
	if calls != 1 {
		t.Fatalf("core lookup invoked the active policy, calls = %d", calls)
	}

	r.SetPolicy(nil)
	if _, err := r.Resolve(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("missing lookup after policy reset = %v, want ErrNotFound", err)
	}
	if calls != 1 {
		t.Fatalf("reset policy invoked the old wrapper, calls = %d", calls)
	}
}
