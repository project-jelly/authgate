package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
)

type fakeClientPolicy struct {
	client *oauthclient.Model
	err    error
}

func (f fakeClientPolicy) ResolveClient(ctx context.Context, clientID string) (*oauthclient.Model, error) {
	return f.client, f.err
}

type fakeFetcher struct {
	client *oauthclient.Model
	err    error
	calls  int
}

func (f *fakeFetcher) FetchClient(ctx context.Context, clientID string) (*oauthclient.Model, error) {
	f.calls++
	return f.client, f.err
}

type fakeResourcePolicy struct {
	authorizeErr error
	tokenErr     error
	authCalls    int
	tokenCalls   int
}

func (f *fakeResourcePolicy) ValidateAuthorizeRequest(ctx context.Context, client *oauthclient.Model, requestResource string) error {
	f.authCalls++
	return f.authorizeErr
}

func (f *fakeResourcePolicy) ValidateTokenRequest(ctx context.Context, clientID, storedResource, requestResource string) error {
	f.tokenCalls++
	return f.tokenErr
}

func TestClientResolutionPolicy_UsesBaseFirst(t *testing.T) {
	baseClient := &oauthclient.Model{ID: "my-app"}
	fetcher := &fakeFetcher{client: &oauthclient.Model{ID: "fetched"}}
	p := NewClientResolutionPolicy(fakeClientPolicy{client: baseClient}, fetcher)

	client, err := p.ResolveClient(context.Background(), "my-app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != "my-app" {
		t.Fatalf("client id = %s, want my-app", client.GetID())
	}
	if fetcher.calls != 0 {
		t.Fatalf("fetcher calls = %d, want 0", fetcher.calls)
	}
}

func TestClientResolutionPolicy_FallsBackToCIMD(t *testing.T) {
	fetcher := &fakeFetcher{client: &oauthclient.Model{ID: "https://mcp.example.com/client.json"}}
	p := NewClientResolutionPolicy(fakeClientPolicy{err: oauthclient.ErrNotFound}, fetcher)

	clientID := "https://mcp.example.com/client.json"
	client, err := p.ResolveClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != clientID {
		t.Fatalf("client id = %s, want %s", client.GetID(), clientID)
	}
	if fetcher.calls != 1 {
		t.Fatalf("fetcher calls = %d, want 1", fetcher.calls)
	}
}

func TestClientResolutionPolicy_NoFallbackForNonCIMD(t *testing.T) {
	fetcher := &fakeFetcher{client: &oauthclient.Model{ID: "fetched"}}
	p := NewClientResolutionPolicy(fakeClientPolicy{err: oauthclient.ErrNotFound}, fetcher)

	_, err := p.ResolveClient(context.Background(), "my-app")
	if !errors.Is(err, oauthclient.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
	if fetcher.calls != 0 {
		t.Fatalf("fetcher calls = %d, want 0", fetcher.calls)
	}
}

func TestResourceBindingPolicy_EnforcesMCPResource(t *testing.T) {
	base := &fakeResourcePolicy{}
	p := NewResourceBindingPolicy(base, nil)

	err := p.ValidateAuthorizeRequest(context.Background(), &oauthclient.Model{LoginChannel: "mcp"}, "")
	if err == nil {
		t.Fatal("expected invalid_target error")
	}
	var oidcErr *oidc.Error
	if !errors.As(err, &oidcErr) || oidcErr.ErrorType != "invalid_target" {
		t.Fatalf("error = %v, want oidc invalid_target", err)
	}
	if base.authCalls != 0 {
		t.Fatalf("base auth calls = %d, want 0", base.authCalls)
	}
}

func TestResourceBindingPolicy_DelegatesToBase(t *testing.T) {
	wantErr := errors.New("base authorize denied")
	base := &fakeResourcePolicy{authorizeErr: wantErr}
	p := NewResourceBindingPolicy(base, nil)

	err := p.ValidateAuthorizeRequest(context.Background(), &oauthclient.Model{LoginChannel: "browser"}, "")
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if base.authCalls != 1 {
		t.Fatalf("base auth calls = %d, want 1", base.authCalls)
	}
}

// #184: a browser-channel client passing `resource` must be rejected
// inside the MCP wrapper without delegating to the base policy. This
// closes the boundary-confusion attack where a non-MCP client mints a
// token whose `aud` is an MCP resource URL.
func TestResourceBindingPolicy_RejectsResourceForBrowserClient(t *testing.T) {
	base := &fakeResourcePolicy{}
	p := NewResourceBindingPolicy(base, nil)

	err := p.ValidateAuthorizeRequest(context.Background(), &oauthclient.Model{LoginChannel: "browser"}, "https://mcp.example.com/resource")
	if err == nil {
		t.Fatal("expected invalid_target for browser client with resource")
	}
	var oidcErr *oidc.Error
	if !errors.As(err, &oidcErr) || oidcErr.ErrorType != "invalid_target" {
		t.Fatalf("error = %v, want oidc invalid_target", err)
	}
	if base.authCalls != 0 {
		t.Fatalf("base auth calls = %d, want 0 (must reject before delegation)", base.authCalls)
	}
}

// #184 (legacy data): a refresh token with storedResource minted before
// the channel × resource gate landed must fail closed on first reuse,
// not silently keep minting MCP-aud tokens. The wrapper rejects with
// invalid_grant when the resolver reports a non-MCP login_channel.
func TestResourceBindingPolicy_RejectsLegacyStoredResourceOnNonMCPClient(t *testing.T) {
	base := &fakeResourcePolicy{}
	resolver := fakeClientPolicy{client: &oauthclient.Model{ID: "browser-app", LoginChannel: "browser"}}
	p := NewResourceBindingPolicy(base, resolver)

	err := p.ValidateTokenRequest(context.Background(), "browser-app", "https://mcp.example.com/resource", "")
	if err == nil {
		t.Fatal("expected invalid_grant for stored resource on browser client")
	}
	var oidcErr *oidc.Error
	if !errors.As(err, &oidcErr) || oidcErr.ErrorType != "invalid_grant" {
		t.Fatalf("error = %v, want oidc invalid_grant (legacy data must fail closed)", err)
	}
	if base.tokenCalls != 0 {
		t.Fatalf("base token calls = %d, want 0", base.tokenCalls)
	}
}

func TestResourceBindingPolicy_TokenDelegatesToBase(t *testing.T) {
	wantErr := errors.New("base token denied")
	base := &fakeResourcePolicy{tokenErr: wantErr}
	p := NewResourceBindingPolicy(base, nil)

	err := p.ValidateTokenRequest(context.Background(), "c1", "r1", "r1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if base.tokenCalls != 1 {
		t.Fatalf("base token calls = %d, want 1", base.tokenCalls)
	}
}
