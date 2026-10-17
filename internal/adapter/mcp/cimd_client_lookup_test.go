package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/storage"
)

func newStoreForClientLookup() *storage.Storage {
	return storage.New(nil, clock.RealClock{}, idgen.CryptoGenerator{}, nil, time.Minute, time.Hour)
}

func TestGetClientByClientID_YAML(t *testing.T) {
	store := newStoreForClientLookup()
	store.LoadClients([]oauthclient.ConfigEntry{{
		ClientID:          "my-app",
		ClientType:        "public",
		LoginChannel:      "browser",
		Name:              "My App",
		RedirectURIs:      []string{"http://localhost:3000/callback"},
		AllowedScopes:     []string{"openid"},
		AllowedGrantTypes: []string{"authorization_code"},
	}})

	client, err := store.GetClientByClientID(context.Background(), "my-app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != "my-app" {
		t.Errorf("client_id = %q, want %q", client.GetID(), "my-app")
	}
}

func TestGetClientByClientID_NotFound(t *testing.T) {
	store := newStoreForClientLookup()

	_, err := store.GetClientByClientID(context.Background(), "nonexistent")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestGetClientByClientID_CIMD(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := CIMDMetadata{
			ClientID:     serverURL + "/oauth/client.json",
			ClientName:   "CIMD Client",
			RedirectURIs: []string{"http://localhost:3000/callback"},
			GrantTypes:   []string{"authorization_code"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	defer srv.Close()
	serverURL = srv.URL

	store := newStoreForClientLookup()
	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	store.SetClientResolutionPolicy(NewClientResolutionPolicy(store.CoreClientResolver(), fetcher))

	clientID := serverURL + "/oauth/client.json"
	client, err := store.GetClientByClientID(context.Background(), clientID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != clientID {
		t.Errorf("client_id = %q, want %q", client.GetID(), clientID)
	}
}
