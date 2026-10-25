package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

func TestCIMDFetcher_UnsupportedAuthMethod(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  serverURL + "/client.json",
			"client_name":                "Bad Auth",
			"redirect_uris":              []string{"http://localhost:3000/callback"},
			"token_endpoint_auth_method": "client_secret_post",
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for unsupported auth method, got nil")
	}
	if !strings.Contains(err.Error(), "token_endpoint_auth_method") {
		t.Errorf("error = %q, want to contain 'token_endpoint_auth_method'", err.Error())
	}
}

func TestCIMDFetcher_UnsupportedResponseType(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":      serverURL + "/client.json",
			"client_name":    "Bad RT",
			"redirect_uris":  []string{"http://localhost:3000/callback"},
			"response_types": []string{"token"},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for unsupported response_type, got nil")
	}
	if !strings.Contains(err.Error(), "response_type") {
		t.Errorf("error = %q, want to contain 'response_type'", err.Error())
	}
}

func TestCIMDFetcher_OversizedDocument(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write 11KB of padding
		w.Write([]byte(`{"client_id":"x","padding":"`))
		for i := 0; i < 11*1024; i++ {
			w.Write([]byte("a"))
		}
		w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/client.json")
	if err == nil {
		t.Fatal("expected error for oversized document, got nil")
	}
	if !strings.Contains(err.Error(), "10KB") {
		t.Errorf("error = %q, want to contain '10KB'", err.Error())
	}
}

func TestCIMDFetcher_GrantTypesMustIncludeAuthorizationCode(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":     serverURL + "/client.json",
			"client_name":   "Bad Grant",
			"redirect_uris": []string{"http://localhost:3000/callback"},
			"grant_types":   []string{"client_credentials"},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for grant_types without authorization_code, got nil")
	}
	if !strings.Contains(err.Error(), "authorization_code") {
		t.Errorf("error = %q, want to contain 'authorization_code'", err.Error())
	}
}

func TestCIMDFetcher_IgnoresUnsupportedAdditionalGrantTypes(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  serverURL + "/client.json",
			"client_name":                "Claude",
			"redirect_uris":              []string{"https://claude.ai/api/mcp/auth_callback"},
			"grant_types":                []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"response_types":             []string{"code"},
			"token_endpoint_auth_method": "none",
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	client, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err != nil {
		t.Fatalf("FetchClient failed: %v", err)
	}
	want := []string{"authorization_code", "refresh_token"}
	if !reflect.DeepEqual(client.AllowedGrantTypeList, want) {
		t.Fatalf("grant_types = %v, want %v", client.AllowedGrantTypeList, want)
	}
}

func TestCIMDFetcher_ClientNameTooLong(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":     serverURL + "/client.json",
			"client_name":   strings.Repeat("a", maxCIMDClientNameLength+1),
			"redirect_uris": []string{"http://localhost:3000/callback"},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for too long client_name, got nil")
	}
	if !strings.Contains(err.Error(), "client_name exceeds") {
		t.Errorf("error = %q, want to contain 'client_name exceeds'", err.Error())
	}
}

func TestCIMDFetcher_TooManyRedirectURIs(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURIs := make([]string, maxCIMDRedirectURICount+1)
		for i := range redirectURIs {
			redirectURIs[i] = fmt.Sprintf("http://localhost:%d/callback", 3000+i)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":     serverURL + "/client.json",
			"client_name":   "Too Many Redirects",
			"redirect_uris": redirectURIs,
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for too many redirect_uris, got nil")
	}
	if !strings.Contains(err.Error(), "redirect_uris exceeds") {
		t.Errorf("error = %q, want to contain 'redirect_uris exceeds'", err.Error())
	}
}

func TestCIMDFetcher_RedirectURITooLong(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":     serverURL + "/client.json",
			"client_name":   "Long Redirect",
			"redirect_uris": []string{"http://localhost/" + strings.Repeat("a", maxCIMDRedirectURILength)},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for too long redirect_uri, got nil")
	}
	if !strings.Contains(err.Error(), "redirect_uri exceeds") {
		t.Errorf("error = %q, want to contain 'redirect_uri exceeds'", err.Error())
	}
}

func TestCIMDFetcher_TooManyGrantTypes(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grantTypes := make([]string, maxCIMDGrantTypeCount+1)
		for i := range grantTypes {
			grantTypes[i] = fmt.Sprintf("urn:example:grant:%d", i)
		}
		grantTypes[0] = "authorization_code"

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":     serverURL + "/client.json",
			"client_name":   "Too Many Grants",
			"redirect_uris": []string{"http://localhost:3000/callback"},
			"grant_types":   grantTypes,
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for too many grant_types, got nil")
	}
	if !strings.Contains(err.Error(), "grant_types exceeds") {
		t.Errorf("error = %q, want to contain 'grant_types exceeds'", err.Error())
	}
}

func TestCIMDFetcher_TooManyResponseTypes(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":      serverURL + "/client.json",
			"client_name":    "Too Many RT",
			"redirect_uris":  []string{"http://localhost:3000/callback"},
			"response_types": []string{"code", "code"},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for too many response_types, got nil")
	}
	if !strings.Contains(err.Error(), "response_types exceeds") {
		t.Errorf("error = %q, want to contain 'response_types exceeds'", err.Error())
	}
}

func TestCIMDFetcher_RedirectRejected(t *testing.T) {
	// Target server that the redirect points to
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"client_id":"x","client_name":"x","redirect_uris":["http://localhost:3000/callback"]}`))
	}))
	defer target.Close()

	// Server that redirects to target
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/client.json", http.StatusFound)
	}))
	defer srv.Close()

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost,
		client:   srv.Client(),
		clock:    clock.RealClock{},
		cacheTTL: 5 * time.Minute,
	}
	// CheckRedirect is only set in NewHTTPCIMDFetcher, so set it manually for test
	fetcher.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("cimd: redirects not allowed")
	}

	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/client.json")
	if err == nil {
		t.Fatal("expected error for redirect, got nil")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("error = %q, want to contain 'redirect'", err.Error())
	}
}

// ChatGPT requests with a query-string client_id (?token_endpoint_auth_method=none)
// while its published document carries the client_id without the query. The
// fetch must succeed and the requested (query-full) client_id must stay the
// client identity so authorize/token lookups remain consistent.
func TestCIMDFetcher_QueryClientIDAcceptsQuerylessDocument(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":     serverURL + "/client.json",
			"client_name":   "ChatGPT",
			"redirect_uris": []string{"https://chatgpt.com/connector/oauth/cb"},
			"grant_types":   []string{"authorization_code", "refresh_token"},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	requested := serverURL + "/client.json?token_endpoint_auth_method=none"
	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	client, err := fetcher.FetchClient(context.Background(), requested)
	if err != nil {
		t.Fatalf("FetchClient() error = %v, want nil", err)
	}
	if client.ID != requested {
		t.Errorf("client.ID = %q, want requested client_id %q", client.ID, requested)
	}
}

// A document whose client_id differs beyond the query string (different path)
// must still be rejected even when the request carries a query.
func TestCIMDFetcher_ClientIDPathMismatchRejected(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":     serverURL + "/other.json",
			"client_name":   "Impostor",
			"redirect_uris": []string{"https://example.com/cb"},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json?token_endpoint_auth_method=none")
	if err == nil {
		t.Fatal("expected client_id mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "client_id mismatch") {
		t.Errorf("error = %q, want to contain 'client_id mismatch'", err.Error())
	}
}
