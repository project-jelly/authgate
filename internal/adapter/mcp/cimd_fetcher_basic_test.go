package mcp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clock"
)

func TestCIMDFetcher_Success(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := CIMDMetadata{
			ClientID:                serverURL + "/oauth/client.json",
			ClientName:              "Test MCP Client",
			RedirectURIs:            []string{"http://localhost:3000/callback"},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "none",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	clientID := serverURL + "/oauth/client.json"

	client, err := fetcher.FetchClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("FetchClient failed: %v", err)
	}
	if client.ID != clientID {
		t.Errorf("client_id = %q, want %q", client.ID, clientID)
	}
	if client.Name != "Test MCP Client" {
		t.Errorf("name = %q, want %q", client.Name, "Test MCP Client")
	}
	if client.LoginChannel != "mcp" {
		t.Errorf("login_channel = %q, want %q", client.LoginChannel, "mcp")
	}
	if client.Type != "public" {
		t.Errorf("type = %q, want %q", client.Type, "public")
	}
	if len(client.RedirectURIList) != 1 || client.RedirectURIList[0] != "http://localhost:3000/callback" {
		t.Errorf("redirect_uris = %v, want [http://localhost:3000/callback]", client.RedirectURIList)
	}
	if len(client.AllowedGrantTypeList) != 2 {
		t.Errorf("grant_types = %v, want 2 entries", client.AllowedGrantTypeList)
	}
}

func TestCIMDFetcher_ClientIDMismatch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := CIMDMetadata{
			ClientID:     "https://wrong.example.com/client.json",
			ClientName:   "Bad Client",
			RedirectURIs: []string{"http://localhost:3000/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	defer srv.Close()

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/oauth/client.json")
	if err == nil {
		t.Fatal("expected error for client_id mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error = %q, want to contain 'mismatch'", err.Error())
	}
}

func TestCIMDFetcher_ServerDown(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	client := srv.Client()
	srv.Close()

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: client, clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), "https://localhost:99999/client.json")
	if err == nil {
		t.Fatal("expected error for server down, got nil")
	}
}

func TestCIMDFetcher_MissingClientName(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":     serverURL + "/client.json",
			"redirect_uris": []string{"http://localhost:3000/callback"},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for missing client_name, got nil")
	}
	if !strings.Contains(err.Error(), "client_name") {
		t.Errorf("error = %q, want to contain 'client_name'", err.Error())
	}
}

func TestCIMDFetcher_HTTP404(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/oauth/client.json")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestCIMDFetcher_InvalidContentType(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	fetcher := &HTTPCIMDFetcher{hosts: anyCIMDHost, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/oauth/client.json")
	if err == nil {
		t.Fatal("expected error for invalid content-type, got nil")
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Errorf("error = %q, want to contain 'Content-Type'", err.Error())
	}
}

func TestIsCIMDClientID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"https://app.example.com/oauth/client.json", true},
		{"https://app.example.com/client", true},
		{"https://app.example.com", false},
		{"https:///oauth/client.json", false},
		{"https://user:pass@app.example.com/client.json", false},
		// A query string is allowed: ChatGPT's CIMD client_id carries
		// `?token_endpoint_auth_method=none` and the document echoes it back, so
		// the exact-match check in fetchAndValidate still holds.
		{"https://app.example.com/client.json?x=1", true},
		{"https://chatgpt.com/oauth/VD94o4JXlMhn/client.json?token_endpoint_auth_method=none", true},
		{"https://app.example.com/client.json#frag", false},
		{"https://app.example.com/client.json?x=1#frag", false},
		{"http://app.example.com/client", false},
		{"my-app", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := oauthclient.IsCIMDClientID(tt.id); got != tt.want {
			t.Errorf("IsCIMDClientID(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.1", true},
		{"169.254.1.1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"::ffff:127.0.0.1", true},
		{"100.64.0.1", true},        // RFC 6598 CGNAT (EKS VPC CNI pod range)
		{"100.127.255.254", true},   // CGNAT upper edge
		{"::ffff:100.64.0.1", true}, // IPv4-mapped CGNAT
		{"192.0.0.10", true},        // RFC 6890 protocol assignments
		{"192.0.2.1", true},         // TEST-NET-1
		{"198.51.100.7", true},      // TEST-NET-2
		{"203.0.113.9", true},       // TEST-NET-3
		{"198.18.0.1", true},        // RFC 2544 benchmarking
		{"224.0.1.1", true},         // multicast (non link-local)
		{"255.255.255.255", true},   // limited broadcast (240/4)
		{"64:ff9b::a00:1", true},    // NAT64-embedded 10.0.0.1
		{"100::1", true},            // discard-only
		{"2001:db8::1", true},       // documentation
		{"8.8.8.8", false},
		{"100.63.255.255", false}, // just below CGNAT
		{"100.128.0.1", false},    // just above CGNAT
		{"2001:4860:4860::8888", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := isPrivateIP(ip); got != tt.want {
			t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
