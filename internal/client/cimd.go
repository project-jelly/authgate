package client

import (
	"context"
	"net/url"
	"strings"
)

// CIMDFetcher fetches and validates CIMD (Client ID Metadata Document) clients.
type CIMDFetcher interface {
	FetchClient(ctx context.Context, clientID string) (*Model, error)
}

func isCIMDClientID(clientID string) bool {
	// ParseRequestURI doesn't parse fragments, check raw string
	if strings.Contains(clientID, "#") {
		return false
	}
	u, err := url.ParseRequestURI(clientID)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	if u.Host == "" || u.Hostname() == "" {
		return false
	}
	if u.User != nil {
		return false
	}
	if u.Path == "" || u.Path == "/" {
		return false
	}
	// A query string is permitted: some CIMD providers (e.g. ChatGPT) serve a
	// self-referential document whose `client_id` includes the query (such as
	// `?token_endpoint_auth_method=none`). The fetcher still enforces an exact
	// `meta.ClientID == clientID` match (query included) and the canonical-key
	// gate preserves the query verbatim, so allowing it adds no alias surface.
	// Fragments stay rejected above because they are never sent to the server.
	return true
}

// IsCIMDClientID reports whether a client_id is a CIMD URL.
func IsCIMDClientID(clientID string) bool {
	return isCIMDClientID(clientID)
}
