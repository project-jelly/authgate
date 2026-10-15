package app

import (
	"encoding/json"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/config"
)

// Both discovery entry points describe the same server. Start with the
// provider's complete document so endpoints, signing algorithms and OIDC
// capabilities remain owned by zitadel/oidc; narrow only AuthGate's policy.
func registerOAuthMetadataRoutes(mux *http.ServeMux, cfg *config.Config, provider op.Configuration, store op.DiscoverStorage) {
	metadata := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := op.ContextWithIssuer(r.Context(), cfg.PublicURL)
		discovery := op.CreateDiscoveryConfig(ctx, provider, store)
		discovery.ResponseTypesSupported = []string{string(oidc.ResponseTypeCode)}
		discovery.GrantTypesSupported = []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeDeviceCode}

		// v3.51.14 has no RFC 9207 discovery field. The explicit CIMD field
		// also preserves false when MCP is disabled (the library omits it).
		document := struct {
			*oidc.DiscoveryConfiguration
			AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
			ClientIDMetadataDocumentSupported          bool `json:"client_id_metadata_document_supported"`
		}{discovery, true, cfg.EnableMCP}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(document)
	})
	mux.Handle("/.well-known/oauth-authorization-server", metadata)
	mux.Handle(oidc.DiscoveryEndpoint, metadata)
}
