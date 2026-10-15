package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/config"
)

type metadataSigningAlgorithms struct{}

func (metadataSigningAlgorithms) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS512}, nil
}

func TestOAuthMetadataRoutes_ShareCapabilitiesAndPreserveProviderDiscovery(t *testing.T) {
	for _, enableMCP := range []bool{false, true} {
		t.Run("MCP="+strconv.FormatBool(enableMCP), func(t *testing.T) {
			cfg := &config.Config{PublicURL: "https://auth.example.com", EnableMCP: enableMCP}
			opConfig := buildOPConfig(cfg)
			opConfig.SupportedClaims = []string{"sub", "custom_claim"}
			provider, err := op.NewProvider(opConfig, nil, op.StaticIssuer(cfg.PublicURL), buildOPOptions(cfg)...)
			if err != nil {
				t.Fatal(err)
			}
			store := metadataSigningAlgorithms{}
			mux := http.NewServeMux()
			registerOAuthMetadataRoutes(mux, cfg, provider, store)

			// Every provider field survives except the two AuthGate policy
			// overrides. This catches accidental loss as the library evolves.
			ctx := op.ContextWithIssuer(context.Background(), cfg.PublicURL)
			base, err := json.Marshal(op.CreateDiscoveryConfig(ctx, provider, store))
			if err != nil {
				t.Fatal(err)
			}
			var expected map[string]any
			if err := json.Unmarshal(base, &expected); err != nil {
				t.Fatal(err)
			}
			expected["response_types_supported"] = []any{"code"}
			expected["grant_types_supported"] = []any{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"}
			expected["authorization_response_iss_parameter_supported"] = true
			expected["client_id_metadata_document_supported"] = enableMCP

			for _, path := range []string{oidc.DiscoveryEndpoint, "/.well-known/oauth-authorization-server"} {
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
				if rec.Code != http.StatusOK {
					t.Fatalf("%s: status = %d", path, rec.Code)
				}
				var document map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &document); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(document, expected) {
					t.Fatalf("%s: metadata = %v, want %v", path, document, expected)
				}
				for field, want := range map[string]string{
					"issuer": cfg.PublicURL, "token_endpoint": cfg.PublicURL + "/oauth/token",
					"device_authorization_endpoint": cfg.PublicURL + "/oauth/device/authorize",
					"revocation_endpoint":           cfg.PublicURL + "/oauth/revoke", "jwks_uri": cfg.PublicURL + "/keys",
				} {
					if document[field] != want {
						t.Errorf("%s: %s = %v, want %s", path, field, document[field], want)
					}
				}
				for field, want := range map[string][]any{
					"code_challenge_methods_supported":              {"S256"},
					"token_endpoint_auth_methods_supported":         {"none", "client_secret_basic", "client_secret_post"},
					"revocation_endpoint_auth_methods_supported":    {"none", "client_secret_basic", "client_secret_post"},
					"introspection_endpoint_auth_methods_supported": {"client_secret_basic"},
					"id_token_signing_alg_values_supported":         {"RS512"},
					"subject_types_supported":                       {"public"}, "claims_supported": {"sub", "custom_claim"},
					"scopes_supported": {"openid", "profile", "email", "offline_access"},
				} {
					if !reflect.DeepEqual(document[field], want) {
						t.Errorf("%s: %s = %v, want %v", path, field, document[field], want)
					}
				}
			}
		})
	}
}
