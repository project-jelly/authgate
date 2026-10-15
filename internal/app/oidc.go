package app

import (
	"context"
	"crypto/sha256"
	"log"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

func mustBuildOIDCProvider(cfg *config.Config, store *storage.Storage) *op.Provider {
	provider, err := buildOIDCProvider(cfg, store)
	if err != nil {
		log.Fatalf("oidc provider: %v", err)
	}
	return provider
}

func buildOIDCProvider(cfg *config.Config, store *storage.Storage) (*op.Provider, error) {
	opts := buildOPOptions(cfg)
	if hintKeys := store.IDTokenHintKeySet(); hintKeys != nil {
		opts = append(opts,
			op.WithIDTokenHintKeySet(hintKeys),
			op.WithIDTokenHintVerifierOpts(op.WithSupportedIDTokenHintSigningAlgorithms("RS256")),
		)
	}
	return op.NewProvider(
		buildOPConfig(cfg),
		store,
		op.StaticIssuer(cfg.PublicURL),
		opts...,
	)
}

// supportedScopes feeds the provider config and, through its discovery
// document, both OIDC and OAuth authorization-server metadata.
var supportedScopes = []string{"openid", "profile", "email", "offline_access"}

func buildOPConfig(cfg *config.Config) *op.Config {
	cryptoKey := sha256.Sum256([]byte(cfg.SessionSecret))
	return &op.Config{
		CryptoKey:             cryptoKey,
		CodeMethodS256:        true,
		AuthMethodPost:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       supportedScopes,
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: devicePollInterval,
			UserFormPath: "/device",
			UserCode: op.UserCodeConfig{
				CharSet:      "BCDFGHJKLMNPQRSTVWXZ",
				CharAmount:   8,
				DashInterval: 4,
			},
		},
	}
}

func buildOPOptions(cfg *config.Config) []op.Option {
	opts := []op.Option{}
	if cfg.DevMode {
		opts = append(opts, op.WithAllowInsecure())
	}
	opts = append(opts,
		op.WithCustomTokenEndpoint(op.NewEndpoint("oauth/token")),
		op.WithCustomRevocationEndpoint(op.NewEndpoint("oauth/revoke")),
		op.WithCustomDeviceAuthorizationEndpoint(op.NewEndpoint("oauth/device/authorize")),
	)
	return opts
}

func buildUpstreamOptions(cfg *config.Config) []upstream.Option {
	opts := []upstream.Option{}
	if cfg.OIDCInternalURL != "" {
		opts = append(opts, upstream.WithInternalURL(cfg.OIDCInternalURL))
	}
	opts = append(opts, upstream.WithHTTPTimeout(cfg.OIDCHTTPTimeout))
	opts = append(opts, upstream.WithCookieSecret(cfg.SessionSecret, !cfg.DevMode))
	return opts
}

func mustBuildUpstreamProvider(ctx context.Context, cfg *config.Config, callbackPath string, upstreamOpts []upstream.Option) upstream.Provider {
	p, err := upstream.NewOIDCProvider(
		ctx,
		cfg.OIDCIssuerURL,
		cfg.OIDCClientID,
		cfg.OIDCClientSecret,
		cfg.PublicURL+callbackPath,
		upstreamOpts...,
	)
	if err != nil {
		log.Fatalf("upstream provider (%s): %v", callbackPath, err)
	}
	return p
}
