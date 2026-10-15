package app

import (
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

	mcpadapter "github.com/kangheeyong/authgate/internal/adapter/mcp"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/middleware"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/storage"
)

// newStateChecker adapts the account state-machine policy (owned by the
// service layer, ADR-000) into the func Storage expects. The "active" rule
// lives in service.IsActive, not inline in this composition root.
func newStateChecker() func(*storage.User) error {
	return func(user *storage.User) error {
		if !service.IsActive(user.Status) {
			return fmt.Errorf("account not active: %s", user.Status)
		}
		return nil
	}
}

func mustBuildStore(cfg *config.Config, db *sql.DB, clk clock.Clock, gen idgen.CryptoGenerator) *storage.Storage {
	store := storage.New(db, clk, gen, newStateChecker(), cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	store.SetDevicePollInterval(devicePollInterval)
	store.SetRefreshReuseGrace(cfg.RefreshTokenReuseGrace)
	mustConfigureSigningKey(cfg, store)
	configureMCPPoliciesIfEnabled(cfg, store)
	return store
}

func mustConfigureSigningKey(cfg *config.Config, store *storage.Storage) {
	if err := configureSigningKey(cfg, store); err != nil {
		log.Fatalf("signing key: %v", err)
	}
}

func configureSigningKey(cfg *config.Config, store *storage.Storage) error {
	for _, path := range []struct{ name, value string }{
		{"SIGNING_KEY_PATH", cfg.SigningKeyPath},
		{"SIGNING_KEY_BUNDLE_PATH", cfg.SigningKeyBundlePath},
	} {
		if path.value != "" && strings.TrimSpace(path.value) == "" {
			return fmt.Errorf("%s must not contain only whitespace", path.name)
		}
	}
	if cfg.SigningKeyBundlePath != "" {
		if cfg.SigningKeyPath != "" {
			return fmt.Errorf("SIGNING_KEY_BUNDLE_PATH and SIGNING_KEY_PATH cannot both be set")
		}
		bundle, err := storage.LoadSigningKeyBundle(cfg.SigningKeyBundlePath)
		if err != nil {
			return fmt.Errorf("load signing key bundle: %w", err)
		}
		store.SetSigningKeyBundle(bundle)
		slog.Info("signing key bundle loaded", "signing_keys", bundle)
		warnSigningKeyHistory(bundle.KeyCount())
		return nil
	}
	if cfg.SigningKeyPath == "" {
		return fmt.Errorf("SIGNING_KEY_PATH is required when no signing key bundle is configured")
	}
	key, err := storage.LoadOrGenerateKey(cfg.SigningKeyPath)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}
	store.SetSigningKey(key, "authgate-key-1")
	return nil
}

func warnSigningKeyHistory(count int) {
	if count >= 96 {
		slog.Warn("signing key history nearing capacity", "key_count", count, "key_limit", 128)
	}
}

func loadClientConfigIfPresent(cfg *config.Config, store *storage.Storage) []string {
	if cfg.ClientConfigPath == "" {
		return nil
	}

	clientCfg, err := storage.LoadClientConfig(cfg.ClientConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("client config not found, skipping", "path", cfg.ClientConfigPath)
			return nil
		}
		log.Fatalf("client config: %v", err)
	}
	if err := storage.ValidateClientChannels(clientCfg.Clients, cfg.EnableMCP); err != nil {
		log.Fatalf("client config: %v", err)
	}
	store.LoadClients(clientCfg.Clients)
	slog.Info("client config loaded", "path", cfg.ClientConfigPath, "count", len(clientCfg.Clients))
	warnPublicClients(clientCfg.Clients)

	// Collect allowed CORS origins from all client redirect URIs.
	var allURIs []string
	for _, c := range clientCfg.Clients {
		allURIs = append(allURIs, c.RedirectURIs...)
	}
	return middleware.OriginsFromRedirectURIs(allURIs)
}

// warnPublicClients logs each client with no access key. Such a client admits
// every authgate account; writing "access: public" records that as intended and
// silences the warning.
func warnPublicClients(clients []storage.ClientConfigEntry) {
	for _, c := range clients {
		if c.Access == nil {
			slog.Warn("client has no access policy; every authgate account can use it", "client_id", c.ClientID)
		}
	}
}

func configureMCPPoliciesIfEnabled(cfg *config.Config, store *storage.Storage) {
	if !cfg.EnableMCP {
		return
	}
	hosts := cfg.MCPCIMDHostAllowlist
	if hosts == nil {
		hosts = mcpadapter.DefaultCIMDHosts
	}
	hostPolicy, err := mcpadapter.NewCIMDHostPolicy(hosts)
	if err != nil {
		log.Fatalf("MCP_CIMD_HOST_ALLOWLIST: %v", err)
	}
	cimdFetcher := mcpadapter.NewHTTPCIMDFetcher(hostPolicy)
	coreResolver := storage.NewCoreClientResolutionPolicy(store)
	// General client resolution (e.g. /authorize) may fetch CIMD documents.
	clientPolicy := mcpadapter.NewClientResolutionPolicy(coreResolver, cimdFetcher)
	store.SetClientResolutionPolicy(clientPolicy)
	// The resource-binding policy's token-endpoint check only needs the
	// locally-known login_channel (browser clients are always in the local
	// registry), so give it the NON-fetching core resolver — never trigger an
	// outbound CIMD HTTP fetch on the hot /oauth/token path.
	store.SetResourceBindingPolicy(mcpadapter.NewResourceBindingPolicy(storage.NewCoreResourceBindingPolicy(), coreResolver))
}
