package app

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
	"github.com/kangheeyong/authgate/internal/clientaccess"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/idgen"
)

// Storage defaults the refresh reuse grace to off, so the configured value only
// takes effect through this wiring.
func TestMustBuildStore_AppliesRefreshReuseGrace(t *testing.T) {
	cfg := &config.Config{
		RefreshTokenReuseGrace: 7 * time.Second,
		SigningKeyPath:         filepath.Join(t.TempDir(), "signing_key.pem"),
	}

	store := mustBuildStore(cfg, nil, clock.RealClock{}, idgen.CryptoGenerator{})

	if got := store.RefreshReuseGrace(); got != 7*time.Second {
		t.Fatalf("RefreshReuseGrace = %v, want 7s from config", got)
	}
}

// A client without an access key admits every account, so startup says so
// once per client; "access: public" records the intent and stays quiet.
func TestWarnPublicClients(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	restricted, err := clientaccess.New(clientaccess.Rules{EmailDomains: []string{"example.com"}}, clientaccess.DenyRules{})
	if err != nil {
		t.Fatal(err)
	}
	warnPublicClients([]oauthclient.ConfigEntry{
		{ClientID: "open-a"},
		{ClientID: "explicit", Access: clientaccess.Public()},
		{ClientID: "restricted", Access: restricted},
		{ClientID: "open-b"},
	})

	out := buf.String()
	if n := strings.Count(out, "level=WARN"); n != 2 {
		t.Fatalf("WARN lines = %d, want 2:\n%s", n, out)
	}
	for _, id := range []string{"client_id=open-a", "client_id=open-b"} {
		if !strings.Contains(out, id) {
			t.Fatalf("missing warning for %s:\n%s", id, out)
		}
	}
	if strings.Contains(out, "explicit") || strings.Contains(out, "client_id=restricted") {
		t.Fatalf("warned about a client with an access key:\n%s", out)
	}
}
