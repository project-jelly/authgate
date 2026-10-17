package mcp

import (
	"strconv"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	oauthclient "github.com/kangheeyong/authgate/internal/client"
)

// cimdCacheEntry is a positive (client) or negative (err) resolution cached
// until expiresAt.
type cimdCacheEntry struct {
	client    *oauthclient.Model
	err       error
	expiresAt time.Time
}

// cimdCache is the bounded (LRU) positive/negative cache for CIMD resolutions.
// It owns only storage and expiry bookkeeping; the caller supplies the current
// time so the cache stays free of a clock dependency (the fetcher's clock is
// the single source of time, and tests construct the fetcher with a fake one).
type cimdCache struct {
	lru *lru.Cache[string, *cimdCacheEntry]
}

func newCIMDCache(maxEntries int) *cimdCache {
	c, _ := lru.New[string, *cimdCacheEntry](maxEntries)
	return &cimdCache{lru: c}
}

// Lookup returns the cached resolution for clientID if a non-expired entry
// exists as of now. hit reports whether such an entry was found; cachedErr is
// the cached negative result (nil for a positive hit). Expired entries are
// removed and reported as a miss.
func (c *cimdCache) Lookup(clientID string, now time.Time) (client *oauthclient.Model, cachedErr error, hit bool) {
	ce, ok := c.lru.Get(clientID)
	if !ok {
		return nil, nil, false
	}
	if now.Before(ce.expiresAt) {
		return ce.client, ce.err, true
	}
	c.lru.Remove(clientID)
	return nil, nil, false
}

// PutPositive caches a successful resolution until expiresAt.
func (c *cimdCache) PutPositive(clientID string, client *oauthclient.Model, expiresAt time.Time) {
	c.lru.Add(clientID, &cimdCacheEntry{client: client, expiresAt: expiresAt})
}

// PutNegative caches a failed resolution until expiresAt so repeat lookups of a
// failing client_id short-circuit without an outbound call.
func (c *cimdCache) PutNegative(clientID string, err error, expiresAt time.Time) {
	c.lru.Add(clientID, &cimdCacheEntry{err: err, expiresAt: expiresAt})
}

// cacheTTLFromCacheControl derives the positive-cache TTL from a Cache-Control
// header, clamped to [cimdFloorTTL, cimdCeilTTL].
func cacheTTLFromCacheControl(cacheControl string, fallback time.Duration) time.Duration {
	ttl := parseCacheControlTTL(cacheControl, fallback)
	if ttl < cimdFloorTTL {
		return cimdFloorTTL
	}
	if ttl > cimdCeilTTL {
		return cimdCeilTTL
	}
	return ttl
}

// parseCacheControlTTL returns the TTL implied by a Cache-Control header
// without applying the cimdFloorTTL clamp. `no-store`, `no-cache`, and
// `max-age<=0` map to 0; an unparseable header falls back to `fallback`.
func parseCacheControlTTL(cacheControl string, fallback time.Duration) time.Duration {
	if cacheControl == "" {
		return fallback
	}
	directives := strings.Split(cacheControl, ",")
	for _, d := range directives {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "no-store" || d == "no-cache" {
			return 0
		}
		if strings.HasPrefix(d, "max-age=") {
			v := strings.TrimSpace(strings.TrimPrefix(d, "max-age="))
			seconds, err := strconv.ParseInt(v, 10, 64)
			if err != nil || seconds <= 0 {
				return 0
			}
			return time.Duration(seconds) * time.Second
		}
	}
	return fallback
}
