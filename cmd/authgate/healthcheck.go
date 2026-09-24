package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// checkHealth probes the running process without loading server configuration
// or opening a database. It also works in images without a shell or wget.
func checkHealth(ctx context.Context, port string) error {
	if port == "" {
		port = "8080"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("healthcheck: invalid PORT %q", port)
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// #nosec G704 -- The host/path are fixed; PORT is parsed and range-checked above.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(n)+"/health", nil)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	// #nosec G704 -- Only loopback is contacted, and redirects are disabled.
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: unexpected HTTP status %d", resp.StatusCode)
	}
	return nil
}
