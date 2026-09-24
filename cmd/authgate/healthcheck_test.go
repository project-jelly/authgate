package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckHealth(t *testing.T) {
	for _, code := range []int{http.StatusOK, http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/health" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Location", "/unexpected-redirect")
				w.WriteHeader(code)
			}))
			defer srv.Close()
			_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if err := checkHealth(context.Background(), port); (err == nil) != (code == http.StatusOK) {
				t.Fatalf("status %d: healthcheck error = %v", code, err)
			}
		})
	}
}

func TestCheckHealthRejectsInvalidPort(t *testing.T) {
	for _, port := range []string{"0", "-1", "65536", "invalid", "8080/other"} {
		if err := checkHealth(context.Background(), port); err == nil {
			t.Errorf("accepted invalid PORT %q", port)
		}
	}
}

func TestCheckHealthUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if err := checkHealth(context.Background(), port); err == nil {
		t.Fatal("accepted an unavailable server")
	}
}

func TestCheckHealthCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkHealth(ctx, ""); err == nil {
		t.Fatal("accepted a canceled probe")
	}
}
