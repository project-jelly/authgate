package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestAccessTokenRewriteFailsClosed(t *testing.T) {
	for _, body := range []string{`{"access_token":"broken","refresh_token":"secret"}`, `{"access_token":"!.!.!","id_token":"secret"}`, `invalid json`} {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
		rec := httptest.NewRecorder()
		WrapAccessTokenJWTType(next, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/oauth/token", nil))
		if rec.Code != 500 || strings.Contains(rec.Body.String(), "secret") || rec.Body.String() != `{"error":"server_error"}` {
			t.Fatalf("rewrite response: %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestAccessTokenRewriteSigningKeyFailureFailsClosed(t *testing.T) {
	accessToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"subject"}`)) + ".signature"
	const refreshToken = "refresh-token-secret"
	const idToken = "id-token-secret"
	body := `{"access_token":"` + accessToken + `","refresh_token":"` + refreshToken + `","id_token":"` + idToken + `"}`
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
	keys := new(failingSigningKeySource)
	rec := httptest.NewRecorder()

	WrapAccessTokenJWTType(next, keys).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/oauth/token", nil))

	if keys.calls != 1 {
		t.Fatalf("signing key calls = %d, want 1", keys.calls)
	}
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != `{"error":"server_error"}` {
		t.Fatalf("rewrite response: %d %s", rec.Code, rec.Body.String())
	}
	for _, token := range []string{accessToken, refreshToken, idToken} {
		if strings.Contains(rec.Body.String(), token) {
			t.Fatal("rewrite response disclosed a token")
		}
	}
}

type failingSigningKeySource struct {
	calls int
}

func (s *failingSigningKeySource) SigningKey(context.Context) (op.SigningKey, error) {
	s.calls++
	return nil, errors.New("signing key unavailable")
}
