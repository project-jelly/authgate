package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// WrapAccessTokenJWTType wraps the OIDC token endpoint and normalizes the
// JWT access token profile: it rewrites the JOSE `typ` header to `at+jwt`
// per RFC 9068 §2.1 and mirrors the token response scope into the JWT `scope`
// claim when the upstream library omits it.
// zitadel/oidc's signer is hardcoded to `typ=JWT` for both access
// tokens and id_tokens (pkg/op/signer.go SignerFromKey), and the library
// exposes no public hook to override this for a single token type. This
// middleware captures the JSON response on the way out, re-signs the
// access_token JWT with our same key but the correct profile typ, and
// passes the response on. The id_token keeps `typ=JWT` per OIDC Core 1.0
// (§2), but because re-signing the access_token changes its string and the
// id_token's `at_hash` is bound to that string (§3.1.3.6), the id_token is
// re-signed with a recomputed `at_hash` so strict OIDC clients don't reject
// the response.
//
// Rewrite failure returns server_error without disclosing any tokens. A grant
// already committed by the provider stays consumed; signing is outside its DB tx.
func WrapAccessTokenJWTType(inner http.Handler, store *Storage) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := newCaptureRW(w)
		inner.ServeHTTP(rec, r)

		body := rec.body.Bytes()
		if rec.code == http.StatusOK && len(body) > 0 {
			upgraded, err := upgradeAccessTokenTyp(r.Context(), store, body)
			switch err {
			case nil:
				body = upgraded
			default:
				slog.ErrorContext(r.Context(), "access token profile rewrite failed", "error", err)
				rec.code = http.StatusInternalServerError
				body = []byte(`{"error":"server_error"}`)
				rec.Header().Set("Content-Type", "application/json")

			}
		}

		for k, vs := range rec.Header() {
			w.Header()[k] = vs
		}
		// Strip any content-integrity headers zitadel may have set against
		// the original body — they would now be inconsistent.
		w.Header().Del("ETag")
		w.Header().Del("Content-Digest")
		w.Header().Del("Repr-Digest")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(rec.code)
		_, _ = w.Write(body)
	})
}

// upgradeAccessTokenTyp parses a token-endpoint JSON response, locates
// the `access_token` field, and if it is a compact JWS, re-signs the payload
// with typ=at+jwt using the storage's signing key. It also adds a JWT `scope`
// claim from the token response when one is available and missing from the
// access token. Returns the modified body or an error; errors must never release the original tokens.
func upgradeAccessTokenTyp(ctx context.Context, store *Storage, body []byte) ([]byte, error) {
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	rawAT, ok := resp["access_token"]
	if !ok {
		return nil, errSkipUpgrade
	}
	var token string
	if err := json.Unmarshal(rawAT, &token); err != nil {
		return nil, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errSkipUpgrade
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, err
	}
	resource := ResourceFromContext(ctx)
	if typ, _ := header["typ"].(string); typ == "at+jwt" && resource == "" {
		return body, nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	payload, err = withScopeClaim(payload, resp)
	if err != nil {
		return nil, err
	}
	payload, err = withResourceAudience(payload, resource)
	if err != nil {
		return nil, err
	}

	sk, err := store.SigningKey(ctx)
	if err != nil {
		return nil, err
	}
	rewritten, err := signJWS(sk, payload, "at+jwt")
	if err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(rewritten)
	if err != nil {
		return nil, err
	}
	resp["access_token"] = encoded

	// Re-signing the access_token changed its string, so the id_token's
	// at_hash (which zitadel computed over the pre-rewrite token) is stale.
	// Recompute it over the rewritten token and re-sign the id_token, else
	// strict OIDC clients reject the response on at_hash mismatch.
	if err := rebindIDTokenAtHash(sk, resp, rewritten); err != nil {
		return nil, err
	}

	return json.Marshal(resp)
}

// rebindIDTokenAtHash recomputes the id_token's at_hash claim against the
// rewritten access_token and re-signs the id_token (preserving typ=JWT and
// every other claim). It is a no-op when the response has no id_token or the
// id_token carries no at_hash claim. The body is only mutated on success.
func rebindIDTokenAtHash(sk op.SigningKey, resp map[string]json.RawMessage, accessToken string) error {
	rawIDT, ok := resp["id_token"]
	if !ok {
		return nil
	}
	var idToken string
	if err := json.Unmarshal(rawIDT, &idToken); err != nil {
		return err
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return err
	}
	if _, ok := claims["at_hash"]; !ok {
		return nil
	}

	atHash, err := oidc.ClaimHash(accessToken, sk.SignatureAlgorithm())
	if err != nil {
		return err
	}
	claims["at_hash"] = atHash

	repacked, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	resigned, err := signJWS(sk, repacked, "JWT")
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(resigned)
	if err != nil {
		return err
	}
	resp["id_token"] = encoded
	return nil
}

// signJWS signs a JWT payload with the storage signing key under the given
// JOSE typ header and returns the compact serialization.
func signJWS(sk op.SigningKey, payload []byte, typ string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: sk.SignatureAlgorithm(),
		Key: &jose.JSONWebKey{
			Key:   sk.Key(),
			KeyID: sk.ID(),
		},
	}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

func withResourceAudience(payload []byte, resource string) ([]byte, error) {
	if resource == "" {
		return payload, nil
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	claims["aud"] = resource
	return json.Marshal(claims)
}

func withScopeClaim(payload []byte, tokenResponse map[string]json.RawMessage) ([]byte, error) {
	rawScope, ok := tokenResponse["scope"]
	if !ok {
		return payload, nil
	}
	var scope string
	if err := json.Unmarshal(rawScope, &scope); err != nil {
		return nil, err
	}
	if strings.TrimSpace(scope) == "" {
		return payload, nil
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	if existing, ok := claims["scope"].(string); ok && strings.TrimSpace(existing) != "" {
		return payload, nil
	}
	claims["scope"] = scope
	return json.Marshal(claims)
}

// errSkipUpgrade signals that the response is not eligible for typ
// rewriting (e.g. no access_token field, or not a compact JWS). It is a
// non-failure condition.
var errSkipUpgrade = &jwtUpgradeSkip{}

type jwtUpgradeSkip struct{}

func (*jwtUpgradeSkip) Error() string { return "access_token typ upgrade skipped" }

// captureRW buffers the entire response so the middleware can inspect
// and rewrite it before flushing to the real ResponseWriter.
type captureRW struct {
	http.ResponseWriter
	header http.Header
	body   *bytes.Buffer
	code   int
	wrote  bool
}

func newCaptureRW(w http.ResponseWriter) *captureRW {
	return &captureRW{
		ResponseWriter: w,
		header:         http.Header{},
		body:           &bytes.Buffer{},
		code:           http.StatusOK,
	}
}

func (c *captureRW) Header() http.Header { return c.header }

func (c *captureRW) WriteHeader(code int) {
	if c.wrote {
		return
	}
	c.code = code
	c.wrote = true
}

func (c *captureRW) Write(b []byte) (int, error) {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}
	return c.body.Write(b)
}
