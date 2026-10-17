package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"
)

var signingBundleFixtureKeys struct {
	sync.Once
	keys []*rsa.PrivateKey
	err  error
}

func signingBundleTestKeys(t *testing.T) []*rsa.PrivateKey {
	t.Helper()
	signingBundleFixtureKeys.Do(func() {
		for i := 0; i < 4; i++ {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				signingBundleFixtureKeys.err = err
				return
			}
			signingBundleFixtureKeys.keys = append(signingBundleFixtureKeys.keys, key)
		}
	})
	if signingBundleFixtureKeys.err != nil {
		t.Fatal("generate bundle fixture keys")
	}
	return signingBundleFixtureKeys.keys
}

func signingBundleTestJWK(t *testing.T, key *rsa.PrivateKey) map[string]any {
	t.Helper()
	jwk := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: string(jose.RS256), Use: "sig"}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(thumbprint)
	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func signingBundleTestDocument(t *testing.T) map[string]any {
	t.Helper()
	keys := signingBundleTestKeys(t)
	entries := make([]any, 0, 3)
	for i, key := range keys[:3] {
		entries = append(entries, map[string]any{"jwk": signingBundleTestJWK(t, key), "publish": i < 2})
	}
	return map[string]any{
		"schema_version":         1,
		"revision":               "rotation-test-1",
		"active_kid":             entries[0].(map[string]any)["jwk"].(map[string]any)["kid"],
		"active_private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keys[0])})),
		"verification_keys":      entries,
	}
}

func signingBundleTestJSON(t *testing.T, document map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func signingBundleTestEntry(document map[string]any, index int) map[string]any {
	return document["verification_keys"].([]any)[index].(map[string]any)
}

func signingBundleTestPublic(document map[string]any, index int) map[string]any {
	return signingBundleTestEntry(document, index)["jwk"].(map[string]any)
}

func TestBundleRejectsInvalidDocuments(t *testing.T) {
	const secretMarker = "PRIVATE_SENTINEL_DO_NOT_LOG"
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing revision", func(d map[string]any) { delete(d, "revision") }},
		{"unknown root member", func(d map[string]any) { d[secretMarker] = "secret" }},
		{"unsupported schema", func(d map[string]any) { d["schema_version"] = 2 }},
		{"fractional schema", func(d map[string]any) { d["schema_version"] = 1.5 }},
		{"null revision", func(d map[string]any) { d["revision"] = nil }},
		{"empty revision", func(d map[string]any) { d["revision"] = "  " }},
		{"wrong revision type", func(d map[string]any) { d["revision"] = true }},
		{"empty active ID", func(d map[string]any) { d["active_kid"] = "" }},
		{"absent active key", func(d map[string]any) { d["active_kid"] = "absent" }},
		{"active mismatch", func(d map[string]any) { d["active_kid"] = signingBundleTestPublic(d, 1)["kid"] }},
		{"active unpublished", func(d map[string]any) { signingBundleTestEntry(d, 0)["publish"] = false }},
		{"null list", func(d map[string]any) { d["verification_keys"] = nil }},
		{"empty list", func(d map[string]any) { d["verification_keys"] = []any{} }},
		{"too many keys", func(d map[string]any) {
			entries := make([]any, signingKeyBundleMaxKeys+1)
			for i := range entries {
				entries[i] = signingBundleTestEntry(d, 0)
			}
			d["verification_keys"] = entries
		}},
		{"null entry", func(d map[string]any) { d["verification_keys"].([]any)[0] = nil }},
		{"unknown entry member", func(d map[string]any) { signingBundleTestEntry(d, 0)[secretMarker] = true }},
		{"missing publication flag", func(d map[string]any) { delete(signingBundleTestEntry(d, 0), "publish") }},
		{"null publication flag", func(d map[string]any) { signingBundleTestEntry(d, 0)["publish"] = nil }},
		{"string publication flag", func(d map[string]any) { signingBundleTestEntry(d, 0)["publish"] = "true" }},
		{"null JWK", func(d map[string]any) { signingBundleTestEntry(d, 0)["jwk"] = nil }},
		{"missing public member", func(d map[string]any) { delete(signingBundleTestPublic(d, 0), "e") }},
		{"unknown public member", func(d map[string]any) { signingBundleTestPublic(d, 0)[secretMarker] = "secret" }},
		{"private JWK member", func(d map[string]any) { signingBundleTestPublic(d, 0)["d"] = secretMarker }},
		{"remote reference", func(d map[string]any) { signingBundleTestPublic(d, 0)["jku"] = secretMarker }},
		{"wrong key type", func(d map[string]any) { signingBundleTestPublic(d, 0)["kty"] = "oct" }},
		{"wrong algorithm", func(d map[string]any) { signingBundleTestPublic(d, 0)["alg"] = "PS256" }},
		{"wrong usage", func(d map[string]any) { signingBundleTestPublic(d, 0)["use"] = "enc" }},
		{"null modulus", func(d map[string]any) { signingBundleTestPublic(d, 0)["n"] = nil }},
		{"small modulus", func(d map[string]any) { signingBundleTestPublic(d, 0)["n"] = "Aw" }},
		{"large modulus", func(d map[string]any) {
			n := new(big.Int).Lsh(big.NewInt(1), 4096)
			n.SetBit(n, 0, 1)
			signingBundleTestPublic(d, 0)["n"] = base64.RawURLEncoding.EncodeToString(n.Bytes())
		}},
		{"invalid exponent", func(d map[string]any) { signingBundleTestPublic(d, 0)["e"] = "Ag" }},
		{"oversized exponent", func(d map[string]any) { signingBundleTestPublic(d, 0)["e"] = "AQAAAAE" }},
		{"padded modulus", func(d map[string]any) {
			signingBundleTestPublic(d, 0)["n"] = signingBundleTestPublic(d, 0)["n"].(string) + "="
		}},
		{"wrong key ID", func(d map[string]any) { signingBundleTestPublic(d, 0)["kid"] = secretMarker }},
		{"duplicate key ID", func(d map[string]any) { d["verification_keys"].([]any)[1] = signingBundleTestEntry(d, 0) }},
		{"duplicate material under legacy alias", func(d map[string]any) {
			jwk := signingBundleTestJWK(t, signingBundleTestKeys(t)[0])
			jwk["kid"] = legacySigningKeyID
			signingBundleTestEntry(d, 1)["jwk"] = jwk
		}},
		{"private text", func(d map[string]any) { d["active_private_key_pem"] = secretMarker }},
		{"PEM leading garbage", func(d map[string]any) {
			d["active_private_key_pem"] = secretMarker + d["active_private_key_pem"].(string)
		}},
		{"second PEM block", func(d map[string]any) {
			d["active_private_key_pem"] = strings.Repeat(d["active_private_key_pem"].(string), 2)
		}},
		{"malformed first PEM before valid block", func(d map[string]any) {
			d["active_private_key_pem"] = "-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----\n" + d["active_private_key_pem"].(string)
		}},
		{"PEM trailing garbage", func(d map[string]any) {
			d["active_private_key_pem"] = d["active_private_key_pem"].(string) + secretMarker
		}},
		{"PEM headers", func(d map[string]any) {
			block := &pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Comment": secretMarker}, Bytes: x509.MarshalPKCS1PrivateKey(signingBundleTestKeys(t)[0])}
			d["active_private_key_pem"] = string(pem.EncodeToMemory(block))
		}},
		{"PKCS8 PEM", func(d map[string]any) {
			der, err := x509.MarshalPKCS8PrivateKey(signingBundleTestKeys(t)[0])
			if err != nil {
				t.Fatal(err)
			}
			d["active_private_key_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := signingBundleTestDocument(t)
			tc.mutate(document)
			_, err := parseBundle(signingBundleTestJSON(t, document))
			if err == nil {
				t.Fatal("invalid document accepted")
			}
			if strings.Contains(err.Error(), secretMarker) || strings.Contains(err.Error(), "BEGIN") {
				t.Fatal("error exposed input")
			}
		})
	}
}

func TestBundleRejectsDuplicateAndMalformedJSON(t *testing.T) {
	valid := string(signingBundleTestJSON(t, signingBundleTestDocument(t)))
	cases := map[string][]byte{
		"duplicate root":   []byte(strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)),
		"duplicate entry":  []byte(strings.Replace(valid, `"publish":true`, `"publish":true,"publish":false`, 1)),
		"duplicate JWK":    []byte(strings.Replace(valid, `"kty":"RSA"`, `"kty":"RSA","k\u0074y":"RSA"`, 1)),
		"trailing object":  []byte(valid + `{}`),
		"trailing garbage": []byte(valid + `private-sentinel`),
		"invalid UTF8":     bytes.Replace([]byte(valid), []byte("rotation-test-1"), []byte{0xff}, 1),
		"deep nesting":     []byte(strings.Repeat("[", 100) + "1" + strings.Repeat("]", 100)),
		"scalar":           []byte(`"private-sentinel"`),
		"truncated":        []byte(valid[:len(valid)-1]),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseBundle(data); err == nil {
				t.Fatal("malformed or duplicate JSON accepted")
			}
		})
	}
}

func TestBundleLoadIsBoundedAndDoesNotExposePath(t *testing.T) {
	data := signingBundleTestJSON(t, signingBundleTestDocument(t))
	path := filepath.Join(t.TempDir(), "PRIVATE_SENTINEL.json")
	data = append(data, bytes.Repeat([]byte(" "), signingKeyBundleMaxBytes-len(data))...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(path); err != nil {
		t.Fatalf("valid document at size limit refused: %v", err)
	}
	if err := os.WriteFile(path, append(data, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(path); err == nil || strings.Contains(err.Error(), path) {
		t.Fatal("size limit or path privacy failed")
	}
	if _, err := LoadBundle(path + ".missing"); err == nil || strings.Contains(err.Error(), "PRIVATE_SENTINEL") {
		t.Fatal("missing file error exposed its path")
	}
}

func signingBundleTestSigned(t *testing.T, key *rsa.PrivateKey, kid string, algorithm jose.SignatureAlgorithm) *jose.JSONWebSignature {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign([]byte(`{"iss":"https://auth.example","sub":"subject","exp":1}`))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{algorithm})
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestBundleRejectsWeakAndCorruptPrivateMaterial(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := *signingBundleTestKeys(t)[0]
	corrupt.D = big.NewInt(1)
	corrupt.Precomputed = rsa.PrecomputedValues{}
	for _, key := range []*rsa.PrivateKey{weak, &corrupt} {
		document := signingBundleTestDocument(t)
		document["active_private_key_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
		if _, err := parseBundle(signingBundleTestJSON(t, document)); err == nil {
			t.Fatal("weak or invalid RSA private key accepted")
		}
	}
}

func TestBundleSeparatesPublishedAndHintKeys(t *testing.T) {
	document := signingBundleTestDocument(t)
	bundle, err := parseBundle(signingBundleTestJSON(t, document))
	if err != nil {
		t.Fatal(err)
	}
	provider := new(Provider)
	provider.SetBundle(bundle)
	if bundle.KeyCount() != 3 {
		t.Fatalf("key count = %d", bundle.KeyCount())
	}
	current, err := provider.SigningKey()
	if err != nil || current.ID() != document["active_kid"] {
		t.Fatal("incorrect active signer")
	}
	published := provider.KeySet()
	if len(published) != 2 {
		t.Fatal("incorrect published key count")
	}
	for _, key := range published {
		if _, ok := key.Key().(*rsa.PublicKey); !ok {
			t.Fatal("private material returned through KeySet")
		}
	}
	keys := signingBundleTestKeys(t)
	local := &op.OpenIDKeySet{Storage: &providerKeyStorage{provider: provider}}
	for i := 0; i < 3; i++ {
		kid := signingBundleTestPublic(document, i)["kid"].(string)
		signed := signingBundleTestSigned(t, keys[i], kid, jose.RS256)
		// Expiration belongs to the provider verifier, not this key set. In
		// particular an old signature must remain available for expired hints.
		if _, err := provider.IDTokenHintKeySet().VerifySignature(context.Background(), signed); err != nil {
			t.Fatalf("hint key %d refused: %v", i, err)
		}
		_, err := local.VerifySignature(context.Background(), signed)
		if (i < 2) != (err == nil) {
			t.Fatalf("published verification result for key %d: %v", i, err)
		}
	}
	// A caller mutating a returned JWKS key must not alter the snapshot or hints.
	published[0].Key().(*rsa.PublicKey).N.SetInt64(1)
	fresh := provider.KeySet()
	if fresh[0].Key().(*rsa.PublicKey).N.BitLen() < 2048 {
		t.Fatal("returned key mutated the immutable snapshot")
	}
}

// providerKeyStorage adapts only the method exercised by op.OpenIDKeySet. The
// signing component does not depend on AuthGate's persistence adapter.
type providerKeyStorage struct {
	op.Storage
	provider *Provider
}

func (s *providerKeyStorage) KeySet(context.Context) ([]op.Key, error) {
	return s.provider.KeySet(), nil
}

func TestBundleHintVerifierRejectsWrongHeadersAndSignatures(t *testing.T) {
	document := signingBundleTestDocument(t)
	bundle, err := parseBundle(signingBundleTestJSON(t, document))
	if err != nil {
		t.Fatal(err)
	}
	key := signingBundleTestKeys(t)[0]
	kid := document["active_kid"].(string)
	cases := map[string]*jose.JSONWebSignature{
		"nil":                 nil,
		"multiple signatures": {Signatures: make([]jose.Signature, 2)},
		"missing kid":         signingBundleTestSigned(t, key, "", jose.RS256),
		"unknown kid":         signingBundleTestSigned(t, key, "unknown", jose.RS256),
		"PS256 same RSA key":  signingBundleTestSigned(t, key, kid, jose.PS256),
		"wrong key":           signingBundleTestSigned(t, signingBundleTestKeys(t)[1], kid, jose.RS256),
	}
	for name, signed := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := bundle.hints.VerifySignature(context.Background(), signed); err == nil {
				t.Fatal("invalid hint signature accepted")
			}
		})
	}
}

func TestBundleReloadPreservesIdentityAndOnlyLogsPublicMetadata(t *testing.T) {
	document := signingBundleTestDocument(t)
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, signingBundleTestJSON(t, document), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := LoadBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bundle := range []*Bundle{first, second} {
		provider := new(Provider)
		provider.SetBundle(bundle)
		key, err := provider.SigningKey()
		if err != nil || key.ID() != first.activeID || bundle.KeyCount() != 3 {
			t.Fatal("restart changed the key identity")
		}
	}
	if err := os.WriteFile(path, []byte(`{"invalid":"replacement"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if first.activeID != second.activeID || len(first.publishedKeys()) != 2 {
		t.Fatal("file replacement changed an existing snapshot")
	}
	var output bytes.Buffer
	slog.New(slog.NewJSONHandler(&output, nil)).Info("startup", "signing_keys", first)
	log := output.String()
	privateBlock, _ := pem.Decode([]byte(document["active_private_key_pem"].(string)))
	if strings.Contains(log, "PRIVATE KEY") || strings.Contains(log, "active_private_key_pem") || strings.Contains(log, base64.StdEncoding.EncodeToString(privateBlock.Bytes)) {
		t.Fatal("private key material appeared in structured log")
	}
	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	metadata := event["signing_keys"].(map[string]any)
	if metadata["revision"] != "rotation-test-1" || len(metadata["verification_keys"].([]any)) != 3 {
		t.Fatal("public startup evidence missing")
	}
}

func TestBundleLegacyMigrationAndInitializationBoundary(t *testing.T) {
	document := signingBundleTestDocument(t)
	document["active_kid"] = legacySigningKeyID
	signingBundleTestPublic(document, 0)["kid"] = legacySigningKeyID
	bundle, err := parseBundle(signingBundleTestJSON(t, document))
	if err != nil {
		t.Fatal(err)
	}
	provider := new(Provider)
	keys := signingBundleTestKeys(t)
	provider.SetCurrent(keys[0], legacySigningKeyID)
	provider.SetPrevious(keys[1], "previous")
	if provider.IDTokenHintKeySet() != nil {
		t.Fatal("legacy hint key set must use the provider default")
	}
	if provider.previous == &keys[1].PublicKey {
		t.Fatal("legacy previous public key was not copied")
	}
	provider.SetBundle(bundle)
	if provider.current != nil || provider.previous != nil {
		t.Fatal("legacy material retained after bundle initialization")
	}
	for _, change := range []func(){
		func() { provider.SetBundle(bundle) },
		func() { provider.SetCurrent(keys[1], "replacement") },
		func() { provider.SetPrevious(keys[1], "replacement") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("bundle snapshot could be reconfigured")
				}
			}()
			change()
		}()
	}
}
