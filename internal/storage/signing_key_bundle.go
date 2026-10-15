package storage

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256" // Register SHA-256 for the RFC 7638 thumbprint API.
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	signingKeyBundleMaxBytes = 256 << 10
	signingKeyBundleMaxKeys  = 128
	legacySigningKeyID       = "authgate-key-1"
)

// SigningKeyBundle is a validated startup snapshot. Only its active key contains
// private material; verification keys remain public even after publication ends.
// Its contents are deliberately unexported and never reloaded during serving.
type SigningKeyBundle struct {
	revision string
	activeID string
	active   *rsa.PrivateKey
	keys     []bundleVerificationKey
	hints    *bundleHintKeySet
}

type bundleVerificationKey struct {
	id          string
	fingerprint string
	public      *rsa.PublicKey
	publish     bool
}

// LoadSigningKeyBundle reads at most the documented size limit plus one byte.
// Errors never include input paths, JSON members/values or cryptographic material.
func LoadSigningKeyBundle(path string) (*SigningKeyBundle, error) {
	//nolint:gosec // Path is operator-controlled SIGNING_KEY_BUNDLE_PATH, not request input.
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("signing key bundle: cannot open file")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, signingKeyBundleMaxBytes+1))
	if err != nil {
		return nil, errors.New("signing key bundle: cannot read file")
	}
	if len(data) > signingKeyBundleMaxBytes {
		return nil, errors.New("signing key bundle: file exceeds size limit")
	}
	return parseSigningKeyBundle(data)
}

func parseSigningKeyBundle(data []byte) (*SigningKeyBundle, error) {
	if len(data) > signingKeyBundleMaxBytes || !utf8.Valid(data) || !validBundleJSON(data) {
		return nil, errors.New("signing key bundle: invalid JSON")
	}
	root, err := bundleObject(data, "schema_version", "revision", "active_kid", "active_private_key_pem", "verification_keys")
	if err != nil {
		return nil, err
	}
	var version int
	if json.Unmarshal(root["schema_version"], &version) != nil || version != 1 {
		return nil, errors.New("signing key bundle: unsupported schema version")
	}
	revision, err := bundleString(root["revision"])
	if err != nil {
		return nil, err
	}
	activeID, err := bundleString(root["active_kid"])
	if err != nil {
		return nil, err
	}
	privatePEM, err := bundleString(root["active_private_key_pem"])
	if err != nil {
		return nil, err
	}
	active, err := bundlePrivateKey(privatePEM)
	if err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if json.Unmarshal(root["verification_keys"], &entries) != nil || len(entries) == 0 || len(entries) > signingKeyBundleMaxKeys {
		return nil, errors.New("signing key bundle: invalid verification key count")
	}
	bundle := &SigningKeyBundle{revision: revision, activeID: activeID, active: active}
	ids := make(map[string]struct{}, len(entries))
	material := make(map[string]struct{}, len(entries))
	activeFound := false
	for _, raw := range entries {
		entry, err := bundleObject(raw, "jwk", "publish")
		if err != nil {
			return nil, err
		}
		var publish bool
		if json.Unmarshal(entry["publish"], &publish) != nil {
			return nil, errors.New("signing key bundle: invalid publication flag")
		}
		key, err := bundlePublicKey(entry["jwk"])
		if err != nil {
			return nil, err
		}
		key.publish = publish
		if _, exists := ids[key.id]; exists {
			return nil, errors.New("signing key bundle: duplicate key ID")
		}
		if _, exists := material[key.fingerprint]; exists {
			return nil, errors.New("signing key bundle: duplicate public key material")
		}
		ids[key.id] = struct{}{}
		material[key.fingerprint] = struct{}{}
		if key.id == activeID {
			if !publish || key.public.E != active.PublicKey.E || key.public.N.Cmp(active.PublicKey.N) != 0 {
				return nil, errors.New("signing key bundle: active key does not match published key")
			}
			activeFound = true
		}
		bundle.keys = append(bundle.keys, key)
	}
	if !activeFound {
		return nil, errors.New("signing key bundle: active key is absent")
	}
	bundle.hints = &bundleHintKeySet{keys: make(map[string]*rsa.PublicKey, len(bundle.keys))}
	for _, key := range bundle.keys {
		bundle.hints.keys[key.id] = key.public
	}
	return bundle, nil
}

// validBundleJSON checks duplicates before decoding into maps (which would lose
// them). A depth bound also keeps hostile but size-bounded nesting off the stack.
func validBundleJSON(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if !bundleJSONValue(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func bundleJSONValue(decoder *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return false // No field in this schema permits null.
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return true
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			name, ok := token.(string)
			if err != nil || !ok {
				return false
			}
			if _, duplicate := seen[name]; duplicate {
				return false
			}
			seen[name] = struct{}{}
			if !bundleJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !bundleJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}

func bundleObject(raw []byte, fields ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != len(fields) {
		return nil, errors.New("signing key bundle: invalid object fields")
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return nil, errors.New("signing key bundle: invalid object fields")
		}
	}
	return object, nil
}

func bundleString(raw []byte) (string, error) {
	var value string
	if json.Unmarshal(raw, &value) != nil || strings.TrimSpace(value) == "" {
		return "", errors.New("signing key bundle: invalid string field")
	}
	return value, nil
}

func bundlePrivateKey(value string) (*rsa.PrivateKey, error) {
	data := bytes.TrimSpace([]byte(value))
	if !bytes.HasPrefix(data, []byte("-----BEGIN RSA PRIVATE KEY-----")) ||
		bytes.Count(data, []byte("-----BEGIN ")) != 1 || bytes.Count(data, []byte("-----END ")) != 1 {
		return nil, errors.New("signing key bundle: invalid private key PEM")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("signing key bundle: invalid private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 || key.Validate() != nil {
		return nil, errors.New("signing key bundle: invalid RSA private key")
	}
	return key, nil
}

func bundlePublicKey(raw []byte) (bundleVerificationKey, error) {
	var empty bundleVerificationKey
	object, err := bundleObject(raw, "kty", "n", "e", "kid", "alg", "use")
	if err != nil {
		return empty, err
	}
	values := make(map[string]string, len(object))
	for name, raw := range object {
		value, err := bundleString(raw)
		if err != nil {
			return empty, err
		}
		values[name] = value
	}
	if values["kty"] != "RSA" || values["alg"] != string(jose.RS256) || values["use"] != "sig" {
		return empty, errors.New("signing key bundle: unsupported public key profile")
	}
	modulus, ok := bundleBase64Integer(values["n"])
	if !ok {
		return empty, errors.New("signing key bundle: invalid RSA public key")
	}
	exponent, ok := bundleBase64Integer(values["e"])
	if !ok || len(exponent) > 4 {
		return empty, errors.New("signing key bundle: invalid RSA public key")
	}
	n := new(big.Int).SetBytes(modulus)
	e := new(big.Int).SetBytes(exponent).Int64()
	if n.BitLen() < 2048 || n.BitLen() > 4096 || n.Bit(0) == 0 || e < 3 || e > (1<<31)-1 || e%2 == 0 {
		return empty, errors.New("signing key bundle: invalid RSA public key")
	}
	public := &rsa.PublicKey{N: n, E: int(e)}
	jwk := jose.JSONWebKey{Key: public}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return empty, errors.New("signing key bundle: cannot identify public key")
	}
	fingerprint := base64.RawURLEncoding.EncodeToString(thumbprint)
	if values["kid"] != fingerprint && values["kid"] != legacySigningKeyID {
		return empty, errors.New("signing key bundle: public key ID does not match thumbprint")
	}
	return bundleVerificationKey{id: values["kid"], fingerprint: fingerprint, public: public}, nil
}

func bundleBase64Integer(value string) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || decoded[0] == 0 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	return decoded, true
}

// LogValue intentionally contains only operator revision and public metadata.
func (b *SigningKeyBundle) LogValue() slog.Value {
	if b == nil {
		return slog.GroupValue()
	}
	type publicMetadata struct {
		Kid         string `json:"kid"`
		Fingerprint string `json:"fingerprint"`
		Publish     bool   `json:"publish"`
	}
	keys := make([]publicMetadata, 0, len(b.keys))
	for _, key := range b.keys {
		keys = append(keys, publicMetadata{Kid: key.id, Fingerprint: key.fingerprint, Publish: key.publish})
	}
	return slog.GroupValue(slog.String("revision", b.revision), slog.String("active_kid", b.activeID), slog.Any("verification_keys", keys))
}

func (b *SigningKeyBundle) KeyCount() int { return len(b.keys) }

func (b *SigningKeyBundle) publishedKeys() []op.Key {
	keys := make([]op.Key, 0, len(b.keys))
	for _, key := range b.keys {
		if key.publish {
			keys = append(keys, &publicKeyModel{id: key.id, algorithm: jose.RS256, key: cloneSigningPublicKey(key.public)})
		}
	}
	return keys
}

func cloneSigningPublicKey(key *rsa.PublicKey) *rsa.PublicKey {
	return &rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E}
}

type bundleHintKeySet struct{ keys map[string]*rsa.PublicKey }

func (s *bundleHintKeySet) VerifySignature(_ context.Context, signed *jose.JSONWebSignature) ([]byte, error) {
	if signed == nil || len(signed.Signatures) != 1 {
		return nil, errors.New("signing key bundle: invalid hint signature")
	}
	header := signed.Signatures[0].Protected
	if header.KeyID == "" || header.Algorithm != string(jose.RS256) {
		return nil, errors.New("signing key bundle: invalid hint signature header")
	}
	key, ok := s.keys[header.KeyID]
	if !ok {
		return nil, errors.New("signing key bundle: unknown hint key")
	}
	payload, err := signed.Verify(key)
	if err != nil {
		return nil, errors.New("signing key bundle: hint signature verification failed")
	}
	return payload, nil
}

var _ oidc.KeySet = (*bundleHintKeySet)(nil)
