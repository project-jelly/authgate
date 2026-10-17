package signing

import (
	"crypto/rsa"
	"errors"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Provider owns the RSA signing material for JWT issuance and JWKS
// publication. Bundle mode is a fixed startup snapshot; legacy mode retains the
// current/previous API while holding only the previous key's public material.
// Configure a Provider at startup before it is used to serve requests.
type Provider struct {
	current    *rsa.PrivateKey
	currentID  string
	previous   *rsa.PublicKey
	previousID string
	bundle     *Bundle
}

// SetCurrent sets the current RSA signing key used for JWT issuance.
func (p *Provider) SetCurrent(key *rsa.PrivateKey, keyID string) {
	p.requireLegacyMode()
	p.current = key
	p.currentID = keyID
}

// SetPrevious sets the previous signing key for 2-slot rotation. JWKS returns
// both keys; JWTs are signed with the current key only.
func (p *Provider) SetPrevious(key *rsa.PrivateKey, keyID string) {
	p.requireLegacyMode()
	p.previous = nil
	if key != nil {
		p.previous = cloneSigningPublicKey(&key.PublicKey)
	}
	p.previousID = keyID
}

// SetBundle installs a validated startup snapshot. Once configured, the bundle
// and all legacy signing material setters remain immutable for this process.
func (p *Provider) SetBundle(bundle *Bundle) {
	if bundle == nil || bundle.active == nil || bundle.hints == nil {
		panic("signing key bundle: unvalidated startup snapshot")
	}
	if p.bundle != nil {
		panic("signing key bundle: startup snapshot already configured")
	}
	p.current, p.previous = nil, nil
	p.currentID, p.previousID = "", ""
	p.bundle = bundle
}

func (p *Provider) requireLegacyMode() {
	if p.bundle != nil {
		panic("signing key bundle: startup snapshot cannot be changed")
	}
}

// SigningKey returns the current key for JWT signing, or an error when no key
// is configured.
func (p *Provider) SigningKey() (op.SigningKey, error) {
	if p.bundle != nil {
		return &signingKeyModel{id: p.bundle.activeID, algorithm: jose.RS256, key: p.bundle.active}, nil
	}
	if p.current == nil {
		return nil, errors.New("no signing key configured")
	}
	return &signingKeyModel{
		id:        p.currentID,
		algorithm: jose.RS256,
		key:       p.current,
	}, nil
}

func (p *Provider) SignatureAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.RS256}
}

// KeySet returns the public keys for JWKS: the current key, plus the previous
// key while a 2-slot rotation overlap is configured.
func (p *Provider) KeySet() []op.Key {
	if p.bundle != nil {
		return p.bundle.publishedKeys()
	}
	if p.current == nil {
		return nil
	}
	keys := []op.Key{
		&publicKeyModel{
			id:        p.currentID,
			algorithm: jose.RS256,
			key:       &p.current.PublicKey,
		},
	}
	if p.previous != nil {
		keys = append(keys, &publicKeyModel{
			id:        p.previousID,
			algorithm: jose.RS256,
			key:       cloneSigningPublicKey(p.previous),
		})
	}
	return keys
}

func (p *Provider) IDTokenHintKeySet() oidc.KeySet {
	if p.bundle == nil {
		return nil
	}
	return p.bundle.hints
}
