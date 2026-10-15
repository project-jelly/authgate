package storage

import (
	"crypto/rsa"
	"errors"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// signingKeyProvider owns the RSA signing material for JWT issuance and JWKS
// publication. Bundle mode is a fixed startup snapshot; legacy mode retains the
// current/previous API while holding only the previous key's public material. Storage
// holds one and its op.Storage signing methods delegate here, keeping key
// management out of the Storage adapter (#301).
type signingKeyProvider struct {
	current    *rsa.PrivateKey
	currentID  string
	previous   *rsa.PublicKey
	previousID string
	bundle     *SigningKeyBundle
}

// SetCurrent sets the current RSA signing key used for JWT issuance.
func (p *signingKeyProvider) SetCurrent(key *rsa.PrivateKey, keyID string) {
	p.requireLegacyMode()
	p.current = key
	p.currentID = keyID
}

// SetPrevious sets the previous signing key for 2-slot rotation. JWKS returns
// both keys; JWTs are signed with the current key only.
func (p *signingKeyProvider) SetPrevious(key *rsa.PrivateKey, keyID string) {
	p.requireLegacyMode()
	p.previous = nil
	if key != nil {
		p.previous = cloneSigningPublicKey(&key.PublicKey)
	}
	p.previousID = keyID
}

func (p *signingKeyProvider) SetBundle(bundle *SigningKeyBundle) {
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

func (p *signingKeyProvider) requireLegacyMode() {
	if p.bundle != nil {
		panic("signing key bundle: startup snapshot cannot be changed")
	}
}

// SigningKey returns the current key for JWT signing, or an error when no key
// is configured.
func (p *signingKeyProvider) SigningKey() (op.SigningKey, error) {
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

func (p *signingKeyProvider) SignatureAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.RS256}
}

// KeySet returns the public keys for JWKS: the current key, plus the previous
// key while a 2-slot rotation overlap is configured.
func (p *signingKeyProvider) KeySet() []op.Key {
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

func (p *signingKeyProvider) IDTokenHintKeySet() oidc.KeySet {
	if p.bundle == nil {
		return nil
	}
	return p.bundle.hints
}
