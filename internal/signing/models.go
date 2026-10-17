package signing

import (
	"crypto/rsa"

	jose "github.com/go-jose/go-jose/v4"
)

type signingKeyModel struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PrivateKey
}

func (k *signingKeyModel) SignatureAlgorithm() jose.SignatureAlgorithm { return k.algorithm }
func (k *signingKeyModel) Key() any                                    { return k.key }
func (k *signingKeyModel) ID() string                                  { return k.id }

type publicKeyModel struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PublicKey
}

func (k *publicKeyModel) ID() string                         { return k.id }
func (k *publicKeyModel) Algorithm() jose.SignatureAlgorithm { return k.algorithm }
func (k *publicKeyModel) Use() string                        { return "sig" }
func (k *publicKeyModel) Key() any                           { return k.key }
