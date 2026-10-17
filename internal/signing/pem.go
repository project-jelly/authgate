package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadOrGenerateKey loads an RSA private key from path, or generates a new one if not found.
func LoadOrGenerateKey(path string) (*rsa.PrivateKey, error) {
	//nolint:gosec // Path is operator-controlled SIGNING_KEY_PATH, not user input.
	data, err := os.ReadFile(path)
	if err == nil {
		return parseRSAKey(data)
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key: %w", err)
	}

	// Generate new key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Save to file
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}

	return key, nil
}

func parseRSAKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	return key, nil
}
