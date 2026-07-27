package identity

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// ToPEM exports the Ed25519 private key as PEM (RFC 8410).
// Suitable for config files that want human-readable key blocks.
func (id *Identity) ToPEM() (string, error) {
	priv, err := hex.DecodeString(id.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}

	derBytes, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(priv))
	if err != nil {
		return "", fmt.Errorf("marshal PKCS8 private key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})
	return string(pemBytes), nil
}

// IdentityFromPEM loads an Ed25519 keypair from PEM bytes.
// Expects RFC 8410 PKCS8 format ("PRIVATE KEY" block).
func IdentityFromPEM(pemData []byte) (*Identity, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PEM key is not Ed25519 (got %T)", key)
	}

	pub := edKey.Public().(ed25519.PublicKey)
	return &Identity{
		PrivateKey: hex.EncodeToString(edKey),
		PublicKey:  hex.EncodeToString(pub),
	}, nil
}

// PublicKeyToPEM exports only the public key as PEM (SPKI format).
func PublicKeyToPEM(pubHex string) (string, error) {
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return "", fmt.Errorf("decode public key hex: %w", err)
	}

	derBytes, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		return "", fmt.Errorf("marshal SPKI public key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})
	return string(pemBytes), nil
}
