// Package peer provides WireGuard key management and peer identity types.
package peer

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyLen is the byte length of a WireGuard key.
const KeyLen = 32

// Identity represents a node's WireGuard identity.
type Identity struct {
	PrivateKey string // hex-encoded private key
	PublicKey  string // hex-encoded public key
}

// Route represents a known peer and the mesh IPs routed to it.
type Route struct {
	PeerID     string   // hex public key
	Endpoint   string   // host:port
	AllowedIPs []string // mesh IPs routed to this peer
}

// GenerateIdentity creates a new random WireGuard keypair.
// The private key is clamped per the Curve25519 spec.
func GenerateIdentity() (*Identity, error) {
	priv := make([]byte, KeyLen)
	if _, err := rand.Read(priv); err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	// Clamp private key per Curve25519 / WireGuard spec
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	return &Identity{
		PrivateKey: hex.EncodeToString(priv),
		PublicKey:  hex.EncodeToString(pub),
	}, nil
}

// IdentityFromHex creates an Identity from a hex-encoded private key.
func IdentityFromHex(privHex string) (*Identity, error) {
	priv, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, fmt.Errorf("decode private key hex: %w", err)
	}
	if len(priv) != KeyLen {
		return nil, fmt.Errorf("invalid key length: got %d, want %d", len(priv), KeyLen)
	}

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return &Identity{
		PrivateKey: privHex,
		PublicKey:  hex.EncodeToString(pub),
	}, nil
}

// PublicKeyFromPrivateHex derives the public key from a hex private key.
func PublicKeyFromPrivateHex(privHex string) (string, error) {
	priv, err := hex.DecodeString(privHex)
	if err != nil {
		return "", fmt.Errorf("decode private key hex: %w", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return hex.EncodeToString(pub), nil
}

// Base64Key converts a hex-encoded WireGuard key to base64.
func Base64Key(hexKey string) (string, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("decode hex key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// HexKey converts a base64-encoded WireGuard key to hex.
func HexKey(b64Key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", fmt.Errorf("decode base64 key: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
