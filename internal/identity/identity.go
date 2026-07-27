// Package identity provides the permanent node identity for MeshDesk v2.
//
// In v2, identity is an Ed25519 keypair — not a Curve25519/X25519 key.
// Ed25519 supports digital signatures, enabling:
//   - Session auth: signing the Layer 2 X25519 ephemeral proves ownership
//   - Gossip integrity: every NodeMeta update carries an Ed25519 signature
//   - Peer authentication: PeerManager can verify claimed identity
//
// This replaces v1's internal/mesh/peer/ package (Curve25519, ~101 lines).
// Implementation: crypto/ed25519 from Go stdlib. No external dependency.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// KeyLen is the byte length of an Ed25519 public key.
const KeyLen = ed25519.PublicKeySize // 32 bytes

// PrivKeyLen is the byte length of an Ed25519 private key (includes public key).
const PrivKeyLen = ed25519.PrivateKeySize // 64 bytes

// SignatureLen is the byte length of an Ed25519 signature.
const SignatureLen = ed25519.SignatureSize // 64 bytes

// Identity is the permanent, immutable identity of a mesh node.
// The PublicKey IS the node's identifier throughout the mesh:
// gossip, PeerManager, session auth, and Dashboard all reference
// nodes by their Ed25519 public key (hex-encoded).
//
// There is no mesh IP, no subnet, no allowed_ips. The public key
// is the sole namespace for peer identification.
type Identity struct {
	// PrivateKey is the hex-encoded Ed25519 private key (64 bytes / 128 hex chars).
	// Never transmitted over the network. Used for signing.
	PrivateKey string

	// PublicKey is the hex-encoded Ed25519 public key (32 bytes / 64 hex chars).
	// This IS the node's mesh identity. Shared freely via gossip.
	PublicKey string
}

// GenerateIdentity creates a new random Ed25519 keypair.
// Uses crypto/rand for secure random key generation.
// No key clamping needed — Ed25519 has no clamping requirement.
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	return &Identity{
		PrivateKey: hex.EncodeToString(priv),
		PublicKey:  hex.EncodeToString(pub),
	}, nil
}

// IdentityFromHex creates an Identity from a hex-encoded private key.
// The public key is derived from the private key automatically.
func IdentityFromHex(privHex string) (*Identity, error) {
	priv, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, fmt.Errorf("decode private key hex: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key length: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	// Extract the public key from the private key
	privKey := ed25519.PrivateKey(priv)
	pub := privKey.Public().(ed25519.PublicKey)
	return &Identity{
		PrivateKey: privHex,
		PublicKey:  hex.EncodeToString(pub),
	}, nil
}

// Sign signs data with this node's Ed25519 private key.
// The signature is 64 bytes. Returns hex-encoded signature.
// This is the contract that Layer 2 (Session) and Gossip depend on:
//   - Layer 2: Sign(X25519_ephemeral_pub) → sig[32:64] attached to key exchange
//   - Gossip:   Sign(NodeMeta) → sig included in memberlist broadcast
func (id *Identity) Sign(data []byte) (string, error) {
	priv, err := hex.DecodeString(id.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	privKey := ed25519.PrivateKey(priv)
	sig := ed25519.Sign(privKey, data)
	return hex.EncodeToString(sig), nil
}

// Verify checks an Ed25519 signature against a public key.
// Used by PeerManager to verify gossip payloads and session-handshake proofs.
func Verify(pubKeyHex string, data []byte, sigHex string) bool {
	pub, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), data, sig)
}

// PublicKeyFromPrivateHex derives the Ed25519 public key from a hex-encoded
// private key. Convenience function for config loading.
func PublicKeyFromPrivateHex(privHex string) (string, error) {
	priv, err := hex.DecodeString(privHex)
	if err != nil {
		return "", fmt.Errorf("decode private key hex: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid key length: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	privKey := ed25519.PrivateKey(priv)
	pub := privKey.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub), nil
}
