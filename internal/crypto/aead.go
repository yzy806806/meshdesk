// Package crypto provides the AES-256-GCM encryption layer for MeshDesk v2.
//
// SecureConn wraps a net.Conn with authenticated encryption. Every Write
// produces one framed ciphertext record. Every Read reassembles and decrypts
// one plaintext frame. The caller sees a standard net.Conn — no crypto API,
// no key rotation, no nonce management.
//
// This package is separate from internal/session/ because:
//   - It has no knowledge of mesh identity or key exchange.
//   - It is testable with static 32-byte keys (no Ed25519, no X25519).
//   - It is the single point of encryption for ALL data-plane traffic.
//
// Thread safety: SecureConn is safe for concurrent Read and concurrent Write
// from different goroutines. It is NOT safe for concurrent Read or concurrent
// Write from multiple goroutines — use Layer 3 (smux) for that.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

// NewAESGCM creates an AES-GCM AEAD from a 16/24/32-byte key.
//
// This is the shared helper extracted from reality_transport.go:861-867.
// Both the handshake package (REALITY auth tag) and this package (SecureConn)
// use the same AES-GCM construction.
func NewAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// newAESGCM is an unexported alias used internally by SecureConn.
// External callers should use NewAESGCM.
func newAESGCM(key []byte) (cipher.AEAD, error) {
	return NewAESGCM(key)
}
