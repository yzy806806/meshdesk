package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// SessionKeys holds the derived AES-256 keys for SecureConn.
type SessionKeys struct {
	SendKey [KeySize]byte   // encrypt outbound data
	RecvKey [KeySize]byte   // decrypt inbound data
	Nonce   [NonceSize]byte // reserved for future use
}

// DeriveSessionKeys derives AES-256 keys from a shared secret.
//
// sharedSecret: output of X25519 ECDH (32 bytes)
// role: true = initiator, false = responder
// identityBinding: Ed25519 signature of (initiator_pub || responder_pub || sharedSecret)
//
//	contained in the HKDF info string for domain separation.
//
// Both roles derive from the SAME HKDF output (same info string) to ensure
// complementary keys: the initiator's SendKey equals the responder's RecvKey
// and vice versa. The role determines which derived key is assigned to send
// vs recv, preventing cross-role key confusion without breaking
// complementarity.
//
// The info string includes:
//   - "meshdesk-v2-session" domain separator
//   - first 8 bytes of the identity binding signature
//
// This prevents cross-identity key confusion.
func DeriveSessionKeys(sharedSecret []byte, role bool, identityBinding []byte) *SessionKeys {
	info := []byte("meshdesk-v2-session")
	// Include first 8 bytes of identity binding signature for domain separation.
	// This binds the session keys to the Ed25519 identity verification,
	// preventing cross-identity key confusion.
	if len(identityBinding) >= 8 {
		info = append(info, identityBinding[:8]...)
	}

	reader := hkdf.New(sha256.New, sharedSecret, nil, info)

	// Derive two keys from the same HKDF stream.
	var key1, key2 [KeySize]byte
	_, _ = io.ReadFull(reader, key1[:])
	_, _ = io.ReadFull(reader, key2[:])

	// Assign based on role: initiator sends with key1, responder sends with key2.
	// This ensures initiator's SendKey == responder's RecvKey.
	var keys SessionKeys
	if role {
		keys.SendKey = key1
		keys.RecvKey = key2
	} else {
		keys.SendKey = key2
		keys.RecvKey = key1
	}

	// Derive the reserved nonce from the remaining HKDF output.
	_, _ = io.ReadFull(reader, keys.Nonce[:])

	return &keys
}
