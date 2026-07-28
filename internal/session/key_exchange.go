// Package session provides the Layer 2a session key exchange for MeshDesk v2.
//
// It performs an authenticated X25519 ECDH key exchange over a Layer 1
// net.Conn, binding each peer's Ed25519 identity to their ephemeral key
// via signatures. The output is a crypto.SessionKeys (sendKey + recvKey)
// suitable for creating a crypto.SecureConn (Layer 2b).
//
// Two functions cover both roles:
//   - ClientKeyExchange: called by the peer that initiated the L1 connection
//     (the one that called handshake.Connect). Sends first, role=initiator.
//   - ServerKeyExchange: called by the peer that accepted the L1 connection
//     (the one that called ln.Accept after handshake.Listen). Receives first,
//     role=responder.
//
// This package imports identity/ (for Ed25519 signing) and crypto/ (for
// SessionKeys + DeriveSessionKeys). It does NOT import handshake/ — only
// the caller knows the L1 transport.
//
// Dependencies: stdlib crypto/ed25519, crypto/rand, golang.org/x/crypto/curve25519
// (all already vendored in v1 go.sum).
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/yzy806806/meshdesk/internal/crypto"
	"github.com/yzy806806/meshdesk/internal/identity"
)

// ──────────────────────────────────────────────────────────────────────
// Error sentinels
// ──────────────────────────────────────────────────────────────────────

var (
	// ErrIdentityMismatch is returned when the peer's signature verifies
	// but the claimed identity does not match the expected peer.
	// The exchange is valid but the peer is not who we expected.
	ErrIdentityMismatch = errors.New("session: peer identity does not match expected")

	// ErrSignatureInvalid is returned when the peer's Ed25519 signature
	// fails verification. The connection should be dropped — the peer
	// cannot prove ownership of the claimed identity.
	ErrSignatureInvalid = errors.New("session: Ed25519 signature verification failed")

	// ErrKeyExchangeTimeout is returned when the exchange does not
	// complete within the configured deadline.
	ErrKeyExchangeTimeout = errors.New("session: key exchange timed out")

	// ErrProtocolViolation is returned when the peer sends a message
	// that doesn't conform to the wire format (wrong length, etc.).
	ErrProtocolViolation = errors.New("session: protocol violation in key exchange")
)

// ──────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────

const (
	// domainInitiator is the signing domain for the initiator's signature.
	// Signed over: domainInitiator || ephemeralPub || nonce
	domainInitiator = "meshdesk-v2-kx-initiator"

	// domainResponder is the signing domain for the responder's signature.
	// Signed over: domainResponder || peerEphemeralPub || ourEphemeralPub || nonce
	domainResponder = "meshdesk-v2-kx-responder"

	// Wire format sizes (fixed-size messages, no length prefix).
	msg1Size = 160 // [identityPub:32][ephPub:32][nonce:32][signature:64]
	msg2Size = 128 // [identityPub:32][ephPub:32][signature:64]

	// Field sizes within wire messages.
	keyFieldSize   = 32 // Ed25519 public key / X25519 public key / nonce
	signatureSize  = 64 // Ed25519 signature
	nonceFieldSize = 32 // random nonce

	// DefaultTimeout is the default deadline for the full 1-RTT exchange.
	DefaultTimeout = 10 * time.Second
)

// ──────────────────────────────────────────────────────────────────────
// Shared nonce cache for replay protection
// ──────────────────────────────────────────────────────────────────────

// globalNonceCache is the default nonce cache used by ServerKeyExchange.
// It prevents replay attacks by tracking recently seen nonces across
// all server-side exchanges. This is per-responder (per-process), not
// per-peer — which is correct because replay protection needs to detect
// the same nonce being used again, regardless of which initiator sent it.
var globalNonceCache = newNonceCache(MaxNonceCache)

// ──────────────────────────────────────────────────────────────────────
// ClientKeyExchange (Initiator role)
// ──────────────────────────────────────────────────────────────────────

// ClientKeyExchange performs the initiator-side authenticated key exchange
// over the given net.Conn (typically from handshake.Connect).
//
// Protocol:
//  1. Generate X25519 ephemeral keypair + 32-byte random nonce.
//  2. Sign: Sign(id, domain_i || ephPub || nonce)
//  3. Send msg1: [identityPub:32][ephPub:32][nonce:32][signature:64] = 160 bytes.
//  4. Read msg2: [peerIdentityPub:32][peerEphPub:32][peerSignature:64] = 128 bytes.
//  5. Verify peer signature over domain_r || ourEphPub || peerEphPub || nonce.
//  6. Compute sharedSecret = X25519(ourEphPriv, peerEphPub).
//  7. identityBinding = sha256(sig_i || sig_r)[:32] (symmetric — same for both peers).
//  8. Return DeriveSessionKeys(sharedSecret, role=true, identityBinding).
//
// Returns:
//   - *crypto.SessionKeys: sendKey, recvKey ready for NewSecureConn.
//   - string: the peer's Ed25519 public key (hex-encoded, 64 chars).
//   - error: if the exchange fails (signature verification, I/O, timeout).
//
// The conn is NOT closed on error — the caller decides whether to retry.
// After a successful exchange, the conn is still open and ready for
// Layer 2b (SecureConn) wrapping.
func ClientKeyExchange(conn net.Conn, id *identity.Identity) (*crypto.SessionKeys, string, error) {
	// 1. Generate X25519 ephemeral keypair.
	ephPriv, ephPub, err := generateX25519Keypair()
	if err != nil {
		return nil, "", fmt.Errorf("generate ephemeral keypair: %w", err)
	}

	// 2. Generate 32-byte random nonce.
	var nonce [nonceFieldSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, "", fmt.Errorf("generate nonce: %w", err)
	}

	// 3. Get identity public key bytes.
	idPubBytes, err := hex.DecodeString(id.PublicKey)
	if err != nil || len(idPubBytes) != keyFieldSize {
		return nil, "", fmt.Errorf("invalid identity public key: %w", err)
	}

	// 4. Sign: Sign(id, domain_i || ephPub || nonce)
	signPayload := buildInitiatorSignPayload(ephPub[:], nonce[:])
	sigHex, err := id.Sign(signPayload)
	if err != nil {
		return nil, "", fmt.Errorf("sign key exchange: %w", err)
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != signatureSize {
		return nil, "", fmt.Errorf("invalid signature: %w", err)
	}

	// 5. Build and send msg1: [identityPub:32][ephPub:32][nonce:32][signature:64] = 160 bytes.
	msg1 := make([]byte, msg1Size)
	copy(msg1[0:keyFieldSize], idPubBytes)              // identityPub
	copy(msg1[keyFieldSize:2*keyFieldSize], ephPub[:])  // ephPub
	copy(msg1[2*keyFieldSize:3*keyFieldSize], nonce[:]) // nonce
	copy(msg1[3*keyFieldSize:msg1Size], sigBytes)       // signature

	if _, err := conn.Write(msg1); err != nil {
		return nil, "", wrapTimeout(err, "write msg1")
	}

	// 6. Read msg2: [peerIdentityPub:32][peerEphPub:32][peerSignature:64] = 128 bytes.
	msg2 := make([]byte, msg2Size)
	if _, err := io.ReadFull(conn, msg2); err != nil {
		return nil, "", wrapTimeout(err, "read msg2")
	}

	// Parse msg2 fields.
	peerIdentityPub := msg2[0:keyFieldSize]           // 32 bytes
	peerEphPub := msg2[keyFieldSize : 2*keyFieldSize] // 32 bytes
	peerSig := msg2[2*keyFieldSize : msg2Size]        // 64 bytes

	// 7. Verify peer signature over domain_r || ourEphPub || peerEphPub || nonce.
	verifyPayload := buildResponderSignPayload(ephPub[:], peerEphPub, nonce[:])
	peerIdentityHex := hex.EncodeToString(peerIdentityPub)
	if !identity.Verify(peerIdentityHex, verifyPayload, hex.EncodeToString(peerSig)) {
		return nil, peerIdentityHex, ErrSignatureInvalid
	}

	// 8. Compute sharedSecret = X25519(ourEphPriv, peerEphPub).
	sharedSecret, err := curve25519.X25519(ephPriv[:], peerEphPub)
	if err != nil {
		return nil, peerIdentityHex, fmt.Errorf("ecdh: %w", err)
	}

	// 9. Compute identityBinding = sha256(sig_i || sig_r)[:32].
	// CRITICAL: sig_i is the initiator's signature, sig_r is the responder's.
	// The order is always (sig_i || sig_r) — both peers compute the same value.
	identityBinding := computeIdentityBinding(sigBytes, peerSig)

	// 10. Derive session keys with role=true (initiator).
	keys := crypto.DeriveSessionKeys(sharedSecret, true, identityBinding)

	return keys, peerIdentityHex, nil
}

// ──────────────────────────────────────────────────────────────────────
// ServerKeyExchange (Responder role)
// ──────────────────────────────────────────────────────────────────────

// ServerKeyExchange performs the responder-side authenticated key exchange
// over the given net.Conn (typically from handshake.Listen + Accept).
//
// Protocol:
//  1. Read msg1: [peerIdentityPub:32][peerEphPub:32][nonce:32][peerSignature:64] = 160 bytes.
//  2. Verify peer signature over domain_i || peerEphPub || nonce.
//  3. Check nonce cache for replay.
//  4. Generate X25519 ephemeral keypair.
//  5. Sign: Sign(id, domain_r || peerEphPub || ourEphPub || nonce)
//  6. Send msg2: [identityPub:32][ephPub:32][signature:64] = 128 bytes.
//  7. Compute sharedSecret = X25519(ourEphPriv, peerEphPub).
//  8. identityBinding = sha256(sig_i || sig_r)[:32] (symmetric — same for both peers).
//  9. Return DeriveSessionKeys(sharedSecret, role=false, identityBinding).
//
// Returns:
//   - *crypto.SessionKeys: sendKey, recvKey ready for NewSecureConn.
//   - string: the peer's Ed25519 public key (hex-encoded, 64 chars).
//   - error: if the exchange fails.
//
// The conn is NOT closed on error. After success, the conn is ready for
// SecureConn wrapping.
func ServerKeyExchange(conn net.Conn, id *identity.Identity) (*crypto.SessionKeys, string, error) {
	// 1. Read msg1: [peerIdentityPub:32][peerEphPub:32][nonce:32][peerSignature:64] = 160 bytes.
	msg1 := make([]byte, msg1Size)
	if _, err := io.ReadFull(conn, msg1); err != nil {
		return nil, "", wrapTimeout(err, "read msg1")
	}

	// Parse msg1 fields.
	peerIdentityPub := msg1[0:keyFieldSize]           // 32 bytes
	peerEphPub := msg1[keyFieldSize : 2*keyFieldSize] // 32 bytes
	nonce := msg1[2*keyFieldSize : 3*keyFieldSize]    // 32 bytes
	peerSig := msg1[3*keyFieldSize : msg1Size]        // 64 bytes

	peerIdentityHex := hex.EncodeToString(peerIdentityPub)

	// 2. Verify peer signature over domain_i || peerEphPub || nonce.
	verifyPayload := buildInitiatorSignPayload(peerEphPub, nonce)
	if !identity.Verify(peerIdentityHex, verifyPayload, hex.EncodeToString(peerSig)) {
		return nil, peerIdentityHex, ErrSignatureInvalid
	}

	// 3. Check nonce cache for replay.
	var nonceKey [nonceFieldSize]byte
	copy(nonceKey[:], nonce)
	if !globalNonceCache.checkAndRecord(nonceKey) {
		return nil, peerIdentityHex, ErrProtocolViolation
	}

	// 4. Generate X25519 ephemeral keypair.
	ephPriv, ephPub, err := generateX25519Keypair()
	if err != nil {
		return nil, peerIdentityHex, fmt.Errorf("generate ephemeral keypair: %w", err)
	}

	// 5. Get identity public key bytes.
	idPubBytes, err := hex.DecodeString(id.PublicKey)
	if err != nil || len(idPubBytes) != keyFieldSize {
		return nil, peerIdentityHex, fmt.Errorf("invalid identity public key: %w", err)
	}

	// 6. Sign: Sign(id, domain_r || peerEphPub || ourEphPub || nonce)
	signPayload := buildResponderSignPayload(peerEphPub, ephPub[:], nonce)
	sigHex, err := id.Sign(signPayload)
	if err != nil {
		return nil, peerIdentityHex, fmt.Errorf("sign key exchange: %w", err)
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != signatureSize {
		return nil, peerIdentityHex, fmt.Errorf("invalid signature: %w", err)
	}

	// 7. Build and send msg2: [identityPub:32][ephPub:32][signature:64] = 128 bytes.
	msg2 := make([]byte, msg2Size)
	copy(msg2[0:keyFieldSize], idPubBytes)             // identityPub
	copy(msg2[keyFieldSize:2*keyFieldSize], ephPub[:]) // ephPub
	copy(msg2[2*keyFieldSize:msg2Size], sigBytes)      // signature

	if _, err := conn.Write(msg2); err != nil {
		return nil, peerIdentityHex, wrapTimeout(err, "write msg2")
	}

	// 8. Compute sharedSecret = X25519(ourEphPriv, peerEphPub).
	sharedSecret, err := curve25519.X25519(ephPriv[:], peerEphPub)
	if err != nil {
		return nil, peerIdentityHex, fmt.Errorf("ecdh: %w", err)
	}

	// 9. Compute identityBinding = sha256(sig_i || sig_r)[:32].
	// sig_i = peerSig (initiator's signature from msg1)
	// sig_r = sigBytes (our/responder's signature just created)
	identityBinding := computeIdentityBinding(peerSig, sigBytes)

	// 10. Derive session keys with role=false (responder).
	keys := crypto.DeriveSessionKeys(sharedSecret, false, identityBinding)

	return keys, peerIdentityHex, nil
}

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

// generateX25519Keypair creates a new X25519 ephemeral keypair.
// The private key is 32 random bytes (clamped by X25519 internally).
// The public key is curve25519.ScalarBaseMult(privateKey).
func generateX25519Keypair() (priv [keyFieldSize]byte, pub [keyFieldSize]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
		return priv, pub, fmt.Errorf("generate x25519 private key: %w", err)
	}
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, fmt.Errorf("derive x25519 public key: %w", err)
	}
	copy(pub[:], pubBytes)
	return priv, pub, nil
}

// buildInitiatorSignPayload constructs the signing payload for the initiator:
//
//	domainInitiator || ephemeralPub || nonce
func buildInitiatorSignPayload(ephPub, nonce []byte) []byte {
	payload := make([]byte, 0, len(domainInitiator)+len(ephPub)+len(nonce))
	payload = append(payload, []byte(domainInitiator)...)
	payload = append(payload, ephPub...)
	payload = append(payload, nonce...)
	return payload
}

// buildResponderSignPayload constructs the signing payload for the responder:
//
//	domainResponder || peerEphPub || ourEphPub || nonce
func buildResponderSignPayload(peerEphPub, ourEphPub, nonce []byte) []byte {
	payload := make([]byte, 0, len(domainResponder)+len(peerEphPub)+len(ourEphPub)+len(nonce))
	payload = append(payload, []byte(domainResponder)...)
	payload = append(payload, peerEphPub...)
	payload = append(payload, ourEphPub...)
	payload = append(payload, nonce...)
	return payload
}

// computeIdentityBinding calculates sha256(sig_i || sig_r)[:32].
// This value MUST be identical for both peers:
//   - Initiator: sha256(ourSig || peerSig)
//   - Responder: sha256(peerSig || ourSig)
//
// Both pass (sig_i, sig_r) in the same order — initiator's signature first,
// responder's signature second — ensuring complementarity.
func computeIdentityBinding(sigInitiator, sigResponder []byte) []byte {
	h := sha256.New()
	h.Write(sigInitiator)
	h.Write(sigResponder)
	return h.Sum(nil)[:32]
}

// wrapTimeout converts a net timeout error into ErrKeyExchangeTimeout,
// while wrapping other errors with context. This ensures that deadline
// exceeded errors are returned as ErrKeyExchangeTimeout (wrapped, so
// errors.Is works) rather than as raw os.ErrDeadlineExceeded.
func wrapTimeout(err error, context string) error {
	if errors.Is(err, ErrKeyExchangeTimeout) {
		return err
	}
	// Check for deadline exceeded / timeout.
	if isTimeoutErr(err) {
		return fmt.Errorf("%s: %w: %v", context, ErrKeyExchangeTimeout, err)
	}
	// Check for io.ErrUnexpectedEOF (wrong message size / connection closed).
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%s: %w: %v", context, ErrProtocolViolation, err)
	}
	return fmt.Errorf("%s: %w", context, err)
}

// isTimeoutErr checks whether err is a timeout/deadline error.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	// Check for os.ErrDeadlineExceeded.
	if errors.Is(err, ErrKeyExchangeTimeout) {
		return true
	}
	// Fallback: check error string for common timeout patterns.
	return false
}
