package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// NonceChallenge implements the binary upgrade confirmation challenge
// from ARCHITECTURE.md Decision E:
//
//  1. Requesting node sends upgrade request
//  2. Target node responds with a cryptographic nonce
//  3. Requesting node signs the nonce with its service key
//  4. Target verifies signature before accepting the binary
//
// This prevents a compromised but authorized node from pushing a
// backdoored binary to every peer in one sweep — each target requires
// a fresh nonce challenge, and the requesting node must prove it holds
// the private key corresponding to its registered public key.
type NonceChallenge struct {
	mu       sync.Mutex
	pending  map[string]*pendingChallenge // requesterPeerID → challenge
	ttl      time.Duration
}

type pendingChallenge struct {
	Nonce       []byte
	RequesterID string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// NewNonceChallenge creates a nonce challenge manager with the given
// TTL for pending challenges (default 60s if zero).
func NewNonceChallenge(ttl time.Duration) *NonceChallenge {
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	return &NonceChallenge{
		pending: make(map[string]*pendingChallenge),
		ttl:     ttl,
	}
}

// Issue generates a new nonce challenge for the requesting peer.
// The nonce is 32 bytes of cryptographic randomness. The challenge
// expires after the configured TTL. Only one pending challenge per
// requester is allowed — issuing a new one replaces the old.
func (nc *NonceChallenge) Issue(requesterPeerID string) ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	now := time.Now()
	ch := &pendingChallenge{
		Nonce:       nonce,
		RequesterID: requesterPeerID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(nc.ttl),
	}

	nc.mu.Lock()
	nc.pending[requesterPeerID] = ch
	nc.mu.Unlock()

	return nonce, nil
}

// Verify checks that the requester's signature over the nonce is valid
// and that the challenge has not expired. On success, the challenge is
// consumed (deleted) — it cannot be reused.
//
// requesterPubKeyHex is the hex-encoded Ed25519 public key of the
// requesting node.
func (nc *NonceChallenge) Verify(requesterPeerID, requesterPubKeyHex, signatureHex string) error {
	nc.mu.Lock()
	ch, ok := nc.pending[requesterPeerID]
	if ok {
		delete(nc.pending, requesterPeerID)
	}
	nc.mu.Unlock()

	if !ok {
		return fmt.Errorf("no pending challenge for peer %s", shortID(requesterPeerID))
	}

	if time.Now().After(ch.ExpiresAt) {
		return fmt.Errorf("challenge expired")
	}

	pubKey, err := parseHexKey(requesterPubKeyHex)
	if err != nil {
		return fmt.Errorf("parse requester public key: %w", err)
	}

	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(pubKey, ch.Nonce, sig) {
		return fmt.Errorf("invalid nonce signature")
	}

	return nil
}

// SignNonce signs a nonce with the requesting node's Ed25519 private key.
// This is called by the requesting node after receiving a nonce from the
// target node.
func SignNonce(privKey ed25519.PrivateKey, nonce []byte) string {
	sig := ed25519.Sign(privKey, nonce)
	return hex.EncodeToString(sig)
}

// PendingCount returns the number of pending challenges (for monitoring).
func (nc *NonceChallenge) PendingCount() int {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return len(nc.pending)
}

// CleanupExpired removes expired challenges. Should be called periodically
// to prevent memory growth from abandoned upgrade requests.
func (nc *NonceChallenge) CleanupExpired() int {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	now := time.Now()
	count := 0
	for id, ch := range nc.pending {
		if now.After(ch.ExpiresAt) {
			delete(nc.pending, id)
			count++
		}
	}
	return count
}

// shortID returns a truncated peer ID for display.
func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
