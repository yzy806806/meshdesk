package auth

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestNonceIssueAndVerify(t *testing.T) {
	nc := NewNonceChallenge(60 * time.Second)
	pub, priv, _ := ed25519.GenerateKey(nil)

	peerID := "requesting-peer-12345"

	// Issue nonce
	nonce, err := nc.Issue(peerID)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(nonce) != 32 {
		t.Errorf("expected 32-byte nonce, got %d", len(nonce))
	}

	// Sign the nonce
	sig := SignNonce(priv, nonce)

	// Verify
	pubHex := pubKeyToHex(pub)
	err = nc.Verify(peerID, pubHex, sig)
	if err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

func TestNonceVerifyNoPending(t *testing.T) {
	nc := NewNonceChallenge(60 * time.Second)
	pub, _, _ := ed25519.GenerateKey(nil)

	err := nc.Verify("nonexistent-peer", pubKeyToHex(pub), "somesig")
	if err == nil {
		t.Error("expected error for nonexistent pending challenge")
	}
}

func TestNonceVerifyWrongSignature(t *testing.T) {
	nc := NewNonceChallenge(60 * time.Second)
	pub, _, _ := ed25519.GenerateKey(nil)
	_, wrongPriv, _ := ed25519.GenerateKey(nil)

	peerID := "requesting-peer"
	nonce, _ := nc.Issue(peerID)

	// Sign with wrong key
	wrongSig := SignNonce(wrongPriv, nonce)

	err := nc.Verify(peerID, pubKeyToHex(pub), wrongSig)
	if err == nil {
		t.Error("expected error for wrong signature")
	}
}

func TestNonceVerifyExpired(t *testing.T) {
	nc := NewNonceChallenge(1 * time.Millisecond) // very short TTL
	pub, priv, _ := ed25519.GenerateKey(nil)

	peerID := "requesting-peer"
	nonce, _ := nc.Issue(peerID)

	// Wait for expiry
	time.Sleep(50 * time.Millisecond)

	sig := SignNonce(priv, nonce)
	err := nc.Verify(peerID, pubKeyToHex(pub), sig)
	if err == nil {
		t.Error("expected error for expired challenge")
	}
}

func TestNonceCannotReuse(t *testing.T) {
	nc := NewNonceChallenge(60 * time.Second)
	pub, priv, _ := ed25519.GenerateKey(nil)

	peerID := "requesting-peer"
	nonce, _ := nc.Issue(peerID)
	sig := SignNonce(priv, nonce)

	// First verify succeeds
	err := nc.Verify(peerID, pubKeyToHex(pub), sig)
	if err != nil {
		t.Fatalf("first verify failed: %v", err)
	}

	// Second verify should fail (consumed)
	err = nc.Verify(peerID, pubKeyToHex(pub), sig)
	if err == nil {
		t.Error("expected error for reused challenge")
	}
}

func TestNonceIssueReplaces(t *testing.T) {
	nc := NewNonceChallenge(60 * time.Second)
	peerID := "requesting-peer"

	nonce1, _ := nc.Issue(peerID)
	nonce2, _ := nc.Issue(peerID)

	if string(nonce1) == string(nonce2) {
		t.Error("expected different nonces when re-issuing")
	}

	if nc.PendingCount() != 1 {
		t.Errorf("expected 1 pending, got %d", nc.PendingCount())
	}
}

func TestNonceCleanupExpired(t *testing.T) {
	nc := NewNonceChallenge(1 * time.Millisecond)

	nc.Issue("peer1")
	nc.Issue("peer2")
	nc.Issue("peer3")

	if nc.PendingCount() != 3 {
		t.Fatalf("expected 3 pending, got %d", nc.PendingCount())
	}

	time.Sleep(50 * time.Millisecond)

	removed := nc.CleanupExpired()
	if removed != 3 {
		t.Errorf("expected 3 removed, got %d", removed)
	}
	if nc.PendingCount() != 0 {
		t.Errorf("expected 0 pending after cleanup, got %d", nc.PendingCount())
	}
}

func TestNonceDefaultTTL(t *testing.T) {
	nc := NewNonceChallenge(0) // zero → default 60s
	if nc.ttl != 60*time.Second {
		t.Errorf("expected default TTL 60s, got %v", nc.ttl)
	}
}
