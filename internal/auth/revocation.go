package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// RevocationNotice is a signed message that one mesh node gossips to
// all other nodes when it revokes a peer's key. The signature prevents
// a malicious node from revoking another node's peers.
//
// Wire format (for gossip transport):
//
//	{
//	  "revoked_peer":  "<hex public key>",
//	  "revoked_by":    "<hex public key>",
//	  "revoked_at":    "RFC3339",
//	  "reason":        "human-readable reason",
//	  "signature":     "<hex ed25519 signature>"
//	}
//
// The signature is computed over: revoked_peer || revoked_by || revoked_at || reason
type RevocationNotice struct {
	RevokedPeer string `json:"revoked_peer"`
	RevokedBy   string `json:"revoked_by"`
	RevokedAt   string `json:"revoked_at"`
	Reason      string `json:"reason"`
	Signature   string `json:"signature"`
}

// SignRevocation creates a signed revocation notice using the revoking
// node's Ed25519 private key. The private key must correspond to the
// public key in RevokedBy.
func SignRevocation(revokedPeer string, privKey ed25519.PrivateKey, reason string) (*RevocationNotice, error) {
	pubKey := privKey.Public().(ed25519.PublicKey)
	revokedBy := hex.EncodeToString(pubKey)
	revokedAt := time.Now().UTC().Format(time.RFC3339)

	msg := signableRevocationMessage(revokedPeer, revokedBy, revokedAt, reason)
	sig := ed25519.Sign(privKey, msg)

	return &RevocationNotice{
		RevokedPeer: revokedPeer,
		RevokedBy:   revokedBy,
		RevokedAt:   revokedAt,
		Reason:      reason,
		Signature:   hex.EncodeToString(sig),
	}, nil
}

// VerifyRevocation checks that a revocation notice was signed by the
// node claiming to have issued it (RevokedBy). Returns nil if valid.
func (rn *RevocationNotice) Verify(revokerPubKey ed25519.PublicKey) error {
	sig, err := hex.DecodeString(rn.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	msg := signableRevocationMessage(rn.RevokedPeer, rn.RevokedBy, rn.RevokedAt, rn.Reason)
	if !ed25519.Verify(revokerPubKey, msg, sig) {
		return fmt.Errorf("invalid revocation signature")
	}
	return nil
}

// VerifyRevocationByHexKey is a convenience method that accepts the
// revoker's public key as a hex string.
func (rn *RevocationNotice) VerifyByHexKey(revokerPubKeyHex string) error {
	pubKey, err := parseHexKey(revokerPubKeyHex)
	if err != nil {
		return fmt.Errorf("parse revoker key: %w", err)
	}
	return rn.Verify(pubKey)
}

// signableRevocationMessage builds the canonical byte sequence that is
// signed. The order and concatenation must match between Sign and Verify.
func signableRevocationMessage(revokedPeer, revokedBy, revokedAt, reason string) []byte {
	return []byte(revokedPeer + revokedBy + revokedAt + reason)
}

// parseHexKey converts a hex-encoded 32-byte Ed25519 public key to bytes.
func parseHexKey(hexKey string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode hex key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid key length: got %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// GenerateRevokerKeyPair creates an Ed25519 keypair for signing revocation
// notices. This is separate from the WireGuard keypair (which uses
// Curve25519/X25519). Having a separate signing key prevents a
// WireGuard key compromise from enabling forged revocations.
func GenerateRevokerKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
