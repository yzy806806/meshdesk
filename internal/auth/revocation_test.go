package auth

import (
	"crypto/ed25519"
	"testing"
)

func TestSignAndVerifyRevocation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	revokedPeer := "abc123peer-key-to-revoke"
	reason := "key compromised in CI leak"

	notice, err := SignRevocation(revokedPeer, priv, reason)
	if err != nil {
		t.Fatalf("sign revocation: %v", err)
	}

	if notice.RevokedPeer != revokedPeer {
		t.Errorf("expected revoked_peer %s, got %s", revokedPeer, notice.RevokedPeer)
	}
	if notice.Reason != reason {
		t.Errorf("expected reason %s, got %s", reason, notice.Reason)
	}
	if notice.Signature == "" {
		t.Error("expected non-empty signature")
	}

	// Verify with the correct public key
	if err := notice.Verify(pub); err != nil {
		t.Errorf("verify with correct key failed: %v", err)
	}

	// Verify with hex key
	pubHex := pubKeyToHex(pub)
	if err := notice.VerifyByHexKey(pubHex); err != nil {
		t.Errorf("verify by hex key failed: %v", err)
	}
}

func TestVerifyRevocationWrongKey(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)

	notice, err := SignRevocation("peer-to-revoke", priv1, "test")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify with the wrong key should fail
	if err := notice.Verify(pub2); err == nil {
		t.Error("expected verification to fail with wrong key")
	}
}

func TestVerifyRevocationTampered(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	notice, _ := SignRevocation("peer-to-revoke", priv, "legit reason")

	// Tamper with the reason
	notice.Reason = "tampered reason"

	if err := notice.Verify(pub); err == nil {
		t.Error("expected verification to fail for tampered notice")
	}
}

func TestVerifyRevocationBadSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	notice, _ := SignRevocation("peer-to-revoke", priv, "reason")
	notice.Signature = "invalid-hex-signature"

	if err := notice.Verify(pub); err == nil {
		t.Error("expected error for invalid hex signature")
	}
}

func TestGenerateRevokerKeyPair(t *testing.T) {
	pub, priv, err := GenerateRevokerKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(priv))
	}
}

// pubKeyToHex converts an Ed25519 public key to hex string.
func pubKeyToHex(pub ed25519.PublicKey) string {
	// Use the same encoding/hex package
	return hexEncodeToString(pub)
}

// hexEncodeToString encodes bytes as hex without importing encoding/hex
// (to avoid an import just for this helper).
func hexEncodeToString(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0xf]
	}
	return string(result)
}
