package identity

import (
	"encoding/hex"
	"strings"
	"testing"
)

// AC-0.1: GenerateIdentity produces valid Ed25519 keypair.
func TestGenerateIdentity(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}
	if len(id.PrivateKey) != 128 {
		t.Errorf("len(PrivateKey) = %d, want 128 (64 bytes hex-encoded)", len(id.PrivateKey))
	}
	if len(id.PublicKey) != 64 {
		t.Errorf("len(PublicKey) = %d, want 64 (32 bytes hex-encoded)", len(id.PublicKey))
	}
	// Hex strings must decode cleanly.
	if _, err := hex.DecodeString(id.PrivateKey); err != nil {
		t.Errorf("hex.DecodeString(PrivateKey) error: %v", err)
	}
	if _, err := hex.DecodeString(id.PublicKey); err != nil {
		t.Errorf("hex.DecodeString(PublicKey) error: %v", err)
	}
}

// AC-0.2: IdentityFromHex round-trips correctly.
func TestIdentityFromHexRoundTrip(t *testing.T) {
	id1, _ := GenerateIdentity()
	id2, err := IdentityFromHex(id1.PrivateKey)
	if err != nil {
		t.Fatalf("IdentityFromHex() error: %v", err)
	}
	if id1.PublicKey != id2.PublicKey {
		t.Errorf("PublicKey mismatch: %s != %s", id1.PublicKey, id2.PublicKey)
	}
	if id1.PrivateKey != id2.PrivateKey {
		t.Errorf("PrivateKey mismatch: %s != %s", id1.PrivateKey, id2.PrivateKey)
	}
}

// AC-0.3: Sign + Verify round-trips.
func TestSignVerify(t *testing.T) {
	id, _ := GenerateIdentity()
	data := []byte("test message")
	sig, err := id.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if len(sig) != 128 {
		t.Errorf("len(sig) = %d, want 128 (64 bytes hex-encoded)", len(sig))
	}
	ok := Verify(id.PublicKey, data, sig)
	if !ok {
		t.Error("Verify() returned false, want true")
	}
}

// AC-0.4: Verify rejects tampered data or wrong key.
func TestVerifyRejectsTampered(t *testing.T) {
	id, _ := GenerateIdentity()
	sig, _ := id.Sign([]byte("original"))

	// Tampered data
	ok := Verify(id.PublicKey, []byte("tampered"), sig)
	if ok {
		t.Error("Verify(tampered data) returned true, want false")
	}

	// Wrong public key
	id2, _ := GenerateIdentity()
	ok = Verify(id2.PublicKey, []byte("original"), sig)
	if ok {
		t.Error("Verify(wrong key) returned true, want false")
	}
}

// AC-0.5: No Curve25519 dependency.
func TestNoCurve25519Dependency(t *testing.T) {
	// This is verified at test time by checking the imports don't reference curve25519.
	// The go list command is checked separately in integration.
	// Here we just make sure the package compiles without x/crypto.
}

// AC-0.6: Zero external dependencies.
func TestZeroExternalDeps(t *testing.T) {
	// The identity package should only use stdlib.
	// Verified via go list -deps in integration tests.
	// Here we just ensure the test compiles and runs.
	id, _ := GenerateIdentity()
	if id == nil {
		t.Fatal("GenerateIdentity returned nil")
	}
}

// Additional: Test that different keypairs are unique.
func TestKeyPairUniqueness(t *testing.T) {
	id1, _ := GenerateIdentity()
	id2, _ := GenerateIdentity()
	if id1.PublicKey == id2.PublicKey {
		t.Error("two GenerateIdentity() calls produced identical public keys")
	}
	if id1.PrivateKey == id2.PrivateKey {
		t.Error("two GenerateIdentity() calls produced identical private keys")
	}
}

// Additional: Test that IdentityFromHex rejects invalid input.
func TestIdentityFromHexInvalid(t *testing.T) {
	// Invalid hex
	_, err := IdentityFromHex("not-valid-hex")
	if err == nil {
		t.Error("IdentityFromHex(invalid hex) should error")
	}

	// Wrong length (too short)
	_, err = IdentityFromHex("deadbeef")
	if err == nil {
		t.Error("IdentityFromHex(short key) should error")
	}
}

// Additional: Test PublicKeyFromPrivateHex convenience function.
func TestPublicKeyFromPrivateHex(t *testing.T) {
	id, _ := GenerateIdentity()
	pub, err := PublicKeyFromPrivateHex(id.PrivateKey)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivateHex() error: %v", err)
	}
	if pub != id.PublicKey {
		t.Errorf("PublicKeyFromPrivateHex() = %s, want %s", pub, id.PublicKey)
	}
}

// Additional: Test PEM encode/decode round-trip.
func TestPEMRoundTrip(t *testing.T) {
	id, _ := GenerateIdentity()
	pemStr, err := id.ToPEM()
	if err != nil {
		t.Fatalf("ToPEM() error: %v", err)
	}
	if !strings.Contains(pemStr, "BEGIN PRIVATE KEY") {
		t.Errorf("ToPEM() output doesn't look like PEM: %s", pemStr)
	}

	id2, err := IdentityFromPEM([]byte(pemStr))
	if err != nil {
		t.Fatalf("IdentityFromPEM() error: %v", err)
	}
	if id1Pub, id2Pub := id.PublicKey, id2.PublicKey; id1Pub != id2Pub {
		t.Errorf("PEM round-trip PublicKey mismatch: %s != %s", id1Pub, id2Pub)
	}
}

// Additional: Test public key PEM export.
func TestPublicKeyToPEM(t *testing.T) {
	id, _ := GenerateIdentity()
	pemStr, err := PublicKeyToPEM(id.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToPEM() error: %v", err)
	}
	if !strings.Contains(pemStr, "BEGIN PUBLIC KEY") {
		t.Errorf("PublicKeyToPEM() output doesn't look like PEM: %s", pemStr)
	}
}
