package peer

import (
	"encoding/hex"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}
	if id.PrivateKey == "" {
		t.Error("PrivateKey is empty")
	}
	if id.PublicKey == "" {
		t.Error("PublicKey is empty")
	}
	if id.PrivateKey == id.PublicKey {
		t.Error("PrivateKey and PublicKey are identical")
	}

	// Keys should be 64 hex chars (32 bytes).
	if len(id.PrivateKey) != 64 {
		t.Errorf("PrivateKey length = %d, want 64", len(id.PrivateKey))
	}
	if len(id.PublicKey) != 64 {
		t.Errorf("PublicKey length = %d, want 64", len(id.PublicKey))
	}

	// Verify keys are valid hex.
	if _, err := hex.DecodeString(id.PrivateKey); err != nil {
		t.Errorf("PrivateKey is not valid hex: %v", err)
	}
	if _, err := hex.DecodeString(id.PublicKey); err != nil {
		t.Errorf("PublicKey is not valid hex: %v", err)
	}
}

func TestGenerateIdentityUniqueness(t *testing.T) {
	id1, _ := GenerateIdentity()
	id2, _ := GenerateIdentity()
	if id1.PrivateKey == id2.PrivateKey {
		t.Error("Two generated identities have the same private key")
	}
	if id1.PublicKey == id2.PublicKey {
		t.Error("Two generated identities have the same public key")
	}
}

func TestIdentityFromHex(t *testing.T) {
	// Generate an identity, then reconstruct it from the hex private key.
	id1, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	id2, err := IdentityFromHex(id1.PrivateKey)
	if err != nil {
		t.Fatalf("IdentityFromHex() error: %v", err)
	}

	if id2.PrivateKey != id1.PrivateKey {
		t.Errorf("PrivateKey mismatch: %s != %s", id2.PrivateKey, id1.PrivateKey)
	}
	if id2.PublicKey != id1.PublicKey {
		t.Errorf("PublicKey mismatch: %s != %s", id2.PublicKey, id1.PublicKey)
	}
}

func TestIdentityFromHexInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty", "", true},
		{"not hex", "zzzz", true},
		{"too short", "abcd", true},
		{"valid", "a" + "b0000000000000000000000000000000000000000000000000000000000000000"[:63], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := IdentityFromHex(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("IdentityFromHex(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestPublicKeyFromPrivateHex(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	pub, err := PublicKeyFromPrivateHex(id.PrivateKey)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivateHex() error: %v", err)
	}
	if pub != id.PublicKey {
		t.Errorf("Derived public key %s doesn't match %s", pub, id.PublicKey)
	}
}

func TestBase64Key(t *testing.T) {
	// Use a known 32-byte hex key.
	hexKey := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	b64, err := Base64Key(hexKey)
	if err != nil {
		t.Fatalf("Base64Key() error: %v", err)
	}
	if b64 != "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=" {
		t.Errorf("Base64Key() = %q, want expected base64", b64)
	}
}

func TestHexKey(t *testing.T) {
	// Round-trip: hex -> base64 -> hex
	originalHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	b64, _ := Base64Key(originalHex)
	backToHex, err := HexKey(b64)
	if err != nil {
		t.Fatalf("HexKey() error: %v", err)
	}
	if backToHex != originalHex {
		t.Errorf("HexKey() = %q, want %q", backToHex, originalHex)
	}
}

func TestKeyClamping(t *testing.T) {
	// Generate multiple identities and verify the private key is properly clamped.
	for i := 0; i < 100; i++ {
		id, err := GenerateIdentity()
		if err != nil {
			t.Fatalf("GenerateIdentity() error: %v", err)
		}
		priv, err := hex.DecodeString(id.PrivateKey)
		if err != nil {
			t.Fatalf("invalid hex: %v", err)
		}
		// Clamping: priv[0] & 248, priv[31] & 127 | 64
		if priv[0]&7 != 0 {
			t.Errorf("Iteration %d: private key byte 0 not clamped: %d", i, priv[0])
		}
		if priv[31]&128 != 0 {
			t.Errorf("Iteration %d: private key byte 31 high bit not cleared: %d", i, priv[31])
		}
		if priv[31]&64 == 0 {
			t.Errorf("Iteration %d: private key byte 31 bit 6 not set: %d", i, priv[31])
		}
	}
}
