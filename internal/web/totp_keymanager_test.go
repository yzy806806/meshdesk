package web

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestTOTPKeyManager_FromBytes_RoundTrip verifies that Seal/Open
// correctly encrypts and decrypts a TOTP secret.
func TestTOTPKeyManager_FromBytes_RoundTrip(t *testing.T) {
	masterSecret := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(i + 1)
	}

	km, err := NewTOTPKeyManagerFromBytes(masterSecret)
	if err != nil {
		t.Fatalf("NewTOTPKeyManagerFromBytes: %v", err)
	}

	secret := "JBSWY3DPEHPK3PXPTEST1234567890"
	ciphertext, err := km.Seal("alice", secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if string(ciphertext) == secret {
		t.Error("ciphertext should not equal plaintext")
	}

	plaintext, err := km.Open("alice", ciphertext)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if plaintext != secret {
		t.Errorf("round-trip mismatch: got %q, want %q", plaintext, secret)
	}
}

// TestTOTPKeyManager_DerivationDeterminism verifies that the same
// master secret always derives the same encryption key.
func TestTOTPKeyManager_DerivationDeterminism(t *testing.T) {
	masterSecret := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(42)
	}

	km1, _ := NewTOTPKeyManagerFromBytes(masterSecret)
	km2, _ := NewTOTPKeyManagerFromBytes(masterSecret)

	secret := "TESTSECRET1234567890ABCDEFGH"

	ct1, _ := km1.Seal("bob", secret)
	ct2, _ := km2.Seal("bob", secret)

	// Both should be able to decrypt each other's ciphertext
	pt1, err := km1.Open("bob", ct2)
	if err != nil {
		t.Errorf("km1 should decrypt km2's ciphertext: %v", err)
	}
	if pt1 != secret {
		t.Errorf("decryption mismatch: got %q, want %q", pt1, secret)
	}

	pt2, err := km2.Open("bob", ct1)
	if err != nil {
		t.Errorf("km2 should decrypt km1's ciphertext: %v", err)
	}
	if pt2 != secret {
		t.Errorf("decryption mismatch: got %q, want %q", pt2, secret)
	}
}

// TestTOTPKeyManager_WrongUsernameAADRejected verifies that a ciphertext
// sealed with one username cannot be opened with a different username.
func TestTOTPKeyManager_WrongUsernameAADRejected(t *testing.T) {
	masterSecret := make([]byte, 32)
	masterSecret[0] = 0xFF

	km, _ := NewTOTPKeyManagerFromBytes(masterSecret)

	secret := "SECRETKEY1234567890ABCDEFGHIJK"
	ciphertext, _ := km.Seal("alice", secret)

	// Try to open with wrong username — should fail
	_, err := km.Open("bob", ciphertext)
	if err == nil {
		t.Error("Open with wrong username should fail (AAD mismatch)")
	}
}

// TestTOTPKeyManager_CorruptedCiphertextRejected verifies that tampered
// ciphertext is rejected (GCM authentication tag check).
func TestTOTPKeyManager_CorruptedCiphertextRejected(t *testing.T) {
	masterSecret := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}

	km, _ := NewTOTPKeyManagerFromBytes(masterSecret)

	secret := "SECRETKEY1234567890ABCDEFGHIJK"
	ciphertext, _ := km.Seal("alice", secret)

	// Flip a bit in the ciphertext (after the nonce)
	if len(ciphertext) <= 13 {
		t.Fatalf("ciphertext too short: %d", len(ciphertext))
	}
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[13] ^= 0x01

	_, err := km.Open("alice", corrupted)
	if err == nil {
		t.Error("Open with corrupted ciphertext should fail")
	}
}

// TestTOTPKeyManager_NonceUniqueness verifies that sealing the same
// secret twice produces different ciphertexts (random nonce).
func TestTOTPKeyManager_NonceUniqueness(t *testing.T) {
	masterSecret := make([]byte, 32)
	km, _ := NewTOTPKeyManagerFromBytes(masterSecret)

	secret := "SAMESECRET1234567890ABCDEFGHIJK"

	ct1, _ := km.Seal("alice", secret)
	ct2, _ := km.Seal("alice", secret)

	if bytes.Equal(ct1, ct2) {
		t.Error("sealing the same secret twice should produce different ciphertexts (random nonce)")
	}

	// Both should decrypt to the same plaintext
	pt1, _ := km.Open("alice", ct1)
	pt2, _ := km.Open("alice", ct2)
	if pt1 != pt2 || pt1 != secret {
		t.Error("both ciphertexts should decrypt to the same plaintext")
	}
}

// TestTOTPKeyManager_DifferentMasterSecrets verifies that ciphertexts
// sealed with one master secret cannot be opened with a different one.
func TestTOTPKeyManager_DifferentMasterSecrets(t *testing.T) {
	ms1 := make([]byte, 32)
	ms2 := make([]byte, 32)
	ms2[0] = 1 // different

	km1, _ := NewTOTPKeyManagerFromBytes(ms1)
	km2, _ := NewTOTPKeyManagerFromBytes(ms2)

	secret := "SECRETKEY1234567890ABCDEFGHIJK"
	ciphertext, _ := km1.Seal("alice", secret)

	_, err := km2.Open("alice", ciphertext)
	if err == nil {
		t.Error("ciphertext from km1 should not be decryptable by km2 (different master secret)")
	}
}

// TestTOTPKeyManager_FileBased_GenerateAndLoad verifies that:
// 1. A new master secret is generated when the file doesn't exist
// 2. The file is created with mode 0600
// 3. On subsequent load, the same secret is used
func TestTOTPKeyManager_FileBased_GenerateAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	msPath := filepath.Join(tmpDir, "totp.ms")

	// First call: generates and writes the master secret
	km1, err := NewTOTPKeyManager(msPath, "")
	if err != nil {
		t.Fatalf("first NewTOTPKeyManager: %v", err)
	}

	// Verify file was created with 0600
	info, err := os.Stat(msPath)
	if err != nil {
		t.Fatalf("stat master secret file: %v", err)
	}
	if info.Mode() != 0600 {
		t.Errorf("master secret file mode = %o, want 0600", info.Mode())
	}

	// Seal a secret with km1
	secret := "TESTSECRET1234567890ABCDEFGHIJK"
	ciphertext, _ := km1.Seal("alice", secret)

	// Second call: loads the existing master secret
	km2, err := NewTOTPKeyManager(msPath, "")
	if err != nil {
		t.Fatalf("second NewTOTPKeyManager: %v", err)
	}

	// km2 should be able to decrypt what km1 sealed
	plaintext, err := km2.Open("alice", ciphertext)
	if err != nil {
		t.Fatalf("km2 should decrypt km1's ciphertext: %v", err)
	}
	if plaintext != secret {
		t.Errorf("round-trip mismatch: got %q, want %q", plaintext, secret)
	}
}

// TestTOTPKeyManager_LegacySecretMigration verifies that a legacy
// totp_secret from config.yaml is used as the initial master secret
// when the file doesn't exist.
func TestTOTPKeyManager_LegacySecretMigration(t *testing.T) {
	tmpDir := t.TempDir()
	msPath := filepath.Join(tmpDir, "totp.ms")

	legacySecret := "JBSWY3DPEHPK3PXP" // valid base32, 10 bytes

	// First call with legacy secret — should use it as master
	km1, err := NewTOTPKeyManager(msPath, legacySecret)
	if err != nil {
		t.Fatalf("NewTOTPKeyManager with legacy: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(msPath); err != nil {
		t.Fatalf("master secret file should exist after migration: %v", err)
	}

	// Seal and open should work
	secret := "TESTSECRET1234567890ABCDEFGHIJK"
	ciphertext, _ := km1.Seal("alice", secret)
	plaintext, _ := km1.Open("alice", ciphertext)
	if plaintext != secret {
		t.Errorf("round-trip mismatch: got %q, want %q", plaintext, secret)
	}
}

// TestTOTPKeyManager_LegacySecretIgnoredWhenFileExists verifies that
// the legacy secret is NOT used when the master secret file already exists.
func TestTOTPKeyManager_LegacySecretIgnoredWhenFileExists(t *testing.T) {
	tmpDir := t.TempDir()
	msPath := filepath.Join(tmpDir, "totp.ms")

	// First: generate without legacy
	km1, _ := NewTOTPKeyManager(msPath, "")
	secret := "TESTSECRET1234567890ABCDEFGHIJK"
	ciphertext, _ := km1.Seal("alice", secret)

	// Second: load with legacy — legacy should be ignored
	km2, err := NewTOTPKeyManager(msPath, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("second NewTOTPKeyManager: %v", err)
	}

	// km2 should still decrypt km1's ciphertext (same master secret)
	plaintext, err := km2.Open("alice", ciphertext)
	if err != nil {
		t.Fatalf("legacy should be ignored when file exists — decryption failed: %v", err)
	}
	if plaintext != secret {
		t.Errorf("round-trip mismatch: got %q, want %q", plaintext, secret)
	}
}

// TestTOTPKeyManager_EmptyCiphertextRejected verifies that opening
// an empty or too-short ciphertext returns an error.
func TestTOTPKeyManager_EmptyCiphertextRejected(t *testing.T) {
	masterSecret := make([]byte, 32)
	km, _ := NewTOTPKeyManagerFromBytes(masterSecret)

	_, err := km.Open("alice", []byte{})
	if err == nil {
		t.Error("opening empty ciphertext should fail")
	}

	_, err = km.Open("alice", make([]byte, 11)) // < gcmNonceSize
	if err == nil {
		t.Error("opening too-short ciphertext should fail")
	}
}

// TestTOTPKeyManager_ShortMasterSecret verifies that a master secret
// shorter than 32 bytes is rejected.
func TestTOTPKeyManager_ShortMasterSecret(t *testing.T) {
	shortSecret := make([]byte, 16)
	_, err := NewTOTPKeyManagerFromBytes(shortSecret)
	if err == nil {
		t.Error("short master secret should be rejected")
	}
}
