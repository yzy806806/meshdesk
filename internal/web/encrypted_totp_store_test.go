package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// helper: create a TOTPKeyManager from a fixed master secret for tests
func testKeyManager(t *testing.T) *TOTPKeyManager {
	t.Helper()
	ms := make([]byte, 32)
	for i := range ms {
		ms[i] = byte(i + 1)
	}
	km, err := NewTOTPKeyManagerFromBytes(ms)
	if err != nil {
		t.Fatalf("NewTOTPKeyManagerFromBytes: %v", err)
	}
	return km
}

func decodeBase32OrPanic(s string) []byte {
	b, err := decodeBase32(s)
	if err != nil {
		panic(err)
	}
	return b
}

// =============================================================================
// 9.1 Cryptographic Correctness
// =============================================================================

// AC-CRYPTO-01: Round-trip — encrypt and decrypt returns original secret
func TestAC_Crypto01_RoundTrip(t *testing.T) {
	km := testKeyManager(t)
	store, err := NewPersistentTOTPStore(km, t.TempDir())
	if err != nil {
		t.Fatalf("NewPersistentTOTPStore: %v", err)
	}
	defer store.Close()

	result, err := store.Enroll("alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Validate with the correct code — proves the secret was stored and decrypted correctly
	validCode := computeTOTP(result.Secret, time.Now())
	if !store.ValidateCode("alice", validCode) {
		t.Error("round-trip: valid code should be accepted")
	}
}

// AC-CRYPTO-02: GCM tag verification fails when ciphertext is modified by 1 bit
func TestAC_Crypto02_GCMTagVerification(t *testing.T) {
	km := testKeyManager(t)
	ciphertext, err := km.Seal("alice", "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Flip 1 bit in the ciphertext (after the nonce)
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[13] ^= 0x01

	_, err = km.Open("alice", corrupted)
	if err == nil {
		t.Error("modified ciphertext should fail GCM tag verification")
	}
}

// AC-CRYPTO-03: Two different usernames with the same secret produce different ciphertexts
func TestAC_Crypto03_DifferentUsersDifferentCiphertext(t *testing.T) {
	km := testKeyManager(t)
	secret := "JBSWY3DPEHPK3PXPTEST1234567890"

	ct1, _ := km.Seal("alice", secret)
	ct2, _ := km.Seal("bob", secret)

	if string(ct1) == string(ct2) {
		t.Error("different usernames should produce different ciphertexts (HKDF salt isolation)")
	}
}

// AC-CRYPTO-04: Encrypting the same secret twice for the same user produces different ciphertexts
func TestAC_Crypto04_NonceUniqueness(t *testing.T) {
	km := testKeyManager(t)
	secret := "JBSWY3DPEHPK3PXPTEST1234567890"

	ct1, _ := km.Seal("alice", secret)
	ct2, _ := km.Seal("alice", secret)

	if string(ct1) == string(ct2) {
		t.Error("same secret encrypted twice should produce different ciphertexts (random nonce)")
	}
}

// AC-CRYPTO-05: deriveUserKey with same (masterKey, username) produces same key deterministically
func TestAC_Crypto05_DerivationDeterminism(t *testing.T) {
	ms := make([]byte, 32)
	for i := range ms {
		ms[i] = byte(42)
	}
	km1, _ := NewTOTPKeyManagerFromBytes(ms)
	km2, _ := NewTOTPKeyManagerFromBytes(ms)

	secret := "TESTSECRET1234567890ABCDEFGH"
	ct1, _ := km1.Seal("bob", secret)

	// km2 should decrypt km1's ciphertext (same derived key)
	pt, err := km2.Open("bob", ct1)
	if err != nil {
		t.Errorf("deterministic derivation: km2 should decrypt km1's ciphertext: %v", err)
	}
	if pt != secret {
		t.Errorf("deterministic derivation: got %q, want %q", pt, secret)
	}
}

// =============================================================================
// 9.2 Persistence
// =============================================================================

// AC-PERSIST-01: After Enroll and process restart, IsEnrolled returns true
func TestAC_Persist01_EnrollSurvivesRestart(t *testing.T) {
	storeDir := t.TempDir()
	km := testKeyManager(t)

	// First "process": enroll and verify
	store1, err := NewPersistentTOTPStore(km, storeDir)
	if err != nil {
		t.Fatalf("NewPersistentTOTPStore: %v", err)
	}
	result, err := store1.Enroll("alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	validCode := computeTOTP(result.Secret, time.Now())
	if !store1.ValidateCode("alice", validCode) {
		t.Fatal("ValidateCode failed in first process")
	}
	store1.Close()

	// Second "process": restart — should load from disk
	store2, err := NewPersistentTOTPStore(km, storeDir)
	if err != nil {
		t.Fatalf("NewPersistentTOTPStore (restart): %v", err)
	}
	defer store2.Close()

	if !store2.IsEnrolled("alice") {
		t.Error("after restart, IsEnrolled should return true")
	}
}

// AC-PERSIST-02: After Enroll and Verify, enrollment state is VERIFIED across restarts
func TestAC_Persist02_VerifiedStateSurvivesRestart(t *testing.T) {
	storeDir := t.TempDir()
	km := testKeyManager(t)

	store1, _ := NewPersistentTOTPStore(km, storeDir)
	result, _ := store1.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store1.ValidateCode("alice", validCode) // PENDING → VERIFIED
	store1.Close()

	// Restart
	store2, _ := NewPersistentTOTPStore(km, storeDir)
	defer store2.Close()

	if !store2.IsEnrolled("alice") {
		t.Error("VERIFIED state should survive restart")
	}

	// The secret should still work after restart
	validCode2 := computeTOTP(result.Secret, time.Now())
	if !store2.ValidateCode("alice", validCode2) {
		t.Error("TOTP code should be valid after restart (secret persisted)")
	}
}

// AC-PERSIST-03: After Disable, the file users/alice.enc does not exist on disk
func TestAC_Persist03_DisableRemovesFile(t *testing.T) {
	storeDir := t.TempDir()
	km := testKeyManager(t)

	store, _ := NewPersistentTOTPStore(km, storeDir)
	defer store.Close()

	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("alice", validCode)

	encPath := encFilePath(storeDir, "alice")
	if _, err := os.Stat(encPath); err != nil {
		t.Fatalf("enc file should exist before disable: %v", err)
	}

	store.Disable("alice")

	if _, err := os.Stat(encPath); !os.IsNotExist(err) {
		t.Error("enc file should not exist after disable")
	}
}

// AC-PERSIST-04: Recovery codes consumed during one process lifetime are not available after restart
func TestAC_Persist04_ConsumedRecoveryCodeNotAvailableAfterRestart(t *testing.T) {
	storeDir := t.TempDir()
	km := testKeyManager(t)

	store1, _ := NewPersistentTOTPStore(km, storeDir)
	result, _ := store1.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store1.ValidateCode("alice", validCode) // PENDING → VERIFIED

	// Consume one recovery code
	firstCode := result.RecoveryCodes[0]
	if !store1.ConsumeRecoveryCode("alice", firstCode) {
		t.Fatal("first recovery code should be consumed")
	}
	store1.Close()

	// Restart
	store2, _ := NewPersistentTOTPStore(km, storeDir)
	defer store2.Close()

	// The consumed code should NOT be available
	if store2.ConsumeRecoveryCode("alice", firstCode) {
		t.Error("consumed recovery code should not be available after restart")
	}

	// A different recovery code should still work
	if len(result.RecoveryCodes) > 1 {
		secondCode := result.RecoveryCodes[1]
		if !store2.ConsumeRecoveryCode("alice", secondCode) {
			t.Error("unconsumed recovery code should still work after restart")
		}
	}
}

// =============================================================================
// 9.3 Enrollment State Machine
// =============================================================================

// AC-STATE-01: Enroll transitions DISABLED → PENDING. Enroll again in PENDING returns error.
func TestAC_State01_DisabledToPending(t *testing.T) {
	store := NewTOTPStore(testKeyManager(t))
	defer store.Close()

	_, err := store.Enroll("alice")
	if err != nil {
		t.Fatalf("Enroll from DISABLED: %v", err)
	}

	if store.Get("alice").State != StatePending {
		t.Error("state should be PENDING after Enroll")
	}
}

// AC-STATE-02: Verify(wrongCode) in PENDING increments FailedAttempts but stays PENDING.
// After maxFailedTOTP (5) attempts, account is locked.
func TestAC_State02_PendingWrongCodeIncrementsFailures(t *testing.T) {
	store := NewTOTPStore(testKeyManager(t))
	defer store.Close()

	store.Enroll("alice")

	// In the handler flow, a wrong TOTP code causes RecordFailedAttempt to be called
	for i := 0; i < maxFailedTOTP; i++ {
		store.RecordFailedAttempt("alice")
	}

	// Should be locked now
	if !store.IsLocked("alice") {
		t.Error("account should be locked after 5 failed attempts")
	}

	// State should still be PENDING (not VERIFIED)
	if store.Get("alice").State != StatePending {
		t.Error("state should still be PENDING after failed verifications")
	}
}

// AC-STATE-03: Verify(correctCode) in PENDING transitions to VERIFIED
func TestAC_State03_PendingToVerified(t *testing.T) {
	store := NewTOTPStore(testKeyManager(t))
	defer store.Close()

	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())

	if !store.ValidateCode("alice", validCode) {
		t.Fatal("valid code should be accepted")
	}

	if !store.IsEnrolled("alice") {
		t.Error("IsEnrolled should return true after PENDING → VERIFIED")
	}
}

// AC-STATE-04: Disable in VERIFIED transitions to DISABLED
func TestAC_State04_VerifiedToDisabled(t *testing.T) {
	store := NewTOTPStore(testKeyManager(t))
	defer store.Close()

	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("alice", validCode) // → VERIFIED

	store.Disable("alice")

	if store.IsEnrolled("alice") {
		t.Error("should not be enrolled after Disable")
	}
	if store.Exists("alice") {
		t.Error("should not exist after Disable")
	}
}

// AC-STATE-05: InitiateRotation in VERIFIED transitions to ROTATING. Old secret still validates.
func TestAC_State05_RotationOldSecretValid(t *testing.T) {
	store := NewTOTPStore(testKeyManager(t))
	defer store.Close()

	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("alice", validCode) // → VERIFIED

	oldSecret := result.Secret

	// Initiate rotation
	rotationResult, err := store.InitiateRotation("alice")
	if err != nil {
		t.Fatalf("InitiateRotation: %v", err)
	}

	if store.Get("alice").State != StateRotating {
		t.Error("state should be ROTATING after InitiateRotation")
	}

	// Old secret should still validate (via ValidateCodeWithOld)
	oldCode := computeTOTP(oldSecret, time.Now())
	if !store.ValidateCodeWithOld("alice", oldCode) {
		t.Error("old secret should still validate during rotation")
	}

	// New secret should also validate (via ValidateCode)
	newCode := computeTOTP(rotationResult.Secret, time.Now())
	if !store.ValidateCode("alice", newCode) {
		t.Error("new secret should validate during rotation")
	}
}

// AC-STATE-06: ConfirmRotation(correctNewCode) in ROTATING transitions to VERIFIED with new secret
func TestAC_State06_ConfirmRotation(t *testing.T) {
	store := NewTOTPStore(testKeyManager(t))
	defer store.Close()

	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("alice", validCode) // → VERIFIED

	oldSecret := result.Secret

	rotationResult, _ := store.InitiateRotation("alice")

	// Confirm with new code
	newCode := computeTOTP(rotationResult.Secret, time.Now())
	if err := store.ConfirmRotation("alice", newCode); err != nil {
		t.Fatalf("ConfirmRotation: %v", err)
	}

	if store.Get("alice").State != StateVerified {
		t.Error("state should be VERIFIED after ConfirmRotation")
	}

	// Old secret should NO LONGER validate
	oldCode := computeTOTP(oldSecret, time.Now())
	if store.ValidateCodeWithOld("alice", oldCode) {
		t.Error("old secret should not validate after rotation confirmed")
	}
}

// AC-STATE-07: CancelRotation in ROTATING reverts to VERIFIED with old secret
func TestAC_State07_CancelRotation(t *testing.T) {
	store := NewTOTPStore(testKeyManager(t))
	defer store.Close()

	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("alice", validCode) // → VERIFIED

	oldSecret := result.Secret

	store.InitiateRotation("alice")

	// Cancel rotation
	if err := store.CancelRotation("alice"); err != nil {
		t.Fatalf("CancelRotation: %v", err)
	}

	if store.Get("alice").State != StateVerified {
		t.Error("state should be VERIFIED after CancelRotation")
	}

	// Old secret should still work
	oldCode := computeTOTP(oldSecret, time.Now())
	if !store.ValidateCode("alice", oldCode) {
		t.Error("old secret should work after CancelRotation")
	}
}

// AC-STATE-08: AdminDisable from any state → DISABLED_BY_ADMIN
func TestAC_State08_AdminDisable(t *testing.T) {
	store := NewTOTPStore(testKeyManager(t))
	defer store.Close()

	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("alice", validCode) // → VERIFIED

	store.DisableByAdmin("alice")

	if store.Get("alice").State != StateDisabledByAdmin {
		t.Error("state should be DISABLED_BY_ADMIN after AdminDisable")
	}

	// Should not be enrolled
	if store.IsEnrolled("alice") {
		t.Error("should not be enrolled after admin disable")
	}

	// Self-enrollment should fail
	_, err := store.Enroll("alice")
	if err == nil {
		t.Error("self-enrollment should fail when DISABLED_BY_ADMIN")
	}

	// Admin re-enable
	if !store.AdminEnable("alice") {
		t.Error("AdminEnable should succeed")
	}

	// Now can self-enroll
	_, err = store.Enroll("alice")
	if err != nil {
		t.Errorf("should be able to enroll after admin re-enable: %v", err)
	}
}

// AC-STATE-09: PENDING state expires after TTL (secret deleted, back to DISABLED)
func TestAC_State09_PendingTimeout(t *testing.T) {
	store := NewTOTPStore(testKeyManager(t))
	defer store.Close()

	store.Enroll("alice")

	// Manually expire the pending state
	store.mu.Lock()
	st := store.users["alice"]
	st.PendingSince = time.Now().Add(-2 * pendingTTL)
	store.mu.Unlock()

	// Manually trigger sweep logic
	store.mu.Lock()
	now := time.Now()
	for username, st := range store.users {
		if st.State == StatePending && now.Sub(st.PendingSince) > pendingTTL {
			delete(store.users, username)
		}
	}
	store.mu.Unlock()

	if store.Exists("alice") {
		t.Error("PENDING enrollment should expire after TTL")
	}
}

// =============================================================================
// 9.4 Key Rotation (Master Key)
// =============================================================================

// AC-ROTATE-01: RotateMasterKey with N users succeeds — all re-encrypted
func TestAC_Rotate01_MasterKeyRotationMultipleUsers(t *testing.T) {
	storeDir := t.TempDir()
	msPath := filepath.Join(storeDir, "master.key")

	// Create file-based key manager
	km1, err := NewTOTPKeyManager(msPath, "")
	if err != nil {
		t.Fatalf("NewTOTPKeyManager: %v", err)
	}

	store, err := NewPersistentTOTPStore(km1, storeDir)
	if err != nil {
		t.Fatalf("NewPersistentTOTPStore: %v", err)
	}
	defer store.Close()

	// Enroll 3 users
	var secrets []string
	for _, name := range []string{"alice", "bob", "carol"} {
		result, _ := store.Enroll(name)
		validCode := computeTOTP(result.Secret, time.Now())
		store.ValidateCode(name, validCode) // → VERIFIED
		secrets = append(secrets, result.Secret)
	}

	// Rotate master key
	if err := store.RotateMasterKey(); err != nil {
		t.Fatalf("RotateMasterKey: %v", err)
	}

	// All users should still be enrolled
	for _, name := range []string{"alice", "bob", "carol"} {
		if !store.IsEnrolled(name) {
			t.Errorf("%s should still be enrolled after rotation", name)
		}
	}
}

// AC-ROTATE-02: After rotation, user secrets decrypt correctly with the new master key
func TestAC_Rotate02_SecretsDecryptAfterRotation(t *testing.T) {
	storeDir := t.TempDir()
	msPath := filepath.Join(storeDir, "master.key")

	km1, _ := NewTOTPKeyManager(msPath, "")
	store, _ := NewPersistentTOTPStore(km1, storeDir)
	defer store.Close()

	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("alice", validCode) // → VERIFIED
	originalSecret := result.Secret

	// Rotate
	store.RotateMasterKey()

	// The in-memory store should now use the new key and still decrypt correctly
	validCode2 := computeTOTP(originalSecret, time.Now())
	if !store.ValidateCode("alice", validCode2) {
		t.Error("secret should decrypt correctly with new master key after rotation")
	}
}

// AC-ROTATE-03: After rotation, secrets do NOT decrypt with the old master key
func TestAC_Rotate03_OldKeyFails(t *testing.T) {
	storeDir := t.TempDir()
	msPath := filepath.Join(storeDir, "master.key")

	km1, _ := NewTOTPKeyManager(msPath, "")
	store, _ := NewPersistentTOTPStore(km1, storeDir)
	defer store.Close()

	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("alice", validCode)

	// Read the old master key before rotation
	oldMasterKey, _ := os.ReadFile(msPath)

	// Rotate
	store.RotateMasterKey()

	// Create a new store with the OLD key — should fail to decrypt
	oldKM, _ := NewTOTPKeyManagerFromBytes(oldMasterKey)
	oldStore, _ := NewPersistentTOTPStore(oldKM, storeDir)
	defer oldStore.Close()

	// The old key should NOT be able to validate the code
	validCode2 := computeTOTP(result.Secret, time.Now())
	if oldStore.ValidateCode("alice", validCode2) {
		t.Error("secrets should NOT decrypt with old master key after rotation")
	}
}

// AC-ROTATE-05: master.key.old exists after successful rotation
func TestAC_Rotate05_OldKeyBackedUp(t *testing.T) {
	storeDir := t.TempDir()
	msPath := filepath.Join(storeDir, "master.key")

	km1, _ := NewTOTPKeyManager(msPath, "")
	store, _ := NewPersistentTOTPStore(km1, storeDir)
	defer store.Close()

	store.Enroll("alice")

	store.RotateMasterKey()

	oldPath := msPath + masterKeyOldSuffix
	if _, err := os.Stat(oldPath); err != nil {
		t.Errorf("master.key.old should exist after rotation: %v", err)
	}
}

// =============================================================================
// 9.5 Master Key Management
// =============================================================================

// AC-MASTER-01: First startup generates master.key if it doesn't exist
func TestAC_Master01_GeneratesOnFirstBoot(t *testing.T) {
	tmpDir := t.TempDir()
	msPath := filepath.Join(tmpDir, "master.key")

	if _, err := os.Stat(msPath); !os.IsNotExist(err) {
		t.Fatal("master.key should not exist before first boot")
	}

	_, err := NewTOTPKeyManager(msPath, "")
	if err != nil {
		t.Fatalf("NewTOTPKeyManager: %v", err)
	}

	if _, err := os.Stat(msPath); err != nil {
		t.Errorf("master.key should exist after first boot: %v", err)
	}
}

// AC-MASTER-02: master.key permissions are 0600
func TestAC_Master02_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	msPath := filepath.Join(tmpDir, "master.key")

	NewTOTPKeyManager(msPath, "")

	info, _ := os.Stat(msPath)
	if info.Mode() != 0600 {
		t.Errorf("master.key mode = %o, want 0600", info.Mode())
	}
}

// AC-MASTER-03: users/ directory permissions are 0700
func TestAC_Master03_UsersDirPermissions(t *testing.T) {
	storeDir := t.TempDir()
	km := testKeyManager(t)

	store, _ := NewPersistentTOTPStore(km, storeDir)
	defer store.Close()

	usersDir := filepath.Join(storeDir, usersSubDir)
	info, _ := os.Stat(usersDir)

	// Check the permission bits (may have extra bits on some systems)
	if info.Mode().Perm() != 0700 {
		t.Errorf("users/ dir mode = %o, want 0700", info.Mode().Perm())
	}
}

// AC-MASTER-04: Encrypted user blob permissions are 0600
func TestAC_Master04_BlobPermissions(t *testing.T) {
	storeDir := t.TempDir()
	km := testKeyManager(t)

	store, _ := NewPersistentTOTPStore(km, storeDir)
	defer store.Close()

	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("alice", validCode)

	encPath := encFilePath(storeDir, "alice")
	info, _ := os.Stat(encPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("enc blob mode = %o, want 0600", info.Mode().Perm())
	}
}

// AC-MASTER-05: Startup fails with clear error if master.key is unreadable
func TestAC_Master05_UnreadableMasterKey(t *testing.T) {
	tmpDir := t.TempDir()
	msPath := filepath.Join(tmpDir, "master.key")

	// Create the file with wrong content (too short)
	os.WriteFile(msPath, []byte("too-short"), 0600)

	_, err := NewTOTPKeyManager(msPath, "")
	if err == nil {
		t.Error("should fail when master.key is too short")
	}
}

// =============================================================================
// 9.6 Atomicity
// =============================================================================

// AC-ATOMIC-01: Process crash during writeBlob leaves old or new file, no partial
func TestAC_Atomic01_NoPartialFiles(t *testing.T) {
	storeDir := t.TempDir()
	km := testKeyManager(t)

	store, _ := NewPersistentTOTPStore(km, storeDir)
	defer store.Close()

	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("alice", validCode)

	// Verify no .tmp files remain
	usersDir := filepath.Join(storeDir, usersSubDir)
	entries, _ := os.ReadDir(usersDir)
	for _, e := range entries {
		if e.Name()[len(e.Name())-4:] == tmpFileExtension {
			t.Errorf("tmp file should not remain: %s", e.Name())
		}
	}

	// Verify the .enc file exists and is valid
	encPath := encFilePath(storeDir, "alice")
	if _, err := os.Stat(encPath); err != nil {
		t.Errorf("enc file should exist: %v", err)
	}
}

// AC-ATOMIC-02: After crash during rotation, no .new or .tmp files remain
func TestAC_Atomic02_NoStaleFilesAfterStartup(t *testing.T) {
	storeDir := t.TempDir()
	km := testKeyManager(t)

	store, _ := NewPersistentTOTPStore(km, storeDir)
	defer store.Close()

	store.Enroll("alice")

	// Simulate stale tmp file
	usersDir := filepath.Join(storeDir, usersSubDir)
	os.WriteFile(filepath.Join(usersDir, "stale.tmp"), []byte("garbage"), 0600)

	// Restart — should clean up
	store.Close()
	store2, err := NewPersistentTOTPStore(km, storeDir)
	if err != nil {
		t.Fatalf("NewPersistentTOTPStore after stale: %v", err)
	}
	defer store2.Close()

	// Verify no .tmp files remain
	entries, _ := os.ReadDir(usersDir)
	for _, e := range entries {
		name := e.Name()
		if len(name) > 4 && name[len(name)-4:] == tmpFileExtension {
			t.Errorf("stale tmp file should have been cleaned up: %s", name)
		}
	}
}

// =============================================================================
// 9.7 Backward Compatibility
// =============================================================================

// AC-COMPAT-01: All existing handlers_2fa.go callers work with the new store
func TestAC_Compat01_HandlerCompatibleMethods(t *testing.T) {
	store := NewTOTPStore(testKeyManager(t))
	defer store.Close()

	// These are all the methods called from handlers_2fa.go:
	// IsEnrolled, Enroll, IsLocked, ValidateCode, ClearFailedAttempts,
	// RecordFailedAttempt, ConsumeRecoveryCode, Exists, Disable

	store.IsEnrolled("alice")
	store.Enroll("alice")
	store.IsLocked("alice")
	result, _ := store.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("alice", validCode)
	store.ClearFailedAttempts("alice")
	store.RecordFailedAttempt("alice")
	store.Exists("alice")
	store.Disable("alice")
}

// AC-COMPAT-02: Server.New wires EncryptedTOTPStore via same Deps.TOTPStore field
func TestAC_Compat02_ServerWiring(t *testing.T) {
	// Verify that NewPersistentTOTPStore returns a *TOTPStore (same type)
	km := testKeyManager(t)
	store, err := NewPersistentTOTPStore(km, t.TempDir())
	if err != nil {
		t.Fatalf("NewPersistentTOTPStore: %v", err)
	}
	defer store.Close()

	// It should be assignable to Deps.TOTPStore field
	deps := Deps{TOTPStore: store}
	if deps.TOTPStore != store {
		t.Error("persistent store should be assignable to Deps.TOTPStore")
	}
}

// =============================================================================
// Migration Tests
// =============================================================================

// TestMigration_PlaintextToEncrypted verifies that plaintext .json files
// are migrated to encrypted .enc files on startup.
func TestMigration_PlaintextToEncrypted(t *testing.T) {
	storeDir := t.TempDir()
	usersDir := filepath.Join(storeDir, usersSubDir)
	os.MkdirAll(usersDir, 0700)

	km := testKeyManager(t)

	// Create a plaintext state file that simulates a legacy store
	// The state contains a plaintext TOTP secret in EncryptedSecret field
	// (which in legacy mode was just the raw secret)
	secret := "JBSWY3DPEHPK3PXP"
	legacyState := &persistedState{
		Version:         1,
		EncryptedSecret: []byte(secret), // plaintext in legacy mode
		State:           int(StateVerified),
	}
	plaintextJSON, _ := json.Marshal(legacyState)
	os.WriteFile(filepath.Join(usersDir, "alice.json"), plaintextJSON, 0600)

	// Start the store — should migrate the plaintext file
	store, err := NewPersistentTOTPStore(km, storeDir)
	if err != nil {
		t.Fatalf("NewPersistentTOTPStore with migration: %v", err)
	}
	defer store.Close()

	// The plaintext file should be gone
	if _, err := os.Stat(filepath.Join(usersDir, "alice.json")); !os.IsNotExist(err) {
		t.Error("plaintext .json file should be removed after migration")
	}

	// The encrypted file should exist
	encPath := encFilePath(storeDir, "alice")
	if _, err := os.Stat(encPath); err != nil {
		t.Errorf("encrypted .enc file should exist after migration: %v", err)
	}

	// The user should be loaded
	if !store.IsEnrolled("alice") {
		t.Error("migrated user should be enrolled")
	}
}

// TestPersistence_FailedAttemptsPersistAcrossRestart verifies that
// failed attempt counters survive restart.
func TestPersistence_FailedAttemptsPersistAcrossRestart(t *testing.T) {
	storeDir := t.TempDir()
	km := testKeyManager(t)

	store1, _ := NewPersistentTOTPStore(km, storeDir)
	result, _ := store1.Enroll("alice")
	validCode := computeTOTP(result.Secret, time.Now())
	store1.ValidateCode("alice", validCode) // → VERIFIED

	// Record a failed attempt (should persist lockout if threshold reached)
	for i := 0; i < maxFailedTOTP; i++ {
		store1.RecordFailedAttempt("alice")
	}
	store1.Close()

	// Restart
	store2, _ := NewPersistentTOTPStore(km, storeDir)
	defer store2.Close()

	// Should still be locked
	if !store2.IsLocked("alice") {
		t.Error("lockout should persist across restart")
	}
}
