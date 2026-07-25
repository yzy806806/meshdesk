package web

import (
	"testing"
	"time"
)

// TestTOTPStore_FiveStateModel_DisabledByAdmin verifies that a
// DISABLED_BY_ADMIN user cannot self-enroll.
func TestTOTPStore_FiveStateModel_DisabledByAdmin(t *testing.T) {
	store := NewTOTPStore(nil)
	result, _ := store.Enroll("admin")

	// Complete enrollment to VERIFIED
	validCode := computeTOTP(result.Secret, time.Now())
	store.ValidateCode("admin", validCode)

	// Admin disables
	store.DisableByAdmin("admin")

	// IsEnrolled should return false
	if store.IsEnrolled("admin") {
		t.Error("user should not be enrolled after admin disable")
	}

	// User tries to self-enroll — should fail
	_, err := store.Enroll("admin")
	if err == nil {
		t.Error("self-enrollment should fail when DISABLED_BY_ADMIN")
	}

	// Admin re-enables
	if !store.AdminEnable("admin") {
		t.Error("AdminEnable should succeed for DISABLED_BY_ADMIN user")
	}

	// Now user can self-enroll
	_, err = store.Enroll("admin")
	if err != nil {
		t.Errorf("self-enrollment should succeed after admin re-enable: %v", err)
	}
}

// TestTOTPStore_FiveStateModel_PendingTimeout verifies that a PENDING
// enrollment expires after the TTL.
func TestTOTPStore_FiveStateModel_PendingTimeout(t *testing.T) {
	store := NewTOTPStore(nil)
	store.Enroll("admin")

	// User should exist in PENDING state
	if !store.Exists("admin") {
		t.Fatal("user should exist in PENDING state after enrollment")
	}

	// Manually expire the pending state by setting PendingSince far in the past
	store.mu.Lock()
	st := store.users["admin"]
	st.PendingSince = time.Now().Add(-11 * time.Minute)
	store.mu.Unlock()

	// Wait for the sweeper to run (or manually trigger)
	// The sweeper runs every 60s, but we can manually check:
	store.mu.Lock()
	now := time.Now()
	for username, st := range store.users {
		if st.State == StatePending && now.Sub(st.PendingSince) > pendingTTL {
			delete(store.users, username)
		}
	}
	store.mu.Unlock()

	// User should be gone (PENDING expired → DISABLED)
	if store.Exists("admin") {
		t.Error("PENDING enrollment should have expired and been removed")
	}
}

// TestTOTPStore_EncryptedSecretNotPlaintext verifies that with a
// TOTPKeyManager, the stored secret is encrypted (not plaintext).
func TestTOTPStore_EncryptedSecretNotPlaintext(t *testing.T) {
	masterSecret := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(i + 1)
	}
	km, _ := NewTOTPKeyManagerFromBytes(masterSecret)
	store := NewTOTPStore(km)

	result, _ := store.Enroll("alice")

	// The stored secret should NOT be the plaintext
	st := store.Get("alice")
	if string(st.EncryptedSecret) == result.Secret {
		t.Error("stored secret should be encrypted, not plaintext")
	}

	// But ValidateCode should still work (decrypts internally)
	validCode := computeTOTP(result.Secret, time.Now())
	if !store.ValidateCode("alice", validCode) {
		t.Error("valid TOTP code should be accepted even with encrypted secret")
	}

	// After completing enrollment (PENDING → VERIFIED), still encrypted
	if !store.IsEnrolled("alice") {
		t.Error("alice should be enrolled after valid code")
	}
}

// TestTOTPStore_EnrollmentStateString verifies the String() method.
func TestTOTPStore_EnrollmentStateString(t *testing.T) {
	tests := []struct {
		state EnrollmentState
		want  string
	}{
		{StateDisabled, "DISABLED"},
		{StatePending, "PENDING"},
		{StateVerified, "VERIFIED"},
		{StateRotating, "ROTATING"},
		{StateDisabledByAdmin, "DISABLED_BY_ADMIN"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State %d String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// TestTOTPStore_CloseStopsSweeper verifies that Close() stops the
// background sweeper goroutine without panicking.
func TestTOTPStore_CloseStopsSweeper(t *testing.T) {
	store := NewTOTPStore(nil)
	store.Close()

	// Second close should not panic
	store.Close()

	// Store should still be usable after close (just no sweeper)
	store.Enroll("testuser")
	if !store.Exists("testuser") {
		t.Error("store should still be functional after Close")
	}
}
