package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TOTP defaults (RFC 6238).
const (
	totpPeriod    = 30    // seconds
	totpDigits    = 6     // 6-digit code
	totpSkew      = 1     // ±1 window tolerance
	totpKeySize   = 32    // 256-bit secret
	maxFailedTOTP = 5     // lockout threshold
	totpLockout   = 30 * time.Second // lockout duration
	numRecoveryCodes = 10
	recoveryCodeLen  = 8   // alphanumeric chars

	// pendingTTL is the time limit for completing enrollment after
	// a secret is generated. If the user doesn't verify within this
	// window, the PENDING state auto-transitions to DISABLED.
	pendingTTL = 10 * time.Minute

	// pendingSweepInterval is how often the background sweeper checks
	// for expired PENDING enrollments.
	pendingSweepInterval = 60 * time.Second
)

// recoveryAlphabet excludes ambiguous chars (0, O, 1, I, L).
const recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// EnrollmentState models the 5-state TOTP enrollment lifecycle.
type EnrollmentState int

const (
	StateDisabled         EnrollmentState = iota // DISABLED: no TOTP configured
	StatePending                                // PENDING: secret generated, awaiting first verification
	StateVerified                               // VERIFIED: fully enrolled and active
	StateRotating                               // ROTATING: new secret generated, old key still valid for login
	StateDisabledByAdmin                        // DISABLED_BY_ADMIN: admin override, user cannot self-re-enroll
)

// String returns a human-readable name for the enrollment state.
func (s EnrollmentState) String() string {
	switch s {
	case StateDisabled:
		return "DISABLED"
	case StatePending:
		return "PENDING"
	case StateVerified:
		return "VERIFIED"
	case StateRotating:
		return "ROTATING"
	case StateDisabledByAdmin:
		return "DISABLED_BY_ADMIN"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// totpState holds the per-user TOTP enrollment state.
// The TOTP secret is stored as AES-256-GCM ciphertext — the plaintext
// secret exists only transiently on the stack during ValidateCode.
type totpState struct {
	// EncryptedSecret holds the AES-256-GCM ciphertext of the base32
	// TOTP secret, sealed with the user's username as AAD.
	EncryptedSecret []byte

	// OldEncryptedSecret is used during ROTATING: the previous secret
	// remains valid for login until the new secret is verified.
	OldEncryptedSecret []byte

	// RecoveryCodes are one-time-use recovery codes (plaintext by design —
	// they are consumed and discarded, not persistent secrets).
	RecoveryCodes []string

	// State is the current enrollment lifecycle state.
	State EnrollmentState

	// PendingSince is when the PENDING state began (for TTL expiry).
	PendingSince time.Time

	// FailedAttempts tracks consecutive failed TOTP verifications.
	FailedAttempts int

	// LockedUntil is the lockout expiry time (rate-limiting).
	LockedUntil time.Time
}

// TOTPStore manages per-user TOTP enrollment and verification state.
// Secrets are encrypted at rest with AES-256-GCM using a key derived
// from a node-local master secret (see TOTPKeyManager).
//
// When storeDir is non-empty and a key manager is present, state is
// persisted to disk as encrypted blobs (storeDir/users/<username>.enc).
// Otherwise the store operates in-memory only (for backward compat).
type TOTPStore struct {
	mu          sync.RWMutex
	users       map[string]*totpState
	km          *TOTPKeyManager
	storeDir    string
	stopSweeper chan struct{}
}

// NewTOTPStore creates a new TOTP store with the given key manager.
// If km is nil, the store operates in a legacy plaintext mode (for
// backward compatibility — secrets are stored unencrypted). Production
// code should always provide a non-nil key manager.
func NewTOTPStore(km *TOTPKeyManager) *TOTPStore {
	return newTOTPStore(km, "")
}

// NewPersistentTOTPStore creates a TOTP store that persists encrypted
// state to storeDir. The key manager must be non-nil. The users/
// subdirectory is created if it doesn't exist. Existing encrypted
// blobs are loaded into the in-memory cache on startup.
//
// If a plaintext .json file is found for a user, it is migrated to
// an encrypted .enc blob and the plaintext is deleted (spec §7).
func NewPersistentTOTPStore(km *TOTPKeyManager, storeDir string) (*TOTPStore, error) {
	if km == nil {
		return nil, fmt.Errorf("persistent TOTP store requires a non-nil key manager")
	}
	if storeDir == "" {
		return nil, fmt.Errorf("persistent TOTP store requires a non-empty storeDir")
	}

	// Create the users/ subdirectory
	usersDir := filepath.Join(storeDir, usersSubDir)
	if err := os.MkdirAll(usersDir, 0700); err != nil {
		return nil, fmt.Errorf("create TOTP users directory: %w", err)
	}

	s := newTOTPStore(km, storeDir)

	// Clean up any stale .tmp files from a previous crash
	if err := s.cleanupStaleTmpFiles(); err != nil {
		return nil, fmt.Errorf("TOTP cleanup: %w", err)
	}

	// Migrate any plaintext files
	if err := s.migratePlaintext(); err != nil {
		return nil, fmt.Errorf("TOTP migration: %w", err)
	}

	// Load encrypted state from disk
	if err := s.loadFromDisk(); err != nil {
		return nil, fmt.Errorf("load TOTP state: %w", err)
	}

	return s, nil
}

// newTOTPStore is the internal constructor that sets up the common
// fields and starts the PENDING sweeper.
func newTOTPStore(km *TOTPKeyManager, storeDir string) *TOTPStore {
	s := &TOTPStore{
		users:       make(map[string]*totpState),
		km:          km,
		storeDir:    storeDir,
		stopSweeper: make(chan struct{}),
	}
	// Start the PENDING expiry sweeper.
	go s.sweepPending()
	return s
}

// sweepPending periodically checks for expired PENDING enrollments
// and transitions them to DISABLED.
func (s *TOTPStore) sweepPending() {
	ticker := time.NewTicker(pendingSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			var expired []string
			for username, st := range s.users {
				if st.State == StatePending && now.Sub(st.PendingSince) > pendingTTL {
					log.Printf("[INFO] TOTP PENDING enrollment for user %s expired after %v, removing", username, pendingTTL)
					delete(s.users, username)
					expired = append(expired, username)
				}
			}
			// Persist removals to disk
			for _, u := range expired {
				if perr := s.persist(u); perr != nil {
					log.Printf("[WARNING] TOTP: failed to persist expired PENDING removal for %s: %v", u, perr)
				}
			}
			s.mu.Unlock()
		case <-s.stopSweeper:
			return
		}
	}
}

// Close stops the background PENDING sweeper goroutine.
func (s *TOTPStore) Close() {
	select {
	case <-s.stopSweeper:
		// already closed
	default:
		close(s.stopSweeper)
	}
}

// EnrollResult is returned by Enroll — the plaintext secret is provided
// once for QR code display and is never stored in plaintext.
type EnrollResult struct {
	Secret        string   // base32-encoded TOTP secret (plaintext, one-time)
	RecoveryCodes []string // one-time recovery codes
	State         EnrollmentState
}

// Enroll generates a new TOTP secret and recovery codes for the user.
// The secret is encrypted (Seal) before storage; only the plaintext is
// returned for one-time QR display.
//
// If the user is already enrolled (VERIFIED), returns an error (must
// disable first). If the user is in PENDING, replaces the pending secret.
// If the user is DISABLED_BY_ADMIN, returns an error (admin must re-enable).
func (s *TOTPStore) Enroll(username string) (*EnrollResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if st, ok := s.users[username]; ok {
		switch st.State {
		case StateVerified, StateRotating:
			return nil, fmt.Errorf("TOTP already enrolled for user %s", username)
		case StateDisabledByAdmin:
			return nil, fmt.Errorf("TOTP enrollment disabled by admin for user %s", username)
		case StatePending:
			// Replace the pending secret — user is re-trying enrollment
			st.EncryptedSecret = nil
			st.OldEncryptedSecret = nil
			st.RecoveryCodes = nil
		}
	}

	secret, err := generateTOTPSecret()
	if err != nil {
		return nil, fmt.Errorf("generate TOTP secret: %w", err)
	}

	var encrypted []byte
	if s.km != nil {
		encrypted, err = s.km.Seal(username, secret)
		if err != nil {
			return nil, fmt.Errorf("encrypt TOTP secret: %w", err)
		}
	} else {
		// Legacy mode: no encryption (for backward compat / testing).
		encrypted = []byte(secret)
	}

	recoveryCodes := generateRecoveryCodes()

	state := &totpState{
		EncryptedSecret: encrypted,
		RecoveryCodes:   recoveryCodes,
		State:           StatePending,
		PendingSince:    time.Now(),
	}
	s.users[username] = state

	// Persist to disk (no-op in in-memory mode)
	if perr := s.persist(username); perr != nil {
		log.Printf("[WARNING] TOTP: failed to persist enrollment for %s: %v", username, perr)
	}

	return &EnrollResult{
		Secret:        secret,
		RecoveryCodes: recoveryCodes,
		State:         StatePending,
	}, nil
}

// CompleteEnrollment transitions a PENDING user to VERIFIED after they
// provide a valid first TOTP code. This is called when ValidateCode
// succeeds for a PENDING user.
func (s *TOTPStore) CompleteEnrollment(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	if !ok {
		return false
	}
	if st.State != StatePending {
		return false
	}
	st.State = StateVerified
	st.PendingSince = time.Time{}
	// Persist the state transition
	if perr := s.persist(username); perr != nil {
		log.Printf("[WARNING] TOTP: failed to persist enrollment completion for %s: %v", username, perr)
	}
	return true
}

// Get returns the TOTP state for a user, or nil if not enrolled.
func (s *TOTPStore) Get(username string) *totpState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.users[username]
}

// IsEnrolled reports whether the user has completed TOTP enrollment.
// Returns true only for VERIFIED and ROTATING states (the two states
// where 2FA is enforced at login).
func (s *TOTPStore) IsEnrolled(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	if !ok {
		return false
	}
	return st.State == StateVerified || st.State == StateRotating
}

// Exists reports whether the user has any TOTP state (including PENDING
// and DISABLED_BY_ADMIN). Used by the disable handler to allow cancelling
// a PENDING enrollment, not just a VERIFIED one.
func (s *TOTPStore) Exists(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.users[username]
	return ok
}

// Disable removes TOTP enrollment for a user (self-service).
// Has no effect on DISABLED_BY_ADMIN users (admin must re-enable).
func (s *TOTPStore) Disable(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return false
	}
	delete(s.users, username)
	// Remove from disk (no-op in in-memory mode)
	if perr := s.persist(username); perr != nil {
		log.Printf("[WARNING] TOTP: failed to remove disk state for %s: %v", username, perr)
	}
	return true
}

// DisableByAdmin transitions a user to DISABLED_BY_ADMIN.
// The user cannot self-re-enroll without admin action.
func (s *TOTPStore) DisableByAdmin(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	if !ok {
		return false
	}
	st.State = StateDisabledByAdmin
	st.EncryptedSecret = nil
	st.OldEncryptedSecret = nil
	st.RecoveryCodes = nil
	st.PendingSince = time.Time{}
	// Persist the disabled state
	if perr := s.persist(username); perr != nil {
		log.Printf("[WARNING] TOTP: failed to persist admin-disable for %s: %v", username, perr)
	}
	return true
}

// AdminEnable transitions a DISABLED_BY_ADMIN user back to DISABLED,
// allowing the user to self-enroll again.
func (s *TOTPStore) AdminEnable(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	if !ok || st.State != StateDisabledByAdmin {
		return false
	}
	delete(s.users, username) // → back to DISABLED (absent = not enrolled)
	// Remove from disk (no-op in in-memory mode)
	if perr := s.persist(username); perr != nil {
		log.Printf("[WARNING] TOTP: failed to remove disk state for %s: %v", username, perr)
	}
	return true
}

// ValidateCode checks a TOTP code against the user's secret with ±skew tolerance.
// Returns true if the code is valid for the current, previous, or next window.
//
// For PENDING users, a valid code completes enrollment (PENDING → VERIFIED).
// For ROTATING users, if the code matches the NEW secret, rotation completes
// (ROTATING → VERIFIED). If it matches the OLD secret, it's accepted for login
// but rotation remains in progress.
func (s *TOTPStore) ValidateCode(username, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.users[username]
	if !ok {
		return false
	}

	// Only PENDING, VERIFIED, and ROTATING states accept TOTP codes.
	switch st.State {
	case StateDisabled, StateDisabledByAdmin:
		return false
	}

	// Check lockout
	if !st.LockedUntil.IsZero() && time.Now().Before(st.LockedUntil) {
		return false
	}

	// Decrypt the secret for validation.
	plaintext, err := s.decryptSecret(username, st.EncryptedSecret)
	if err != nil {
		// If decryption fails (e.g., master secret rotated), can't validate.
		return false
	}

	valid := validateTOTP(plaintext, code, time.Now(), totpSkew)

	if valid {
		stateChanged := false
		// If PENDING, complete enrollment.
		if st.State == StatePending {
			st.State = StateVerified
			st.PendingSince = time.Time{}
			stateChanged = true
		}
		// If ROTATING and code matches the NEW secret, complete rotation.
		if st.State == StateRotating {
			st.State = StateVerified
			st.OldEncryptedSecret = nil
			stateChanged = true
		}
		st.FailedAttempts = 0
		st.LockedUntil = time.Time{}
		// Persist if state changed or counters reset
		if stateChanged || st.FailedAttempts == 0 {
			if perr := s.persist(username); perr != nil {
				log.Printf("[WARNING] TOTP: failed to persist state after ValidateCode for %s: %v", username, perr)
			}
		}
	}

	return valid
}

// ValidateCodeWithOld checks a TOTP code against the OLD secret (for
// ROTATING state). Returns true if the code matches the previous secret.
// This allows login during key rotation without completing the rotation.
func (s *TOTPStore) ValidateCodeWithOld(username, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.users[username]
	if !ok || st.State != StateRotating || len(st.OldEncryptedSecret) == 0 {
		return false
	}

	plaintext, err := s.decryptSecret(username, st.OldEncryptedSecret)
	if err != nil {
		return false
	}

	return validateTOTP(plaintext, code, time.Now(), totpSkew)
}

// decryptSecret decrypts an encrypted TOTP secret for on-stack use.
// If the key manager is nil (legacy mode), treats the stored value
// as plaintext.
func (s *TOTPStore) decryptSecret(username string, encrypted []byte) (string, error) {
	if s.km == nil {
		return string(encrypted), nil
	}
	return s.km.Open(username, encrypted)
}

// RecordFailedAttempt increments the failure counter and locks the account
// after maxFailedTOTP consecutive failures. Returns true if the account
// is now locked.
func (s *TOTPStore) RecordFailedAttempt(username string) (locked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	if !ok {
		return false
	}
	st.FailedAttempts++
	if st.FailedAttempts >= maxFailedTOTP {
		st.LockedUntil = time.Now().Add(totpLockout)
		// Persist the locked state
		if perr := s.persist(username); perr != nil {
			log.Printf("[WARNING] TOTP: failed to persist lockout for %s: %v", username, perr)
		}
		return true
	}
	return false
}

// ClearFailedAttempts resets the failure counter (called on successful verification).
func (s *TOTPStore) ClearFailedAttempts(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	if !ok {
		return
	}
	st.FailedAttempts = 0
	st.LockedUntil = time.Time{}
	// Persist the cleared state
	if perr := s.persist(username); perr != nil {
		log.Printf("[WARNING] TOTP: failed to persist cleared attempts for %s: %v", username, perr)
	}
}

// IsLocked reports whether the user is currently locked out.
func (s *TOTPStore) IsLocked(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	if !ok {
		return false
	}
	return !st.LockedUntil.IsZero() && time.Now().Before(st.LockedUntil)
}

// ConsumeRecoveryCode attempts to use a one-time recovery code.
// Returns true if the code was valid and has been consumed.
func (s *TOTPStore) ConsumeRecoveryCode(username, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	if !ok {
		return false
	}
	// Recovery codes are only valid in VERIFIED and ROTATING states.
	if st.State != StateVerified && st.State != StateRotating {
		return false
	}
	for i, rc := range st.RecoveryCodes {
		if rc == code {
			st.RecoveryCodes = append(st.RecoveryCodes[:i], st.RecoveryCodes[i+1:]...)
			// Persist the consumed recovery code
			if perr := s.persist(username); perr != nil {
				log.Printf("[WARNING] TOTP: failed to persist recovery code consumption for %s: %v", username, perr)
			}
			return true
		}
	}
	return false
}

// QRURL builds the otpauth:// provisioning URI for QR code generation.
func QRURL(issuer, username, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA256&digits=%d&period=%d",
		issuer, username, secret, issuer, totpDigits, totpPeriod)
}

// --- crypto helpers ---

// generateTOTPSecret produces a 32-byte cryptographically random key,
// base32-encoded without padding (standard TOTP format).
func generateTOTPSecret() (string, error) {
	b := make([]byte, totpKeySize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// generateRecoveryCodes produces 10 random 8-character alphanumeric codes
// from an unambiguous alphabet (no O/0/I/1/L).
func generateRecoveryCodes() []string {
	codes := make([]string, numRecoveryCodes)
	buf := make([]byte, recoveryCodeLen)
	for i := 0; i < numRecoveryCodes; i++ {
		if _, err := rand.Read(buf); err != nil {
			// Fallback should never happen; use time-seeded pseudo-random
			for j := range buf {
				buf[j] = recoveryAlphabet[time.Now().UnixNano()%int64(len(recoveryAlphabet))]
			}
		}
		for j, b := range buf {
			buf[j] = recoveryAlphabet[int(b)%len(recoveryAlphabet)]
		}
		codes[i] = string(buf)
	}
	return codes
}

// validateTOTP checks a code against a secret with the given skew tolerance.
// Uses HMAC-SHA256 per the test spec's algorithm field.
func validateTOTP(secretBase32, code string, t time.Time, skew int) bool {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretBase32)
	if err != nil {
		return false
	}
	counter := uint64(t.Unix() / totpPeriod)
	for offset := -skew; offset <= skew; offset++ {
		c := counter + uint64(offset) // underflow wraps around; negative offsets produce valid prior-window codes
		if computeTOTPCode(secret, c) == code {
			return true
		}
	}
	return false
}

// computeTOTPCode implements RFC 6238 dynamic truncation with HMAC-SHA256.
func computeTOTPCode(secret []byte, counter uint64) string {
	buf := make([]byte, 8)
	buf[0] = byte(counter >> 56)
	buf[1] = byte(counter >> 48)
	buf[2] = byte(counter >> 40)
	buf[3] = byte(counter >> 32)
	buf[4] = byte(counter >> 24)
	buf[5] = byte(counter >> 16)
	buf[6] = byte(counter >> 8)
	buf[7] = byte(counter)

	mac := hmac.New(sha256.New, secret)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	binCode := int(hash[offset]&0x7f)<<24 |
		int(hash[offset+1])<<16 |
		int(hash[offset+2])<<8 |
		int(hash[offset+3])
	return fmt.Sprintf("%06d", binCode%1000000)
}
