package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
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
)

// recoveryAlphabet excludes ambiguous chars (0, O, 1, I, L).
const recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// totpState holds the per-user TOTP enrollment state.
type totpState struct {
	Secret          string   // base32-encoded (no padding) key
	RecoveryCodes   []string // one-time-use recovery codes
	Enrolled        bool
	FailedAttempts  int
	LockedUntil     time.Time
}

// TOTPStore manages per-user TOTP enrollment and verification state.
// All state is held in-memory; it does not persist across restarts.
type TOTPStore struct {
	mu    sync.Mutex
	users map[string]*totpState
}

// NewTOTPStore creates a new in-memory TOTP store.
func NewTOTPStore() *TOTPStore {
	return &TOTPStore{users: make(map[string]*totpState)}
}

// Enroll generates a new TOTP secret and recovery codes for the user.
// If the user is already enrolled, it returns an error (must disable first).
func (s *TOTPStore) Enroll(username string) (*totpState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if st, ok := s.users[username]; ok && st.Enrolled {
		return nil, fmt.Errorf("TOTP already enrolled for user %s", username)
	}

	secret, err := generateTOTPSecret()
	if err != nil {
		return nil, fmt.Errorf("generate TOTP secret: %w", err)
	}

	state := &totpState{
		Secret:        secret,
		RecoveryCodes: generateRecoveryCodes(),
		Enrolled:      true,
	}
	s.users[username] = state
	return state, nil
}

// Get returns the TOTP state for a user, or nil if not enrolled.
func (s *TOTPStore) Get(username string) *totpState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.users[username]
}

// IsEnrolled reports whether the user has completed TOTP enrollment.
func (s *TOTPStore) IsEnrolled(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	return ok && st.Enrolled
}

// Disable removes TOTP enrollment for a user.
func (s *TOTPStore) Disable(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return false
	}
	delete(s.users, username)
	return true
}

// ValidateCode checks a TOTP code against the user's secret with ±skew tolerance.
// Returns true if the code is valid for the current, previous, or next window.
func (s *TOTPStore) ValidateCode(username, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.users[username]
	if !ok || !st.Enrolled {
		return false
	}

	// Check lockout
	if !st.LockedUntil.IsZero() && time.Now().Before(st.LockedUntil) {
		return false
	}

	valid := validateTOTP(st.Secret, code, time.Now(), totpSkew)
	if valid {
		st.FailedAttempts = 0
		st.LockedUntil = time.Time{}
	}
	return valid
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
	for i, rc := range st.RecoveryCodes {
		if rc == code {
			st.RecoveryCodes = append(st.RecoveryCodes[:i], st.RecoveryCodes[i+1:]...)
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
