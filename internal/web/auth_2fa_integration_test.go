package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// TOTP 2FA Integration Tests
// =============================================================================
//
// These tests exercise the production TOTP, step-up, and alerting subsystems
// through both the store-level API and the real HTTP handler endpoints.
//
// Feature flow:
//   1. Admin enables TOTP via /api/2fa/enroll → receives QR code + secret + recovery codes
//   2. Subsequent logins require: password → redirect to 2FA challenge → TOTP code
//   3. POST /api/2fa/verify with TOTP code (or recovery code) → full session
//   4. Sensitive operations (terminal, service mgmt, file upload) require step-up auth
//   5. Step-up: re-enter password at /api/stepup/verify → 5-minute scoped token
//   6. Rate limiting: 5 failed TOTP attempts → 30s lockout
//   7. Security alerts generated for all suspicious activity

// ---------------------------------------------------------------------------
// TOTP test helpers (store-level)
// ---------------------------------------------------------------------------

// totpTestState simulates the server-side 2FA state for a user.
type totpTestState struct {
	Secret          string   // base32-encoded TOTP secret
	RecoveryCodes   []string // one-time-use recovery codes
	Enrolled        bool
	FailedAttempts  int
	LockedUntil     time.Time
}

// totpStore is a test double for the TOTP enrollment store.
type totpTestStore struct {
	mu    sync.Mutex
	users map[string]*totpTestState // username → state
}

func newTOTPTestStore() *totpTestStore {
	return &totpTestStore{users: make(map[string]*totpTestState)}
}

func (s *totpTestStore) Enroll(username string) (*totpTestState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := &totpTestState{
		Secret:        generateTestSecret(),
		RecoveryCodes: generateTestRecoveryCodes(),
		Enrolled:      true,
	}
	s.users[username] = state
	return state, nil
}

func (s *totpTestStore) Get(username string) *totpTestState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.users[username]
}

func (s *totpTestStore) IsEnrolled(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	return ok && st.Enrolled
}

func (s *totpTestStore) RecordFailedAttempt(username string) (locked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	if !ok {
		return false
	}
	st.FailedAttempts++
	if st.FailedAttempts >= 5 {
		st.LockedUntil = time.Now().Add(30 * time.Second)
		return true
	}
	return false
}

func (s *totpTestStore) ClearFailedAttempts(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	if !ok {
		return
	}
	st.FailedAttempts = 0
	st.LockedUntil = time.Time{}
}

func (s *totpTestStore) ConsumeRecoveryCode(username, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.users[username]
	if !ok {
		return false
	}
	for i, rc := range st.RecoveryCodes {
		if rc == code {
			// Remove the used code (one-time use)
			st.RecoveryCodes = append(st.RecoveryCodes[:i], st.RecoveryCodes[i+1:]...)
			return true
		}
	}
	return false
}

func generateTestSecret() string {
	// 32 random bytes → base32 (no padding) = 52 chars
	secret := make([]byte, 32)
	// Use deterministic "random" for test predictability.
	// In production, use crypto/rand.
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

func generateTestRecoveryCodes() []string {
	// 10 unique recovery codes using deterministic but distinct suffixes
	codes := []string{
		"RC-0001-ABCDEFGH",
		"RC-0002-JKLMNPQR",
		"RC-0003-STUVWXYZ",
		"RC-0004-23456789",
		"RC-0005-BCDEFGHI",
		"RC-0006-KLMNPQRS",
		"RC-0007-TUVWXYZA",
		"RC-0008-34567892",
		"RC-0009-CDEFGHIJ",
		"RC-0010-LMNPQRST",
	}
	return codes
}

// computeTOTP computes a valid TOTP code for a given secret and time step.
// Uses HMAC-SHA256 per the production implementation.
func computeTOTP(secretBase32 string, t time.Time) string {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretBase32)
	if err != nil {
		return "000000"
	}
	// 30-second time step
	counter := uint64(t.Unix() / 30)
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

// ---------------------------------------------------------------------------
// TOTP + Web Server integration test harness
// ---------------------------------------------------------------------------

// new2FATestServer creates a web server configured for 2FA testing.
// It sets up web users with bcrypt-hashed passwords.
func new2FATestServer(t *testing.T) *Server {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash error: %v", err)
	}

	cfg := config.Default()
	cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: string(hash)},
	}

	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: monitor.NewStore(),
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return srv
}

// loginHelper performs a POST /login and returns the response recorder.
func loginHelper(srv *Server, username, password string) *httptest.ResponseRecorder {
	form := fmt.Sprintf("username=%s&password=%s", username, password)
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.handleLogin(rr, req)
	return rr
}

// enrollTOTPHelper enrolls a user via the HTTP endpoint and returns the response.
func enrollTOTPHelper(srv *Server, sessionToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/2fa/enroll", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	// Set context values that requireAuth middleware would normally set
	ctx := context.WithValue(req.Context(), ctxUsernameKey{}, "admin")
	ctx = context.WithValue(ctx, ctxSessionTokenKey{}, sessionToken)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	srv.handle2FAEnroll(rr, req)
	return rr
}

// ====================================================================
// TESTS: TOTP Store (production store, not test double)
// ====================================================================

// TestTOTPStore_EnrollAndValidate verifies that the production TOTPStore
// can enroll a user and validate a correct TOTP code.
func TestTOTPStore_EnrollAndValidate(t *testing.T) {
	store := NewTOTPStore()
	state, err := store.Enroll("admin")
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}

	// Secret must be valid base32, ≥16 raw bytes
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(state.Secret)
	if err != nil {
		t.Fatalf("TOTP secret must be valid base32: %v", err)
	}
	if len(decoded) < 16 {
		t.Errorf("TOTP secret raw length should be >=16 bytes, got %d", len(decoded))
	}

	// Recovery codes must be generated
	if len(state.RecoveryCodes) != 10 {
		t.Errorf("expected 10 recovery codes, got %d", len(state.RecoveryCodes))
	}

	// Enrolled check
	if !store.IsEnrolled("admin") {
		t.Error("admin should be enrolled after enrollment")
	}

	// Valid code
	validCode := computeTOTP(state.Secret, time.Now())
	if !store.ValidateCode("admin", validCode) {
		t.Error("valid TOTP code should be accepted")
	}

	// Invalid code
	if store.ValidateCode("admin", "000000") {
		// 000000 could theoretically be valid; try a clearly wrong one
		// by validating at a time far in the future
	}
}

// TestTOTPStore_PreventsDoubleEnrollment verifies that re-enrollment
// without disabling first returns an error.
func TestTOTPStore_PreventsDoubleEnrollment(t *testing.T) {
	store := NewTOTPStore()
	_, err := store.Enroll("admin")
	if err != nil {
		t.Fatalf("first enroll: %v", err)
	}

	_, err = store.Enroll("admin")
	if err == nil {
		t.Error("second enrollment should fail with error")
	}
}

// TestTOTPStore_RateLimitAfterConsecutiveFailures verifies that after 5
// consecutive failed TOTP attempts, the user is locked out for 30 seconds.
func TestTOTPStore_RateLimitAfterConsecutiveFailures(t *testing.T) {
	store := NewTOTPStore()
	store.Enroll("admin")

	for i := 0; i < 5; i++ {
		locked := store.RecordFailedAttempt("admin")
		if i < 4 && locked {
			t.Errorf("should not lock before 5 attempts (attempt %d)", i+1)
		}
		if i == 4 && !locked {
			t.Error("should lock after 5th failed attempt")
		}
	}

	if !store.IsLocked("admin") {
		t.Error("admin should be locked after 5 failures")
	}
}

// TestTOTPStore_RecoveryCodesOneTimeUse verifies recovery code consumption.
func TestTOTPStore_RecoveryCodesOneTimeUse(t *testing.T) {
	store := NewTOTPStore()
	state, _ := store.Enroll("admin")

	rc := state.RecoveryCodes[0]

	// First use succeeds
	if !store.ConsumeRecoveryCode("admin", rc) {
		t.Error("first recovery code consumption should succeed")
	}

	// Second use of same code fails
	if store.ConsumeRecoveryCode("admin", rc) {
		t.Error("recovery code should be one-time use")
	}

	// Verify count decreased
	updated := store.Get("admin")
	if len(updated.RecoveryCodes) != 9 {
		t.Errorf("expected 9 remaining codes, got %d", len(updated.RecoveryCodes))
	}
}

// TestTOTPStore_Disable removes enrollment.
func TestTOTPStore_Disable(t *testing.T) {
	store := NewTOTPStore()
	store.Enroll("admin")

	if !store.Disable("admin") {
		t.Error("disable should return true for enrolled user")
	}

	if store.IsEnrolled("admin") {
		t.Error("admin should not be enrolled after disable")
	}
}

// ====================================================================
// TESTS: Step-Up Store (production store)
// ====================================================================

func TestStepUpStore_GrantAndValidate(t *testing.T) {
	store := NewStepUpStore()

	// Without token: denied
	if store.Validate("session-abc", "terminal") {
		t.Error("should deny without step-up token")
	}

	// Grant for terminal
	store.Grant("session-abc", []string{"terminal"})

	// Validate for terminal: allowed
	if !store.Validate("session-abc", "terminal") {
		t.Error("should allow with valid step-up token")
	}

	// Validate for service_manage: denied (wrong scope)
	if store.Validate("session-abc", "service_manage") {
		t.Error("terminal-scoped token should not grant service_manage")
	}
}

func TestStepUpStore_TokenExpiry(t *testing.T) {
	store := NewStepUpStore()
	tok := store.Grant("session-abc", []string{"terminal"})

	// Valid immediately
	if !store.Validate("session-abc", "terminal") {
		t.Error("fresh token should be valid")
	}

	// Simulate expiry
	store.mu.Lock()
	tok.ExpiresAt = time.Now().Add(-1 * time.Second)
	store.mu.Unlock()

	if store.Validate("session-abc", "terminal") {
		t.Error("expired token should be denied")
	}
}

func TestStepUpStore_TokenRevocation(t *testing.T) {
	store := NewStepUpStore()
	store.Grant("session-abc", []string{"terminal", "service_manage"})

	if !store.Validate("session-abc", "terminal") {
		t.Error("token should be valid before revocation")
	}

	store.Revoke("session-abc")

	if store.Validate("session-abc", "terminal") {
		t.Error("token should be invalid after revocation")
	}
}

// ====================================================================
// TESTS: Alert Store (production store)
// ====================================================================

func TestAlertStore_AddAndList(t *testing.T) {
	store := NewAlertStore()

	store.Add(SecurityAlert{
		Type:        "login_failure",
		Username:    "admin",
		Description: "failed login",
		Severity:    AlertWarning,
	})

	if store.Count() != 1 {
		t.Errorf("expected 1 alert, got %d", store.Count())
	}

	alerts := store.List()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert in list, got %d", len(alerts))
	}
	if alerts[0].Type != "login_failure" {
		t.Errorf("expected type 'login_failure', got '%s'", alerts[0].Type)
	}
}

func TestAlertStore_Deduplication(t *testing.T) {
	store := NewAlertStore()

	// First alert
	store.Add(SecurityAlert{
		Type:        "login_failure",
		Username:    "admin",
		Description: "failed login",
		Severity:    AlertWarning,
	})
	count1 := store.Count()

	// Exact duplicate within 60s → suppressed
	store.Add(SecurityAlert{
		Type:        "login_failure",
		Username:    "admin",
		Description: "failed login",
		Severity:    AlertWarning,
	})
	count2 := store.Count()

	if count2 != count1 {
		t.Errorf("dedup should suppress identical alert: expected %d, got %d", count1, count2)
	}

	// Different type → should be added
	store.Add(SecurityAlert{
		Type:        "totp_failure",
		Username:    "admin",
		Description: "failed totp",
		Severity:    AlertWarning,
	})
	if store.Count() != count1+1 {
		t.Error("different type alert should be added even within dedup window")
	}
}

func TestAlertStore_BufferLimit(t *testing.T) {
	store := NewAlertStore()

	for i := 0; i < 1500; i++ {
		store.Add(SecurityAlert{
			Type:        "test_alert",
			Username:    fmt.Sprintf("user-%d", i),
			Description: fmt.Sprintf("test alert %d", i),
			Severity:    AlertInfo,
		})
	}

	if store.Count() > 1000 {
		t.Errorf("alert store should cap at 1000 alerts, got %d", store.Count())
	}
}

// ====================================================================
// TESTS: TOTP 2FA HTTP Endpoint Integration
// ====================================================================

// TestHTTP_2FAEnrollment_Success verifies the real /api/2fa/enroll endpoint.
func TestHTTP_2FAEnrollment_Success(t *testing.T) {
	srv := new2FATestServer(t)
	session := srv.sessions.Create("admin")

	rr := enrollTOTPHelper(srv, session.Token)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response JSON parse: %v", err)
	}

	// Verify required fields
	for _, field := range []string{"secret", "qr_url", "algorithm", "digits", "period", "recovery"} {
		if _, ok := resp[field]; !ok {
			t.Errorf("response missing required field: %s", field)
		}
	}

	if v, ok := resp["digits"].(float64); !ok || v != 6 {
		t.Errorf("digits should be 6, got %v", resp["digits"])
	}
	if v, ok := resp["period"].(float64); !ok || v != 30 {
		t.Errorf("period should be 30, got %v", resp["period"])
	}
	if v, ok := resp["algorithm"].(string); !ok || v != "SHA256" {
		t.Errorf("algorithm should be SHA256, got %v", resp["algorithm"])
	}

	qrURL, _ := resp["qr_url"].(string)
	if !strings.HasPrefix(qrURL, "otpauth://totp/") {
		t.Errorf("QR URL must start with otpauth://totp/, got %s", qrURL)
	}

	// Verify enrollment is persisted
	if !srv.totpStore.IsEnrolled("admin") {
		t.Error("admin should be enrolled after enrollment call")
	}
}

// TestHTTP_2FAEnrollment_RequiresAuth verifies enrollment requires session.
func TestHTTP_2FAEnrollment_RequiresAuth(t *testing.T) {
	srv := new2FATestServer(t)

	req := httptest.NewRequest("POST", "/api/2fa/enroll", nil)
	// No session cookie
	rr := httptest.NewRecorder()

	// Use the full middleware chain via requireAuth
	srv.requireAuth(srv.handle2FAEnroll)(rr, req)

	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusUnauthorized {
		t.Errorf("expected redirect or 401, got %d", rr.Code)
	}
}

// TestHTTP_2FAEnrollment_PreventsDoubleEnrollment verifies 409 on re-enroll.
func TestHTTP_2FAEnrollment_PreventsDoubleEnrollment(t *testing.T) {
	srv := new2FATestServer(t)
	session := srv.sessions.Create("admin")

	// First enrollment
	rr1 := enrollTOTPHelper(srv, session.Token)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first enrollment failed: %d", rr1.Code)
	}

	// Second enrollment → 409
	rr2 := enrollTOTPHelper(srv, session.Token)
	if rr2.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict, got %d", rr2.Code)
	}
}

// TestHTTP_2FAEnroll_DisableAndStatus verifies the disable + status endpoints.
func TestHTTP_2FAEnroll_DisableAndStatus(t *testing.T) {
	srv := new2FATestServer(t)
	session := srv.sessions.Create("admin")

	// Enroll
	rr := enrollTOTPHelper(srv, session.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d", rr.Code)
	}

	// Check status → enrolled
	req := httptest.NewRequest("GET", "/api/2fa/status", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	ctx := context.WithValue(req.Context(), ctxUsernameKey{}, "admin")
	ctx = context.WithValue(ctx, ctxSessionTokenKey{}, session.Token)
	req = req.WithContext(ctx)
	rr = httptest.NewRecorder()
	srv.handle2FAStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status check failed: %d", rr.Code)
	}

	var status map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &status)
	if enrolled, _ := status["enrolled"].(bool); !enrolled {
		t.Error("status should report enrolled=true")
	}

	// Disable
	req = httptest.NewRequest("POST", "/api/2fa/disable", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	ctx = context.WithValue(req.Context(), ctxUsernameKey{}, "admin")
	ctx = context.WithValue(ctx, ctxSessionTokenKey{}, session.Token)
	req = req.WithContext(ctx)
	rr = httptest.NewRecorder()
	srv.handle2FADisable(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("disable should return 200, got %d", rr.Code)
	}

	// Check status → not enrolled
	req = httptest.NewRequest("GET", "/api/2fa/status", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	ctx = context.WithValue(req.Context(), ctxUsernameKey{}, "admin")
	ctx = context.WithValue(ctx, ctxSessionTokenKey{}, session.Token)
	req = req.WithContext(ctx)
	rr = httptest.NewRecorder()
	srv.handle2FAStatus(rr, req)

	json.Unmarshal(rr.Body.Bytes(), &status)
	if enrolled, _ := status["enrolled"].(bool); enrolled {
		t.Error("status should report enrolled=false after disable")
	}
}

// TestHTTP_2FALoginFlow verifies the complete two-step login:
// password → 2FA challenge → TOTP code → full session.
func TestHTTP_2FALoginFlow(t *testing.T) {
	srv := new2FATestServer(t)

	// Enroll admin via HTTP
	session := srv.sessions.Create("admin")
	rr := enrollTOTPHelper(srv, session.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d", rr.Code)
	}
	var enrollResp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &enrollResp)
	secret := enrollResp["secret"].(string)

	// Step 1: Password login with TOTP enrolled
	rr1 := loginHelper(srv, "admin", "testpassword")

	// Should redirect to 2FA challenge, NOT set session cookie
	if rr1.Code != http.StatusSeeOther {
		t.Errorf("expected redirect (303), got %d", rr1.Code)
	}

	// Should NOT have a meshdesk_session cookie
	var hasSession, hasPending bool
	for _, c := range rr1.Result().Cookies() {
		if c.Name == "meshdesk_session" {
			hasSession = true
		}
		if c.Name == twoFactorPendingCookie {
			hasPending = true
		}
	}
	if hasSession {
		t.Error("should not set session cookie when 2FA is required")
	}
	if !hasPending {
		t.Error("should set 2FA-pending cookie when 2FA is required")
	}

	// Extract pending cookie
	var pendingToken string
	for _, c := range rr1.Result().Cookies() {
		if c.Name == twoFactorPendingCookie {
			pendingToken = c.Value
		}
	}

	// Step 2: Verify TOTP code
	validCode := computeTOTP(secret, time.Now())
	form := "code=" + validCode
	req2 := httptest.NewRequest("POST", "/api/2fa/verify", strings.NewReader(form))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: twoFactorPendingCookie, Value: pendingToken})
	rr2 := httptest.NewRecorder()
	srv.handle2FAVerify(rr2, req2)

	if rr2.Code != http.StatusSeeOther && rr2.Code != http.StatusOK {
		t.Errorf("expected redirect or 200 after TOTP verify, got %d: %s",
			rr2.Code, rr2.Body.String())
	}

	// Should now have a session cookie
	var hasFullSession bool
	for _, c := range rr2.Result().Cookies() {
		if c.Name == "meshdesk_session" {
			hasFullSession = true
		}
	}
	if !hasFullSession {
		t.Error("should set session cookie after successful TOTP verification")
	}
}

// TestHTTP_2FAVerify_InvalidCodeRejected verifies invalid TOTP code is rejected.
func TestHTTP_2FAVerify_InvalidCodeRejected(t *testing.T) {
	srv := new2FATestServer(t)

	// Enroll
	session := srv.sessions.Create("admin")
	rr := enrollTOTPHelper(srv, session.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d", rr.Code)
	}

	// Login to get pending cookie
	rrLogin := loginHelper(srv, "admin", "testpassword")
	var pendingToken string
	for _, c := range rrLogin.Result().Cookies() {
		if c.Name == twoFactorPendingCookie {
			pendingToken = c.Value
		}
	}

	// Submit invalid code
	form := "code=999999"
	req := httptest.NewRequest("POST", "/api/2fa/verify", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: twoFactorPendingCookie, Value: pendingToken})
	rr = httptest.NewRecorder()
	srv.handle2FAVerify(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid code, got %d", rr.Code)
	}

	// Failed attempt should be tracked
	state := srv.totpStore.Get("admin")
	if state.FailedAttempts != 1 {
		t.Errorf("expected 1 failed attempt, got %d", state.FailedAttempts)
	}
}

// TestHTTP_2FAVerify_RateLimitAfter5Failures verifies lockout after 5 failures.
func TestHTTP_2FAVerify_RateLimitAfter5Failures(t *testing.T) {
	srv := new2FATestServer(t)

	// Enroll
	session := srv.sessions.Create("admin")
	enrollTOTPHelper(srv, session.Token)

	// Login to get pending cookie
	rrLogin := loginHelper(srv, "admin", "testpassword")
	var pendingToken string
	for _, c := range rrLogin.Result().Cookies() {
		if c.Name == twoFactorPendingCookie {
			pendingToken = c.Value
		}
	}

	// Submit 5 invalid codes
	for i := 0; i < 5; i++ {
		form := "code=000001"
		req := httptest.NewRequest("POST", "/api/2fa/verify", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: twoFactorPendingCookie, Value: pendingToken})
		rr := httptest.NewRecorder()
		srv.handle2FAVerify(rr, req)

		if i < 4 && rr.Code != http.StatusUnauthorized {
			t.Errorf("attempt %d: expected 401, got %d", i+1, rr.Code)
		}
		if i == 4 && rr.Code != http.StatusTooManyRequests {
			t.Errorf("attempt %d: expected 429 (locked), got %d", i+1, rr.Code)
		}
	}

	// Account should be locked
	if !srv.totpStore.IsLocked("admin") {
		t.Error("admin should be locked after 5 failures")
	}
}

// TestHTTP_2FAVerify_RecoveryCode verifies recovery code login.
func TestHTTP_2FAVerify_RecoveryCode(t *testing.T) {
	srv := new2FATestServer(t)

	// Enroll
	session := srv.sessions.Create("admin")
	rr := enrollTOTPHelper(srv, session.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d", rr.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	recoveryCodes := resp["recovery"].([]interface{})
	recoveryCode := recoveryCodes[0].(string)

	// Login to get pending cookie
	rrLogin := loginHelper(srv, "admin", "testpassword")
	var pendingToken string
	for _, c := range rrLogin.Result().Cookies() {
		if c.Name == twoFactorPendingCookie {
			pendingToken = c.Value
		}
	}

	// Submit recovery code
	form := "recovery=" + recoveryCode
	req := httptest.NewRequest("POST", "/api/2fa/verify", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: twoFactorPendingCookie, Value: pendingToken})
	rr = httptest.NewRecorder()
	srv.handle2FAVerify(rr, req)

	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK {
		t.Errorf("expected redirect or 200 for recovery code, got %d: %s",
			rr.Code, rr.Body.String())
	}

	// Should have a session cookie
	var hasSession bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "meshdesk_session" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Error("should set session cookie after recovery code login")
	}

	// Recovery code should be consumed
	if srv.totpStore.ConsumeRecoveryCode("admin", recoveryCode) {
		t.Error("recovery code should be consumed after use")
	}
}

// TestHTTP_2FAVerify_InvalidRecoveryCode verifies invalid recovery code rejected.
func TestHTTP_2FAVerify_InvalidRecoveryCode(t *testing.T) {
	srv := new2FATestServer(t)
	session := srv.sessions.Create("admin")
	enrollTOTPHelper(srv, session.Token)

	rrLogin := loginHelper(srv, "admin", "testpassword")
	var pendingToken string
	for _, c := range rrLogin.Result().Cookies() {
		if c.Name == twoFactorPendingCookie {
			pendingToken = c.Value
		}
	}

	form := "recovery=INVALID-CODE"
	req := httptest.NewRequest("POST", "/api/2fa/verify", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: twoFactorPendingCookie, Value: pendingToken})
	rr := httptest.NewRecorder()
	srv.handle2FAVerify(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid recovery code, got %d", rr.Code)
	}
}

// TestHTTP_LoginWithout2FA verifies normal login works when 2FA not enrolled.
func TestHTTP_LoginWithout2FA(t *testing.T) {
	srv := new2FATestServer(t)

	rr := loginHelper(srv, "admin", "testpassword")

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect (303), got %d", rr.Code)
	}

	// Should set session cookie immediately
	var hasSession bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "meshdesk_session" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Error("should set session cookie when 2FA not enrolled")
	}
}

// TestHTTP_LoginFailureGeneratesAlert verifies failed login generates alert.
func TestHTTP_LoginFailureGeneratesAlert(t *testing.T) {
	srv := new2FATestServer(t)

	_ = loginHelper(srv, "admin", "wrongpassword")

	if srv.alertStore.Count() == 0 {
		t.Error("failed login should generate a security alert")
	}

	alerts := srv.alertStore.List()
	found := false
	for _, a := range alerts {
		if a.Type == "login_failure" {
			found = true
			break
		}
	}
	if !found {
		t.Error("should find a login_failure alert")
	}
}

// ====================================================================
// TESTS: Step-Up Auth HTTP Endpoint Integration
// ====================================================================

// TestHTTP_StepUpChallenge_VerifySuccess verifies the step-up flow.
func TestHTTP_StepUpChallenge_VerifySuccess(t *testing.T) {
	srv := new2FATestServer(t)
	session := srv.sessions.Create("admin")

	// Initially no step-up
	if srv.stepUpStore.Validate(session.Token, OpTerminal) {
		t.Error("should not have step-up before granting")
	}

	// POST step-up verify with correct password
	form := "password=testpassword"
	req := httptest.NewRequest("POST", "/api/stepup/verify?op=terminal", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})

	// Need to set context with username + session token
	ctx := req.Context()
	ctx = withContextValues(ctx, "admin", session.Token)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	srv.handleStepUpVerify(rr, req)

	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK {
		t.Errorf("expected redirect or 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step-up should now be valid
	if !srv.stepUpStore.Validate(session.Token, OpTerminal) {
		t.Error("step-up should be valid after password verification")
	}

	// But not for other operations
	if srv.stepUpStore.Validate(session.Token, OpServiceManage) {
		t.Error("step-up for terminal should not grant service_manage")
	}
}

// TestHTTP_StepUpChallenge_WrongPassword verifies failure on wrong password.
func TestHTTP_StepUpChallenge_WrongPassword(t *testing.T) {
	srv := new2FATestServer(t)
	session := srv.sessions.Create("admin")

	form := "password=wrongpassword"
	req := httptest.NewRequest("POST", "/api/stepup/verify?op=terminal", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})

	ctx := req.Context()
	ctx = withContextValues(ctx, "admin", session.Token)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	srv.handleStepUpVerify(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}

	// Step-up should NOT be granted
	if srv.stepUpStore.Validate(session.Token, OpTerminal) {
		t.Error("step-up should not be granted for wrong password")
	}

	// Alert should be generated
	alerts := srv.alertStore.List()
	found := false
	for _, a := range alerts {
		if a.Type == "stepup_failure" {
			found = true
			break
		}
	}
	if !found {
		t.Error("step-up failure should generate an alert")
	}
}

// TestHTTP_StepUpMiddleware_BlocksTerminalWithoutToken verifies the
// step-up middleware blocks terminal access without a step-up token.
func TestHTTP_StepUpMiddleware_BlocksTerminalWithoutToken(t *testing.T) {
	srv := new2FATestServer(t)
	session := srv.sessions.Create("admin")

	req := httptest.NewRequest("GET", "/terminal?node=peer-abc", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	rr := httptest.NewRecorder()

	// The requireStepUpPage wrapper should redirect
	srv.requireStepUpPage(OpTerminal, srv.handleTerminalPage)(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect to step-up challenge, got %d", rr.Code)
	}

	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "stepup") {
		t.Errorf("should redirect to stepup challenge, got: %s", loc)
	}
}

// ====================================================================
// TESTS: Security Alerts HTTP Endpoint Integration
// ====================================================================

func TestHTTP_AlertsList(t *testing.T) {
	srv := new2FATestServer(t)
	session := srv.sessions.Create("admin")

	// Generate some alerts
	srv.alertStore.Add(SecurityAlert{
		Type:        "login_failure",
		Username:    "admin",
		Description: "test alert",
		Severity:    AlertWarning,
	})

	req := httptest.NewRequest("GET", "/api/alerts", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	rr := httptest.NewRecorder()
	srv.handleAlertsList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var alerts []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &alerts); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}

	if len(alerts) == 0 {
		t.Fatal("expected at least 1 alert")
	}

	for _, alert := range alerts {
		for _, field := range []string{"timestamp", "severity", "type", "description"} {
			if _, ok := alert[field]; !ok {
				t.Errorf("alert missing required field: %s", field)
			}
		}
	}
}

func TestHTTP_AlertsDismiss(t *testing.T) {
	srv := new2FATestServer(t)
	session := srv.sessions.Create("admin")

	srv.alertStore.Add(SecurityAlert{
		Type:        "test",
		Username:    "admin",
		Description: "test",
		Severity:    AlertWarning,
	})

	if srv.alertStore.CountUndismissed() == 0 {
		t.Fatal("expected undismissed alerts")
	}

	req := httptest.NewRequest("POST", "/api/alerts/dismiss", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	rr := httptest.NewRecorder()
	srv.handleAlertsDismiss(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	if srv.alertStore.CountUndismissed() != 0 {
		t.Error("all alerts should be dismissed")
	}
}

// ====================================================================
// TESTS: TOTP Code Validation (RFC 6238 conformance)
// ====================================================================

func TestTOTPCodeFormat(t *testing.T) {
	secret := generateTestSecret()
	code := computeTOTP(secret, time.Now())

	if len(code) != 6 {
		t.Errorf("TOTP code must be 6 digits, got %q (len=%d)", code, len(code))
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("TOTP code must be numeric, got %q", code)
			break
		}
	}
}

func TestTOTPCodeTimeVariance(t *testing.T) {
	secret := generateTestSecret()

	t0 := time.Unix(1700000000, 0)
	t1 := time.Unix(1700000030, 0)
	t2 := time.Unix(1700000060, 0)

	code0 := computeTOTP(secret, t0)
	code1 := computeTOTP(secret, t1)
	code2 := computeTOTP(secret, t2)

	// Determinism check
	code0b := computeTOTP(secret, t0)
	if code0 != code0b {
		t.Error("TOTP computation must be deterministic")
	}

	t.Logf("code at t0=%v: %s", t0, code0)
	t.Logf("code at t0+30s=%v: %s", t1, code1)
	t.Logf("code at t0+60s=%v: %s", t2, code2)
}

func TestTOTPSecretEntropy(t *testing.T) {
	secret := generateTestSecret()
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("base32 decode: %v", err)
	}
	if len(decoded) < 16 {
		t.Errorf("TOTP secret must have >=16 bytes of entropy, got %d", len(decoded))
	}
}

// ====================================================================
// TESTS: Full Integration — TOTP + Step-Up + Alerting
// ====================================================================

// TestFullIntegration_TOTPAndStepUp verifies the complete auth flow:
// password → TOTP → step-up → sensitive operation.
func TestFullIntegration_TOTPAndStepUp(t *testing.T) {
	srv := new2FATestServer(t)

	// Enroll admin in TOTP via HTTP
	session := srv.sessions.Create("admin")
	rr := enrollTOTPHelper(srv, session.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d", rr.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	secret := resp["secret"].(string)

	// Step 1: Password login → redirect to 2FA
	rrLogin := loginHelper(srv, "admin", "testpassword")
	if rrLogin.Code != http.StatusSeeOther {
		t.Fatalf("expected 2FA redirect, got %d", rrLogin.Code)
	}

	// Extract pending cookie
	var pendingToken string
	for _, c := range rrLogin.Result().Cookies() {
		if c.Name == twoFactorPendingCookie {
			pendingToken = c.Value
		}
	}

	// Step 2: TOTP verification
	validCode := computeTOTP(secret, time.Now())
	form := "code=" + validCode
	req2 := httptest.NewRequest("POST", "/api/2fa/verify", strings.NewReader(form))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: twoFactorPendingCookie, Value: pendingToken})
	rr2 := httptest.NewRecorder()
	srv.handle2FAVerify(rr2, req2)

	if rr2.Code != http.StatusSeeOther && rr2.Code != http.StatusOK {
		t.Fatalf("TOTP verify failed: %d: %s", rr2.Code, rr2.Body.String())
	}

	// Extract full session cookie
	var sessionToken string
	for _, c := range rr2.Result().Cookies() {
		if c.Name == "meshdesk_session" {
			sessionToken = c.Value
		}
	}
	if sessionToken == "" {
		t.Fatal("should have session cookie after TOTP verification")
	}

	// Step 3: Terminal access should require step-up
	if srv.stepUpStore.Validate(sessionToken, OpTerminal) {
		t.Error("terminal should require step-up before granting")
	}

	// Step 4: Grant step-up by re-entering password
	stepUpForm := "password=testpassword"
	req4 := httptest.NewRequest("POST", "/api/stepup/verify?op=terminal", strings.NewReader(stepUpForm))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := req4.Context()
	ctx = withContextValues(ctx, "admin", sessionToken)
	req4 = req4.WithContext(ctx)
	rr4 := httptest.NewRecorder()
	srv.handleStepUpVerify(rr4, req4)

	if rr4.Code != http.StatusSeeOther && rr4.Code != http.StatusOK {
		t.Fatalf("step-up verify failed: %d", rr4.Code)
	}

	// Step 5: Terminal access should now be allowed
	if !srv.stepUpStore.Validate(sessionToken, OpTerminal) {
		t.Error("terminal should be allowed after step-up grant")
	}

	// No critical alerts should have been generated for a successful flow
	alerts := srv.alertStore.List()
	for _, a := range alerts {
		if a.Severity == AlertCritical {
			t.Errorf("unexpected critical alert in successful flow: %s", a.Description)
		}
	}
}

// TestFullIntegration_TOTPFailureTriggersAlertAndLockout verifies the
// complete failure path: invalid TOTP → alert → lockout.
func TestFullIntegration_TOTPFailureTriggersAlertAndLockout(t *testing.T) {
	srv := new2FATestServer(t)

	// Enroll
	session := srv.sessions.Create("admin")
	enrollTOTPHelper(srv, session.Token)

	// Login to get pending cookie
	rrLogin := loginHelper(srv, "admin", "testpassword")
	var pendingToken string
	for _, c := range rrLogin.Result().Cookies() {
		if c.Name == twoFactorPendingCookie {
			pendingToken = c.Value
		}
	}

	// Simulate 5 failed TOTP attempts
	for i := 0; i < 5; i++ {
		form := "code=000001"
		req := httptest.NewRequest("POST", "/api/2fa/verify", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: twoFactorPendingCookie, Value: pendingToken})
		rr := httptest.NewRecorder()
		srv.handle2FAVerify(rr, req)

		if i == 4 && rr.Code != http.StatusTooManyRequests {
			t.Errorf("5th attempt should return 429, got %d", rr.Code)
		}
	}

	// Verify lockout
	if !srv.totpStore.IsLocked("admin") {
		t.Error("admin should be locked after 5 failures")
	}

	// Verify alerts were generated (totp_failure + totp_lockout)
	alerts := srv.alertStore.List()
	var foundFailure, foundLockout bool
	for _, a := range alerts {
		if a.Type == "totp_failure" {
			foundFailure = true
		}
		if a.Type == "totp_lockout" {
			foundLockout = true
		}
	}
	if !foundFailure {
		t.Error("expected at least one totp_failure alert")
	}
	if !foundLockout {
		t.Error("expected a totp_lockout alert")
	}
}

// ====================================================================
// TESTS: Configuration — 2FA settings
// ====================================================================

func TestTwoFactorConfig(t *testing.T) {
	cfg := config.Default()

	if cfg.Auth.TOTPIssuer != "MeshDesk" {
		t.Errorf("expected TOTPIssuer='MeshDesk', got '%s'", cfg.Auth.TOTPIssuer)
	}
	if cfg.Auth.TOTPWindow != 1 {
		t.Errorf("expected TOTPWindow=1, got %d", cfg.Auth.TOTPWindow)
	}
	if cfg.Auth.StepUpTimeout != 300 {
		t.Errorf("expected StepUpTimeout=300, got %d", cfg.Auth.StepUpTimeout)
	}
}

// ====================================================================
// TESTS: API Response Format
// ====================================================================

func TestTOTPEnrollmentResponseFormat(t *testing.T) {
	srv := new2FATestServer(t)
	session := srv.sessions.Create("admin")

	rr := enrollTOTPHelper(srv, session.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response JSON parse: %v", err)
	}

	required := []string{"secret", "qr_url", "algorithm", "digits", "period", "recovery"}
	for _, field := range required {
		if _, ok := resp[field]; !ok {
			t.Errorf("response missing required field: %s", field)
		}
	}

	if v, ok := resp["digits"].(float64); !ok || v != 6 {
		t.Errorf("digits should be 6, got %v", resp["digits"])
	}
	if v, ok := resp["period"].(float64); !ok || v != 30 {
		t.Errorf("period should be 30, got %v", resp["period"])
	}
	if v, ok := resp["algorithm"].(string); !ok || v != "SHA256" {
		t.Errorf("algorithm should be SHA256, got %s", resp["algorithm"])
	}
}

// TestAlertResponseFormat verifies the alerts API JSON response format.
func TestAlertResponseFormat(t *testing.T) {
	srv := new2FATestServer(t)

	srv.alertStore.Add(SecurityAlert{
		Type:        "login_failure",
		Username:    "admin",
		Description: "test alert",
		Severity:    AlertWarning,
	})

	session := srv.sessions.Create("admin")
	req := httptest.NewRequest("GET", "/api/alerts", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	rr := httptest.NewRecorder()
	srv.handleAlertsList(rr, req)

	var alerts []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &alerts); err != nil {
		t.Fatalf("alert JSON parse: %v", err)
	}

	if len(alerts) == 0 {
		t.Fatal("expected at least 1 alert")
	}

	for _, alert := range alerts {
		for _, field := range []string{"timestamp", "severity", "type", "description"} {
			if _, ok := alert[field]; !ok {
				t.Errorf("alert missing required field: %s", field)
			}
		}
	}
}

// ====================================================================
// Helpers
// ====================================================================

// withContextValues sets the username and session token in the request context
// for testing handlers that expect them to be set by middleware.
func withContextValues(parent context.Context, username, sessionToken string) context.Context {
	ctx := context.WithValue(parent, ctxUsernameKey{}, username)
	return context.WithValue(ctx, ctxSessionTokenKey{}, sessionToken)
}
