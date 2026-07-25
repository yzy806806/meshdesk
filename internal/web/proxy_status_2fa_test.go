package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"golang.org/x/crypto/bcrypt"
)

// mockProxyStatusProvider is a test double for ProxyStatusProvider.
type mockProxyStatusProvider struct {
	status any
}

func (m *mockProxyStatusProvider) ProxyStatus() any {
	return m.status
}

// new2FAEnforcementTestServer creates a web server with web users
// configured for testing the Require2FA enforcement middleware.
// The Require2FA flag is set via the cfg parameter by the caller.
func new2FAEnforcementTestServer(t *testing.T, require2FA bool) *Server {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash error: %v", err)
	}

	cfg := config.Default()
	cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: string(hash)},
	}
	cfg.Auth.Require2FA = require2FA

	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: monitor.NewStore(),
		ProxyStatusProvider: &mockProxyStatusProvider{
			status: proxyStatusData{
				Running:       true,
				SessionCount:  3,
				CFTunnelReady: true,
				Path1Relays:   []string{"relay1:9000"},
				Path2Relays:   []string{"relay2:9000"},
				ExitAddr:      "exit.mesh:443",
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return srv
}

// fullMiddlewareChain wraps the mux with the same middleware chain
// used by Start(): recoverMiddleware → authMiddleware → require2FAEnforcement.
// This lets tests exercise the full chain without starting a real HTTP server.
func fullMiddlewareChain(srv *Server) http.Handler {
	mux := http.NewServeMux()
	srv.registerRoutes(mux)
	return srv.recoverMiddleware(srv.authMiddleware(srv.require2FAEnforcement(mux)))
}

// loginAndGetSession logs in via the handler and returns the session token.
// Uses the 2FA-exempt login path (no TOTP enrolled).
func loginAndGetSession(t *testing.T, srv *Server) string {
	t.Helper()

	form := "username=admin&password=testpassword"
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	// Use the full middleware chain so /login goes through authMiddleware
	// (which exempts /login from session checks).
	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("login failed: expected 303, got %d: %s", rr.Code, rr.Body.String())
	}

	// Extract session cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "meshdesk_session" {
			return c.Value
		}
	}
	t.Fatal("no meshdesk_session cookie in login response")
	return ""
}

// =====================================================================
// TESTS: Proxy Status Endpoint
// =====================================================================

// TestProxyStatus_WithProvider verifies that /api/proxy/status returns
// the proxy status JSON when a ProxyStatusProvider is configured.
func TestProxyStatus_WithProvider(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, false) // Require2FA=false

	sessionToken := loginAndGetSession(t, srv)

	req := httptest.NewRequest("GET", "/api/proxy/status", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp proxyStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Running {
		t.Error("expected running=true")
	}
	if resp.SessionCount != 3 {
		t.Errorf("expected session_count=3, got %d", resp.SessionCount)
	}
	if !resp.CFTunnelReady {
		t.Error("expected cf_tunnel_ready=true")
	}
	if resp.ExitAddr != "exit.mesh:443" {
		t.Errorf("expected exit_addr=exit.mesh:443, got %s", resp.ExitAddr)
	}
	if len(resp.Path1Relays) != 1 || resp.Path1Relays[0] != "relay1:9000" {
		t.Errorf("unexpected path1_relays: %v", resp.Path1Relays)
	}
}

// TestProxyStatus_WithoutProvider verifies that /api/proxy/status returns
// a stub response when no ProxyStatusProvider is configured (e.g., on
// a node that is not running as a proxy entry point).
func TestProxyStatus_WithoutProvider(t *testing.T) {
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
		// No ProxyStatusProvider
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	sessionToken := loginAndGetSession(t, srv)

	req := httptest.NewRequest("GET", "/api/proxy/status", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp proxyStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Should be an empty stub
	if resp.Running {
		t.Error("expected running=false for stub")
	}
	if resp.SessionCount != 0 {
		t.Errorf("expected session_count=0, got %d", resp.SessionCount)
	}
}

// TestProxyStatus_RequiresAuth verifies that /api/proxy/status requires
// a valid session — unauthenticated requests are rejected.
func TestProxyStatus_RequiresAuth(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, false)

	req := httptest.NewRequest("GET", "/api/proxy/status", nil)
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	// Should be redirected to /login (303 See Other)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect to /login, got %d", rr.Code)
	}
}

// TestProxyStatus_MethodNotAllowed verifies that non-GET methods are rejected.
func TestProxyStatus_MethodNotAllowed(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, false)

	sessionToken := loginAndGetSession(t, srv)

	req := httptest.NewRequest("POST", "/api/proxy/status", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// =====================================================================
// TESTS: 2FA Enforcement Middleware
// =====================================================================

// TestRequire2FAEnforcement_DisabledWhenFlagFalse verifies that when
// Require2FA is false, all endpoints are accessible without 2FA enrollment.
func TestRequire2FAEnforcement_DisabledWhenFlagFalse(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, false) // Require2FA=false

	sessionToken := loginAndGetSession(t, srv)

	// User is NOT enrolled in TOTP, but Require2FA is false,
	// so all endpoints should be accessible.
	req := httptest.NewRequest("GET", "/api/services/list", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	// Should NOT be 403 (2FA enforcement should not block)
	if rr.Code == http.StatusForbidden {
		t.Error("endpoint was blocked by 2FA enforcement when Require2FA=false")
	}
}

// TestRequire2FAEnforcement_ProxyStatusExemptWhenNotEnrolled verifies
// the CRITICAL task requirement: /api/proxy/status must remain accessible
// even when Require2FA is true AND the user has NOT completed TOTP enrollment.
//
// This is the core test for the task: "ensuring the TOTP middleware does NOT
// force 2FA on proxy status API endpoints that share the same HTTP router."
func TestRequire2FAEnforcement_ProxyStatusExemptWhenNotEnrolled(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, true) // Require2FA=true

	// Login — user is NOT enrolled in TOTP.
	sessionToken := loginAndGetSession(t, srv)

	// Verify the user is not enrolled
	if srv.totpStore.IsEnrolled("admin") {
		t.Fatal("precondition: admin should not be enrolled in TOTP")
	}

	// /api/proxy/status should be accessible despite 2FA enforcement.
	req := httptest.NewRequest("GET", "/api/proxy/status", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("EXPECTED: /api/proxy/status accessible (200) when Require2FA=true and user not enrolled. GOT: %d. %s",
			rr.Code, rr.Body.String())
	}

	// Verify the response body has valid JSON
	var resp proxyStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode proxy status response: %v", err)
	}
	if !resp.Running {
		t.Error("proxy status should show running=true")
	}
}

// TestRequire2FAEnforcement_OtherEndpointsBlockedWhenNotEnrolled verifies
// that when Require2FA is true and the user has NOT enrolled in TOTP,
// non-exempt endpoints are blocked with 403.
func TestRequire2FAEnforcement_OtherEndpointsBlockedWhenNotEnrolled(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, true) // Require2FA=true

	sessionToken := loginAndGetSession(t, srv)

	// User is not enrolled — should be blocked.
	endpoints := []string{
		"/api/services/list",
		"/api/files/list",
		"/",
		"/nodes",
		"/services",
	}

	chain := fullMiddlewareChain(srv)

	for _, endpoint := range endpoints {
		req := httptest.NewRequest("GET", endpoint, nil)
		req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
		rr := httptest.NewRecorder()
		chain.ServeHTTP(rr, req)

		// API endpoints should get 403; page routes should get 303 redirect.
		if endpoint == "/api/services/list" || endpoint == "/api/files/list" {
			if rr.Code != http.StatusForbidden {
				t.Errorf("endpoint %s: expected 403 (2FA enforcement), got %d", endpoint, rr.Code)
			}
		}
		// Page routes redirect to /api/2fa/enroll
		if endpoint == "/" || endpoint == "/nodes" || endpoint == "/services" {
			if rr.Code != http.StatusSeeOther {
				t.Errorf("endpoint %s: expected 303 redirect to enrollment, got %d", endpoint, rr.Code)
			}
			loc := rr.Header().Get("Location")
			if loc != "/api/2fa/enroll" {
				t.Errorf("endpoint %s: expected redirect to /api/2fa/enroll, got %s", endpoint, loc)
			}
		}
	}
}

// TestRequire2FAEnforcement_EnrolledUserCanAccessAllEndpoints verifies that
// when Require2FA is true AND the user HAS enrolled in TOTP, all endpoints
// are accessible.
func TestRequire2FAEnforcement_EnrolledUserCanAccessAllEndpoints(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, true) // Require2FA=true

	sessionToken := loginAndGetSession(t, srv)

	// Enroll the user in TOTP and complete enrollment to VERIFIED state
	result, err := srv.totpStore.Enroll("admin")
	if err != nil {
		t.Fatalf("failed to enroll admin in TOTP: %v", err)
	}

	// Complete enrollment: PENDING → VERIFIED
	validCode := computeTOTP(result.Secret, time.Now())
	if !srv.totpStore.ValidateCode("admin", validCode) {
		t.Fatal("failed to complete TOTP enrollment")
	}

	if !srv.totpStore.IsEnrolled("admin") {
		t.Fatal("admin should be enrolled after enrollment completion")
	}

	// Now the user should be able to access all endpoints.
	req := httptest.NewRequest("GET", "/api/services/list", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Errorf("endpoint should NOT be blocked when user is enrolled in TOTP, got 403: %s", rr.Body.String())
	}
}

// TestRequire2FAEnforcement_EnrolledUserProxyStatusAccessible verifies
// that /api/proxy/status is still accessible when the user IS enrolled
// (no regression on the exempt path).
func TestRequire2FAEnforcement_EnrolledUserProxyStatusAccessible(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, true)

	sessionToken := loginAndGetSession(t, srv)

	// Enroll and complete to VERIFIED state
	result, err := srv.totpStore.Enroll("admin")
	if err != nil {
		t.Fatalf("enroll error: %v", err)
	}
	validCode := computeTOTP(result.Secret, time.Now())
	srv.totpStore.ValidateCode("admin", validCode)

	req := httptest.NewRequest("GET", "/api/proxy/status", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for proxy status with enrolled user, got %d", rr.Code)
	}
}

// TestRequire2FAEnforcement_2FAEnrollEndpointExempt verifies that the
// /api/2fa/enroll endpoint is exempt from 2FA enforcement — the user
// must be able to enroll in order to satisfy the requirement.
func TestRequire2FAEnforcement_2FAEnrollEndpointExempt(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, true)

	sessionToken := loginAndGetSession(t, srv)

	// User is NOT enrolled, but /api/2fa/enroll should still be accessible.
	req := httptest.NewRequest("POST", "/api/2fa/enroll", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Error("/api/2fa/enroll should be exempt from 2FA enforcement, got 403")
	}
}

// TestRequire2FAEnforcement_2FAStatusEndpointExempt verifies that
// /api/2fa/status is exempt from 2FA enforcement.
func TestRequire2FAEnforcement_2FAStatusEndpointExempt(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, true)

	sessionToken := loginAndGetSession(t, srv)

	req := httptest.NewRequest("GET", "/api/2fa/status", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Error("/api/2fa/status should be exempt from 2FA enforcement, got 403")
	}
}

// TestRequire2FAEnforcement_AlertsEndpointExempt verifies that
// /api/alerts is exempt from 2FA enforcement — security alerts must
// remain visible so the admin can see what's being blocked.
func TestRequire2FAEnforcement_AlertsEndpointExempt(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, true)

	sessionToken := loginAndGetSession(t, srv)

	req := httptest.NewRequest("GET", "/api/alerts", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Error("/api/alerts should be exempt from 2FA enforcement, got 403")
	}
}

// TestRequire2FAEnforcement_GeneratesAlertOnBlock verifies that a security
// alert is generated when 2FA enforcement blocks a request.
func TestRequire2FAEnforcement_GeneratesAlertOnBlock(t *testing.T) {
	srv := new2FAEnforcementTestServer(t, true)

	sessionToken := loginAndGetSession(t, srv)

	alertCountBefore := srv.alertStore.Count()

	req := httptest.NewRequest("GET", "/api/services/list", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}

	alertCountAfter := srv.alertStore.Count()
	if alertCountAfter <= alertCountBefore {
		t.Error("expected a security alert to be generated when 2FA enforcement blocks a request")
	}

	// Verify the alert type
	alerts := srv.alertStore.List()
	found := false
	for _, a := range alerts {
		if a.Type == "2fa_enforcement_block" {
			found = true
			if a.Username != "admin" {
				t.Errorf("expected alert username=admin, got %s", a.Username)
			}
			break
		}
	}
	if !found {
		t.Error("expected a 2fa_enforcement_block alert in the store")
	}
}

// TestRequire2FAEnforcement_NoWebUsers verifies that 2FA enforcement
// is a no-op when no web users are configured (first-run setup mode).
func TestRequire2FAEnforcement_NoWebUsers(t *testing.T) {
	cfg := config.Default()
	// No web users configured

	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: monitor.NewStore(),
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	srv.cfg.Auth.Require2FA = true

	// /api/proxy/status should be accessible without any session
	req := httptest.NewRequest("GET", "/api/proxy/status", nil)
	rr := httptest.NewRecorder()

	chain := fullMiddlewareChain(srv)
	chain.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 in first-run mode (no web users), got %d", rr.Code)
	}
}
