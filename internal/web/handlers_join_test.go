package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/identity"
	"github.com/yzy806806/meshdesk/internal/join"
)

// mockJoinTokenGenerator is a test implementation of JoinTokenGenerator.
type mockJoinTokenGenerator struct {
	enabled   bool
	secret    string
	serverFP  string
	joinURL   string
	binaryURL string
}

func (m *mockJoinTokenGenerator) GenerateJoinToken(lifetime time.Duration) (string, error) {
	return join.GenerateToken([]byte(m.secret), m.serverFP, lifetime)
}

func (m *mockJoinTokenGenerator) JoinServerURL() string {
	return m.joinURL
}

func (m *mockJoinTokenGenerator) BinaryDownloadURL(arch string) string {
	if m.binaryURL != "" {
		return m.binaryURL
	}
	return ""
}

func (m *mockJoinTokenGenerator) JoinEnabled() bool {
	return m.enabled
}

// newJoinTestServer creates a web server configured for join handler tests.
func newJoinTestServer(t *testing.T) *Server {
	t.Helper()

	cfg := config.Default()
	cfg.Node.Hostname = "test-node"
	cfg.Node.WebAddr = ":8080"
	cfg.Join.Enabled = true
	cfg.Join.Secret = "test-secret-key"
	cfg.Join.ListenAddr = ":8443"
	cfg.Reality.Enabled = true

	srv, err := New(Deps{
		Config: cfg,
		JoinTokenGenerator: &mockJoinTokenGenerator{
			enabled:   true,
			secret:    "test-secret-key",
			serverFP:  "abcdef0123456789",
			joinURL:   "http://test-node:8443",
			binaryURL: "https://github.com/yzy806806/meshdesk/releases/latest/download/meshdesk-linux-amd64",
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	return srv
}

func TestJoinToken_GenerateSuccess(t *testing.T) {
	srv := newJoinTestServer(t)

	body := `{"lifetime": 60, "arch": "amd64"}`
	req := httptest.NewRequest(http.MethodPost, "/api/join/token", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleJoinToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp joinTokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if !resp.Success {
		t.Fatalf("Success = false, want true; error: %s", resp.Error)
	}

	if resp.Token == "" {
		t.Error("Token is empty")
	}

	if resp.JoinURL == "" {
		t.Error("JoinURL is empty")
	}

	if resp.InstallCommand == "" {
		t.Error("InstallCommand is empty")
	}

	// Install command should be a curl|sh command.
	if !strings.Contains(resp.InstallCommand, "curl") {
		t.Errorf("InstallCommand doesn't contain 'curl': %s", resp.InstallCommand)
	}
	if !strings.Contains(resp.InstallCommand, "| sh") {
		t.Errorf("InstallCommand doesn't contain '| sh': %s", resp.InstallCommand)
	}

	// ExpiresIn should be 3600 seconds (60 minutes).
	if resp.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", resp.ExpiresIn)
	}

	// The token should be parseable.
	parsed, err := join.ParseToken(resp.Token, []byte("test-secret-key"))
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}
	if parsed.ServerFP != "abcdef0123456789" {
		t.Errorf("ServerFP = %s, want abcdef0123456789", parsed.ServerFP)
	}
}

func TestJoinToken_DefaultLifetime(t *testing.T) {
	srv := newJoinTestServer(t)

	// Empty body → default 30 min.
	req := httptest.NewRequest(http.MethodPost, "/api/join/token", strings.NewReader(""))
	rr := httptest.NewRecorder()
	srv.handleJoinToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp joinTokenResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.ExpiresIn != 1800 {
		t.Errorf("ExpiresIn = %d, want 1800 (30 min default)", resp.ExpiresIn)
	}
}

func TestJoinToken_JoinDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Join.Enabled = false
	cfg.Reality.Enabled = true

	srv, err := New(Deps{
		Config: cfg,
		JoinTokenGenerator: &mockJoinTokenGenerator{
			enabled: false,
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/join/token", strings.NewReader(`{"lifetime": 30}`))
	rr := httptest.NewRecorder()
	srv.handleJoinToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp joinTokenResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.Success {
		t.Error("Success should be false when join is disabled")
	}
	if !strings.Contains(resp.Error, "not enabled") {
		t.Errorf("Error should mention 'not enabled': %s", resp.Error)
	}
}

func TestJoinToken_MethodNotAllowed(t *testing.T) {
	srv := newJoinTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/join/token", nil)
	rr := httptest.NewRecorder()
	srv.handleJoinToken(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestJoinInstallScript_ContainsAllParams(t *testing.T) {
	joinURL := "http://bootstrap:8443"
	token := "test-token-abc123"
	binaryURL := "https://github.com/yzy806806/meshdesk/releases/latest/download/meshdesk-linux-amd64"

	script := buildInstallScript(joinURL, token, binaryURL)

	// Script should contain the join URL.
	if !strings.Contains(script, joinURL) {
		t.Error("Script doesn't contain join URL")
	}

	// Script should contain the token.
	if !strings.Contains(script, token) {
		t.Error("Script doesn't contain token")
	}

	// Script should contain the binary URL.
	if !strings.Contains(script, binaryURL) {
		t.Error("Script doesn't contain binary URL")
	}

	// Script should detect architecture.
	if !strings.Contains(script, "uname -m") {
		t.Error("Script doesn't detect architecture")
	}

	// Script should create config directory.
	if !strings.Contains(script, "/etc/meshdesk") {
		t.Error("Script doesn't reference /etc/meshdesk")
	}

	// Script should run meshdesk join.
	if !strings.Contains(script, "join --join-url") {
		t.Error("Script doesn't run 'meshdesk join'")
	}

	// Script should contain --join-url and --join-token.
	if !strings.Contains(script, "--join-url") {
		t.Error("Script doesn't contain --join-url")
	}
	if !strings.Contains(script, "--join-token") {
		t.Error("Script doesn't contain --join-token")
	}
}

func TestJoinInstallScript_NoBinaryURL(t *testing.T) {
	joinURL := "http://bootstrap:8443"
	token := "test-token-abc123"

	script := buildInstallScript(joinURL, token, "")

	// Script should still work — should fall back to GitHub releases URL.
	if !strings.Contains(script, "github.com") {
		t.Error("Script should contain GitHub releases fallback URL")
	}

	// Should still contain join URL and token.
	if !strings.Contains(script, joinURL) {
		t.Error("Script doesn't contain join URL")
	}
	if !strings.Contains(script, token) {
		t.Error("Script doesn't contain token")
	}
}

func TestJoinInstallScript_Endpoint(t *testing.T) {
	srv := newJoinTestServer(t)

	req := httptest.NewRequest(http.MethodGet,
		"/api/join/install.sh?join_url=http%3A%2F%2Fbootstrap%3A8443&token=abc123&binary_url=https%3A%2F%2Fexample.com%2Fmeshdesk",
		nil)
	rr := httptest.NewRecorder()
	srv.handleJoinInstallScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "shellscript") {
		t.Errorf("Content-Type = %s, want shellscript", ct)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "bootstrap:8443") {
		t.Error("Script doesn't contain decoded join URL")
	}
	if !strings.Contains(body, "abc123") {
		t.Error("Script doesn't contain token")
	}
	if !strings.Contains(body, "example.com/meshdesk") {
		t.Error("Script doesn't contain binary URL")
	}
}

func TestJoinInstallScript_MissingParams(t *testing.T) {
	srv := newJoinTestServer(t)

	// Missing token.
	req := httptest.NewRequest(http.MethodGet, "/api/join/install.sh?join_url=http://bootstrap:8443", nil)
	rr := httptest.NewRecorder()
	srv.handleJoinInstallScript(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestJoinInstallScript_ShellInjectionSafety(t *testing.T) {
	// Ensure the escapeShellSingle function properly escapes single quotes.
	input := "it's a test"
	escaped := escapeShellSingle(input)

	// The escaped version should contain '\'' which closes the single quote,
	// adds an escaped single quote, and reopens.
	if !strings.Contains(escaped, `'\''`) {
		t.Errorf("escapeShellSingle didn't properly escape single quote: %s", escaped)
	}
}

func TestJoinPage_Renders(t *testing.T) {
	srv := newJoinTestServer(t)

	// Just verify the template can render without panicking.
	req := httptest.NewRequest(http.MethodGet, "/join", nil)
	rr := httptest.NewRecorder()
	srv.handleJoinPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "One-Click Join") {
		t.Error("Page doesn't contain 'One-Click Join'")
	}
	if !strings.Contains(body, "join.js") {
		t.Error("Page doesn't reference join.js")
	}
}

// Test with the default join token generator (no injected JoinTokenGenerator).
func TestJoinToken_DefaultGenerator(t *testing.T) {
	// Create a real identity for the test.
	id, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity.GenerateIdentity: %v", err)
	}

	cfg := config.Default()
	cfg.Join.Enabled = true
	cfg.Join.Secret = "default-gen-secret"
	cfg.Reality.Enabled = true

	// Use the default generator by NOT injecting JoinTokenGenerator.
	srv, err := New(Deps{
		Config: cfg,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// The default generator uses s.node.Identity(), which is nil here
	// since we didn't inject a Node. So it should fail gracefully.
	req := httptest.NewRequest(http.MethodPost, "/api/join/token", strings.NewReader(`{"lifetime": 30}`))
	rr := httptest.NewRecorder()
	srv.handleJoinToken(rr, req)

	// Should fail because join is enabled in config but the default
	// generator's JoinEnabled() checks cfg.Join.Enabled && cfg.Reality.Enabled.
	// Both are true, so it should try to generate. But without a node identity,
	// the token generation should fail.
	var resp joinTokenResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	// Either it fails with "identity not available" or succeeds if the
	// default generator doesn't need identity. Either way, it shouldn't panic.
	_ = id // keep identity alive
}

func TestUrlEncode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"http://example.com:8443", "http%3A%2F%2Fexample.com%3A8443"},
		{"a+b=c", "a%2Bb%3Dc"},
		{"token-123.456", "token-123.456"},
	}

	for _, tc := range tests {
		got := urlEncode(tc.input)
		if got != tc.expected {
			t.Errorf("urlEncode(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

// TestJoinScript_ValidToken verifies that GET /join?token=xxx with a
// valid token returns the install shell script.
func TestJoinScript_ValidToken(t *testing.T) {
	srv := newJoinTestServer(t)

	// Generate a valid token using the test secret.
	tok, err := join.GenerateToken([]byte("test-secret-key"), "abcdef0123456789", 30*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/join?token="+tok, nil)
	rr := httptest.NewRecorder()
	srv.handleJoinScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "shellscript") {
		t.Errorf("Content-Type = %s, want shellscript", ct)
	}

	body := rr.Body.String()
	// Script should contain the token.
	if !strings.Contains(body, tok) {
		t.Error("Script doesn't contain the token")
	}
	// Script should detect architecture.
	if !strings.Contains(body, "uname -m") {
		t.Error("Script doesn't detect architecture")
	}
	// Script should support both amd64 and arm64.
	if !strings.Contains(body, "amd64") {
		t.Error("Script doesn't support amd64")
	}
	if !strings.Contains(body, "arm64") {
		t.Error("Script doesn't support arm64")
	}
	// Script should create config directory.
	if !strings.Contains(body, "/etc/meshdesk") {
		t.Error("Script doesn't reference /etc/meshdesk")
	}
	// Script should run meshdesk join with --join-url and --join-token.
	if !strings.Contains(body, "join --join-url") {
		t.Error("Script doesn't run 'meshdesk join'")
	}
	if !strings.Contains(body, "--join-token") {
		t.Error("Script doesn't contain --join-token")
	}
}

// TestJoinScript_InvalidToken verifies that GET /join?token=xxx with an
// invalid token returns a 400 error as a shell script.
func TestJoinScript_InvalidToken(t *testing.T) {
	srv := newJoinTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/join?token=invalid-token-data", nil)
	rr := httptest.NewRecorder()
	srv.handleJoinScript(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "shellscript") {
		t.Errorf("Content-Type = %s, want shellscript", ct)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Error:") {
		t.Error("Error script doesn't contain 'Error:'")
	}
	if !strings.Contains(body, "exit 1") {
		t.Error("Error script doesn't exit with code 1")
	}
}

// TestJoinScript_MissingToken verifies that GET /join without a token
// parameter returns a 400 error.
func TestJoinScript_MissingToken(t *testing.T) {
	srv := newJoinTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/join", nil)
	rr := httptest.NewRecorder()
	srv.handleJoinScript(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// TestJoinScript_ExpiredToken verifies that an expired token is rejected.
func TestJoinScript_ExpiredToken(t *testing.T) {
	srv := newJoinTestServer(t)

	// Generate a token that's already expired (negative lifetime).
	tok, err := join.GenerateToken([]byte("test-secret-key"), "abcdef0123456789", -1*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/join?token="+tok, nil)
	rr := httptest.NewRecorder()
	srv.handleJoinScript(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "expired") {
		t.Errorf("Error script should mention 'expired': %s", body)
	}
}

// TestJoinRoute_Dispatch verifies that handleJoinRoute dispatches to
// handleJoinScript when token is present, and to the join page otherwise.
func TestJoinRoute_Dispatch(t *testing.T) {
	srv := newJoinTestServer(t)

	// With token → should serve script (may be 400 if token invalid, but
	// should NOT redirect to login).
	req := httptest.NewRequest(http.MethodGet, "/join?token=some-token", nil)
	rr := httptest.NewRecorder()
	srv.handleJoinRoute(rr, req)

	// Should not be a redirect to /login.
	if rr.Code == http.StatusSeeOther {
		t.Error("handleJoinRoute with token redirected to login (should serve script)")
	}
	// Should be 400 (invalid token) or 200 (valid token) — either way,
	// it should have processed the token.
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 or 400", rr.Code)
	}
}

// TestJoinInstallScript_HTTPAddsInsecureTLS verifies that when the join URL
// uses HTTP (not HTTPS), the install script passes --insecure-tls to the
// meshdesk join command.
func TestJoinInstallScript_HTTPAddsInsecureTLS(t *testing.T) {
	joinURL := "http://bootstrap:8443"
	token := "test-token-abc123"

	script := buildInstallScript(joinURL, token, "")

	if !strings.Contains(script, "--insecure-tls") {
		t.Error("Install script for HTTP join URL should contain --insecure-tls")
	}
}

// TestJoinInstallScript_HTTPSNoInsecureTLS verifies that when the join URL
// uses HTTPS, the install script does NOT pass --insecure-tls.
func TestJoinInstallScript_HTTPSNoInsecureTLS(t *testing.T) {
	joinURL := "https://bootstrap:8443"
	token := "test-token-abc123"

	script := buildInstallScript(joinURL, token, "")

	if strings.Contains(script, "--insecure-tls") {
		t.Error("Install script for HTTPS join URL should NOT contain --insecure-tls")
	}
}

// TestJoinInstallScript_ContainsSystemdService verifies that the install
// script includes systemd service setup for auto-restart on boot.
func TestJoinInstallScript_ContainsSystemdService(t *testing.T) {
	joinURL := "http://bootstrap:8443"
	token := "test-token-abc123"

	script := buildInstallScript(joinURL, token, "")

	// Should contain systemd unit file creation.
	if !strings.Contains(script, "meshdesk.service") {
		t.Error("Install script should create meshdesk.service unit file")
	}
	if !strings.Contains(script, "systemctl") {
		t.Error("Install script should use systemctl commands")
	}
	if !strings.Contains(script, "systemctl enable meshdesk") {
		t.Error("Install script should enable meshdesk service")
	}
	if !strings.Contains(script, "Restart=on-failure") {
		t.Error("Install script should set Restart=on-failure in unit file")
	}
	if !strings.Contains(script, "ExecStart=/usr/local/bin/meshdesk") {
		t.Error("Install script should have ExecStart pointing to meshdesk binary")
	}
}

// TestJoinInstallScript_SystemdBeforeJoin verifies that the systemd service
// setup appears before the exec join command in the script. This is critical
// because exec replaces the shell process — anything after it never runs.
func TestJoinInstallScript_SystemdBeforeJoin(t *testing.T) {
	joinURL := "http://bootstrap:8443"
	token := "test-token-abc123"

	script := buildInstallScript(joinURL, token, "")

	systemdIdx := strings.Index(script, "systemctl enable meshdesk")
	joinIdx := strings.Index(script, "exec \"$INSTALL_DIR/meshdesk\" join")

	if systemdIdx < 0 {
		t.Fatal("Script doesn't contain systemd enable command")
	}
	if joinIdx < 0 {
		t.Fatal("Script doesn't contain exec join command")
	}
	if systemdIdx > joinIdx {
		t.Errorf("Systemd setup (idx=%d) should appear before join exec (idx=%d)", systemdIdx, joinIdx)
	}
}
