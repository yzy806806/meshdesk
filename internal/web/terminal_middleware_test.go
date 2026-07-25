package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/webssh"
)

// newTerminalTestServer creates a web server configured with an auth
// engine, SSH hub, and a peer with ssh_proxy capability for testing
// the /ws/terminal middleware chain.
func newTerminalTestServer(t *testing.T) *Server {
	t.Helper()

	cfg := config.Default()
	cfg.Peers = []config.PeerConfig{
		{
			PublicKey:    "ssh-authorized-peer",
			Capabilities: []string{auth.CapSSHProxy},
		},
		{
			PublicKey:    "ssh-unauthorized-peer",
			Capabilities: []string{auth.CapMonitorRead}, // no ssh_proxy
		},
	}

	audit := auth.NewAuditLogger(nil)
	engine := auth.NewCapabilityEngine(cfg, audit)

	// Create a minimal SSH hub (will not actually connect, but is
	// needed for NewHandler to not be nil).
	dialer := &webssh.NetDialer{}
	sshClient := webssh.NewSSHClient(dialer, 0, nil)
	hub := webssh.NewHub(sshClient, &staticPeerResolver{}, 22, 64, 0, 0)

	srv, err := New(Deps{
		Config:     cfg,
		AuthEngine: engine,
		SSHHub:     hub,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return srv
}

// staticPeerResolver is a minimal resolver for the SSH hub.
type staticPeerResolver struct{}

func (r *staticPeerResolver) ResolvePeerMeshIP(peerID string) (string, error) {
	return "127.0.0.1", nil
}

// TestTerminalMiddleware_AuthorizedPeer verifies that a request with
// the ssh_proxy capability passes through the full middleware chain
// (sessionAuth → peerIDFromQuery → RequireCapability) and reaches the
// handler without being blocked.
func TestTerminalMiddleware_AuthorizedPeer(t *testing.T) {
	srv := newTerminalTestServer(t)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	// No web users configured → sessionAuthMiddleware passes through.
	// The peer has ssh_proxy → RequireCapability passes.
	req := httptest.NewRequest("GET", "/ws/terminal?node=ssh-authorized-peer", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// Should NOT be 401 (no session — but no web users configured so it passes)
	// Should NOT be 403 (peer has ssh_proxy)
	// The WebSocket upgrade will fail (no real SSH server), but that's
	// after the middleware chain — the key assertion is that the middleware
	// didn't block it.
	if rr.Code == http.StatusForbidden {
		t.Errorf("expected authorized peer to pass middleware, got 403: %s", rr.Body.String())
	}
	if rr.Code == http.StatusUnauthorized {
		t.Errorf("expected authorized peer to pass middleware, got 401: %s", rr.Body.String())
	}
}

// TestTerminalMiddleware_UnauthorizedPeer verifies that a peer without
// the ssh_proxy capability is rejected by the RequireCapability middleware
// with 403 Forbidden.
func TestTerminalMiddleware_UnauthorizedPeer(t *testing.T) {
	srv := newTerminalTestServer(t)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	// peer has monitor_read but NOT ssh_proxy → should get 403
	req := httptest.NewRequest("GET", "/ws/terminal?node=ssh-unauthorized-peer", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unauthorized peer, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestTerminalMiddleware_UnknownPeer verifies that an unknown peer is
// rejected with 403 by RequireCapability (zero-trust: default-deny).
func TestTerminalMiddleware_UnknownPeer(t *testing.T) {
	srv := newTerminalTestServer(t)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/ws/terminal?node=unknown-peer-key", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unknown peer, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestTerminalMiddleware_MissingNodeParam verifies that a request without
// the 'node' query parameter is rejected with 400 Bad Request by
// peerIDFromQueryMiddleware before reaching RequireCapability.
func TestTerminalMiddleware_MissingNodeParam(t *testing.T) {
	srv := newTerminalTestServer(t)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/ws/terminal", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing node param, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestTerminalMiddleware_SessionAuthRequired verifies that when web users
// are configured, a request without a valid session cookie is rejected
// with 401 by sessionAuthMiddleware.
func TestTerminalMiddleware_SessionAuthRequired(t *testing.T) {
	srv := newTerminalTestServer(t)

	// Configure web users to enable session enforcement.
	srv.cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: "$2a$10$dummyhashdummyhashdummyhashdummyhashdummyhashdummyhashdum"},
	}

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	// No session cookie → should get 401
	req := httptest.NewRequest("GET", "/ws/terminal?node=ssh-authorized-peer", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing session, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestTerminalMiddleware_RevokedPeer verifies that a peer whose
// capabilities have been revoked is rejected with 403.
func TestTerminalMiddleware_RevokedPeer(t *testing.T) {
	srv := newTerminalTestServer(t)

	// Revoke the authorized peer
	srv.authEngine.Revoke("ssh-authorized-peer", "revoker", "sig", "test")

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest("GET", "/ws/terminal?node=ssh-authorized-peer", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for revoked peer, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestTerminalMiddleware_NoAuthEngine verifies that when no auth engine
// is configured (testing mode), the capability check is skipped but
// session auth is still enforced.
func TestTerminalMiddleware_NoAuthEngine(t *testing.T) {
	cfg := config.Default()
	store := monitor.NewStore()

	// Create a minimal SSH hub so the handler doesn't panic
	dialer := &webssh.NetDialer{}
	sshClient := webssh.NewSSHClient(dialer, 0, nil)
	hub := webssh.NewHub(sshClient, &staticPeerResolver{}, 22, 64, 0, 0)

	// Create a server with no auth engine
	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: store,
		SSHHub:       hub,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	// No auth engine, no web users → request should pass through
	// (it may fail at WebSocket upgrade, but must not be 403/401)
	req := httptest.NewRequest("GET", "/ws/terminal?node=any-peer", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Error("expected no 403 when auth engine is nil (testing mode)")
	}
	if rr.Code == http.StatusUnauthorized {
		t.Error("expected no 401 when no web users configured")
	}
}

// TestPeerIDFromQueryMiddleware verifies that the middleware extracts
// the peer ID from the query string and injects it into the context.
func TestPeerIDFromQueryMiddleware(t *testing.T) {
	srv := newTerminalTestServer(t)

	// Track whether the peer ID was injected
	var capturedPeerID string
	var peerIDFound bool

	handler := srv.peerIDFromQueryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPeerID, peerIDFound = auth.PeerIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// With node param
	req := httptest.NewRequest("GET", "/ws/terminal?node=test-peer-123", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !peerIDFound {
		t.Error("expected peer ID to be in context")
	}
	if capturedPeerID != "test-peer-123" {
		t.Errorf("expected peer ID 'test-peer-123', got %q", capturedPeerID)
	}
}

// TestPeerIDFromQueryMiddleware_MissingNode verifies that the middleware
// rejects requests without the node parameter.
func TestPeerIDFromQueryMiddleware_MissingNode(t *testing.T) {
	srv := newTerminalTestServer(t)

	handler := srv.peerIDFromQueryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when node param is missing")
	}))

	req := httptest.NewRequest("GET", "/ws/terminal", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestSessionAuthMiddleware_NoWebUsers verifies that session auth
// passes through when no web users are configured.
func TestSessionAuthMiddleware_NoWebUsers(t *testing.T) {
	srv := newTerminalTestServer(t)
	// srv has no web users configured by default

	called := false
	handler := srv.sessionAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/ws/terminal", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected handler to be called when no web users configured")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// TestSessionAuthMiddleware_WithWebUsers verifies that session auth
// rejects requests without a valid session cookie when web users are
// configured.
func TestSessionAuthMiddleware_WithWebUsers(t *testing.T) {
	srv := newTerminalTestServer(t)
	srv.cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: "$2a$10$dummyhashdummyhashdummyhashdummyhashdummyhashdummyhashdum"},
	}

	called := false
	handler := srv.sessionAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest("GET", "/ws/terminal", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Error("handler should NOT be called when session is missing")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestSessionAuthMiddleware_ValidSession verifies that a valid session
// cookie passes through.
func TestSessionAuthMiddleware_ValidSession(t *testing.T) {
	srv := newTerminalTestServer(t)
	srv.cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: "$2a$10$dummyhashdummyhashdummyhashdummyhashdummyhashdummyhashdum"},
	}

	// Create a session
	session := srv.sessions.Create("admin")

	called := false
	handler := srv.sessionAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/ws/terminal", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("handler should be called with valid session")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}
