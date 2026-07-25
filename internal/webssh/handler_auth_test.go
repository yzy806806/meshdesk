package webssh

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestHub creates a minimal Hub suitable for handler tests.
// The Hub has a valid WebSocket upgrader but no SSH backend.
func newTestHub() *Hub {
	dialer := &NetDialer{Timeout: 5 * time.Second}
	sshClient := NewSSHClient(dialer, 5*time.Second, nil)
	resolver := &staticResolver{ip: "127.0.0.1:1"}
	return NewHub(sshClient, resolver, 22, 64, 30*time.Second, 5*time.Second)
}

// TestHandlerRejectsMissingNodeParam verifies that the handler returns
// 400 when the 'node' query parameter is missing.
func TestHandlerRejectsMissingNodeParam(t *testing.T) {
	hub := newTestHub()
	defer hub.CloseAll()
	handler := NewHandler(hub)

	req := httptest.NewRequest("GET", "/ws/terminal", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing node, got %d", rr.Code)
	}
}

// TestHandlerNoInlineAuthCheck verifies that the handler does NOT perform
// any capability check itself — that responsibility belongs to the upstream
// RequireCapability middleware. The handler should proceed past the auth
// point regardless of the peer ID (it may fail at WebSocket upgrade, but
// it must not return 403).
func TestHandlerNoInlineAuthCheck(t *testing.T) {
	hub := newTestHub()
	defer hub.CloseAll()
	handler := NewHandler(hub)

	// Any peer ID should pass through the handler without a 403.
	// The WebSocket upgrade will fail (no real SSH server), but the
	// critical assertion is that 403 is never returned by the handler.
	req := httptest.NewRequest("GET", "/ws/terminal?node=any-peer", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Error("handler should not return 403 — auth is handled by middleware")
	}
}

// TestHandlerAcceptsAuthorizedPeer verifies that the handler proceeds
// past the (now removed) auth check for any peer. The WebSocket upgrade
// will fail (no real SSH server), but the critical assertion is that
// it does NOT return 403.
func TestHandlerAcceptsAnyPeer(t *testing.T) {
	hub := newTestHub()
	defer hub.CloseAll()
	handler := NewHandler(hub)

	req := httptest.NewRequest("GET", "/ws/terminal?node=authorized-peer&cols=120&rows=40", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should NOT be 403 — the handler doesn't check auth.
	// The upgrade may fail with another error, but that's acceptable.
	if rr.Code == http.StatusForbidden {
		t.Error("expected handler to NOT return 403 (auth is middleware's job)")
	}
}
