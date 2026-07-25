package webssh

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockAuthChecker is a test AuthChecker that allows/denies based on a preset map.
type mockAuthChecker struct {
	allowedPeers map[string]bool
}

func (m *mockAuthChecker) AuthorizeSSH(peerID string) bool {
	return m.allowedPeers[peerID]
}

func (m *mockAuthChecker) AuthorizeSSHWithIP(peerID, sourceIP string) bool {
	return m.allowedPeers[peerID]
}

// newTestHub creates a minimal Hub suitable for handler auth tests.
// The Hub has a valid WebSocket upgrader but no SSH backend — the
// auth check runs before any SSH connection is attempted.
func newTestHub() *Hub {
	dialer := &NetDialer{Timeout: 5 * time.Second}
	sshClient := NewSSHClient(dialer, 5*time.Second, nil)
	resolver := &staticResolver{ip: "127.0.0.1:1"}
	return NewHub(sshClient, resolver, 22, 64, 30*time.Second, 5*time.Second)
}

// TestHandlerRejectsUnauthorizedPeer verifies that the handler returns
// HTTP 403 when the requesting peer lacks the ssh_proxy capability.
func TestHandlerRejectsUnauthorizedPeer(t *testing.T) {
	hub := newTestHub()
	defer hub.CloseAll()
	checker := &mockAuthChecker{
		allowedPeers: map[string]bool{
			"authorized-peer": true,
			// "unauthorized-peer" is NOT in the map
		},
	}

	handler := NewHandlerWithAuth(hub, checker)

	req := httptest.NewRequest("GET", "/ws/terminal?node=unauthorized-peer", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unauthorized peer, got %d", rr.Code)
	}
}

// TestHandlerAcceptsAuthorizedPeer verifies that the handler proceeds
// past the auth check for authorized peers. The WebSocket upgrade will
// fail (no real SSH server), but the critical assertion is that it does
// NOT return 403 — proving the auth check passed.
func TestHandlerAcceptsAuthorizedPeer(t *testing.T) {
	hub := newTestHub()
	defer hub.CloseAll()
	checker := &mockAuthChecker{
		allowedPeers: map[string]bool{
			"authorized-peer": true,
		},
	}

	handler := NewHandlerWithAuth(hub, checker)

	req := httptest.NewRequest("GET", "/ws/terminal?node=authorized-peer&cols=120&rows=40", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should NOT be 403 — the auth check passed.
	// The upgrade may fail with another error (e.g. 400 from the upgrader),
	// but that's after auth and is acceptable for this unit test.
	if rr.Code == http.StatusForbidden {
		t.Error("expected authorized peer to NOT get 403")
	}
}

// TestHandlerNilAuthCheckerAllowsAll verifies that a nil auth checker
// (testing mode) allows all peers without checking.
func TestHandlerNilAuthCheckerAllowsAll(t *testing.T) {
	hub := newTestHub()
	defer hub.CloseAll()
	handler := NewHandler(hub) // no auth checker

	req := httptest.NewRequest("GET", "/ws/terminal?node=any-peer", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should NOT be 403 — no auth checker means all allowed
	if rr.Code == http.StatusForbidden {
		t.Error("expected nil auth checker to allow all peers")
	}
}

// TestHandlerRejectsMissingNodeParam verifies that the handler still
// returns 400 for missing node parameter, even with auth configured.
func TestHandlerRejectsMissingNodeParam(t *testing.T) {
	hub := newTestHub()
	defer hub.CloseAll()
	checker := &mockAuthChecker{allowedPeers: map[string]bool{}}

	handler := NewHandlerWithAuth(hub, checker)

	req := httptest.NewRequest("GET", "/ws/terminal", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing node, got %d", rr.Code)
	}
}
