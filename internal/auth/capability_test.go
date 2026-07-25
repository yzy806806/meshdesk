package auth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

// --- Stub Auther for middleware tests ---

type stubAuther struct {
	results map[string]AuthResult // key = peerID+":"+capability
	calls   []authCall
}

type authCall struct {
	peerID     string
	capability string
	resource   string
	sourceIP   string
}

func (s *stubAuther) Authorize(sourcePeer, capability, resource string) AuthResult {
	return s.AuthorizeWithSourceIP(sourcePeer, capability, resource, "")
}

func (s *stubAuther) AuthorizeWithSourceIP(sourcePeer, capability, resource, sourceIP string) AuthResult {
	s.calls = append(s.calls, authCall{sourcePeer, capability, resource, sourceIP})
	key := sourcePeer + ":" + capability
	if r, ok := s.results[key]; ok {
		return r
	}
	return AuthResult{Allowed: false, Reason: "no_capability"}
}

// --- Helper: build an engine-backed test setup ---

func newTestAuther(t *testing.T) *CapabilityEngine {
	t.Helper()
	buf := new(bytes.Buffer)
	audit := NewAuditLogger(buf)
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:    "peer-a-key-1234567890abcdef",
				Capabilities: []string{CapSSHProxy, CapFileTransfer},
			},
			{
				PublicKey:    "peer-b-key-abcdefghij123456",
				Capabilities: []string{CapMonitorRead},
			},
		},
	}
	return NewCapabilityEngine(cfg, audit)
}

// --- RequireCapability middleware tests ---

func TestRequireCapability_Allow(t *testing.T) {
	engine := newTestAuther(t)

	called := false
	handler := RequireCapability(engine, CapSSHProxy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/ssh/proxy", nil)
	req = req.WithContext(WithPeerID(req.Context(), "peer-a-key-1234567890abcdef"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected downstream handler to be called when capability is allowed")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestRequireCapability_DenyNoCapability(t *testing.T) {
	engine := newTestAuther(t)

	called := false
	handler := RequireCapability(engine, CapSSHProxy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	// peer-b has monitor_read but not ssh_proxy
	req := httptest.NewRequest(http.MethodGet, "/api/ssh/proxy", nil)
	req = req.WithContext(WithPeerID(req.Context(), "peer-b-key-abcdefghij123456"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if called {
		t.Error("expected downstream handler NOT to be called when capability is denied")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", rr.Code)
	}
}

func TestRequireCapability_DenyUnknownPeer(t *testing.T) {
	engine := newTestAuther(t)

	handler := RequireCapability(engine, CapSSHProxy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/api/ssh/proxy", nil)
	req = req.WithContext(WithPeerID(req.Context(), "unknown-peer-key"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for unknown peer, got %d", rr.Code)
	}
}

func TestRequireCapability_UnauthenticatedNoPeerID(t *testing.T) {
	engine := newTestAuther(t)

	called := false
	handler := RequireCapability(engine, CapSSHProxy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	// No peer ID in context — should get 401 Unauthorized
	req := httptest.NewRequest(http.MethodGet, "/api/ssh/proxy", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if called {
		t.Error("expected downstream handler NOT to be called when peer ID is missing")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized when no peer ID in context, got %d", rr.Code)
	}
}

func TestRequireCapability_NilEngine(t *testing.T) {
	handler := RequireCapability(nil, CapSSHProxy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/api/ssh/proxy", nil)
	req = req.WithContext(WithPeerID(req.Context(), "peer-a-key-1234567890abcdef"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error when engine is nil, got %d", rr.Code)
	}
}

func TestRequireCapability_RevokedPeer(t *testing.T) {
	engine := newTestAuther(t)

	// Revoke peer-a
	engine.Revoke("peer-a-key-1234567890abcdef", "revoker", "sig", "test")

	called := false
	handler := RequireCapability(engine, CapSSHProxy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/ssh/proxy", nil)
	req = req.WithContext(WithPeerID(req.Context(), "peer-a-key-1234567890abcdef"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if called {
		t.Error("expected handler NOT to be called for revoked peer")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for revoked peer, got %d", rr.Code)
	}
}

func TestRequireCapability_DifferentCapabilities(t *testing.T) {
	engine := newTestAuther(t)

	// peer-a has ssh_proxy and file_transfer but NOT monitor_read or service_manage
	tests := []struct {
		name   string
		cap    string
		peerID string
		status int
	}{
		{"ssh_proxy allowed", CapSSHProxy, "peer-a-key-1234567890abcdef", http.StatusOK},
		{"file_transfer allowed", CapFileTransfer, "peer-a-key-1234567890abcdef", http.StatusOK},
		{"monitor_read denied for peer-a", CapMonitorRead, "peer-a-key-1234567890abcdef", http.StatusForbidden},
		{"service_manage denied for peer-a", CapServiceManage, "peer-a-key-1234567890abcdef", http.StatusForbidden},
		{"monitor_read allowed for peer-b", CapMonitorRead, "peer-b-key-abcdefghij123456", http.StatusOK},
		{"ssh_proxy denied for peer-b", CapSSHProxy, "peer-b-key-abcdefghij123456", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := RequireCapability(engine, tt.cap)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req = req.WithContext(WithPeerID(req.Context(), tt.peerID))
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.status {
				t.Errorf("expected %d, got %d (body: %s)", tt.status, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestRequireCapability_StubAuther(t *testing.T) {
	// Verify the middleware works with a stub Auther (not just the real engine)
	stub := &stubAuther{
		results: map[string]AuthResult{
			"peer-1:" + CapSSHProxy: {Allowed: true, Reason: "explicit_allow"},
		},
	}

	handler := RequireCapability(stub, CapSSHProxy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Allowed — set RemoteAddr so we can verify it flows through
	req := httptest.NewRequest(http.MethodGet, "/api/ssh", nil)
	req.RemoteAddr = "192.168.1.5:34567"
	req = req.WithContext(WithPeerID(req.Context(), "peer-1"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for stub-allowed peer, got %d", rr.Code)
	}

	// Verify the stub was called with the right arguments
	if len(stub.calls) != 1 {
		t.Fatalf("expected 1 Authorize call, got %d", len(stub.calls))
	}
	call := stub.calls[0]
	if call.peerID != "peer-1" {
		t.Errorf("expected peerID 'peer-1', got %q", call.peerID)
	}
	if call.capability != CapSSHProxy {
		t.Errorf("expected capability %q, got %q", CapSSHProxy, call.capability)
	}
	if call.resource != "" {
		t.Errorf("expected empty resource, got %q", call.resource)
	}
	// Verify source IP from RemoteAddr was passed through
	if call.sourceIP != "192.168.1.5:34567" {
		t.Errorf("expected sourceIP '192.168.1.5:34567', got %q", call.sourceIP)
	}
}

// --- Context helper tests ---

func TestWithPeerIDAndPeerIDFromContext(t *testing.T) {
	ctx := context.Background()
	ctx = WithPeerID(ctx, "some-peer-key")

	peerID, ok := PeerIDFromContext(ctx)
	if !ok {
		t.Fatal("expected PeerIDFromContext to return ok=true")
	}
	if peerID != "some-peer-key" {
		t.Errorf("expected peerID 'some-peer-key', got %q", peerID)
	}
}

func TestPeerIDFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	_, ok := PeerIDFromContext(ctx)
	if ok {
		t.Error("expected PeerIDFromContext to return ok=false for empty context")
	}
}

func TestPeerIDFromContext_EmptyString(t *testing.T) {
	ctx := WithPeerID(context.Background(), "")
	_, ok := PeerIDFromContext(ctx)
	if ok {
		t.Error("expected PeerIDFromContext to return ok=false for empty string peer ID")
	}
}

func TestPeerIDFromContext_WrongType(t *testing.T) {
	// A context value of the wrong type should not panic and return false
	ctx := context.WithValue(context.Background(), ctxPeerIDKey{}, 12345)
	_, ok := PeerIDFromContext(ctx)
	if ok {
		t.Error("expected PeerIDFromContext to return ok=false for non-string value")
	}
}
