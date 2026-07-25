package auth

import (
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

// TestSetDenyCallback verifies that the deny callback is invoked on
// Authorize denials and not invoked on allow.
func TestSetDenyCallback(t *testing.T) {
	audit := NewAuditLogger(nil) // nil writer → no-op logger
	cfg := config.Default()

	// Add a peer with ssh_proxy capability.
	cfg.Peers = []config.PeerConfig{{
		PublicKey:    "peer-abc-123",
		Endpoint:     "1.2.3.4:51820",
		AllowedIPs:   []string{"10.10.1.2/32"},
		Capabilities: []string{CapSSHProxy},
	}}

	engine := NewCapabilityEngine(cfg, audit)

	var denied []AuthResult
	engine.SetDenyCallback(func(result AuthResult) {
		denied = append(denied, result)
	})

	// Allowed: ssh_proxy capability is present → no callback.
	result := engine.Authorize("peer-abc-123", CapSSHProxy, "")
	if !result.Allowed {
		t.Error("expected allow for ssh_proxy")
	}
	if len(denied) != 0 {
		t.Errorf("deny callback should not fire on allow, got %d calls", len(denied))
	}

	// Denied: file_transfer capability is not present → callback fires.
	result = engine.Authorize("peer-abc-123", CapFileTransfer, "/tmp")
	if result.Allowed {
		t.Error("expected deny for file_transfer")
	}
	if len(denied) != 1 {
		t.Fatalf("expected 1 denial, got %d", len(denied))
	}
	if denied[0].Reason != "no_capability" {
		t.Errorf("expected reason 'no_capability', got '%s'", denied[0].Reason)
	}
	if denied[0].Capability != CapFileTransfer {
		t.Errorf("expected capability '%s', got '%s'", CapFileTransfer, denied[0].Capability)
	}
}

// TestDenyCallback_UnknownPeer verifies the callback fires for peers
// with no grant at all.
func TestDenyCallback_UnknownPeer(t *testing.T) {
	audit := NewAuditLogger(nil)
	cfg := config.Default()
	engine := NewCapabilityEngine(cfg, audit)

	var denied int
	engine.SetDenyCallback(func(result AuthResult) {
		denied++
	})

	result := engine.Authorize("unknown-peer", CapSSHProxy, "")
	if result.Allowed {
		t.Error("expected deny for unknown peer")
	}
	if result.Reason != "no_capability" {
		t.Errorf("expected 'no_capability', got '%s'", result.Reason)
	}
	if denied != 1 {
		t.Errorf("expected 1 denial, got %d", denied)
	}
}

// TestDenyCallback_RevokedPeer verifies the callback fires with
// reason="revoked" for revoked peers.
func TestDenyCallback_RevokedPeer(t *testing.T) {
	audit := NewAuditLogger(nil)
	cfg := config.Default()
	cfg.Peers = []config.PeerConfig{{
		PublicKey:    "peer-revoked",
		Capabilities: []string{CapSSHProxy},
	}}

	engine := NewCapabilityEngine(cfg, audit)
	engine.Revoke("peer-revoked", "revoker", "sig", "compromised")

	var denied []AuthResult
	engine.SetDenyCallback(func(result AuthResult) {
		denied = append(denied, result)
	})

	result := engine.Authorize("peer-revoked", CapSSHProxy, "")
	if result.Allowed {
		t.Error("expected deny for revoked peer")
	}
	if result.Reason != "revoked" {
		t.Errorf("expected 'revoked', got '%s'", result.Reason)
	}
	if len(denied) != 1 {
		t.Errorf("expected 1 denial, got %d", len(denied))
	}
	if denied[0].Reason != "revoked" {
		t.Errorf("callback received reason '%s', expected 'revoked'", denied[0].Reason)
	}
}

// TestDenyCallback_NilDoesNotPanic verifies that no callback is
// safe (no panic).
func TestDenyCallback_NilDoesNotPanic(t *testing.T) {
	audit := NewAuditLogger(nil)
	cfg := config.Default()
	engine := NewCapabilityEngine(cfg, audit)

	// No SetDenyCallback → should not panic on deny.
	_ = engine.Authorize("unknown", CapSSHProxy, "")
}

// TestDenyCallback_AuthorizeWithSourceIP verifies the callback fires
// with the source IP recorded.
func TestDenyCallback_AuthorizeWithSourceIP(t *testing.T) {
	audit := NewAuditLogger(nil)
	cfg := config.Default()
	engine := NewCapabilityEngine(cfg, audit)

	var sourceIP string
	engine.SetDenyCallback(func(result AuthResult) {
		sourceIP = result.SourceIP
	})

	engine.AuthorizeWithSourceIP("unknown", CapSSHProxy, "", "192.168.1.50:12345")
	if sourceIP != "192.168.1.50:12345" {
		t.Errorf("expected source IP '192.168.1.50:12345', got '%s'", sourceIP)
	}
}
