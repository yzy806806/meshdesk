package auth

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

// --- WebSSHAuthChecker tests ---

func newWebSSHTestEngine(t *testing.T) *CapabilityEngine {
	t.Helper()
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:    "ssh-authorized-peer",
				Capabilities: []string{CapSSHProxy},
			},
			{
				PublicKey:    "ssh-unauthorized-peer",
				Capabilities: []string{CapMonitorRead}, // no ssh_proxy
			},
		},
	}
	return NewCapabilityEngine(cfg, NewAuditLogger(nil))
}

func TestWebSSHAuthCheckerAuthorized(t *testing.T) {
	engine := newWebSSHTestEngine(t)
	checker := NewWebSSHAuthChecker(engine)

	if !checker.AuthorizeSSH("ssh-authorized-peer") {
		t.Error("expected authorized peer to be allowed")
	}
}

func TestWebSSHAuthCheckerUnauthorized(t *testing.T) {
	engine := newWebSSHTestEngine(t)
	checker := NewWebSSHAuthChecker(engine)

	if checker.AuthorizeSSH("ssh-unauthorized-peer") {
		t.Error("expected unauthorized peer to be denied")
	}
}

func TestWebSSHAuthCheckerUnknownPeer(t *testing.T) {
	engine := newWebSSHTestEngine(t)
	checker := NewWebSSHAuthChecker(engine)

	if checker.AuthorizeSSH("unknown-peer") {
		t.Error("expected unknown peer to be denied (zero-trust)")
	}
}

func TestWebSSHAuthCheckerNilEngine(t *testing.T) {
	checker := NewWebSSHAuthChecker(nil)

	if checker.AuthorizeSSH("any-peer") {
		t.Error("expected nil engine to deny all (fail-closed)")
	}
}

func TestWebSSHAuthCheckerRevokedPeer(t *testing.T) {
	engine := newWebSSHTestEngine(t)
	checker := NewWebSSHAuthChecker(engine)

	engine.Revoke("ssh-authorized-peer", "revoker", "sig", "test")

	if checker.AuthorizeSSH("ssh-authorized-peer") {
		t.Error("expected revoked peer to be denied")
	}
}

func TestWebSSHAuthCheckerAuditLog(t *testing.T) {
	var buf bytes.Buffer
	engine := NewCapabilityEngine(
		&config.Config{
			Peers: []config.PeerConfig{
				{PublicKey: "ssh-audit-peer", Capabilities: []string{CapSSHProxy}},
			},
		},
		NewAuditLogger(&buf),
	)
	checker := NewWebSSHAuthChecker(engine)

	checker.AuthorizeSSH("ssh-audit-peer")
	checker.AuthorizeSSH("unknown-peer")

	// Parse the audit log output — should have 2 entries
	lines := bytes.Split(buf.Bytes(), []byte("\n"))
	var entries []AuditEntry
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("failed to parse audit entry: %v", err)
		}
		entries = append(entries, entry)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(entries))
	}

	// First entry: authorized peer → allow
	if entries[0].SourcePeer != "ssh-audit-peer" {
		t.Errorf("entry 0 SourcePeer = %s, want ssh-audit-peer", entries[0].SourcePeer)
	}
	if entries[0].RequestedCapability != CapSSHProxy {
		t.Errorf("entry 0 Capability = %s, want %s", entries[0].RequestedCapability, CapSSHProxy)
	}
	if entries[0].Result != "allow" {
		t.Errorf("entry 0 Result = %s, want allow", entries[0].Result)
	}

	// Second entry: unknown peer → deny
	if entries[1].SourcePeer != "unknown-peer" {
		t.Errorf("entry 1 SourcePeer = %s, want unknown-peer", entries[1].SourcePeer)
	}
	if entries[1].Result != "deny" {
		t.Errorf("entry 1 Result = %s, want deny", entries[1].Result)
	}
}

// --- MonitorAuthChecker tests ---

func newMonitorTestEngine(t *testing.T) *CapabilityEngine {
	t.Helper()
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:    "monitor-authorized-peer",
				Capabilities: []string{CapMonitorWrite},
			},
			{
				PublicKey:    "monitor-unauthorized-peer",
				Capabilities: []string{CapMonitorRead}, // no monitor_write
			},
		},
	}
	return NewCapabilityEngine(cfg, NewAuditLogger(nil))
}

func TestMonitorAuthCheckerAuthorized(t *testing.T) {
	engine := newMonitorTestEngine(t)
	checker := NewMonitorAuthChecker(engine)

	if !checker.AuthorizeMonitorWrite("monitor-authorized-peer") {
		t.Error("expected authorized peer to be allowed")
	}
}

func TestMonitorAuthCheckerUnauthorized(t *testing.T) {
	engine := newMonitorTestEngine(t)
	checker := NewMonitorAuthChecker(engine)

	if checker.AuthorizeMonitorWrite("monitor-unauthorized-peer") {
		t.Error("expected unauthorized peer to be denied")
	}
}

func TestMonitorAuthCheckerUnknownPeer(t *testing.T) {
	engine := newMonitorTestEngine(t)
	checker := NewMonitorAuthChecker(engine)

	if checker.AuthorizeMonitorWrite("unknown-peer") {
		t.Error("expected unknown peer to be denied (zero-trust)")
	}
}

func TestMonitorAuthCheckerNilEngine(t *testing.T) {
	checker := NewMonitorAuthChecker(nil)

	if checker.AuthorizeMonitorWrite("any-peer") {
		t.Error("expected nil engine to deny all (fail-closed)")
	}
}

func TestMonitorAuthCheckerRevokedPeer(t *testing.T) {
	engine := newMonitorTestEngine(t)
	checker := NewMonitorAuthChecker(engine)

	engine.Revoke("monitor-authorized-peer", "revoker", "sig", "test")

	if checker.AuthorizeMonitorWrite("monitor-authorized-peer") {
		t.Error("expected revoked peer to be denied")
	}
}

func TestMonitorAuthCheckerAuditLog(t *testing.T) {
	var buf bytes.Buffer
	engine := NewCapabilityEngine(
		&config.Config{
			Peers: []config.PeerConfig{
				{PublicKey: "monitor-audit-peer", Capabilities: []string{CapMonitorWrite}},
			},
		},
		NewAuditLogger(&buf),
	)
	checker := NewMonitorAuthChecker(engine)

	checker.AuthorizeMonitorWrite("monitor-audit-peer")
	checker.AuthorizeMonitorWrite("unknown-peer")

	// Parse the audit log output — should have 2 entries
	lines := bytes.Split(buf.Bytes(), []byte("\n"))
	var entries []AuditEntry
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("failed to parse audit entry: %v", err)
		}
		entries = append(entries, entry)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(entries))
	}

	// First entry: authorized peer → allow
	if entries[0].SourcePeer != "monitor-audit-peer" {
		t.Errorf("entry 0 SourcePeer = %s, want monitor-audit-peer", entries[0].SourcePeer)
	}
	if entries[0].RequestedCapability != CapMonitorWrite {
		t.Errorf("entry 0 Capability = %s, want %s", entries[0].RequestedCapability, CapMonitorWrite)
	}
	if entries[0].Result != "allow" {
		t.Errorf("entry 0 Result = %s, want allow", entries[0].Result)
	}

	// Second entry: unknown peer → deny
	if entries[1].SourcePeer != "unknown-peer" {
		t.Errorf("entry 1 SourcePeer = %s, want unknown-peer", entries[1].SourcePeer)
	}
	if entries[1].Result != "deny" {
		t.Errorf("entry 1 Result = %s, want deny", entries[1].Result)
	}
}
