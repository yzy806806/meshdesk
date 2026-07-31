package auth

import (
	"strings"
	"testing"
)

// TestMeshIdentityAuthCheckerSelfPush verifies that the local node
// is always authorized to push its own metrics.
func TestMeshIdentityAuthCheckerSelfPush(t *testing.T) {
	checker := NewMeshIdentityAuthChecker(
		"my-pubkey",
		func(peerID string) bool { return false }, // routing table lookup fails
		nil,
	)

	if !checker.AuthorizeMonitorWrite("my-pubkey") {
		t.Error("self-push should always be allowed")
	}
}

// TestMeshIdentityAuthCheckerKnownPeer verifies that a peer present
// in the routing table is authorized.
func TestMeshIdentityAuthCheckerKnownPeer(t *testing.T) {
	knownPeers := map[string]bool{
		"peer-abc": true,
		"peer-xyz": true,
	}

	checker := NewMeshIdentityAuthChecker(
		"my-pubkey",
		func(peerID string) bool { return knownPeers[peerID] },
		nil,
	)

	if !checker.AuthorizeMonitorWrite("peer-abc") {
		t.Error("known mesh peer should be authorized")
	}
}

// TestMeshIdentityAuthCheckerUnknownPeer verifies that a peer NOT in
// the routing table is rejected.
func TestMeshIdentityAuthCheckerUnknownPeer(t *testing.T) {
	checker := NewMeshIdentityAuthChecker(
		"my-pubkey",
		func(peerID string) bool { return false },
		nil,
	)

	if checker.AuthorizeMonitorWrite("unknown-peer") {
		t.Error("unknown peer should be rejected")
	}
}

// TestMeshIdentityAuthCheckerEmptyPeerID verifies that an empty
// source peer ID is rejected (fail-closed).
func TestMeshIdentityAuthCheckerEmptyPeerID(t *testing.T) {
	checker := NewMeshIdentityAuthChecker(
		"my-pubkey",
		func(peerID string) bool { return true }, // would allow all
		nil,
	)

	if checker.AuthorizeMonitorWrite("") {
		t.Error("empty peer ID should be rejected")
	}
}

// TestMeshIdentityAuthCheckerNilIsKnownPeer verifies that a nil
// isKnownPeer function causes all non-self pushes to be rejected
// (fail-closed).
func TestMeshIdentityAuthCheckerNilIsKnownPeer(t *testing.T) {
	checker := NewMeshIdentityAuthChecker(
		"my-pubkey",
		nil,
		nil,
	)

	// Self should still pass.
	if !checker.AuthorizeMonitorWrite("my-pubkey") {
		t.Error("self-push should be allowed even with nil isKnownPeer")
	}

	// Other peers should be rejected.
	if checker.AuthorizeMonitorWrite("peer-abc") {
		t.Error("non-self push should be rejected when isKnownPeer is nil")
	}
}

// TestMeshIdentityAuthCheckerAuditLog verifies that audit entries
// are produced for both allowed and denied checks.
func TestMeshIdentityAuthCheckerAuditLog(t *testing.T) {
	auditBuf := &strings.Builder{}
	auditLogger := NewAuditLogger(auditBuf)

	knownPeers := map[string]bool{"peer-ok": true}
	checker := NewMeshIdentityAuthChecker(
		"my-pubkey",
		func(peerID string) bool { return knownPeers[peerID] },
		auditLogger,
	)

	// Allowed: self
	checker.AuthorizeMonitorWrite("my-pubkey")
	// Allowed: known peer
	checker.AuthorizeMonitorWrite("peer-ok")
	// Denied: unknown peer
	checker.AuthorizeMonitorWrite("peer-bad")

	output := auditBuf.String()
	if !strings.Contains(output, "my-pubkey") {
		t.Error("audit log should contain self-push entry")
	}
	if !strings.Contains(output, "peer-ok") {
		t.Error("audit log should contain known peer entry")
	}
	if !strings.Contains(output, "peer-bad") {
		t.Error("audit log should contain unknown peer entry")
	}
	if !strings.Contains(output, "allow") {
		t.Error("audit log should contain 'allow' result")
	}
	if !strings.Contains(output, "deny") {
		t.Error("audit log should contain 'deny' result")
	}
	if !strings.Contains(output, "unknown_peer") {
		t.Error("audit log should contain 'unknown_peer' reason for denied push")
	}
}

// TestMeshIdentityAuthCheckerImplementsInterface is a compile-time
// check that MeshIdentityAuthChecker satisfies monitor.AuthChecker.
func TestMeshIdentityAuthCheckerImplementsInterface(t *testing.T) {
	var _ interface {
		AuthorizeMonitorWrite(sourcePeer string) bool
	} = (*MeshIdentityAuthChecker)(nil)
}
