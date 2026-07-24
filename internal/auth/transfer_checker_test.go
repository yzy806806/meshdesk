package auth

import (
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

// --- Gap 2: TransferAuthChecker tests ---

func newTransferTestEngine(t *testing.T) *CapabilityEngine {
	t.Helper()
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:    "transfer-authorized-peer",
				Capabilities: []string{CapFileTransfer},
			},
			{
				PublicKey:    "transfer-unauthorized-peer",
				Capabilities: []string{CapMonitorRead}, // no file_transfer
			},
		},
	}
	return NewCapabilityEngine(cfg, NewAuditLogger(nil))
}

func TestTransferAuthCheckerAuthorized(t *testing.T) {
	engine := newTransferTestEngine(t)
	checker := NewTransferAuthChecker(engine)

	if !checker.AuthorizeFileTransfer("transfer-authorized-peer") {
		t.Error("expected authorized peer to be allowed")
	}
}

func TestTransferAuthCheckerUnauthorized(t *testing.T) {
	engine := newTransferTestEngine(t)
	checker := NewTransferAuthChecker(engine)

	if checker.AuthorizeFileTransfer("transfer-unauthorized-peer") {
		t.Error("expected unauthorized peer to be denied")
	}
}

func TestTransferAuthCheckerUnknownPeer(t *testing.T) {
	engine := newTransferTestEngine(t)
	checker := NewTransferAuthChecker(engine)

	if checker.AuthorizeFileTransfer("unknown-peer") {
		t.Error("expected unknown peer to be denied (zero-trust)")
	}
}

func TestTransferAuthCheckerNilEngine(t *testing.T) {
	checker := NewTransferAuthChecker(nil)

	// Should fail-closed when engine is nil
	if checker.AuthorizeFileTransfer("any-peer") {
		t.Error("expected nil engine to deny all transfers (fail-closed)")
	}
}

func TestTransferAuthCheckerRevokedPeer(t *testing.T) {
	engine := newTransferTestEngine(t)
	checker := NewTransferAuthChecker(engine)

	// Revoke the authorized peer
	engine.Revoke("transfer-authorized-peer", "revoker", "sig", "test")

	if checker.AuthorizeFileTransfer("transfer-authorized-peer") {
		t.Error("expected revoked peer to be denied")
	}
}
