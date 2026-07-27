package mesh

import (
	"testing"
	"time"
)

// TestIsPeerHandshaked_NilInfo verifies that nil info returns false.
func TestIsPeerHandshaked_NilInfo(t *testing.T) {
	if isPeerHandshaked(nil, 2*time.Minute) {
		t.Error("expected false for nil info")
	}
}

// TestIsPeerHandshaked_NeverHandshaked verifies that a zero handshake
// time (never handshaked) returns false.
func TestIsPeerHandshaked_NeverHandshaked(t *testing.T) {
	info := &PeerHandshakeInfo{LastHandshakeNano: 0}
	if isPeerHandshaked(info, 2*time.Minute) {
		t.Error("expected false for never-handshaked peer")
	}
}

// TestIsPeerHandshaked_Recent verifies that a recent handshake returns true.
func TestIsPeerHandshaked_Recent(t *testing.T) {
	info := &PeerHandshakeInfo{
		LastHandshakeNano: time.Now().Add(-30 * time.Second).UnixNano(),
		LastHandshakeTime: time.Now().Add(-30 * time.Second),
	}
	if !isPeerHandshaked(info, 2*time.Minute) {
		t.Error("expected true for recent handshake")
	}
}

// TestIsPeerHandshaked_Stale verifies that a stale handshake returns false.
func TestIsPeerHandshaked_Stale(t *testing.T) {
	info := &PeerHandshakeInfo{
		LastHandshakeNano: time.Now().Add(-5 * time.Minute).UnixNano(),
		LastHandshakeTime: time.Now().Add(-5 * time.Minute),
	}
	if isPeerHandshaked(info, 2*time.Minute) {
		t.Error("expected false for stale handshake")
	}
}
