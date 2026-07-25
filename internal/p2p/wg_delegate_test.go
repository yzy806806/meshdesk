package p2p

import (
	"testing"
	"time"
)

func TestDeriveMeshIPFromHex(t *testing.T) {
	// Test with a known key.
	// pubKeyHex = "abcdef0123456789..."
	// bytes 0-1: 0xab, 0xcd
	// b0 = 0xab % 254 + 1 = 171 % 254 + 1 = 172
	// b1 = 0xcd % 254 + 1 = 205 % 254 + 1 = 206
	// mesh IP = "10.10.172.206"
	ip := DeriveMeshIPFromHex("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	expected := "10.10.172.206"
	if ip != expected {
		t.Errorf("DeriveMeshIPFromHex: got %s, want %s", ip, expected)
	}
}

func TestDeriveMeshIPFromHexShortKey(t *testing.T) {
	// Short key should return default.
	ip := DeriveMeshIPFromHex("ab")
	if ip != "10.10.0.1" {
		t.Errorf("DeriveMeshIPFromHex with short key: got %s, want 10.10.0.1", ip)
	}
}

func TestMeshIPToCIDR(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"10.10.0.1", "10.10.0.1/32"},
		{"10.10.0.1/32", "10.10.0.1/32"},
		{"10.10.5.20", "10.10.5.20/32"},
		{"  10.10.0.1  ", "10.10.0.1/32"}, // trimmed
	}

	for _, tt := range tests {
		got := MeshIPToCIDR(tt.input)
		if got != tt.want {
			t.Errorf("MeshIPToCIDR(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestWireGuardDelegateStaticPeer(t *testing.T) {
	wg := &WireGuardDelegate{
		health:     make(map[string]*PeerHealth),
		staticKeys: make(map[string]bool),
	}

	key := "statickey0000000000000000000000000000000000000000000000000000000"
	wg.MarkStaticPeer(key)

	if !wg.IsStaticPeer(key) {
		t.Error("IsStaticPeer should return true for marked static peer")
	}

	if wg.IsStaticPeer("nonexistentkey00000000000000000000000000000000000000000000000") {
		t.Error("IsStaticPeer should return false for unmarked key")
	}
}

func TestPeerHealthTracking(t *testing.T) {
	wg := &WireGuardDelegate{
		health:     make(map[string]*PeerHealth),
		staticKeys: make(map[string]bool),
	}

	key := "peerkey0000000000000000000000000000000000000000000000000000000"

	// Simulate adding a peer health record.
	wg.mu.Lock()
	wg.health[key] = &PeerHealth{
		PublicKey:  key,
		Endpoint:   "203.0.113.5:51820",
		AddedAt:    time.Now(),
	}
	wg.mu.Unlock()

	// IsHealthy should return true for recently added peer.
	if !wg.IsHealthy(key) {
		t.Error("IsHealthy should return true for recently added peer")
	}

	// Simulate old addition time.
	wg.mu.Lock()
	wg.health[key].AddedAt = time.Now().Add(-5 * time.Minute)
	wg.mu.Unlock()

	// IsHealthy should return false for peer added 5 minutes ago with no handshake.
	if wg.IsHealthy(key) {
		t.Error("IsHealthy should return false for peer added 5 minutes ago with no handshake")
	}
}

func TestPeerHealthHandshakeTracking(t *testing.T) {
	wg := &WireGuardDelegate{
		health:     make(map[string]*PeerHealth),
		staticKeys: make(map[string]bool),
	}

	key := "peerkey0000000000000000000000000000000000000000000000000000000"

	wg.mu.Lock()
	wg.health[key] = &PeerHealth{
		PublicKey:  key,
		AddedAt:    time.Now().Add(-10 * time.Minute), // old
	}
	wg.mu.Unlock()

	// Not healthy (old addition, no handshake).
	if wg.IsHealthy(key) {
		t.Error("IsHealthy should return false for old peer with no handshake")
	}

	// Update handshake time.
	wg.UpdateHandshakeTime(key)

	// Now should be healthy.
	if !wg.IsHealthy(key) {
		t.Error("IsHealthy should return true after handshake update")
	}

	// Simulate old handshake.
	wg.mu.Lock()
	wg.health[key].LastHandshake = time.Now().Add(-5 * time.Minute)
	wg.mu.Unlock()

	if wg.IsHealthy(key) {
		t.Error("IsHealthy should return false for peer with handshake 5 minutes ago")
	}
}

func TestWireGuardDelegateUnknownPeer(t *testing.T) {
	wg := &WireGuardDelegate{
		health:     make(map[string]*PeerHealth),
		staticKeys: make(map[string]bool),
	}

	// IsHealthy for unknown peer.
	if wg.IsHealthy("unknownkey0000000000000000000000000000000000000000000000000000") {
		t.Error("IsHealthy should return false for unknown peer")
	}

	// GetPeerHealth for unknown peer.
	if wg.GetPeerHealth("unknownkey0000000000000000000000000000000000000000000000000000") != nil {
		t.Error("GetPeerHealth should return nil for unknown peer")
	}

	// AllDynamicPeers should be empty.
	if len(wg.AllDynamicPeers()) != 0 {
		t.Error("AllDynamicPeers should be empty")
	}

	// DynamicPeerCount should be 0.
	if wg.DynamicPeerCount() != 0 {
		t.Error("DynamicPeerCount should be 0")
	}
}

func TestWireGuardDelegateRemoveDynamicPeerIdempotent(t *testing.T) {
	wg := &WireGuardDelegate{
		health:     make(map[string]*PeerHealth),
		staticKeys: make(map[string]bool),
	}

	// RemoveDynamicPeer for a non-existent peer should not error.
	// (It returns nil because the peer is not in the health map.)
	err := wg.RemoveDynamicPeer("nonexistent00000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Errorf("RemoveDynamicPeer for non-existent peer should not error: %v", err)
	}
}
