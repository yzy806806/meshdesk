package p2p

import (
	"testing"
)

// TestResolveAdvertiseAddrPrefersIPv4 tests that resolveAdvertiseAddr selects
// the first IPv4 endpoint from AdvertiseEndpoints when multiple endpoints
// (including IPv6) are configured. hashicorp memberlist's TCP layer is
// IPv4-native, so we must prefer IPv4 for AdvertiseAddr.
func TestResolveAdvertiseAddrPrefersIPv4(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)

	// IPv6 listed first, IPv4 second — should still pick the IPv4 one.
	gl := &GossipLayer{
		cfg: P2pConfig{
			AdvertiseEndpoints: []string{"[2001:db8::1]:51820", "203.0.113.99:51820"},
		},
		delegate: delegate,
	}

	addr := gl.resolveAdvertiseAddr()
	if addr != "203.0.113.99" {
		t.Errorf("expected IPv4 addr 203.0.113.99, got %s", addr)
	}
}

// TestResolveAdvertiseAddrIPv4Only tests that when only IPv4 endpoints exist,
// the first one is selected.
func TestResolveAdvertiseAddrIPv4Only(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg: P2pConfig{
			AdvertiseEndpoints: []string{"192.168.1.5:51820", "10.0.0.1:51820"},
		},
		delegate: delegate,
	}

	addr := gl.resolveAdvertiseAddr()
	if addr != "192.168.1.5" {
		t.Errorf("expected 192.168.1.5, got %s", addr)
	}
}

// TestResolveAdvertiseAddrIPv6Only tests that when only IPv6 endpoints exist,
// the first IPv6 endpoint is used as fallback (no IPv4 available).
func TestResolveAdvertiseAddrIPv6Only(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg: P2pConfig{
			AdvertiseEndpoints: []string{"[2001:db8::1]:51820", "[2001:db8::2]:51820"},
		},
		delegate: delegate,
	}

	addr := gl.resolveAdvertiseAddr()
	if addr != "2001:db8::1" {
		t.Errorf("expected 2001:db8::1 (no IPv4, fallback to first), got %s", addr)
	}
}

// TestResolveAdvertiseAddrFallsBackToLocalMeta tests that when
// AdvertiseEndpoints is empty, the function falls back to localMeta.Endpoints,
// preferring IPv4 there as well.
func TestResolveAdvertiseAddrFallsBackToLocalMeta(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		Endpoints: []string{"[fe80::1]:51820", "10.0.0.5:51820"},
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg:       P2pConfig{},
		delegate:  delegate,
		localMeta: localMeta,
	}

	addr := gl.resolveAdvertiseAddr()
	if addr != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5 from localMeta (IPv4 preferred), got %s", addr)
	}
}

// TestResolveAdvertiseAddrEmpty tests that when no endpoints are configured
// anywhere, the function returns the auto-detected outbound IP or empty string.
func TestResolveAdvertiseAddrEmpty(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg:       P2pConfig{},
		delegate:  delegate,
		localMeta: localMeta,
	}

	// We can't predict the exact IP, but it should not panic.
	// On CI without network, it may return "".
	_ = gl.resolveAdvertiseAddr()
}

// TestFirstIPv4HostFromEndpoints tests the helper directly.
func TestFirstIPv4HostFromEndpoints(t *testing.T) {
	tests := []struct {
		name      string
		endpoints []string
		want      string
	}{
		{"empty", nil, ""},
		{"single IPv4", []string{"1.2.3.4:80"}, "1.2.3.4"},
		{"single IPv6", []string{"[::1]:80"}, ""},
		{"IPv6 then IPv4", []string{"[::1]:80", "1.2.3.4:80"}, "1.2.3.4"},
		{"IPv4 then IPv6", []string{"1.2.3.4:80", "[::1]:80"}, "1.2.3.4"},
		{"all IPv6", []string{"[::1]:80", "[fe80::1]:80"}, ""},
		{"with empty strings", []string{"", "1.2.3.4:80"}, "1.2.3.4"},
		{"invalid endpoint", []string{"garbage", "1.2.3.4:80"}, "1.2.3.4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstIPv4HostFromEndpoints(tt.endpoints)
			if got != tt.want {
				t.Errorf("firstIPv4HostFromEndpoints(%v) = %q, want %q", tt.endpoints, got, tt.want)
			}
		})
	}
}
