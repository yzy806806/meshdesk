package mesh

import (
	"testing"
)

func TestRoutingTableAddRemovePeer(t *testing.T) {
	rt := NewRoutingTable()

	peer1 := &PeerEntry{
		ID:         "aaaa1111",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.10.1.1/32"},
	}
	peer2 := &PeerEntry{
		ID:         "bbbb2222",
		Endpoint:   "5.6.7.8:51820",
		AllowedIPs: []string{"10.10.2.2/32"},
	}

	rt.AddPeer(peer1)
	rt.AddPeer(peer2)

	if rt.PeerCount() != 2 {
		t.Errorf("PeerCount() = %d, want 2", rt.PeerCount())
	}

	// Test route resolution.
	pid, ok := rt.ResolveRoute("10.10.1.1/32")
	if !ok {
		t.Error("ResolveRoute failed for peer1")
	}
	if pid != "aaaa1111" {
		t.Errorf("ResolveRoute = %q, want %q", pid, "aaaa1111")
	}

	pid, ok = rt.ResolveRoute("10.10.2.2/32")
	if !ok {
		t.Error("ResolveRoute failed for peer2")
	}
	if pid != "bbbb2222" {
		t.Errorf("ResolveRoute = %q, want %q", pid, "bbbb2222")
	}

	// Test GetPeer.
	p, ok := rt.GetPeer("aaaa1111")
	if !ok {
		t.Error("GetPeer failed")
	}
	if p.Endpoint != "1.2.3.4:51820" {
		t.Errorf("GetPeer endpoint = %q, want %q", p.Endpoint, "1.2.3.4:51820")
	}

	// Test RemovePeer.
	rt.RemovePeer("aaaa1111")
	if rt.PeerCount() != 1 {
		t.Errorf("After removal, PeerCount() = %d, want 1", rt.PeerCount())
	}
	_, ok = rt.ResolveRoute("10.10.1.1/32")
	if ok {
		t.Error("Route for removed peer should not exist")
	}
}

func TestRoutingTableUpdatePeer(t *testing.T) {
	rt := NewRoutingTable()

	peer1 := &PeerEntry{
		ID:         "aaaa1111",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.10.1.1/32"},
	}
	rt.AddPeer(peer1)

	// Update the same peer with different IPs.
	updated := &PeerEntry{
		ID:         "aaaa1111",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.10.3.3/32"},
	}
	rt.AddPeer(updated)

	// Old IP should be gone.
	_, ok := rt.ResolveRoute("10.10.1.1/32")
	if ok {
		t.Error("Old route should be removed after update")
	}
	// New IP should exist.
	pid, ok := rt.ResolveRoute("10.10.3.3/32")
	if !ok {
		t.Error("New route should exist after update")
	}
	if pid != "aaaa1111" {
		t.Errorf("ResolveRoute = %q, want %q", pid, "aaaa1111")
	}
}

func TestRoutingTableResolvePeerByIP(t *testing.T) {
	rt := NewRoutingTable()
	peer1 := &PeerEntry{
		ID:         "aaaa1111",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.10.1.1/32"},
		Obfuscation: ObfuscationPadded,
	}
	rt.AddPeer(peer1)

	p, ok := rt.ResolvePeerByIP("10.10.1.1/32")
	if !ok {
		t.Fatal("ResolvePeerByIP failed")
	}
	if p.Obfuscation != ObfuscationPadded {
		t.Errorf("Obfuscation = %v, want %v", p.Obfuscation, ObfuscationPadded)
	}
}

func TestRoutingTableNonexistentPeer(t *testing.T) {
	rt := NewRoutingTable()
	_, ok := rt.GetPeer("nonexistent")
	if ok {
		t.Error("GetPeer should return false for nonexistent peer")
	}
	_, ok = rt.ResolveRoute("10.99.99.99/32")
	if ok {
		t.Error("ResolveRoute should return false for unknown IP")
	}
}

func TestRoutingTableAllPeers(t *testing.T) {
	rt := NewRoutingTable()
	for i := 0; i < 5; i++ {
		rt.AddPeer(&PeerEntry{
			ID:         "peer" + string(rune('0'+i)),
			Endpoint:   "1.2.3.4:51820",
			AllowedIPs: []string{"10.10.0." + string(rune('0'+i)) + "/32"},
		})
	}
	peers := rt.AllPeers()
	if len(peers) != 5 {
		t.Errorf("AllPeers() length = %d, want 5", len(peers))
	}
}

func TestIsIPInPrefix(t *testing.T) {
	tests := []struct {
		ip     string
		prefix string
		want   bool
	}{
		{"10.10.0.1", "10.10.0.0/24", true},
		{"10.10.1.1", "10.10.0.0/24", false},
		{"10.10.0.255", "10.10.0.0/24", true},
		{"192.168.1.1", "192.168.0.0/16", true},
		{"172.16.0.1", "192.168.0.0/16", false},
	}
	for _, tt := range tests {
		got, err := IsIPInPrefix(tt.ip, tt.prefix)
		if err != nil {
			t.Errorf("IsIPInPrefix(%q, %q) error: %v", tt.ip, tt.prefix, err)
			continue
		}
		if got != tt.want {
			t.Errorf("IsIPInPrefix(%q, %q) = %v, want %v", tt.ip, tt.prefix, got, tt.want)
		}
	}
}
