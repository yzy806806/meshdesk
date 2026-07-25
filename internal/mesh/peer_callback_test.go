package mesh

import (
	"testing"
)

// TestPeerJoinCallback verifies that the join callback fires when
// a genuinely new peer is added, and does NOT fire on peer updates.
func TestPeerJoinCallback(t *testing.T) {
	rt := NewRoutingTable()

	var joined []*PeerEntry
	rt.SetJoinCallback(func(peer *PeerEntry) {
		joined = append(joined, peer)
	})

	// Add a new peer → callback fires.
	peer1 := &PeerEntry{
		ID:         "peer-aaa",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.10.1.2/32"},
	}
	rt.AddPeer(peer1)
	if len(joined) != 1 {
		t.Fatalf("expected 1 join, got %d", len(joined))
	}
	if joined[0].ID != "peer-aaa" {
		t.Errorf("expected join for peer-aaa, got %s", joined[0].ID)
	}

	// Update the same peer (different endpoint) → callback should NOT fire.
	peer1Updated := &PeerEntry{
		ID:         "peer-aaa",
		Endpoint:   "5.6.7.8:51820",
		AllowedIPs: []string{"10.10.1.2/32"},
	}
	rt.AddPeer(peer1Updated)
	if len(joined) != 1 {
		t.Errorf("join callback should not fire on update, got %d total", len(joined))
	}

	// Add a second new peer → callback fires.
	peer2 := &PeerEntry{
		ID:         "peer-bbb",
		Endpoint:   "9.10.11.12:51820",
		AllowedIPs: []string{"10.10.2.2/32"},
	}
	rt.AddPeer(peer2)
	if len(joined) != 2 {
		t.Fatalf("expected 2 joins, got %d", len(joined))
	}
	if joined[1].ID != "peer-bbb" {
		t.Errorf("expected join for peer-bbb, got %s", joined[1].ID)
	}
}

// TestPeerLeaveCallback verifies that the leave callback fires when
// a peer is removed.
func TestPeerLeaveCallback(t *testing.T) {
	rt := NewRoutingTable()

	peer := &PeerEntry{
		ID:         "peer-ccc",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.10.3.2/32"},
	}
	rt.AddPeer(peer)

	var left []string
	rt.SetLeaveCallback(func(peerID string) {
		left = append(left, peerID)
	})

	rt.RemovePeer("peer-ccc")
	if len(left) != 1 {
		t.Fatalf("expected 1 leave, got %d", len(left))
	}
	if left[0] != "peer-ccc" {
		t.Errorf("expected leave for peer-ccc, got %s", left[0])
	}

	// Remove non-existent peer → callback should still fire (idempotent
	// for the caller's perspective; the peer ID is the key).
	// Actually, RemovePeer only fires the callback if the peer existed.
	rt.RemovePeer("nonexistent")
	if len(left) != 1 {
		t.Errorf("leave callback should not fire for non-existent peer, got %d", len(left))
	}
}

// TestNilCallbacksSafe verifies that nil callbacks (not set) don't panic.
func TestNilCallbacksSafe(t *testing.T) {
	rt := NewRoutingTable()
	// No callbacks set.
	rt.AddPeer(&PeerEntry{ID: "peer-xxx", Endpoint: "1.2.3.4:51820", AllowedIPs: []string{"10.10.4.2/32"}})
	rt.RemovePeer("peer-xxx")
	// Should not panic.
}
