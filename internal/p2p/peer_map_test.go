package p2p

import (
	"testing"
	"time"
)

// TestPeerLinkMap_NextHopDirect verifies Dijkstra picks direct links.
func TestPeerLinkMap_NextHopDirect(t *testing.T) {
	m := NewPeerLinkMap("A")
	m.AddLink("A", "B", "10.0.0.2", 10_000)
	m.AddLink("A", "C", "10.0.0.3", 20_000)
	m.AddLink("B", "C", "10.0.0.3", 5_000) // B→C cheaper but needs relay

	// Direct A→C (20ms) beats A→B→C (10+5+100 penalty = 115ms).
	if nh := m.NextHop("C"); nh != "C" {
		t.Fatalf("expected direct next-hop C, got %s", nh)
	}
	if nh := m.NextHop("B"); nh != "B" {
		t.Fatalf("expected direct next-hop B, got %s", nh)
	}
}

// TestPeerLinkMap_NextHopRelay verifies Dijkstra picks relay when no direct.
func TestPeerLinkMap_NextHopRelay(t *testing.T) {
	m := NewPeerLinkMap("A")
	m.AddLink("A", "B", "10.0.0.2", 10_000)
	m.AddLink("B", "D", "10.0.0.4", 10_000)

	// A→D only via B (relay): next hop is B.
	if nh := m.NextHop("D"); nh != "B" {
		t.Fatalf("expected relay next-hop B for D, got %s", nh)
	}
}

// TestPeerLinkMap_Unreachable verifies unknown targets return "".
func TestPeerLinkMap_Unreachable(t *testing.T) {
	m := NewPeerLinkMap("A")
	m.AddLink("A", "B", "10.0.0.2", 10_000)
	if nh := m.NextHop("Z"); nh != "" {
		t.Fatalf("expected no route to Z, got %s", nh)
	}
}

// TestPeerLinkMap_MultiHopChain verifies 3-hop chain routing.
func TestPeerLinkMap_MultiHopChain(t *testing.T) {
	m := NewPeerLinkMap("A")
	m.AddLink("A", "B", "10.0.0.2", 10_000)
	m.AddLink("B", "C", "10.0.0.3", 10_000)
	m.AddLink("C", "D", "10.0.0.4", 10_000)

	// A→D: A→B→C→D, next hop B.
	if nh := m.NextHop("D"); nh != "B" {
		t.Fatalf("expected next-hop B for D (3-hop), got %s", nh)
	}
}

// TestPeerLinkMap_MessageRoundTrip verifies marshalling.
func TestPeerLinkMap_MessageRoundTrip(t *testing.T) {
	m := &PeerLinkMessage{
		From:        "A",
		To:          "B",
		RTTUs:       12345,
		ToVirtualIP: "10.0.0.2",
		Seq:         7,
	}
	data, err := MarshalPeerLinkMessage(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !IsPeerLinkMessage(data) {
		t.Fatal("IsPeerLinkMessage should be true")
	}
	back, err := UnmarshalPeerLinkMessage(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.From != "A" || back.To != "B" || back.RTTUs != 12345 || back.ToVirtualIP != "10.0.0.2" {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
}

// TestPeerLinkMap_VirtualIPs verifies VirtualIP collection.
func TestPeerLinkMap_VirtualIPs(t *testing.T) {
	m := NewPeerLinkMap("A")
	m.AddLink("A", "B", "10.0.0.2", 10_000)
	m.AddLink("C", "B", "10.0.0.2", 5_000)
	m.AddLink("C", "D", "10.0.0.4", 5_000)

	vips := m.VirtualIPs()
	if vips["B"] != "10.0.0.2" {
		t.Fatalf("expected B vip, got %v", vips)
	}
	if vips["D"] != "10.0.0.4" {
		t.Fatalf("expected D vip, got %v", vips)
	}
}

// TestPeerLinkMap_Prune verifies stale links are removed.
func TestPeerLinkMap_Prune(t *testing.T) {
	m := NewPeerLinkMap("A")
	m.AddLink("A", "B", "10.0.0.2", 10_000)
	// Force staleness.
	m.mu.Lock()
	m.links["A"]["B"].LastSeen = time.Now().Add(-2 * m.ttl)
	m.mu.Unlock()

	m.Prune()
	if nh := m.NextHop("B"); nh != "" {
		t.Fatalf("expected B pruned, got route via %s", nh)
	}
}

// TestPeerLinkMap_RouteTable verifies full table.
func TestPeerLinkMap_RouteTable(t *testing.T) {
	m := NewPeerLinkMap("A")
	m.AddLink("A", "B", "10.0.0.2", 10_000)
	m.AddLink("B", "C", "10.0.0.3", 10_000)

	rt := m.RouteTable()
	if rt["B"] != "B" {
		t.Fatalf("expected B→B, got %v", rt)
	}
	if rt["C"] != "B" {
		t.Fatalf("expected C→B (via relay), got %v", rt)
	}
}
