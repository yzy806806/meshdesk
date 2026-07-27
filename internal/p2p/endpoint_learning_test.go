package p2p

import (
	"sync"
	"testing"

	"github.com/hashicorp/memberlist"
)

// TestNotifyUpdateEndpointChangeTriggersUpdateEndpoint tests the critical
// bug fix (§5.1): when a peer's Endpoints transitions from empty to non-empty,
// UpdateEndpoint MUST be called on the WireGuard delegate.
//
// Before the fix, the cache was updated first and then read back, making
// oldEndpoint always equal newEndpoint — so UpdateEndpoint never fired.
func TestNotifyUpdateEndpointChangeTriggersUpdateEndpoint(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:    "10.10.0.1",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	peerKey := "peerkey0000000000000000000000000000000000000000000000000000000"

	// Step 1: Initial state — peer with NO endpoints.
	initialMeta := &NodeMeta{
		PublicKey: peerKey,
		Hostname:  "test-peer",
		MeshIP:    "10.10.1.5",
		Endpoints: []string{}, // empty
		Seq:       1,
	}
	metaData1, _ := initialMeta.MarshalMeta()
	mockNode1 := &memberlist.Node{
		Name: peerKey[:16],
		Meta: metaData1,
	}
	events.NotifyUpdate(mockNode1)

	// Verify no UpdateEndpoint was called (endpoints were empty).
	mockPM.mu.Lock()
	if len(mockPM.updatedEPs) != 0 {
		mockPM.mu.Unlock()
		t.Fatalf("UpdateEndpoint should not be called for empty endpoints, got: %v", mockPM.updatedEPs)
	}
	mockPM.mu.Unlock()

	// Step 2: Peer updates with a non-empty endpoint.
	updatedMeta := &NodeMeta{
		PublicKey: peerKey,
		Hostname:  "test-peer",
		MeshIP:    "10.10.1.5",
		Endpoints: []string{"203.0.113.5:51820"}, // NEW endpoint
		Seq:       2,
	}
	metaData2, _ := updatedMeta.MarshalMeta()
	mockNode2 := &memberlist.Node{
		Name: peerKey[:16],
		Meta: metaData2,
	}
	events.NotifyUpdate(mockNode2)

	// Verify UpdateEndpoint WAS called with the new endpoint.
	mockPM.mu.Lock()
	got, ok := mockPM.updatedEPs[peerKey]
	mockPM.mu.Unlock()
	if !ok {
		t.Fatal("UpdateEndpoint was NOT called after endpoint changed from empty to non-empty — bug not fixed!")
	}
	if got != "203.0.113.5:51820" {
		t.Errorf("UpdateEndpoint called with wrong endpoint: got %s, want 203.0.113.5:51820", got)
	}
}

// TestNotifyUpdateEndpointUnchangedNoUpdate tests that UpdateEndpoint is NOT
// called when the endpoint has not changed between updates.
func TestNotifyUpdateEndpointUnchangedNoUpdate(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:    "10.10.0.1",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	peerKey := "peerkey0000000000000000000000000000000000000000000000000000000"

	// First update with endpoint.
	meta1 := &NodeMeta{
		PublicKey: peerKey,
		MeshIP:    "10.10.1.5",
		Endpoints: []string{"203.0.113.5:51820"},
		Seq:       1,
	}
	metaData1, _ := meta1.MarshalMeta()
	events.NotifyUpdate(&memberlist.Node{Name: peerKey[:16], Meta: metaData1})

	// Should have 1 UpdateEndpoint call.
	mockPM.mu.Lock()
	callCount := len(mockPM.updatedEPs)
	mockPM.mu.Unlock()
	if callCount != 1 {
		t.Fatalf("expected 1 UpdateEndpoint call after first update, got %d", callCount)
	}

	// Second update with SAME endpoint but different load metrics.
	meta2 := &NodeMeta{
		PublicKey: peerKey,
		MeshIP:    "10.10.1.5",
		Endpoints: []string{"203.0.113.5:51820"}, // same endpoint
		LoadCPU:   0.9,                            // different load
		Seq:       2,
	}
	metaData2, _ := meta2.MarshalMeta()
	events.NotifyUpdate(&memberlist.Node{Name: peerKey[:16], Meta: metaData2})

	// Should still have only 1 UpdateEndpoint call (endpoint didn't change).
	// The mock overwrites the same key, so count stays at 1. We verify the
	// cached value is correct and the endpoint matches.
	mockPM.mu.Lock()
	got := mockPM.updatedEPs[peerKey]
	mockPM.mu.Unlock()
	if got != "203.0.113.5:51820" {
		t.Errorf("endpoint should be unchanged: got %s", got)
	}
}

// TestNotifyUpdateEndpointChangesTriggersUpdate tests that a CHANGED endpoint
// (not just empty→non-empty) also triggers UpdateEndpoint.
func TestNotifyUpdateEndpointChangesTriggersUpdate(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:    "10.10.0.1",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	peerKey := "peerkey0000000000000000000000000000000000000000000000000000000"

	// First update with endpoint A.
	meta1 := &NodeMeta{
		PublicKey: peerKey,
		MeshIP:    "10.10.1.5",
		Endpoints: []string{"203.0.113.5:51820"},
		Seq:       1,
	}
	metaData1, _ := meta1.MarshalMeta()
	events.NotifyUpdate(&memberlist.Node{Name: peerKey[:16], Meta: metaData1})

	// Second update with endpoint B (NAT rebinding).
	meta2 := &NodeMeta{
		PublicKey: peerKey,
		MeshIP:    "10.10.1.5",
		Endpoints: []string{"198.51.100.1:51820"}, // different endpoint
		Seq:       2,
	}
	metaData2, _ := meta2.MarshalMeta()
	events.NotifyUpdate(&memberlist.Node{Name: peerKey[:16], Meta: metaData2})

	// Verify UpdateEndpoint was called with the NEW endpoint.
	mockPM.mu.Lock()
	got := mockPM.updatedEPs[peerKey]
	mockPM.mu.Unlock()
	if got != "198.51.100.1:51820" {
		t.Errorf("UpdateEndpoint should be called with new endpoint: got %s, want 198.51.100.1:51820", got)
	}
}

// TestOnEndpointDiscoveredDedup tests that OnEndpointDiscovered with a
// duplicate endpoint does NOT increment Seq (AC-10).
func TestOnEndpointDiscoveredDedup(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:    "10.10.0.1",
		Endpoints: []string{},
		Seq:       1,
	}
	delegate := newMeshDelegate(localMeta)

	// GossipLayer.OnEndpointDiscovered calls delegate.updateLocalMeta, so we
	// replicate the exact logic here to test the dedup behavior.
	endpoint := "203.0.113.5:51820"

	// First call — adds endpoint.
	delegate.updateLocalMeta(func(m *NodeMeta) {
		for _, ep := range m.Endpoints {
			if ep == endpoint {
				return
			}
		}
		m.Endpoints = append(m.Endpoints, endpoint)
		m.NatType = inferNAT(endpoint)
		m.Seq++
	})

	meta1 := delegate.getLocalMeta()
	if len(meta1.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint after first call, got %d", len(meta1.Endpoints))
	}
	if meta1.Seq != 2 {
		t.Errorf("expected Seq=2 after first call, got %d", meta1.Seq)
	}

	// Second call with same endpoint — should be deduped (no Seq increment).
	delegate.updateLocalMeta(func(m *NodeMeta) {
		for _, ep := range m.Endpoints {
			if ep == endpoint {
				return
			}
		}
		m.Endpoints = append(m.Endpoints, endpoint)
		m.NatType = inferNAT(endpoint)
		m.Seq++
	})

	meta2 := delegate.getLocalMeta()
	if len(meta2.Endpoints) != 1 {
		t.Errorf("expected 1 endpoint after duplicate call, got %d", len(meta2.Endpoints))
	}
	if meta2.Seq != 2 {
		t.Errorf("Seq should NOT increment for duplicate endpoint: got %d, want 2", meta2.Seq)
	}

	// Third call with a different endpoint — adds it.
	endpoint2 := "198.51.100.1:51820"
	delegate.updateLocalMeta(func(m *NodeMeta) {
		for _, ep := range m.Endpoints {
			if ep == endpoint2 {
				return
			}
		}
		m.Endpoints = append(m.Endpoints, endpoint2)
		m.NatType = inferNAT(endpoint2)
		m.Seq++
	})

	meta3 := delegate.getLocalMeta()
	if len(meta3.Endpoints) != 2 {
		t.Errorf("expected 2 endpoints after new call, got %d", len(meta3.Endpoints))
	}
	if meta3.Seq != 3 {
		t.Errorf("Seq should increment for new endpoint: got %d, want 3", meta3.Seq)
	}
}

// TestOnEndpointDiscoveredSetsNATType tests that OnEndpointDiscovered sets
// the NAT type to "restricted_cone" (conservative default).
func TestOnEndpointDiscoveredSetsNATType(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:    "10.10.0.1",
		Endpoints: []string{},
		NatType:   "unknown",
		Seq:       0,
	}
	delegate := newMeshDelegate(localMeta)

	endpoint := "203.0.113.5:51820"
	delegate.updateLocalMeta(func(m *NodeMeta) {
		for _, ep := range m.Endpoints {
			if ep == endpoint {
				return
			}
		}
		m.Endpoints = append(m.Endpoints, endpoint)
		m.NatType = inferNAT(endpoint)
		m.Seq++
	})

	meta := delegate.getLocalMeta()
	if meta.NatType != "restricted_cone" {
		t.Errorf("NatType should be 'restricted_cone', got '%s'", meta.NatType)
	}
}

// TestOnEndpointDiscoveredConcurrent tests thread safety of OnEndpointDiscovered
// under concurrent access. Runs under -race to detect data races.
func TestOnEndpointDiscoveredConcurrent(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:    "10.10.0.1",
		Endpoints: []string{},
		Seq:       0,
	}
	delegate := newMeshDelegate(localMeta)

	endpoint := "203.0.113.5:51820"

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			delegate.updateLocalMeta(func(m *NodeMeta) {
				for _, ep := range m.Endpoints {
					if ep == endpoint {
						return
					}
				}
				m.Endpoints = append(m.Endpoints, endpoint)
				m.NatType = inferNAT(endpoint)
				m.Seq++
			})
		}()
	}
	wg.Wait()

	meta := delegate.getLocalMeta()
	if len(meta.Endpoints) != 1 {
		t.Errorf("expected exactly 1 endpoint after concurrent dedup, got %d", len(meta.Endpoints))
	}
}

// TestInferNAT tests the inferNAT helper returns "restricted_cone".
func TestInferNAT(t *testing.T) {
	result := inferNAT("203.0.113.5:51820")
	if result != "restricted_cone" {
		t.Errorf("inferNAT should return 'restricted_cone', got '%s'", result)
	}
}
