package p2p

import (
	"sync"
	"testing"

	"github.com/hashicorp/memberlist"
)

// TestCollectorDiscoveredOnNotifyJoin verifies that when a peer with
// CapCollector=true joins via gossip, the collector handler is invoked
// with the peer's public key, and the peer is added to the collector pool.
func TestCollectorDiscoveredOnNotifyJoin(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	peerMeta := &NodeMeta{
		PublicKey:   "collector0000000000000000000000000000000000000000000000000000",
		Hostname:    "dashboard-1",
		Role:        "web",
		CapCollector: true,
		Endpoints:   []string{"203.0.113.5:51820"},
	}

	metaData, err := peerMeta.MarshalMeta()
	if err != nil {
		t.Fatalf("MarshalMeta failed: %v", err)
	}

	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	var mu sync.Mutex
	var collectorCalled bool
	var receivedKey string
	events.SetCollectorHandler(func(peerKey string) {
		mu.Lock()
		defer mu.Unlock()
		collectorCalled = true
		receivedKey = peerKey
	})

	events.NotifyJoin(mockNode)

	mu.Lock()
	defer mu.Unlock()
	if !collectorCalled {
		t.Error("collector handler was not called on NotifyJoin")
	}
	if receivedKey != peerMeta.PublicKey {
		t.Errorf("collector handler received wrong key: got %s, want %s",
			receivedKey, peerMeta.PublicKey)
	}

	// Verify the peer is in the collector pool.
	collectors := events.GetCollectorCandidates()
	if len(collectors) != 1 {
		t.Fatalf("expected 1 collector candidate, got %d", len(collectors))
	}
	if collectors[0].PublicKey != peerMeta.PublicKey {
		t.Error("collector candidate is wrong peer")
	}
}

// TestCollectorNotDiscoveredForNonCollector verifies that the collector
// handler is NOT called when a peer without CapCollector joins.
func TestCollectorNotDiscoveredForNonCollector(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	peerMeta := &NodeMeta{
		PublicKey: "agentkey0000000000000000000000000000000000000000000000000000000",
		Hostname:  "agent-1",
		Role:      "agent",
		Endpoints: []string{"203.0.113.10:51820"},
	}

	metaData, _ := peerMeta.MarshalMeta()
	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	var collectorCalled bool
	events.SetCollectorHandler(func(peerKey string) {
		collectorCalled = true
	})

	events.NotifyJoin(mockNode)

	if collectorCalled {
		t.Error("collector handler should NOT be called for non-collector peer")
	}

	collectors := events.GetCollectorCandidates()
	if len(collectors) != 0 {
		t.Errorf("expected 0 collector candidates, got %d", len(collectors))
	}
}

// TestCollectorDiscoveredOnNotifyUpdate verifies that when a peer's
// metadata changes to CapCollector=true via NotifyUpdate, the collector
// handler is invoked (capability transition).
func TestCollectorDiscoveredOnNotifyUpdate(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	// First, the peer joins as a non-collector.
	peerMeta := &NodeMeta{
		PublicKey: "transition0000000000000000000000000000000000000000000000000000",
		Hostname:  "node-1",
		Role:      "agent",
		Seq:       1,
		Endpoints: []string{"203.0.113.5:51820"},
	}

	metaData, _ := peerMeta.MarshalMeta()
	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	var mu sync.Mutex
	var collectorCalled bool
	var receivedKey string
	events.SetCollectorHandler(func(peerKey string) {
		mu.Lock()
		defer mu.Unlock()
		collectorCalled = true
		receivedKey = peerKey
	})

	// Join as non-collector — handler should NOT fire.
	events.NotifyJoin(mockNode)

	mu.Lock()
	if collectorCalled {
		t.Error("collector handler should NOT fire on initial non-collector join")
	}
	mu.Unlock()

	// Now update the peer's metadata to CapCollector=true (transition).
	peerMeta.CapCollector = true
	peerMeta.Seq = 2
	metaData2, _ := peerMeta.MarshalMeta()
	updatedNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData2,
	}

	events.NotifyUpdate(updatedNode)

	mu.Lock()
	defer mu.Unlock()
	if !collectorCalled {
		t.Error("collector handler was not called on NotifyUpdate transition")
	}
	if receivedKey != peerMeta.PublicKey {
		t.Errorf("collector handler received wrong key: got %s, want %s",
			receivedKey, peerMeta.PublicKey)
	}
}

// TestCollectorHandlerIdempotentJoin verifies that if a collector peer
// is seen again via NotifyJoin (e.g., after flapping/rejoin), the handler
// is only called once (on the first discovery).
func TestCollectorHandlerIdempotentJoin(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	peerMeta := &NodeMeta{
		PublicKey:   "collector0000000000000000000000000000000000000000000000000000",
		Hostname:    "dashboard-1",
		Role:        "web",
		CapCollector: true,
		Endpoints:   []string{"203.0.113.5:51820"},
	}

	metaData, _ := peerMeta.MarshalMeta()
	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	var callCount int
	var mu sync.Mutex
	events.SetCollectorHandler(func(peerKey string) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
	})

	// First join — handler fires.
	events.NotifyJoin(mockNode)

	// Second join (same peer, same metadata) — handler should NOT fire again
	// because the peer is already in the collectorPool.
	events.NotifyJoin(mockNode)

	mu.Lock()
	defer mu.Unlock()
	if callCount != 1 {
		t.Errorf("collector handler called %d times, expected 1", callCount)
	}
}

// TestCollectorRemovedOnLeave verifies that the collector pool is cleaned
// up when a collector peer leaves.
func TestCollectorRemovedOnLeave(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	peerMeta := &NodeMeta{
		PublicKey:   "collector0000000000000000000000000000000000000000000000000000",
		Hostname:    "dashboard-1",
		Role:        "web",
		CapCollector: true,
		Endpoints:   []string{"203.0.113.5:51820"},
	}

	metaData, _ := peerMeta.MarshalMeta()
	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	events.NotifyJoin(mockNode)

	// Verify it's in the pool.
	collectors := events.GetCollectorCandidates()
	if len(collectors) != 1 {
		t.Fatalf("expected 1 collector candidate before leave, got %d", len(collectors))
	}

	// Leave.
	events.NotifyLeave(mockNode)

	// Verify it's removed from the pool.
	collectors = events.GetCollectorCandidates()
	if len(collectors) != 0 {
		t.Errorf("expected 0 collector candidates after leave, got %d", len(collectors))
	}
}

// TestGossipLayerOnCollectorDiscovered verifies that the GossipLayer's
// OnCollectorDiscovered method dispatches to the handler installed via
// SetCollectorHandler.
func TestGossipLayerOnCollectorDiscovered(t *testing.T) {
	// Create a minimal GossipLayer with just the events delegate.
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	gl := &GossipLayer{
		delegate: delegate,
		events:   events,
	}

	peerKey := "collector0000000000000000000000000000000000000000000000000000"

	var mu sync.Mutex
	var called bool
	var receivedKey string
	gl.SetCollectorHandler(func(pk string) {
		mu.Lock()
		defer mu.Unlock()
		called = true
		receivedKey = pk
	})

	gl.OnCollectorDiscovered(peerKey)

	mu.Lock()
	defer mu.Unlock()
	if !called {
		t.Error("OnCollectorDiscovered did not call the handler")
	}
	if receivedKey != peerKey {
		t.Errorf("handler received wrong key: got %s, want %s", receivedKey, peerKey)
	}
}

// TestGossipLayerOnCollectorDiscoveredNoHandler verifies that
// OnCollectorDiscovered is a no-op when no handler is set.
func TestGossipLayerOnCollectorDiscoveredNoHandler(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	gl := &GossipLayer{
		delegate: delegate,
		events:   events,
	}

	// Should not panic when no handler is set.
	gl.OnCollectorDiscovered("somekey000000000000000000000000000000000000000000000000000000")
}

// TestCollectorRemovedHandlerOnLeave verifies that the collector removed
// handler is invoked with the correct public key when a collector peer
// leaves the mesh via NotifyLeave.
func TestCollectorRemovedHandlerOnLeave(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	peerMeta := &NodeMeta{
		PublicKey:   "collector0000000000000000000000000000000000000000000000000000",
		Hostname:    "dashboard-1",
		Role:        "web",
		CapCollector: true,
		Endpoints:   []string{"203.0.113.5:51820"},
	}

	metaData, _ := peerMeta.MarshalMeta()
	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	var mu sync.Mutex
	var removedCalled bool
	var removedKey string
	events.SetCollectorRemovedHandler(func(peerKey string) {
		mu.Lock()
		defer mu.Unlock()
		removedCalled = true
		removedKey = peerKey
	})

	// Join the collector peer.
	events.NotifyJoin(mockNode)

	// Leave.
	events.NotifyLeave(mockNode)

	mu.Lock()
	defer mu.Unlock()
	if !removedCalled {
		t.Error("collector removed handler was not called on NotifyLeave")
	}
	if removedKey != peerMeta.PublicKey {
		t.Errorf("collector removed handler received wrong key: got %s, want %s",
			removedKey, peerMeta.PublicKey)
	}
}

// TestCollectorRemovedHandlerNotCalledForNonCollector verifies that the
// collector removed handler is NOT invoked when a non-collector peer leaves.
func TestCollectorRemovedHandlerNotCalledForNonCollector(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	peerMeta := &NodeMeta{
		PublicKey: "agentkey0000000000000000000000000000000000000000000000000000000",
		Hostname:  "agent-1",
		Role:      "agent",
		Endpoints: []string{"203.0.113.10:51820"},
	}

	metaData, _ := peerMeta.MarshalMeta()
	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	var removedCalled bool
	events.SetCollectorRemovedHandler(func(peerKey string) {
		removedCalled = true
	})

	events.NotifyJoin(mockNode)
	events.NotifyLeave(mockNode)

	if removedCalled {
		t.Error("collector removed handler should NOT be called for non-collector peer leave")
	}
}

// TestCollectorRemovedHandlerOnCapabilityLoss verifies that the collector
// removed handler is invoked when a peer loses its CapCollector capability
// via NotifyUpdate (capability transition from collector to non-collector).
func TestCollectorRemovedHandlerOnCapabilityLoss(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	// Peer starts as a collector.
	peerMeta := &NodeMeta{
		PublicKey:   "collector0000000000000000000000000000000000000000000000000000",
		Hostname:    "dashboard-1",
		Role:        "web",
		CapCollector: true,
		Seq:         1,
		Endpoints:   []string{"203.0.113.5:51820"},
	}

	metaData, _ := peerMeta.MarshalMeta()
	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	var mu sync.Mutex
	var removedCalled bool
	var removedKey string
	events.SetCollectorRemovedHandler(func(peerKey string) {
		mu.Lock()
		defer mu.Unlock()
		removedCalled = true
		removedKey = peerKey
	})

	// Join as collector.
	events.NotifyJoin(mockNode)

	// Now update: peer loses CapCollector.
	peerMeta.CapCollector = false
	peerMeta.Seq = 2
	metaData2, _ := peerMeta.MarshalMeta()
	updatedNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData2,
	}

	events.NotifyUpdate(updatedNode)

	mu.Lock()
	defer mu.Unlock()
	if !removedCalled {
		t.Error("collector removed handler was not called on capability loss")
	}
	if removedKey != peerMeta.PublicKey {
		t.Errorf("collector removed handler received wrong key: got %s, want %s",
			removedKey, peerMeta.PublicKey)
	}
}

// TestCollectorRemovedHandlerNotCalledWhenNoHandler verifies that
// NotifyLeave does not panic when no collector removed handler is set.
func TestCollectorRemovedHandlerNotCalledWhenNoHandler(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	peerMeta := &NodeMeta{
		PublicKey:   "collector0000000000000000000000000000000000000000000000000000",
		Hostname:    "dashboard-1",
		Role:        "web",
		CapCollector: true,
		Endpoints:   []string{"203.0.113.5:51820"},
	}

	metaData, _ := peerMeta.MarshalMeta()
	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	// Join and leave without setting a removed handler — should not panic.
	events.NotifyJoin(mockNode)
	events.NotifyLeave(mockNode)

	// Verify the collector pool is cleaned up.
	collectors := events.GetCollectorCandidates()
	if len(collectors) != 0 {
		t.Errorf("expected 0 collector candidates after leave, got %d", len(collectors))
	}
}
