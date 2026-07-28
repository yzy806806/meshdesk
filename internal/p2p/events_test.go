package p2p

import (
	"sync"
	"testing"

	"github.com/hashicorp/memberlist"
)

// TestEventDelegateNotifyJoin verifies that NotifyJoin caches metadata
// and adds the peer to the appropriate capability pools.
func TestEventDelegateNotifyJoin(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	// Create a mock node that joined.
	peerMeta := &NodeMeta{
		PublicKey:     "peerkey0000000000000000000000000000000000000000000000000000000",
		Hostname:      "relay-node-1",
		Role:          "relay",
		CapRelay:      true,
		CapExit:       false,
		CapProxyEntry: true,
		Endpoints:     []string{"203.0.113.5:51820"},
		NatType:       "none",
		MaxCircuits:   1024,
	}

	metaData, err := peerMeta.MarshalMeta()
	if err != nil {
		t.Fatalf("MarshalMeta failed: %v", err)
	}

	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	// Track join handler call.
	var joinCalled bool
	var joinedMeta *NodeMeta
	events.SetJoinHandler(func(m *NodeMeta) {
		joinCalled = true
		joinedMeta = m
	})

	events.NotifyJoin(mockNode)

	if !joinCalled {
		t.Error("join handler was not called")
	}
	if joinedMeta == nil || joinedMeta.PublicKey != peerMeta.PublicKey {
		t.Error("join handler received wrong metadata")
	}

	// Verify metadata is cached.
	cached := events.GetPeerMeta(peerMeta.PublicKey)
	if cached == nil {
		t.Fatal("peer metadata not cached after NotifyJoin")
	}
	if cached.Hostname != peerMeta.Hostname {
		t.Errorf("cached Hostname mismatch: got %s, want %s", cached.Hostname, peerMeta.Hostname)
	}

	// Verify relay pool includes this peer.
	relays := events.GetRelayCandidates()
	if len(relays) != 1 {
		t.Fatalf("expected 1 relay candidate, got %d", len(relays))
	}
	if relays[0].PublicKey != peerMeta.PublicKey {
		t.Error("relay candidate is wrong peer")
	}

	// Verify entry pool includes this peer.
	entries := events.GetEntryCandidates()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry candidate, got %d", len(entries))
	}
}

func TestEventDelegateNotifyJoinSelf(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	// NotifyJoin with our own key should be ignored.
	metaData, _ := localMeta.MarshalMeta()
	mockNode := &memberlist.Node{
		Name: localMeta.PublicKey[:16],
		Meta: metaData,
	}

	var joinCalled bool
	events.SetJoinHandler(func(m *NodeMeta) {
		joinCalled = true
	})

	events.NotifyJoin(mockNode)

	if joinCalled {
		t.Error("join handler should not be called for self")
	}
	if events.KnownPeerCount() != 0 {
		t.Error("self should not be in peer cache")
	}
}

func TestEventDelegateNotifyLeaveRemovesPeer(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	peerMeta := &NodeMeta{
		PublicKey:   "peerkey0000000000000000000000000000000000000000000000000000000",
		Hostname:    "relay-node-1",
		CapRelay:    true,
		Endpoints:   []string{"203.0.113.5:51820"},
		MaxCircuits: 1024,
	}

	// Manually add peer to cache and pools.
	events.mu.Lock()
	events.metaCache[peerMeta.PublicKey] = peerMeta
	events.relayPool[peerMeta.PublicKey] = peerMeta
	events.mu.Unlock()

	// Track leave handler.
	var leaveCalled bool
	var leftKey string
	events.SetLeaveHandler(func(key string) {
		leaveCalled = true
		leftKey = key
	})

	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
	}

	events.NotifyLeave(mockNode)

	if !leaveCalled {
		t.Error("leave handler was not called")
	}
	if leftKey != peerMeta.PublicKey {
		t.Errorf("leave handler received wrong key: got %s, want %s", leftKey, peerMeta.PublicKey)
	}

	// Verify metadata is removed from cache.
	if events.GetPeerMeta(peerMeta.PublicKey) != nil {
		t.Error("peer metadata should be removed after NotifyLeave")
	}

	// Verify relay pool no longer includes this peer.
	relays := events.GetRelayCandidates()
	if len(relays) != 0 {
		t.Errorf("relay pool should be empty after leave, got %d", len(relays))
	}
}

func TestEventDelegateNotifyUpdate(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	// Initial peer metadata.
	peerMeta := &NodeMeta{
		PublicKey:   "peerkey0000000000000000000000000000000000000000000000000000000",
		Hostname:    "relay-node-1",
		CapRelay:    true,
		LoadCPU:     0.3,
		LoadMem:     0.2,
		MaxCircuits: 1024,
		Seq:         1,
	}

	events.mu.Lock()
	events.metaCache[peerMeta.PublicKey] = peerMeta
	events.relayPool[peerMeta.PublicKey] = peerMeta
	events.mu.Unlock()

	// Updated metadata with higher Seq and different load.
	updatedMeta := &NodeMeta{
		PublicKey:   peerMeta.PublicKey,
		Hostname:    "relay-node-1",
		CapRelay:    true,
		LoadCPU:     0.8, // increased
		LoadMem:     0.2,
		MaxCircuits: 1024,
		Seq:         2,
	}

	metaData, _ := updatedMeta.MarshalMeta()
	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	var updateCalled bool
	events.SetUpdateHandler(func(m *NodeMeta) {
		updateCalled = true
		if m.LoadCPU != 0.8 {
			t.Errorf("update handler received wrong LoadCPU: got %f, want 0.8", m.LoadCPU)
		}
	})

	events.NotifyUpdate(mockNode)

	if !updateCalled {
		t.Error("update handler was not called")
	}

	cached := events.GetPeerMeta(peerMeta.PublicKey)
	if cached == nil {
		t.Fatal("peer metadata not cached after update")
	}
	if cached.LoadCPU != 0.8 {
		t.Errorf("cached LoadCPU not updated: got %f, want 0.8", cached.LoadCPU)
	}
	if cached.Seq != 2 {
		t.Errorf("cached Seq not updated: got %d, want 2", cached.Seq)
	}
}

func TestEventDelegateNotifyUpdateStaleIgnored(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	// Current metadata with Seq=5.
	peerMeta := &NodeMeta{
		PublicKey: "peerkey0000000000000000000000000000000000000000000000000000000",
		LoadCPU:   0.5,
		Seq:       5,
	}
	events.mu.Lock()
	events.metaCache[peerMeta.PublicKey] = peerMeta
	events.mu.Unlock()

	// Stale update with Seq=3 (older).
	staleMeta := &NodeMeta{
		PublicKey: peerMeta.PublicKey,
		LoadCPU:   0.9, // different value but older Seq
		Seq:       3,
	}
	metaData, _ := staleMeta.MarshalMeta()
	mockNode := &memberlist.Node{
		Name: peerMeta.PublicKey[:16],
		Meta: metaData,
	}

	var updateCalled bool
	events.SetUpdateHandler(func(m *NodeMeta) {
		updateCalled = true
	})

	events.NotifyUpdate(mockNode)

	if updateCalled {
		t.Error("update handler should not be called for stale metadata")
	}

	// Cached value should remain unchanged.
	cached := events.GetPeerMeta(peerMeta.PublicKey)
	if cached.LoadCPU != 0.5 {
		t.Errorf("cached LoadCPU should be unchanged: got %f, want 0.5", cached.LoadCPU)
	}
}

func TestEventDelegateAllKnownPeers(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	// Add multiple peers.
	for i := 0; i < 5; i++ {
		meta := &NodeMeta{
			PublicKey: "peerkey000000000000000000000000000000000000000000000000000000" + string(rune('A'+i)),
			Seq:       1,
		}
		events.mu.Lock()
		events.metaCache[meta.PublicKey] = meta
		events.mu.Unlock()
	}

	peers := events.AllKnownPeers()
	if len(peers) != 5 {
		t.Errorf("expected 5 known peers, got %d", len(peers))
	}
}

func TestEventDelegateConcurrentAccess(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	// Concurrent reads and writes.
	var wg2 sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg2.Add(2)

		go func(n int) {
			defer wg2.Done()
			meta := &NodeMeta{
				PublicKey: "peer0000000000000000000000000000000000000000000000000000000" + string(rune('A'+n%26)),
				Seq:       uint64(n),
			}
			events.cacheMeta(meta)
		}(i)

		go func() {
			defer wg2.Done()
			_ = events.AllKnownPeers()
			_ = events.GetRelayCandidates()
		}()
	}
	wg2.Wait()
}

func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		input []string
		want  string
	}{
		{[]string{"a", "b"}, "a"},
		{[]string{"", "b"}, "b"},
		{[]string{"", ""}, ""},
		{nil, ""},
	}

	for _, tt := range tests {
		got := firstNonEmpty(tt.input)
		if got != tt.want {
			t.Errorf("firstNonEmpty(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCapabilitiesFromMeta(t *testing.T) {
	tests := []struct {
		name string
		meta *NodeMeta
		want []string
	}{
		{
			name: "all capabilities",
			meta: &NodeMeta{CapRelay: true, CapExit: true, CapProxyEntry: true},
			want: []string{"relay", "exit", "proxy_entry"},
		},
		{
			name: "relay only",
			meta: &NodeMeta{CapRelay: true},
			want: []string{"relay"},
		},
		{
			name: "none",
			meta: &NodeMeta{},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := capabilitiesFromMeta(tt.meta)
			if len(got) != len(tt.want) {
				t.Errorf("capabilitiesFromMeta() = %v, want %v", got, tt.want)
				return
			}
			for i, c := range tt.want {
				if got[i] != c {
					t.Errorf("capabilitiesFromMeta()[%d] = %q, want %q", i, got[i], c)
				}
			}
		})
	}
}
