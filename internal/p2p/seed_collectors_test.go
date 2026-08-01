package p2p

import (
	"path/filepath"
	"sync"
	"testing"
)

// TestSeedCollectorsFromCache verifies that SeedCollectorsFromCache
// re-fires the collector discovery callback for every collector peer
// persisted in the peer cache, enabling monitor routing immediately
// after a restart without waiting for gossip re-discovery.
func TestSeedCollectorsFromCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers-seed.cache")
	pc := NewPeerCache(path)

	// Populate the cache with a collector and a non-collector.
	pc.OnPeerJoin(&NodeMeta{
		PublicKey:   "seed-collector-1",
		Hostname:    "dashboard-seed",
		CapCollector: true,
		Endpoints:   []string{"203.0.113.5:52888"},
	})
	pc.OnPeerJoin(&NodeMeta{
		PublicKey:   "seed-agent-1",
		Hostname:    "agent-seed",
		CapCollector: false,
		Endpoints:   []string{"10.0.0.2:52888"},
	})

	// Build a minimal GossipLayer with just events + peerCache.
	localMeta := &NodeMeta{
		PublicKey: "localkey0000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	gl := &GossipLayer{
		delegate:  delegate,
		events:    events,
		peerCache: pc,
	}

	// Track callback invocations.
	var mu sync.Mutex
	var calledKeys []string
	gl.SetCollectorHandler(func(peerKey string) {
		mu.Lock()
		defer mu.Unlock()
		calledKeys = append(calledKeys, peerKey)
	})

	// Seed from cache.
	gl.SeedCollectorsFromCache()

	mu.Lock()
	defer mu.Unlock()
	if len(calledKeys) != 1 {
		t.Fatalf("expected 1 callback invocation, got %d: %v", len(calledKeys), calledKeys)
	}
	if calledKeys[0] != "seed-collector-1" {
		t.Errorf("expected seed-collector-1, got %s", calledKeys[0])
	}
}

// TestSeedCollectorsFromCacheEmpty verifies that SeedCollectorsFromCache
// is a no-op when the cache has no collectors.
func TestSeedCollectorsFromCacheEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers-empty-seed.cache")
	pc := NewPeerCache(path)

	// Only add a non-collector.
	pc.OnPeerJoin(&NodeMeta{
		PublicKey:   "no-collector",
		CapCollector: false,
		Endpoints:   []string{"10.0.0.1:52888"},
	})

	localMeta := &NodeMeta{
		PublicKey: "localkey0000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	gl := &GossipLayer{
		delegate:  delegate,
		events:    events,
		peerCache: pc,
	}

	var mu sync.Mutex
	var calledCount int
	gl.SetCollectorHandler(func(peerKey string) {
		mu.Lock()
		defer mu.Unlock()
		calledCount++
	})

	gl.SeedCollectorsFromCache()

	mu.Lock()
	defer mu.Unlock()
	if calledCount != 0 {
		t.Errorf("expected 0 callback invocations, got %d", calledCount)
	}
}

// TestSeedCollectorsFromCacheNoHandler verifies that SeedCollectorsFromCache
// does not panic when the collector handler is nil.
func TestSeedCollectorsFromCacheNoHandler(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers-nohdl.cache")
	pc := NewPeerCache(path)

	pc.OnPeerJoin(&NodeMeta{
		PublicKey:   "nohdl-collector",
		CapCollector: true,
		Endpoints:   []string{"203.0.113.5:52888"},
	})

	localMeta := &NodeMeta{
		PublicKey: "localkey0000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	gl := &GossipLayer{
		delegate:  delegate,
		events:    events,
		peerCache: pc,
	}

	// No handler set — should be a no-op, not a panic.
	gl.SeedCollectorsFromCache()
}

// TestSeedCollectorsFromCacheNilCache verifies that SeedCollectorsFromCache
// is a no-op when the peer cache is nil.
func TestSeedCollectorsFromCacheNilCache(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey0000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	gl := &GossipLayer{
		delegate: delegate,
		events:   events,
		// peerCache is nil
	}

	gl.SetCollectorHandler(func(peerKey string) {
		t.Error("handler should not be called with nil cache")
	})

	// Should be a no-op, not a panic.
	gl.SeedCollectorsFromCache()
}
