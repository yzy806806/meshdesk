package p2p

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
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

// TestSeedCollectorsFromCacheMultipleCollectors verifies that all
// collector peers in the cache are seeded — not just one.
func TestSeedCollectorsFromCacheMultipleCollectors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers-multi.cache")
	pc := NewPeerCache(path)

	collectors := []string{"coll-a", "coll-b", "coll-c"}
	for _, key := range collectors {
		pc.OnPeerJoin(&NodeMeta{
			PublicKey:    key,
			Hostname:     "coll-" + key,
			CapCollector: true,
			Endpoints:    []string{"10.0.0.1:52888"},
		})
	}
	// Add a non-collector to ensure it's filtered.
	pc.OnPeerJoin(&NodeMeta{
		PublicKey:    "non-coll",
		Hostname:     "agent-only",
		CapCollector: false,
		Endpoints:    []string{"10.0.0.2:52888"},
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
	called := make(map[string]bool)
	gl.SetCollectorHandler(func(peerKey string) {
		mu.Lock()
		defer mu.Unlock()
		called[peerKey] = true
	})

	gl.SeedCollectorsFromCache()

	mu.Lock()
	defer mu.Unlock()
	if len(called) != 3 {
		t.Fatalf("expected 3 collector callbacks, got %d: %v", len(called), called)
	}
	for _, key := range collectors {
		if !called[key] {
			t.Errorf("collector %s not seeded", key)
		}
	}
	if called["non-coll"] {
		t.Error("non-collector should not be seeded")
	}
}

// TestSeedCollectorsFromCacheRestartFlow simulates a full node restart:
// 1) populate cache with collectors
// 2) save to disk
// 3) create a NEW cache from the same file (simulating fresh process)
// 4) load from disk
// 5) seed — verify all collectors restored without gossip
func TestSeedCollectorsFromCacheRestartFlow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers-restart.cache")

	// ---- Phase 1: first run, populate and save ----
	c1 := NewPeerCache(path)
	c1.OnPeerJoin(&NodeMeta{
		PublicKey:    "restart-coll-1",
		Hostname:     "dashboard-1",
		CapCollector: true,
		Endpoints:    []string{"203.0.113.5:52888"},
	})
	c1.OnPeerJoin(&NodeMeta{
		PublicKey:    "restart-coll-2",
		Hostname:     "dashboard-2",
		CapCollector: true,
		Endpoints:    []string{"203.0.113.6:52888"},
	})
	c1.OnPeerJoin(&NodeMeta{
		PublicKey:    "restart-agent",
		Hostname:     "agent",
		CapCollector: false,
		Endpoints:    []string{"10.0.0.1:52888"},
	})

	if err := c1.SaveNow(); err != nil {
		t.Fatalf("SaveNow failed: %v", err)
	}

	// Verify file exists on disk.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cache file not created: %v", err)
	}

	// ---- Phase 2: simulate restart (new cache, new GossipLayer) ----
	c2 := NewPeerCache(path)
	if err := c2.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify CachedCollectors() returns correct keys immediately.
	collectors := c2.CachedCollectors()
	if len(collectors) != 2 {
		t.Fatalf("expected 2 cached collectors, got %d: %v", len(collectors), collectors)
	}

	// Build a new GossipLayer (simulating fresh start, no memberlist).
	localMeta := &NodeMeta{
		PublicKey: "localkey0000000000000000000000000000000000000000000000000000",
	}
	delegate := newMeshDelegate(localMeta)
	mockPM := newMockPeerManager()
	events := newMeshEventDelegate(delegate, mockPM)

	gl := &GossipLayer{
		delegate:  delegate,
		events:    events,
		peerCache: c2,
	}

	var mu sync.Mutex
	called := make(map[string]bool)
	gl.SetCollectorHandler(func(peerKey string) {
		mu.Lock()
		defer mu.Unlock()
		called[peerKey] = true
	})

	gl.SeedCollectorsFromCache()

	mu.Lock()
	defer mu.Unlock()
	if len(called) != 2 {
		t.Fatalf("expected 2 collector callbacks after restart, got %d: %v", len(called), called)
	}
	if !called["restart-coll-1"] {
		t.Error("restart-coll-1 not seeded from cache")
	}
	if !called["restart-coll-2"] {
		t.Error("restart-coll-2 not seeded from cache")
	}
	if called["restart-agent"] {
		t.Error("non-collector restart-agent should not be seeded")
	}
}

// TestSeedCollectorsFromCacheNoGossipDelay verifies that
// SeedCollectorsFromCache runs synchronously and immediately — it does
// not wait for gossip or memberlist. This confirms the recovery is
// O(N) in the number of cached collectors, not gated by gossip join
// timeouts.
func TestSeedCollectorsFromCacheNoGossipDelay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers-timing.cache")
	pc := NewPeerCache(path)

	// Add multiple collectors to make the timing measurable.
	for i := 0; i < 10; i++ {
		pc.OnPeerJoin(&NodeMeta{
			PublicKey:    "timing-coll-" + string(rune('0'+i)),
			Hostname:     "coll-" + string(rune('0'+i)),
			CapCollector: true,
			Endpoints:    []string{"10.0.0.1:52888"},
		})
	}

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
		// memberlist is nil — no gossip available
	}

	var mu sync.Mutex
	var calledCount int
	gl.SetCollectorHandler(func(peerKey string) {
		mu.Lock()
		defer mu.Unlock()
		calledCount++
	})

	// Measure: SeedCollectorsFromCache must complete in well under 1 second.
	start := time.Now()
	gl.SeedCollectorsFromCache()
	elapsed := time.Since(start)

	mu.Lock()
	defer mu.Unlock()

	if calledCount != 10 {
		t.Fatalf("expected 10 collector callbacks, got %d", calledCount)
	}

	// The seeding must be fast — it's just iterating a map. 100ms is
	// generous, but it MUST be sub-second. Real gossip join takes 5-30s.
	if elapsed > 100*time.Millisecond {
		t.Errorf("SeedCollectorsFromCache took %v — expected sub-100ms (no gossip delay)", elapsed)
	}

	t.Logf("SeedCollectorsFromCache completed in %v for %d collectors", elapsed, calledCount)
}
