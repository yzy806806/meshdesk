package p2p

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPeerCache_LoadNonexistent(t *testing.T) {
	c := NewPeerCache("/tmp/meshdesk-test-nonexistent.cache")
	if err := c.Load(); err != nil {
		t.Fatalf("Load on nonexistent file should not error: %v", err)
	}
	if c.CachedPeerCount() != 0 {
		t.Fatalf("expected 0 cached peers, got %d", c.CachedPeerCount())
	}
}

func TestPeerCache_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.cache")
	c := NewPeerCache(path)

	// Add two peers.
	c.OnPeerJoin(&NodeMeta{
		PublicKey: "aaaa1111bbbb2222",
		Hostname:  "node-a",
		Role:      "agent",
		Endpoints: []string{"10.0.0.1:52888"},
	})
	c.OnPeerJoin(&NodeMeta{
		PublicKey: "cccc3333dddd4444",
		Hostname:  "node-b",
		Role:      "web",
		Endpoints: []string{"10.0.0.2:52888", "192.168.1.2:52888"},
	})

	if c.CachedPeerCount() != 2 {
		t.Fatalf("expected 2 cached peers, got %d", c.CachedPeerCount())
	}

	// Save.
	if err := c.SaveNow(); err != nil {
		t.Fatalf("SaveNow failed: %v", err)
	}

	// Verify file exists.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cache file not created: %v", err)
	}

	// Load into a new cache.
	c2 := NewPeerCache(path)
	if err := c2.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if c2.CachedPeerCount() != 2 {
		t.Fatalf("expected 2 loaded peers, got %d", c2.CachedPeerCount())
	}

	// Verify content.
	peers := c2.AllCachedPeers()
	foundA := false
	foundB := false
	for _, p := range peers {
		switch p.PublicKey {
		case "aaaa1111bbbb2222":
			foundA = true
			if p.Hostname != "node-a" {
				t.Errorf("expected hostname node-a, got %s", p.Hostname)
			}
			if len(p.Endpoints) != 1 || p.Endpoints[0] != "10.0.0.1:52888" {
				t.Errorf("unexpected endpoints: %v", p.Endpoints)
			}
		case "cccc3333dddd4444":
			foundB = true
			if p.Hostname != "node-b" {
				t.Errorf("expected hostname node-b, got %s", p.Hostname)
			}
			if len(p.Endpoints) != 2 {
				t.Errorf("expected 2 endpoints, got %d", len(p.Endpoints))
			}
		}
	}
	if !foundA {
		t.Error("peer a not found after load")
	}
	if !foundB {
		t.Error("peer b not found after load")
	}
}

func TestPeerCache_SkipNATPeers(t *testing.T) {
	c := NewPeerCache("/tmp/meshdesk-test-nat.cache")
	defer func() { _ = os.Remove("/tmp/meshdesk-test-nat.cache") }()

	// Peer with no endpoints should NOT be cached.
	c.OnPeerJoin(&NodeMeta{
		PublicKey: "nat1234",
		Hostname:  "nat-node",
		Endpoints: []string{},
	})
	if c.CachedPeerCount() != 0 {
		t.Fatalf("NAT peer (no endpoints) should not be cached, got %d", c.CachedPeerCount())
	}
}

func TestPeerCache_OnPeerUpdate(t *testing.T) {
	c := NewPeerCache("/tmp/meshdesk-test-update.cache")
	defer func() { _ = os.Remove("/tmp/meshdesk-test-update.cache") }()

	// Add a peer.
	c.OnPeerJoin(&NodeMeta{
		PublicKey: "update1234",
		Hostname:  "node-u",
		Endpoints: []string{"10.0.0.1:52888"},
	})

	// Update with new endpoints.
	c.OnPeerUpdate(&NodeMeta{
		PublicKey: "update1234",
		Hostname:  "node-u-updated",
		Endpoints: []string{"10.0.0.99:52888"},
	})

	peers := c.AllCachedPeers()
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Hostname != "node-u-updated" {
		t.Errorf("expected updated hostname, got %s", peers[0].Hostname)
	}
	if len(peers[0].Endpoints) != 1 || peers[0].Endpoints[0] != "10.0.0.99:52888" {
		t.Errorf("expected updated endpoint, got %v", peers[0].Endpoints)
	}

	// Update with empty endpoints should remove the peer.
	c.OnPeerUpdate(&NodeMeta{
		PublicKey: "update1234",
		Endpoints: []string{},
	})
	if c.CachedPeerCount() != 0 {
		t.Fatalf("expected 0 peers after endpoint removal, got %d", c.CachedPeerCount())
	}
}

func TestPeerCache_OnPeerLeave(t *testing.T) {
	c := NewPeerCache("/tmp/meshdesk-test-leave.cache")
	defer func() { _ = os.Remove("/tmp/meshdesk-test-leave.cache") }()

	c.OnPeerJoin(&NodeMeta{
		PublicKey: "leave1234",
		Endpoints: []string{"10.0.0.1:52888"},
	})
	if c.CachedPeerCount() != 1 {
		t.Fatalf("expected 1 peer, got %d", c.CachedPeerCount())
	}

	c.OnPeerLeave("leave1234")
	if c.CachedPeerCount() != 0 {
		t.Fatalf("expected 0 peers after leave, got %d", c.CachedPeerCount())
	}
}

func TestPeerCache_CachedEndpointsAsSeeds(t *testing.T) {
	c := NewPeerCache("/tmp/meshdesk-test-seeds.cache")
	defer func() { _ = os.Remove("/tmp/meshdesk-test-seeds.cache") }()

	c.OnPeerJoin(&NodeMeta{
		PublicKey: "seed1",
		Endpoints: []string{"10.0.0.1:52888"},
	})
	c.OnPeerJoin(&NodeMeta{
		PublicKey: "seed2",
		Endpoints: []string{"10.0.0.2:52888", "10.0.0.1:52888"}, // duplicate
	})

	seeds := c.CachedEndpointsAsSeeds()
	if len(seeds) != 2 {
		t.Fatalf("expected 2 unique seeds, got %d: %v", len(seeds), seeds)
	}

	seen := make(map[string]bool)
	for _, s := range seeds {
		if seen[s] {
			t.Errorf("duplicate seed: %s", s)
		}
		seen[s] = true
	}
}

func TestPeerCache_StopFlushes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers-flush.cache")
	c := NewPeerCache(path)

	c.OnPeerJoin(&NodeMeta{
		PublicKey: "flush1",
		Endpoints: []string{"10.0.0.1:52888"},
	})

	// Stop should flush.
	c.Stop()

	// Verify file was written.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected file to be written on Stop: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty cache file")
	}

	// Load and verify.
	c2 := NewPeerCache(path)
	if err := c2.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if c2.CachedPeerCount() != 1 {
		t.Fatalf("expected 1 peer after load, got %d", c2.CachedPeerCount())
	}
}

func TestPeerCache_SaveLoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers-loop.cache")
	c := NewPeerCache(path)

	// Start save loop with very short interval for testing.
	// We can't easily change the interval, so we just test that
	// StartSaveLoop + Stop works without panicking.
	c.StartSaveLoop()

	c.OnPeerJoin(&NodeMeta{
		PublicKey: "loop1",
		Endpoints: []string{"10.0.0.1:52888"},
	})

	// Give the loop a moment to potentially run.
	time.Sleep(50 * time.Millisecond)

	c.Stop()

	// File should exist.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected cache file to exist: %v", err)
	}
}

func TestPeerCache_EmptySaveNow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers-empty.cache")
	c := NewPeerCache(path)

	// SaveNow with no peers and no dirty flag should not write a file.
	if err := c.SaveNow(); err != nil {
		t.Fatalf("SaveNow on empty cache should not error: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expected no file for empty cache")
	}
}

func TestPeerCache_DefaultPath(t *testing.T) {
	c := NewPeerCache("")
	if c.path != DefaultPeerCachePath {
		t.Errorf("expected default path %s, got %s", DefaultPeerCachePath, c.path)
	}
}
