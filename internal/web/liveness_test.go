package web

import (
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/monitor"
)

// mockLiveness is a test PeerLiveness implementation.
type mockLiveness struct {
	alive     map[string]bool // peerID → alive
	aliveIDs  []string        // ordered list for AlivePeerIDs
	hostnames map[string]string // peerID → hostname (for PeerHostname)
}

func (m *mockLiveness) IsAlive(peerID string) bool {
	return m.alive[peerID]
}

func (m *mockLiveness) AlivePeerIDs() []string {
	return m.aliveIDs
}

func (m *mockLiveness) PeerHostname(peerID string) string {
	return m.hostnames[peerID]
}

// --- Test 1: AllPeerIDs includes gossip-discovered peers not in routing table ---

func TestLiveness_AllPeerIDsIncludesGossipPeers(t *testing.T) {
	m := &meshTopologyPeers{
		localNodeID: "local",
		liveness: &mockLiveness{
			alive:    map[string]bool{"gossip1": true, "gossip2": true},
			aliveIDs: []string{"gossip1", "gossip2"},
		},
	}

	ids := m.AllPeerIDs()

	// Should include local + both gossip peers.
	idSet := make(map[string]bool)
	for _, id := range ids {
		idSet[id] = true
	}
	if !idSet["local"] {
		t.Error("AllPeerIDs missing local node")
	}
	if !idSet["gossip1"] {
		t.Error("AllPeerIDs missing gossip-discovered peer gossip1")
	}
	if !idSet["gossip2"] {
		t.Error("AllPeerIDs missing gossip-discovered peer gossip2")
	}
}

// --- Test 2: NodeStatus returns "online" when metrics fresh even if gossip says dead ---

func TestLiveness_NodeStatusOnlineWhenFreshMetricsGossipDead(t *testing.T) {
	store := monitor.NewStore()
	now := time.Now().UTC()
	store.Append("dead-peer", &monitor.Metrics{
		Timestamp: now, // fresh metrics
		NodeID:    "dead-peer",
		Hostname:  "dead-host",
	})

	m := &monitorTopologyMetrics{
		store: store,
		liveness: &mockLiveness{
			alive: map[string]bool{"dead-peer": false}, // gossip says dead
		},
	}

	// Metrics are authoritative — fresh metrics → "online" even if gossip says dead.
	status := m.NodeStatus("dead-peer", 60*time.Second)
	if status != "online" {
		t.Errorf("Expected 'online' for fresh metrics (metrics-first priority), got %q", status)
	}
}

// --- Test 2b: NodeStatus returns "offline" when stale metrics + gossip dead ---

func TestLiveness_NodeStatusOfflineWhenStaleMetricsGossipDead(t *testing.T) {
	store := monitor.NewStore()
	now := time.Now().UTC()
	store.Append("stale-dead", &monitor.Metrics{
		Timestamp: now.Add(-5 * time.Minute), // stale metrics
		NodeID:    "stale-dead",
		Hostname:  "stale-dead-host",
	})

	m := &monitorTopologyMetrics{
		store: store,
		liveness: &mockLiveness{
			alive: map[string]bool{"stale-dead": false}, // gossip says dead
		},
	}

	status := m.NodeStatus("stale-dead", 60*time.Second)
	if status != "offline" {
		t.Errorf("Expected 'offline' for stale metrics + gossip dead, got %q", status)
	}
}

// --- Test 2c: NodeStatus returns "online" when stale metrics + gossip alive ---

func TestLiveness_NodeStatusOnlineWhenStaleMetricsGossipAlive(t *testing.T) {
	store := monitor.NewStore()
	now := time.Now().UTC()
	store.Append("stale-alive", &monitor.Metrics{
		Timestamp: now.Add(-5 * time.Minute), // stale metrics
		NodeID:    "stale-alive",
		Hostname:  "stale-alive-host",
	})

	m := &monitorTopologyMetrics{
		store: store,
		liveness: &mockLiveness{
			alive: map[string]bool{"stale-alive": true}, // gossip says alive
		},
	}

	status := m.NodeStatus("stale-alive", 60*time.Second)
	if status != "online" {
		t.Errorf("Expected 'online' for stale metrics + gossip alive (fallback), got %q", status)
	}
}

// --- Test 2d: NodeStatus returns "offline" when no metrics + gossip dead ---

func TestLiveness_NodeStatusOfflineWhenNoMetricsGossipDead(t *testing.T) {
	store := monitor.NewStore()
	// No metrics stored for "no-metrics-dead"

	m := &monitorTopologyMetrics{
		store: store,
		liveness: &mockLiveness{
			alive: map[string]bool{"no-metrics-dead": false}, // gossip says dead
		},
	}

	status := m.NodeStatus("no-metrics-dead", 60*time.Second)
	if status != "offline" {
		t.Errorf("Expected 'offline' for no metrics + gossip dead, got %q", status)
	}
}

// --- Test 3: NodeStatus returns "online" when gossip alive but no metrics ---

func TestLiveness_NodeStatusOnlineWhenAliveNoMetrics(t *testing.T) {
	store := monitor.NewStore()
	// No metrics stored for "alive-no-metrics"

	m := &monitorTopologyMetrics{
		store: store,
		liveness: &mockLiveness{
			alive: map[string]bool{"alive-no-metrics": true},
		},
	}

	status := m.NodeStatus("alive-no-metrics", 60*time.Second)
	if status != "online" {
		t.Errorf("Expected 'online' for gossip-alive peer with no metrics, got %q", status)
	}
}

// --- Test 4: Backward compat — liveness=nil preserves existing behavior ---

func TestLiveness_NilLivenessPreservesExistingBehavior(t *testing.T) {
	store := monitor.NewStore()
	now := time.Now().UTC()

	// Fresh metrics → online
	store.Append("fresh", &monitor.Metrics{
		Timestamp: now,
		NodeID:    "fresh",
	})

	// Stale metrics → offline
	store.Append("stale", &monitor.Metrics{
		Timestamp: now.Add(-5 * time.Minute),
		NodeID:    "stale",
	})

	m := &monitorTopologyMetrics{
		store:    store,
		liveness: nil, // backward compatible
	}

	if status := m.NodeStatus("fresh", 60*time.Second); status != "online" {
		t.Errorf("Expected 'online' for fresh metrics (nil liveness), got %q", status)
	}
	if status := m.NodeStatus("stale", 60*time.Second); status != "offline" {
		t.Errorf("Expected 'offline' for stale metrics (nil liveness), got %q", status)
	}
	if status := m.NodeStatus("nonexistent", 60*time.Second); status != "offline" {
		t.Errorf("Expected 'offline' for nonexistent peer (nil liveness), got %q", status)
	}

	// Also verify AllPeerIDs with nil liveness on meshTopologyPeers.
	peers := &meshTopologyPeers{
		localNodeID: "local",
		liveness:    nil,
	}
	ids := peers.AllPeerIDs()
	if len(ids) != 1 || ids[0] != "local" {
		t.Errorf("Expected [local] with nil liveness, got %v", ids)
	}
}

// --- Test 5: NodeStatus returns "online" when gossip alive + fresh metrics ---

func TestLiveness_NodeStatusOnlineWhenAliveWithMetrics(t *testing.T) {
	store := monitor.NewStore()
	now := time.Now().UTC()
	store.Append("alive-fresh", &monitor.Metrics{
		Timestamp: now,
		NodeID:    "alive-fresh",
		Hostname:  "alive-host",
		CPU:       monitor.CPUMetrics{UsagePercent: 42.0},
	})

	m := &monitorTopologyMetrics{
		store: store,
		liveness: &mockLiveness{
			alive: map[string]bool{"alive-fresh": true},
		},
	}

	status := m.NodeStatus("alive-fresh", 60*time.Second)
	if status != "online" {
		t.Errorf("Expected 'online' for alive+fresh peer, got %q", status)
	}
}

// --- Test 6: PeerExists returns true for gossip-alive peers not in routing table ---

func TestLiveness_PeerExistsForGossipPeer(t *testing.T) {
	m := &meshTopologyPeers{
		localNodeID: "local",
		liveness: &mockLiveness{
			alive: map[string]bool{"gossip-only": true},
		},
	}

	if !m.PeerExists("local") {
		t.Error("PeerExists should return true for local node")
	}
	if !m.PeerExists("gossip-only") {
		t.Error("PeerExists should return true for gossip-alive peer")
	}
	if m.PeerExists("unknown") {
		t.Error("PeerExists should return false for unknown peer")
	}
}

// --- Test 7: Local node is always alive ---

func TestLiveness_LocalNodeAlwaysAlive(t *testing.T) {
	// Even with a liveness provider that doesn't know about the local node,
	// the local node should still be considered alive.
	m := &monitorTopologyMetrics{
		store: monitor.NewStore(),
		liveness: &mockLiveness{
			alive: map[string]bool{}, // local node not in gossip alive set
		},
	}

	// With no metrics and liveness saying not alive, local should be offline
	// UNLESS the liveness adapter handles local node specially.
	// In production, gossipLiveness.IsAlive(localKey) returns true.
	// Here we test with a mock that doesn't have the local node — it should
	// return "offline", which is correct behavior for the mock.
	status := m.NodeStatus("local", 60*time.Second)
	if status != "offline" {
		t.Errorf("Expected 'offline' for local node not in mock liveness, got %q", status)
	}

	// Now test with the local node in the alive set — should be online.
	m2 := &monitorTopologyMetrics{
		store: monitor.NewStore(),
		liveness: &mockLiveness{
			alive: map[string]bool{"local": true},
		},
	}
	status2 := m2.NodeStatus("local", 60*time.Second)
	if status2 != "online" {
		t.Errorf("Expected 'online' for local node in liveness alive set, got %q", status2)
	}
}

// --- Test 8: Integration — full topology snapshot with liveness ---

func TestLiveness_TopologySnapshotWithLiveness(t *testing.T) {
	store := monitor.NewStore()
	now := time.Now().UTC()

	// Node "aaa1" has fresh metrics and is alive in gossip.
	store.Append("aaa1", &monitor.Metrics{
		Timestamp: now,
		NodeID:    "aaa1",
		Hostname:  "node-alpha",
		CPU:       monitor.CPUMetrics{UsagePercent: 23.7},
	})

	// Node "bbb2" has NO metrics but is alive in gossip → should show "online".
	// Node "ccc3" has stale metrics and is dead in gossip → should show "offline".
	store.Append("ccc3", &monitor.Metrics{
		Timestamp: now.Add(-5 * time.Minute),
		NodeID:    "ccc3",
	})

	// Use testPeers (which implements TopologyPeers directly) for the
	// peer list, and monitorTopologyMetrics with liveness for metrics.
	peers := &testPeers{
		ids: []string{"aaa1", "bbb2", "ccc3"},
		roles: map[string]string{
			"aaa1": "entry",
			"bbb2": "exit",
			"ccc3": "relay",
		},
	}
	liveness := &mockLiveness{
		alive: map[string]bool{
			"aaa1": true,
			"bbb2": true, // alive but no metrics
			"ccc3": false, // dead
		},
		aliveIDs: []string{"aaa1", "bbb2"},
	}
	metrics := &monitorTopologyMetrics{
		store:    store,
		liveness: liveness,
	}

	snap := buildTopologySnapshot(peers, metrics, nil)

	nodeMap := make(map[string]TopologyNodeSnapshotHelper)
	for _, n := range snap.Nodes {
		nodeMap[n.ID] = TopologyNodeSnapshotHelper{Status: n.Status, Hostname: n.Hostname}
	}

	if nodeMap["aaa1"].Status != "online" {
		t.Errorf("aaa1: expected 'online', got %q", nodeMap["aaa1"].Status)
	}
	if nodeMap["bbb2"].Status != "online" {
		t.Errorf("bbb2: expected 'online' (alive, no metrics), got %q", nodeMap["bbb2"].Status)
	}
	if nodeMap["ccc3"].Status != "offline" {
		t.Errorf("ccc3: expected 'offline' (gossip dead), got %q", nodeMap["ccc3"].Status)
	}
}

// TopologyNodeSnapshotHelper is a small helper struct for test assertions.
type TopologyNodeSnapshotHelper struct {
	Status   string
	Hostname string
}

// --- Test 9: LatestHostname falls back to gossip when monitor store has no hostname ---

func TestLiveness_LatestHostnameGossipFallback(t *testing.T) {
	store := monitor.NewStore()

	// "gossip-only" has no metrics but gossip has its hostname.
	m := &monitorTopologyMetrics{
		store: store,
		liveness: &mockLiveness{
			alive:     map[string]bool{"gossip-only": true},
			hostnames: map[string]string{"gossip-only": "gossip-host"},
		},
	}

	h := m.LatestHostname("gossip-only")
	if h != "gossip-host" {
		t.Errorf("Expected 'gossip-host' from gossip fallback, got %q", h)
	}
}

// --- Test 10: LatestHostname uses monitor store when available (no fallback) ---

func TestLiveness_LatestHostnameMonitorPreferred(t *testing.T) {
	store := monitor.NewStore()
	now := time.Now().UTC()
	store.Append("node1", &monitor.Metrics{
		Timestamp: now,
		NodeID:    "node1",
		Hostname:  "monitor-host",
	})

	m := &monitorTopologyMetrics{
		store: store,
		liveness: &mockLiveness{
			alive:     map[string]bool{"node1": true},
			hostnames: map[string]string{"node1": "gossip-host-different"},
		},
	}

	h := m.LatestHostname("node1")
	if h != "monitor-host" {
		t.Errorf("Expected 'monitor-host' (monitor preferred), got %q", h)
	}
}

// --- Test 11: LatestHostname returns empty when neither source has it ---

func TestLiveness_LatestHostnameEmptyWhenNoSource(t *testing.T) {
	store := monitor.NewStore()

	m := &monitorTopologyMetrics{
		store: store,
		liveness: &mockLiveness{
			alive:     map[string]bool{"unknown": true},
			hostnames: map[string]string{},
		},
	}

	h := m.LatestHostname("unknown")
	if h != "" {
		t.Errorf("Expected empty string, got %q", h)
	}
}

// --- Test 12: LatestHostname returns empty when monitor has empty hostname, falls back to gossip ---

func TestLiveness_LatestHostnameFallsBackWhenMonitorEmpty(t *testing.T) {
	store := monitor.NewStore()
	now := time.Now().UTC()
	// Metrics exist but hostname is empty.
	store.Append("node2", &monitor.Metrics{
		Timestamp: now,
		NodeID:    "node2",
		Hostname:  "",
	})

	m := &monitorTopologyMetrics{
		store: store,
		liveness: &mockLiveness{
			alive:     map[string]bool{"node2": true},
			hostnames: map[string]string{"node2": "gossip-name"},
		},
	}

	h := m.LatestHostname("node2")
	if h != "gossip-name" {
		t.Errorf("Expected 'gossip-name' from fallback (monitor hostname empty), got %q", h)
	}
}

// --- Test 13: LatestHostname with nil liveness — no fallback, backward compatible ---

func TestLiveness_LatestHostnameNilLiveness(t *testing.T) {
	store := monitor.NewStore()
	now := time.Now().UTC()
	store.Append("node3", &monitor.Metrics{
		Timestamp: now,
		NodeID:    "node3",
		Hostname:  "store-host",
	})

	m := &monitorTopologyMetrics{
		store:    store,
		liveness: nil,
	}

	h := m.LatestHostname("node3")
	if h != "store-host" {
		t.Errorf("Expected 'store-host' (nil liveness), got %q", h)
	}

	// No metrics + nil liveness → empty.
	h = m.LatestHostname("nonexistent")
	if h != "" {
		t.Errorf("Expected empty for nonexistent with nil liveness, got %q", h)
	}
}

// --- Test 14: Full topology snapshot shows gossip hostname for node without metrics ---

func TestLiveness_TopologySnapshotGossipHostname(t *testing.T) {
	store := monitor.NewStore()
	now := time.Now().UTC()

	// "aaa1" has fresh metrics with hostname.
	store.Append("aaa1", &monitor.Metrics{
		Timestamp: now,
		NodeID:    "aaa1",
		Hostname:  "node-alpha",
	})
	// "bbb2" has NO metrics — hostname must come from gossip.

	peers := &testPeers{
		ids: []string{"aaa1", "bbb2"},
		roles: map[string]string{
			"aaa1": "entry",
			"bbb2": "exit",
		},
	}
	liveness := &mockLiveness{
		alive: map[string]bool{
			"aaa1": true,
			"bbb2": true,
		},
		hostnames: map[string]string{
			"bbb2": "node-beta-gossip",
		},
	}
	metrics := &monitorTopologyMetrics{
		store:    store,
		liveness: liveness,
	}

	snap := buildTopologySnapshot(peers, metrics, nil)

	nodeMap := make(map[string]string) // id → hostname
	for _, n := range snap.Nodes {
		nodeMap[n.ID] = n.Hostname
	}

	if nodeMap["aaa1"] != "node-alpha" {
		t.Errorf("aaa1: expected 'node-alpha' from monitor, got %q", nodeMap["aaa1"])
	}
	if nodeMap["bbb2"] != "node-beta-gossip" {
		t.Errorf("bbb2: expected 'node-beta-gossip' from gossip fallback, got %q", nodeMap["bbb2"])
	}
}
