package mock

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/topology"
)

// --- Interface conformance tests ---

func TestMockPeers_ImplementsTopologyPeers(t *testing.T) {
	var _ topology.TopologyPeers = NewMockPeers()
}

func TestMockMetrics_ImplementsTopologyMetrics(t *testing.T) {
	var _ topology.TopologyMetrics = NewMockMetrics()
}

func TestMockPaths_ImplementsTopologyPathInfo(t *testing.T) {
	var _ topology.TopologyPathInfo = NewMockPaths()
}

// --- AC2: Valid JSON with nodes and edges arrays ---

func TestSnapshot_ValidJSON(t *testing.T) {
	snap := DefaultSnapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	// Parse back to verify structure
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if _, ok := parsed["nodes"]; !ok {
		t.Fatal("JSON missing 'nodes' array")
	}
	if _, ok := parsed["edges"]; !ok {
		t.Fatal("JSON missing 'edges' array")
	}
}

// --- AC3: Every node has non-empty id and role ---

func TestSnapshot_NodesHaveIDAndRole(t *testing.T) {
	snap := DefaultSnapshot()
	if len(snap.Nodes) == 0 {
		t.Fatal("Expected non-empty nodes array")
	}
	for i, n := range snap.Nodes {
		if n.ID == "" {
			t.Errorf("Node %d has empty ID", i)
		}
		if n.Role == "" {
			t.Errorf("Node %d has empty role", i)
		}
	}
}

// --- AC4: cpu/mem present when metrics fresh, absent when stale ---

func TestSnapshot_CPUFreshNodeHasCPU(t *testing.T) {
	snap := DefaultSnapshot()
	found := false
	for _, n := range snap.Nodes {
		if n.ID == nodeEntryID {
			if n.CPU != 23.7 {
				t.Errorf("Expected CPU=23.7 for entry node, got %f", n.CPU)
			}
			if n.Mem != 62.1 {
				t.Errorf("Expected Mem=62.1 for entry node, got %f", n.Mem)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("Entry node not found in snapshot")
	}
}

func TestSnapshot_OfflineNodeHasZeroCPU(t *testing.T) {
	snap := DefaultSnapshot()
	found := false
	for _, n := range snap.Nodes {
		if n.ID == nodeOfflineID {
			// Offline node should have cpu=0, mem=0
			if n.CPU != 0 {
				t.Errorf("Expected CPU=0 for offline node, got %f", n.CPU)
			}
			if n.Mem != 0 {
				t.Errorf("Expected Mem=0 for offline node, got %f", n.Mem)
			}
			if n.Status != "offline" {
				t.Errorf("Expected status=offline, got %s", n.Status)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("Offline node not found in snapshot")
	}
}

// --- AC5: Edge latency_ms is -1 when unknown ---

func TestPeerLatency_UnknownPairReturnsMinus1(t *testing.T) {
	mp := NewMockPaths()
	lat := mp.PeerLatency("nonexistent", "alsononexistent")
	if lat != -1 {
		t.Errorf("Expected -1 for unknown pair, got %f", lat)
	}
}

func TestPeerLatency_KnownPairReturnsValue(t *testing.T) {
	mp := NewMockPaths()
	lat := mp.PeerLatency(nodeEntryID, nodeRelayID)
	if lat != 12.5 {
		t.Errorf("Expected 12.5, got %f", lat)
	}
}

// --- AC6: Empty result is valid when no nodes known ---

func TestEmptySnapshot(t *testing.T) {
	snap := topology.TopologySnapshot{
		Nodes: []topology.TopologyNode{},
		Edges: []topology.TopologyEdge{},
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal of empty snapshot failed: %v", err)
	}
	expected := `{"nodes":[],"edges":[]}`
	if string(data) != expected {
		t.Errorf("Expected %s, got %s", expected, string(data))
	}
}

// --- AC12: Position returns (0,0,0) for unknown nodes ---

func TestPosition_UnknownReturnsZero(t *testing.T) {
	mp := NewMockPeers()
	x, y, z := mp.Position("nonexistent")
	if x != 0 || y != 0 || z != 0 {
		t.Errorf("Expected (0,0,0), got (%f,%f,%f)", x, y, z)
	}
}

// --- AC13: Position is deterministic for the same peer ID ---

func TestDerivePosition_Deterministic(t *testing.T) {
	x1, y1, z1 := topology.DerivePosition(nodeEntryID)
	x2, y2, z2 := topology.DerivePosition(nodeEntryID)
	if x1 != x2 || y1 != y2 || z1 != z2 {
		t.Errorf("Position not deterministic: (%f,%f,%f) vs (%f,%f,%f)",
			x1, y1, z1, x2, y2, z2)
	}
}

func TestDerivePosition_DifferentForDifferentIDs(t *testing.T) {
	x1, y1, z1 := topology.DerivePosition(nodeEntryID)
	x2, y2, z2 := topology.DerivePosition(nodeRelayID)
	if x1 == x2 && y1 == y2 && z1 == z2 {
		t.Error("Expected different positions for different peer IDs")
	}
}

// --- Mock data integrity tests ---

func TestMockPeers_AllPeerIDs_Count(t *testing.T) {
	mp := NewMockPeers()
	ids := mp.AllPeerIDs()
	if len(ids) != 5 {
		t.Errorf("Expected 5 peer IDs, got %d", len(ids))
	}
}

func TestMockPeers_PeerExists(t *testing.T) {
	mp := NewMockPeers()
	if !mp.PeerExists(nodeEntryID) {
		t.Error("Expected PeerExists=true for entry node")
	}
	if mp.PeerExists("nonexistent") {
		t.Error("Expected PeerExists=false for unknown ID")
	}
}

func TestMockPeers_PeerRole(t *testing.T) {
	mp := NewMockPeers()
	tests := []struct {
		id       string
		expected string
	}{
		{nodeEntryID, "entry"},
		{nodeRelayID, "entry+relay"},
		{nodeExitID, "exit"},
		{nodeDashID, "dashboard"},
		{nodeOfflineID, "relay"},
	}
	for _, tt := range tests {
		got := mp.PeerRole(tt.id)
		if got != tt.expected {
			t.Errorf("PeerRole(%s) = %q, want %q", tt.id, got, tt.expected)
		}
	}
}

func TestMockPeers_PeerRole_Unknown(t *testing.T) {
	mp := NewMockPeers()
	role := mp.PeerRole("nonexistent")
	if role != "" {
		t.Errorf("Expected empty role for unknown ID, got %q", role)
	}
}

func TestMockMetrics_LatestCPU(t *testing.T) {
	mm := NewMockMetrics()
	cpu, fresh := mm.LatestCPU(nodeEntryID, 60*time.Second)
	if !fresh {
		t.Error("Expected fresh=true for entry node within 60s")
	}
	if cpu != 23.7 {
		t.Errorf("Expected CPU=23.7, got %f", cpu)
	}
}

func TestMockMetrics_LatestCPU_OfflineNode(t *testing.T) {
	mm := NewMockMetrics()
	cpu, fresh := mm.LatestCPU(nodeOfflineID, 60*time.Second)
	if fresh {
		t.Error("Expected fresh=false for offline node within 60s threshold")
	}
	if cpu != 0 {
		t.Errorf("Expected CPU=0 for offline node, got %f", cpu)
	}
}

func TestMockMetrics_LatestHostname(t *testing.T) {
	mm := NewMockMetrics()
	hostname := mm.LatestHostname(nodeEntryID)
	if hostname != "node-us-east" {
		t.Errorf("Expected hostname 'node-us-east', got %q", hostname)
	}
	// Unknown node
	hostname = mm.LatestHostname("nonexistent")
	if hostname != "" {
		t.Errorf("Expected empty hostname for unknown node, got %q", hostname)
	}
}

func TestMockMetrics_NodeStatus(t *testing.T) {
	mm := NewMockMetrics()
	tests := []struct {
		id       string
		expected string
	}{
		{nodeEntryID, "online"},
		{nodeOfflineID, "offline"},
		{"nonexistent", "offline"},
	}
	for _, tt := range tests {
		got := mm.NodeStatus(tt.id, 60*time.Second)
		if got != tt.expected {
			t.Errorf("NodeStatus(%s) = %q, want %q", tt.id, got, tt.expected)
		}
	}
}

func TestMockMetrics_BestBandwidth(t *testing.T) {
	mm := NewMockMetrics()
	bw := mm.BestBandwidth(nodeEntryID)
	if bw != 940 {
		t.Errorf("Expected bandwidth=940, got %f", bw)
	}
	bw = mm.BestBandwidth("nonexistent")
	if bw != -1 {
		t.Errorf("Expected bandwidth=-1 for unknown, got %f", bw)
	}
}

func TestMockPaths_PeerLatency_Symmetric(t *testing.T) {
	mp := NewMockPaths()
	// Latency should be symmetric
	lat1 := mp.PeerLatency(nodeEntryID, nodeRelayID)
	lat2 := mp.PeerLatency(nodeRelayID, nodeEntryID)
	if lat1 != lat2 {
		t.Errorf("Latency not symmetric: %f vs %f", lat1, lat2)
	}
}

// --- Snapshot edge tests ---

func TestSnapshot_EdgesCount(t *testing.T) {
	snap := DefaultSnapshot()
	if len(snap.Edges) != 5 {
		t.Errorf("Expected 5 edges, got %d", len(snap.Edges))
	}
}

func TestSnapshot_EdgesHaveValidSources(t *testing.T) {
	snap := DefaultSnapshot()
	peers := NewMockPeers()
	for i, e := range snap.Edges {
		if !peers.PeerExists(e.Source) {
			t.Errorf("Edge %d has unknown source %q", i, e.Source)
		}
		if !peers.PeerExists(e.Target) {
			t.Errorf("Edge %d has unknown target %q", i, e.Target)
		}
	}
}

func TestSnapshot_EdgeLatency(t *testing.T) {
	snap := DefaultSnapshot()
	found := false
	for _, e := range snap.Edges {
		if e.Source == nodeEntryID && e.Target == nodeRelayID {
			if e.LatencyMs != 12.5 {
				t.Errorf("Expected latency=12.5, got %f", e.LatencyMs)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("Expected entry→relay edge not found")
	}
}

// --- No proxy import test (G1 from guardrails) ---

func TestNoProxyImport(t *testing.T) {
	// This test exists as documentation. The real check is in CI:
	//   go list -f '{{.Deps}}' ./internal/topology/ | grep -q 'internal/proxy'
	// The topology package only imports stdlib (crypto/sha256, encoding/binary)
	// and its own sub-packages. It must NEVER import internal/proxy.
}
