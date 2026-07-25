// Package mock provides deterministic in-memory implementations of the
// topology interfaces for testing and development.
//
// It implements TopologyPeers, TopologyMetrics, and TopologyPathInfo
// with fixed fake data — 5 nodes with deterministic IDs, roles, positions,
// CPU/mem values, and 5 edges with latency/bandwidth values.
//
// This enables testing the topology API (GET /api/topology, SSE
// /api/topology/events) without a live multi-node mesh.
//
// Enable in production via MOCK_TOPOLOGY=1 env var or ?mock=true query param.
package mock

import (
	"time"

	"github.com/yzy806806/meshdesk/internal/topology"
)

// Compile-time assertions that mock implements all three interfaces.
var (
	_ topology.TopologyPeers    = (*MockPeers)(nil)
	_ topology.TopologyMetrics  = (*MockMetrics)(nil)
	_ topology.TopologyPathInfo = (*MockPaths)(nil)
)

// --- Node definitions ---

// Deterministic fake node IDs (32 hex chars, mimicking WireGuard public keys).
const (
	nodeEntryID   = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	nodeRelayID   = "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
	nodeExitID    = "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"
	nodeDashID    = "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"
	nodeOfflineID = "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
)

// mockNode is a single fake node's static data.
type mockNode struct {
	id        string
	role      string
	hostname  string
	cpu       float64
	mem       float64
	status    string
	bandwidth float64
	ts        time.Time
}

// mockNodes is the deterministic node set (5 nodes).
var mockNodes = map[string]*mockNode{
	nodeEntryID: {
		id:        nodeEntryID,
		role:      "entry",
		hostname:  "node-us-east",
		cpu:       23.7,
		mem:       62.1,
		status:    "online",
		bandwidth: 940,
		ts:        time.Now(),
	},
	nodeRelayID: {
		id:        nodeRelayID,
		role:      "entry+relay",
		hostname:  "node-eu-central",
		cpu:       45.2,
		mem:       71.8,
		status:    "online",
		bandwidth: 1000,
		ts:        time.Now(),
	},
	nodeExitID: {
		id:        nodeExitID,
		role:      "exit",
		hostname:  "node-asia-south",
		cpu:       12.3,
		mem:       38.5,
		status:    "online",
		bandwidth: 500,
		ts:        time.Now(),
	},
	nodeDashID: {
		id:        nodeDashID,
		role:      "dashboard",
		hostname:  "node-local-dash",
		cpu:       5.1,
		mem:       28.0,
		status:    "online",
		bandwidth: 1000,
		ts:        time.Now(),
	},
	nodeOfflineID: {
		id:        nodeOfflineID,
		role:      "relay",
		hostname:  "node-offline-relay",
		cpu:       0,
		mem:       0,
		status:    "offline",
		bandwidth: -1,
		// Timestamp is 2 minutes in the past → stale → offline
		ts: time.Now().Add(-2 * time.Minute),
	},
}

// mockEdge is a single fake edge.
type mockEdge struct {
	source    string
	target    string
	latency   float64
	bandwidth float64
}

// mockEdges is the deterministic edge set (5 edges).
var mockEdges = []mockEdge{
	{source: nodeEntryID, target: nodeRelayID, latency: 12.5, bandwidth: 940},
	{source: nodeRelayID, target: nodeExitID, latency: 89.3, bandwidth: 500},
	{source: nodeEntryID, target: nodeExitID, latency: 156.7, bandwidth: 250},
	{source: nodeDashID, target: nodeEntryID, latency: 2.1, bandwidth: 1000},
	{source: nodeDashID, target: nodeRelayID, latency: 24.8, bandwidth: 940},
}

// --- MockPeers: implements topology.TopologyPeers ---

// MockPeers is a mock implementation of topology.TopologyPeers
// backed by the static node set.
type MockPeers struct {
	positions map[string][3]float64
}

// NewMockPeers creates a MockPeers with deterministic positions
// derived from each node's ID via topology.DerivePosition.
func NewMockPeers() *MockPeers {
	mp := &MockPeers{
		positions: make(map[string][3]float64, len(mockNodes)),
	}
	for id := range mockNodes {
		x, y, z := topology.DerivePosition(id)
		mp.positions[id] = [3]float64{x, y, z}
	}
	return mp
}

// AllPeerIDs returns all 5 mock node IDs.
func (m *MockPeers) AllPeerIDs() []string {
	ids := make([]string, 0, len(mockNodes))
	for id := range mockNodes {
		ids = append(ids, id)
	}
	return ids
}

// PeerExists reports whether the given ID is one of the 5 mock nodes.
func (m *MockPeers) PeerExists(peerID string) bool {
	_, ok := mockNodes[peerID]
	return ok
}

// PeerRole returns the role string for the given node ID.
// Returns "" if the ID is unknown.
func (m *MockPeers) PeerRole(peerID string) string {
	node, ok := mockNodes[peerID]
	if !ok {
		return ""
	}
	return node.role
}

// Position returns the deterministic 3D position for the given node.
// Uses pre-computed positions from topology.DerivePosition.
// Returns (0, 0, 0) if the node is unknown.
func (m *MockPeers) Position(peerID string) (x, y, z float64) {
	pos, ok := m.positions[peerID]
	if !ok {
		return 0, 0, 0
	}
	return pos[0], pos[1], pos[2]
}

// --- MockMetrics: implements topology.TopologyMetrics ---

// MockMetrics is a mock implementation of topology.TopologyMetrics
// backed by the static node set.
type MockMetrics struct{}

// NewMockMetrics creates a MockMetrics.
func NewMockMetrics() *MockMetrics {
	return &MockMetrics{}
}

// LatestCPU returns the node's CPU usage and whether it's fresh.
// Offline nodes return (0, false). Unknown nodes return (0, false).
func (m *MockMetrics) LatestCPU(nodeID string, freshnessThreshold time.Duration) (float64, bool) {
	node, ok := mockNodes[nodeID]
	if !ok {
		return 0, false
	}
	if time.Since(node.ts) > freshnessThreshold {
		return 0, false
	}
	return node.cpu, true
}

// LatestMem returns the node's memory usage percentage and whether it's fresh.
// Offline nodes return (0, false). Unknown nodes return (0, false).
func (m *MockMetrics) LatestMem(nodeID string, freshnessThreshold time.Duration) (float64, bool) {
	node, ok := mockNodes[nodeID]
	if !ok {
		return 0, false
	}
	if time.Since(node.ts) > freshnessThreshold {
		return 0, false
	}
	return node.mem, true
}

// LatestHostname returns the node's hostname, or "" if unknown.
func (m *MockMetrics) LatestHostname(nodeID string) string {
	node, ok := mockNodes[nodeID]
	if !ok {
		return ""
	}
	return node.hostname
}

// NodeStatus returns "online" or "offline" based on metric freshness.
func (m *MockMetrics) NodeStatus(nodeID string, freshnessThreshold time.Duration) string {
	node, ok := mockNodes[nodeID]
	if !ok {
		return "offline"
	}
	if time.Since(node.ts) > freshnessThreshold {
		return "offline"
	}
	return node.status
}

// BestBandwidth returns the node's bandwidth, or -1 if unknown.
func (m *MockMetrics) BestBandwidth(nodeID string) float64 {
	node, ok := mockNodes[nodeID]
	if !ok {
		return -1
	}
	return node.bandwidth
}

// --- MockPaths: implements topology.TopologyPathInfo ---

// MockPaths is a mock implementation of topology.TopologyPathInfo
// backed by the static edge set.
type MockPaths struct {
	latencies map[string]float64 // "src→dst" → latency
}

// NewMockPaths creates a MockPaths with deterministic latency data.
func NewMockPaths() *MockPaths {
	mp := &MockPaths{
		latencies: make(map[string]float64, len(mockEdges)*2),
	}
	for _, e := range mockEdges {
		// Store both directions (latency is symmetric).
		mp.latencies[e.source+"→"+e.target] = e.latency
		mp.latencies[e.target+"→"+e.source] = e.latency
	}
	return mp
}

// PeerLatency returns the latency between two nodes, or -1 if no edge exists.
func (m *MockPaths) PeerLatency(sourceID, targetID string) float64 {
	lat, ok := m.latencies[sourceID+"→"+targetID]
	if !ok {
		return -1
	}
	return lat
}

// --- Snapshot helper ---

// Snapshot builds a complete TopologySnapshot from the mock data.
// This is the primary entry point for tests and the mock-mode handler.
func Snapshot(peers topology.TopologyPeers, metrics topology.TopologyMetrics, paths topology.TopologyPathInfo) topology.TopologySnapshot {
	nodes := make([]topology.TopologyNode, 0, len(mockNodes))
	ids := peers.AllPeerIDs()
	for _, id := range ids {
		x, y, z := peers.Position(id)
		cpu, _ := metrics.LatestCPU(id, 60*time.Second)
		mem, _ := metrics.LatestMem(id, 60*time.Second)
		nodes = append(nodes, topology.TopologyNode{
			ID:       id,
			Role:     peers.PeerRole(id),
			X:        x,
			Y:        y,
			Z:        z,
			CPU:      cpu,
			Mem:      mem,
			Hostname: metrics.LatestHostname(id),
			Status:   metrics.NodeStatus(id, 60*time.Second),
		})
	}

	edges := make([]topology.TopologyEdge, 0, len(mockEdges))
	for _, e := range mockEdges {
		edges = append(edges, topology.TopologyEdge{
			Source:        e.source,
			Target:        e.target,
			LatencyMs:     paths.PeerLatency(e.source, e.target),
			BandwidthMbps: metrics.BestBandwidth(e.source),
		})
	}

	return topology.TopologySnapshot{
		Nodes: nodes,
		Edges: edges,
	}
}

// DefaultSnapshot is a convenience function that builds a snapshot
// from all three mock implementations. Useful for quick tests.
func DefaultSnapshot() topology.TopologySnapshot {
	return Snapshot(NewMockPeers(), NewMockMetrics(), NewMockPaths())
}
