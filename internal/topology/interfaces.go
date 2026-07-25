// Package topology defines the stable read-only interfaces that the
// topology API consumes. These interfaces are implemented by existing
// packages (mesh, monitor, proxy) and MUST NOT introduce new
// dependencies into those packages.
package topology

import (
	"time"
)

// TopologyPeers provides a read-only view of mesh peers needed for
// topology visualization. Implemented by mesh.RoutingTable.
type TopologyPeers interface {
	// AllPeerIDs returns the IDs of all known mesh peers.
	// The order is non-deterministic; callers sort if needed.
	AllPeerIDs() []string

	// PeerExists reports whether a peer with the given ID is in
	// the routing table.
	PeerExists(peerID string) bool

	// PeerRole returns the node's role string (e.g. "entry+relay").
	// Returns "" if the peer is unknown.
	PeerRole(peerID string) string

	// Position returns the 3D display position for a node.
	// Position (0,0,0) is the default — the caller assumes no
	// explicit position has been set.
	Position(peerID string) (x, y, z float64)
}

// TopologyMetrics provides a read-only view of per-node system metrics
// for topology visualization. Implemented by monitor.Store.
type TopologyMetrics interface {
	// LatestCPU returns the node's latest CPU usage (0-100) and
	// whether a recent measurement exists (updated within the
	// last freshnessThreshold). Returns (0, false) for unknown nodes.
	LatestCPU(nodeID string, freshnessThreshold time.Duration) (float64, bool)

	// LatestMem returns the node's latest memory usage (0-100) and
	// freshness. Returns (0, false) for unknown nodes.
	LatestMem(nodeID string, freshnessThreshold time.Duration) (float64, bool)

	// LatestHostname returns the node's hostname.
	// Returns "" if unknown.
	LatestHostname(nodeID string) string

	// NodeStatus returns whether a node is "online" (metrics within
	// freshnessThreshold) or "offline".
	NodeStatus(nodeID string, freshnessThreshold time.Duration) string

	// BestBandwidth returns the highest SpeedMbps across all network
	// interfaces for a node, or -1 if unknown.
	BestBandwidth(nodeID string) float64
}

// TopologyPathInfo provides a read-only view of inter-node path
// measurements for topology edges. Implemented by a thin adapter
// over proxy path selection probe results.
type TopologyPathInfo interface {
	// PeerLatency returns the latest measured RTT between two nodes
	// in milliseconds. Returns -1 if no measurement exists.
	PeerLatency(sourceID, targetID string) float64
}
