// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the CircuitManager — the central orchestrator for
// circuit lifecycle management in the multi-path dispersed proxy.
//
// It owns:
//  1. Path selection — finds two node-disjoint paths from entry to exit
//     using the mesh latency matrix (Dijkstra k-shortest, k=2) with
//     probe-based fallback.
//  2. Chunk-to-path assignment — distributes chunks across the two paths
//     using a pluggable strategy (round-robin, weighted by path quality,
//     fastest-only).
//  3. Circuit lifecycle — manages the full FSM: creation, active tracking
//     (keepalive RTT, path health), teardown (flush in-flight chunks, send
//     ChunkStreamEnd markers), and resource cleanup (zero keys, free buffers).
//
// Design spec: docs/CIRCUIT_MANAGER_SPEC.md
// Design decisions: Dijkstra for weighted graph (Decision 1), single-hop
// for v1 (Decision 2), co-located in internal/proxy/ (Decision 3),
// CircuitManager owns all key lifecycle (Decision 4).
package proxy

import (
	"container/heap"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Data Model — MeshLatencyMatrix
// ──────────────────────────────────────────────────────────────────────────────

// NodeRole classifies a mesh node's function in the proxy topology.
type NodeRole string

const (
	NodeRoleEntry    NodeRole = "entry"
	NodeRoleRelay    NodeRole = "relay"
	NodeRoleExit     NodeRole = "exit"
	NodeRoleStandard NodeRole = "standard"
)

// NodeStatus indicates a mesh node's current availability.
type NodeStatus string

const (
	NodeStatusOnline   NodeStatus = "online"
	NodeStatusOffline  NodeStatus = "offline"
	NodeStatusDegraded NodeStatus = "degraded"
)

// NodeCapability is a capability string advertised by a mesh node.
type NodeCapability string

const (
	CapRelay NodeCapability = "relay"
	CapExit  NodeCapability = "exit"
)

// NodeInfo holds metadata for a mesh node in the latency matrix.
type NodeInfo struct {
	ID           string
	Hostname     string
	MeshAddr     string
	Role         NodeRole
	Capabilities []NodeCapability
	Status       NodeStatus
}

// EdgeSource indicates where a latency edge measurement came from.
type EdgeSource string

const (
	EdgeProbe     EdgeSource = "probe"
	EdgeGossip    EdgeSource = "gossip"
	EdgeKeepalive EdgeSource = "keepalive"
)

// LatencyEdge represents a weighted connection between two mesh nodes.
type LatencyEdge struct {
	Source       string
	Target       string
	RTTms        float64
	BandwidthBps int64
	MeasuredAt   time.Time
	SourceType   EdgeSource
}

// MeshLatencyMatrix is the weighted undirected graph representing the mesh.
// Nodes are mesh peers; edges are peer-to-peer connections with measured RTT.
type MeshLatencyMatrix struct {
	mu        sync.RWMutex
	nodes     map[string]NodeInfo
	edges     map[string]map[string]LatencyEdge // source → target → edge
	updatedAt time.Time
}

// NewMeshLatencyMatrix creates an empty latency matrix.
func NewMeshLatencyMatrix() *MeshLatencyMatrix {
	return &MeshLatencyMatrix{
		nodes: make(map[string]NodeInfo),
		edges: make(map[string]map[string]LatencyEdge),
	}
}

// AddNode adds or updates a node in the matrix.
func (m *MeshLatencyMatrix) AddNode(n NodeInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[n.ID] = n
	m.updatedAt = time.Now()
}

// AddEdge adds or updates a bidirectional latency edge. Both endpoints
// must already exist in the matrix (call AddNode first).
func (m *MeshLatencyMatrix) AddEdge(e LatencyEdge) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.edges[e.Source] == nil {
		m.edges[e.Source] = make(map[string]LatencyEdge)
	}
	if m.edges[e.Target] == nil {
		m.edges[e.Target] = make(map[string]LatencyEdge)
	}
	m.edges[e.Source][e.Target] = e
	// Reverse edge (undirected graph).
	m.edges[e.Target][e.Source] = LatencyEdge{
		Source:       e.Target,
		Target:       e.Source,
		RTTms:        e.RTTms,
		BandwidthBps: e.BandwidthBps,
		MeasuredAt:   e.MeasuredAt,
		SourceType:   e.SourceType,
	}
	m.updatedAt = time.Now()
}

// MergeEdges adds or updates multiple edges atomically.
func (m *MeshLatencyMatrix) MergeEdges(edges []LatencyEdge) {
	for _, e := range edges {
		m.AddEdge(e)
	}
}

// GetNode returns node info, or false if not found.
func (m *MeshLatencyMatrix) GetNode(id string) (NodeInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.nodes[id]
	return n, ok
}

// Neighbors returns the edges from a given node.
func (m *MeshLatencyMatrix) Neighbors(nodeID string) map[string]LatencyEdge {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if edges, ok := m.edges[nodeID]; ok {
		// Return a copy to avoid races.
		cp := make(map[string]LatencyEdge, len(edges))
		for k, v := range edges {
			cp[k] = v
		}
		return cp
	}
	return nil
}

// EdgeWeight returns the RTT weight for an edge. Unmeasured edges (RTT=0)
// get a 500ms penalty (spec §2.1).
func (m *MeshLatencyMatrix) EdgeWeight(source, target string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if edges, ok := m.edges[source]; ok {
		if e, ok := edges[target]; ok {
			if e.RTTms > 0 {
				return e.RTTms
			}
			return 500.0 // penalty for unmeasured
		}
	}
	// No edge — return infinity (no connection).
	return math.Inf(1)
}

// RelayNodes returns all nodes with the "relay" capability.
func (m *MeshLatencyMatrix) RelayNodes() []NodeInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []NodeInfo
	for _, n := range m.nodes {
		for _, c := range n.Capabilities {
			if c == CapRelay {
				result = append(result, n)
				break
			}
		}
	}
	return result
}

// RelayCount returns the number of relay-capable nodes with known RTT edges
// to a given node (entry or exit).
func (m *MeshLatencyMatrix) RelayCountWithRTT(nodeID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for id, n := range m.nodes {
		if id == nodeID {
			continue
		}
		isRelay := false
		for _, c := range n.Capabilities {
			if c == CapRelay {
				isRelay = true
				break
			}
		}
		if !isRelay {
			continue
		}
		if edges, ok := m.edges[nodeID]; ok {
			if e, ok := edges[id]; ok && e.RTTms > 0 {
				count++
			}
		}
	}
	return count
}

// UpdatedAt returns the last update timestamp.
func (m *MeshLatencyMatrix) UpdatedAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.updatedAt
}

// ──────────────────────────────────────────────────────────────────────────────
// Data Model — Circuit and CircuitPath
// ──────────────────────────────────────────────────────────────────────────────

// CircuitIDType is the 16-byte circuit identifier type.
type CircuitIDType = [CircuitIDSize]byte

// PathHealthState tracks the health FSM for a single path.
type PathHealthState int

const (
	PathHealthHealthy   PathHealthState = iota
	PathHealthDegraded                  // 2 missed keepalives (20s)
	PathHealthUnhealthy                 // 4 missed keepalives (40s)
)

// CircuitPath represents one of the two paths a circuit uses.
type CircuitPath struct {
	Index            int           // 0 or 1
	Hops             []string      // relay node IDs in order (entry→relay₁→...→exit)
	RelayKeys        [][]byte      // per-hop onion header keys, one per relay
	TotalChunks      uint64        // chunks dispatched on this path
	TotalBytes       uint64        // bytes dispatched on this path
	LastRTT          time.Duration // last measured RTT from keepalive
	Health           PathHealthState
	MissedKeepalives int // consecutive missed keepalive responses
	EstablishedAt    time.Time

	mu sync.Mutex
}

// Healthy returns true if the path is usable for new chunk dispatch.
func (p *CircuitPath) Healthy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Health != PathHealthUnhealthy
}

// RecordChunk updates path statistics when a chunk is dispatched.
func (p *CircuitPath) RecordChunk(byteCount int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.TotalChunks++
	p.TotalBytes += uint64(byteCount)
}

// RecordRTT updates the path's last measured RTT and resets missed count.
func (p *CircuitPath) RecordRTT(rtt time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastRTT = rtt
	p.MissedKeepalives = 0
	p.Health = PathHealthHealthy
}

// MissKeepalive increments the missed keepalive counter and transitions
// health state per the spec FSM:
//
//	HEALTHY → DEGRADED after 2 missed (20s)
//	DEGRADED → UNHEALTHY after 4 total missed (40s)
func (p *CircuitPath) MissKeepalive(keepaliveInterval time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.MissedKeepalives++
	// Health FSM per spec §4.4:
	//   HEALTHY → DEGRADED after 2 missed keepalives (20s at 10s timeout)
	//   DEGRADED → UNHEALTHY after 4 total missed (40s)
	if p.MissedKeepalives >= 4 {
		p.Health = PathHealthUnhealthy
	} else if p.MissedKeepalives >= 2 {
		p.Health = PathHealthDegraded
	}
}

// ZeroKeys zeroes all relay keys on this path.
func (p *CircuitPath) ZeroKeys() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.RelayKeys {
		for j := range p.RelayKeys[i] {
			p.RelayKeys[i][j] = 0
		}
	}
}

// Circuit represents a single proxy circuit with two paths.
type Circuit struct {
	ID           CircuitIDType
	State        CircuitState
	CreatedAt    time.Time
	LastActivity time.Time

	Entry      string
	Exit       string
	TargetAddr string

	E2EKey      [KeySize]byte // zeroed on teardown
	PaddingSeed [32]byte      // zeroed on teardown

	Paths              [2]*CircuitPath
	AssignmentStrategy ChunkAssignmentStrategy

	KeepaliveInterval time.Duration
	IdleTimeout       time.Duration

	// nextPathIndex is used by round-robin assignment.
	nextPathIndex int

	mu sync.RWMutex
}

// CircuitInfo is a read-only snapshot of a circuit for the topology API.
type CircuitInfo struct {
	ID              string
	State           string
	Entry           string
	Exit            string
	Target          string
	Paths           []PathInfo
	AgeSeconds      int64
	BytesDispatched uint64
}

// PathInfo is a read-only snapshot of a circuit path.
type PathInfo struct {
	Hops      []string
	LatencyMs float64
	Chunks    uint64
	Healthy   bool
}

// ToInfo returns a read-only snapshot of the circuit.
func (c *Circuit) ToInfo() CircuitInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	paths := make([]PathInfo, 0, 2)
	for _, p := range c.Paths {
		if p == nil {
			continue
		}
		p.mu.Lock()
		paths = append(paths, PathInfo{
			Hops:      append([]string{}, p.Hops...),
			LatencyMs: float64(p.LastRTT.Milliseconds()),
			Chunks:    p.TotalChunks,
			Healthy:   p.Health != PathHealthUnhealthy,
		})
		p.mu.Unlock()
	}

	return CircuitInfo{
		ID:              fmt.Sprintf("%x", c.ID[:]),
		State:           circuitStateName(c.State),
		Entry:           c.Entry,
		Exit:            c.Exit,
		Target:          c.TargetAddr,
		Paths:           paths,
		AgeSeconds:      int64(time.Since(c.CreatedAt).Seconds()),
		BytesDispatched: c.Paths[0].TotalChunks + c.Paths[1].TotalChunks, // simplified
	}
}

// circuitStateName converts a CircuitState to a human-readable string.
func circuitStateName(s CircuitState) string {
	switch s {
	case CircuitCreating:
		return "creating"
	case CircuitActive:
		return "active"
	case CircuitTeardown:
		return "teardown"
	case CircuitClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// UpdateActivity records that data was sent/received on this circuit.
func (c *Circuit) UpdateActivity() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastActivity = time.Now()
}

// IsIdle returns true if the circuit has been idle longer than IdleTimeout.
func (c *Circuit) IsIdle() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.LastActivity) > c.IdleTimeout
}

// BothPathsUnhealthy returns true if both paths are in UNHEALTHY state.
func (c *Circuit) BothPathsUnhealthy() bool {
	return !c.Paths[0].Healthy() && !c.Paths[1].Healthy()
}

// AssignPath delegates to the circuit's assignment strategy.
func (c *Circuit) AssignPath() int {
	c.mu.Lock()
	idx := c.nextPathIndex
	c.nextPathIndex++
	c.mu.Unlock()
	return c.AssignmentStrategy.AssignPath(c, idx)
}

// ZeroKeys zeroes E2E key, padding seed, and all relay keys.
// Called on circuit close to prevent key material leakage (AC-CL-07, AC-SE-04).
func (c *Circuit) ZeroKeys() {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Zero E2E key.
	for i := range c.E2EKey {
		c.E2EKey[i] = 0
	}
	// Zero padding seed.
	for i := range c.PaddingSeed {
		c.PaddingSeed[i] = 0
	}
	// Zero per-path relay keys.
	for _, p := range c.Paths {
		if p != nil {
			p.ZeroKeys()
		}
	}
}

// KeysZeroed returns true if E2E key and padding seed are all zeros.
// Used for verifying key zeroing in tests (AC-CL-07, AC-SE-04).
func (c *Circuit) KeysZeroed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, b := range c.E2EKey {
		if b != 0 {
			return false
		}
	}
	for _, b := range c.PaddingSeed {
		if b != 0 {
			return false
		}
	}
	return true
}

// ──────────────────────────────────────────────────────────────────────────────
// Chunk Assignment Strategy Interface
// ──────────────────────────────────────────────────────────────────────────────

// ChunkAssignmentStrategy determines which path carries the next chunk.
// The circuit provides path health and latency data for weighted decisions.
type ChunkAssignmentStrategy interface {
	// AssignPath returns 0 or 1 — which path should carry the next chunk.
	// The callCount parameter is the number of chunks previously assigned
	// (for round-robin toggling).
	AssignPath(c *Circuit, callCount int) int

	// Name returns a human-readable strategy name for config/logging.
	Name() string
}

// ──────────────────────────────────────────────────────────────────────────────
// Concrete Strategies
// ──────────────────────────────────────────────────────────────────────────────

// RoundRobinStrategy alternates chunks between the two paths.
// This is the v1 default (AC-CA-01).
// When one path is unhealthy, it routes all chunks to the healthy path (AC-CA-04).
type RoundRobinStrategy struct{}

func (s *RoundRobinStrategy) AssignPath(c *Circuit, callCount int) int {
	// Check path health — route to healthy path if one is down (AC-CA-04).
	p0Healthy := c.Paths[0].Healthy()
	p1Healthy := c.Paths[1].Healthy()
	if !p0Healthy && p1Healthy {
		return 1
	}
	if !p1Healthy && p0Healthy {
		return 0
	}
	// Both healthy or both unhealthy — round-robin.
	return callCount % 2
}

func (s *RoundRobinStrategy) Name() string { return "round-robin" }

// WeightedStrategy assigns chunks proportionally to inverse latency.
// Faster path gets more chunks. Falls back to round-robin when no RTT
// data is available (AC-CA-02, AC-CA-03).
type WeightedStrategy struct{}

// NewWeightedStrategy creates a weighted strategy.
func NewWeightedStrategy() *WeightedStrategy {
	return &WeightedStrategy{}
}

// cryptoRandFloat returns a cryptographically random float64 in [0, 1).
func cryptoRandFloat() float64 {
	var buf [8]byte
	rand.Read(buf[:])
	// Use the top 53 bits for a float64 in [0, 1).
	bits := binary.LittleEndian.Uint64(buf[:]) >> (64 - 53)
	return float64(bits) / (1 << 53)
}

func (s *WeightedStrategy) AssignPath(c *Circuit, callCount int) int {
	p0 := c.Paths[0]
	p1 := c.Paths[1]

	// If one path is unhealthy, route all to the healthy one (AC-CA-04).
	if !p0.Healthy() && p1.Healthy() {
		return 1
	}
	if !p1.Healthy() && p0.Healthy() {
		return 0
	}
	// Both unhealthy — round-robin as fallback.
	if !p0.Healthy() && !p1.Healthy() {
		return callCount % 2
	}

	rttA := p0.LastRTT
	rttB := p1.LastRTT

	// If both unmeasured, fall back to round-robin (AC-CA-03).
	if rttA == 0 && rttB == 0 {
		return callCount % 2
	}

	// Handle single unmeasured path — treat as equal weight.
	if rttA == 0 {
		rttA = rttB
	}
	if rttB == 0 {
		rttB = rttA
	}

	// Weight by inverse latency: p(path_0) = rtt_1 / (rtt_0 + rtt_1).
	// Faster path gets larger weight.
	weightA := float64(rttB) / float64(rttA+rttB)
	if cryptoRandFloat() < weightA {
		return 0
	}
	return 1
}

func (s *WeightedStrategy) Name() string { return "weighted" }

// FastestOnlyStrategy uses only the fastest (lowest RTT) path.
// Falls back to the other path if the primary is unhealthy.
type FastestOnlyStrategy struct{}

func (s *FastestOnlyStrategy) AssignPath(c *Circuit, callCount int) int {
	p0 := c.Paths[0]
	p1 := c.Paths[1]

	// If one path is unhealthy, use the other (AC-CA-04).
	if !p0.Healthy() && p1.Healthy() {
		return 1
	}
	if !p1.Healthy() && p0.Healthy() {
		return 0
	}

	rttA := p0.LastRTT
	rttB := p1.LastRTT

	// If both unmeasured, round-robin.
	if rttA == 0 && rttB == 0 {
		return callCount % 2
	}
	if rttA == 0 {
		return 1 // path 0 unmeasured, prefer path 1
	}
	if rttB == 0 {
		return 0
	}
	if rttA <= rttB {
		return 0
	}
	return 1
}

func (s *FastestOnlyStrategy) Name() string { return "fastest-only" }

// NewChunkAssignmentStrategy creates a strategy by name.
func NewChunkAssignmentStrategy(name string) ChunkAssignmentStrategy {
	switch name {
	case "weighted":
		return NewWeightedStrategy()
	case "fastest-only":
		return &FastestOnlyStrategy{}
	default:
		return &RoundRobinStrategy{}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Path Selection — Dijkstra k-Shortest Node-Disjoint Paths
// ──────────────────────────────────────────────────────────────────────────────

// dijkstraNode is a min-heap entry for Dijkstra's algorithm.
type dijkstraNode struct {
	dist  float64
	node  string
	index int
}

// dijkstraHeap implements heap.Interface for a min-heap by dist.
type dijkstraHeap []*dijkstraNode

func (h dijkstraHeap) Len() int           { return len(h) }
func (h dijkstraHeap) Less(i, j int) bool { return h[i].dist < h[j].dist }
func (h dijkstraHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *dijkstraHeap) Push(x interface{}) {
	n := len(*h)
	item := x.(*dijkstraNode)
	item.index = n
	*h = append(*h, item)
}
func (h *dijkstraHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return item
}

// ShortestPath finds the lowest-cost path from source to target using
// Dijkstra's algorithm on the latency-weighted graph. blocked is a set
// of node IDs to exclude (for disjointness). Returns nil if no path.
//
// Unmeasured edges (RTT=0) get a 500ms penalty (AC-PS-04).
func ShortestPath(matrix *MeshLatencyMatrix, source, target string, blocked map[string]bool) []string {
	if blocked[source] || blocked[target] {
		return nil
	}

	dist := map[string]float64{source: 0}
	prev := map[string]string{}
	visited := map[string]bool{}

	pq := &dijkstraHeap{}
	heap.Init(pq)
	heap.Push(pq, &dijkstraNode{dist: 0, node: source})

	for pq.Len() > 0 {
		cur := heap.Pop(pq).(*dijkstraNode)
		u := cur.node

		if visited[u] {
			continue
		}
		visited[u] = true

		if u == target {
			break
		}

		neighbors := matrix.Neighbors(u)
		for v, edge := range neighbors {
			if blocked[v] || visited[v] {
				continue
			}
			weight := edge.RTTms
			if weight == 0 {
				weight = 500.0 // penalty for unmeasured (AC-PS-04)
			}
			alt := dist[u] + weight
			if d, ok := dist[v]; !ok || alt < d {
				dist[v] = alt
				prev[v] = u
				heap.Push(pq, &dijkstraNode{dist: alt, node: v})
			}
		}
	}

	if _, ok := dist[target]; !ok {
		return nil
	}

	// Reconstruct path.
	var path []string
	cur := target
	for cur != "" {
		path = append([]string{cur}, path...)
		if cur == source {
			break
		}
		cur = prev[cur]
	}
	if len(path) == 0 || path[0] != source {
		return nil
	}
	return path
}

// KShortestDisjointPaths finds k=2 node-disjoint paths from source to target
// that minimize total latency. After finding each path, the relay nodes
// (intermediate, excluding source and target) are added to the blocked set
// so the next path cannot use them.
//
// Returns an error if fewer than k disjoint paths can be found (AC-EH-01).
func KShortestDisjointPaths(matrix *MeshLatencyMatrix, source, target string, k int) ([][]string, error) {
	paths := make([][]string, 0, k)
	blocked := make(map[string]bool)

	for i := 0; i < k; i++ {
		path := ShortestPath(matrix, source, target, blocked)
		if path == nil {
			break
		}
		paths = append(paths, path)
		// Block relay nodes (exclude source and target).
		for j := 1; j < len(path)-1; j++ {
			blocked[path[j]] = true
		}
	}

	if len(paths) < k {
		return nil, ErrNoPaths
	}

	// Verify disjointness: no relay node appears on two paths.
	relaySet := make(map[string]int)
	for _, path := range paths {
		seen := map[string]bool{}
		for j := 1; j < len(path)-1; j++ {
			if !seen[path[j]] {
				relaySet[path[j]]++
				seen[path[j]] = true
			}
		}
	}
	for _, count := range relaySet {
		if count > 1 {
			return nil, ErrPathOverlap
		}
	}

	return paths, nil
}

// PathsHaveOverlap returns true if two paths share any relay node
// (excluding entry and exit endpoints).
func PathsHaveOverlap(pathA, pathB []string) bool {
	relaysA := make(map[string]bool)
	for i := 1; i < len(pathA)-1; i++ {
		relaysA[pathA[i]] = true
	}
	for i := 1; i < len(pathB)-1; i++ {
		if relaysA[pathB[i]] {
			return true
		}
	}
	return false
}

// ──────────────────────────────────────────────────────────────────────────────
// Circuit Events
// ──────────────────────────────────────────────────────────────────────────────

// CircuitEventType classifies a circuit lifecycle event.
type CircuitEventType int

const (
	EventCircuitCreated CircuitEventType = iota
	EventCircuitEstablished
	EventCircuitTeardownInitiated
	EventCircuitClosed
	EventPathDegraded
	EventPathRestored
	EventPathUnhealthy
	EventKeepaliveTimeout
	EventNACKReceived
)

// CircuitEvent is a lifecycle notification emitted by CircuitManager.
type CircuitEvent struct {
	Type      CircuitEventType
	CircuitID CircuitIDType
	Timestamp time.Time
	Data      interface{}
}

// CircuitEventCallback is called when a circuit event fires.
type CircuitEventCallback func(event CircuitEvent)

// ──────────────────────────────────────────────────────────────────────────────
// Circuit Stats
// ──────────────────────────────────────────────────────────────────────────────

// CircuitStats holds aggregate circuit metrics.
type CircuitStats struct {
	TotalCreated          uint64
	TotalClosed           uint64
	Active                int
	TearingDown           int
	TotalChunksDispatched uint64
	TotalBytesDispatched  uint64
	AvgCircuitLifetime    time.Duration
}

// ──────────────────────────────────────────────────────────────────────────────
// CircuitManager Configuration
// ──────────────────────────────────────────────────────────────────────────────

// CircuitManagerConfig holds all configuration for the CircuitManager.
type CircuitManagerConfig struct {
	// Path selection
	PathCount         int
	SelectionStrategy string // "bfs" | "probe" | "auto"
	MaxCandidates     int
	ProbeTimeout      time.Duration
	MinCandidates     int

	// Chunk assignment
	ChunkAssignment string // "round-robin" | "weighted" | "fastest-only"

	// Lifecycle
	SetupTimeout            time.Duration
	IdleTimeout             time.Duration
	KeepaliveInterval       time.Duration
	FlushTimeout            time.Duration
	OrphanTimeout           time.Duration
	StreamReassemblyTimeout time.Duration
	NACKTimeout             time.Duration
	MaxNACKRetries          int

	// Path health
	KeepaliveTimeout     time.Duration
	KeepaliveDeadTimeout time.Duration

	// DoS protection
	MaxReassemblyWindow int
	MaxCircuitsPerExit  int
	MaxCircuitsTotal    int

	// Mesh transport
	ExitAddr string
	DialFunc func(ctx context.Context, network, address string) (net.Conn, error)
}

// DefaultCircuitManagerConfig returns sensible defaults matching the spec.
func DefaultCircuitManagerConfig() CircuitManagerConfig {
	return CircuitManagerConfig{
		PathCount:               2,
		SelectionStrategy:       "auto",
		MaxCandidates:           10,
		ProbeTimeout:            3 * time.Second,
		MinCandidates:           2,
		ChunkAssignment:         "round-robin",
		SetupTimeout:            10 * time.Second,
		IdleTimeout:             5 * time.Minute,
		KeepaliveInterval:       30 * time.Second,
		FlushTimeout:            10 * time.Second,
		OrphanTimeout:           30 * time.Second,
		StreamReassemblyTimeout: 60 * time.Second,
		NACKTimeout:             5 * time.Second,
		MaxNACKRetries:          3,
		KeepaliveTimeout:        10 * time.Second,
		KeepaliveDeadTimeout:    40 * time.Second,
		MaxReassemblyWindow:     256,
		MaxCircuitsPerExit:      1024,
		MaxCircuitsTotal:        4096,
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────────────

var (
	ErrNoPaths         = errors.New("insufficient disjoint paths available")
	ErrPathOverlap     = errors.New("candidate paths share relay nodes")
	ErrSetupTimeout    = errors.New("circuit setup timeout")
	ErrTooManyCircuits = errors.New("maximum circuit limit reached")
)

// ──────────────────────────────────────────────────────────────────────────────
// CircuitManager
// ──────────────────────────────────────────────────────────────────────────────

// CircuitManager is the central orchestrator for circuit lifecycle management.
// It owns path selection, chunk assignment, circuit tracking, keepalive,
// teardown with flush, and key zeroing.
//
// All mutations go through CircuitManager methods which internalize
// synchronization (spec §8 Concurrency Model).
type CircuitManager struct {
	cfg    CircuitManagerConfig
	matrix *MeshLatencyMatrix
	probe  *PathSelector // for probe-based fallback

	mu             sync.RWMutex
	circuits       map[CircuitIDType]*Circuit
	circuitsByExit map[string][]CircuitIDType
	stats          CircuitStats

	eventCb CircuitEventCallback

	ctx    context.Context
	cancel context.CancelFunc
}

// NewCircuitManager creates a new CircuitManager with the given config.
func NewCircuitManager(cfg CircuitManagerConfig) *CircuitManager {
	if cfg.PathCount <= 0 {
		cfg.PathCount = 2
	}
	if cfg.MinCandidates <= 0 {
		cfg.MinCandidates = 2
	}
	if cfg.MaxCandidates <= 0 {
		cfg.MaxCandidates = 10
	}
	if cfg.ChunkAssignment == "" {
		cfg.ChunkAssignment = "round-robin"
	}
	if cfg.SelectionStrategy == "" {
		cfg.SelectionStrategy = "auto"
	}

	matrix := NewMeshLatencyMatrix()

	ctx, cancel := context.WithCancel(context.Background())

	cm := &CircuitManager{
		cfg:            cfg,
		matrix:         matrix,
		circuits:       make(map[CircuitIDType]*Circuit),
		circuitsByExit: make(map[string][]CircuitIDType),
		ctx:            ctx,
		cancel:         cancel,
	}

	// Initialize probe-based selector for fallback.
	probeCfg := PathSelectorConfig{
		MaxRelaysPerPath: 2,
		ProbeTimeout:     cfg.ProbeTimeout,
		ProbeConcurrency: 8,
		MinCandidates:    cfg.MinCandidates,
		MaxCandidates:    cfg.MaxCandidates,
		PathCount:        cfg.PathCount,
		DialFunc: func(ctx context.Context, addr string) (time.Duration, error) {
			if cfg.DialFunc == nil {
				start := time.Now()
				dialer := &net.Dialer{Timeout: cfg.ProbeTimeout}
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				if err != nil {
					return 0, err
				}
				conn.Close()
				return time.Since(start), nil
			}
			start := time.Now()
			conn, err := cfg.DialFunc(ctx, "tcp", addr)
			if err != nil {
				return 0, err
			}
			conn.Close()
			return time.Since(start), nil
		},
	}
	cm.probe = NewPathSelector(probeCfg)

	return cm
}

// GetLatencyMatrix returns the mesh latency matrix (AC-IN-04).
func (cm *CircuitManager) GetLatencyMatrix() *MeshLatencyMatrix {
	return cm.matrix
}

// UpdateLatencyMatrix merges new latency data from gossip/probes (AC-IN-04).
func (cm *CircuitManager) UpdateLatencyMatrix(edges []LatencyEdge) {
	cm.matrix.MergeEdges(edges)
}

// OnCircuitEvent registers a callback for circuit lifecycle events
// (AC-TO-02).
func (cm *CircuitManager) OnCircuitEvent(cb CircuitEventCallback) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.eventCb = cb
}

// emitEvent fires a circuit event to the registered callback.
func (cm *CircuitManager) emitEvent(typ CircuitEventType, cid CircuitIDType, data interface{}) {
	cm.mu.RLock()
	cb := cm.eventCb
	cm.mu.RUnlock()
	if cb != nil {
		cb(CircuitEvent{
			Type:      typ,
			CircuitID: cid,
			Timestamp: time.Now(),
			Data:      data,
		})
	}
}

// selectPaths selects two disjoint paths from entry to exit.
// Strategy decision (spec §2.2):
//   - "bfs": Use Dijkstra k-shortest on the latency matrix.
//   - "probe": Use probe-based PathSelector.
//   - "auto": BFS if matrix has ≥MinCandidates relays with RTT; else probe.
func (cm *CircuitManager) selectPaths(ctx context.Context, entryID, exitID string, candidates []CandidateRelay) ([]*Path, error) {
	strategy := cm.cfg.SelectionStrategy

	// Determine whether to use BFS or probe.
	useBFS := false
	switch strategy {
	case "bfs":
		useBFS = true
	case "probe":
		useBFS = false
	case "auto":
		// Use BFS if the matrix has enough relay candidates with known RTTs.
		if cm.matrix.RelayCountWithRTT(entryID) >= cm.cfg.MinCandidates {
			useBFS = true
		}
	}

	if useBFS {
		paths, err := KShortestDisjointPaths(cm.matrix, entryID, exitID, cm.cfg.PathCount)
		if err == nil {
			// Convert graph paths to proxy.Path objects.
			result := make([]*Path, 0, len(paths))
			for _, p := range paths {
				proxyPath, pErr := cm.graphPathToProxyPath(p)
				if pErr != nil {
					return nil, pErr
				}
				result = append(result, proxyPath)
			}
			// Validate disjointness at creation time (AC-PS-03).
			if len(result) >= 2 {
				if HasOverlap(result[0], result[1]) {
					return nil, ErrPathOverlap
				}
			}
			return result, nil
		}
		// BFS failed — fall through to probe if auto.
		if strategy != "auto" {
			return nil, err
		}
	}

	// Probe-based fallback (AC-PS-05).
	if len(candidates) < cm.cfg.MinCandidates {
		return nil, ErrNoPaths
	}

	p1, p2, err := cm.probe.SelectPaths(ctx, candidates, cm.cfg.ExitAddr)
	if err != nil {
		return nil, fmt.Errorf("probe-based path selection failed: %w", err)
	}
	return []*Path{p1, p2}, nil
}

// graphPathToProxyPath converts a graph path [entry, relay₁, ..., exit]
// to a proxy.Path with generated relay keys.
func (cm *CircuitManager) graphPathToProxyPath(graphPath []string) (*Path, error) {
	if len(graphPath) < 2 {
		return nil, fmt.Errorf("invalid graph path: too short")
	}
	// Relays are intermediate nodes (exclude entry and exit).
	relays := graphPath[1 : len(graphPath)-1]
	relayKeys := make([][]byte, len(relays))
	for i := range relays {
		key := make([]byte, KeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate relay key: %w", err)
		}
		relayKeys[i] = key
	}
	return &Path{Relays: relays, RelayKeys: relayKeys}, nil
}

// CreateCircuit initiates a new circuit to the given target.
// It selects paths (BFS or probe), generates a unique circuit ID and E2E key,
// and stores the circuit in CREATING state.
//
// Returns the circuit ID or an error if path selection fails (AC-EH-01,
// AC-EH-02) or circuit limits are exceeded.
func (cm *CircuitManager) CreateCircuit(targetAddr string, entryID, exitID string, candidates []CandidateRelay) (CircuitIDType, error) {
	cm.mu.Lock()
	// Check circuit limits (DoS protection).
	if int(len(cm.circuits)) >= cm.cfg.MaxCircuitsTotal {
		cm.mu.Unlock()
		return CircuitIDType{}, ErrTooManyCircuits
	}
	exitCount := len(cm.circuitsByExit[exitID])
	if exitCount >= cm.cfg.MaxCircuitsPerExit {
		cm.mu.Unlock()
		return CircuitIDType{}, ErrTooManyCircuits
	}
	cm.mu.Unlock()

	// Select paths.
	paths, err := cm.selectPaths(cm.ctx, entryID, exitID, candidates)
	if err != nil {
		return CircuitIDType{}, fmt.Errorf("path selection: %w", err)
	}

	// Generate circuit ID (16 bytes, crypto/rand — AC-SE-02).
	idBytes, err := GenerateCircuitID()
	if err != nil {
		return CircuitIDType{}, fmt.Errorf("generate circuit ID: %w", err)
	}
	var cid CircuitIDType
	copy(cid[:], idBytes)

	// Generate E2E key (32 bytes).
	var e2eKey [KeySize]byte
	if _, err := rand.Read(e2eKey[:]); err != nil {
		return CircuitIDType{}, fmt.Errorf("generate E2E key: %w", err)
	}

	// Generate padding seed (32 bytes).
	var paddingSeed [32]byte
	if _, err := rand.Read(paddingSeed[:]); err != nil {
		return CircuitIDType{}, fmt.Errorf("generate padding seed: %w", err)
	}

	// Build circuit paths.
	strategy := NewChunkAssignmentStrategy(cm.cfg.ChunkAssignment)

	now := time.Now()
	circuitPaths := [2]*CircuitPath{}
	for i, p := range paths {
		if i >= 2 {
			break
		}
		circuitPaths[i] = &CircuitPath{
			Index:         i,
			Hops:          append([]string{}, p.Relays...),
			RelayKeys:     p.RelayKeys,
			Health:        PathHealthHealthy,
			EstablishedAt: now,
		}
	}

	circuit := &Circuit{
		ID:                 cid,
		State:              CircuitCreating,
		CreatedAt:          now,
		LastActivity:       now,
		Entry:              entryID,
		Exit:               exitID,
		TargetAddr:         targetAddr,
		E2EKey:             e2eKey,
		PaddingSeed:        paddingSeed,
		Paths:              circuitPaths,
		AssignmentStrategy: strategy,
		KeepaliveInterval:  cm.cfg.KeepaliveInterval,
		IdleTimeout:        cm.cfg.IdleTimeout,
	}

	cm.mu.Lock()
	cm.circuits[cid] = circuit
	cm.circuitsByExit[exitID] = append(cm.circuitsByExit[exitID], cid)
	cm.stats.TotalCreated++
	cm.stats.Active++
	cm.mu.Unlock()

	cm.emitEvent(EventCircuitCreated, cid, nil)
	return cid, nil
}

// HandleCircuitAck processes the exit's response to a circuit setup.
// On Accepted=true: transitions CREATING → ACTIVE, marks paths healthy,
// starts keepalive (AC-CL-01).
// On Accepted=false or setup timeout: transitions CREATING → CLOSED
// (AC-CL-02).
func (cm *CircuitManager) HandleCircuitAck(cid CircuitIDType, ack *CircuitAck) error {
	cm.mu.Lock()
	circuit, ok := cm.circuits[cid]
	cm.mu.Unlock()
	if !ok {
		return ErrCircuitNotFound
	}

	circuit.mu.Lock()

	if circuit.State != CircuitCreating {
		circuit.mu.Unlock()
		return fmt.Errorf("%w: circuit in state %s", ErrInvalidCircuitState,
			circuitStateName(circuit.State))
	}

	if !ack.Accepted {
		// Rejected — transition to CLOSED.
		circuit.State = CircuitClosed
		circuit.mu.Unlock()
		circuit.ZeroKeys()
		cm.removeCircuit(cid)
		cm.emitEvent(EventCircuitClosed, cid, ack.Reason)
		return fmt.Errorf("exit rejected circuit: %s", ack.Reason)
	}

	// Accepted — transition to ACTIVE.
	circuit.State = CircuitActive
	circuit.LastActivity = time.Now()

	// Mark both paths as healthy.
	for _, p := range circuit.Paths {
		if p != nil {
			p.mu.Lock()
			p.Health = PathHealthHealthy
			p.MissedKeepalives = 0
			p.mu.Unlock()
		}
	}
	circuit.mu.Unlock()

	cm.emitEvent(EventCircuitEstablished, cid, nil)
	return nil
}

// HandleSetupTimeout handles a CREATING circuit that exceeded SetupTimeout.
// Transitions to CLOSED (AC-CL-02).
func (cm *CircuitManager) HandleSetupTimeout(cid CircuitIDType) error {
	cm.mu.Lock()
	circuit, ok := cm.circuits[cid]
	cm.mu.Unlock()
	if !ok {
		return ErrCircuitNotFound
	}

	circuit.mu.Lock()
	if circuit.State != CircuitCreating {
		circuit.mu.Unlock()
		return nil
	}
	circuit.State = CircuitClosed
	circuit.mu.Unlock()

	circuit.ZeroKeys()
	cm.removeCircuit(cid)
	cm.emitEvent(EventCircuitClosed, cid, "setup timeout")
	return nil
}

// TeardownCircuit initiates graceful teardown with flush.
// Transitions ACTIVE → TEARDOWN, sends ChunkStreamEnd on all healthy paths,
// waits for flush or timeout, then transitions to CLOSED (AC-CL-03, AC-CL-05,
// AC-CL-06).
//
// The sendChunkEnd callback is called to send ChunkStreamEnd markers.
// If nil, the flush step is skipped (used in tests).
func (cm *CircuitManager) TeardownCircuit(cid CircuitIDType, reason string, sendChunkEnd func(pathIdx int) error) error {
	cm.mu.Lock()
	circuit, ok := cm.circuits[cid]
	cm.mu.Unlock()
	if !ok {
		return ErrCircuitNotFound
	}

	circuit.mu.Lock()
	if circuit.State == CircuitClosed || circuit.State == CircuitTeardown {
		circuit.mu.Unlock()
		return nil
	}

	// Transition to TEARDOWN.
	circuit.State = CircuitTeardown
	circuit.mu.Unlock()

	cm.emitEvent(EventCircuitTeardownInitiated, cid, reason)

	// Flush: send ChunkStreamEnd on all healthy paths (AC-CL-05).
	if sendChunkEnd != nil {
		for i, p := range circuit.Paths {
			if p != nil && p.Healthy() {
				_ = sendChunkEnd(i)
			}
		}
	}

	// Wait for flush or timeout (AC-CL-06).
	// In production this would wait for acks; here we use a timer.
	flushTimer := time.NewTimer(cm.cfg.FlushTimeout)
	defer flushTimer.Stop()
	<-flushTimer.C

	// Force close.
	return cm.closeCircuit(cid, "teardown: "+reason)
}

// HandleTeardown processes an exit-initiated teardown (AC-CL-04).
func (cm *CircuitManager) HandleTeardown(cid CircuitIDType, msg *TeardownMsg) error {
	cm.mu.Lock()
	circuit, ok := cm.circuits[cid]
	cm.mu.Unlock()
	if !ok {
		return ErrCircuitNotFound
	}

	circuit.mu.Lock()
	if circuit.State == CircuitClosed || circuit.State == CircuitTeardown {
		circuit.mu.Unlock()
		return nil
	}
	circuit.State = CircuitTeardown
	circuit.mu.Unlock()

	cm.emitEvent(EventCircuitTeardownInitiated, cid, msg.Reason)
	return cm.closeCircuit(cid, "exit teardown: "+msg.Reason)
}

// closeCircuit transitions a circuit to CLOSED and cleans up all resources.
// Zeros all key material (AC-CL-07, AC-SE-04), removes from tracking,
// emits CIRCUIT_CLOSED event.
func (cm *CircuitManager) closeCircuit(cid CircuitIDType, reason string) error {
	cm.mu.Lock()
	circuit, ok := cm.circuits[cid]
	cm.mu.Unlock()
	if !ok {
		return ErrCircuitNotFound
	}

	circuit.mu.Lock()
	circuit.State = CircuitClosed
	circuit.mu.Unlock()

	// Zero all key material (AC-CL-07, AC-SE-04).
	circuit.ZeroKeys()

	cm.removeCircuit(cid)
	cm.emitEvent(EventCircuitClosed, cid, reason)
	return nil
}

// removeCircuit removes a circuit from all tracking maps and updates stats.
func (cm *CircuitManager) removeCircuit(cid CircuitIDType) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	circuit, ok := cm.circuits[cid]
	if !ok {
		return
	}
	delete(cm.circuits, cid)

	// Remove from circuitsByExit.
	exit := circuit.Exit
	exitList := cm.circuitsByExit[exit]
	for i, id := range exitList {
		if id == cid {
			cm.circuitsByExit[exit] = append(exitList[:i], exitList[i+1:]...)
			break
		}
	}
	if len(cm.circuitsByExit[exit]) == 0 {
		delete(cm.circuitsByExit, exit)
	}

	// Update stats.
	cm.stats.TotalClosed++
	if circuit.State == CircuitActive {
		cm.stats.Active--
	} else if circuit.State == CircuitTeardown {
		cm.stats.TearingDown--
	}

	// Update chunk/byte stats.
	for _, p := range circuit.Paths {
		if p != nil {
			cm.stats.TotalChunksDispatched += p.TotalChunks
			cm.stats.TotalBytesDispatched += p.TotalBytes
		}
	}
}

// HandleKeepaliveResponse processes a keepalive echo to measure RTT and
// update path health (AC-CL-09, AC-CL-10).
//
// If a DEGRADED or UNHEALTHY path recovers, emits PATH_RESTORED.
func (cm *CircuitManager) HandleKeepaliveResponse(cid CircuitIDType, pathIdx int, timestamp int64) error {
	cm.mu.Lock()
	circuit, ok := cm.circuits[cid]
	cm.mu.Unlock()
	if !ok {
		return ErrCircuitNotFound
	}
	if pathIdx < 0 || pathIdx >= 2 {
		return fmt.Errorf("invalid path index: %d", pathIdx)
	}

	path := circuit.Paths[pathIdx]
	if path == nil {
		return fmt.Errorf("path %d is nil", pathIdx)
	}

	rtt := time.Duration(time.Now().UnixNano()-timestamp) - 0
	if rtt < 0 {
		rtt = 0
	}

	wasUnhealthy := path.Health == PathHealthUnhealthy
	wasDegraded := path.Health == PathHealthDegraded

	path.RecordRTT(rtt)
	circuit.UpdateActivity()

	if wasUnhealthy || wasDegraded {
		cm.emitEvent(EventPathRestored, cid, pathIdx)
	}

	return nil
}

// MissKeepalive records a missed keepalive for a path and transitions
// health state (AC-CL-10):
//
//	HEALTHY → DEGRADED after 2 missed (20s at 10s interval)
//	DEGRADED → UNHEALTHY after 4 total missed (40s)
//
// If both paths become unhealthy, the circuit transitions to TEARDOWN.
func (cm *CircuitManager) MissKeepalive(cid CircuitIDType, pathIdx int) error {
	cm.mu.Lock()
	circuit, ok := cm.circuits[cid]
	cm.mu.Unlock()
	if !ok {
		return ErrCircuitNotFound
	}
	if pathIdx < 0 || pathIdx >= 2 {
		return fmt.Errorf("invalid path index: %d", pathIdx)
	}

	path := circuit.Paths[pathIdx]
	if path == nil {
		return fmt.Errorf("path %d is nil", pathIdx)
	}

	wasHealthy := path.Health == PathHealthHealthy
	path.MissKeepalive(cm.cfg.KeepaliveInterval)

	if path.Health == PathHealthDegraded && wasHealthy {
		cm.emitEvent(EventPathDegraded, cid, pathIdx)
	}
	if path.Health == PathHealthUnhealthy {
		cm.emitEvent(EventPathUnhealthy, cid, pathIdx)
	}

	// If both paths are unhealthy, teardown (AC-CL-03).
	if circuit.BothPathsUnhealthy() {
		cm.emitEvent(EventKeepaliveTimeout, cid, nil)
		go cm.TeardownCircuit(cid, "both paths unhealthy", nil)
	}

	return nil
}

// RecordChunkDispatch updates circuit and path stats when a chunk is sent.
func (cm *CircuitManager) RecordChunkDispatch(cid CircuitIDType, pathIdx int, byteCount int) error {
	cm.mu.Lock()
	circuit, ok := cm.circuits[cid]
	cm.mu.Unlock()
	if !ok {
		return ErrCircuitNotFound
	}
	if pathIdx < 0 || pathIdx >= 2 {
		return fmt.Errorf("invalid path index: %d", pathIdx)
	}
	path := circuit.Paths[pathIdx]
	if path == nil {
		return fmt.Errorf("path %d is nil", pathIdx)
	}
	path.RecordChunk(byteCount)
	circuit.UpdateActivity()
	return nil
}

// AssignChunkPath asks the circuit's assignment strategy which path
// should carry the next chunk. Used by the Dispatcher (AC-IN-02).
func (cm *CircuitManager) AssignChunkPath(cid CircuitIDType) (int, error) {
	cm.mu.RLock()
	circuit, ok := cm.circuits[cid]
	cm.mu.RUnlock()
	if !ok {
		return -1, ErrCircuitNotFound
	}
	return circuit.AssignPath(), nil
}

// GetCircuit returns the current circuit state.
func (cm *CircuitManager) GetCircuit(cid CircuitIDType) (*Circuit, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	circuit, ok := cm.circuits[cid]
	if !ok {
		return nil, ErrCircuitNotFound
	}
	return circuit, nil
}

// ListCircuits returns all active and tearing-down circuits (AC-CL-08).
func (cm *CircuitManager) ListCircuits() []CircuitInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	result := make([]CircuitInfo, 0, len(cm.circuits))
	for _, c := range cm.circuits {
		if c.State == CircuitClosed {
			continue
		}
		result = append(result, c.ToInfo())
	}
	return result
}

// GetCircuitStats returns aggregate circuit metrics (AC-TO-01).
func (cm *CircuitManager) GetCircuitStats() CircuitStats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	stats := cm.stats
	stats.Active = 0
	stats.TearingDown = 0
	for _, c := range cm.circuits {
		if c.State == CircuitActive {
			stats.Active++
		} else if c.State == CircuitTeardown {
			stats.TearingDown++
		}
	}
	return stats
}

// CheckIdleTimeouts scans all active circuits and tears down any that have
// been idle longer than IdleTimeout (AC-CL-03). Should be called periodically.
func (cm *CircuitManager) CheckIdleTimeouts() {
	cm.mu.RLock()
	var toTeardown []CircuitIDType
	for id, c := range cm.circuits {
		if c.State == CircuitActive && c.IsIdle() {
			toTeardown = append(toTeardown, id)
		}
	}
	cm.mu.RUnlock()

	for _, cid := range toTeardown {
		go cm.TeardownCircuit(cid, "idle timeout", nil)
	}
}

// Shutdown gracefully tears down all circuits and stops the manager.
func (cm *CircuitManager) Shutdown() {
	cm.cancel()

	cm.mu.Lock()
	circuits := make(map[CircuitIDType]*Circuit, len(cm.circuits))
	for k, v := range cm.circuits {
		circuits[k] = v
	}
	cm.mu.Unlock()

	var wg sync.WaitGroup
	for cid := range circuits {
		wg.Add(1)
		go func(id CircuitIDType) {
			defer wg.Done()
			cm.closeCircuit(id, "shutdown")
		}(cid)
	}
	wg.Wait()
}
