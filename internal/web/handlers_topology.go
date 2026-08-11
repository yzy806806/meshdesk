package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/proxy"
	"github.com/yzy806806/meshdesk/internal/topology"
)

// PeerLiveness provides memberlist alive/dead state for topology
// visualization. Implemented by a thin adapter over *p2p.GossipLayer.
// This interface lives in the web package to avoid importing p2p/memberlist.
type PeerLiveness interface {
	// IsAlive reports whether a peer is currently known to the gossip
	// cluster (i.e., present in metaCache — NotifyJoin received, no
	// NotifyLeave yet).
	IsAlive(peerID string) bool

	// AlivePeerIDs returns the public keys of all peers currently known
	// to the gossip cluster. This includes peers not in the routing table
	// (gossip-discovered only).
	AlivePeerIDs() []string

	// PeerHostname returns the hostname for a peer from gossip NodeMeta,
	// or empty string if the peer is unknown or has no hostname.
	// Used as a fallback when monitor metrics are not yet available.
	PeerHostname(peerID string) string
}

// --- Adapters: bridge existing types to topology interfaces ---

// meshTopologyPeers adapts mesh.RoutingTable + config.Config to
// topology.TopologyPeers. It derives node roles from config and
// positions from config override or DerivePosition.
type meshTopologyPeers struct {
	rt  *mesh.RoutingTable
	cfg *config.Config
	// node provides zone/transport lookups (nil-safe for tests).
	node *mesh.MeshNode
	// localNodeID is this node's own public key (so it appears in topology)
	localNodeID string
	// liveness provides gossip-based peer liveness. When non-nil,
	// gossip-discovered peers not in the routing table are included.
	// nil = backward compatible (routing table only).
	liveness PeerLiveness
}

// Compile-time assertion that meshTopologyPeers implements TopologyPeers.
var _ topology.TopologyPeers = (*meshTopologyPeers)(nil)

func (m *meshTopologyPeers) AllPeerIDs() []string {
	if m.rt == nil {
		// Even with no routing table, include the local node + gossip peers.
		var ids []string
		if m.localNodeID != "" {
			ids = []string{m.localNodeID}
		}
		return mergeGossipPeers(ids, m.liveness)
	}

	peers := m.rt.AllPeers()
	ids := make([]string, 0, len(peers)+1)

	// Include local node first if known.
	hasLocal := false
	if m.localNodeID != "" {
		ids = append(ids, m.localNodeID)
		hasLocal = true
	}

	for _, p := range peers {
		if hasLocal && p.ID == m.localNodeID {
			continue // avoid duplicate
		}
		ids = append(ids, p.ID)
	}

	// Include peers learned via the meta exchange (0x4D45) that have a
	// VirtualIP route but no PeerEntry — keeps the topology complete
	// even when memberlist/gossip is degraded.
	if m.node != nil {
		known := make(map[string]bool, len(ids))
		for _, id := range ids {
			known[id] = true
		}
		for pubKey := range m.node.PeerVirtualIPs() {
			if !known[pubKey] {
				ids = append(ids, pubKey)
			}
		}
	}

	return mergeGossipPeers(ids, m.liveness)
}

// mergeGossipPeers appends gossip-discovered peer IDs not already
// present in ids. When liveness is nil, ids is returned unchanged.
func mergeGossipPeers(ids []string, liveness PeerLiveness) []string {
	if liveness == nil {
		return ids
	}
	known := make(map[string]bool, len(ids))
	for _, id := range ids {
		known[id] = true
	}
	for _, id := range liveness.AlivePeerIDs() {
		if !known[id] {
			ids = append(ids, id)
			known[id] = true
		}
	}
	return ids
}

func (m *meshTopologyPeers) PeerExists(peerID string) bool {
	if m.localNodeID != "" && peerID == m.localNodeID {
		return true
	}
	if m.rt != nil {
		if _, ok := m.rt.GetPeer(peerID); ok {
			return true
		}
	}
	// Check gossip liveness for peers not in the routing table.
	if m.liveness != nil {
		return m.liveness.IsAlive(peerID)
	}
	return false
}

func (m *meshTopologyPeers) PeerRole(peerID string) string {
	if m.cfg == nil {
		return "dashboard"
	}

	// Check if this is the local node — use local config.
	if m.localNodeID != "" && peerID == m.localNodeID {
		return deriveRoleFromConfig(m.cfg)
	}

	// For remote peers, we don't have their config. Derive role from
	// whether they appear in our proxy paths or latency matrix as a
	// relay, and whether they have capabilities. For v1, remote peers
	// default to "relay" if they appear in path config, otherwise "node".
	// This is a best-effort derivation; a future gossip protocol can
	// propagate actual roles.
	if m.cfg != nil {
		if isPeerRelay(m.cfg, peerID) {
			return "relay"
		}
	}

	return "node"
}

func (m *meshTopologyPeers) Position(peerID string) (x, y, z float64) {
	// Tier 1: Manual override from config (local node only).
	if m.cfg != nil && m.localNodeID != "" && peerID == m.localNodeID {
		if m.cfg.Node.Position != nil {
			return m.cfg.Node.Position.X, m.cfg.Node.Position.Y, m.cfg.Node.Position.Z
		}
	}

	// Tier 2: Deterministic auto-assignment from public key.
	// This applies to all nodes (local and remote).
	return topology.DerivePosition(peerID)
}

// PeerZone returns the node's zone tag (local node from config,
// peers via the mesh node — config first, gossip fallback).
func (m *meshTopologyPeers) PeerZone(peerID string) string {
	// Local node: authoritative from config.
	if m.cfg != nil && peerID == m.localNodeID {
		return m.cfg.Mesh.Zone
	}
	if m.node != nil {
		return m.node.PeerZone(peerID)
	}
	return ""
}

// PeerTransport returns the transport the session to the node was
// established over ("reality"/"0x4d"/"udp"/"").
func (m *meshTopologyPeers) PeerTransport(peerID string) string {
	if m.node == nil {
		return ""
	}
	return m.node.PeerTransport(peerID)
}

// deriveRoleFromConfig computes the local node's role from its config.
func deriveRoleFromConfig(cfg *config.Config) string {
	ssPasswordSet := cfg.Proxy.SS.Password != ""
	relayEnabled := cfg.Proxy.Relay.Enabled
	exitHasPorts := len(cfg.Proxy.Exit.AllowedPorts) > 0
	exitAllowAll := cfg.Proxy.Exit.AllowAllPorts
	webAddrSet := cfg.Node.WebAddr != ""

	return topology.DeriveRole(ssPasswordSet, relayEnabled, exitHasPorts, exitAllowAll, webAddrSet)
}

// isPeerRelay checks whether a peer appears in the proxy paths or
// path selection config as a relay node.
func isPeerRelay(cfg *config.Config, peerID string) bool {
	// Check manual paths.
	for _, path := range cfg.Proxy.Paths {
		for _, id := range path {
			if id == peerID {
				return true
			}
		}
	}

	// Check exit latency matrix (relays and exits appear here).
	if _, ok := cfg.Proxy.PathSelection.ExitLatencyMatrix[peerID]; ok {
		return true
	}

	return false
}

// monitorTopologyMetrics adapts monitor.Store to topology.TopologyMetrics.
type monitorTopologyMetrics struct {
	store *monitor.Store
	// liveness provides gossip-based peer liveness. When non-nil,
	// NodeStatus uses it as a FALLBACK when metrics are stale or missing.
	// nil = backward compatible (monitor-only liveness).
	liveness PeerLiveness
}

// Compile-time assertion.
var _ topology.TopologyMetrics = (*monitorTopologyMetrics)(nil)

func (m *monitorTopologyMetrics) LatestCPU(nodeID string, freshnessThreshold time.Duration) (float64, bool) {
	if m.store == nil {
		return 0, false
	}
	metrics := m.store.Latest(nodeID)
	if metrics == nil {
		return 0, false
	}
	if time.Since(metrics.Timestamp) > freshnessThreshold {
		return 0, false
	}
	return metrics.CPU.UsagePercent, true
}

func (m *monitorTopologyMetrics) LatestMem(nodeID string, freshnessThreshold time.Duration) (float64, bool) {
	if m.store == nil {
		return 0, false
	}
	metrics := m.store.Latest(nodeID)
	if metrics == nil {
		return 0, false
	}
	if time.Since(metrics.Timestamp) > freshnessThreshold {
		return 0, false
	}
	if metrics.Memory.Total == 0 {
		return 0, true // fresh, but no memory data
	}
	pct := float64(metrics.Memory.Used) / float64(metrics.Memory.Total) * 100
	return pct, true
}

func (m *monitorTopologyMetrics) LatestHostname(nodeID string) string {
	// Try monitor store first — it has the most up-to-date hostname
	// (pushed by the node with its metrics).
	if m.store != nil {
		metrics := m.store.Latest(nodeID)
		if metrics != nil && metrics.Hostname != "" {
			return metrics.Hostname
		}
	}

	// Fallback: consult gossip liveness for hostname from NodeMeta.
	// This covers the window between gossip join and first metrics push.
	if m.liveness != nil {
		if h := m.liveness.PeerHostname(nodeID); h != "" {
			return h
		}
	}

	return ""
}

func (m *monitorTopologyMetrics) NodeStatus(nodeID string, freshnessThreshold time.Duration) string {
	// Metrics are checked FIRST — they are authoritative when fresh.
	// Gossip liveness is a FALLBACK, consulted only when metrics are
	// stale or missing. This prevents false "offline" when memberlist
	// UDP pings are unreliable (e.g., in EasyTier VPN environments)
	// but fresh metrics are flowing via TCP push/pull sync.
	//
	// Priority:
	//   1. Fresh metrics     → "online" (metrics authoritative)
	//   2. Stale/missing + gossip alive  → "online" (alive, no metrics)
	//   3. Stale/missing + gossip dead   → "offline"
	//   4. Stale/missing + no liveness   → "offline"
	if m.store != nil {
		metrics := m.store.Latest(nodeID)
		if metrics != nil && time.Since(metrics.Timestamp) <= freshnessThreshold {
			return "online" // fresh metrics → authoritative
		}
	}

	// Metrics are stale or missing — consult gossip liveness as fallback.
	if m.liveness != nil {
		if m.liveness.IsAlive(nodeID) {
			return "online" // alive in gossip, no fresh metrics
		}
		return "offline" // not alive in gossip, no fresh metrics
	}

	// No liveness provider — metrics were stale or missing, so offline.
	return "offline"
}

func (m *monitorTopologyMetrics) BestBandwidth(nodeID string) float64 {
	if m.store == nil {
		return -1
	}
	metrics := m.store.Latest(nodeID)
	if metrics == nil {
		return -1
	}
	best := -1
	for _, net := range metrics.Network {
		if net.SpeedMbps > best {
			best = net.SpeedMbps
		}
	}
	if best < 0 {
		return -1
	}
	return float64(best)
}

// pathProbeTopologyPaths adapts proxy.PathProbeCache to
// topology.TopologyPathInfo. This is the single compilation seam
// between the proxy and topology packages.
//
// NOTE: This adapter lives in the web package, not in internal/proxy
// or internal/topology. It imports proxy only for the PathProbeCache
// type. If the proxy type changes, this adapter is the single place
// that must be updated.
//
// We use an interface here so that tests can inject a mock without
// importing proxy. In production, the caller passes a
// *proxy.PathProbeCache wrapped in a pathProbeAdapter.
type pathProbeAdapter struct {
	cache pathProbeReader
}

// pathProbeReader is the minimal read interface that PathProbeCache
// satisfies. Defined here to avoid importing proxy in tests.
type pathProbeReader interface {
	Get(src, dst string) float64
	AllPairs() []pathProbePair
}

// pathProbePair is a latency pair returned by AllPairs.
type pathProbePair struct {
	Src     string
	Dst     string
	Latency float64
}

// Compile-time assertion.
var _ topology.TopologyPathInfo = (*pathProbeAdapter)(nil)

func (a *pathProbeAdapter) PeerLatency(sourceID, targetID string) float64 {
	if a == nil || a.cache == nil {
		return -1
	}
	return a.cache.Get(sourceID, targetID)
}

// NewPathProbeAdapter creates a TopologyPathInfo adapter from a
// proxy.PathProbeCache. This is the single compilation seam between
// the proxy package and the topology visualization system.
//
// The adapter lives in the web package. If proxy.PathProbeCache changes,
// this function is the only place that needs updating.
//
// NOTE: This function imports internal/proxy. Callers that want to
// avoid the proxy dependency (e.g., tests) should implement
// pathProbeReader directly and construct a pathProbeAdapter manually.
func NewPathProbeAdapter(cache *proxy.PathProbeCache) topology.TopologyPathInfo {
	return &pathProbeAdapter{cache: &proxyCacheReader{cache: cache}}
}

// proxyCacheReader wraps *proxy.PathProbeCache to satisfy the
// pathProbeReader interface. The proxy type returns []PathLatency
// from AllPairs; we convert to []pathProbePair here.
type proxyCacheReader struct {
	cache *proxy.PathProbeCache
}

func (r *proxyCacheReader) Get(src, dst string) float64 {
	return r.cache.Get(src, dst)
}

func (r *proxyCacheReader) AllPairs() []pathProbePair {
	pairs := r.cache.AllPairs()
	result := make([]pathProbePair, len(pairs))
	for i, p := range pairs {
		result[i] = pathProbePair{
			Src:     p.Src,
			Dst:     p.Dst,
			Latency: p.Latency,
		}
	}
	return result
}

// --- Snapshot builder ---

// freshnessThreshold is the time window within which metrics are
// considered "fresh" (node is online).
const topologyFreshnessThreshold = 60 * time.Second

// buildTopologySnapshot assembles a complete topology snapshot from
// the three interfaces. This is the core data-building function used
// by both the REST handler and the SSE initial event.
//
// peers must be non-nil. metrics and paths may be nil — in that case,
// nodes will have zero CPU/mem and no edges will be produced.
func buildTopologySnapshot(peers topology.TopologyPeers, metrics topology.TopologyMetrics, paths topology.TopologyPathInfo) topology.TopologySnapshot {
	ids := peers.AllPeerIDs()

	// Sort IDs for deterministic output.
	sort.Strings(ids)

	// Build nodes.
	nodes := make([]topology.TopologyNode, 0, len(ids))
	for _, id := range ids {
		x, y, z := peers.Position(id)

		node := topology.TopologyNode{
			ID:   id,
			Role: peers.PeerRole(id),
			X:    x,
			Y:    y,
			Z:    z,
			Zone: peers.PeerZone(id),
		}

		if metrics != nil {
			cpu, cpuFresh := metrics.LatestCPU(id, topologyFreshnessThreshold)
			mem, memFresh := metrics.LatestMem(id, topologyFreshnessThreshold)
			status := metrics.NodeStatus(id, topologyFreshnessThreshold)

			node.Hostname = metrics.LatestHostname(id)
			node.Status = status

			// Only include CPU/mem when the node is online and metrics are fresh.
			if status == "online" && cpuFresh {
				node.CPU = cpu
			}
			if status == "online" && memFresh {
				node.Mem = mem
			}
		}

		nodes = append(nodes, node)
	}

	// Build edges from the path probe cache.
	// Edges are derived from measured pairs; if no probe cache exists,
	// edges will be empty (the frontend handles this gracefully).
	edges := buildEdges(paths, metrics, ids, peers)

	return topology.TopologySnapshot{
		Nodes: nodes,
		Edges: edges,
	}
}

// buildEdges constructs the edge list from path probe data.
// Each measured pair becomes one edge. Bandwidth is derived from
// the source node's best network interface speed.
func buildEdges(paths topology.TopologyPathInfo, metrics topology.TopologyMetrics, knownIDs []string, peers topology.TopologyPeers) []topology.TopologyEdge {
	if paths == nil {
		return []topology.TopologyEdge{}
	}

	// Build a set of known node IDs for filtering.
	known := make(map[string]bool, len(knownIDs))
	for _, id := range knownIDs {
		known[id] = true
	}

	// Use the pathProbeAdapter to access AllPairs via the cache.
	adapter, ok := paths.(*pathProbeAdapter)
	if !ok || adapter.cache == nil {
		// Fall back to individual latency queries for any TopologyPathInfo.
		// This handles mock implementations that don't use the adapter.
		return buildEdgesFromInterface(paths, metrics, knownIDs, peers)
	}

	pairs := adapter.cache.AllPairs()
	edges := make([]topology.TopologyEdge, 0, len(pairs))

	for _, p := range pairs {
		// Only include edges between known nodes.
		if !known[p.Src] || !known[p.Dst] {
			continue
		}

		bandwidth := metrics.BestBandwidth(p.Src)
		if bandwidth < 0 {
			bandwidth = metrics.BestBandwidth(p.Dst)
		}

		transport := ""
		if peers != nil {
			// Transport is per-peer (our session to the peer). Use the
			// target that is NOT the local node when possible.
			if peers.PeerTransport(p.Src) != "" {
				transport = peers.PeerTransport(p.Src)
			} else {
				transport = peers.PeerTransport(p.Dst)
			}
		}

		edges = append(edges, topology.TopologyEdge{
			Source:        p.Src,
			Target:        p.Dst,
			LatencyMs:     p.Latency,
			BandwidthMbps: bandwidth,
			Transport:     transport,
		})
	}

	return edges
}

// buildEdgesFromInterface builds edges by querying PeerLatency for
// each pair of known nodes. Used when the TopologyPathInfo is not
// a *pathProbeAdapter (e.g., mock implementations in tests).
func buildEdgesFromInterface(paths topology.TopologyPathInfo, metrics topology.TopologyMetrics, ids []string, peers topology.TopologyPeers) []topology.TopologyEdge {
	edges := make([]topology.TopologyEdge, 0, len(ids)*(len(ids)-1)/2)

	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			src, dst := ids[i], ids[j]
			lat := paths.PeerLatency(src, dst)
			if lat < 0 {
				// Try reverse direction.
				lat = paths.PeerLatency(dst, src)
			}
			if lat < 0 {
				continue // no measurement for this pair
			}

			bandwidth := metrics.BestBandwidth(src)
			if bandwidth < 0 {
				bandwidth = metrics.BestBandwidth(dst)
			}

			edges = append(edges, topology.TopologyEdge{
				Source:        src,
				Target:        dst,
				LatencyMs:     lat,
				BandwidthMbps: bandwidth,
			})
		}
	}

	return edges
}

// --- REST Handler: GET /api/topology ---

// handleTopology handles GET /api/topology.
// Returns a JSON topology snapshot with nodes and edges.
//
// Auth: Session cookie (requireAuth). Same as /api/events.
// When no topology providers are configured, returns an empty snapshot.
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	snapshot := s.getTopologySnapshot()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)
	}
}

// getTopologySnapshot builds the current topology snapshot using
// the server's configured providers. When mock mode is enabled
// (MOCK_TOPOLOGY env var or ?mock=true query param), uses mock data.
func (s *Server) getTopologySnapshot() topology.TopologySnapshot {
	// Check for mock mode.
	if s.topologyMockMode() {
		return s.buildMockSnapshot()
	}

	peers := s.topologyPeers()
	metrics := s.topologyMetrics()
	paths := s.topologyPaths()

	// If peers is nil, we have no node list — return empty.
	// (metrics and paths are useless without a peer list.)
	if peers == nil {
		return topology.TopologySnapshot{
			Nodes: []topology.TopologyNode{},
			Edges: []topology.TopologyEdge{},
		}
	}

	return buildTopologySnapshot(peers, metrics, paths)
}

// topologyMockMode returns true if mock topology data should be used
// instead of real mesh/monitor data. Enabled via MOCK_TOPOLOGY=1 env
// var or ?mock=true query param.
func (s *Server) topologyMockMode() bool {
	// Check query param (per-request).
	if s.mockTopologyQuery != nil {
		// In tests, this is set directly.
		return s.mockTopologyQuery()
	}
	return false
}

// topologyPeers returns the TopologyPeers provider, or nil if none.
func (s *Server) topologyPeers() topology.TopologyPeers {
	if s.topologyPeersProvider != nil {
		return s.topologyPeersProvider
	}

	// Build from mesh node + config if available.
	if s.node != nil {
		localID := ""
		if s.node.Identity() != nil {
			localID = s.node.Identity().PublicKey
		}
		return &meshTopologyPeers{
			rt:          s.node.RoutingTable(),
			cfg:         s.cfg,
			localNodeID: localID,
			liveness:    s.liveness,
			node:        s.node,
		}
	}

	return nil
}

// topologyMetrics returns the TopologyMetrics provider, or nil if none.
func (s *Server) topologyMetrics() topology.TopologyMetrics {
	if s.topologyMetricsProvider != nil {
		return s.topologyMetricsProvider
	}

	if s.monitorStore != nil {
		return &monitorTopologyMetrics{store: s.monitorStore, liveness: s.liveness}
	}

	return nil
}

// topologyPaths returns the TopologyPathInfo provider, or nil if none.
func (s *Server) topologyPaths() topology.TopologyPathInfo {
	if s.topologyPathsProvider != nil {
		return s.topologyPathsProvider
	}
	return nil
}

// buildMockSnapshot returns a snapshot from mock data.
// Used for development and testing without a live mesh.
func (s *Server) buildMockSnapshot() topology.TopologySnapshot {
	// Import the mock package lazily to avoid circular dependencies
	// in non-mock builds. This is set via SetMockTopology in tests.
	if s.mockSnapshotFn != nil {
		return s.mockSnapshotFn()
	}
	return topology.TopologySnapshot{
		Nodes: []topology.TopologyNode{},
		Edges: []topology.TopologyEdge{},
	}
}

// --- SSE Handler: GET /api/topology/events ---

// handleTopologySSE handles GET /api/topology/events (Server-Sent Events).
//
// On connection, sends a full "topology" event (cold start).
// Then streams "node_update", "node_online", "node_offline", and
// "edge_update" events as topology data changes.
// Sends keepalive comments every 15 seconds.
//
// Auth: Session cookie (requireAuth). Same as /api/events.
func (s *Server) handleTopologySSE(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Register with SSE hub for topology events.
	ch := s.sseHub.Register()
	defer s.sseHub.Unregister(ch)

	// AC7: Send initial topology event immediately (cold start).
	snapshot := s.getTopologySnapshot()
	data, err := json.Marshal(snapshot)
	if err == nil {
		fmt.Fprintf(w, "event: topology\ndata: %s\n\n", data)
		flusher.Flush()
	}

	// Keepalive ticker (AC11: every 15 seconds).
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			// Only forward topology-related events.
			switch event.Event {
			case "topology", "node_update", "node_online", "node_offline", "edge_update":
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Event, event.Data)
				flusher.Flush()
			}
		case <-ticker.C:
			// AC11: Send keepalive comment.
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// BroadcastTopology sends a full topology snapshot to all SSE clients
// on the topology event stream. This can be called when the topology
// data changes (e.g., new metrics arrive, node goes online/offline).
func (s *Server) BroadcastTopology() {
	if s.sseHub == nil || s.sseHub.ClientCount() == 0 {
		return
	}

	snapshot := s.getTopologySnapshot()
	data, err := json.Marshal(snapshot)
	if err != nil {
		return
	}

	s.sseHub.Broadcast(SSEEvent{
		Event: "topology",
		Data:  string(data),
	})
}

// BroadcastTopologyNodeUpdate sends a node_update event for a single
// node. Call this when a node's metrics, role, or position changes.
func (s *Server) BroadcastTopologyNodeUpdate(nodeID string) {
	if s.sseHub == nil || s.sseHub.ClientCount() == 0 {
		return
	}

	peers := s.topologyPeers()
	metrics := s.topologyMetrics()
	if peers == nil || metrics == nil {
		return
	}

	x, y, z := peers.Position(nodeID)
	cpu, cpuFresh := metrics.LatestCPU(nodeID, topologyFreshnessThreshold)
	mem, memFresh := metrics.LatestMem(nodeID, topologyFreshnessThreshold)
	status := metrics.NodeStatus(nodeID, topologyFreshnessThreshold)

	node := topology.TopologyNode{
		ID:       nodeID,
		Role:     peers.PeerRole(nodeID),
		X:        x,
		Y:        y,
		Z:        z,
		Hostname: metrics.LatestHostname(nodeID),
		Status:   status,
	}

	if status == "online" && cpuFresh {
		node.CPU = cpu
	}
	if status == "online" && memFresh {
		node.Mem = mem
	}

	data, err := json.Marshal(node)
	if err != nil {
		return
	}

	s.sseHub.Broadcast(SSEEvent{
		Event: "node_update",
		Data:  string(data),
	})
}

// BroadcastTopologyNodeOnline sends a node_online event.
// Call this when a node starts reporting metrics after being offline.
func (s *Server) BroadcastTopologyNodeOnline(nodeID, hostname string) {
	if s.sseHub == nil || s.sseHub.ClientCount() == 0 {
		return
	}

	payload := struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
	}{
		ID:       nodeID,
		Hostname: hostname,
	}

	data, _ := json.Marshal(payload)
	s.sseHub.Broadcast(SSEEvent{
		Event: "node_online",
		Data:  string(data),
	})
}

// BroadcastTopologyNodeOffline sends a node_offline event.
// Call this when a node's metrics go stale (>60s).
func (s *Server) BroadcastTopologyNodeOffline(nodeID, hostname string) {
	if s.sseHub == nil || s.sseHub.ClientCount() == 0 {
		return
	}

	payload := struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
	}{
		ID:       nodeID,
		Hostname: hostname,
	}

	data, _ := json.Marshal(payload)
	s.sseHub.Broadcast(SSEEvent{
		Event: "node_offline",
		Data:  string(data),
	})
}

// BroadcastTopologyEdgeUpdate sends an edge_update event for a single
// edge. Call this when an edge's latency or bandwidth estimate changes.
func (s *Server) BroadcastTopologyEdgeUpdate(source, target string, latencyMs, bandwidthMbps float64) {
	if s.sseHub == nil || s.sseHub.ClientCount() == 0 {
		return
	}

	edge := topology.TopologyEdge{
		Source:        source,
		Target:        target,
		LatencyMs:     latencyMs,
		BandwidthMbps: bandwidthMbps,
	}

	data, _ := json.Marshal(edge)
	s.sseHub.Broadcast(SSEEvent{
		Event: "edge_update",
		Data:  string(data),
	})
}

// --- REST Handler: GET /api/peers ---

// handlePeersAPI handles GET /api/peers.
// Returns a JSON array of peers derived from the topology snapshot
// (which itself is built from the mesh routing table, config roles,
// and monitor metrics). This is a thin wrapper over the same
// getTopologySnapshot() used by /api/topology — no logic is duplicated.
//
// Each peer object contains: id, role, hostname, status, cpu, mem,
// and 3D position (x, y, z).
//
// Auth: Session cookie (requireAuth).
func (s *Server) handlePeersAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	snapshot := s.getTopologySnapshot()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snapshot.Nodes); err != nil {
		http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)
	}
}

// --- REST Handler: GET /api/monitor ---

// monitorNodeJSON is the JSON representation of a single node's
// monitor metrics for the /api/monitor endpoint.
type monitorNodeJSON struct {
	NodeID    string  `json:"node_id"`
	ShortID   string  `json:"short_id"`
	Hostname  string  `json:"hostname"`
	CPUUsage  float64 `json:"cpu_usage"`
	CoreCount int     `json:"core_count"`
	MemUsed   uint64  `json:"mem_used"`
	MemTotal  uint64  `json:"mem_total"`
	MemUsage  float64 `json:"mem_usage"`
	Load1     float64 `json:"load1"`
	Load5     float64 `json:"load5"`
	Load15    float64 `json:"load15"`
	Uptime    int64   `json:"uptime_seconds"`
}

type monitorResponse struct {
	Nodes          []monitorNodeJSON `json:"nodes"`
	NodeCount      int               `json:"node_count"`
	ActiveSessions int               `json:"active_sessions"`
}

// handleMonitorAPI handles GET /api/monitor.
// Returns node monitor metrics (CPU, memory, load average, uptime)
// as JSON for all nodes known to the monitor store. This is a thin
// wrapper over buildNodeCards() — the same data used by the dashboard
// HTML partial and SSE stream.
//
// Auth: Session cookie (requireAuth).
func (s *Server) handleMonitorAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	cards := s.buildNodeCards()

	nodes := make([]monitorNodeJSON, 0, len(cards))
	for _, c := range cards {
		nodes = append(nodes, monitorNodeJSON{
			NodeID:    c.NodeID,
			ShortID:   c.ShortID,
			Hostname:  c.Hostname,
			CPUUsage:  c.CPUUsage,
			CoreCount: c.CoreCount,
			MemUsed:   c.MemUsed,
			MemTotal:  c.MemTotal,
			MemUsage:  c.MemUsage,
			Load1:     c.Load1,
			Load5:     c.Load5,
			Load15:    c.Load15,
			Uptime:    c.Uptime,
		})
	}

	resp := monitorResponse{
		Nodes:          nodes,
		NodeCount:      len(nodes),
		ActiveSessions: s.activeSessionCount(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)
	}
}
