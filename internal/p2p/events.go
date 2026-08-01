package p2p

import (
	"log"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
)

// PeerJoinHandler is called when a new peer joins the mesh via gossip.
type PeerJoinHandler func(meta *NodeMeta)

// PeerLeaveHandler is called when a peer leaves the mesh via gossip.
type PeerLeaveHandler func(peerKey string)

// PeerUpdateHandler is called when a peer's metadata is updated (load metrics, etc).
type PeerUpdateHandler func(meta *NodeMeta)

// RelayPathBuilder is the interface for managing relay circuits for NAT peers.
// When a NAT peer (no public endpoint) is discovered via gossip, the event
// delegate calls OnNATPeerDiscovered instead of Connect. The
// implementation selects a relay, sets up the circuit, and wires the
// routing through the relay.
type RelayPathBuilder interface {
	// OnNATPeerDiscovered is called by NotifyJoin when a NAT peer with
	// no endpoints is discovered. It selects relays and sets up the circuit.
	OnNATPeerDiscovered(meta *NodeMeta)

	// OnPeerLeft cleans up relay circuits when a peer leaves.
	OnPeerLeft(peerKey string)
}

// CollectorDiscoveredHandler is called when a peer with CapCollector=true
// is discovered via gossip (NotifyJoin or NotifyUpdate). The peerKey is the
// collector's Ed25519 public key (hex-encoded).
type CollectorDiscoveredHandler func(peerKey string)

// meshEventDelegate implements memberlist.EventDelegate to bridge gossip
// events to the PeerManager and routing table.
type meshEventDelegate struct {
	delegate  *meshDelegate
	wg        PeerManager
	mu        sync.RWMutex
	metaCache map[string]*NodeMeta // publicKey → latest metadata
	relayPool map[string]*NodeMeta // publicKey → relay candidates (CapRelay)
	exitPool  map[string]*NodeMeta // publicKey → exit candidates (CapExit)
	entryPool map[string]*NodeMeta // publicKey → entry candidates (CapProxyEntry)
	collectorPool map[string]*NodeMeta // publicKey → collector candidates (CapCollector)

	joinHandler   PeerJoinHandler
	leaveHandler  PeerLeaveHandler
	updateHandler PeerUpdateHandler

	// collectorHandler is called when a collector peer is discovered
	// or updated. nil if not wired (monitor auto-routing disabled).
	collectorHandler CollectorDiscoveredHandler

	// peerCache persists discovered peer endpoints to disk so they
	// survive restarts. nil when persistence is disabled.
	peerCache *PeerCache

	// relayPathBuilder manages relay circuits for NAT peers.
	// nil if relay path building is not enabled (no gossip layer wiring).
	relayPathBuilder RelayPathBuilder

	// Flapping prevention (§1.7)
	leaveTimes map[string]time.Time // publicKey → last leave time
	cooldownMu sync.Mutex
}

// newMeshEventDelegate creates a new event delegate.
func newMeshEventDelegate(delegate *meshDelegate, wg PeerManager) *meshEventDelegate {
	return &meshEventDelegate{
		delegate:      delegate,
		wg:            wg,
		metaCache:     make(map[string]*NodeMeta),
		relayPool:     make(map[string]*NodeMeta),
		exitPool:      make(map[string]*NodeMeta),
		entryPool:     make(map[string]*NodeMeta),
		collectorPool: make(map[string]*NodeMeta),
		leaveTimes:    make(map[string]time.Time),
	}
}

// SetJoinHandler installs a callback for peer join events.
func (e *meshEventDelegate) SetJoinHandler(h PeerJoinHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.joinHandler = h
}

// SetLeaveHandler installs a callback for peer leave events.
func (e *meshEventDelegate) SetLeaveHandler(h PeerLeaveHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.leaveHandler = h
}

// SetUpdateHandler installs a callback for peer metadata update events.
func (e *meshEventDelegate) SetUpdateHandler(h PeerUpdateHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.updateHandler = h
}

// SetCollectorHandler installs a callback for collector discovery events.
// When a peer with CapCollector=true is discovered via gossip (NotifyJoin or
// NotifyUpdate), this callback is invoked with the collector's public key.
// This enables automatic monitor routing: the reporter learns about collector
// nodes without static configuration.
func (e *meshEventDelegate) SetCollectorHandler(h CollectorDiscoveredHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.collectorHandler = h
}

// SetRelayPathBuilder installs the relay path builder for NAT peer relay selection.
// When set, NotifyJoin will detect NAT peers (empty endpoints) and delegate
// their setup to the relay path builder instead of calling
// Connect with an empty endpoint.
func (e *meshEventDelegate) SetRelayPathBuilder(rpb RelayPathBuilder) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.relayPathBuilder = rpb
}

// SetPeerCache installs a PeerCache for persisting discovered peer
// endpoints to disk. When set, NotifyJoin/NotifyUpdate/NotifyLeave
// events update the cache so that peer endpoints survive restarts.
func (e *meshEventDelegate) SetPeerCache(pc *PeerCache) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.peerCache = pc
}

// NotifyJoin is called when a new node joins the memberlist cluster.
// It parses the node's metadata and, if the peer is new, connects to it
// via the PeerManager and adds it to the appropriate candidate pools.
func (e *meshEventDelegate) NotifyJoin(node *memberlist.Node) {
	meta, err := ParseNodeMeta(node)
	if err != nil {
		log.Printf("[p2p] NotifyJoin: failed to parse metadata for %s: %v", node.Name, err)
		return
	}

	// Skip our own node.
	if e.isSelf(meta.PublicKey) {
		return
	}

	// Flapping prevention: check if this peer recently left.
	if e.inCooldown(meta.PublicKey) {
		log.Printf("[p2p] NotifyJoin: peer %s in cooldown (recently left), delaying connection",
			meta.PublicKey[:8])
		// Still cache the metadata, but delay connection.
		e.cacheMeta(meta)
		return
	}

	e.mu.Lock()
	// Peer is rejoining.
	isNew := e.metaCache[meta.PublicKey] == nil
	e.metaCache[meta.PublicKey] = meta
	pc := e.peerCache

	// Add to capability pools.
	if meta.CapRelay {
		e.relayPool[meta.PublicKey] = meta
	}
	if meta.CapExit {
		e.exitPool[meta.PublicKey] = meta
	}
	if meta.CapProxyEntry {
		e.entryPool[meta.PublicKey] = meta
	}

	// Track collector peers and fire the discovery callback if this is
	// a new collector or a transition to collector capability.
	collectorChanged := false
	if meta.CapCollector {
		_, wasCollector := e.collectorPool[meta.PublicKey]
		if !wasCollector {
			e.collectorPool[meta.PublicKey] = meta
			collectorChanged = true
		}
	} else {
		delete(e.collectorPool, meta.PublicKey)
	}

	joinHdl := e.joinHandler
	collectorHdl := e.collectorHandler
	e.mu.Unlock()

	// Persist peer endpoint to cache.
	if pc != nil {
		pc.OnPeerJoin(meta)
	}

	// Fire collector discovery callback (outside the lock).
	if collectorChanged && collectorHdl != nil {
		log.Printf("[p2p] NotifyJoin: collector peer %s discovered, notifying handler",
			meta.PublicKey[:8])
		collectorHdl(meta.PublicKey)
	}

	// Connect via PeerManager.
	if isNew {
		endpoints := meta.Endpoints
		if len(endpoints) == 0 && e.relayPathBuilder != nil {
			log.Printf("[p2p] NotifyJoin: NAT peer %s discovered (no endpoints), selecting relay...",
				meta.PublicKey[:8])
			e.relayPathBuilder.OnNATPeerDiscovered(meta)

			// Still invoke the external join handler.
			if joinHdl != nil {
				joinHdl(meta)
			}
			return // Skip direct peer addition — relay handles it
		}

		if err := e.wg.Connect(meta.PublicKey, endpoints); err != nil {
			log.Printf("[p2p] NotifyJoin: failed to connect peer %s: %v",
				meta.PublicKey[:8], err)
		} else {
			log.Printf("[p2p] NotifyJoin: connected peer %s (role %s, %d endpoints)",
				meta.PublicKey[:8], meta.Role, len(endpoints))
		}
	}

	// Invoke external join handler.
	if joinHdl != nil {
		joinHdl(meta)
	}
}

// NotifyLeave is called when a node leaves the memberlist cluster.
// It removes the peer from the PeerManager and all pools.
func (e *meshEventDelegate) NotifyLeave(node *memberlist.Node) {
	e.mu.Lock()
	// Look up the full metadata. node.Name is the first 16 chars of the
	// public key, so we need to search the cache for a matching key.
	var meta *NodeMeta
	var foundKey string
	for pk, m := range e.metaCache {
		if len(pk) >= 16 && pk[:16] == node.Name {
			meta = m
			foundKey = pk
			break
		}
	}
	e.mu.Unlock()

	// Set cooldown using the full public key (not node.Name which is only
	// the first 16 chars). This must match the key used by inCooldown,
	// which checks meta.PublicKey (the full 64-char key).
	cooldownKey := foundKey
	if cooldownKey == "" {
		cooldownKey = node.Name // fallback: no metadata available
	}
	e.cooldownMu.Lock()
	e.leaveTimes[cooldownKey] = time.Now()
	e.cooldownMu.Unlock()

	e.mu.Lock()
	if meta != nil {
		// Keep metaCache entry so fallback dialing (DialPeerByEndpoint
		// in main.go meshDialerAdapter) can still find the peer's
		// endpoints. memberlist may mark a peer as failed due to UDP
		// ping timeout even though TCP push/pull works.
		// However, remove from active pools since the connection is gone.
		delete(e.relayPool, foundKey)
		delete(e.exitPool, foundKey)
		delete(e.entryPool, foundKey)
		delete(e.collectorPool, foundKey)
	}
	pc := e.peerCache
	leaveHdl := e.leaveHandler
	e.mu.Unlock()

	// Remove from peer cache.
	if pc != nil && meta != nil {
		pc.OnPeerLeave(meta.PublicKey)
	}

	if meta == nil {
		// We didn't have metadata for this node — nothing to remove.
		if leaveHdl != nil {
			leaveHdl(node.Name)
		}
		return
	}

	// Disconnect from the peer.
	if err := e.wg.Disconnect(meta.PublicKey); err != nil {
		log.Printf("[p2p] NotifyLeave: failed to disconnect peer %s: %v",
			meta.PublicKey[:8], err)
	} else {
		log.Printf("[p2p] NotifyLeave: disconnected peer %s",
			meta.PublicKey[:8])
	}

	// Clean up relay circuits for this peer.
	e.mu.RLock()
	rpb := e.relayPathBuilder
	e.mu.RUnlock()
	if rpb != nil {
		rpb.OnPeerLeft(meta.PublicKey)
	}

	if leaveHdl != nil {
		leaveHdl(meta.PublicKey)
	}
}

// NotifyUpdate is called when a node's metadata changes.
// It updates the cached metadata and recomputes relay rankings if needed.
func (e *meshEventDelegate) NotifyUpdate(node *memberlist.Node) {
	meta, err := ParseNodeMeta(node)
	if err != nil {
		log.Printf("[p2p] NotifyUpdate: failed to parse metadata for %s: %v", node.Name, err)
		return
	}

	if e.isSelf(meta.PublicKey) {
		return
	}

	e.mu.Lock()

	// Capture OLD endpoints BEFORE updating the cache.
	oldEndpoints := []string{}
	if existing, ok := e.metaCache[meta.PublicKey]; ok {
		if existing.Seq > meta.Seq {
			e.mu.Unlock()
			return // stale update, ignore
		}
		oldEndpoints = existing.Endpoints
	}

	// Update cached metadata.
	e.metaCache[meta.PublicKey] = meta
	pc := e.peerCache

	// Update capability pools.
	if meta.CapRelay {
		e.relayPool[meta.PublicKey] = meta
	} else {
		delete(e.relayPool, meta.PublicKey)
	}
	if meta.CapExit {
		e.exitPool[meta.PublicKey] = meta
	} else {
		delete(e.exitPool, meta.PublicKey)
	}
	if meta.CapProxyEntry {
		e.entryPool[meta.PublicKey] = meta
	} else {
		delete(e.entryPool, meta.PublicKey)
	}

	// Track collector capability changes — fire callback on transition.
	collectorChanged := false
	if meta.CapCollector {
		_, wasCollector := e.collectorPool[meta.PublicKey]
		if !wasCollector {
			e.collectorPool[meta.PublicKey] = meta
			collectorChanged = true
		}
	} else {
		delete(e.collectorPool, meta.PublicKey)
	}

	// Endpoint change detection — compares captured old endpoints.
	newEndpoints := meta.Endpoints
	if !endpointsEqual(newEndpoints, oldEndpoints) {
		e.mu.Unlock()
		if err := e.wg.UpdateEndpoints(meta.PublicKey, newEndpoints); err != nil {
			log.Printf("[p2p] NotifyUpdate: failed to update endpoints for %s: %v",
				meta.PublicKey[:8], err)
		}
	} else {
		e.mu.Unlock()
	}

	// Update peer cache with new metadata/endpoints.
	if pc != nil {
		pc.OnPeerUpdate(meta)
	}

	// Fire collector discovery callback if this peer transitioned to collector.
	if collectorChanged {
		e.mu.RLock()
		collectorHdl := e.collectorHandler
		e.mu.RUnlock()
		if collectorHdl != nil {
			log.Printf("[p2p] NotifyUpdate: peer %s became collector, notifying handler",
				meta.PublicKey[:8])
			collectorHdl(meta.PublicKey)
		}
	}

	// Invoke external update handler.
	e.mu.RLock()
	updateHdl := e.updateHandler
	e.mu.RUnlock()

	if updateHdl != nil {
		updateHdl(meta)
	}
}

// endpointsEqual returns true if two endpoint slices contain the same elements.
func endpointsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	// For small slices, a simple comparison is sufficient.
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- Pool accessors ---

// GetRelayCandidates returns all relay-capable peers.
func (e *meshEventDelegate) GetRelayCandidates() []*NodeMeta {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*NodeMeta, 0, len(e.relayPool))
	for _, m := range e.relayPool {
		copy := *m
		result = append(result, &copy)
	}
	return result
}

// GetExitCandidates returns all exit-capable peers.
func (e *meshEventDelegate) GetExitCandidates() []*NodeMeta {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*NodeMeta, 0, len(e.exitPool))
	for _, m := range e.exitPool {
		copy := *m
		result = append(result, &copy)
	}
	return result
}

// GetEntryCandidates returns all proxy-entry-capable peers.
func (e *meshEventDelegate) GetEntryCandidates() []*NodeMeta {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*NodeMeta, 0, len(e.entryPool))
	for _, m := range e.entryPool {
		copy := *m
		result = append(result, &copy)
	}
	return result
}

// GetCollectorCandidates returns all collector-capable peers (CapCollector=true).
func (e *meshEventDelegate) GetCollectorCandidates() []*NodeMeta {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*NodeMeta, 0, len(e.collectorPool))
	for _, m := range e.collectorPool {
		copy := *m
		result = append(result, &copy)
	}
	return result
}

// GetPeerMeta returns cached metadata for a peer, or nil if unknown.
func (e *meshEventDelegate) GetPeerMeta(publicKey string) *NodeMeta {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if m, ok := e.metaCache[publicKey]; ok {
		copy := *m
		return &copy
	}
	return nil
}

// AllKnownPeers returns metadata for all known peers.
func (e *meshEventDelegate) AllKnownPeers() []*NodeMeta {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*NodeMeta, 0, len(e.metaCache))
	for _, m := range e.metaCache {
		copy := *m
		result = append(result, &copy)
	}
	return result
}

// KnownPeerCount returns the number of known peers (excluding self).
func (e *meshEventDelegate) KnownPeerCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.metaCache)
}

// --- Internal helpers ---

func (e *meshEventDelegate) isSelf(publicKey string) bool {
	local := e.delegate.getLocalMeta()
	return local.PublicKey == publicKey
}

func (e *meshEventDelegate) cacheMeta(meta *NodeMeta) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.metaCache[meta.PublicKey] = meta
	if meta.CapRelay {
		e.relayPool[meta.PublicKey] = meta
	}
	if meta.CapExit {
		e.exitPool[meta.PublicKey] = meta
	}
	if meta.CapProxyEntry {
		e.entryPool[meta.PublicKey] = meta
	}
	if meta.CapCollector {
		e.collectorPool[meta.PublicKey] = meta
	}
}

// inCooldown checks flapping prevention: if the peer left within the last
// 60 seconds, it enters a 30-second cooldown before reconnection.
func (e *meshEventDelegate) inCooldown(peerKey string) bool {
	e.cooldownMu.Lock()
	defer e.cooldownMu.Unlock()

	leaveTime, ok := e.leaveTimes[peerKey]
	if !ok {
		return false
	}

	elapsed := time.Since(leaveTime)
	if elapsed > 60*time.Second {
		// Stale entry — clean up.
		delete(e.leaveTimes, peerKey)
		return false
	}

	// In cooldown for the first 30 seconds after leave.
	return elapsed < 30*time.Second
}

// firstNonEmpty returns the first non-empty string in a slice, or "" if all empty.
func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// capabilitiesFromMeta extracts capability strings from NodeMeta.
func capabilitiesFromMeta(m *NodeMeta) []string {
	caps := []string{}
	if m.CapRelay {
		caps = append(caps, "relay")
	}
	if m.CapExit {
		caps = append(caps, "exit")
	}
	if m.CapProxyEntry {
		caps = append(caps, "proxy_entry")
	}
	if m.CapCollector {
		caps = append(caps, "collector")
	}
	return caps
}
