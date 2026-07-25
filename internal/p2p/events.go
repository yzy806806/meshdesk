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

// meshEventDelegate implements memberlist.EventDelegate to bridge gossip
// events to the WireGuard delegate and routing table.
type meshEventDelegate struct {
	delegate  *meshDelegate
	wg        PeerManager
	mu        sync.RWMutex
	metaCache map[string]*NodeMeta // publicKey → latest metadata
	relayPool map[string]*NodeMeta // publicKey → relay candidates (CapRelay)
	exitPool  map[string]*NodeMeta // publicKey → exit candidates (CapExit)
	entryPool map[string]*NodeMeta // publicKey → entry candidates (CapProxyEntry)

	joinHandler   PeerJoinHandler
	leaveHandler  PeerLeaveHandler
	updateHandler PeerUpdateHandler

	// Flapping prevention (§1.7)
	leaveTimes map[string]time.Time // publicKey → last leave time
	cooldownMu sync.Mutex
}

// newMeshEventDelegate creates a new event delegate.
func newMeshEventDelegate(delegate *meshDelegate, wg PeerManager) *meshEventDelegate {
	return &meshEventDelegate{
		delegate:   delegate,
		wg:         wg,
		metaCache:  make(map[string]*NodeMeta),
		relayPool:  make(map[string]*NodeMeta),
		exitPool:   make(map[string]*NodeMeta),
		entryPool:  make(map[string]*NodeMeta),
		leaveTimes: make(map[string]time.Time),
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

// NotifyJoin is called when a new node joins the memberlist cluster.
// It parses the node's metadata and, if the peer is new, adds it to
// WireGuard, the routing table, and the appropriate candidate pools.
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
		log.Printf("[p2p] NotifyJoin: peer %s in cooldown (recently left), delaying WireGuard add",
			meta.PublicKey[:8])
		// Still cache the metadata, but delay WG addition.
		e.cacheMeta(meta)
		return
	}

	e.mu.Lock()
	isNew := e.metaCache[meta.PublicKey] == nil
	e.metaCache[meta.PublicKey] = meta

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

	joinHdl := e.joinHandler
	e.mu.Unlock()

	// Add to WireGuard via delegate.
	if isNew {
		peer := DynamicPeer{
			PublicKey:    meta.PublicKey,
			Endpoint:     firstNonEmpty(meta.Endpoints),
			AllowedIPs:   []string{MeshIPToCIDR(meta.MeshIP)},
			Obfuscation:  "padded",
			Capabilities: capabilitiesFromMeta(meta),
		}

		if err := e.wg.AddDynamicPeer(peer); err != nil {
			log.Printf("[p2p] NotifyJoin: failed to add WireGuard peer %s: %v",
				meta.PublicKey[:8], err)
		} else {
			log.Printf("[p2p] NotifyJoin: added peer %s (mesh IP %s, role %s)",
				meta.PublicKey[:8], meta.MeshIP, meta.Role)
		}
	}

	// Invoke external join handler.
	if joinHdl != nil {
		joinHdl(meta)
	}
}

// NotifyLeave is called when a node leaves the memberlist cluster.
// It removes the peer from WireGuard, the routing table, and all pools.
func (e *meshEventDelegate) NotifyLeave(node *memberlist.Node) {
	e.cooldownMu.Lock()
	e.leaveTimes[node.Name] = time.Now()
	e.cooldownMu.Unlock()

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
	if meta != nil {
		delete(e.metaCache, foundKey)
		delete(e.relayPool, foundKey)
		delete(e.exitPool, foundKey)
		delete(e.entryPool, foundKey)
	}
	leaveHdl := e.leaveHandler
	e.mu.Unlock()

	if meta == nil {
		// We didn't have metadata for this node — nothing to remove.
		if leaveHdl != nil {
			leaveHdl(node.Name)
		}
		return
	}

	// Remove from WireGuard.
	if err := e.wg.RemoveDynamicPeer(meta.PublicKey); err != nil {
		log.Printf("[p2p] NotifyLeave: failed to remove WireGuard peer %s: %v",
			meta.PublicKey[:8], err)
	} else {
		log.Printf("[p2p] NotifyLeave: removed peer %s (mesh IP %s)",
			meta.PublicKey[:8], meta.MeshIP)
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

	// Check for stale metadata (older sequence number).
	if existing, ok := e.metaCache[meta.PublicKey]; ok && existing.Seq > meta.Seq {
		e.mu.Unlock()
		return // stale update, ignore
	}

	// Update cached metadata.
	e.metaCache[meta.PublicKey] = meta

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

	// Update WireGuard endpoint if changed.
	if existing, ok := e.metaCache[meta.PublicKey]; ok {
		newEndpoint := firstNonEmpty(meta.Endpoints)
		oldEndpoint := firstNonEmpty(existing.Endpoints)
		if newEndpoint != "" && newEndpoint != oldEndpoint {
			e.mu.Unlock()
			if err := e.wg.UpdateEndpoint(meta.PublicKey, newEndpoint); err != nil {
				log.Printf("[p2p] NotifyUpdate: failed to update endpoint for %s: %v",
					meta.PublicKey[:8], err)
			}
		} else {
			e.mu.Unlock()
		}
	} else {
		e.mu.Unlock()
	}

	// Invoke external update handler.
	e.mu.RLock()
	updateHdl := e.updateHandler
	e.mu.RUnlock()

	if updateHdl != nil {
		updateHdl(meta)
	}
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
}

// inCooldown checks flapping prevention: if the peer left within the last
// 60 seconds, it enters a 30-second cooldown before WireGuard re-addition.
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
	return caps
}
