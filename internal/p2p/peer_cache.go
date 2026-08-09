package p2p

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
)

// DefaultPeerCachePath is the default file path for persisted discovered
// peer endpoints. The file is JSON-encoded and written atomically.
// This constant is kept for backward compatibility; new code should use
// config.DefaultPeerCachePath() which resolves a non-root fallback path.
const DefaultPeerCachePath = "/var/lib/meshdesk/peers.cache"

// peerCacheSaveInterval is how often the background save goroutine flushes
// the cache to disk when dirty.
const peerCacheSaveInterval = 30 * time.Second

// CachedPeer holds the persisted state for a single discovered peer.
// Only peers with at least one endpoint are cached — NAT peers without
// endpoints are not persisted because their relay circuits are rebuilt
// dynamically on each startup.
type CachedPeer struct {
	PublicKey    string   `json:"pk"`
	Hostname     string   `json:"hn,omitempty"`
	Role         string   `json:"role,omitempty"`
	Endpoints    []string `json:"eps"`
	VirtualIP    string   `json:"vip,omitempty"` // persisted TUN VirtualIP for route restoration
	FirstSeen    int64    `json:"fs"`            // Unix timestamp
	LastSeen     int64    `json:"ls"`            // Unix timestamp
	CapCollector bool     `json:"cc,omitempty"`  // persisted collector capability
}

// peerCacheFile is the JSON representation of the on-disk cache file.
type peerCacheFile struct {
	Version int          `json:"v"`
	SavedAt int64        `json:"saved_at"`
	Peers   []CachedPeer `json:"peers"`
}

// PeerCache persists discovered shared-node endpoints to disk so that
// on restart the node can immediately attempt to re-connect to previously
// known peers without waiting for gossip to rediscover them.
//
// The cache is:
//   - Updated on every NotifyJoin/NotifyUpdate/NotifyLeave event
//   - Flushed to disk periodically (every 30s) by a background goroutine
//   - Flushed on shutdown via SaveNow()
//   - Loaded at startup via LoadPeerCache()
//
// Only peers with non-empty Endpoints are cached. The cache is advisory —
// gossip is the authoritative source. Stale entries are overwritten when
// gossip re-discovers the peer.
type PeerCache struct {
	mu      sync.Mutex
	path    string
	peers   map[string]*CachedPeer // publicKey → cached peer
	dirty   bool
	stopCh  chan struct{}
	stopped bool
}

// NewPeerCache creates a new PeerCache backed by the given file path.
// The file is not read or written until Load() or SaveNow() is called.
// When path is empty, the default path is resolved via
// config.DefaultPeerCachePath(), which picks /var/lib/meshdesk/peers.cache
// for root or ~/.meshdesk/peers.cache for non-root users.
func NewPeerCache(path string) *PeerCache {
	if path == "" {
		path = config.DefaultPeerCachePath()
	}
	return &PeerCache{
		path:   path,
		peers:  make(map[string]*CachedPeer),
		stopCh: make(chan struct{}),
	}
}

// Load reads the cache file from disk. Returns an empty cache (no error)
// if the file does not exist. Returns an error only for malformed JSON
// or read permission issues.
func (c *PeerCache) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no cache file — fresh start
		}
		return fmt.Errorf("read peer cache %s: %w", c.path, err)
	}

	if len(data) == 0 {
		return nil
	}

	var f peerCacheFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse peer cache %s: %w", c.path, err)
	}

	c.peers = make(map[string]*CachedPeer, len(f.Peers))
	for i := range f.Peers {
		p := f.Peers[i]
		c.peers[p.PublicKey] = &p
	}

	log.Printf("[p2p] loaded peer cache: %d peers from %s", len(c.peers), c.path)
	return nil
}

// SaveNow writes the cache to disk immediately. Safe to call concurrently
// with the background save loop. Creates parent directories if needed.
func (c *PeerCache) SaveNow() error {
	c.mu.Lock()
	if !c.dirty && len(c.peers) > 0 {
		// Not dirty but has data — still allow save (called on shutdown).
	} else if !c.dirty && len(c.peers) == 0 {
		c.mu.Unlock()
		return nil
	}

	peers := make([]CachedPeer, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, *p)
	}
	c.dirty = false
	c.mu.Unlock()

	f := peerCacheFile{
		Version: 1,
		SavedAt: time.Now().Unix(),
		Peers:   peers,
	}

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal peer cache: %w", err)
	}

	// Write atomically: write to temp file, then rename.
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create peer cache dir %s: %w", dir, err)
	}

	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write peer cache tmp %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, c.path); err != nil {
		// Best-effort cleanup of the temp file.
		_ = os.Remove(tmp)
		return fmt.Errorf("rename peer cache %s → %s: %w", tmp, c.path, err)
	}

	return nil
}

// OnPeerJoin adds or updates a peer in the cache. Called from NotifyJoin.
// Only peers with at least one endpoint are cached.
func (c *PeerCache) OnPeerJoin(meta *NodeMeta) {
	if meta == nil || meta.PublicKey == "" {
		return
	}
	if len(meta.Endpoints) == 0 {
		return // Don't cache peers without endpoints (NAT peers)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().Unix()
	if existing, ok := c.peers[meta.PublicKey]; ok {
		existing.Hostname = meta.Hostname
		existing.Role = meta.Role
		existing.Endpoints = meta.Endpoints
		existing.VirtualIP = meta.VirtualIP
		existing.LastSeen = now
		existing.CapCollector = meta.CapCollector
	} else {
		c.peers[meta.PublicKey] = &CachedPeer{
			PublicKey:    meta.PublicKey,
			Hostname:     meta.Hostname,
			Role:         meta.Role,
			Endpoints:    meta.Endpoints,
			VirtualIP:    meta.VirtualIP,
			FirstSeen:    now,
			LastSeen:     now,
			CapCollector: meta.CapCollector,
		}
	}
	c.dirty = true
}

// OnPeerUpdate updates a peer's metadata in the cache. Called from
// NotifyUpdate. Removes the peer if its endpoints become empty.
func (c *PeerCache) OnPeerUpdate(meta *NodeMeta) {
	if meta == nil || meta.PublicKey == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(meta.Endpoints) == 0 {
		// Peer lost all endpoints — remove from cache.
		if _, ok := c.peers[meta.PublicKey]; ok {
			delete(c.peers, meta.PublicKey)
			c.dirty = true
		}
		return
	}

	now := time.Now().Unix()
	if existing, ok := c.peers[meta.PublicKey]; ok {
		existing.Hostname = meta.Hostname
		existing.Role = meta.Role
		existing.Endpoints = meta.Endpoints
		existing.VirtualIP = meta.VirtualIP
		existing.LastSeen = now
		existing.CapCollector = meta.CapCollector
	} else {
		c.peers[meta.PublicKey] = &CachedPeer{
			PublicKey:    meta.PublicKey,
			Hostname:     meta.Hostname,
			Role:         meta.Role,
			Endpoints:    meta.Endpoints,
			VirtualIP:    meta.VirtualIP,
			FirstSeen:    now,
			LastSeen:     now,
			CapCollector: meta.CapCollector,
		}
	}
	c.dirty = true
}

// OnPeerLeave marks a peer as stale in the cache but does NOT delete it.
// Called from NotifyLeave. The peer entry is retained so that on restart
// the node can still use the cached endpoint as a gossip seed and collector
// candidates survive transient UDP failures. Stale entries are overwritten
// when gossip re-discovers the peer via OnPeerJoin/OnPeerUpdate.
//
// This matches the metaCache retention behavior in NotifyLeave (events.go):
// the metaCache entry is kept for fallback dialing, and the peer cache
// follows the same strategy for endpoint and collector persistence.
func (c *PeerCache) OnPeerLeave(peerKey string) {
	if peerKey == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.peers[peerKey]; ok {
		existing.LastSeen = time.Now().Unix()
		c.dirty = true
	}
}

// AllCachedPeers returns a copy of all cached peers.
func (c *PeerCache) AllCachedPeers() []CachedPeer {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := make([]CachedPeer, 0, len(c.peers))
	for _, p := range c.peers {
		result = append(result, *p)
	}
	return result
}

// CachedPeerCount returns the number of cached peers.
func (c *PeerCache) CachedPeerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.peers)
}

// StartSaveLoop launches a background goroutine that periodically flushes
// the cache to disk when dirty. Call Stop() to terminate the loop and
// perform a final save.
func (c *PeerCache) StartSaveLoop() {
	go func() {
		ticker := time.NewTicker(peerCacheSaveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				if err := c.SaveNow(); err != nil {
					log.Printf("[p2p] peer cache periodic save error: %v", err)
				}
			}
		}
	}()
}

// Stop terminates the background save loop and performs a final flush.
// Safe to call multiple times.
func (c *PeerCache) Stop() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	c.mu.Unlock()

	close(c.stopCh)

	if err := c.SaveNow(); err != nil {
		log.Printf("[p2p] peer cache final save error: %v", err)
	}
}

// CachedEndpointsAsSeeds returns all cached peer endpoints as a list
// of "host:port" addresses suitable for use as gossip seeds. This allows
// a restarting node to immediately try connecting to previously known
// peers without waiting for gossip discovery.
func (c *PeerCache) CachedEndpointsAsSeeds() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	seen := make(map[string]bool)
	var seeds []string
	for _, p := range c.peers {
		for _, ep := range p.Endpoints {
			if ep == "" || seen[ep] {
				continue
			}
			seen[ep] = true
			seeds = append(seeds, ep)
		}
	}
	return seeds
}

// CachedVirtualIPs returns a map of peer public key → persisted TUN
// VirtualIP. Used at startup to restore TUN /32 routes before gossip has
// propagated peer metadata (which may take minutes in mixed IP-family
// meshes). Only peers with both an endpoint and a VirtualIP are included.
func (c *PeerCache) CachedVirtualIPs() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make(map[string]string)
	for pk, p := range c.peers {
		if p.VirtualIP != "" && len(p.Endpoints) > 0 {
			out[pk] = p.VirtualIP
		}
	}
	return out
}

// CachedCollectors returns the public keys of all cached peers that have
// CapCollector=true. This is used at startup to seed the reporter's
// collector list from persisted state, so that monitor routing is
// immediately available after a restart — without waiting for gossip
// to re-discover collector nodes.
func (c *PeerCache) CachedCollectors() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var keys []string
	for _, p := range c.peers {
		if p.CapCollector {
			keys = append(keys, p.PublicKey)
		}
	}
	return keys
}
