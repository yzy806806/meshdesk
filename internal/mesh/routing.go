package mesh

import (
	"fmt"
	"net/netip"
	"sync"
)

// RoutingTable maintains the mapping of mesh IPs to peer IDs.
// It's the core data structure that the mesh routing layer uses to
// decide which peer to send a packet to.
type RoutingTable struct {
	mu     sync.RWMutex
	routes map[string]string     // mesh IP (string) → peer ID (hex public key)
	peers  map[string]*PeerEntry // peer ID → peer entry
}

// PeerEntry holds the state for a single mesh peer.
type PeerEntry struct {
	ID          string   // hex public key
	Endpoint    string   // host:port
	AllowedIPs  []string // mesh IPs
	Obfuscation ObfuscationMode
}

// NewRoutingTable creates an empty routing table.
func NewRoutingTable() *RoutingTable {
	return &RoutingTable{
		routes: make(map[string]string),
		peers:  make(map[string]*PeerEntry),
	}
}

// AddPeer adds or updates a peer in the routing table.
func (rt *RoutingTable) AddPeer(peer *PeerEntry) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Remove old routes for this peer if it already exists.
	if existing, ok := rt.peers[peer.ID]; ok {
		for _, ip := range existing.AllowedIPs {
			delete(rt.routes, ip)
		}
	}

	rt.peers[peer.ID] = peer
	for _, ip := range peer.AllowedIPs {
		rt.routes[ip] = peer.ID
	}
}

// RemovePeer removes a peer from the routing table.
func (rt *RoutingTable) RemovePeer(peerID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if peer, ok := rt.peers[peerID]; ok {
		for _, ip := range peer.AllowedIPs {
			delete(rt.routes, ip)
		}
		delete(rt.peers, peerID)
	}
}

// ResolveRoute looks up the peer ID for a given mesh IP.
func (rt *RoutingTable) ResolveRoute(meshIP string) (string, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	pid, ok := rt.routes[meshIP]
	return pid, ok
}

// GetPeer returns the peer entry for a given peer ID.
func (rt *RoutingTable) GetPeer(peerID string) (*PeerEntry, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	p, ok := rt.peers[peerID]
	return p, ok
}

// AllPeers returns a slice of all known peers.
func (rt *RoutingTable) AllPeers() []*PeerEntry {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	peers := make([]*PeerEntry, 0, len(rt.peers))
	for _, p := range rt.peers {
		peers = append(peers, p)
	}
	return peers
}

// PeerCount returns the number of known peers.
func (rt *RoutingTable) PeerCount() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return len(rt.peers)
}

// ResolvePeerByIP resolves a mesh IP to its PeerEntry.
func (rt *RoutingTable) ResolvePeerByIP(meshIP string) (*PeerEntry, bool) {
	pid, ok := rt.ResolveRoute(meshIP)
	if !ok {
		return nil, false
	}
	return rt.GetPeer(pid)
}

// IsIPInPrefix checks whether the given IP falls within a CIDR prefix string.
func IsIPInPrefix(ip, prefix string) (bool, error) {
	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return false, fmt.Errorf("parse IP: %w", err)
	}
	parsedPrefix, err := netip.ParsePrefix(prefix)
	if err != nil {
		return false, fmt.Errorf("parse prefix: %w", err)
	}
	return parsedPrefix.Contains(parsedIP), nil
}
