// Package tun provides TUN device management and routing for mesh
// virtual network interfaces.
//
// Router maintains the VirtualIP → PublicKey mapping that allows the
// TUN forwarder to look up the destination peer for each IP packet
// read from the TUN device. The mapping is populated from gossip
// NodeMeta (VirtualIP field) and is updated as peers join/leave.
package tun

import (
	"fmt"
	"net"
	"sync"
)

// Router maintains the bidirectional mapping between TUN subnet
// VirtualIPs and mesh peer public keys.
//
// The router is the core data structure for the TUN data path:
//   - TUN → mesh: when an IP packet is read from the TUN device,
//     the destination IP is looked up in the router to find the
//     target peer's public key, then a smux stream is opened to
//     that peer's TUN virtual port.
//   - mesh → TUN: when a packet arrives over a smux stream, the
//     source peer's public key is looked up to find the source
//     VirtualIP (for logging/validation), and the raw IP packet
//     is written to the TUN device.
//
// All methods are safe for concurrent use.
type Router struct {
	mu sync.RWMutex

	// ipToPeer maps VirtualIP (string form, e.g. "10.10.0.5") →
	// peer public key (hex string).
	ipToPeer map[string]string

	// peerToIP maps peer public key (hex string) → VirtualIP
	// (net.IP). This is the reverse mapping, used for source IP
	// lookup and for removing entries by peer key.
	peerToIP map[string]net.IP

	// localIP is this node's own VirtualIP. Used to detect
	// packets destined for self (which should be delivered
	// locally, not forwarded over the mesh).
	localIP net.IP

	// localPubKey is this node's own public key (hex string).
	localPubKey string

	// subnet is the TUN subnet CIDR (e.g. 10.10.0.0/24).
	// Used to validate that IPs belong to the mesh subnet.
	subnet *net.IPNet
}

// NewRouter creates a new TUN router for the given subnet.
// localPubKey is this node's Ed25519 public key (hex-encoded).
func NewRouter(subnet *net.IPNet, localPubKey string) *Router {
	return &Router{
		ipToPeer:    make(map[string]string),
		peerToIP:    make(map[string]net.IP),
		localPubKey: localPubKey,
		subnet:      subnet,
	}
}

// SetLocalIP sets this node's own VirtualIP in the routing table.
// This allows the router to recognize self-destined packets.
func (r *Router) SetLocalIP(ip net.IP) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Remove old self IP entry if present to prevent stale route leakage.
	if r.localIP != nil {
		oldStr := r.localIP.String()
		if oldStr != ip.String() {
			delete(r.ipToPeer, oldStr)
		}
	}
	r.localIP = make(net.IP, len(ip))
	copy(r.localIP, ip)
	// Also add self to the routing table so lookups work.
	r.ipToPeer[ip.String()] = r.localPubKey
	r.peerToIP[r.localPubKey] = ip
}

// LocalIP returns this node's VirtualIP, or nil if not set.
func (r *Router) LocalIP() net.IP {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.localIP == nil {
		return nil
	}
	cp := make(net.IP, len(r.localIP))
	copy(cp, r.localIP)
	return cp
}

// LocalPubKey returns this node's public key (hex string).
func (r *Router) LocalPubKey() string {
	return r.localPubKey
}

// Subnet returns the TUN subnet CIDR.
func (r *Router) Subnet() *net.IPNet {
	return r.subnet
}

// AddRoute adds or updates a VirtualIP → publicKey mapping.
// If the peer already had a different IP, the old mapping is removed.
// If the IP was already assigned to a different peer, it is overwritten
// (the most recent announcement wins, matching gossip's last-writer
// semantics).
func (r *Router) AddRoute(virtualIP net.IP, pubKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ipStr := virtualIP.String()

	// If this peer already had a different IP, remove the old mapping.
	if oldIP, ok := r.peerToIP[pubKey]; ok && oldIP.String() != ipStr {
		delete(r.ipToPeer, oldIP.String())
	}

	// If this IP was assigned to a different peer, remove the old
	// peer's reverse mapping (the new peer takes over this IP).
	if oldPeer, ok := r.ipToPeer[ipStr]; ok && oldPeer != pubKey {
		delete(r.peerToIP, oldPeer)
	}

	r.ipToPeer[ipStr] = pubKey
	peerIP := make(net.IP, len(virtualIP))
	copy(peerIP, virtualIP)
	r.peerToIP[pubKey] = peerIP
}

// RemoveRoute removes the mapping for the given peer public key.
// Returns the IP that was removed, if any. Self routes (where pubKey
// matches the local node's key) are never removed — RemoveRoute returns
// (nil, false) for them.
func (r *Router) RemoveRoute(pubKey string) (net.IP, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Never remove self route.
	if pubKey == r.localPubKey {
		return nil, false
	}

	ip, ok := r.peerToIP[pubKey]
	if !ok {
		return nil, false
	}

	delete(r.peerToIP, pubKey)
	delete(r.ipToPeer, ip.String())

	return ip, true
}

// RemoveByIP removes the mapping for the given VirtualIP.
// Returns the peer key that was removed, if any.
func (r *Router) RemoveByIP(virtualIP net.IP) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ipStr := virtualIP.String()
	pubKey, ok := r.ipToPeer[ipStr]
	if !ok {
		return "", false
	}

	// Don't remove self.
	if pubKey == r.localPubKey {
		return pubKey, false
	}

	delete(r.ipToPeer, ipStr)
	delete(r.peerToIP, pubKey)

	return pubKey, true
}

// ResolveIP looks up the peer public key for a given VirtualIP.
// Returns the public key and true if found, empty string and false
// otherwise.
func (r *Router) ResolveIP(virtualIP net.IP) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	pubKey, ok := r.ipToPeer[virtualIP.String()]
	return pubKey, ok
}

// ResolvePeer looks up the VirtualIP for a given peer public key.
// Returns the IP and true if found, nil and false otherwise.
func (r *Router) ResolvePeer(pubKey string) (net.IP, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ip, ok := r.peerToIP[pubKey]
	if !ok {
		return nil, false
	}
	cp := make(net.IP, len(ip))
	copy(cp, ip)
	return cp, true
}

// IsLocalIP returns true if the given IP is this node's own VirtualIP.
func (r *Router) IsLocalIP(ip net.IP) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.localIP == nil {
		return false
	}
	return r.localIP.Equal(ip)
}

// IsInSubnet returns true if the given IP falls within the TUN subnet.
func (r *Router) IsInSubnet(ip net.IP) bool {
	if r.subnet == nil {
		return false
	}
	return r.subnet.Contains(ip)
}

// IsSelf returns true if the given public key is this node's own key.
func (r *Router) IsSelf(pubKey string) bool {
	return pubKey == r.localPubKey
}

// RouteCount returns the number of routes in the table (excluding self).
func (r *Router) RouteCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	count := 0
	for pk := range r.peerToIP {
		if pk != r.localPubKey {
			count++
		}
	}
	return count
}

// AllRoutes returns a snapshot of all VirtualIP → publicKey mappings
// as a map of IP string → public key. Includes self.
func (r *Router) AllRoutes() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]string, len(r.ipToPeer))
	for ip, pk := range r.ipToPeer {
		result[ip] = pk
	}
	return result
}

// SyncFromPeers rebuilds the routing table from a set of peer metadata.
// Each entry is a (publicKey, virtualIP) pair. Existing entries for
// peers not in the new set are removed.
//
// This is typically called periodically (e.g., on gossip state sync)
// to ensure the routing table converges with the gossip view.
func (r *Router) SyncFromPeers(peers []PeerRoute) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Build the new set.
	newIPs := make(map[string]string)   // ip → pubkey
	newPeers := make(map[string]net.IP) // pubkey → ip

	for _, p := range peers {
		if p.VirtualIP == nil || p.PublicKey == "" {
			continue
		}
		ipStr := p.VirtualIP.String()
		// If duplicate IPs, first one wins (deterministic).
		if _, exists := newIPs[ipStr]; !exists {
			newIPs[ipStr] = p.PublicKey
			ip := make(net.IP, len(p.VirtualIP))
			copy(ip, p.VirtualIP)
			newPeers[p.PublicKey] = ip
		}
	}

	// Preserve self.
	if r.localIP != nil {
		newIPs[r.localIP.String()] = r.localPubKey
		ip := make(net.IP, len(r.localIP))
		copy(ip, r.localIP)
		newPeers[r.localPubKey] = ip
	}

	r.ipToPeer = newIPs
	r.peerToIP = newPeers
}

// PeerRoute is a single peer routing entry used by SyncFromPeers.
type PeerRoute struct {
	PublicKey string
	VirtualIP net.IP
}

// String returns a human-readable summary of the router state.
func (r *Router) String() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return fmt.Sprintf("tun.Router{subnet=%s, routes=%d, localIP=%s}",
		r.subnet, len(r.ipToPeer), r.localIP)
}
