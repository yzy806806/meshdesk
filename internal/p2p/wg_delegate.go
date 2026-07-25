package p2p

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh"
)

// PeerManager is the interface for dynamic WireGuard peer management.
// WireGuardDelegate implements this interface, and tests can use mock
// implementations to test event delegate logic without a real MeshNode.
type PeerManager interface {
	// AddDynamicPeer adds a peer discovered via gossip/NAT to WireGuard.
	AddDynamicPeer(peer DynamicPeer) error

	// RemoveDynamicPeer removes a peer from WireGuard.
	RemoveDynamicPeer(publicKey string) error

	// UpdateEndpoint changes a peer's endpoint.
	UpdateEndpoint(publicKey, endpoint string) error

	// IsHealthy returns whether the peer has a recent WireGuard handshake.
	IsHealthy(publicKey string) bool

	// UpdateHandshakeTime records that a handshake completed for a peer.
	UpdateHandshakeTime(publicKey string)

	// IsStaticPeer returns true if the key was from static config.
	IsStaticPeer(publicKey string) bool

	// MarkStaticPeer registers a peer key as static.
	MarkStaticPeer(publicKey string)
}

// Compile-time check that WireGuardDelegate satisfies PeerManager.
var _ PeerManager = (*WireGuardDelegate)(nil)

// DynamicPeer describes a peer discovered via gossip/NAT that should be
// added to WireGuard dynamically (as opposed to static config).
type DynamicPeer struct {
	// PublicKey is the WireGuard public key (hex).
	PublicKey string

	// Endpoint is the "host:port" for WG UDP.
	Endpoint string

	// AllowedIPs are the mesh IPs to route to this peer.
	AllowedIPs []string

	// Capabilities from NodeMeta.
	Capabilities []string

	// Obfuscation mode string ("none", "padded", "websocket").
	Obfuscation string

	// IsRelay indicates this is a relayed connection (not direct).
	IsRelay bool

	// RelayVia is the peer key of the relay (if IsRelay).
	RelayVia string
}

// PeerHealth tracks the WireGuard handshake health for a dynamic peer.
type PeerHealth struct {
	PublicKey        string
	LastHandshake    time.Time
	Endpoint         string
	IsRelay          bool
	RelayVia         string
	AddedAt          time.Time
}

// WireGuardDelegate is the bridge between dynamic gossip events and the
// static MeshNode.AddPeer()/RemovePeer() API. It wraps MeshNode and
// provides dynamic peer management with health tracking.
type WireGuardDelegate struct {
	node    *mesh.MeshNode
	mu      sync.Mutex
	health  map[string]*PeerHealth // publicKey → health
	staticKeys map[string]bool      // keys from static config (never removed)
}

// NewWireGuardDelegate creates a new delegate wrapping the given MeshNode.
func NewWireGuardDelegate(node *mesh.MeshNode) *WireGuardDelegate {
	return &WireGuardDelegate{
		node:       node,
		health:     make(map[string]*PeerHealth),
		staticKeys: make(map[string]bool),
	}
}

// MarkStaticPeer registers a peer key as coming from static config.
// Static peers are never removed by dynamic events (§4.4 backward compat).
func (d *WireGuardDelegate) MarkStaticPeer(publicKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.staticKeys[publicKey] = true
}

// IsStaticPeer returns true if the key was registered as static.
func (d *WireGuardDelegate) IsStaticPeer(publicKey string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.staticKeys[publicKey]
}

// AddDynamicPeer adds a peer discovered via gossip/NAT to WireGuard.
// It configures the peer in the WireGuard device and the routing table.
// If the peer already exists (endpoint update), it updates the endpoint
// without removing and re-adding.
func (d *WireGuardDelegate) AddDynamicPeer(peer DynamicPeer) error {
	if peer.PublicKey == "" {
		return fmt.Errorf("dynamic peer public key is empty")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if we already have this peer.
	if existing, ok := d.health[peer.PublicKey]; ok {
		// Update endpoint only — WireGuard UAPI supports in-place updates.
		if existing.Endpoint != peer.Endpoint && peer.Endpoint != "" {
			if err := d.updateEndpointLocked(peer.PublicKey, peer.Endpoint); err != nil {
				return fmt.Errorf("update endpoint for %s: %w", peer.PublicKey[:8], err)
			}
			existing.Endpoint = peer.Endpoint
		}
		existing.IsRelay = peer.IsRelay
		existing.RelayVia = peer.RelayVia
		return nil
	}

	// Build PeerConfig for MeshNode.AddPeer.
	peerCfg := config.PeerConfig{
		PublicKey:   peer.PublicKey,
		Endpoint:    peer.Endpoint,
		AllowedIPs:  peer.AllowedIPs,
		Obfuscation: peer.Obfuscation,
	}
	if peer.Obfuscation == "" {
		peerCfg.Obfuscation = "padded" // default to padded for GFW resistance
	}

	// Add to WireGuard via MeshNode (which handles IPC + routing table).
	if err := d.node.AddPeer(peerCfg); err != nil {
		return fmt.Errorf("add dynamic peer %s: %w", peer.PublicKey[:8], err)
	}

	// Track health.
	d.health[peer.PublicKey] = &PeerHealth{
		PublicKey:     peer.PublicKey,
		Endpoint:      peer.Endpoint,
		IsRelay:       peer.IsRelay,
		RelayVia:      peer.RelayVia,
		AddedAt:       time.Now(),
	}

	return nil
}

// RemoveDynamicPeer removes a peer from WireGuard (gossip leave/failure).
// Static peers are NOT removed (§4.4 backward compat).
func (d *WireGuardDelegate) RemoveDynamicPeer(publicKey string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Never remove static peers.
	if d.staticKeys[publicKey] {
		return nil
	}

	// Check if we have this peer.
	if _, ok := d.health[publicKey]; !ok {
		return nil // already removed or never added — idempotent
	}

	// Remove from WireGuard via MeshNode.
	if err := d.node.RemovePeer(publicKey); err != nil {
		return fmt.Errorf("remove dynamic peer %s: %w", publicKey[:8], err)
	}

	delete(d.health, publicKey)
	return nil
}

// UpdateEndpoint changes a peer's endpoint (NAT rebind, direct↔relay switch).
// This uses WireGuard's UAPI in-place endpoint update — no re-key needed.
func (d *WireGuardDelegate) UpdateEndpoint(publicKey, endpoint string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.updateEndpointLocked(publicKey, endpoint)
}

func (d *WireGuardDelegate) updateEndpointLocked(publicKey, endpoint string) error {
	if publicKey == "" || endpoint == "" {
		return fmt.Errorf("public key and endpoint are required")
	}

	// Use WireGuard UAPI to update the endpoint in-place.
	// The IPC format is:
	//   public_key=<hex>
	//   endpoint=<host:port>
	ipc := fmt.Sprintf("public_key=%s\nendpoint=%s\n", publicKey, endpoint)
	if err := d.node.Device().IpcSet(ipc); err != nil {
		return fmt.Errorf("ipc update endpoint: %w", err)
	}

	// Update health tracking.
	if h, ok := d.health[publicKey]; ok {
		h.Endpoint = endpoint
	}

	return nil
}

// IsHealthy returns whether the WireGuard handshake with this peer
// completed within the last 2 minutes.
func (d *WireGuardDelegate) IsHealthy(publicKey string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	h, ok := d.health[publicKey]
	if !ok {
		return false
	}

	// If we haven't seen a handshake, check if the peer was recently added.
	if h.LastHandshake.IsZero() {
		return time.Since(h.AddedAt) < 2*time.Minute
	}

	return time.Since(h.LastHandshake) < 2*time.Minute
}

// UpdateHandshakeTime records that a handshake completed for a peer.
// This is called by the health polling goroutine (§2.3).
func (d *WireGuardDelegate) UpdateHandshakeTime(publicKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if h, ok := d.health[publicKey]; ok {
		h.LastHandshake = time.Now()
	}
}

// GetPeerHealth returns the health record for a peer, or nil if not tracked.
func (d *WireGuardDelegate) GetPeerHealth(publicKey string) *PeerHealth {
	d.mu.Lock()
	defer d.mu.Unlock()

	if h, ok := d.health[publicKey]; ok {
		copy := *h
		return &copy
	}
	return nil
}

// AllDynamicPeers returns all dynamically-added peer keys.
func (d *WireGuardDelegate) AllDynamicPeers() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	keys := make([]string, 0, len(d.health))
	for k := range d.health {
		keys = append(keys, k)
	}
	return keys
}

// DynamicPeerCount returns the number of dynamically-added peers.
func (d *WireGuardDelegate) DynamicPeerCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.health)
}

// deriveMeshIPFromHex computes a mesh IP from a hex public key,
// using the same algorithm as mesh.deriveMeshIP.
func deriveMeshIPFromHex(pubKeyHex string) string {
	if len(pubKeyHex) < 4 {
		return "10.10.0.1"
	}
	var b0, b1 byte
	fmt.Sscanf(pubKeyHex[:2], "%02x", &b0)
	fmt.Sscanf(pubKeyHex[2:4], "%02x", &b1)
	b0 = b0%254 + 1
	b1 = b1%254 + 1
	return fmt.Sprintf("10.10.%d.%d", b0, b1)
}

// MeshIPToCIDR converts a bare mesh IP to a /32 CIDR for AllowedIPs.
func MeshIPToCIDR(meshIP string) string {
	meshIP = strings.TrimSpace(meshIP)
	if strings.Contains(meshIP, "/") {
		return meshIP
	}
	return meshIP + "/32"
}
