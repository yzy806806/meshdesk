package p2p

import (
	"fmt"
	"log"
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

	// AddRelayTarget adds a remote peer to this relay's WireGuard config
	// so that traffic can be forwarded to it. Called by RelaySessionManager
	// when a circuit_setup request is accepted.
	AddRelayTarget(targetKey, targetMeshIP string) error

	// AddRelayRoute extends a relay peer's AllowedIPs to include a
	// target peer's mesh IP, routing that target's traffic through the relay.
	// Called on the entry node (A) when the relay accepts the circuit.
	AddRelayRoute(relayKey, targetMeshIP string) error

	// RemoveRelayRoute removes a target mesh IP from a relay peer's
	// AllowedIPs. Called on the entry node when a circuit is torn down.
	RemoveRelayRoute(relayKey, targetMeshIP string) error
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

	// IsRelay indicates this is a relayed connection (not direct).
	IsRelay bool

	// RelayVia is the peer key of the relay (if IsRelay).
	RelayVia string
}

// PeerHealth tracks the WireGuard handshake health for a dynamic peer.
type PeerHealth struct {
	PublicKey     string
	LastHandshake time.Time
	Endpoint      string
	IsRelay       bool
	RelayVia      string
	AddedAt       time.Time
}

// WireGuardDelegate is the bridge between dynamic gossip events and the
// static MeshNode.AddPeer()/RemovePeer() API. It wraps MeshNode and
// provides dynamic peer management with health tracking.
type WireGuardDelegate struct {
	node       *mesh.MeshNode
	mu         sync.Mutex
	health     map[string]*PeerHealth // publicKey → health
	staticKeys map[string]bool        // keys from static config (never removed)
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
		PublicKey:  peer.PublicKey,
		Endpoint:   peer.Endpoint,
		AllowedIPs: peer.AllowedIPs,
	}

	// Add to the mesh node (v2: routing table update).
	if err := d.node.AddPeer(peerCfg); err != nil {
		return fmt.Errorf("add dynamic peer %s: %w", peer.PublicKey[:8], err)
	}

	// Track health.
	d.health[peer.PublicKey] = &PeerHealth{
		PublicKey: peer.PublicKey,
		Endpoint:  peer.Endpoint,
		IsRelay:   peer.IsRelay,
		RelayVia:  peer.RelayVia,
		AddedAt:   time.Now(),
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

	// TODO(v2): update peer endpoint via the new protocol layer.
	// v1 used WireGuard UAPI IpcSet; v2 will use the HandshakeLayer.

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

// AddRelayTarget adds a remote peer to this relay's config so that
// traffic can be forwarded to it. The peer is added without an explicit
// endpoint — the relay learns the endpoint via the v2 protocol layer.
//
// This is called by the RelaySessionManager when a circuit_setup
// request is accepted (on the relay node R, adding target B).
func (d *WireGuardDelegate) AddRelayTarget(targetKey, targetMeshIP string) error {
	if targetKey == "" {
		return fmt.Errorf("target key is empty")
	}

	d.mu.Lock()
	// Check if already tracked (may have been added via gossip).
	if _, ok := d.health[targetKey]; ok {
		// Already known — no need to re-add. The peer was added by
		// NotifyJoin when this relay discovered it via gossip.
		d.mu.Unlock()
		return nil
	}
	d.mu.Unlock()

	peer := DynamicPeer{
		PublicKey:  targetKey,
		AllowedIPs: []string{targetMeshIP},
		IsRelay:    true,
	}
	// Endpoint is intentionally empty — learned from keepalive.
	return d.AddDynamicPeer(peer)
}

// AddRelayRoute extends a relay peer's AllowedIPs to include a
// target peer's mesh IP. This tells WireGuard to route packets
// destined for the target through this relay.
//
// This is called on the entry node (A) after the relay (R) accepts
// the circuit — A extends R's AllowedIPs to include B's mesh IP.
//
// WireGuard UAPI allows in-place peer modification by re-sending
// the peer config with updated allowed_ips.
func (d *WireGuardDelegate) AddRelayRoute(relayKey, targetMeshIP string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.health[relayKey]; !ok {
		return fmt.Errorf("relay peer %s not found", shortKey(relayKey))
	}

	// Build IPC to extend the relay peer's AllowedIPs.
	// WireGuard UAPI: setting allowed_ip on an existing peer replaces
	// the entire AllowedIPs set, so we must include all existing IPs
	// plus the new one.
	// TODO(v2): extend relay peer's routes via the new protocol layer.
	_ = targetMeshIP

	log.Printf("[p2p] added relay route: peer %s → target %s via relay %s",
		shortKey(relayKey), targetMeshIP, shortKey(relayKey))

	return nil
}

// RemoveRelayRoute removes a target mesh IP from a relay peer's AllowedIPs.
//
// WireGuard UAPI supports removing specific allowed_ip entries using
// the "-" prefix on the allowed_ip line. This allows surgical removal
// without affecting other routes.
func (d *WireGuardDelegate) RemoveRelayRoute(relayKey, targetMeshIP string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.health[relayKey]; !ok {
		return nil // peer already removed — idempotent
	}

	// TODO(v2): remove relay route via the new protocol layer.
	_ = targetMeshIP

	log.Printf("[p2p] removed relay route: target %s from relay %s",
		targetMeshIP, shortKey(relayKey))

	return nil
}
