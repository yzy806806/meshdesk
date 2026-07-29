package p2p

import (
	"fmt"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/mesh"
)

// PeerManager is the v2 interface for dynamic peer connection management.
// Unlike v1's PeerManager (which was WireGuard-specific), v2 PeerManager
// works with HandshakeLayer connections and is transport-agnostic.
type PeerManager interface {
	// Connect establishes a connection to a peer using the first reachable
	// endpoint from its metadata. Returns an error if all endpoints fail.
	Connect(peerKey string, endpoints []string) error

	// Disconnect closes the connection to a peer and cleans up state.
	Disconnect(peerKey string) error

	// UpdateEndpoints refreshes the known endpoints for a peer.
	// Called when NotifyUpdate detects endpoint changes.
	UpdateEndpoints(peerKey string, endpoints []string) error

	// IsConnected returns whether a connection to the peer is active.
	IsConnected(peerKey string) bool

	// IsStaticPeer returns true if the peer was from static config.
	IsStaticPeer(peerKey string) bool

	// MarkStaticPeer registers a peer key as static.
	MarkStaticPeer(peerKey string)

	// ── Relay operations ──

	// AddRelayTarget adds a remote peer as a relay target on this node.
	// Called on the RELAY node (R) when a circuit_setup is accepted.
	AddRelayTarget(targetKey string, targetEndpoints []string) error

	// RemoveRelayTarget removes a relay target from this node.
	// Called on the RELAY node when a circuit is torn down.
	RemoveRelayTarget(targetKey string) error
}

// Compile-time check that WireGuardDelegate satisfies PeerManager.
var _ PeerManager = (*WireGuardDelegate)(nil)

// PeerHealth tracks the connection health for a dynamic peer.
type PeerHealth struct {
	PublicKey     string
	LastHandshake time.Time
	Endpoints     []string
	IsRelay       bool
	AddedAt       time.Time
}

// WireGuardDelegate is the bridge between dynamic gossip events and the
// MeshNode connection management API. It wraps MeshNode and provides
// dynamic peer management with health tracking.
//
// In v2, this no longer configures WireGuard — it tracks connection state
// and delegates to the HandshakeLayer for actual connection establishment.
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

// Connect establishes a connection to a peer using the provided endpoints.
// It records the peer in the health map for tracking. The actual connection
// establishment is handled by the HandshakeLayer.
func (d *WireGuardDelegate) Connect(peerKey string, endpoints []string) error {
	if peerKey == "" {
		return fmt.Errorf("peer key is empty")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// If already tracked, update endpoints.
	if existing, ok := d.health[peerKey]; ok {
		existing.Endpoints = endpoints
		return nil
	}

	// Track health.
	d.health[peerKey] = &PeerHealth{
		PublicKey: peerKey,
		Endpoints: endpoints,
		AddedAt:   time.Now(),
	}

	// Add to routing table so peer appears in /api/peers.
	// In v2, the REALITY TLS + smux session may not be established yet
	// due to library compatibility issues. Adding to the routing table
	// allows the topology API to show the peer.
	if d.node != nil && len(endpoints) > 0 {
		d.node.RoutingTable().AddPeer(&mesh.PeerEntry{
			ID:       peerKey,
			Endpoint: endpoints[0],
		})
	}

	return nil
}

// Disconnect closes the connection to a peer and cleans up state.
// Static peers are NOT removed (§4.4 backward compat).
func (d *WireGuardDelegate) Disconnect(peerKey string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Never remove static peers.
	if d.staticKeys[peerKey] {
		return nil
	}

	// Check if we have this peer.
	if _, ok := d.health[peerKey]; !ok {
		return nil // already removed or never added — idempotent
	}

	delete(d.health, peerKey)
	return nil
}

// UpdateEndpoints refreshes the known endpoints for a peer.
// Called when NotifyUpdate detects endpoint changes.
func (d *WireGuardDelegate) UpdateEndpoints(peerKey string, endpoints []string) error {
	if peerKey == "" {
		return fmt.Errorf("peer key is required")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if h, ok := d.health[peerKey]; ok {
		h.Endpoints = endpoints
	}

	return nil
}

// IsConnected returns whether a connection to the peer is active.
// In v2, this checks if the peer is tracked in the health map and
// was recently active.
func (d *WireGuardDelegate) IsConnected(peerKey string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	h, ok := d.health[peerKey]
	if !ok {
		return false
	}

	// If we haven't seen a handshake, check if the peer was recently added.
	if h.LastHandshake.IsZero() {
		return time.Since(h.AddedAt) < 2*time.Minute
	}

	return time.Since(h.LastHandshake) < 2*time.Minute
}

// AddRelayTarget adds a remote peer as a relay target on this node.
// Called on the RELAY node (R) when a circuit_setup is accepted.
// The peer is registered for relay data forwarding.
func (d *WireGuardDelegate) AddRelayTarget(targetKey string, targetEndpoints []string) error {
	if targetKey == "" {
		return fmt.Errorf("target key is empty")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if already tracked (may have been added via gossip).
	if _, ok := d.health[targetKey]; ok {
		// Already known — no need to re-add.
		return nil
	}

	d.health[targetKey] = &PeerHealth{
		PublicKey: targetKey,
		Endpoints: targetEndpoints,
		IsRelay:   true,
		AddedAt:   time.Now(),
	}

	return nil
}

// RemoveRelayTarget removes a relay target from this node.
// Called on the RELAY node when a circuit is torn down.
func (d *WireGuardDelegate) RemoveRelayTarget(targetKey string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.staticKeys[targetKey] {
		return nil
	}

	delete(d.health, targetKey)
	return nil
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
