// Package mesh provides the core mesh node abstraction.
//
// In v2, the MeshNode is being rewritten to use a self-developed protocol
// stack instead of WireGuard/gVisor. This file is a transitional stub:
// the v1 WireGuard/gVisor/obfuscation code has been removed, and the
// methods are stubbed with panic("v2: not implemented") until the new
// protocol layers (HandshakeLayer, AELayer, etc.) are implemented.
//
// The RoutingTable and PeerEntry types are kept because they are used
// widely across the web dashboard, p2p, and security alerting packages.
// In v2, the RoutingTable will be repurposed to map peer IDs (not mesh IPs)
// to connections.
package mesh

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh/peer"
)

// MeshNode is the core mesh node. In v2, it will manage:
//   - An Ed25519 identity (Layer 0)
//   - A Reality TLS transport (Layer 1)
//   - A HandshakeLayer for authenticated key exchange (Layer 2)
//   - An AELayer for authenticated encryption (Layer 3)
//   - A smux-based multiplexed stream layer (Layer 4)
//
// Currently a stub — the WireGuard/gVisor/obfuscation v1 code has been
// removed and methods panic until the new layers are implemented.
type MeshNode struct {
	identity *peer.Identity
	routes   *RoutingTable
	cfg      *config.Config
	registry *TransportRegistry
	mu       sync.RWMutex
	closed   bool
}

// New creates a new MeshNode from a config.
// TODO(v2): implement identity loading, transport setup, handshake layer.
func New(cfg *config.Config) (*MeshNode, error) {
	var identity *peer.Identity
	var err error

	if cfg.Node.Identity != "" {
		identity, err = peer.IdentityFromHex(cfg.Node.Identity)
		if err != nil {
			return nil, fmt.Errorf("load identity: %w", err)
		}
	} else {
		identity, err = peer.GenerateIdentity()
		if err != nil {
			return nil, fmt.Errorf("generate identity: %w", err)
		}
		cfg.Node.Identity = identity.PrivateKey
	}

	registry := NewTransportRegistry()

	node := &MeshNode{
		identity: identity,
		routes:   NewRoutingTable(),
		cfg:      cfg,
		registry: registry,
	}

	return node, nil
}

// Start begins mesh operation.
// TODO(v2): implement Reality TLS listener, handshake layer, etc.
func (n *MeshNode) Start() error {
	// v2: transport and handshake layers will be started here.
	return nil
}

// Close shuts down the mesh node and releases all resources.
func (n *MeshNode) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	if n.registry != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = n.registry.ShutdownAll(ctx)
	}
	return nil
}

// Identity returns this node's Ed25519 identity.
func (n *MeshNode) Identity() *peer.Identity {
	return n.identity
}

// RoutingTable returns the routing table for peer lookups.
func (n *MeshNode) RoutingTable() *RoutingTable {
	return n.routes
}

// Registry returns the TransportRegistry used by this node.
func (n *MeshNode) Registry() *TransportRegistry {
	return n.registry
}

// Dial opens a connection to a peer.
// TODO(v2): implement using smux streams over the Reality TLS transport.
func (n *MeshNode) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, fmt.Errorf("v2: Dial not implemented")
}

// AddPeer adds a new peer to the mesh.
// TODO(v2): implement using the new handshake layer.
func (n *MeshNode) AddPeer(cfg config.PeerConfig) error {
	// Register in routing table so the web dashboard can display peers.
	entry := &PeerEntry{
		ID:         cfg.PublicKey,
		Endpoint:   cfg.Endpoint,
		AllowedIPs: cfg.AllowedIPs,
	}
	n.routes.AddPeer(entry)
	return nil
}

// RemovePeer removes a peer from the mesh.
// TODO(v2): implement using the new handshake layer.
func (n *MeshNode) RemovePeer(peerKey string) error {
	n.routes.RemovePeer(peerKey)
	return nil
}

// GenerateIdentity creates a new Ed25519 keypair for the mesh.
func GenerateIdentity() (*peer.Identity, error) {
	return peer.GenerateIdentity()
}
