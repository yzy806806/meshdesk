package mesh

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh/peer"
)

// defaultMTU is the MTU for the userspace TUN device.
const defaultMTU = 1420

// MeshNode is the core mesh VPN node. It manages:
//   - A WireGuard device (wireguard-go) for encryption
//   - A gVisor netstack for userspace TCP/IP (no kernel TUN needed)
//   - A routing table for peer-to-peer mesh routing
//   - An obfuscating bind for per-peer GFW resistance
type MeshNode struct {
	identity   *peer.Identity
	dev        *device.Device
	tnet       *netstack.Net
	routes     *RoutingTable
	bind       *obfuscatingBind
	cfg        *config.Config
	mu         sync.RWMutex
	closed     bool
}

// New creates a new MeshNode from a config. If the config has no identity,
// a new keypair is auto-generated. The node is not started until Start() is called.
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

	// Determine the mesh IP address for this node.
	// We use the first AllowedIPs from any peer's config, or default to
	// an auto-assigned IP in the 10.10.0.0/16 range.
	meshIP := deriveMeshIP(identity.PublicKey)

	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(meshIP)},
		[]netip.Addr{}, // no DNS resolver in netstack for now
		defaultMTU,
	)
	if err != nil {
		return nil, fmt.Errorf("create netstack TUN: %w", err)
	}

	// Create the obfuscating bind wrapping the default UDP bind.
	innerBind := conn.NewDefaultBind()
	obBind := NewObfuscatingBind(innerBind)

	logger := device.NewLogger(device.LogLevelError, "meshdesk: ")
	dev := device.NewDevice(tunDev, obBind, logger)
	if dev == nil {
		return nil, fmt.Errorf("failed to create WireGuard device")
	}

	node := &MeshNode{
		identity: identity,
		dev:      dev,
		tnet:     tnet,
		routes:   NewRoutingTable(),
		bind:     obBind,
		cfg:      cfg,
	}

	// Configure the WireGuard device with the private key and port.
	if err := node.configureDevice(); err != nil {
		dev.Close()
		return nil, err
	}

	// Add all configured peers.
	for _, peerCfg := range cfg.Peers {
		if err := node.AddPeer(peerCfg); err != nil {
			dev.Close()
			return nil, fmt.Errorf("add peer %s: %w", peerCfg.PublicKey[:8], err)
		}
	}

	return node, nil
}

// Start brings up the WireGuard device and begins mesh operation.
func (n *MeshNode) Start() error {
	if err := n.dev.Up(); err != nil {
		return fmt.Errorf("bring up WireGuard device: %w", err)
	}
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
	n.dev.Close()
	return nil
}

// Identity returns this node's WireGuard identity.
func (n *MeshNode) Identity() *peer.Identity {
	return n.identity
}

// RoutingTable returns the routing table for mesh IP lookups.
func (n *MeshNode) RoutingTable() *RoutingTable {
	return n.routes
}

// Net returns the gVisor netstack, which provides DialContext/ListenTCP
// for mesh-internal connections (the tsnet pattern).
func (n *MeshNode) Net() *netstack.Net {
	return n.tnet
}

// Device returns the underlying WireGuard device (for advanced use).
func (n *MeshNode) Device() *device.Device {
	return n.dev
}

// AddPeer adds a new peer to the mesh and configures it in WireGuard.
func (n *MeshNode) AddPeer(cfg config.PeerConfig) error {
	if cfg.PublicKey == "" {
		return fmt.Errorf("peer public key is empty")
	}

	// Set up obfuscation for this peer.
	mode := ParseObfuscationMode(cfg.Obfuscation)
	n.bind.SetObfuscator(cfg.PublicKey, mode)

	// Add to routing table.
	entry := &PeerEntry{
		ID:          cfg.PublicKey,
		Endpoint:    cfg.Endpoint,
		AllowedIPs:  cfg.AllowedIPs,
		Obfuscation: mode,
	}
	n.routes.AddPeer(entry)

	// Build the IPC config for this peer.
	var ipc strings.Builder
	ipc.WriteString(fmt.Sprintf("public_key=%s\n", cfg.PublicKey))
	if cfg.Endpoint != "" {
		ipc.WriteString(fmt.Sprintf("endpoint=%s\n", cfg.Endpoint))
	}
	if cfg.PresharedKey != "" {
		ipc.WriteString(fmt.Sprintf("preshared_key=%s\n", cfg.PresharedKey))
	}
	for _, ip := range cfg.AllowedIPs {
		ipc.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
	}

	if err := n.dev.IpcSet(ipc.String()); err != nil {
		return fmt.Errorf("ipc set peer: %w", err)
	}

	return nil
}

// RemovePeer removes a peer from the mesh and WireGuard.
func (n *MeshNode) RemovePeer(peerKey string) error {
	n.routes.RemovePeer(peerKey)
	// WireGuard UAPI: select peer by public_key, then set remove=true
	if err := n.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", peerKey)); err != nil {
		return fmt.Errorf("ipc remove peer: %w", err)
	}
	return nil
}

// Dial opens a connection to a peer's mesh IP:port through the gVisor netstack.
// This is the primary API for mesh-internal communication (WebSSH, file transfer, etc).
func (n *MeshNode) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return n.tnet.DialContext(ctx, network, address)
}

// configureDevice sets the private key and listen port on the WireGuard device.
func (n *MeshNode) configureDevice() error {
	var ipc strings.Builder
	ipc.WriteString(fmt.Sprintf("private_key=%s\n", n.identity.PrivateKey))
	ipc.WriteString(fmt.Sprintf("listen_port=%d\n", n.cfg.Mesh.Port))
	if err := n.dev.IpcSet(ipc.String()); err != nil {
		return fmt.Errorf("ipc set device config: %w", err)
	}
	return nil
}

// deriveMeshIP deterministically assigns a mesh IP from the node's public key.
// The IP is in the 10.10.0.0/16 range, using the first two bytes of the
// public key hash as the last two octets.
func deriveMeshIP(pubKeyHex string) string {
	// Use bytes 0-1 of the public key for the last two octets.
	// This gives us 65536 possible mesh IPs, which is sufficient for a mesh.
	if len(pubKeyHex) < 4 {
		return "10.10.0.1"
	}
	// Parse the first two bytes of the hex key.
	var b0, b1 byte
	fmt.Sscanf(pubKeyHex[:2], "%02x", &b0)
	fmt.Sscanf(pubKeyHex[2:4], "%02x", &b1)
	// Avoid .0.0 and .255.255 by masking
	b0 = b0%254 + 1
	b1 = b1%254 + 1
	return fmt.Sprintf("10.10.%d.%d", b0, b1)
}

// GenerateIdentity creates a new WireGuard keypair for the mesh.
func GenerateIdentity() (*peer.Identity, error) {
	return peer.GenerateIdentity()
}
