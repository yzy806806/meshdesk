package mesh

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

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
//   - A TransportRegistry for pluggable transport selection (UDP, Reality, WS)
type MeshNode struct {
	identity *peer.Identity
	dev      *device.Device
	tnet     *netstack.Net
	routes   *RoutingTable
	bind     *obfuscatingBind
	cfg      *config.Config
	registry *TransportRegistry
	mu       sync.RWMutex
	closed   bool
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
	meshIP := deriveMeshIP(identity.PublicKey)

	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(meshIP)},
		[]netip.Addr{}, // no DNS resolver in netstack for now
		defaultMTU,
	)
	if err != nil {
		return nil, fmt.Errorf("create netstack TUN: %w", err)
	}

	// Create the TransportRegistry and register built-in factories.
	registry := NewTransportRegistry()
	udpFactory := NewUDPTransportFactory()
	realityFactory := NewRealityTransportFactory()
	registry.Register(udpFactory)
	registry.Register(realityFactory)

	// Create the obfuscating bind wrapping the default UDP bind.
	innerBind := conn.NewDefaultBind()
	obBind := NewObfuscatingBind(innerBind)

	// If any peer uses websocket mode, create a wsBind and install it.
	for _, peerCfg := range cfg.Peers {
		if ParseObfuscationMode(peerCfg.Obfuscation) == ObfuscationWebSocket {
			wsAddr := fmt.Sprintf(":%d", cfg.Mesh.Port)
			useTLS := false
			tlsSni := ""
			tlsFingerprint := ""
			if peerCfg.ObfConfig != nil {
				useTLS = peerCfg.ObfConfig.WSUseTLS
				tlsSni = peerCfg.ObfConfig.TLSSni
				tlsFingerprint = peerCfg.ObfConfig.TLSFingerprint
			}
			var wsCert, wsKey string
			wb := NewWSBind(wsAddr, useTLS, wsCert, wsKey, tlsSni, tlsFingerprint)
			obBind.SetWSBind(wb)
			break // one wsBind handles all websocket-mode peers
		}
	}

	// If any peer uses reality mode, create a RealityTransport for outbound
	// connections and a realityBind to route packets through it.
	// Each reality-mode peer gets its own Transport instance because the
	// Reality config (server public key, short ID, SNI) is per-peer.
	for _, peerCfg := range cfg.Peers {
		if ParseObfuscationMode(peerCfg.Obfuscation) != ObfuscationReality {
			continue
		}
		if peerCfg.Reality == nil {
			return nil, fmt.Errorf("peer %s: obfuscation=reality but no reality config block",
				peerCfg.PublicKey[:8])
		}
		rcfg := peerCfg.Reality
		transportCfg := TransportConfig{
			Name:             "reality",
			DialTimeout:      30 * time.Second,
			ServerName:       rcfg.ServerName,
			RealityPublicKey: rcfg.PublicKey,
			RealityShortID:   rcfg.ShortID,
			TLSFingerprint:   rcfg.TLSFingerprint,
		}
		if transportCfg.TLSFingerprint == "" {
			transportCfg.TLSFingerprint = "chrome"
		}
		transport, err := realityFactory.NewTransport(transportCfg)
		if err != nil {
			return nil, fmt.Errorf("create reality transport for peer %s: %w",
				peerCfg.PublicKey[:8], err)
		}
		rb := newRealityBind(transport)
		obBind.SetRealityBind(rb)
		break // one realityBind handles all reality-mode peers (shared transport)
	}

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
		registry: registry,
	}

	// Configure the WireGuard device with the private key and port.
	if err := node.configureDevice(); err != nil {
		dev.Close()
		return nil, err
	}

	// NOTE: Peers are added in Start() after dev.Up() — WireGuard-go
	// does not reliably trigger handshake timers for peers added before
	// the interface is brought up.

	return node, nil
}

// Start brings up the WireGuard device and begins mesh operation.
func (n *MeshNode) Start() error {
	if err := n.dev.Up(); err != nil {
		return fmt.Errorf("bring up WireGuard device: %w", err)
	}

	// Start the server-side Reality listener if configured.
	// This makes the node accept REALITY TLS connections on the configured
	// port (default 443) when acting as a relay/shared node.
	if n.cfg.Reality.Enabled {
		if err := n.startRealityListener(); err != nil {
			return fmt.Errorf("start reality listener: %w", err)
		}
	}

	// Add all configured peers AFTER the interface is up.
	// WireGuard-go only triggers handshake timers for peers added
	// while the interface is up.
	for _, peerCfg := range n.cfg.Peers {
		if err := n.AddPeer(peerCfg); err != nil {
			return fmt.Errorf("add peer %s: %w", peerCfg.PublicKey[:8], err)
		}
	}

	return nil
}

// startRealityListener creates a server-side RealityTransport and starts
// listening for inbound REALITY TLS connections. This is called when
// cfg.Reality.Enabled is true — the node acts as a relay/shared node.
func (n *MeshNode) startRealityListener() error {
	rcfg := n.cfg.Reality
	if rcfg.PrivateKey == "" {
		return fmt.Errorf("reality.enabled=true but reality.private_key is empty")
	}
	if rcfg.Dest == "" {
		return fmt.Errorf("reality.enabled=true but reality.dest is empty")
	}

	// Determine listen address.
	listenAddr := rcfg.ListenAddr
	if listenAddr == "" {
		port := rcfg.ListenPort
		if port == 0 {
			port = 443
		}
		listenAddr = fmt.Sprintf(":%d", port)
	}

	// Create a server-side RealityTransport.
	transportCfg := TransportConfig{
		Name:               "reality",
		DialTimeout:        30 * time.Second,
		RealityDest:        rcfg.Dest,
		RealityPrivateKey:  rcfg.PrivateKey,
		RealityServerNames: rcfg.ServerNames,
	}
	if len(rcfg.ShortIDs) > 0 {
		// Use the first short ID for the server-side config.
		// The reality.Config built by buildRealityConfig accepts all
		// configured short IDs via RealityShortID (which is also used
		// to populate the ShortIds map).
		transportCfg.RealityShortID = rcfg.ShortIDs[0]
	}

	// Get the reality factory from the registry.
	realityFactory, err := n.registry.Get("reality")
	if err != nil {
		return fmt.Errorf("reality factory not registered: %w", err)
	}
	transport, err := realityFactory.NewTransport(transportCfg)
	if err != nil {
		return fmt.Errorf("create server-side reality transport: %w", err)
	}

	// If a realityBind is already installed (for outbound), replace it
	// with one that also has the server-side listener. Otherwise create
	// a new one just for the listener.
	n.bind.mu.RLock()
	existing := n.bind.reality
	n.bind.mu.RUnlock()

	if existing != nil {
		// The existing realityBind was created for outbound. We start
		// the listener on it so it also accepts inbound connections.
		ctx := context.Background()
		if err := existing.open(ctx, listenAddr); err != nil {
			return fmt.Errorf("open reality listener on existing bind: %w", err)
		}
	} else {
		// No existing realityBind — create one with the server transport
		// and start the listener.
		rb := newRealityBind(transport)
		ctx := context.Background()
		if err := rb.open(ctx, listenAddr); err != nil {
			return fmt.Errorf("open reality listener: %w", err)
		}
		n.bind.SetRealityBind(rb)
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
	// Shut down all transport factories.
	if n.registry != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = n.registry.ShutdownAll(ctx)
	}
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

// Registry returns the TransportRegistry used by this node.
// Exposed for PeerManager integration and testing.
func (n *MeshNode) Registry() *TransportRegistry {
	return n.registry
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
	if cfg.ObfConfig != nil {
		obfCfg := ObfuscationConfig{
			H1:          cfg.ObfConfig.H1,
			H2:          cfg.ObfConfig.H2,
			H3:          cfg.ObfConfig.H3,
			H4:          cfg.ObfConfig.H4,
			S1:          cfg.ObfConfig.S1,
			S2:          cfg.ObfConfig.S2,
			S3:          cfg.ObfConfig.S3,
			S4:          cfg.ObfConfig.S4,
			Jc:          cfg.ObfConfig.Jc,
			Jmin:        cfg.ObfConfig.Jmin,
			Jmax:        cfg.ObfConfig.Jmax,
			PSK:         cfg.ObfConfig.PSK,
			JitterMaxMs: cfg.ObfConfig.JitterMaxMs,
		}
		// Apply defaults for zero-valued fields.
		if !obfCfg.hasHeaderRandomization() {
			def := DefaultObfuscationConfig()
			obfCfg.H1, obfCfg.H2, obfCfg.H3, obfCfg.H4 = def.H1, def.H2, def.H3, def.H4
		}
		if obfCfg.S1 == 0 && obfCfg.S2 == 0 && obfCfg.S3 == 0 && obfCfg.S4 == 0 {
			def := DefaultObfuscationConfig()
			obfCfg.S1, obfCfg.S2, obfCfg.S3, obfCfg.S4 = def.S1, def.S2, def.S3, def.S4
		}
		if obfCfg.JitterMaxMs == 0 {
			obfCfg.JitterMaxMs = DefaultObfuscationConfig().JitterMaxMs
		}
		n.bind.SetObfuscatorWithConfig(cfg.PublicKey, mode, obfCfg, true)
	} else {
		n.bind.SetObfuscator(cfg.PublicKey, mode)
	}

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
	// Persistent keepalive: trigger handshake even without outbound traffic.
	// wireguard-go does NOT auto-initiate handshake on its own; it needs
	// either outbound traffic or a persistent_keepalive to start.
	ipc.WriteString("persistent_keepalive_interval=10\n")

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
