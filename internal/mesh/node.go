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
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/crypto"
	"github.com/yzy806806/meshdesk/internal/handshake"
	"github.com/yzy806806/meshdesk/internal/identity"
	"github.com/yzy806806/meshdesk/internal/session"
	"github.com/yzy806806/meshdesk/internal/smux"
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
	identity *identity.Identity
	routes   *RoutingTable
	cfg      *config.Config
	registry *TransportRegistry

	// v2 session management
	listener   net.Listener
	hs         handshake.HandshakeLayer
	sessions   map[string]*smux.Session // peer identity hex → smux session
	sessionsMu sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc

	mu     sync.RWMutex
	closed bool
}

// New creates a new MeshNode from a config.
func New(cfg *config.Config) (*MeshNode, error) {
	nodeIdentity, err := loadOrCreateIdentity(cfg)
	if err != nil {
		return nil, err
	}

	registry := NewTransportRegistry()
	ctx, cancel := context.WithCancel(context.Background())

	node := &MeshNode{
		identity: nodeIdentity,
		routes:   NewRoutingTable(),
		cfg:      cfg,
		registry: registry,
		sessions: make(map[string]*smux.Session),
		ctx:      ctx,
		cancel:   cancel,
	}

	return node, nil
}

// Start begins mesh operation.
// It creates a Reality TLS listener, starts an accept loop in a background
// goroutine, and for each accepted connection performs X25519 ECDH key
// exchange, wraps the connection in AES-256-GCM, and creates an smux session.
func (n *MeshNode) Start() error {
	if !n.cfg.Reality.Enabled {
		return fmt.Errorf("mesh: Reality TLS not enabled in config (set reality.enabled=true)")
	}

	// Build the listen address from config.
	addr := buildRealityListenAddr(n.cfg)

	// Create the Reality TLS listener.
	hsCfg := handshake.HandshakeConfig{
		ListenAddr:         addr,
		RealityDest:        n.cfg.Reality.Dest,
		RealityPrivateKey:  n.cfg.Reality.PrivateKey,
		RealityShortID:     firstShortID(n.cfg.Reality.ShortIDs),
		RealityServerNames: n.cfg.Reality.ServerNames,
		DialTimeout:        30 * time.Second,
		TLSFingerprint:     "chrome",
	}

	hs := handshake.NewRealityHandshake(hsCfg)
	ln, err := hs.Listen(n.ctx, addr)
	if err != nil {
		return fmt.Errorf("mesh: start reality listener on %s: %w", addr, err)
	}

	n.mu.Lock()
	if n.listener != nil {
		n.listener.Close()
	}
	n.listener = ln
	n.hs = hs
	n.mu.Unlock()

	log.Printf("[mesh] Reality TLS listener started on %s (dest=%s)", addr, n.cfg.Reality.Dest)

	// Start accept loop in background.
	go n.acceptLoop(ln)

	return nil
}

// acceptLoop accepts inbound Reality TLS connections, performs the
// full protocol handshake (key exchange → SecureConn → smux), and
// stores the resulting session.
func (n *MeshNode) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-n.ctx.Done():
				return
			default:
			}
			// Check if listener was closed.
			n.mu.RLock()
			closed := n.closed
			n.mu.RUnlock()
			if closed {
				return
			}
			log.Printf("[mesh] accept error: %v", err)
			// Brief sleep before retry on transient errors.
			time.Sleep(100 * time.Millisecond)
			continue
		}

		remoteAddr := conn.RemoteAddr().String()
		log.Printf("[mesh] accepted connection from %s", remoteAddr)

		// Handle each connection in its own goroutine.
		go n.handleConnection(conn, remoteAddr)
	}
}

// handleConnection performs the Layer 2–3 handshake on an accepted
// Reality TLS connection:
//  1. Server-side X25519 ECDH key exchange (session.ServerKeyExchange)
//  2. Wrap in AES-256-GCM SecureConn (crypto.NewSecureConn)
//  3. Create smux multiplexer session (smux.Server)
//  4. Store the session keyed by peer identity
func (n *MeshNode) handleConnection(conn net.Conn, remoteAddr string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[mesh] panic handling connection from %s: %v", remoteAddr, r)
		}
	}()

	// Set a deadline for the full key exchange.
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Step 1: Server-side X25519 ECDH key exchange.
	keys, peerIdentityHex, err := session.ServerKeyExchange(conn, n.identity)
	if err != nil {
		log.Printf("[mesh] key exchange failed with %s: %v", remoteAddr, err)
		conn.Close()
		return
	}

	// Clear the deadline — the secure channel manages its own timeouts.
	conn.SetDeadline(time.Time{})

	log.Printf("[mesh] key exchange complete with %s (peer=%s)", remoteAddr, peerIdentityHex[:16]+"...")

	// Step 2: Wrap in AES-256-GCM SecureConn.
	secureConn, err := crypto.NewSecureConn(conn, keys.SendKey[:], keys.RecvKey[:])
	if err != nil {
		log.Printf("[mesh] failed to create SecureConn with %s: %v", remoteAddr, err)
		conn.Close()
		return
	}

	// Step 3: Create smux server session.
	smuxSession, err := smux.Server(secureConn, smux.DefaultConfig())
	if err != nil {
		log.Printf("[mesh] smux handshake failed with %s: %v", remoteAddr, err)
		secureConn.Close()
		return
	}

	// Step 4: Store the session.
	n.sessionsMu.Lock()
	oldSession, exists := n.sessions[peerIdentityHex]
	n.sessions[peerIdentityHex] = smuxSession
	n.sessionsMu.Unlock()

	// If the same peer reconnected, close the old session.
	if exists {
		log.Printf("[mesh] peer %s reconnected — closing old session", peerIdentityHex[:16]+"...")
		oldSession.Close()
	}

	log.Printf("[mesh] session established with %s (peer=%s, addr=%s)",
		remoteAddr, peerIdentityHex[:16]+"...", remoteAddr)

	// Add the peer to the routing table.
	n.routes.AddPeer(&PeerEntry{
		ID:       peerIdentityHex,
		Endpoint: remoteAddr,
	})

	// TODO(v2): hand the smux session to the PeerManager for stream handling.
	// For now, the session is stored and available via GetSession().
}

// Close shuts down the mesh node and releases all resources.
func (n *MeshNode) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true

	// Cancel the context first — this signals the accept loop to stop.
	if n.cancel != nil {
		n.cancel()
	}

	// Close the Reality TLS listener.
	if n.listener != nil {
		n.listener.Close()
	}
	if n.hs != nil {
		n.hs.Close()
	}

	n.mu.Unlock()

	// Close all smux sessions.
	n.sessionsMu.Lock()
	for id, sess := range n.sessions {
		log.Printf("[mesh] closing session for peer %s", id[:16]+"...")
		sess.Close()
	}
	n.sessions = make(map[string]*smux.Session)
	n.sessionsMu.Unlock()

	// Shut down transports.
	if n.registry != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = n.registry.ShutdownAll(ctx)
	}
	return nil
}

// GetSession returns the smux session for a peer by identity hex string.
// Returns nil if no session exists for the peer.
func (n *MeshNode) GetSession(peerIdentityHex string) *smux.Session {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()
	return n.sessions[peerIdentityHex]
}

// ListSessions returns a copy of all active peer sessions.
// Key: peer identity hex string, Value: smux session.
func (n *MeshNode) ListSessions() map[string]*smux.Session {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()
	out := make(map[string]*smux.Session, len(n.sessions))
	for k, v := range n.sessions {
		out[k] = v
	}
	return out
}

// Listener returns the active Reality TLS listener, or nil if not started.
func (n *MeshNode) Listener() net.Listener {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.listener
}

// Identity returns this node's Ed25519 identity.
func (n *MeshNode) Identity() *identity.Identity {
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

// Dial opens a cryptographically secure stream to a peer.
//
// It performs the full client-side protocol handshake:
//  1. Looks up the peer's Reality TLS config by address.
//  2. Dials the peer via Reality TLS (Layer 1).
//  3. Performs X25519 ECDH key exchange (Layer 2a).
//  4. Wraps the connection in AES-256-GCM SecureConn (Layer 2b).
//  5. Creates an smux client session (Layer 3).
//  6. Opens a stream and returns it as a net.Conn.
//
// The returned net.Conn is an authenticated, encrypted, multiplexed stream.
// Multiple streams can share one underlying session via subsequent calls to
// Dial with the same address.
//
// network is the transport type ("tcp", "tcp4", "tcp6" — all mapped to TCP).
// address is "host:port" and must match a configured peer's Endpoint field.
func (n *MeshNode) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	// 1. Find the peer's Reality config by address.
	peerCfg, ok := n.findPeerConfigByAddress(address)
	if !ok {
		return nil, fmt.Errorf("mesh: no peer configured at address %s", address)
	}
	if peerCfg.Reality == nil {
		return nil, fmt.Errorf("mesh: peer at %s has no Reality TLS configuration (required for v2)", address)
	}

	// 2. Build a client-side Reality handshake config from the peer config.
	hsCfg := handshake.HandshakeConfig{
		DialTimeout:     30 * time.Second,
		TLSFingerprint:  "chrome",
		RealityPublicKey: peerCfg.Reality.PublicKey,
		RealityShortID:   peerCfg.Reality.ShortID,
		ServerName:       peerCfg.Reality.ServerName,
	}
	if peerCfg.Reality.TLSFingerprint != "" {
		hsCfg.TLSFingerprint = peerCfg.Reality.TLSFingerprint
	}

	// 3. Dial the peer's Reality TLS address (Layer 1).
	hs := handshake.NewRealityHandshake(hsCfg)
	conn, err := hs.Connect(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("mesh: dial %s: %w", address, err)
	}

	// 4. Set a deadline for the key exchange (Layer 2a).
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 5. Perform X25519 ECDH key exchange (client/initiator side).
	keys, peerIdentityHex, err := session.ClientKeyExchange(conn, n.identity)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mesh: key exchange with %s: %w", address, err)
	}

	// 6. Clear the deadline — the secure channel manages its own timeouts.
	conn.SetDeadline(time.Time{})

	log.Printf("[mesh] key exchange complete with %s (peer=%s)", address, peerIdentityHex[:16]+"...")

	// 7. Wrap in AES-256-GCM SecureConn (Layer 2b).
	secureConn, err := crypto.NewSecureConn(conn, keys.SendKey[:], keys.RecvKey[:])
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mesh: create SecureConn with %s: %w", address, err)
	}

	// 8. Create smux client session (Layer 3).
	smuxSession, err := smux.Client(secureConn, smux.DefaultConfig())
	if err != nil {
		secureConn.Close()
		return nil, fmt.Errorf("mesh: smux handshake with %s: %w", address, err)
	}

	// 9. Store the session keyed by peer identity.
	//    If the same peer reconnected via Dial, close the old session.
	n.sessionsMu.Lock()
	oldSession, exists := n.sessions[peerIdentityHex]
	n.sessions[peerIdentityHex] = smuxSession
	n.sessionsMu.Unlock()

	if exists {
		log.Printf("[mesh] peer %s reconnected via Dial — closing old session", peerIdentityHex[:16]+"...")
		oldSession.Close()
	}

	log.Printf("[mesh] session established with %s (peer=%s)", address, peerIdentityHex[:16]+"...")

	// 10. Add/update the peer in the routing table.
	n.routes.AddPeer(&PeerEntry{
		ID:       peerIdentityHex,
		Endpoint: address,
	})

	// 11. Open a stream on the session and return it.
	stream, err := smuxSession.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("mesh: open stream to %s: %w", address, err)
	}

	return stream, nil
}

// findPeerConfigByAddress searches the node's config Peers list for a
// peer whose Endpoint matches the given address (host:port).
func (n *MeshNode) findPeerConfigByAddress(address string) (*config.PeerConfig, bool) {
	for i := range n.cfg.Peers {
		if n.cfg.Peers[i].Endpoint == address {
			return &n.cfg.Peers[i], true
		}
	}
	return nil, false
}

// AddPeer adds a new peer to the mesh and, when Reality TLS parameters
// are configured, establishes a persistent secure mesh connection.
//
// When the peer config includes Reality TLS parameters and a non-empty
// Endpoint (the v2 path), AddPeer initiates the full protocol handshake
// (Reality TLS → X25519 ECDH key exchange → AES-256-GCM SecureConn →
// smux session), stores the resulting session in the node's session map,
// and registers the peer in the routing table.
//
// When Reality is not configured (the v1 backward-compatible path), the
// peer is registered in the routing table only. This preserves compatibility
// with v1 peers discovered via gossip that lack Reality TLS configuration.
func (n *MeshNode) AddPeer(cfg config.PeerConfig) error {
	// v2 path: Reality TLS enabled — establish a persistent secure connection.
	if cfg.Reality != nil && cfg.Endpoint != "" {
		return n.addPeerWithConnection(cfg)
	}

	// v1 backward-compatible path: routing table only.
	entry := &PeerEntry{
		ID:         cfg.PublicKey,
		Endpoint:   cfg.Endpoint,
		AllowedIPs: cfg.AllowedIPs,
	}
	n.routes.AddPeer(entry)
	return nil
}

// addPeerWithConnection establishes a persistent secure mesh connection
// to a peer with Reality TLS configuration by calling Dial.
//
// Dial handles the full v2 protocol handshake and already stores the
// resulting smux session (keyed by the peer's verified identity hex)
// and adds the peer to the routing table. AddPeer only ensures the peer
// config is discoverable by Dial's address lookup, then closes the
// returned stream — the session persists independently.
func (n *MeshNode) addPeerWithConnection(cfg config.PeerConfig) error {
	// Ensure the peer config is available for Dial's address lookup.
	if !n.hasPeerConfigByAddress(cfg.Endpoint) {
		n.cfg.Peers = append(n.cfg.Peers, cfg)
		log.Printf("[mesh] AddPeer: registered peer config for %s", cfg.Endpoint)
	}

	// Dial performs the full v2 handshake: Reality TLS → key exchange →
	// SecureConn → smux session creation → session storage → routing table.
	ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
	defer cancel()

	stream, err := n.Dial(ctx, "tcp", cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("mesh: add peer %s (%s): %w",
			cfg.PublicKey[:min(len(cfg.PublicKey), 16)]+"...", cfg.Endpoint, err)
	}

	// Close the stream — AddPeer establishes the persistent session;
	// the caller does not need a data stream right now. The smux session
	// lives on in n.sessions and streams can be opened later via Dial.
	stream.Close()

	log.Printf("[mesh] AddPeer: persistent session established with %s (%s)",
		cfg.PublicKey[:min(len(cfg.PublicKey), 16)]+"...", cfg.Endpoint)

	return nil
}

// hasPeerConfigByAddress checks whether a peer config with the given
// endpoint address exists in the node's config peer list.
func (n *MeshNode) hasPeerConfigByAddress(address string) bool {
	for i := range n.cfg.Peers {
		if n.cfg.Peers[i].Endpoint == address {
			return true
		}
	}
	return false
}

// RemovePeer removes a peer from the mesh.
// TODO(v2): implement using the new handshake layer.
func (n *MeshNode) RemovePeer(peerKey string) error {
	n.routes.RemovePeer(peerKey)
	return nil
}

// GenerateIdentity creates a new Ed25519 keypair for the mesh.
func GenerateIdentity() (*identity.Identity, error) {
	return identity.GenerateIdentity()
}

// loadOrCreateIdentity loads an Ed25519 identity from the config, or generates
// a new one if not configured. Updates cfg.Node.Identity with the generated key.
func loadOrCreateIdentity(cfg *config.Config) (*identity.Identity, error) {
	if cfg.Node.Identity != "" {
		id, err := identity.IdentityFromHex(cfg.Node.Identity)
		if err != nil {
			return nil, fmt.Errorf("load identity: %w", err)
		}
		return id, nil
	}
	id, err := identity.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	cfg.Node.Identity = id.PrivateKey
	return id, nil
}

// buildRealityListenAddr constructs the Reality TLS listen address from config.
// Uses cfg.Reality.ListenPort if set, otherwise parses cfg.Reality.ListenAddr.
func buildRealityListenAddr(cfg *config.Config) string {
	port := cfg.Reality.ListenPort
	if port == 0 {
		port = 443
	}
	host := cfg.Reality.ListenAddr
	if host == "" {
		host = "0.0.0.0"
	}
	// If host already contains a port, strip it and use our port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// firstShortID returns the first short ID from the list, or empty string.
func firstShortID(ids []string) string {
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
}
