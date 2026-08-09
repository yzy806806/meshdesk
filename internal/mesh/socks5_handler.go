package mesh

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

// SOCKS5VirtualPort is the virtual port for the SOCKS5 proxy handler.
// 0x5350 = 'S' (0x53) 'P' (0x50) — mnemonic for "SOCKS5 Proxy".
const SOCKS5VirtualPort = 0x5350 // 21328

// socks5Closer is the common interface for SOCKS5 handlers (both direct-dial
// and forward modes) used by MeshNode for lifecycle management.
type socks5Closer interface {
	Close() error
	ActiveConnections() int64
}

// SOCKS5 protocol constants (RFC 1928).
const (
	socks5Version  = 0x05
	socks5NoAuth   = 0x00
	socks5Connect  = 0x01
	socks5AtypIPv4 = 0x01
	socks5AtypFQDN = 0x03
	socks5AtypIPv6 = 0x04

	socks5RepSuccess          = 0x00
	socks5RepGeneralFailure   = 0x01
	socks5RepNotAllowed       = 0x02
	socks5RepHostUnreachable  = 0x04
	socks5RepConnRefused      = 0x05
	socks5RepTTLExpired       = 0x06
	socks5RepCmdNotSupported  = 0x07
	socks5RepAtypNotSupported = 0x08
)

// SOCKS5Config holds runtime configuration for the SOCKS5 handler.
type SOCKS5Config struct {
	// DialTimeout is the timeout for dialing target addresses.
	// Default: 30 seconds.
	DialTimeout time.Duration

	// IdleTimeout is the idle timeout for established connections.
	// Connections with no data flow for this duration are closed.
	// Default: 5 minutes.
	IdleTimeout time.Duration

	// AllowedPorts restricts which destination ports the SOCKS5 handler
	// will connect to. If empty, all ports are allowed.
	AllowedPorts map[int]bool

	// AllowAllPorts overrides AllowedPorts to permit any port.
	AllowAllPorts bool

	// DestinationFilter is a list of CIDR prefixes that the handler is
	// allowed to connect to. If empty, all destinations are allowed.
	DestinationFilter []string

	// MaxConnections limits concurrent SOCKS5 connections.
	// Default: 256.
	MaxConnections int

	// AllowedPeers restricts which mesh peers can use this SOCKS5
	// proxy. If empty, all authenticated mesh peers are permitted.
	// Each entry is a mesh identity hex string (64 hex chars for
	// Ed25519 public key).
	// Phone clients that connect via Reality TLS (non-mesh peers)
	// are NOT restricted by this list — their authorization is
	// determined by SOCKS5 authentication at the protocol level.
	// To allow only mesh peers, set RequireMeshPeer = true.
	AllowedPeers []string

	// RequireMeshPeer, when true, requires that every connection to
	// this SOCKS5 handler comes from a mesh peer (i.e. a peer whose
	// identity was authenticated via the join protocol). Phone clients
	// connecting through Reality TLS without a mesh identity will be
	// rejected. Default: false (permissive, for backward compatibility).
	RequireMeshPeer bool

	// CheckMeshPeer, when non-nil, is called to verify that a peerID
	// represents a valid mesh peer. When RequireMeshPeer is true and
	// this function returns false, the connection is rejected.
	// If nil and RequireMeshPeer is true, the handler falls back to
	// checking that peerID is non-empty (legacy behavior — insufficient
	// for true mesh membership verification).
	// Wire this to RoutingTable.GetPeer in production; leave nil in tests.
	CheckMeshPeer func(peerID string) bool
}

// DefaultSOCKS5Config returns a SOCKS5Config with sensible defaults.
func DefaultSOCKS5Config() SOCKS5Config {
	return SOCKS5Config{
		DialTimeout:    30 * time.Second,
		IdleTimeout:    5 * time.Minute,
		MaxConnections: 256,
	}
}

// SOCKS5Handler processes inbound SOCKS5 proxy requests on virtual port
// 0x5350. It runs on exit/shared nodes and acts as a SOCKS5 server:
// when a peer opens a stream on port 0x5350, the handler performs the
// SOCKS5 handshake (no-auth, CONNECT), dials the requested target
// address, and bridges data bidirectionally between the mesh stream and
// the target TCP connection.
//
// The mesh stream is already encrypted by the SecureConn layer and
// multiplexed by smux, so the SOCKS5 protocol runs on top of an
// authenticated, encrypted channel — no additional SOCKS5 auth is needed.
//
// Lifecycle:
//  1. RegisterSOCKS5Handler creates a SOCKS5Handler and registers it on
//     the virtual port mux for port 0x5350.
//  2. When a peer opens a stream on port 0x5350, the mux delivers it to
//     HandleStream.
//  3. HandleStream performs the SOCKS5 greeting + request handshake,
//     dials the target, and starts a bidirectional io.Copy bridge.
//  4. When either direction completes, both connections are closed.
//  5. Close() tears down all active connections.
type SOCKS5Handler struct {
	config        SOCKS5Config
	dialer        *net.Dialer
	activeConns   int64
	closed        atomic.Bool
	allowedNets   []*net.IPNet      // parsed DestinationFilter
	allowedPeers  map[string]bool   // set of peerIDs permitted to connect
	checkMeshPeer func(string) bool // routing table check (nil = fallback to non-empty check)
	requireMesh   bool              // true if non-mesh connections are rejected
}

// NewSOCKS5Handler creates a SOCKS5Handler with the given configuration.
func NewSOCKS5Handler(cfg SOCKS5Config) *SOCKS5Handler {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 30 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 256
	}

	h := &SOCKS5Handler{
		config: cfg,
		dialer: &net.Dialer{Timeout: cfg.DialTimeout},
	}

	// Build allowed peers set.
	if len(cfg.AllowedPeers) > 0 {
		h.allowedPeers = make(map[string]bool, len(cfg.AllowedPeers))
		for _, peerID := range cfg.AllowedPeers {
			h.allowedPeers[peerID] = true
		}
	}
	h.checkMeshPeer = cfg.CheckMeshPeer
	h.requireMesh = cfg.RequireMeshPeer

	// Parse destination filter CIDRs.
	for _, cidr := range cfg.DestinationFilter {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[socks5] invalid destination filter CIDR %q: %v (ignored)", cidr, err)
			continue
		}
		h.allowedNets = append(h.allowedNets, ipNet)
	}

	return h
}

// HandleStream is called by the virtual port mux when a stream arrives
// on port 0x5350. It performs the full SOCKS5 handshake and data relay.
func (h *SOCKS5Handler) HandleStream(conn net.Conn) {
	if h.closed.Load() {
		conn.Close()
		return
	}

	// Enforce max connections.
	if atomic.LoadInt64(&h.activeConns) >= int64(h.config.MaxConnections) {
		log.Printf("[socks5] connection limit reached (%d), rejecting", h.config.MaxConnections)
		conn.Close()
		return
	}

	// Peer authorization — thread peer identity was added by the virtual
	// port dispatch layer. A conn without a peerID is from a test or a
	// legacy path; we default to permitted unless RequireMeshPeer is set.
	peerID := ""
	if cwp, ok := conn.(*connWithPeer); ok {
		peerID = cwp.peerID
	}

	// If RequireMeshPeer is set, verify mesh membership through the
	// configured CheckMeshPeer callback. When wired to the routing table,
	// this rejects phone clients with locally-generated Ed25519 keys
	// that have not completed the mesh join protocol.
	if h.requireMesh {
		if h.checkMeshPeer != nil {
			if !h.checkMeshPeer(peerID) {
				log.Printf("[socks5] rejecting non-mesh peer %s (RequireMeshPeer=true)", peerID[:min(len(peerID), 16)])
				conn.Close()
				return
			}
		} else if peerID == "" {
			// Legacy fallback: without a CheckMeshPeer callback, at
			// minimum require a non-empty peerID. Note: this does NOT
			// verify mesh membership — it only checks that the peer
			// presented some Ed25519 identity during key exchange.
			log.Printf("[socks5] rejecting non-mesh connection (RequireMeshPeer=true, no peerID)")
			conn.Close()
			return
		}
	}

	// If AllowedPeers is configured, check the peer is in the list.
	if len(h.allowedPeers) > 0 {
		if peerID == "" || !h.allowedPeers[peerID] {
			log.Printf("[socks5] rejecting peer %s (not in AllowedPeers)", peerID)
			conn.Close()
			return
		}
	}

	atomic.AddInt64(&h.activeConns, 1)
	defer atomic.AddInt64(&h.activeConns, -1)

	// Set a deadline for the handshake phase.
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{}) // reset deadline for data phase

	// Phase 1: SOCKS5 greeting.
	targetAddr, err := h.handleGreeting(conn)
	if err != nil {
		log.Printf("[socks5] handshake failed: %v", err)
		conn.Close()
		return
	}

	// Validate the target against allowed ports / destination filter.
	if !h.isTargetAllowed(targetAddr) {
		h.sendReply(conn, socks5RepNotAllowed, nil, 0)
		conn.Close()
		return
	}

	// Phase 2: Dial the target.
	log.Printf("[socks5] dialing target %s", targetAddr)
	targetConn, err := h.dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[socks5] dial %s failed: %v", targetAddr, err)
		rep := byte(socks5RepGeneralFailure)
		if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				rep = socks5RepTTLExpired
			}
		}
		h.sendReply(conn, rep, nil, 0)
		conn.Close()
		return
	}

	// Phase 3: Send success reply.
	// BND.ADDR and BND.PORT can be zeros — the client typically ignores them.
	h.sendReply(conn, socks5RepSuccess, nil, 0)

	// Phase 4: Bidirectional data relay.
	h.relay(conn, targetConn)
}

// handleGreeting performs the SOCKS5 greeting and request parsing.
// It returns the target address as "host:port".
func (h *SOCKS5Handler) handleGreeting(conn net.Conn) (string, error) {
	// Read greeting: VER, NMETHODS, METHODS...
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("read greeting: %w", err)
	}
	if buf[0] != socks5Version {
		return "", fmt.Errorf("unsupported SOCKS version %d", buf[0])
	}
	nMethods := int(buf[1])
	if nMethods == 0 {
		return "", fmt.Errorf("no auth methods offered")
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("read methods: %w", err)
	}

	// Reply: no authentication required.
	if _, err := conn.Write([]byte{socks5Version, socks5NoAuth}); err != nil {
		return "", fmt.Errorf("write auth reply: %w", err)
	}

	// Read request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}
	if header[0] != socks5Version {
		return "", fmt.Errorf("unsupported SOCKS version in request: %d", header[0])
	}
	if header[1] != socks5Connect {
		h.sendReply(conn, socks5RepCmdNotSupported, nil, 0)
		return "", fmt.Errorf("unsupported CMD %d (only CONNECT=1)", header[1])
	}

	// Parse destination address based on ATYP.
	atyp := header[3]
	var host string
	switch atyp {
	case socks5AtypIPv4:
		addrBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return "", fmt.Errorf("read IPv4 addr: %w", err)
		}
		host = net.IP(addrBuf).String()
	case socks5AtypFQDN:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read FQDN length: %w", err)
		}
		fqdnLen := int(lenBuf[0])
		if fqdnLen == 0 {
			return "", fmt.Errorf("empty FQDN")
		}
		fqdnBuf := make([]byte, fqdnLen)
		if _, err := io.ReadFull(conn, fqdnBuf); err != nil {
			return "", fmt.Errorf("read FQDN: %w", err)
		}
		host = string(fqdnBuf)
	case socks5AtypIPv6:
		addrBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return "", fmt.Errorf("read IPv6 addr: %w", err)
		}
		host = net.IP(addrBuf).String()
	default:
		h.sendReply(conn, socks5RepAtypNotSupported, nil, 0)
		return "", fmt.Errorf("unsupported ATYP %d", atyp)
	}

	// Read port (2 bytes, big-endian).
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// isTargetAllowed checks whether the target address is permitted by
// the AllowedPorts and DestinationFilter configuration.
func (h *SOCKS5Handler) isTargetAllowed(targetAddr string) bool {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return false
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}

	// Check port restrictions.
	if !h.config.AllowAllPorts && len(h.config.AllowedPorts) > 0 {
		if !h.config.AllowedPorts[port] {
			return false
		}
	}

	// Check destination filter (CIDR).
	if len(h.allowedNets) > 0 {
		ip := net.ParseIP(host)
		if ip == nil {
			// Could be a hostname — resolve and check.
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				return false
			}
			ip = ips[0]
		}
		allowed := false
		for _, ipNet := range h.allowedNets {
			if ipNet.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	return true
}

// sendReply sends a SOCKS5 reply on the connection.
// bndAddr may be nil for a zero-length bind address.
func (h *SOCKS5Handler) sendReply(conn net.Conn, rep byte, bndAddr net.IP, bndPort uint16) {
	// VER=5, REP, RSV=0, ATYP=1 (IPv4), BND.ADDR (4 bytes), BND.PORT (2 bytes)
	reply := []byte{socks5Version, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
	if bndAddr != nil {
		if v4 := bndAddr.To4(); v4 != nil {
			copy(reply[4:8], v4)
		}
	}
	binary.BigEndian.PutUint16(reply[8:10], bndPort)
	conn.Write(reply)
}

// relay bridges two connections bidirectionally with an idle timeout.
// When either direction completes or the idle timeout fires, both
// connections are closed.
func (h *SOCKS5Handler) relay(meshConn, targetConn net.Conn) {
	// Apply idle timeout if configured.
	if h.config.IdleTimeout > 0 {
		meshConn.SetDeadline(time.Now().Add(h.config.IdleTimeout))
		targetConn.SetDeadline(time.Now().Add(h.config.IdleTimeout))
	}

	done := make(chan struct{}, 2)

	// mesh → target
	go func() {
		_, err := io.Copy(targetConn, meshConn)
		if err != nil {
			log.Printf("[socks5] copy mesh→target: %v", err)
		}
		// Half-close target's write side.
		if cw, ok := targetConn.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	// target → mesh
	go func() {
		_, err := io.Copy(meshConn, targetConn)
		if err != nil {
			log.Printf("[socks5] copy target→mesh: %v", err)
		}
		// Half-close mesh's write side.
		if cw, ok := meshConn.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	// Wait for either direction to finish, then close both.
	<-done
	meshConn.Close()
	targetConn.Close()

	// Drain the second goroutine.
	<-done
}

// Close tears down the handler. New connections are rejected immediately.
// Existing connections are not forcibly closed — they will finish or
// time out naturally.
func (h *SOCKS5Handler) Close() error {
	h.closed.Store(true)
	return nil
}

// ActiveConnections returns the number of currently active SOCKS5 connections.
func (h *SOCKS5Handler) ActiveConnections() int64 {
	return atomic.LoadInt64(&h.activeConns)
}

// closeWriter is defined in conn_prefix.go and re-used here.

// RegisterSOCKS5ExitHandler registers a SOCKS5Handler on virtual port
// 0x4558 (ExitVirtualPort), enabling this node to act as a SOCKS5 exit
// for forwarded requests from shared nodes. This is the exit-side
// counterpart to RegisterSOCKS5ForwardHandler: shared nodes forward
// SOCKS5 traffic via DialVirtualPort(ctx, exitPeerID, 0x4558), and this
// handler receives it, performs the actual target dial, and bridges data.
//
// The returned handler should be Closed when no longer needed. It is also
// closed automatically when the node's Close() is called.
func (n *MeshNode) RegisterSOCKS5ExitHandler(cfg SOCKS5Config) (*SOCKS5Handler, error) {
	// Wire CheckMeshPeer from routing table if needed. Also accept
	// relay-reached peers via gossip membership (see RegisterSOCKS5Handler).
	if cfg.RequireMeshPeer && cfg.CheckMeshPeer == nil {
		cfg.CheckMeshPeer = func(peerID string) bool {
			if _, ok := n.routes.GetPeer(peerID); ok {
				return true
			}
			if n.relayMetaProvider != nil {
				for _, rp := range n.relayMetaProvider() {
					if rp.PeerKey == peerID {
						return true
					}
				}
			}
			return false
		}
	}
	handler := NewSOCKS5Handler(cfg)

	// Register a virtual port listener for 0x4558.
	ln, err := n.ListenVirtualPort(int(ExitVirtualPort))
	if err != nil {
		return nil, fmt.Errorf("socks5-exit: register port 0x%x: %w", ExitVirtualPort, err)
	}

	// Start the accept loop in a background goroutine.
	go n.serveSOCKS5(handler, ln)

	// Store the handler so Close() can clean it up.
	n.mu.Lock()
	n.socks5ExitHandler = handler
	n.mu.Unlock()

	return handler, nil
}

// RegisterSOCKS5Handler registers a SOCKS5Handler on virtual port 0x5350,
// enabling this node to act as a SOCKS5 proxy exit for mesh peers.
//
// When a peer dials virtual port 0x5350, the handler performs a SOCKS5
// CONNECT handshake and bridges the stream to the requested target
// address (e.g. a website on the public internet). This replaces the
// removed xray-core dependency with a lightweight, mesh-native SOCKS5
// implementation.
//
// The returned handler should be Closed when the node no longer wants
// to accept SOCKS5 connections. It is also closed automatically when
// the node's Close() is called if it was registered via this method.
func (n *MeshNode) RegisterSOCKS5Handler(cfg SOCKS5Config) (*SOCKS5Handler, error) {
	// If RequireMeshPeer is set and no custom CheckMeshPeer is provided,
	// wire the routing table as the mesh membership verifier. This ensures
	// that only peers who completed the join protocol (present in the
	// routing table) can use the SOCKS5 proxy. Phone clients with
	// locally-generated Ed25519 keys are rejected because their key is
	// not in the routing table — only join-protocol-authenticated peers
	// are present there.
	//
	// Note: a peer reached only via relay (no direct smux session) may be
	// absent from the routing table even though it is a legitimate mesh
	// member. The membership check therefore ALSO accepts peers known to
	// gossip (memberlist) — the relay path already authenticated the
	// InitiatorKey through the smux session chain, so accepting
	// memberlist-known peers is safe.
	if cfg.RequireMeshPeer && cfg.CheckMeshPeer == nil {
		cfg.CheckMeshPeer = func(peerID string) bool {
			if _, ok := n.routes.GetPeer(peerID); ok {
				return true
			}
			// Fall back to mesh-membership (gossip) check for
			// relay-reached peers.
			if n.relayMetaProvider != nil {
				for _, rp := range n.relayMetaProvider() {
					if rp.PeerKey == peerID {
						return true
					}
				}
			}
			return false
		}
	}
	handler := NewSOCKS5Handler(cfg)

	// Register a virtual port listener for 0x5350.
	ln, err := n.ListenVirtualPort(int(SOCKS5VirtualPort))
	if err != nil {
		return nil, fmt.Errorf("socks5: register port 0x%x: %w", SOCKS5VirtualPort, err)
	}

	// Start the accept loop in a background goroutine.
	go n.serveSOCKS5(handler, ln)

	// Store the handler so Close() can clean it up.
	n.mu.Lock()
	n.socks5Handler = handler
	n.mu.Unlock()

	return handler, nil
}

// serveSOCKS5 runs the accept loop for the SOCKS5 virtual port listener.
func (n *MeshNode) serveSOCKS5(handler *SOCKS5Handler, ln net.Listener) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed — exit.
			return
		}
		go handler.HandleStream(conn)
	}
}
