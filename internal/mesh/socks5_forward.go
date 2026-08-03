package mesh

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/yzy806806/meshdesk/internal/proxy"
)

// ExitVirtualPort is the virtual port for the SOCKS5 exit-side handler.
// 0x4558 = 'E' (0x45) 'X' (0x58) — mnemonic for "EXit".
// Exit nodes listen on this port to receive forwarded SOCKS5 requests
// from shared nodes.
const ExitVirtualPort = 0x4558 // 17752

// SOCKS5ForwardConfig holds configuration for the SOCKS5 forwarding handler.
// Unlike SOCKS5Config (which configures the exit-side direct-dial handler),
// this configures the shared-node forwarding handler that relays SOCKS5
// traffic to a remote exit node through the mesh.
type SOCKS5ForwardConfig struct {
	// DialTimeout is the timeout for dialing the exit node's virtual port.
	// Default: 15 seconds.
	DialTimeout time.Duration

	// IdleTimeout is the idle timeout for established connections.
	// Default: 5 minutes.
	IdleTimeout time.Duration

	// MaxConnections limits concurrent forwarded connections.
	// Default: 256.
	MaxConnections int

	// ExitNodeID, when non-empty, pins the exit node to use.
	// When empty, the handler selects an exit node dynamically using
	// the path_selector's SelectExit function with the mesh's exit
	// candidate pool.
	ExitNodeID string

	// ExitProbeResults holds RTT measurements from exit nodes to
	// target regions, used by SelectExit for dynamic exit selection.
	// Map key: exitNodeID → map[region]RTT.
	// Optional — when nil, the first available exit candidate is used.
	ExitProbeResults map[string]map[string]time.Duration

	// GetExitCandidates returns the current set of exit-capable peers.
	// When nil, ExitNodeID must be set (static mode).
	// Wire this to GossipLayer.Events().GetExitCandidates() in production.
	GetExitCandidates func() []ExitCandidate
}

// ExitCandidate describes an exit-capable mesh peer for path selection.
// It mirrors proxy.CandidateRelay but for exit nodes.
type ExitCandidate struct {
	// NodeID is the Ed25519 public key (hex) of the exit node.
	NodeID string

	// Endpoint is the mesh address for probing (optional).
	Endpoint string

	// AdvertisedRTT is the node's self-reported latency (optional).
	AdvertisedRTT time.Duration
}

// DefaultSOCKS5ForwardConfig returns sensible defaults.
func DefaultSOCKS5ForwardConfig() SOCKS5ForwardConfig {
	return SOCKS5ForwardConfig{
		DialTimeout:   15 * time.Second,
		IdleTimeout:   5 * time.Minute,
		MaxConnections: 256,
	}
}

// SOCKS5ForwardHandler forwards inbound SOCKS5 requests to a remote exit
// node via DialVirtualPort. It runs on shared nodes: when a phone client
// connects via Reality TLS and opens a stream on virtual port 0x5350,
// this handler:
//
//  1. Parses the SOCKS5 greeting + CONNECT request from the client.
//  2. Selects an exit node (static via ExitNodeID, or dynamic via
//     path_selector's SelectExit using gossip-discovered exit candidates).
//  3. Dials the exit node's virtual port 0x4558 via DialVirtualPort.
//  4. Forwards the SOCKS5 greeting + CONNECT to the exit node.
//  5. Relays the exit node's reply back to the client.
//  6. Bridges data bidirectionally with io.Copy.
//
// This reuses internal/proxy/path_selector.go's SelectExit for exit node
// selection and internal/proxy/exit.go's port validation logic.
type SOCKS5ForwardHandler struct {
	config   SOCKS5ForwardConfig
	node     *MeshNode
	dialer   *net.Dialer
	active   int64
	closed   atomic.Bool
}

// NewSOCKS5ForwardHandler creates a forwarding handler bound to the given node.
func NewSOCKS5ForwardHandler(node *MeshNode, cfg SOCKS5ForwardConfig) *SOCKS5ForwardHandler {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 256
	}
	return &SOCKS5ForwardHandler{
		config: cfg,
		node:   node,
		dialer: &net.Dialer{Timeout: cfg.DialTimeout},
	}
}

// HandleStream processes a SOCKS5 connection from a phone client and
// forwards it to an exit node through the mesh.
func (h *SOCKS5ForwardHandler) HandleStream(clientConn net.Conn) {
	if h.closed.Load() {
		clientConn.Close()
		return
	}

	if atomic.LoadInt64(&h.active) >= int64(h.config.MaxConnections) {
		log.Printf("[socks5-fwd] connection limit reached (%d), rejecting", h.config.MaxConnections)
		clientConn.Close()
		return
	}

	atomic.AddInt64(&h.active, 1)
	defer atomic.AddInt64(&h.active, -1)

	// Set a deadline for the handshake phase.
	clientConn.SetDeadline(time.Now().Add(15 * time.Second))
	defer clientConn.SetDeadline(time.Time{})

	// Phase 1: Read SOCKS5 greeting + CONNECT from the client.
	targetAddr, atyp, host, port, err := h.readClientRequest(clientConn)
	if err != nil {
		log.Printf("[socks5-fwd] read client request: %v", err)
		clientConn.Close()
		return
	}

	log.Printf("[socks5-fwd] CONNECT %s from client", targetAddr)

	// Phase 2: Select an exit node.
	exitPeerID, err := h.selectExitNode()
	if err != nil {
		log.Printf("[socks5-fwd] exit selection: %v", err)
		h.sendReply(clientConn, socks5RepHostUnreachable, nil, 0)
		clientConn.Close()
		return
	}

	// Phase 3: Dial the exit node's virtual port 0x4558.
	ctx, cancel := context.WithTimeout(context.Background(), h.config.DialTimeout)
	defer cancel()

	exitConn, err := h.node.DialVirtualPort(ctx, exitPeerID, int(ExitVirtualPort))
	if err != nil {
		log.Printf("[socks5-fwd] dial exit %s: %v", exitPeerID[:min(len(exitPeerID), 16)], err)
		h.sendReply(clientConn, socks5RepHostUnreachable, nil, 0)
		clientConn.Close()
		return
	}
	defer exitConn.Close()

	// Phase 4: Forward the SOCKS5 greeting + CONNECT to the exit node.
	if err := h.forwardRequest(exitConn, atyp, host, port); err != nil {
		log.Printf("[socks5-fwd] forward request to exit: %v", err)
		h.sendReply(clientConn, socks5RepGeneralFailure, nil, 0)
		clientConn.Close()
		return
	}

	// Phase 5: Read the exit node's reply and forward to client.
	exitRep, err := h.readExitReply(exitConn)
	if err != nil {
		log.Printf("[socks5-fwd] read exit reply: %v", err)
		h.sendReply(clientConn, socks5RepGeneralFailure, nil, 0)
		clientConn.Close()
		return
	}

	// Forward the exit's reply to the client.
	h.sendReply(clientConn, exitRep, nil, 0)

	if exitRep != socks5RepSuccess {
		log.Printf("[socks5-fwd] exit returned error: 0x%02x", exitRep)
		clientConn.Close()
		return
	}

	// Phase 6: Bidirectional data relay.
	h.relay(clientConn, exitConn)
}

// readClientRequest reads the SOCKS5 greeting and CONNECT request from
// the client, returning the target address, address type, host, and port.
func (h *SOCKS5ForwardHandler) readClientRequest(conn net.Conn) (targetAddr string, atyp byte, host string, port uint16, err error) {
	// Read greeting: VER, NMETHODS, METHODS...
	greeting := make([]byte, 2)
	if _, e := io.ReadFull(conn, greeting); e != nil {
		err = fmt.Errorf("read greeting: %w", e)
		return
	}
	if greeting[0] != socks5Version {
		err = fmt.Errorf("unsupported SOCKS version %d", greeting[0])
		return
	}
	nMethods := int(greeting[1])
	if nMethods == 0 {
		err = fmt.Errorf("no auth methods offered")
		return
	}
	methods := make([]byte, nMethods)
	if _, e := io.ReadFull(conn, methods); e != nil {
		err = fmt.Errorf("read methods: %w", e)
		return
	}

	// Reply: no authentication required.
	if _, e := conn.Write([]byte{socks5Version, socks5NoAuth}); e != nil {
		err = fmt.Errorf("write auth reply: %w", e)
		return
	}

	// Read request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	header := make([]byte, 4)
	if _, e := io.ReadFull(conn, header); e != nil {
		err = fmt.Errorf("read request header: %w", e)
		return
	}
	if header[0] != socks5Version {
		err = fmt.Errorf("unsupported SOCKS version in request: %d", header[0])
		return
	}
	if header[1] != socks5Connect {
		h.sendReply(conn, socks5RepCmdNotSupported, nil, 0)
		err = fmt.Errorf("unsupported CMD %d (only CONNECT=1)", header[1])
		return
	}

	atyp = header[3]
	switch atyp {
	case socks5AtypIPv4:
		addrBuf := make([]byte, 4)
		if _, e := io.ReadFull(conn, addrBuf); e != nil {
			err = fmt.Errorf("read IPv4 addr: %w", e)
			return
		}
		host = net.IP(addrBuf).String()
	case socks5AtypFQDN:
		lenBuf := make([]byte, 1)
		if _, e := io.ReadFull(conn, lenBuf); e != nil {
			err = fmt.Errorf("read FQDN length: %w", e)
			return
		}
		fqdnLen := int(lenBuf[0])
		if fqdnLen == 0 {
			err = fmt.Errorf("empty FQDN")
			return
		}
		fqdnBuf := make([]byte, fqdnLen)
		if _, e := io.ReadFull(conn, fqdnBuf); e != nil {
			err = fmt.Errorf("read FQDN: %w", e)
			return
		}
		host = string(fqdnBuf)
	case socks5AtypIPv6:
		addrBuf := make([]byte, 16)
		if _, e := io.ReadFull(conn, addrBuf); e != nil {
			err = fmt.Errorf("read IPv6 addr: %w", e)
			return
		}
		host = net.IP(addrBuf).String()
	default:
		h.sendReply(conn, socks5RepAtypNotSupported, nil, 0)
		err = fmt.Errorf("unsupported ATYP %d", atyp)
		return
	}

	portBuf := make([]byte, 2)
	if _, e := io.ReadFull(conn, portBuf); e != nil {
		err = fmt.Errorf("read port: %w", e)
		return
	}
	port = binary.BigEndian.Uint16(portBuf)
	targetAddr = net.JoinHostPort(host, fmt.Sprintf("%d", port))
	return
}

// selectExitNode selects an exit node for forwarding. If ExitNodeID is
// configured, it uses that. Otherwise, it uses path_selector's SelectExit
// with the gossip-discovered exit candidates.
func (h *SOCKS5ForwardHandler) selectExitNode() (string, error) {
	// Static exit node mode.
	if h.config.ExitNodeID != "" {
		return h.config.ExitNodeID, nil
	}

	// Dynamic mode: use GetExitCandidates + SelectExit.
	if h.config.GetExitCandidates == nil {
		return "", fmt.Errorf("no exit node configured (ExitNodeID empty and GetExitCandidates nil)")
	}

	candidates := h.config.GetExitCandidates()
	if len(candidates) == 0 {
		return "", fmt.Errorf("no exit candidates available")
	}

	// Build exit probe map for SelectExit. If ExitProbeResults is nil,
	// use the first candidate.
	if h.config.ExitProbeResults == nil || len(h.config.ExitProbeResults) == 0 {
		return candidates[0].NodeID, nil
	}

	// Use proxy.SelectExit to pick the best exit based on RTT data.
	// We don't have GeoIP region info, so pass empty string — SelectExit
	// will fall back to best-average-RTT selection.
	exitID, err := proxy.SelectExit(h.config.ExitProbeResults, "")
	if err != nil {
		// Fallback to first candidate.
		return candidates[0].NodeID, nil
	}
	return exitID, nil
}

// forwardRequest sends a SOCKS5 greeting + CONNECT request to the exit node.
func (h *SOCKS5ForwardHandler) forwardRequest(conn net.Conn, atyp byte, host string, port uint16) error {
	// Greeting: VER=5, NMETHODS=1, METHODS=[no auth]
	if _, err := conn.Write([]byte{socks5Version, 0x01, socks5NoAuth}); err != nil {
		return fmt.Errorf("write greeting: %w", err)
	}

	// Read auth reply.
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil {
		return fmt.Errorf("read auth reply: %w", err)
	}
	if authReply[0] != socks5Version || authReply[1] != socks5NoAuth {
		return fmt.Errorf("exit rejected auth: %v", authReply)
	}

	// CONNECT request.
	var msg []byte
	msg = append(msg, socks5Version, socks5Connect, 0x00, atyp)
	switch atyp {
	case socks5AtypIPv4:
		ip := net.ParseIP(host).To4()
		if ip == nil {
			return fmt.Errorf("invalid IPv4: %s", host)
		}
		msg = append(msg, ip...)
	case socks5AtypFQDN:
		msg = append(msg, byte(len(host)))
		msg = append(msg, []byte(host)...)
	case socks5AtypIPv6:
		ip := net.ParseIP(host).To16()
		if ip == nil {
			return fmt.Errorf("invalid IPv6: %s", host)
		}
		msg = append(msg, ip...)
	default:
		return fmt.Errorf("unsupported ATYP %d", atyp)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	msg = append(msg, portBuf[:]...)

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("write connect request: %w", err)
	}
	return nil
}

// readExitReply reads the SOCKS5 reply from the exit node and returns
// the REP field.
func (h *SOCKS5ForwardHandler) readExitReply(conn net.Conn) (byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, fmt.Errorf("read reply header: %w", err)
	}
	rep := header[1]
	atyp := header[3]

	var addrLen int
	switch atyp {
	case socks5AtypIPv4:
		addrLen = 4
	case socks5AtypFQDN:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return rep, fmt.Errorf("read FQDN length: %w", err)
		}
		addrLen = int(lenBuf[0])
	case socks5AtypIPv6:
		addrLen = 16
	}
	if addrLen > 0 {
		if _, err := io.ReadFull(conn, make([]byte, addrLen)); err != nil {
			return rep, fmt.Errorf("read bind addr: %w", err)
		}
	}
	// Read bind port (2 bytes).
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		return rep, fmt.Errorf("read bind port: %w", err)
	}
	return rep, nil
}

// sendReply sends a SOCKS5 reply on the connection.
func (h *SOCKS5ForwardHandler) sendReply(conn net.Conn, rep byte, bndAddr net.IP, bndPort uint16) {
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
func (h *SOCKS5ForwardHandler) relay(clientConn, exitConn net.Conn) {
	if h.config.IdleTimeout > 0 {
		clientConn.SetDeadline(time.Now().Add(h.config.IdleTimeout))
		exitConn.SetDeadline(time.Now().Add(h.config.IdleTimeout))
	}

	done := make(chan struct{}, 2)

	// client → exit
	go func() {
		io.Copy(exitConn, clientConn)
		if cw, ok := exitConn.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	// exit → client
	go func() {
		io.Copy(clientConn, exitConn)
		if cw, ok := clientConn.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	clientConn.Close()
	exitConn.Close()
	<-done
}

// Close tears down the forward handler. New connections are rejected.
func (h *SOCKS5ForwardHandler) Close() error {
	h.closed.Store(true)
	return nil
}

// ActiveConnections returns the number of currently active forwarded connections.
func (h *SOCKS5ForwardHandler) ActiveConnections() int64 {
	return atomic.LoadInt64(&h.active)
}

// RegisterSOCKS5ForwardHandler registers a SOCKS5ForwardHandler on virtual
// port 0x5350, enabling this node to forward SOCKS5 requests from phone
// clients to a remote exit node through the mesh.
//
// This is the "shared node" side of the SOCKS5 proxy: phones connect via
// Reality TLS, open a stream on port 0x5350, and the handler forwards the
// request to an exit node listening on port 0x4558.
//
// The returned handler should be Closed when no longer needed. It is also
// closed automatically when the node's Close() is called.
func (n *MeshNode) RegisterSOCKS5ForwardHandler(cfg SOCKS5ForwardConfig) (*SOCKS5ForwardHandler, error) {
	handler := NewSOCKS5ForwardHandler(n, cfg)

	// Register a virtual port listener for 0x5350.
	ln, err := n.ListenVirtualPort(int(SOCKS5VirtualPort))
	if err != nil {
		return nil, fmt.Errorf("socks5-fwd: register port 0x%x: %w", SOCKS5VirtualPort, err)
	}

	// Start the accept loop.
	go n.serveSOCKS5Forward(handler, ln)

	// Store the handler so Close() can clean it up.
	n.mu.Lock()
	n.socks5Handler = handler
	n.mu.Unlock()

	return handler, nil
}

// serveSOCKS5Forward runs the accept loop for the SOCKS5 forward handler.
func (n *MeshNode) serveSOCKS5Forward(handler *SOCKS5ForwardHandler, ln net.Listener) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handler.HandleStream(conn)
	}
}
