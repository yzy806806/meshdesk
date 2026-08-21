package mesh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

)

// ──────────────────────────────────────────────────────────────────────────────
// Protocol detection constants
// ──────────────────────────────────────────────────────────────────────────────

// tlsHandshakeRecordType is the TLS ContentType for handshake records (0x16 = 22).
// Every TLS connection begins with this byte in the first record header.
// See RFC 5246 §6.2.1: ContentType handshake = 22.
const tlsHandshakeRecordType = 0x16

// debugEnabled caches the MESHDESK_DEBUG env check (read on hot paths).
var debugEnabled = os.Getenv("MESHDESK_DEBUG") == "1"

// muxUDPPacketBufSize is the receive buffer size for UDP packet reads.
const muxUDPPacketBufSize = 65536

// muxUDPRecvBufSize is the target SO_RCVBUF for UDP sockets.
const muxUDPRecvBufSize = 2 * 1024 * 1024

// punchKeepaliveInterval is how often the punchSocketPoller sends a
// 6B probe from each punch socket to refresh the peer's stateful
// firewall conntrack entry. Must be well under typical UDP conntrack
// timeouts (~30s for most stateful firewalls incl. Oracle Cloud
// security lists and iptables ESTABLISHED-only rules); 15s keeps the
// hole open with minimal overhead. EasyTier keeps its tunnel socket
// busy for exactly this reason — without it the peer's data-plane
// frames become "new inbound" and are dropped once the mapping
// expires.
const punchKeepaliveInterval = 15 * time.Second

// ──────────────────────────────────────────────────────────────────────────────
// MuxTransportConfig
// ──────────────────────────────────────────────────────────────────────────────

// MuxTransportConfig configures a MuxTransport.
type MuxTransportConfig struct {
	// TCPListener is the shared TCP listener that will accept both
	// memberlist gossip streams and Reality TLS connections. The
	// MuxTransport takes ownership of this listener and will close it
	// on Shutdown.
	TCPListener net.Listener

	// BindAddr is the bind address used for the UDP PacketConn.
	// Typically "0.0.0.0" or a specific IP.
	BindAddr string

	// UDPPort is the port for the UDP PacketConn. If 0, the same port
	// as the TCP listener is used.
	UDPPort int

	// AdvertiseAddr is the IP address to advertise to the cluster.
	// If empty, the transport auto-detects a private IP.
	AdvertiseAddr string

	// AdvertisePort is the port to advertise to the cluster.
	// If 0, the TCP listener's port is used.
	AdvertisePort int

	// Logger is used for operational messages. If nil, a default
	// logger writing to log.Writer() is used.
	Logger *log.Logger
}

// ──────────────────────────────────────────────────────────────────────────────
// MuxTransport — memberlist.Transport + Reality demux
// ──────────────────────────────────────────────────────────────────────────────

// MuxTransport implements the memberlist.Transport interface while
// multiplexing a single TCP listener between memberlist gossip streams
// and Reality TLS connections.
//
// Protocol detection: For each accepted TCP connection, the first byte is
// peeked. If it equals 0x16 (TLS handshake record type), the connection
// is routed to the Reality listener. Otherwise, it is treated as a
// memberlist gossip stream and routed to StreamCh().
//
// The peeked byte is replayed via connWithPrefix so that the downstream
// protocol handler sees the complete stream from byte zero.
//
// UDP packets are handled by a separate net.UDPConn, independent of the
// shared TCP listener. This matches memberlist's design where packet
// (UDP) and stream (TCP) paths are fully decoupled.
//
// All methods are safe for concurrent use.
type MuxTransport struct {
	// observedSourceMu guards observedSource (recent 0x504B echo source).
	observedSourceMu sync.Mutex
	observedSource   *net.UDPAddr

	// punchSockets are independent hole-punch sockets kept alive after
	// a successful punch — the data plane dials through them so the
	// source port matches the conntrack mapping the peer opened.
	punchMu      sync.Mutex
	punchSockets map[string]*net.UDPConn // peer key -> socket
	tcpListener  net.Listener            // shared TCP listener
	udpConns     []*net.UDPConn          // UDP sockets (IPv4 + IPv6)
	logger       *log.Logger

	streamCh   chan net.Conn           // mesh-internal connections (pre-0x4D)
	realityCh  chan net.Conn           // Reality TLS connections → reality listener
	meshCh     chan net.Conn           // mesh-internal connections → mesh listener
	udpMesh    *udpMeshManager         // per-remote UDP ARQ streams (0x4D routing)
	// connSem bounds concurrent TCP connection handling (slowloris guard).
	connSem chan struct{}

	shutdown   atomic.Int32
	shutdownCh chan struct{} // created in NewMuxTransport, closed on Shutdown (never lazily)
	wg         sync.WaitGroup

	bindAddr      string
	advertiseAddr string
	advertisePort int
}

// NewMuxTransport creates a new MuxTransport from the given config.
// The shared TCP listener must already be listening. A UDP PacketConn
// is created on the specified bind address and port.
//
// On success, the transport is ready to be assigned to
// memberlist.Config.Transport. The accept loop is started automatically.
func NewMuxTransport(cfg MuxTransportConfig) (*MuxTransport, error) {
	// TCPListener is optional. Ordinary nodes (reality.enabled=false,
	// p2p.enabled=true) do not expose a public TCP port but still need
	// a UDP PacketConn for memberlist gossip. When TCPListener is nil,
	// the transport operates in UDP-only mode: no TCP accept loop is
	// started, StreamCh()/RealityListener()/MeshListener() never deliver
	// connections, but PacketCh()/WriteTo()/FinalAdvertiseAddr() work
	// normally.

	bindAddr := cfg.BindAddr
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(log.Writer(), "[mux-transport] ", log.LstdFlags)
	}

	// Determine the UDP port: use UDPPort if set, otherwise mirror the
	// TCP listener's port (0 if no TCP listener).
	tcpPort := 0
	if cfg.TCPListener != nil {
		tcpPort = tcpPortFromListener(cfg.TCPListener)
	}
	udpPort := cfg.UDPPort
	randUDP := udpPort == -1 // ordinary node: two family sockets, random ports
	if udpPort <= 0 && !randUDP {
		udpPort = tcpPort
	}
	if randUDP {
		udpPort = 0 // each bind below uses :0 → OS-assigned
	}
	// When both TCPListener and UDPPort are unset, udpPort is 0.
	// net.ListenUDP with port 0 lets the OS pick a free port — valid
	// for testing, though production deployments should set UDPPort
	// explicitly so the advertised port is stable across restarts.

	// Create the UDP listener(s). Three modes, chosen to dodge a Go
	// runtime quirk verified on txcloud: when a UDP socket shares its
	// port with ANOTHER UDP socket of the other family (or with the
	// TCP listener), its public-send silently fails — WriteToUDP
	// returns nil but the datagram never leaves the box. Hence:
	//
	//   A. Distinct UDP ports (UDPPort=-1, ordinary nodes): bind
	//      udp4:0 + udp6:0 — two family sockets, each on an
	//      OS-assigned random port (different by construction), so
	//      each sends cleanly. The real ports are exchanged via the
	//      punch coordination message.
	//   B. Single-port multiplex (UDPPort unset, shared nodes with
	//      TCP on the same port): bind a single [::] dual-stack
	//      socket. Receives v4+v6; sends small frames (gossip, punch
	//      coordination) fine — shared nodes do not pump the big TUN
	//      data plane (relay traffic rides TCP).
	//   C. Ephemeral (udpPort==0, tests): single [::] socket.
	//
	// Explicit single-address binds (e.g. "127.0.0.1", "::1") stay as-is.
	var udpConns []*net.UDPConn
	udpBinds := []string{bindAddr}
	switch {
	case bindAddr == "0.0.0.0" || bindAddr == "::":
		if randUDP {
			// Mode A: two family sockets, random ports each.
			udpBinds = []string{"0.0.0.0", "::"}
		} else if udpPort == 0 {
			// Mode C: ephemeral — single [::] socket (avoids two
			// :0 binds racing for distinct ports).
			udpBinds = []string{"::"}
		} else if udpPort == tcpPort && tcpPort != 0 {
			// Mode B: single-port multiplex — one [::] dual-stack
			// socket carries gossip + coordination. Same port as
			// TCP is fine (different protocol); two UDP sockets on
			// the same port would break sends.
			udpBinds = []string{"::"}
		} else {
			// Explicit distinct fixed port: one socket per family,
			// DIFFERENT ports (udpPort for v4, udpPort+1 for v6),
			// so neither socket's public send is broken by sharing.
			udpBinds = []string{"0.0.0.0", "::"}
		}
	}
	for _, bind := range udpBinds {
		port := udpPort
		if len(udpBinds) == 2 && !randUDP {
			// Explicit distinct fixed ports: v6 socket gets
			// udpPort+1 so the two family sockets never share.
			if bind == "::" {
				port++
			}
		}
		udpAddr := &net.UDPAddr{IP: net.ParseIP(bind), Port: port}
		var conn *net.UDPConn
		isV6Bind := strings.Contains(bind, ":") // "::", "::1", "fe80::..." etc.
		if isV6Bind {
			if bind == "::" && len(udpBinds) == 2 {
				// Mode A: set IPV6_V6ONLY=1 so the [::] socket does
				// NOT also grab the IPv4 port — otherwise binding
				// 0.0.0.0 fails with "address already in use"
				// (Linux default V6ONLY=0 makes [::] cover both
				// families). In Mode B/C (single socket) we keep
				// V6ONLY=0 so v4+v6 both arrive.
				lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
					var sockErr error
					c.Control(func(fd uintptr) {
						sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
					})
					return sockErr
				}}
				pc, err := lc.ListenPacket(context.Background(), "udp6", udpAddr.String())
				if err != nil {
					return nil, fmt.Errorf("mux: failed to listen UDP on %s:%d: %w", bind, port, err)
				}
				conn = pc.(*net.UDPConn)
			} else {
				// Explicit v6 address (::1, ::, or Mode B/C [::]):
				// plain ListenUDP("udp6") — no V6ONLY needed.
				var err error
				conn, err = net.ListenUDP("udp6", udpAddr)
				if err != nil {
					return nil, fmt.Errorf("mux: failed to listen UDP on %s:%d: %w", bind, port, err)
				}
			}
			logger.Printf("[mux] UDP v6 socket bound on %s", conn.LocalAddr())
		} else {
			// MUST use "udp4" explicitly: Go's "udp" network with a
			// 0.0.0.0 address actually binds [::] (v6 dual-stack),
			// which collides with the [::] socket bound above.
			var err error
			conn, err = net.ListenUDP("udp4", udpAddr)
			if err != nil {
				return nil, fmt.Errorf("mux: failed to listen UDP on %s:%d: %w", bind, port, err)
			}
		}
		if err := setMuxUDPRecvBuf(conn); err != nil {
			logger.Printf("[WARN] mux: failed to resize UDP recv buffer on %s: %v (continuing)", bind, err)
		}
		udpConns = append(udpConns, conn)
	}

	t := &MuxTransport{
		tcpListener:   cfg.TCPListener,
		udpConns:      udpConns,
		logger:        logger,
		streamCh:      make(chan net.Conn, 64),
		realityCh:     make(chan net.Conn, 64),
		meshCh:        make(chan net.Conn, 64),
		connSem:       make(chan struct{}, maxConcurrentMuxConns),
		shutdownCh:    make(chan struct{}),
		bindAddr:      bindAddr,
		advertiseAddr: cfg.AdvertiseAddr,
		advertisePort: cfg.AdvertisePort,
		udpMesh:       newUDPMeshManager(),
	}

	if t.advertisePort == 0 {
		t.advertisePort = tcpPort
	}
	// In UDP-only mode (no TCP listener), advertisePort is still 0.
	// Extract the actual bound port from the first UDP socket so
	// memberlist can advertise a valid port for TCP push/pull sync.
	if t.advertisePort == 0 && len(udpConns) > 0 {
		if addr, ok := udpConns[0].LocalAddr().(*net.UDPAddr); ok && addr != nil {
			t.advertisePort = addr.Port
		}
	}

	// Start the UDP listen loop (always needed for gossip).
	t.wg.Add(1)
	go t.udpListenLoop()

	// Start the TCP accept loop only if we have a TCP listener.
	if t.tcpListener != nil {
		t.wg.Add(1)
		go t.tcpAcceptLoop()
	}

	return t, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// DialUDP initiates a UDP mesh stream to the given remote address
// (host:port). Returns a reliable ARQ conn ready for key exchange.
// nil if no UDP socket or manager available.
func (t *MuxTransport) DialUDP(remoteAddr string) (*udpStreamConn, error) {
	local, udpAddr, err := t.pickUDPSocket(remoteAddr)
	if err != nil {
		return nil, err
	}
	// Source socket stays the mux socket (fixed listen port — the
	// mesh port, 52888 by default from cfg.Mesh.Port): the peer's
	// conntrack entry was created by ITS outbound probe (peerSrc ->
	// our listen port), so our datagrams MUST come from the listen
	// port to match. The punched TARGET port (the peer's outbound
	// source, remoteAddr) is what changes — the learned endpoint
	// already carries it. Using the punch socket as the SOURCE breaks
	// the peer-side conntrack match (its ephemeral port has no
	// conntrack entry on the peer).
	return t.udpMesh.DialUDPStream(local, udpAddr)
}

// DialTUNUDP establishes a UDP ARQ stream to a remote address for TUN
// data (multipath D: UDP-preferred data plane). authHeader is the
// first-frame authentication payload (pubkey+ts+sig) proving identity.
// Returns a reliable conn carrying framed TUN packets.
func (t *MuxTransport) DialTUNUDP(remoteAddr string, authHeader []byte) (*udpStreamConn, error) {
	local, udpAddr, err := t.pickUDPSocket(remoteAddr)
	if err != nil {
		return nil, err
	}
	// Source socket stays the mux socket (fixed listen port — the
	// mesh port, 52888 by default from cfg.Mesh.Port): the peer's
	// conntrack entry was created by ITS outbound probe (peerSrc ->
	// our listen port), so our datagrams MUST come from the listen
	// port to match. The punched TARGET port (the peer's outbound
	// source, remoteAddr) is what changes — the learned endpoint
	// already carries it. Using the punch socket as the SOURCE was
	// wrong: its ephemeral port (49425) breaks the
	// peer-side conntrack match.
	return t.udpMesh.DialTUNStream(local, udpAddr, authHeader)
}

// UDPMesh returns the UDP mesh manager (for punched stream registration).
func (t *MuxTransport) UDPMesh() *udpMeshManager {
	return t.udpMesh
}

// TunCh returns the channel on which inbound TUN UDP streams are
// delivered (consumed by the TUN forwarder's accept loop).
func (t *MuxTransport) TunCh() chan net.Conn {
	if t.udpMesh == nil {
		return nil
	}
	return t.udpMesh.tunCh
}

// pickUDPSocket resolves the remote address and picks a local UDP
// socket matching the remote family.
func (t *MuxTransport) pickUDPSocket(remoteAddr string) (*net.UDPConn, *net.UDPAddr, error) {
	if t.udpMesh == nil {
		return nil, nil, fmt.Errorf("mux: udp mesh manager not initialized")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("mux: resolve %s: %w", remoteAddr, err)
	}
	local := t.UDPConnFor(udpAddr.IP)
	if local == nil {
		return nil, nil, fmt.Errorf("mux: no UDP socket available")
	}
	return local, udpAddr, nil
}

// UDPConnFor returns the mux UDP socket matching the remote IP family
// (IPv4 socket for IPv4 peers, IPv6 for IPv6) — the same socket the
// TUN UDP data plane dials from. Hole-punching reuses this socket so
// the punched NAT mapping is exactly the one the data plane uses.
//
// On ordinary nodes (Mode A: two family sockets), strict family matching
// is correct — a v6 socket sending v4 frames (::ffff: mapped source)
// gets dropped by some NATs/firewalls.
//
// On shared nodes (Mode B/C: single [::] dual-stack socket), there is
// only one socket — it carries both v4 and v6. The family check fails
// because [::]'s To4() is nil, so we fall back to the single socket.
func (t *MuxTransport) UDPConnFor(remoteIP net.IP) *net.UDPConn {
	for _, conn := range t.udpConns {
		if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			if (la.IP.To4() != nil) == (remoteIP.To4() != nil) {
				return conn
			}
		}
	}
	// Shared nodes (Mode B/C) have a single [::] dual-stack socket
	// that handles both families — fall back to it.
	if len(t.udpConns) == 1 {
		return t.udpConns[0]
	}
	return nil
}

// AddPunchSocket registers a kept-alive hole-punch socket for a peer
// (source port = the conntrack mapping the peer's data plane targets).
// If a socket was already registered for this peer, it is closed first
// to prevent fd/goroutine leaks on re-punch.
func (t *MuxTransport) AddPunchSocket(peerKey string, conn *net.UDPConn) {
	t.punchMu.Lock()
	defer t.punchMu.Unlock()
	if t.punchSockets == nil {
		t.punchSockets = make(map[string]*net.UDPConn)
	}
	if old := t.punchSockets[peerKey]; old != nil && old != conn {
		old.Close() // closes the old socket → its reader goroutine exits on error
	}
	t.punchSockets[peerKey] = conn
}

// AddPunchSocketAddr registers a punch socket keyed by the remote
// address (used by the coordinator's pre-answer socket, which has no
// peer key). If a socket was already registered for this address, it
// is closed first to prevent fd/goroutine leaks.
func (t *MuxTransport) AddPunchSocketAddr(remoteAddr string, conn *net.UDPConn) {
	t.punchMu.Lock()
	defer t.punchMu.Unlock()
	if t.punchSockets == nil {
		t.punchSockets = make(map[string]*net.UDPConn)
	}
	if old := t.punchSockets[remoteAddr]; old != nil && old != conn {
		old.Close()
	}
	t.punchSockets[remoteAddr] = conn
}

// RemovePunchSocket closes and removes the punch socket for a peer
// key or endpoint. Called on session death (CleanupPeer) to release
// the fd and stop the reader goroutine.
func (t *MuxTransport) RemovePunchSocket(key string) {
	t.punchMu.Lock()
	defer t.punchMu.Unlock()
	if c := t.punchSockets[key]; c != nil {
		c.Close()
		delete(t.punchSockets, key)
	}
}

// PunchSocket returns the registered punch socket for a peer (nil if none).
func (t *MuxTransport) PunchSocket(key string) *net.UDPConn {
	t.punchMu.Lock()
	defer t.punchMu.Unlock()
	if c := t.punchSockets[key]; c != nil {
		return c
	}
	// Fall back to IP-only match (the key may carry a different port).
	if ua, err := net.ResolveUDPAddr("udp", key); err == nil {
		for k, c := range t.punchSockets {
			if ku, kerr := net.ResolveUDPAddr("udp", k); kerr == nil && ku.IP.Equal(ua.IP) {
				return c
			}
		}
	}
	return nil
}

// ObservedSourcePort returns the most recent 0x504B echo source port
// (0 if none) — the peer's conntrack-matched outbound source port.
func (t *MuxTransport) ObservedSourcePort() int {
	t.observedSourceMu.Lock()
	defer t.observedSourceMu.Unlock()
	if t.observedSource == nil {
		return 0
	}
	return t.observedSource.Port
}

// TunUDPListener returns a listener that accepts inbound TUN-data UDP
// streams (each conn carries framed TUN packets via ARQ).
func (t *MuxTransport) TunUDPListener() net.Listener {
	return &muxTunUDPListener{
		transport: t,
		doneCh:    make(chan struct{}),
	}
}

type muxTunUDPListener struct {
	transport *MuxTransport
	once      sync.Once
	doneCh    chan struct{}
}

func (l *muxTunUDPListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.transport.udpMesh.TunCh():
		return conn, nil
	case <-l.doneCh:
		return nil, net.ErrClosed
	}
}

func (l *muxTunUDPListener) Addr() net.Addr {
	if l.transport.tcpListener != nil {
		return l.transport.tcpListener.Addr()
	}
	return nil
}

func (l *muxTunUDPListener) Close() error {
	l.once.Do(func() {
		close(l.doneCh)
	})
	return nil
}

// DialTimeout creates an outbound TCP connection to the given address
// with the specified timeout. This is used by memberlist for anti-entropy
// syncs and fallback probes. The dialed connection arrives at the remote
// peer's shared TCP listener, where the remote muxTransport's peek logic
// routes it to the gossip StreamCh.
func (t *MuxTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.Dial("tcp", addr)
}

// StreamCh returns the channel for receiving incoming memberlist gossip
// TCP streams. Each conn delivered here has been demuxed: the peeked
// byte has been replayed via connWithPrefix so the stream is intact.
func (t *MuxTransport) StreamCh() <-chan net.Conn {
	return t.streamCh
}

// Shutdown stops the transport, closing the TCP listener and UDP conn.
// It is idempotent and blocks until all goroutines have exited.
func (t *MuxTransport) Shutdown() error {
	if !t.shutdown.CompareAndSwap(0, 1) {
		return nil
	}

	// Signal the shutdown channel so blocked sends can unblock.
	// shutdownCh is eagerly created in NewMuxTransport — never nil.
	close(t.shutdownCh)

	if t.tcpListener != nil {
		_ = t.tcpListener.Close()
	}
	for _, conn := range t.udpConns {
		_ = conn.Close()
	}

	t.wg.Wait()
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Reality listener — net.Listener backed by the demuxed Reality connections
// ──────────────────────────────────────────────────────────────────────────────

// RealityListener returns a net.Listener that accepts connections demuxed
// to the Reality TLS path. The returned listener is valid for the lifetime
// of the MuxTransport; closing it does not close the MuxTransport.
//
// The typical usage is:
//
//	mt, _ := NewMuxTransport(cfg)
//	rl := mt.RealityListener()
//	// ... pass rl to reality handshake layer ...
func (t *MuxTransport) RealityListener() net.Listener {
	return &muxRealityListener{
		transport: t,
		doneCh:    make(chan struct{}),
	}
}

// muxRealityListener implements net.Listener for Reality TLS connections
// demuxed from the shared TCP listener.
type muxRealityListener struct {
	transport *MuxTransport
	once      sync.Once
	doneCh    chan struct{}
}

// Accept blocks until a Reality TLS connection is available or the
// transport is shut down.
func (l *muxRealityListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.transport.realityCh:
		return conn, nil
	case <-l.doneCh:
		return nil, net.ErrClosed
	}
}

// Close stops accepting Reality connections. It does not close the
// underlying MuxTransport.
func (l *muxRealityListener) Close() error {
	l.once.Do(func() {
		close(l.doneCh)
	})
	return nil
}

// Addr returns the address of the shared TCP listener.
func (l *muxRealityListener) Addr() net.Addr {
	if l.transport.tcpListener != nil {
		return l.transport.tcpListener.Addr()
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal: TCP accept loop with protocol demux
// ──────────────────────────────────────────────────────────────────────────────

// tcpAcceptLoop accepts incoming TCP connections, peeks the first byte,
// and routes the connection to either the gossip StreamCh or the Reality
// listener based on the byte value.
func (t *MuxTransport) tcpAcceptLoop() {
	defer t.wg.Done()

	const baseDelay = 5 * time.Millisecond
	const maxDelay = 1 * time.Second
	var loopDelay time.Duration

	for {
		conn, err := t.tcpListener.Accept()
		if err != nil {
			if t.shutdown.Load() == 1 {
				return
			}
			if loopDelay == 0 {
				loopDelay = baseDelay
			} else {
				loopDelay *= 2
			}
			if loopDelay > maxDelay {
				loopDelay = maxDelay
			}
			t.logger.Printf("[ERR] mux: TCP accept error: %v", err)
			time.Sleep(loopDelay)
			continue
		}
		loopDelay = 0

		// Bound concurrent connection handling: an attacker opening
		// connections faster than they're drained would otherwise
		// spawn unbounded goroutines (each holds a conn up to the
		// 10s peek deadline). When saturated, refuse immediately.
		select {
		case t.connSem <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-t.connSem }()
				t.handleMuxConn(c)
			}(conn)
		default:
			conn.Close()
		}
	}
}

// meshInternalMarker is the first byte sent by a mesh-internal connection
// (mesh-internal dial → key exchange → smux). It must not collide with
// TLS ClientHello (0x16) or memberlist message types (0–13, 244).
// 0x4D = 'M' for Mesh.
const meshInternalMarker = 0x4D

// maxConcurrentMuxConns caps how many TCP connections the mux accept
// path handles simultaneously (slowloris guard). Each conn may be held
// up to the 10s peek deadline before routing.
const maxConcurrentMuxConns = 256

// MeshListener returns a net.Listener that accepts mesh-internal connections
// demuxed from the shared TCP listener. These are connections from other
// meshdesk nodes that want to establish a smux session directly (without
// Reality TLS). The caller (MeshNode) performs the key exchange + smux
// handshake on each accepted connection.
func (t *MuxTransport) MeshListener() net.Listener {
	return &muxMeshListener{
		transport: t,
		doneCh:    make(chan struct{}),
	}
}

// muxMeshListener implements net.Listener for mesh-internal connections.
type muxMeshListener struct {
	transport *MuxTransport
	once      sync.Once
	doneCh    chan struct{}
}

func (l *muxMeshListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.transport.meshCh:
		return conn, nil
	case <-l.doneCh:
		return nil, net.ErrClosed
	}
}

func (l *muxMeshListener) Close() error {
	l.once.Do(func() { close(l.doneCh) })
	return nil
}

func (l *muxMeshListener) Addr() net.Addr {
	if l.transport.tcpListener != nil {
		return l.transport.tcpListener.Addr()
	}
	return nil
}

// handleMuxConn peeks the first byte of the connection and routes it
// to the appropriate channel.
func (t *MuxTransport) handleMuxConn(conn net.Conn) {
	// Peek the first byte with a short deadline to avoid hanging on
	// slow or malicious clients that connect but never send data.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read the first byte directly (not via bufio) so we can decide
	// the routing without buffering side effects. For memberlist gossip
	// streams, we wrap with bufferedConn (bufio.Reader-based) to be
	// compatible with memberlist v0.6.0's RemoveLabelHeaderFromStream.
	// For mesh-internal connections, we use connWithPrefix (simple
	// prefix replay) since mesh key exchange does not go through
	// memberlist's bufio wrapping.
	peekBuf := make([]byte, 1)
	n, err := io.ReadFull(conn, peekBuf)
	conn.SetReadDeadline(time.Time{}) // reset deadline

	if err != nil {
		if n == 0 {
			conn.Close()
			return
		}
		conn.Close()
		return
	}
	firstByte := peekBuf[0]

	if firstByte == tlsHandshakeRecordType {
		// TLS ClientHello → Reality path.
		// Use bufferedConn so the peeked byte is replayed correctly
		// when the Reality TLS listener reads from this connection.
		wrapped := &bufferedConn{Reader: bufio.NewReader(conn), conn: conn}
		// Prepend the peeked byte so the Reality listener sees it.
		wrapped.Reader = bufio.NewReader(io.MultiReader(bytes.NewReader(peekBuf), conn))
		select {
		case t.realityCh <- wrapped:
		case <-t.shutdownDone():
			wrapped.Close()
		default:
			// Reality accept queue full — apply backpressure.
			t.logger.Printf("[WARN] mux: reality accept queue full, dropping connection from %s", conn.RemoteAddr())
			wrapped.Close()
		}
	} else if firstByte == meshInternalMarker {
		// Mesh-internal connection → mesh key exchange + smux path.
		// Use connWithPrefix to replay the marker byte — mesh key
		// exchange does NOT go through memberlist's RemoveLabelHeaderFromStream,
		// so there is no double-buffering issue.
		// However, the mesh key exchange expects the connection WITHOUT
		// the 0x4D marker (it was already consumed by the peek above).
		// So we use the raw conn (no prefix replay).
		select {
		case t.meshCh <- conn:
		case <-t.shutdownDone():
			conn.Close()
		default:
			t.logger.Printf("[WARN] mux: mesh accept queue full, dropping connection from %s", conn.RemoteAddr())
			conn.Close()
		}
	} else if firstByte == 'G' || firstByte == 'P' || firstByte == 'H' {
		// HTTP request (GET/POST/HEAD) → Reality path (camouflage).
		//
		// The Dashboard is NO LONGER served on the mesh port (removed
		// in the reality-discipline refactor): intercepting HTTP here
		// made shared nodes fingerprintable — a DPI active probe
		// sending GET / received the mesh Dashboard instead of the
		// camouflage site, defeating REALITY's active-probe
		// resistance. HTTP bytes are now routed to the Reality
		// listener exactly like any other non-authenticated traffic:
		// the REALITY handshake fails auth and forwards the
		// connection to the camouflage destination (RealityDest), so
		// the probe sees the real website's response.
		wrapped := &bufferedConn{Reader: bufio.NewReader(io.MultiReader(bytes.NewReader(peekBuf), conn)), conn: conn}
		select {
		case t.realityCh <- wrapped:
		case <-t.shutdownDone():
			wrapped.Close()
		default:
			// Reality accept queue full — apply backpressure.
			t.logger.Printf("[WARN] mux: reality accept queue full, dropping connection from %s", conn.RemoteAddr())
			wrapped.Close()
		}
	} else {
		// Memberlist gossip stream.
		// Use bufferedConn (bufio.Reader-based) for compatibility with
		// memberlist v0.6.0's RemoveLabelHeaderFromStream.
		wrapped := &bufferedConn{Reader: bufio.NewReader(io.MultiReader(bytes.NewReader(peekBuf), conn)), conn: conn}
		select {
		case t.streamCh <- wrapped:
		case <-t.shutdownDone():
			wrapped.Close()
		default:
			t.logger.Printf("[WARN] mux: mesh accept queue full, dropping connection from %s", conn.RemoteAddr())
			wrapped.Close()
		}
	}
}

// shutdownDone returns a channel that is closed when the transport shuts down.
// Used to avoid blocking on channel sends during shutdown.
func (t *MuxTransport) shutdownDone() <-chan struct{} {
	// Eagerly created in NewMuxTransport — never nil, no lock needed.
	// (The old lazy init raced: readers like punchSocketPoller and
	// Shutdown read the field without the lock and could observe a
	// nil channel, silently losing the shutdown signal and leaking
	// the goroutine.)
	return t.shutdownCh
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal: UDP listen loop
// ──────────────────────────────────────────────────────────────────────────────

// udpListenLoop reads UDP packets and delivers them to the packet channel.
func (t *MuxTransport) udpListenLoop() {
	defer t.wg.Done()

	// Kept-alive punch sockets (registered after a punch) feed the
	// packet path too — polled in a background loop so they are picked
	// up whenever AddPunchSocket registers one.
	go t.punchSocketPoller()

	// One reader goroutine per UDP socket (IPv4 + IPv6), all feeding
	// the same packetChIn channel (or the mesh manager for 0x4D).
	var readers sync.WaitGroup
	seen := make(map[*net.UDPConn]bool)
	for _, conn := range t.udpConns {
		seen[conn] = true
		conn := conn
		readers.Add(1)
		go func() {
			defer readers.Done()
			buf := make([]byte, muxUDPPacketBufSize)
			for {
				n, addr, err := conn.ReadFrom(buf)
				if err != nil {
					if t.shutdown.Load() == 1 {
						return
					}
					t.logger.Printf("[ERR] mux: UDP read error: %v", err)
					continue
				}
				if n < 1 {
					t.logger.Printf("[WARN] mux: UDP packet too short (%d bytes) from %s", n, addr)
					continue
				}
				// Copy out of the shared read buffer: the same buf is
				// reused for the next ReadFrom, and packets queued on
				// packetChIn must not alias it (memberlist's consumer
				// may read them after the buffer was overwritten —
				// corrupted gossip packets under load).
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				// Hole-punch probe echo REMOVED: echoing every 0x50 0x4A
				// datagram caused an infinite ping-pong — A's probe is
				// echoed by B, A's listener echoes B's echo, B echoes
				// again, ad infinitum (~400fps of 6B frames, observed
				// on txcloud↔Oracle). Keepalive probes are one-way:
				// each side sends its own to refresh the conntrack
				// mapping, no reply needed. The punchUDP handshake's
				// echo-confirmation is handled inside punchUDP (its
				// own ReadFrom), not by this listener.
				if n >= 6 && pkt[0] == 0x50 && pkt[1] == 0x4A {
					continue
				}
				// Observation probe (0x50 0x4C): reply from an
				// EPHEMERAL socket so the peer observes our true
				// outbound source port — its conntrack-matched
				// data-plane target (EasyTier's trick: stateful
				// security groups pass ESTABLISHED, and the
				// restricted link carries large datagrams to these
				// ports without loss).
				if n >= 6 && pkt[0] == 0x50 && pkt[1] == 0x4C {
					if ua, ok := addr.(*net.UDPAddr); ok {
						t.observedSourceMu.Lock()
						t.observedSource = ua
						t.observedSourceMu.Unlock()
					}
					if econn, derr := net.DialUDP("udp", nil, addr.(*net.UDPAddr)); derr == nil {
						econn.Write(pkt)
						econn.Close()
					}
					continue
				}
				// Route mesh-marked datagrams to the ARQ stream manager.
				if udpAddr, ok := addr.(*net.UDPAddr); ok && t.udpMesh != nil {
					if t.udpMesh.routeUDPPacket(conn, udpAddr, pkt, t.meshCh) {
						continue
					}
				}
				// Not a mesh-internal packet — drop (memberlist retired).
			}
		}()
	}
	readers.Wait()
}

// punchSocketPoller periodically picks up newly registered punch
// sockets and starts a reader goroutine for each (their datagrams are
// data-plane frames — routed into the UDP mesh manager). It also
// keeps the punch sockets ALIVE: a stateful firewall (e.g. Oracle
// Cloud security list / iptables ESTABLISHED-only) drops the peer's
// data-plane frames once the conntrack entry expires (~30s of UDP
// idle). Periodic 6B probes from the punch socket refresh the NAT
// mapping so the hole stays open — EasyTier keeps its tunnel socket
// busy for exactly this reason.
func (t *MuxTransport) punchSocketPoller() {
	seen := make(map[*net.UDPConn]bool)
	keepalive := time.NewTicker(punchKeepaliveInterval)
	defer keepalive.Stop()
	for {
		t.punchMu.Lock()
		var fresh []*net.UDPConn
		live := make(map[*net.UDPConn]bool, len(t.punchSockets))
		for _, c := range t.punchSockets {
			live[c] = true
			if !seen[c] {
				seen[c] = true
				fresh = append(fresh, c)
			}
		}
		// Purge dead conns from seen: ones that are no longer in
		// punchSockets were replaced/closed — their reader goroutines
		// have exited (Bug 2 fix), so stop tracking them.
		for c := range seen {
			if !live[c] {
				delete(seen, c)
			}
		}
		t.punchMu.Unlock()
		for _, c := range fresh {
			c := c
			go func() {
				buf := make([]byte, muxUDPPacketBufSize)
				errCount := 0
				for {
					n, addr, err := c.ReadFrom(buf)
					if err != nil {
						if t.shutdown.Load() == 1 {
							return
						}
						errCount++
						// After repeated errors the socket is
						// likely closed (replaced or GC'd):
						// stop the goroutine instead of spinning.
						if errCount > 3 {
							return
						}
						time.Sleep(100 * time.Millisecond)
						continue
					}
					errCount = 0 // reset on successful read
					if n < 1 {
						continue
					}
					if debugEnabled {
						log.Printf("[punchpoller] read %dB from %s on %s", n, addr, c.LocalAddr())
					}
					// Copy — the buffer is reused.
					pkt := make([]byte, n)
					copy(pkt, buf[:n])
					// Hole-punch probe echo REMOVED (mirrors
					// udpListenLoop): echoing 0x50 0x4A caused an
					// infinite 6B ping-pong storm between the two
					// peers' listeners (~400fps). Keepalive probes
					// are one-way conntrack refreshers.
					if n >= 6 && pkt[0] == 0x50 && pkt[1] == 0x4A {
						continue
					}
					// Punch-socket datagrams are data-plane frames:
					// route them into the UDP mesh manager directly.
					if ua, ok := addr.(*net.UDPAddr); ok && t.udpMesh != nil {
						t.udpMesh.routeUDPPacket(c, ua, pkt, t.meshCh)
					}
				}
			}()
		}
		select {
		case <-keepalive.C:
			// Refresh the conntrack/NAT mapping of every punch
			// socket: a 6B probe (0x50 0x4A) to the peer keeps the
			// stateful firewall's ESTABLISHED entry alive so the
			// data plane's frames keep flowing (EasyTier's tunnel
			// socket stays busy for the same reason). Keepalive
			// probes are one-way conntrack refreshers — the peer's
			// punchSocketPoller receives and discards them (does
			// NOT echo back; echoing caused an infinite ping-pong
			// storm in v1.6.x).
			//
			// Punch sockets are UNCONNECTED (ListenUDP) — use
			// WriteToUDP with the peer address, which we recover
			// from the endpoint-form registration key ("ip:port").
			// Keys that are pure peer keys (hex) or IP-only resolve
			// without a port and are skipped here; every punch
			// socket is also registered under its endpoint key.
			t.punchMu.Lock()
			peers := make(map[*net.UDPConn]*net.UDPAddr)
			for k, c := range t.punchSockets {
				if ua, err := net.ResolveUDPAddr("udp", k); err == nil && ua.Port > 0 {
					peers[c] = ua
				}
			}
			for c, peer := range peers {
				probe := make([]byte, 6)
				probe[0], probe[1] = 0x50, 0x4A
				binary.BigEndian.PutUint32(probe[2:], uint32(time.Now().UnixNano()))
				c.WriteToUDP(probe, peer) // best-effort; errors ignored
			}
			t.punchMu.Unlock()
		case <-time.After(2 * time.Second):
		case <-t.shutdownDone():
			return
		}
	}
}

// setMuxUDPRecvBuf attempts to set the UDP receive buffer to a large size.
func setMuxUDPRecvBuf(c *net.UDPConn) error {
	size := muxUDPRecvBufSize
	var err error
	for size > 0 {
		if err = c.SetReadBuffer(size); err == nil {
			return nil
		}
		size = size / 2
	}
	return err
}

// tcpPortFromListener extracts the port from a TCP listener's address.
func tcpPortFromListener(ln net.Listener) int {
	addr := ln.Addr()
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.Port
	}
	// Best-effort parse for non-TCP listeners.
	_, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	return port
}
