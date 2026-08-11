package mesh

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	sockaddr "github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/memberlist"
)

// ──────────────────────────────────────────────────────────────────────────────
// Protocol detection constants
// ──────────────────────────────────────────────────────────────────────────────

// tlsHandshakeRecordType is the TLS ContentType for handshake records (0x16 = 22).
// Every TLS connection begins with this byte in the first record header.
// See RFC 5246 §6.2.1: ContentType handshake = 22.
const tlsHandshakeRecordType = 0x16

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
	tcpListener net.Listener // shared TCP listener
	logger      *log.Logger

	streamCh  chan net.Conn // gossip streams → memberlist
	realityCh chan net.Conn // Reality TLS connections → reality listener
	httpCh    chan net.Conn // HTTP connections → Dashboard/join server
	// connSem bounds concurrent TCP connection handling (slowloris guard).
	connSem chan struct{}
	// realityDialer is injected by MeshNode: memberlist's DialTimeout
	// uses it to establish Reality-TLS-masked connections (Reality-only
	// architecture — no plaintext gossip dials).
	realityDialer func(addr string, timeout time.Duration) (net.Conn, error)

	shutdown   atomic.Int32
	shutdownMu sync.Mutex
	shutdownCh chan struct{} // lazily created, closed on shutdown
	wg         sync.WaitGroup

	bindAddr      string
	advertiseAddr string
	advertisePort int
}

// Compile-time assertion: MuxTransport satisfies memberlist.Transport.
var _ memberlist.Transport = (*MuxTransport)(nil)

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

	t := &MuxTransport{
		tcpListener:   cfg.TCPListener,
		logger:        logger,
		streamCh:      make(chan net.Conn, 64),
		realityCh:     make(chan net.Conn, 64),
		httpCh:        make(chan net.Conn, 64),
		connSem:       make(chan struct{}, maxConcurrentMuxConns),
		bindAddr:      bindAddr,
		advertiseAddr: cfg.AdvertiseAddr,
		advertisePort: cfg.AdvertisePort,
	}

	if t.advertisePort == 0 && t.tcpListener != nil {
		if addr, ok := t.tcpListener.Addr().(*net.TCPAddr); ok {
			t.advertisePort = addr.Port
		}
	}
	// Start the TCP accept loop only if we have a TCP listener.
	if t.tcpListener != nil {
		t.wg.Add(1)
		go t.tcpAcceptLoop()
	}

	return t, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// memberlist.Transport interface (6 methods)
// ──────────────────────────────────────────────────────────────────────────────

// FinalAdvertiseAddr returns the IP and port to advertise to the cluster.
// If the user supplied an explicit address, it is used. Otherwise, if
// bound to 0.0.0.0, a private IP is auto-detected via go-sockaddr.
//
// The advertised port is always the MuxTransport's own port (the shared
// TCP/UDP port), regardless of the port memberlist passes. This is correct
// because the MuxTransport knows its own listener port, which may differ
// from the GossipPort in the memberlist config when multiplexing.
func (t *MuxTransport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
	var advertiseAddr net.IP

	if ip != "" {
		advertiseAddr = net.ParseIP(ip)
		if advertiseAddr == nil {
			return nil, 0, fmt.Errorf("mux: failed to parse advertise address %q", ip)
		}
		if ip4 := advertiseAddr.To4(); ip4 != nil {
			advertiseAddr = ip4
		}
	} else if t.advertiseAddr != "" {
		// Use the transport's configured advertise address.
		advertiseAddr = net.ParseIP(t.advertiseAddr)
		if advertiseAddr == nil {
			return nil, 0, fmt.Errorf("mux: failed to parse configured advertise address %q", t.advertiseAddr)
		}
		if ip4 := advertiseAddr.To4(); ip4 != nil {
			advertiseAddr = ip4
		}
	} else {
		// No explicit advertise address — auto-detect.
		if t.bindAddr == "0.0.0.0" || t.bindAddr == "::" {
			privIP, err := sockaddr.GetPrivateIP()
			if err != nil {
				return nil, 0, fmt.Errorf("mux: failed to get private IP: %w", err)
			}
			if privIP == "" {
				return nil, 0, fmt.Errorf("mux: no private IP address found, and explicit IP not provided")
			}
			advertiseAddr = net.ParseIP(privIP)
			if advertiseAddr == nil {
				return nil, 0, fmt.Errorf("mux: failed to parse auto-detected address %q", privIP)
			}
		} else {
			advertiseAddr = net.ParseIP(t.bindAddr)
		}
	}

	// Always use our own advertise port (the shared TCP/UDP port).
	// The port from memberlist config is the GossipPort, which may differ
	// from the actual TCP listener port when multiplexing with Reality TLS.
	return advertiseAddr, t.advertisePort, nil
}

// WriteTo sends a UDP packet to the given address. The address is a
// "host:port" string. Returns the transmission timestamp as close to
// the actual send time as possible.
// WriteTo writes a packet to the given address. Reality-only: UDP is
// fully disabled, so this always fails (memberlist must use TCP
// streams via DialTimeout).
func (t *MuxTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	return time.Time{}, fmt.Errorf("mux: UDP disabled (Reality-only transport)")
}

// PacketCh returns the channel for receiving incoming UDP packets.
// Reality-only: UDP is disabled — returns nil so memberlist runs in
// TCP-stream mode (gossip rides inside Reality TLS).
func (t *MuxTransport) PacketCh() <-chan *memberlist.Packet {
	return nil
}

// DialTimeout creates an outbound connection to the given address with
// the specified timeout. This is used by memberlist for anti-entropy
// syncs and fallback probes.
//
// Reality-only: the dial goes through the injected Reality dialer so
// memberlist traffic is ALSO masked as Reality TLS — no plaintext
// memberlist connection ever leaves the node. Without an injected
// dialer (non-Reality setup) the dial fails: every connection must be
// Reality.
func (t *MuxTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	if t.realityDialer == nil {
		return nil, fmt.Errorf("mux: no Reality dialer injected (Reality-only transport)")
	}
	return t.realityDialer(addr, timeout)
}

// StreamCh returns the channel for receiving incoming memberlist gossip
// streams. Each conn delivered here has been demuxed: the peeked
// byte has been replayed via connWithPrefix so the stream is intact.
func (t *MuxTransport) StreamCh() <-chan net.Conn {
	return t.streamCh
}

// DeliverStream hands a connection to the memberlist gossip consumer.
// Used by MeshNode to route Reality-decrypted memberlist streams (the
// Reality-only architecture carries gossip inside Reality TLS).
func (t *MuxTransport) DeliverStream(conn net.Conn) {
	select {
	case t.streamCh <- conn:
	case <-t.shutdownDone():
		conn.Close()
	default:
		t.logger.Printf("[WARN] mux: gossip accept queue full, dropping connection from %s", conn.RemoteAddr())
		conn.Close()
	}
}

// SetRealityDialer injects the Reality dialer used by memberlist's
// DialTimeout (Reality-only transport: every outbound connection,
// including gossip, is Reality TLS).
func (t *MuxTransport) SetRealityDialer(fn func(addr string, timeout time.Duration) (net.Conn, error)) {
	t.realityDialer = fn
}

// Shutdown stops the transport, closing the TCP listener and UDP conn.
// It is idempotent and blocks until all goroutines have exited.
func (t *MuxTransport) Shutdown() error {
	if !t.shutdown.CompareAndSwap(0, 1) {
		return nil
	}

	// Signal the shutdown channel so blocked sends can unblock.
	t.shutdownMu.Lock()
	if t.shutdownCh == nil {
		t.shutdownCh = make(chan struct{})
	}
	close(t.shutdownCh)
	t.shutdownMu.Unlock()

	if t.tcpListener != nil {
		_ = t.tcpListener.Close()
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

// maxConcurrentMuxConns caps how many TCP connections the mux accept
// path handles simultaneously (slowloris guard). Each conn may be held
// up to the 10s peek deadline before routing.
const maxConcurrentMuxConns = 256

// HTTPListener returns a net.Listener that receives HTTP connections
// (GET/POST/HEAD) demuxed from the shared TCP port. Use this to serve
// Dashboard and join server HTTP on the same port as Reality/gossip.
func (t *MuxTransport) HTTPListener() net.Listener {
	return &muxHTTPListener{
		transport: t,
		doneCh:    make(chan struct{}),
	}
}

type muxHTTPListener struct {
	transport *MuxTransport
	once      sync.Once
	doneCh    chan struct{}
}

func (l *muxHTTPListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.transport.httpCh:
		return conn, nil
	case <-l.doneCh:
		return nil, net.ErrClosed
	}
}

func (l *muxHTTPListener) Close() error {
	l.once.Do(func() { close(l.doneCh) })
	return nil
}

func (l *muxHTTPListener) Addr() net.Addr {
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
	} else if firstByte == 0x4D {
		// 0x4D mesh-internal protocol is retired (Reality-only
		// architecture): every mesh connection must be Reality TLS.
		// Refuse rather than serve plaintext.
		conn.Close()
	} else if firstByte == 'G' || firstByte == 'P' || firstByte == 'H' {
		// HTTP request (GET/POST/HEAD) → Dashboard/join server.
		// HTTP methods start with 'G' (0x47), 'P' (0x50), or 'H' (0x48),
		// which never collide with memberlist message types (0-11, 244).
		wrapped := &bufferedConn{Reader: bufio.NewReader(io.MultiReader(bytes.NewReader(peekBuf), conn)), conn: conn}
		select {
		case t.httpCh <- wrapped:
		case <-t.shutdownDone():
			wrapped.Close()
		default:
			t.logger.Printf("[WARN] mux: HTTP accept queue full, dropping connection from %s", conn.RemoteAddr())
			wrapped.Close()
		}
	} else {
		// Unknown/plaintext protocol (e.g. raw memberlist gossip from an
		// old peer). Reality-only: every connection must be TLS — refuse
		// plaintext rather than serve it.
		conn.Close()
	}
}

// shutdownDone returns a channel that is closed when the transport shuts down.
// Used to avoid blocking on channel sends during shutdown.
func (t *MuxTransport) shutdownDone() <-chan struct{} {
	// We create a lazily-initialized channel for this.
	// In practice, the shutdown flag is checked atomically; the channel
	// is a secondary signal. Since memberlist.NetTransport doesn't use
	// a shutdown channel either (it relies on closing listeners), we
	// use a simple nil channel that never fires — the blocking send
	// will be unblocked by the listener close causing Accept errors,
	// which eventually drains the loop. However, to be safe, we provide
	// a proper channel.
	t.shutdownMu.Lock()
	defer t.shutdownMu.Unlock()
	if t.shutdownCh == nil {
		t.shutdownCh = make(chan struct{})
	}
	return t.shutdownCh
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal: UDP listen loop
// ──────────────────────────────────────────────────────────────────────────────

// udpListenLoop reads UDP packets and delivers them to the packet channel.

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
