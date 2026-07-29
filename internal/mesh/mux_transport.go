package mesh

import (
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

// peekByteCount is the number of bytes to peek from each incoming TCP connection
// to determine whether it is a TLS/Reality connection or a memberlist gossip
// stream. One byte is sufficient: TLS starts with 0x16, while memberlist
// messageType values are 0–14 or 244 (hasLabelMsg) — none equals 22.
const peekByteCount = 1

// muxUDPPacketBufSize is the receive buffer size for UDP packet reads.
const muxUDPPacketBufSize = 65536

// muxUDPRecvBufSize is the target SO_RCVBUF for UDP sockets.
const muxUDPRecvBufSize = 2 * 1024 * 1024

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
	udpConn     *net.UDPConn // separate UDP for memberlist packets
	logger      *log.Logger

	streamCh   chan net.Conn           // gossip streams → memberlist
	realityCh  chan net.Conn           // Reality TLS connections → reality listener
	packetChIn chan *memberlist.Packet // UDP packets → memberlist

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
	if cfg.TCPListener == nil {
		return nil, fmt.Errorf("mux: TCPListener is required")
	}

	bindAddr := cfg.BindAddr
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(log.Writer(), "[mux-transport] ", log.LstdFlags)
	}

	// Determine the UDP port: use UDPPort if set, otherwise mirror the
	// TCP listener's port.
	tcpPort := tcpPortFromListener(cfg.TCPListener)
	udpPort := cfg.UDPPort
	if udpPort == 0 {
		udpPort = tcpPort
	}

	// Create the UDP listener.
	udpAddr := &net.UDPAddr{IP: net.ParseIP(bindAddr), Port: udpPort}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("mux: failed to listen UDP on %s:%d: %w", bindAddr, udpPort, err)
	}
	if err := setMuxUDPRecvBuf(udpConn); err != nil {
		logger.Printf("[WARN] mux: failed to resize UDP recv buffer: %v (continuing)", err)
	}

	t := &MuxTransport{
		tcpListener:   cfg.TCPListener,
		udpConn:       udpConn,
		logger:        logger,
		streamCh:      make(chan net.Conn),
		realityCh:     make(chan net.Conn, 64),
		packetChIn:    make(chan *memberlist.Packet),
		bindAddr:      bindAddr,
		advertiseAddr: cfg.AdvertiseAddr,
		advertisePort: cfg.AdvertisePort,
	}

	if t.advertisePort == 0 {
		t.advertisePort = tcpPort
	}

	// Start the accept and UDP listen loops.
	t.wg.Add(2)
	go t.tcpAcceptLoop()
	go t.udpListenLoop()

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
func (t *MuxTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return time.Time{}, fmt.Errorf("mux: resolve UDP addr %q: %w", addr, err)
	}
	_, err = t.udpConn.WriteTo(b, udpAddr)
	return time.Now(), err
}

// PacketCh returns the channel for receiving incoming UDP packets.
func (t *MuxTransport) PacketCh() <-chan *memberlist.Packet {
	return t.packetChIn
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
	t.shutdownMu.Lock()
	if t.shutdownCh == nil {
		t.shutdownCh = make(chan struct{})
	}
	close(t.shutdownCh)
	t.shutdownMu.Unlock()

	_ = t.tcpListener.Close()
	_ = t.udpConn.Close()

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
	return l.transport.tcpListener.Addr()
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

		// Handle the connection in a goroutine to avoid blocking the
		// accept loop on slow clients.
		go t.handleMuxConn(conn)
	}
}

// handleMuxConn peeks the first byte of the connection and routes it
// to the appropriate channel.
func (t *MuxTransport) handleMuxConn(conn net.Conn) {
	// Peek the first byte with a short deadline to avoid hanging on
	// slow or malicious clients that connect but never send data.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	peekBuf := make([]byte, peekByteCount)
	n, err := io.ReadFull(conn, peekBuf)
	conn.SetReadDeadline(time.Time{}) // reset deadline

	if err != nil {
		if n == 0 {
			// Nothing peeked — close the connection.
			conn.Close()
			return
		}
		// Got partial data before error. If we got at least 1 byte,
		// we can still make a routing decision.
		if n < peekByteCount {
			conn.Close()
			return
		}
	}

	// Wrap the connection so the peeked byte is replayed.
	wrapped := NewConnWithPrefix(conn, peekBuf[:n])

	if peekBuf[0] == tlsHandshakeRecordType {
		// TLS ClientHello → Reality path.
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
		select {
		case t.streamCh <- wrapped:
		case <-t.shutdownDone():
			wrapped.Close()
		}
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
func (t *MuxTransport) udpListenLoop() {
	defer t.wg.Done()

	for {
		buf := make([]byte, muxUDPPacketBufSize)
		n, addr, err := t.udpConn.ReadFrom(buf)
		ts := time.Now()
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
		t.packetChIn <- &memberlist.Packet{
			Buf:       buf[:n],
			From:      addr,
			Timestamp: ts,
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
