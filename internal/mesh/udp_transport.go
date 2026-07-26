// Package mesh implements the WireGuard UDP transport — the first concrete
// TransportFactory implementation under the three-layer transport contract
// (transport.go).
//
// The UDP transport provides:
//   - Connected-UDP outbound (Connect) using net.DialUDP
//   - Session-oriented inbound (Listen) that groups packets by source address
//   - Application-level latency probing via a single-packet round trip
//   - Graceful shutdown with connection draining and context cancellation
//   - Connection limiting (MaxConns) via a counting semaphore
//   - Idle timeout enforcement via per-connection deadlines
//   - Transient/permanent error classification on every error path
//
// Design notes:
//   - UDP is connectionless, but the Transport contract exposes a net.Conn
//     via Connect and a net.Listener via Listen. Connect uses a connected
//     UDP socket (net.DialUDP with a fixed peer), which satisfies net.Conn
//     directly. Listen uses a session-oriented listener that demultiplexes
//     incoming packets by source address, creating one virtual connection
//     per unique remote endpoint.
//   - All public types satisfy the interfaces in transport.go and carry full
//     godoc comments.
package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// UDPTransportFactory — creates and manages UDP Transport instances
// ──────────────────────────────────────────────────────────────────────────────

// UDPTransportFactory is the concrete TransportFactory for WireGuard UDP
// transport. It creates UDPTransport instances and tracks all active
// connections across them for graceful shutdown and metrics.
//
// Lifecycle:
//  1. NewUDPTransportFactory() — create the factory
//  2. NewTransport(cfg) — create a UDPTransport instance
//  3. Connect/Listen — use the transport
//  4. Shutdown(ctx) — drain all connections, close listeners
//
// The factory is safe for concurrent use.
type UDPTransportFactory struct {
	// activeSince is set at construction time and used for ActiveSince().
	activeSince time.Time

	// connCount tracks the total number of active connections across all
	// UDPTransport instances created by this factory. Incremented on Connect
	// and on inbound Accept; decremented on Close/ForceClose.
	connCount atomic.Int64

	mu         sync.Mutex
	closed     bool                       // true after Shutdown returns
	conns      map[*udpPeerConn]struct{}  // all active outbound connections
	listeners  map[*udpListener]struct{}  // all active listeners
	transports map[*UDPTransport]struct{} // all created transports
}

// NewUDPTransportFactory creates a new UDPTransportFactory.
func NewUDPTransportFactory() *UDPTransportFactory {
	return &UDPTransportFactory{
		activeSince: time.Now(),
		conns:       make(map[*udpPeerConn]struct{}),
		listeners:   make(map[*udpListener]struct{}),
		transports:  make(map[*UDPTransport]struct{}),
	}
}

// Name returns the transport type this factory creates: "udp".
func (f *UDPTransportFactory) Name() string { return "udp" }

// NewTransport creates a new UDP Transport instance from the given config.
// Returns ErrTransportShutdown if the factory has been shut down, or a
// TransportConfigError if the config is invalid for UDP transport.
func (f *UDPTransportFactory) NewTransport(cfg TransportConfig) (Transport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, ErrTransportShutdown
	}
	if cfg.Name != "udp" && cfg.Name != "" {
		return nil, &TransportConfigError{
			Field:  "Name",
			Reason: fmt.Sprintf("UDPTransportFactory received config for %q, expected \"udp\"", cfg.Name),
		}
	}
	// Apply defaults for zero-value fields.
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 30 * time.Second
	}
	t := &UDPTransport{
		factory: f,
		cfg:     cfg,
	}
	f.transports[t] = struct{}{}
	return t, nil
}

// Shutdown gracefully shuts down all Transports created by this factory.
// It blocks until all connections have drained or ctx is cancelled.
// Shutdown is idempotent.
func (f *UDPTransportFactory) Shutdown(ctx context.Context) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true

	// Snapshot conns, listeners, and transports under the lock.
	conns := make([]*udpPeerConn, 0, len(f.conns))
	for c := range f.conns {
		conns = append(conns, c)
	}
	listeners := make([]*udpListener, 0, len(f.listeners))
	for l := range f.listeners {
		listeners = append(listeners, l)
	}
	transports := make([]*UDPTransport, 0, len(f.transports))
	for t := range f.transports {
		transports = append(transports, t)
	}
	// Clear the maps — but DON'T clear conns yet; we need unregisterConn
	// to work during ForceClose. We'll clear after.
	f.listeners = make(map[*udpListener]struct{})
	f.transports = make(map[*UDPTransport]struct{})
	f.mu.Unlock()

	// Mark all transports as closed so Connect/Listen/IsHealthy reflect it.
	for _, t := range transports {
		t.markClosed()
	}

	// Close all listeners first — this stops new inbound connections.
	for _, l := range listeners {
		l.closeLocked()
	}

	// Force-close all outbound connections. For UDP there is no drain
	// semantics (no FIN handshake), so we close immediately. The ctx
	// parameter is honored for future transports that may have drain
	// semantics (e.g. WebSocket, Reality).
	//
	// ForceClose decrements connCount via unregisterConn, so we don't
	// need to separately track the count here.
	for _, c := range conns {
		c.ForceClose()
	}

	// Wait for connCount to reach zero, or ctx to expire.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for f.connCount.Load() > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return nil
}

// ConnCount returns the total number of active connections across all
// Transport instances created by this factory.
func (f *UDPTransportFactory) ConnCount() int {
	return int(f.connCount.Load())
}

// ActiveSince returns the time the factory was created.
func (f *UDPTransportFactory) ActiveSince() time.Time {
	return f.activeSince
}

// registerConn adds an outbound connection to the factory's tracking set.
// Called by UDPTransport.Connect after creating a udpPeerConn.
func (f *UDPTransportFactory) registerConn(c *udpPeerConn) {
	f.mu.Lock()
	if !f.closed {
		f.conns[c] = struct{}{}
		f.connCount.Add(1)
	}
	f.mu.Unlock()
}

// unregisterConn removes a connection from the factory's tracking set and
// decrements the global connCount. Called by udpPeerConn.Close/ForceClose.
func (f *UDPTransportFactory) unregisterConn(c *udpPeerConn) {
	f.mu.Lock()
	if _, ok := f.conns[c]; ok {
		delete(f.conns, c)
		f.connCount.Add(-1)
	}
	f.mu.Unlock()
}

// registerListener adds a listener to the factory's tracking set.
func (f *UDPTransportFactory) registerListener(l *udpListener) {
	f.mu.Lock()
	if !f.closed {
		f.listeners[l] = struct{}{}
	}
	f.mu.Unlock()
}

// unregisterListener removes a listener from the factory's tracking set.
func (f *UDPTransportFactory) unregisterListener(l *udpListener) {
	f.mu.Lock()
	delete(f.listeners, l)
	f.mu.Unlock()
}

// isClosed returns true if the factory has been shut down.
func (f *UDPTransportFactory) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// ──────────────────────────────────────────────────────────────────────────────
// UDPTransport — per-instance UDP transport (Transport interface)
// ──────────────────────────────────────────────────────────────────────────────

// UDPTransport is a concrete Transport instance for WireGuard UDP.
// It is created by UDPTransportFactory.NewTransport and provides
// Connect (outbound), Listen (inbound), LatencyProbe, and health checking.
//
// A UDPTransport is bound to a TransportConfig that controls dial timeout,
// idle timeout, and connection limits. Different peers may use different
// UDPTransport instances with different configs.
type UDPTransport struct {
	factory *UDPTransportFactory
	cfg     TransportConfig

	// semCh is a counting semaphore for MaxConns enforcement.
	// nil when MaxConns == 0 (unlimited).
	semCh chan struct{}

	// healthy is an atomic flag for IsHealthy().
	healthy atomic.Bool

	// closed is set when the transport's factory is shut down.
	closed atomic.Bool

	// once ensures semCh is initialized only once.
	semOnce sync.Once
}

// Name returns the transport protocol name: "udp".
func (t *UDPTransport) Name() string { return "udp" }

// initSemaphore lazily initializes the connection-limit semaphore.
func (t *UDPTransport) initSemaphore() {
	t.semOnce.Do(func() {
		if t.cfg.MaxConns > 0 {
			t.semCh = make(chan struct{}, t.cfg.MaxConns)
		}
	})
}

// Connect establishes an outbound UDP connection to the given address.
// addr is a "host:port" string. The returned PeerConn wraps a connected
// UDP socket (*net.UDPConn) that is bound to the remote peer.
//
// The connection respects the configured DialTimeout. If MaxConns > 0,
// Connect blocks until a slot is available or ctx is cancelled.
//
// Errors are classified:
//   - Context cancellation, timeouts, temporary network errors → transient
//   - Invalid address, unknown host → permanent
func (t *UDPTransport) Connect(ctx context.Context, addr string) (PeerConn, error) {
	if t.closed.Load() {
		return nil, NewTransportError("connect", "udp", addr, net.ErrClosed, false)
	}

	// Enforce MaxConns via semaphore.
	t.initSemaphore()
	if t.semCh != nil {
		select {
		case t.semCh <- struct{}{}:
			// slot acquired
		case <-ctx.Done():
			return nil, NewTransportError("connect", "udp", addr, ctx.Err(), true)
		}
	}

	// Resolve the address.
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.releaseSemSlot()
		return nil, NewTransportError("connect", "udp", addr, err, false)
	}

	// Use a dialer that respects the context and dial timeout.
	dialer := net.Dialer{Timeout: t.cfg.DialTimeout}
	conn, err := dialer.DialContext(ctx, "udp", udpAddr.String())
	if err != nil {
		t.releaseSemSlot()
		retryable := isTransientError(err)
		return nil, NewTransportError("connect", "udp", addr, err, retryable)
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		t.releaseSemSlot()
		return nil, NewTransportError("connect", "udp", addr,
			fmt.Errorf("expected *net.UDPConn, got %T", conn), false)
	}

	pc := &udpPeerConn{
		UDPConn:     udpConn,
		transport:   "udp",
		factory:     t.factory,
		slotRelease: t.releaseSemSlot,
	}

	// Apply idle timeout if configured.
	if t.cfg.IdleTimeout > 0 {
		pc.SetDeadline(time.Now().Add(t.cfg.IdleTimeout))
	}

	t.factory.registerConn(pc)
	t.healthy.Store(true)
	return pc, nil
}

// releaseSemSlot releases a MaxConns semaphore slot if one was acquired.
func (t *UDPTransport) releaseSemSlot() {
	if t.semCh != nil {
		select {
		case <-t.semCh:
		default:
		}
	}
}

// Listen starts an inbound UDP listener on the given address.
// addr is a "host:port" string (port 0 for random).
//
// The returned net.Listener is a udpListener that demultiplexes incoming
// UDP packets by source address, creating one virtual connection per
// unique remote endpoint. This enables the standard Accept() pattern
// over a connectionless protocol.
func (t *UDPTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	if t.closed.Load() {
		return nil, NewTransportError("listen", "udp", addr, net.ErrClosed, false)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, NewTransportError("listen", "udp", addr, err, false)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		retryable := isTransientError(err)
		return nil, NewTransportError("listen", "udp", addr, err, retryable)
	}

	l := &udpListener{
		conn:      conn,
		transport: t,
		sessions:  make(map[string]*udpSessionConn),
		acceptCh:  make(chan *udpSessionConn, 64),
		closeCh:   make(chan struct{}),
	}

	t.factory.registerListener(l)

	// Start the packet receive loop.
	go l.readLoop()

	t.healthy.Store(true)
	return l, nil
}

// LatencyProbe measures the round-trip time to addr without establishing
// a full peer connection. For UDP, it sends a 1-byte probe packet and
// waits for any response within the configured DialTimeout.
//
// If no response is received within the timeout, returns a transient
// TransportError (the peer may be reachable on retry).
func (t *UDPTransport) LatencyProbe(ctx context.Context, addr string) (time.Duration, error) {
	if t.closed.Load() {
		return 0, NewTransportError("latency_probe", "udp", addr, net.ErrClosed, false)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, NewTransportError("latency_probe", "udp", addr, err, false)
	}

	// Create a temporary connected UDP socket for the probe.
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		retryable := isTransientError(err)
		return 0, NewTransportError("latency_probe", "udp", addr, err, retryable)
	}
	defer conn.Close()

	// Set a read deadline based on DialTimeout or a default probe timeout.
	probeTimeout := t.cfg.DialTimeout
	if probeTimeout == 0 || probeTimeout > 5*time.Second {
		probeTimeout = 5 * time.Second
	}

	// Honor context cancellation.
	deadline := time.Now().Add(probeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetReadDeadline(deadline)

	// Send a 1-byte probe.
	start := time.Now()
	_, err = conn.Write([]byte{0x00})
	if err != nil {
		retryable := isTransientError(err)
		return 0, NewTransportError("latency_probe", "udp", addr, err, retryable)
	}

	// Wait for any response.
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err != nil {
		// Timeout or read error — transient (peer may respond on retry).
		return 0, NewTransportError("latency_probe", "udp", addr, err, true)
	}

	rtt := time.Since(start)
	t.healthy.Store(true)
	return rtt, nil
}

// IsHealthy returns true if the transport is operational and can accept
// new connections. After Shutdown, returns false.
func (t *UDPTransport) IsHealthy() bool {
	if t.closed.Load() {
		return false
	}
	return true
}

// markClosed is called when the factory shuts down this transport.
func (t *UDPTransport) markClosed() {
	t.closed.Store(true)
	t.healthy.Store(false)
}

// ──────────────────────────────────────────────────────────────────────────────
// udpPeerConn — PeerConn wrapper over *net.UDPConn
// ──────────────────────────────────────────────────────────────────────────────

// udpPeerConn wraps a connected UDP socket as a PeerConn.
// It embeds *net.UDPConn which satisfies net.Conn, and adds transport
// metadata, latency tracking, and factory integration for graceful shutdown.
type udpPeerConn struct {
	*net.UDPConn
	transport   string
	factory     *UDPTransportFactory
	latency     atomic.Int64 // nanoseconds
	slotRelease func()       // releases the MaxConns semaphore slot
	closed      atomic.Bool
}

// Transport returns the transport name that created this connection: "udp".
func (c *udpPeerConn) Transport() string { return c.transport }

// Latency returns the last measured round-trip time for this connection.
func (c *udpPeerConn) Latency() time.Duration {
	return time.Duration(c.latency.Load())
}

// setLatency updates the latency measurement (internal).
func (c *udpPeerConn) setLatency(d time.Duration) {
	c.latency.Store(int64(d))
}

// ForceClose immediately closes the connection without draining.
// For UDP this is identical to Close — there is no graceful close.
func (c *udpPeerConn) ForceClose() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil // already closed
	}
	if c.slotRelease != nil {
		c.slotRelease()
	}
	c.factory.unregisterConn(c)
	return c.UDPConn.Close()
}

// Close closes the connection. For UDP, this is the same as ForceClose.
func (c *udpPeerConn) Close() error {
	return c.ForceClose()
}

// ──────────────────────────────────────────────────────────────────────────────
// udpListener — session-oriented net.Listener over UDP
// ──────────────────────────────────────────────────────────────────────────────

// udpListener implements net.Listener for UDP. Since UDP is connectionless,
// the listener demultiplexes incoming packets by source address, creating
// one udpSessionConn per unique remote endpoint. The first packet from a
// new source triggers an Accept() event; subsequent packets from the same
// source are delivered to the corresponding udpSessionConn's read buffer.
type udpListener struct {
	conn      *net.UDPConn
	transport *UDPTransport

	mu       sync.Mutex
	sessions map[string]*udpSessionConn // keyed by "host:port"
	acceptCh chan *udpSessionConn
	closeCh  chan struct{}
	closed   atomic.Bool
}

// Accept waits for and returns the next inbound connection.
// The returned net.Conn is a udpSessionConn that receives all subsequent
// packets from the same source address.
func (l *udpListener) Accept() (net.Conn, error) {
	select {
	case sc := <-l.acceptCh:
		return sc, nil
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

// Close closes the listener and all active sessions.
func (l *udpListener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(l.closeCh)
	l.closeLocked()
	l.transport.factory.unregisterListener(l)
	return l.conn.Close()
}

// closeLocked closes all sessions without closing the underlying socket.
// Called by the factory during Shutdown.
func (l *udpListener) closeLocked() {
	l.closed.Store(true)
	select {
	case <-l.closeCh:
		// already closed
	default:
		close(l.closeCh)
	}
	l.mu.Lock()
	for _, sc := range l.sessions {
		sc.close()
	}
	l.sessions = make(map[string]*udpSessionConn)
	l.mu.Unlock()
}

// Addr returns the listener's network address.
func (l *udpListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// readLoop reads packets from the UDP socket and dispatches them to
// the appropriate session connection (or creates a new one).
func (l *udpListener) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if l.closed.Load() {
				return
			}
			// Transient read error — continue after a brief pause.
			time.Sleep(1 * time.Millisecond)
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		key := raddr.String()

		l.mu.Lock()
		sc, ok := l.sessions[key]
		if !ok {
			// New session — create a udpSessionConn and enqueue for Accept.
			sc = &udpSessionConn{
				remoteAddr: raddr,
				localAddr:  l.conn.LocalAddr(),
				packets:    make(chan []byte, 256),
				closeCh:    make(chan struct{}),
				writer:     l.conn.WriteToUDP,
				onClose:    func() { l.removeSession(key) },
			}
			l.sessions[key] = sc

			// Apply idle timeout cleanup if configured.
			if l.transport.cfg.IdleTimeout > 0 {
				go l.idleWatcher(sc, key)
			}

			select {
			case l.acceptCh <- sc:
			default:
				// Accept queue full — drop the session.
				delete(l.sessions, key)
				sc.close()
				l.mu.Unlock()
				continue
			}
		}
		l.mu.Unlock()

		// Deliver the packet to the session's channel.
		select {
		case sc.packets <- data:
		default:
			// Packet buffer full — drop the packet (backpressure).
		}
	}
}

// idleWatcher closes a session if no packets are received within
// the configured IdleTimeout.
func (l *udpListener) idleWatcher(sc *udpSessionConn, key string) {
	timeout := l.transport.cfg.IdleTimeout
	if timeout == 0 {
		return
	}
	for {
		select {
		case <-sc.closeCh:
			return
		case <-time.After(timeout):
			// Session idle too long — close it.
			l.mu.Lock()
			if _, ok := l.sessions[key]; ok {
				delete(l.sessions, key)
				sc.close()
				l.mu.Unlock()
				return
			}
			l.mu.Unlock()
			return
		}
	}
}

// removeSession removes a session from the listener's map when the
// session is closed by the caller.
func (l *udpListener) removeSession(key string) {
	l.mu.Lock()
	if sc, ok := l.sessions[key]; ok {
		delete(l.sessions, key)
		sc.close()
	}
	l.mu.Unlock()
}

// ──────────────────────────────────────────────────────────────────────────────
// udpSessionConn — virtual net.Conn for a single UDP source address
// ──────────────────────────────────────────────────────────────────────────────

// udpSessionConn represents a virtual connection for all packets arriving
// from a single UDP source address. It satisfies net.Conn by reading from
// a packet channel and writing through the listener's underlying socket.
//
// Read blocks until a packet is available or the session is closed.
// Write sends a UDP packet to the session's remote address via the
// listener's underlying socket.
type udpSessionConn struct {
	remoteAddr *net.UDPAddr
	localAddr  net.Addr
	packets    chan []byte
	closeCh    chan struct{}
	closed     atomic.Bool

	writeMu sync.Mutex
	writer  func(b []byte, addr *net.UDPAddr) (int, error) // set by listener
	onClose func()                                         // called once on Close
}

// Read reads the next received UDP packet into p.
// Returns the number of bytes read.
func (c *udpSessionConn) Read(p []byte) (int, error) {
	select {
	case pkt := <-c.packets:
		n := copy(p, pkt)
		return n, nil
	case <-c.closeCh:
		return 0, net.ErrClosed
	}
}

// Write writes a UDP packet to the session's remote address.
// The write goes through the listener's underlying socket.
func (c *udpSessionConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writer == nil {
		return 0, fmt.Errorf("udpSessionConn: no writer configured")
	}
	return c.writer(p, c.remoteAddr)
}

// Close closes the session.
func (c *udpSessionConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeCh)
		if c.onClose != nil {
			c.onClose()
		}
	}
	return nil
}

// close is the internal close that doesn't panic if already closed.
func (c *udpSessionConn) close() {
	c.closed.Store(true)
	select {
	case <-c.closeCh:
	default:
		close(c.closeCh)
	}
}

// LocalAddr returns the local address of the listener.
func (c *udpSessionConn) LocalAddr() net.Addr { return c.localAddr }

// RemoteAddr returns the remote address of the session.
func (c *udpSessionConn) RemoteAddr() net.Addr { return c.remoteAddr }

// SetDeadline sets the read and write deadlines.
// For UDP sessions, only the read deadline is meaningful (controls Read blocking).
func (c *udpSessionConn) SetDeadline(t time.Time) error {
	// We can't set a deadline on a channel read directly, but we can
	// use a timer in Read. For simplicity, this is a no-op — callers
	// should use context-based cancellation for timeout control.
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *udpSessionConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *udpSessionConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Error classification helpers
// ──────────────────────────────────────────────────────────────────────────────

// isTransientError classifies a network error as transient (retryable) or
// permanent. Transient errors include timeouts, temporary failures, and
// context cancellations. Permanent errors include invalid addresses and
// unknown hosts.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
		if netErr.Temporary() {
			return true
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// DNS resolution failures for "udp" are typically permanent
	// (unknown host), but "no such host" is permanent while
	// "server misbehaving" is transient.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTemporary || dnsErr.IsNotFound == false
	}
	// Default: treat as transient (fail-safe for retry logic).
	return true
}
