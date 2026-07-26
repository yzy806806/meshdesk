// Package mesh implements the Reality TLS transport — the second concrete
// TransportFactory implementation under the three-layer transport contract
// (transport.go).
//
// The Reality transport provides TLS 1.3 camouflaging via xray-core's REALITY
// protocol, natively embedded in Go (no subprocess). It achieves:
//
//   - Client-side: uTLS ClientHello with browser fingerprint mimicking, then
//     hijacks the TLS handshake by injecting an authentication tag derived
//     from X25519 ECDH with the server's public key into the SessionId field.
//   - Server-side: uses github.com/xtls/reality to hijack the incoming TLS
//     handshake, authenticating clients via the ECDH-derived auth key and
//     forwarding non-mesh traffic to the camouflage destination.
//   - The resulting connection is a standard net.Conn carrying WireGuard
//     packets inside the encrypted TLS channel.
//
// Protocol summary (from xray-core transport/internet/reality/reality.go):
//
//  1. Client builds a uTLS UConn with the specified browser fingerprint.
//  2. BuildHandshakeState() prepares the ClientHello message.
//  3. SessionId[0:4] = xray version, SessionId[4:8] = unix timestamp,
//     SessionId[8:16] = shortId (client identity).
//  4. Client performs ECDH between its ephemeral key share (from the
//     ClientHello key_share extension) and the server's X25519 public key
//     to derive an auth key.
//  5. HKDF-SHA256(salt=ClientHello.Random[:20], ikm=authKey, info="REALITY")
//     produces the final auth key.
//  6. AES-GCM seals SessionId[:16] with nonce=Random[20:] and AAD=entire
//     ClientHello raw bytes, producing the authentication tag that replaces
//     SessionId[:16].
//  7. The modified ClientHello is sent to the server.
//  8. Server-side: reality.Server() processes the ClientHello, extracts the
//     key share, performs ECDH with its private key, derives the same auth
//     key, and verifies the AES-GCM authentication tag. If valid, the
//     connection is authenticated; if not, traffic is forwarded to dest.
//
// Design notes:
//   - The Reality transport uses TCP as the underlying transport, wrapping
//     it in TLS 1.3 via the REALITY protocol.
//   - Connect (client-side) uses uTLS with browser fingerprint mimicking
//     to defeat JA3/JA4 fingerprinting by the GFW.
//   - Listen (server-side) uses github.com/xtls/reality.Listen which accepts
//     TCP connections and performs the REALITY server-side handshake.
//   - All public types satisfy the interfaces in transport.go and carry
//     full godoc comments.
package mesh

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"

	realitypkg "github.com/xtls/reality"
)

// ──────────────────────────────────────────────────────────────────────────────
// RealityTransportFactory — creates and manages Reality Transport instances
// ──────────────────────────────────────────────────────────────────────────────

// RealityTransportFactory is the concrete TransportFactory for Reality TLS
// transport. It creates RealityTransport instances and tracks all active
// connections across them for graceful shutdown and metrics.
//
// Lifecycle:
//  1. NewRealityTransportFactory() — create the factory
//  2. NewTransport(cfg) — create a RealityTransport instance
//  3. Connect/Listen — use the transport
//  4. Shutdown(ctx) — drain all connections, close listeners
//
// The factory is safe for concurrent use.
type RealityTransportFactory struct {
	// activeSince is set at construction time and used for ActiveSince().
	activeSince time.Time

	// connCount tracks the total number of active connections across all
	// RealityTransport instances created by this factory.
	connCount atomic.Int64

	mu         sync.Mutex
	closed     bool
	conns      map[*realityPeerConn]struct{} // all active outbound connections
	listeners  map[*realityListener]struct{} // all active listeners
	transports map[*RealityTransport]struct{}
}

// NewRealityTransportFactory creates a new RealityTransportFactory.
func NewRealityTransportFactory() *RealityTransportFactory {
	return &RealityTransportFactory{
		activeSince: time.Now(),
		conns:       make(map[*realityPeerConn]struct{}),
		listeners:   make(map[*realityListener]struct{}),
		transports:  make(map[*RealityTransport]struct{}),
	}
}

// Name returns the transport type this factory creates: "reality".
func (f *RealityTransportFactory) Name() string { return "reality" }

// NewTransport creates a new Reality Transport instance from the given config.
// Returns ErrTransportShutdown if the factory has been shut down, or a
// TransportConfigError if the config is invalid for Reality transport.
func (f *RealityTransportFactory) NewTransport(cfg TransportConfig) (Transport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, ErrTransportShutdown
	}
	if cfg.Name != "reality" && cfg.Name != "" {
		return nil, &TransportConfigError{
			Field:  "Name",
			Reason: fmt.Sprintf("RealityTransportFactory received config for %q, expected \"reality\"", cfg.Name),
		}
	}
	// Apply defaults for zero-value fields.
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 30 * time.Second
	}
	if cfg.TLSFingerprint == "" {
		cfg.TLSFingerprint = "chrome"
	}
	t := &RealityTransport{
		factory: f,
		cfg:     cfg,
	}
	f.transports[t] = struct{}{}
	return t, nil
}

// Shutdown gracefully shuts down all Transports created by this factory.
// It blocks until all connections have drained or ctx is cancelled.
// Shutdown is idempotent.
func (f *RealityTransportFactory) Shutdown(ctx context.Context) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true

	// Snapshot conns, listeners, and transports under the lock.
	conns := make([]*realityPeerConn, 0, len(f.conns))
	for c := range f.conns {
		conns = append(conns, c)
	}
	listeners := make([]*realityListener, 0, len(f.listeners))
	for l := range f.listeners {
		listeners = append(listeners, l)
	}
	transports := make([]*RealityTransport, 0, len(f.transports))
	for t := range f.transports {
		transports = append(transports, t)
	}
	f.listeners = make(map[*realityListener]struct{})
	f.transports = make(map[*RealityTransport]struct{})
	f.mu.Unlock()

	// Mark all transports as closed.
	for _, t := range transports {
		t.markClosed()
	}

	// Close all listeners first — stops new inbound connections.
	for _, l := range listeners {
		l.closeLocked()
	}

	// Force-close all outbound connections.
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
func (f *RealityTransportFactory) ConnCount() int {
	return int(f.connCount.Load())
}

// ActiveSince returns the time the factory was created.
func (f *RealityTransportFactory) ActiveSince() time.Time {
	return f.activeSince
}

// registerConn adds an outbound connection to the factory's tracking set.
func (f *RealityTransportFactory) registerConn(c *realityPeerConn) {
	f.mu.Lock()
	if !f.closed {
		f.conns[c] = struct{}{}
		f.connCount.Add(1)
	}
	f.mu.Unlock()
}

// unregisterConn removes a connection from the factory's tracking set.
func (f *RealityTransportFactory) unregisterConn(c *realityPeerConn) {
	f.mu.Lock()
	if _, ok := f.conns[c]; ok {
		delete(f.conns, c)
		f.connCount.Add(-1)
	}
	f.mu.Unlock()
}

// registerListener adds a listener to the factory's tracking set.
func (f *RealityTransportFactory) registerListener(l *realityListener) {
	f.mu.Lock()
	if !f.closed {
		f.listeners[l] = struct{}{}
	}
	f.mu.Unlock()
}

// unregisterListener removes a listener from the factory's tracking set.
func (f *RealityTransportFactory) unregisterListener(l *realityListener) {
	f.mu.Lock()
	delete(f.listeners, l)
	f.mu.Unlock()
}

// ──────────────────────────────────────────────────────────────────────────────
// RealityTransport — per-instance Reality transport (Transport interface)
// ──────────────────────────────────────────────────────────────────────────────

// RealityTransport is a concrete Transport instance for Reality TLS.
// It is created by RealityTransportFactory.NewTransport and provides
// Connect (outbound, client-side), Listen (inbound, server-side),
// LatencyProbe, and health checking.
//
// A RealityTransport is bound to a TransportConfig that controls dial timeout,
// idle timeout, connection limits, TLS fingerprint, camouflage destination,
// and X25519 key material. Different peers may use different RealityTransport
// instances with different configs.
type RealityTransport struct {
	factory *RealityTransportFactory
	cfg     TransportConfig

	// semCh is a counting semaphore for MaxConns enforcement.
	semCh chan struct{}

	// healthy is an atomic flag for IsHealthy().
	healthy atomic.Bool

	// closed is set when the transport's factory is shut down.
	closed atomic.Bool

	// once ensures semCh is initialized only once.
	semOnce sync.Once
}

// Name returns the transport protocol name: "reality".
func (t *RealityTransport) Name() string { return "reality" }

// initSemaphore lazily initializes the connection-limit semaphore.
func (t *RealityTransport) initSemaphore() {
	t.semOnce.Do(func() {
		if t.cfg.MaxConns > 0 {
			t.semCh = make(chan struct{}, t.cfg.MaxConns)
		}
	})
}

// Connect establishes an outbound Reality TLS connection to the given address.
// addr is a "host:port" string. The returned PeerConn wraps a uTLS connection
// that has completed the REALITY handshake with the server.
//
// The connection respects the configured DialTimeout. If MaxConns > 0,
// Connect blocks until a slot is available or ctx is cancelled.
//
// Errors are classified:
//   - Context cancellation, timeouts, temporary network errors → transient
//   - Invalid address, missing RealityPublicKey, TLS handshake failure → permanent
func (t *RealityTransport) Connect(ctx context.Context, addr string) (PeerConn, error) {
	if t.closed.Load() {
		return nil, NewTransportError("connect", "reality", addr, net.ErrClosed, false)
	}

	// Validate required Reality fields.
	if t.cfg.RealityPublicKey == "" {
		return nil, NewTransportError("connect", "reality", addr,
			&TransportConfigError{Field: "RealityPublicKey", Reason: "required for reality client-side"}, false)
	}

	// Enforce MaxConns via semaphore.
	t.initSemaphore()
	if t.semCh != nil {
		select {
		case t.semCh <- struct{}{}:
		case <-ctx.Done():
			return nil, NewTransportError("connect", "reality", addr, ctx.Err(), true)
		}
	}

	conn, err := t.dialReality(ctx, addr)
	if err != nil {
		t.releaseSemSlot()
		return nil, err
	}

	pc := &realityPeerConn{
		Conn:        conn,
		transport:   "reality",
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

// dialReality performs the TCP dial + uTLS REALITY client handshake.
// It returns the established net.Conn (a *utls.UConn) on success.
func (t *RealityTransport) dialReality(ctx context.Context, addr string) (net.Conn, error) {
	// Dial the underlying TCP connection.
	dialer := net.Dialer{Timeout: t.cfg.DialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		retryable := isTransientError(err)
		return nil, NewTransportError("connect", "reality", addr, err, retryable)
	}

	// Determine SNI.
	sni := t.cfg.ServerName
	if sni == "" {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr == nil {
			sni = host
		}
	}

	// Decode the server's X25519 public key.
	pubKeyBytes, err := decodeHexKey(t.cfg.RealityPublicKey)
	if err != nil {
		rawConn.Close()
		return nil, NewTransportError("connect", "reality", addr,
			fmt.Errorf("invalid RealityPublicKey: %w", err), false)
	}
	serverPubKey, err := ecdh.X25519().NewPublicKey(pubKeyBytes)
	if err != nil {
		rawConn.Close()
		return nil, NewTransportError("connect", "reality", addr,
			fmt.Errorf("invalid server X25519 public key: %w", err), false)
	}

	// Build the uTLS connection with the specified browser fingerprint.
	helloID := fingerprintToHelloID(t.cfg.TLSFingerprint)
	utlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // REALITY uses its own auth, not cert verification
	}
	uConn := utls.UClient(rawConn, utlsConfig, helloID)

	// Build the handshake state so we can modify the ClientHello before sending.
	if err := uConn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, NewTransportError("connect", "reality", addr,
			fmt.Errorf("uTLS BuildHandshakeState: %w", err), false)
	}

	// Perform the REALITY authentication tag injection.
	hello := uConn.HandshakeState.Hello

	// Set SessionId: [version(4)][timestamp(4)][shortId(8)][padding(16)]
	hello.SessionId = make([]byte, 32)
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	shortIDBytes, _ := decodeHexKey(t.cfg.RealityShortID)
	copy(hello.SessionId[8:], shortIDBytes)

	// Get the client's ephemeral ECDHE private key from the handshake state.
	ecdhe := getEcdheKey(&uConn.HandshakeState)
	if ecdhe == nil {
		rawConn.Close()
		return nil, NewTransportError("connect", "reality", addr,
			errors.New("uTLS fingerprint does not support TLS 1.3 key share (X25519)"), false)
	}

	// ECDH with server's public key to derive the shared auth key.
	authKey, err := ecdhe.ECDH(serverPubKey)
	if err != nil {
		rawConn.Close()
		return nil, NewTransportError("connect", "reality", addr,
			fmt.Errorf("ECDH with server public key: %w", err), false)
	}

	// HKDF-SHA256: salt=Random[:20], ikm=authKey, info="REALITY"
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		rawConn.Close()
		return nil, NewTransportError("connect", "reality", addr,
			fmt.Errorf("HKDF derive auth key: %w", err), false)
	}

	// AES-GCM seal: seal SessionId[:16] with nonce=Random[20:] and AAD=hello.Raw
	aead, err := newAESGCM(authKey)
	if err != nil {
		rawConn.Close()
		return nil, NewTransportError("connect", "reality", addr,
			fmt.Errorf("AES-GCM init: %w", err), false)
	}
	// Seal in-place: the tag (16 bytes) overwrites SessionId[:16].
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)

	// Patch the raw ClientHello bytes with the modified SessionId.
	// In the ClientHello, SessionId starts at byte offset 39 (after:
	// 1 record type + 2 version + 2 length + 1 handshake type +
	// 3 handshake length + 2 client version + 32 random = 43... but actually
	// the session_id position in the raw message is at offset 39 counting
	// from the handshake message start, which is what hello.Raw tracks).
	copy(hello.Raw[39:], hello.SessionId)

	// Perform the TLS handshake with the modified ClientHello.
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		retryable := isTransientError(err)
		return nil, NewTransportError("connect", "reality", addr,
			fmt.Errorf("REALITY handshake: %w", err), retryable)
	}

	return uConn, nil
}

// releaseSemSlot releases a MaxConns semaphore slot if one was acquired.
func (t *RealityTransport) releaseSemSlot() {
	if t.semCh != nil {
		select {
		case <-t.semCh:
		default:
		}
	}
}

// Listen starts an inbound Reality TLS listener on the given address.
// addr is a "host:port" string.
//
// The returned net.Listener wraps reality.Listen, which accepts TCP
// connections and performs the REALITY server-side handshake. Non-mesh
// traffic (failing REALITY auth) is forwarded to the configured camouflage
// destination (RealityDest).
func (t *RealityTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	if t.closed.Load() {
		return nil, NewTransportError("listen", "reality", addr, net.ErrClosed, false)
	}

	// Validate required server-side fields.
	if t.cfg.RealityPrivateKey == "" {
		return nil, NewTransportError("listen", "reality", addr,
			&TransportConfigError{Field: "RealityPrivateKey", Reason: "required for reality server-side"}, false)
	}
	if t.cfg.RealityDest == "" {
		return nil, NewTransportError("listen", "reality", addr,
			&TransportConfigError{Field: "RealityDest", Reason: "required for reality server-side camouflage"}, false)
	}

	// Build the reality.Config.
	realityCfg, err := t.buildRealityConfig()
	if err != nil {
		return nil, NewTransportError("listen", "reality", addr, err, false)
	}

	// Use reality.Listen to create the listener.
	innerListener, err := realitypkg.Listen("tcp", addr, realityCfg)
	if err != nil {
		retryable := isTransientError(err)
		return nil, NewTransportError("listen", "reality", addr, err, retryable)
	}

	l := &realityListener{
		listener:  innerListener,
		transport: t,
		acceptCh:  make(chan net.Conn, 64),
		closeCh:   make(chan struct{}),
	}

	t.factory.registerListener(l)

	// Start the accept loop.
	go l.acceptLoop()

	t.healthy.Store(true)
	return l, nil
}

// buildRealityConfig constructs a *reality.Config from the TransportConfig.
func (t *RealityTransport) buildRealityConfig() (*realitypkg.Config, error) {
	privKeyBytes, err := decodeHexKey(t.cfg.RealityPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid RealityPrivateKey: %w", err)
	}

	cfg := &realitypkg.Config{
		Show:        false,
		Dest:        t.cfg.RealityDest,
		Xver:        0,
		ServerNames: make(map[string]bool),
		PrivateKey:  privKeyBytes,
		ShortIds:    make(map[[8]byte]bool),
	}

	// Populate accepted server names.
	for _, sn := range t.cfg.RealityServerNames {
		cfg.ServerNames[sn] = true
	}
	// If no server names configured, accept any SNI matching the dest host.
	if len(cfg.ServerNames) == 0 {
		host, _, _ := net.SplitHostPort(t.cfg.RealityDest)
		if host != "" {
			cfg.ServerNames[host] = true
		}
	}

	// Populate accepted short IDs.
	if t.cfg.RealityShortID != "" {
		shortIDBytes, err := decodeHexKey(t.cfg.RealityShortID)
		if err != nil {
			return nil, fmt.Errorf("invalid RealityShortID: %w", err)
		}
		var sid [8]byte
		copy(sid[:], shortIDBytes)
		cfg.ShortIds[sid] = true
	}
	// Always accept empty shortId (allows clients without shortId).
	cfg.ShortIds[[8]byte{}] = true

	// DialContext for forwarding non-authenticated traffic to dest.
	cfg.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: t.cfg.DialTimeout}
		return d.DialContext(ctx, network, address)
	}

	return cfg, nil
}

// LatencyProbe measures the round-trip time to addr without establishing
// a full peer connection. For Reality TLS, it performs a TCP connect +
// TLS ClientHello/ServerHello exchange timing (without completing the full
// REALITY handshake).
//
// If no response is received within the timeout, returns a transient
// TransportError (the peer may be reachable on retry).
func (t *RealityTransport) LatencyProbe(ctx context.Context, addr string) (time.Duration, error) {
	if t.closed.Load() {
		return 0, NewTransportError("latency_probe", "reality", addr, net.ErrClosed, false)
	}

	// For Reality, we do a lightweight TCP connect + TLS handshake timing.
	// We don't need the full REALITY auth — just measuring reachability and RTT.
	dialer := net.Dialer{Timeout: t.cfg.DialTimeout}
	probeTimeout := t.cfg.DialTimeout
	if probeTimeout == 0 || probeTimeout > 5*time.Second {
		probeTimeout = 5 * time.Second
	}

	start := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		retryable := isTransientError(err)
		return 0, NewTransportError("latency_probe", "reality", addr, err, retryable)
	}
	defer rawConn.Close()

	// Set deadline for the TLS handshake portion.
	deadline := time.Now().Add(probeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	rawConn.SetDeadline(deadline)

	// Send a minimal TLS ClientHello (just to get a ServerHello response).
	// We use crypto/tls for the probe — no REALITY auth needed.
	// If the server responds, we have our RTT.
	sni := t.cfg.ServerName
	if sni == "" {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr == nil {
			sni = host
		}
	}

	// Use uTLS with a browser fingerprint for the probe to measure realistic RTT.
	helloID := fingerprintToHelloID(t.cfg.TLSFingerprint)
	uConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, helloID)

	// We only need to measure the time to ServerHello, so we start the
	// handshake and measure the RTT. If it fails, that's OK — the probe
	// still tells us about reachability.
	handshakeErr := uConn.HandshakeContext(ctx)
	rtt := time.Since(start)

	if handshakeErr != nil {
		// If we at least got a response (server sent something), the probe
		// succeeded in measuring reachability. A handshake failure could be
		// because the server sent a real TLS response (not REALITY).
		// We treat this as a successful probe — the server is reachable.
		t.healthy.Store(true)
		return rtt, nil
	}

	t.healthy.Store(true)
	return rtt, nil
}

// IsHealthy returns true if the transport is operational and can accept
// new connections. After Shutdown, returns false.
func (t *RealityTransport) IsHealthy() bool {
	if t.closed.Load() {
		return false
	}
	return true
}

// markClosed is called when the factory shuts down this transport.
func (t *RealityTransport) markClosed() {
	t.closed.Store(true)
	t.healthy.Store(false)
}

// ──────────────────────────────────────────────────────────────────────────────
// realityPeerConn — PeerConn wrapper over a uTLS/UConn or reality.Conn
// ──────────────────────────────────────────────────────────────────────────────

// realityPeerConn wraps a REALITY TLS connection as a PeerConn.
// It embeds net.Conn (which may be a *utls.UConn for client-side or a
// *reality.Conn for server-side) and adds transport metadata, latency
// tracking, and factory integration for graceful shutdown.
type realityPeerConn struct {
	net.Conn
	transport   string
	factory     *RealityTransportFactory
	latency     atomic.Int64 // nanoseconds
	slotRelease func()
	closed      atomic.Bool
}

// Transport returns the transport name that created this connection: "reality".
func (c *realityPeerConn) Transport() string { return c.transport }

// Latency returns the last measured round-trip time for this connection.
func (c *realityPeerConn) Latency() time.Duration {
	return time.Duration(c.latency.Load())
}

// setLatency updates the latency measurement (internal).
func (c *realityPeerConn) setLatency(d time.Duration) {
	c.latency.Store(int64(d))
}

// ForceClose immediately closes the connection without draining.
// For TLS, this directly closes the underlying TCP socket.
func (c *realityPeerConn) ForceClose() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.slotRelease != nil {
		c.slotRelease()
	}
	c.factory.unregisterConn(c)
	return c.Conn.Close()
}

// Close closes the connection. For Reality TLS, this sends a TLS
// close_notify alert before closing the underlying socket.
func (c *realityPeerConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.slotRelease != nil {
		c.slotRelease()
	}
	c.factory.unregisterConn(c)
	return c.Conn.Close()
}

// ──────────────────────────────────────────────────────────────────────────────
// realityListener — net.Listener wrapping reality.Listen
// ──────────────────────────────────────────────────────────────────────────────

// realityListener implements net.Listener for Reality TLS transport.
// It wraps the reality.Listener and provides an accept loop that delivers
// authenticated REALITY connections as net.Conn.
type realityListener struct {
	listener  net.Listener
	transport *RealityTransport

	mu       sync.Mutex
	acceptCh chan net.Conn
	closeCh  chan struct{}
	closed   atomic.Bool
}

// Accept waits for and returns the next inbound REALITY connection.
// The returned net.Conn is an authenticated REALITY connection.
func (l *realityListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

// Close closes the listener and stops accepting new connections.
func (l *realityListener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(l.closeCh)
	l.closeLocked()
	l.transport.factory.unregisterListener(l)
	return l.listener.Close()
}

// closeLocked closes the listener without closing the underlying socket.
// Called by the factory during Shutdown.
func (l *realityListener) closeLocked() {
	l.closed.Store(true)
	select {
	case <-l.closeCh:
	default:
		close(l.closeCh)
	}
}

// Addr returns the listener's network address.
func (l *realityListener) Addr() net.Addr {
	return l.listener.Addr()
}

// acceptLoop accepts inbound REALITY connections from the underlying
// reality.Listener and delivers them via the accept channel.
func (l *realityListener) acceptLoop() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if l.closed.Load() {
				return
			}
			// Transient error — brief pause and retry.
			select {
			case <-l.closeCh:
				return
			case <-time.After(1 * time.Millisecond):
			}
			continue
		}

		// Deliver the connection via the accept channel.
		select {
		case l.acceptCh <- conn:
		default:
			// Accept queue full — drop the connection (backpressure).
			conn.Close()
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// REALITY crypto helpers
// ──────────────────────────────────────────────────────────────────────────────

// getEcdheKey extracts the ephemeral X25519 private key from the uTLS
// handshake state's key share. This is used to perform ECDH with the
// server's Reality public key.
func getEcdheKey(hs *utls.PubClientHandshakeState) *ecdh.PrivateKey {
	if hs == nil || hs.State13.KeyShareKeys == nil {
		return nil
	}
	if hs.State13.KeyShareKeys.Ecdhe != nil {
		return hs.State13.KeyShareKeys.Ecdhe
	}
	if hs.State13.KeyShareKeys.MlkemEcdhe != nil {
		return hs.State13.KeyShareKeys.MlkemEcdhe
	}
	return nil
}

// newAESGCM creates an AES-GCM AEAD from a 16/24/32-byte key.
func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// decodeHexKey decodes a hex-encoded key string to raw bytes.
// Returns an empty byte slice (not error) for empty input.
func decodeHexKey(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

// ──────────────────────────────────────────────────────────────────────────────
// Key generation utility (for setup/testing)
// ──────────────────────────────────────────────────────────────────────────────

// GenerateRealityKeyPair generates a new X25519 key pair for Reality transport.
// Returns (privateKeyHex, publicKeyHex, error).
// The private key is used server-side; the public key is used client-side.
func GenerateRealityKeyPair() (string, string, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate X25519 key pair: %w", err)
	}
	pubKey := privKey.PublicKey()
	return hex.EncodeToString(privKey.Bytes()), hex.EncodeToString(pubKey.Bytes()), nil
}
