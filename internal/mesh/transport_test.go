// Package mesh provides transport-layer contract tests using net.Pipe()
// for in-memory PeerConn assertions and Transport-level integration without
// real network I/O.
//
// These tests validate the contract in transport.go independently of any
// specific transport implementation. They use:
//   - net.Pipe() — synchronous, in-memory, byte-stream connections
//   - mockTransport/mockTransportFactory — minimal Transport implementations
//     that satisfy the interface contract for failover and registry testing
//
// The UDP-specific tests in udp_transport_test.go cover the concrete
// implementation. These tests validate the abstraction layer and ensure
// any future transport (WebSocket, Reality) can be tested against the
// same contract assertions.
package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// mockTransport — minimal Transport for in-memory testing via net.Pipe()
// ──────────────────────────────────────────────────────────────────────────────

// mockTransport implements Transport using net.Pipe() for Connect, producing
// PeerConn instances that communicate over in-memory byte streams. This is the
// recommended pattern for transport contract testing: a real Transport is not
// required for validating PeerConn assertions or failover logic.
type mockTransport struct {
	name     string
	healthy  bool
	latency  time.Duration
	pipeAddr net.Addr // reported as the remote address for connections
	mu       sync.Mutex
	closed   bool
}

// mockAddr implements net.Addr for in-memory pipe connections.
type mockAddr struct{ network, address string }

func (a mockAddr) Network() string { return a.network }
func (a mockAddr) String() string  { return a.address }

func newMockTransport(name string) *mockTransport {
	return &mockTransport{
		name:    name,
		healthy: true,
		latency: 1 * time.Millisecond,
		pipeAddr: mockAddr{
			network: "pipe",
			address: fmt.Sprintf("%s-pipe", name),
		},
	}
}

func (m *mockTransport) Name() string { return m.name }

func (m *mockTransport) Connect(ctx context.Context, addr string) (PeerConn, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, NewTransportError("connect", m.name, addr, net.ErrClosed, false)
	}
	m.mu.Unlock()

	// Verify context is not cancelled.
	select {
	case <-ctx.Done():
		return nil, NewTransportError("connect", m.name, addr, ctx.Err(), true)
	default:
	}

	// Use net.Pipe() to create an in-memory connection.
	client, _ := net.Pipe()
	pc := NewPeerConn(client, m.name)
	// Set a synthetic latency for testing Latency() assertions.
	if pc2, ok := pc.(*peerConn); ok {
		pc2.setLatency(m.latency)
	}
	return pc, nil
}

func (m *mockTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, NewTransportError("listen", m.name, addr, net.ErrClosed, false)
	}
	// Return a pipe listener: Accept returns a new pipe connection.
	return &mockListener{transport: m, addr: m.pipeAddr}, nil
}

func (m *mockTransport) LatencyProbe(ctx context.Context, addr string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, NewTransportError("latency_probe", m.name, addr, net.ErrClosed, false)
	}
	if !m.healthy {
		return 0, NewTransportError("latency_probe", m.name, addr,
			fmt.Errorf("transport unhealthy"), true)
	}
	return m.latency, nil
}

func (m *mockTransport) IsHealthy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthy && !m.closed
}

// SetHealthy controls the health status for failover testing.
func (m *mockTransport) SetHealthy(healthy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = healthy
}

// SetLatency controls the synthetic RTT returned by LatencyProbe.
func (m *mockTransport) SetLatency(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latency = d
}

// Close marks the transport as closed.
func (m *mockTransport) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
}

// ──────────────────────────────────────────────────────────────────────────────
// mockListener — minimal net.Listener backed by net.Pipe()
// ──────────────────────────────────────────────────────────────────────────────

type mockListener struct {
	transport *mockTransport
	addr      net.Addr
	mu        sync.Mutex
	closed    bool
}

func (l *mockListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	l.mu.Unlock()

	// Create a pipe pair: one side returned to Accept, the other discarded
	// (callers are expected to have already connected via mockTransport.Connect).
	server, _ := net.Pipe()
	return server, nil
}

func (l *mockListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return nil
}

func (l *mockListener) Addr() net.Addr { return l.addr }

// ──────────────────────────────────────────────────────────────────────────────
// mockTransportFactory — minimal TransportFactory for registry/failover tests
// ──────────────────────────────────────────────────────────────────────────────

type mockTransportFactory struct {
	name        string
	transport   *mockTransport
	activeSince time.Time
	shutdownMu  sync.Mutex
	shutdown    bool
	// NewTransportFn is an optional override for NewTransport behavior.
	NewTransportFn func(cfg TransportConfig) (Transport, error)
}

func newMockTransportFactory(name string) *mockTransportFactory {
	return &mockTransportFactory{
		name:        name,
		transport:   newMockTransport(name),
		activeSince: time.Now(),
	}
}

func (f *mockTransportFactory) Name() string { return f.name }

func (f *mockTransportFactory) NewTransport(cfg TransportConfig) (Transport, error) {
	f.shutdownMu.Lock()
	defer f.shutdownMu.Unlock()
	if f.shutdown {
		return nil, ErrTransportShutdown
	}
	if f.NewTransportFn != nil {
		return f.NewTransportFn(cfg)
	}
	return f.transport, nil
}

func (f *mockTransportFactory) Shutdown(ctx context.Context) error {
	f.shutdownMu.Lock()
	defer f.shutdownMu.Unlock()
	if f.shutdown {
		return nil
	}
	f.shutdown = true
	f.transport.Close()
	return nil
}

func (f *mockTransportFactory) ConnCount() int { return 0 }

func (f *mockTransportFactory) ActiveSince() time.Time { return f.activeSince }

// ──────────────────────────────────────────────────────────────────────────────
// PeerConn tests using net.Pipe()
// ──────────────────────────────────────────────────────────────────────────────

// TestPeerConnWrapsPipe verifies that NewPeerConn correctly wraps a
// net.Pipe() connection and exposes transport metadata.
func TestPeerConnWrapsPipe(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewPeerConn(client, "udp")
	if pc.Transport() != "udp" {
		t.Errorf("Transport() = %q, want %q", pc.Transport(), "udp")
	}
	if pc.Latency() != 0 {
		t.Errorf("Latency() = %v, want 0 (default)", pc.Latency())
	}
	// Verify it satisfies net.Conn — these must not panic.
	if pc.LocalAddr() == nil {
		t.Error("LocalAddr() is nil")
	}
	if pc.RemoteAddr() == nil {
		t.Error("RemoteAddr() is nil")
	}
}

// TestPeerConnPipeRoundTrip verifies that data flows correctly through a
// PeerConn wrapping a net.Pipe() — the canonical in-memory transport test.
func TestPeerConnPipeRoundTrip(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	pc := NewPeerConn(clientPipe, "udp")

	// Goroutine: server reads and echoes back.
	go func() {
		buf := make([]byte, 1024)
		n, err := serverPipe.Read(buf)
		if err != nil {
			return
		}
		serverPipe.Write(buf[:n])
	}()

	// Client writes.
	msg := []byte("hello-pipe-transport")
	if _, err := pc.Write(msg); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	// Client reads echo.
	buf := make([]byte, 1024)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Errorf("Read() = %q, want %q", string(buf[:n]), string(msg))
	}
}

// TestPeerConnPipeForceClose verifies that ForceClose closes the underlying
// net.Pipe() connection and subsequent operations fail.
func TestPeerConnPipeForceClose(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pc := NewPeerConn(client, "udp")

	if err := pc.ForceClose(); err != nil {
		t.Fatalf("ForceClose() error: %v", err)
	}

	// Read after ForceClose should fail.
	buf := make([]byte, 1)
	_, err := pc.Read(buf)
	if err == nil {
		t.Error("Read() after ForceClose should fail")
	}
}

// TestPeerConnPipeDoubleForceClose verifies that double ForceClose is safe.
func TestPeerConnPipeDoubleForceClose(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pc := NewPeerConn(client, "udp")

	if err := pc.ForceClose(); err != nil {
		t.Fatalf("first ForceClose() error: %v", err)
	}
	if err := pc.ForceClose(); err != nil {
		t.Errorf("second ForceClose() error: %v", err)
	}
}

// TestPeerConnPipeClose is distinct from ForceClose and should still work.
func TestPeerConnPipeClose(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pc := NewPeerConn(client, "udp")

	if err := pc.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// Read after Close should fail.
	buf := make([]byte, 1)
	_, err := pc.Read(buf)
	if err == nil {
		t.Error("Read() after Close should fail")
	}
}

// TestPeerConnPipeSetDeadline verifies that SetDeadline and friends work
// through the wrapped connection.
func TestPeerConnPipeSetDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewPeerConn(client, "udp")

	deadline := time.Now().Add(100 * time.Millisecond)
	if err := pc.SetDeadline(deadline); err != nil {
		t.Errorf("SetDeadline() error: %v", err)
	}
	if err := pc.SetReadDeadline(deadline); err != nil {
		t.Errorf("SetReadDeadline() error: %v", err)
	}
	if err := pc.SetWriteDeadline(deadline); err != nil {
		t.Errorf("SetWriteDeadline() error: %v", err)
	}

	// After the deadline, Read should fail with a timeout.
	time.Sleep(150 * time.Millisecond)
	buf := make([]byte, 1)
	_, err := pc.Read(buf)
	if err == nil {
		t.Error("Read() after deadline should fail")
	}
}

// TestPeerConnPipeLargeData verifies correct handling of data larger than
// a single pipe buffer (the kernel typically buffers 64KB).
func TestPeerConnPipeLargeData(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewPeerConn(client, "udp")

	// 128KB — larger than the typical pipe buffer.
	dataSize := 128 * 1024
	go func() {
		buf := make([]byte, dataSize)
		total := 0
		for total < dataSize {
			n, err := server.Read(buf[total:])
			if err != nil {
				return
			}
			total += n
		}
		server.Write(buf[:total])
	}()

	payload := make([]byte, dataSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	if _, err := pc.Write(payload); err != nil {
		t.Fatalf("Write() large data error: %v", err)
	}

	// Read back.
	resp := make([]byte, dataSize)
	total := 0
	for total < dataSize {
		n, err := pc.Read(resp[total:])
		if err != nil {
			t.Fatalf("Read() large data error at %d bytes: %v", total, err)
		}
		total += n
	}
	if total != dataSize {
		t.Errorf("Read() returned %d bytes, want %d", total, dataSize)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// PeerConn latency tests (via internal setLatency hook)
// ──────────────────────────────────────────────────────────────────────────────

// TestPeerConnLatencyDefault verifies that a new PeerConn has zero latency.
func TestPeerConnLatencyDefault(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewPeerConn(client, "udp")
	if pc.Latency() != 0 {
		t.Errorf("default Latency() = %v, want 0", pc.Latency())
	}
}

// TestPeerConnSetLatency verifies the internal setLatency hook updates
// the latency value returned by PeerConn.Latency().
func TestPeerConnSetLatency(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewPeerConn(client, "udp")

	// Access the internal peerConn to call setLatency.
	p, ok := pc.(*peerConn)
	if !ok {
		t.Fatalf("NewPeerConn did not return *peerConn, got %T", pc)
	}

	testLatency := 42 * time.Millisecond
	p.setLatency(testLatency)

	if got := pc.Latency(); got != testLatency {
		t.Errorf("Latency() = %v, want %v", got, testLatency)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// mockTransport tests — in-memory Transport contract validation
// ──────────────────────────────────────────────────────────────────────────────

// TestMockTransportConnectReturnsPipe verifies that mockTransport.Connect
// returns a PeerConn backed by a net.Pipe().
func TestMockTransportConnectReturnsPipe(t *testing.T) {
	mt := newMockTransport("test")
	ctx := context.Background()

	pc, err := mt.Connect(ctx, "pipe:dest")
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	defer pc.ForceClose()

	if pc.Transport() != "test" {
		t.Errorf("Transport() = %q, want %q", pc.Transport(), "test")
	}
	// Verify the latency was set by the mock.
	if pc.Latency() != 1*time.Millisecond {
		t.Errorf("Latency() = %v, want 1ms", pc.Latency())
	}
}

// TestMockTransportConnectAndListen verifies that mockTransport.Connect
// and mockTransport.Listen produce valid PeerConn and Listener respectively.
func TestMockTransportConnectAndListen(t *testing.T) {
	mt := newMockTransport("test")
	ctx := context.Background()

	// Connect returns a PeerConn backed by a net.Pipe().
	pc, err := mt.Connect(ctx, "pipe:dest")
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	defer pc.ForceClose()

	if pc.Transport() != "test" {
		t.Errorf("Transport() = %q, want %q", pc.Transport(), "test")
	}

	// Listen returns a mockListener with the transport's address.
	l, err := mt.Listen(ctx, "pipe:addr")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	defer l.Close()

	if l.Addr() == nil {
		t.Error("listener Addr() is nil")
	}
	if l.Addr().Network() != "pipe" {
		t.Errorf("listener Addr().Network() = %q, want %q", l.Addr().Network(), "pipe")
	}
}

// TestMockTransportConnectContextCancelled verifies that Connect honors
// context cancellation.

// TestMockTransportIsHealthy verifies that IsHealthy reflects the current state.
func TestMockTransportIsHealthy(t *testing.T) {
	mt := newMockTransport("test")
	if !mt.IsHealthy() {
		t.Error("IsHealthy() = false, want true for fresh transport")
	}

	mt.SetHealthy(false)
	if mt.IsHealthy() {
		t.Error("IsHealthy() = true after SetHealthy(false)")
	}

	mt.SetHealthy(true)
	if !mt.IsHealthy() {
		t.Error("IsHealthy() = false after SetHealthy(true)")
	}

	mt.Close()
	if mt.IsHealthy() {
		t.Error("IsHealthy() = true after Close()")
	}
}

// TestMockTransportLatencyProbe verifies that LatencyProbe returns the
// configured synthetic latency.
func TestMockTransportLatencyProbe(t *testing.T) {
	mt := newMockTransport("test")

	ctx := context.Background()
	rtt, err := mt.LatencyProbe(ctx, "pipe:addr")
	if err != nil {
		t.Fatalf("LatencyProbe() error: %v", err)
	}
	if rtt != 1*time.Millisecond {
		t.Errorf("LatencyProbe() = %v, want 1ms", rtt)
	}
}

// TestMockTransportLatencyProbeUnhealthy verifies that LatencyProbe returns
// an error when the transport is unhealthy.
func TestMockTransportLatencyProbeUnhealthy(t *testing.T) {
	mt := newMockTransport("test")
	mt.SetHealthy(false)

	ctx := context.Background()
	_, err := mt.LatencyProbe(ctx, "pipe:addr")
	if err == nil {
		t.Fatal("LatencyProbe() should fail when unhealthy")
	}

	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if !tErr.Retry {
		t.Error("error should be retryable when unhealthy")
	}
}

// TestMockTransportConnectAfterClose verifies that Connect returns an
// error after the transport is closed.
func TestMockTransportConnectAfterClose(t *testing.T) {
	mt := newMockTransport("test")
	mt.Close()

	ctx := context.Background()
	_, err := mt.Connect(ctx, "pipe:addr")
	if err == nil {
		t.Fatal("Connect() should fail after Close()")
	}
	if !errors.Is(err, net.ErrClosed) {
		var tErr *TransportError
		if !errors.As(err, &tErr) {
			t.Errorf("expected either net.ErrClosed or TransportError, got %T: %v", err, err)
		}
	}
}

// TestMockTransportConnectContextCancelled verifies that Connect honors
// context cancellation.
func TestMockTransportConnectContextCancelled(t *testing.T) {
	mt := newMockTransport("test")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := mt.Connect(ctx, "pipe:addr")
	if err == nil {
		t.Fatal("Connect() should fail with cancelled context")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportRegistry tests using mock factories
// ──────────────────────────────────────────────────────────────────────────────

// TestTransportRegistryRegisterAndGet verifies that registering a factory
// and retrieving it by name works.
func TestTransportRegistryRegisterAndGet(t *testing.T) {
	reg := NewTransportRegistry()
	f := newMockTransportFactory("udp")
	reg.Register(f)

	got, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got.Name() != "udp" {
		t.Errorf("Get() Name() = %q, want %q", got.Name(), "udp")
	}
}

// TestTransportRegistryGetNotFound verifies that Get returns an error
// for unregistered transports.
func TestTransportRegistryGetNotFound(t *testing.T) {
	reg := NewTransportRegistry()

	_, err := reg.Get("nonexistent")
	if err == nil {
		t.Fatal("Get() should fail for unregistered transport")
	}
	if !errors.Is(err, ErrTransportNotFound) {
		t.Errorf("expected ErrTransportNotFound, got %v", err)
	}
}

// TestTransportRegistryGetEmpty verifies that Get on an empty registry
// returns ErrTransportNotFound.
func TestTransportRegistryGetEmpty(t *testing.T) {
	reg := NewTransportRegistry()

	_, err := reg.Get("udp")
	if !errors.Is(err, ErrTransportNotFound) {
		t.Errorf("expected ErrTransportNotFound on empty registry, got %v", err)
	}
}

// TestTransportRegistryList verifies that List returns all registered names.
func TestTransportRegistryList(t *testing.T) {
	reg := NewTransportRegistry()
	reg.Register(newMockTransportFactory("udp"))
	reg.Register(newMockTransportFactory("websocket"))
	reg.Register(newMockTransportFactory("reality"))

	names := reg.List()
	if len(names) != 3 {
		t.Fatalf("List() length = %d, want 3", len(names))
	}

	seen := make(map[string]bool)
	for _, n := range names {
		seen[n] = true
	}
	for _, want := range []string{"udp", "websocket", "reality"} {
		if !seen[want] {
			t.Errorf("List() missing %q", want)
		}
	}
}

// TestTransportRegistryListEmpty verifies that List on an empty registry
// returns an empty slice.
func TestTransportRegistryListEmpty(t *testing.T) {
	reg := NewTransportRegistry()

	names := reg.List()
	if len(names) != 0 {
		t.Errorf("List() on empty registry = %v, want empty", names)
	}
}

// TestTransportRegistryRegisterReplace verifies that registering a factory
// with the same name replaces the previous one.
func TestTransportRegistryRegisterReplace(t *testing.T) {
	reg := NewTransportRegistry()
	f1 := newMockTransportFactory("udp")
	f2 := newMockTransportFactory("udp")

	reg.Register(f1)
	reg.Register(f2)

	got, _ := reg.Get("udp")
	if got != f2 {
		t.Error("Register should replace existing factory by name")
	}
}

// TestTransportRegistryShutdownAll verifies that ShutdownAll shuts down
// all registered factories.
func TestTransportRegistryShutdownAll(t *testing.T) {
	reg := NewTransportRegistry()
	f1 := newMockTransportFactory("transport-a")
	f2 := newMockTransportFactory("transport-b")
	reg.Register(f1)
	reg.Register(f2)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := reg.ShutdownAll(ctx); err != nil {
		t.Fatalf("ShutdownAll() error: %v", err)
	}

	// Verify both factories are shut down.
	_, err1 := f1.NewTransport(TransportConfig{Name: "transport-a"})
	if !errors.Is(err1, ErrTransportShutdown) {
		t.Errorf("f1 not shut down: %v", err1)
	}
	_, err2 := f2.NewTransport(TransportConfig{Name: "transport-b"})
	if !errors.Is(err2, ErrTransportShutdown) {
		t.Errorf("f2 not shut down: %v", err2)
	}
}

// TestTransportRegistryShutdownAllEmpty verifies that ShutdownAll on an
// empty registry returns nil.
func TestTransportRegistryShutdownAllEmpty(t *testing.T) {
	reg := NewTransportRegistry()

	ctx := context.Background()
	if err := reg.ShutdownAll(ctx); err != nil {
		t.Errorf("ShutdownAll on empty registry: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportConfig Validate tests
// ──────────────────────────────────────────────────────────────────────────────

// TestTransportConfigValidateUDP verifies that a "udp" config passes validation.
func TestTransportConfigValidateUDP(t *testing.T) {
	cfg := TransportConfig{Name: "udp"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() for udp: unexpected error: %v", err)
	}
}

// TestTransportConfigValidateEmptyName verifies that an empty Name fails validation.
func TestTransportConfigValidateEmptyName(t *testing.T) {
	cfg := TransportConfig{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() for empty name should fail")
	}
	var cfgErr *TransportConfigError
	if !errors.As(err, &cfgErr) {
		t.Errorf("expected TransportConfigError, got %T: %v", err, err)
	}
}

// TestTransportConfigValidateRealityMissingCerts verifies that a reality
// config with TLS but no certs fails validation.
func TestTransportConfigValidateRealityMissingCerts(t *testing.T) {
	cfg := TransportConfig{Name: "reality", UseTLS: true}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() for reality+TLS without certs should fail")
	}
}

// TestTransportConfigValidateWebSocketMissingCerts verifies that a websocket
// config with TLS but no certs fails validation.
func TestTransportConfigValidateWebSocketMissingCerts(t *testing.T) {
	cfg := TransportConfig{Name: "websocket", UseTLS: true}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() for websocket+TLS without certs should fail")
	}
}

// TestTransportConfigValidateRealityNoTLS verifies that a reality config
// without TLS passes (it uses its own TLS layer).
func TestTransportConfigValidateRealityNoTLS(t *testing.T) {
	cfg := TransportConfig{Name: "reality"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() for reality without TLS: unexpected error: %v", err)
	}
}

// TestDefaultTransportConfig verifies that DefaultTransportConfig returns
// sensible defaults.
func TestDefaultTransportConfig(t *testing.T) {
	cfg := DefaultTransportConfig()
	if cfg.Name != "udp" {
		t.Errorf("Name = %q, want %q", cfg.Name, "udp")
	}
	if cfg.DialTimeout != 30*time.Second {
		t.Errorf("DialTimeout = %v, want 30s", cfg.DialTimeout)
	}
	if cfg.TLSFingerprint != "chrome" {
		t.Errorf("TLSFingerprint = %q, want %q", cfg.TLSFingerprint, "chrome")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportError tests
// ──────────────────────────────────────────────────────────────────────────────

// TestTransportErrorIsRetryable verifies that TransportError correctly
// reports its retryable status.
func TestTransportErrorIsRetryable(t *testing.T) {
	// Retryable (transient).
	e := NewTransportError("connect", "udp", "addr", fmt.Errorf("timeout"), true)
	if !e.IsRetryable() {
		t.Error("IsRetryable() = false for transient error, want true")
	}

	// Non-retryable (permanent).
	e2 := NewTransportError("connect", "udp", "addr", fmt.Errorf("bad cert"), false)
	if e2.IsRetryable() {
		t.Error("IsRetryable() = true for permanent error, want false")
	}
}

// TestTransportErrorUnwrap verifies that TransportError.Uwrap() returns
// the underlying error for errors.Is / errors.As compatibility.
func TestTransportErrorUnwrap(t *testing.T) {
	underlying := fmt.Errorf("connection refused")
	e := NewTransportError("connect", "udp", "1.2.3.4:51820", underlying, true)

	if !errors.Is(e, underlying) {
		t.Error("errors.Is(e, underlying) = false, want true")
	}

	var tErr *TransportError
	if !errors.As(e, &tErr) {
		t.Error("errors.As(e, &tErr) = false, want true")
	}
	if tErr.Op != "connect" {
		t.Errorf("Op = %q, want %q", tErr.Op, "connect")
	}
	if tErr.Name != "udp" {
		t.Errorf("Name = %q, want %q", tErr.Name, "udp")
	}
	if tErr.Addr != "1.2.3.4:51820" {
		t.Errorf("Addr = %q, want %q", tErr.Addr, "1.2.3.4:51820")
	}
}

// TestTransportErrorFormat verifies that TransportError.Error() includes
// the operation, transport name, and address.
func TestTransportErrorFormat(t *testing.T) {
	e := NewTransportError("connect", "udp", "1.2.3.4:51820", fmt.Errorf("timeout"), true)
	s := e.Error()
	required := []string{"connect", "udp", "1.2.3.4:51820", "timeout"}
	for _, r := range required {
		if !containsStr(s, r) {
			t.Errorf("Error() = %q, must contain %q", s, r)
		}
	}
}

// TestTransportErrorNoAddr verifies that TransportError without an address
// still formats correctly.
func TestTransportErrorNoAddr(t *testing.T) {
	e := NewTransportError("listen", "websocket", "", fmt.Errorf("bind failed"), false)
	s := e.Error()
	if !containsStr(s, "listen") || !containsStr(s, "websocket") {
		t.Errorf("Error() = %q, must contain listen and websocket", s)
	}
}

// TestErrTransportNotFound verifies the sentinel error is a TransportError.
func TestErrTransportNotFound(t *testing.T) {
	if !errors.Is(ErrTransportNotFound, ErrTransportNotFound) {
		t.Error("ErrTransportNotFound is not errors.Is itself")
	}
	var tErr *TransportError
	if !errors.As(ErrTransportNotFound, &tErr) {
		t.Error("ErrTransportNotFound is not a TransportError")
	}
}

// TestErrTransportUnavailable verifies the sentinel error is retryable.
func TestErrTransportUnavailable(t *testing.T) {
	var tErr *TransportError
	if !errors.As(ErrTransportUnavailable, &tErr) {
		t.Fatal("ErrTransportUnavailable is not a TransportError")
	}
	if !tErr.Retry {
		t.Error("ErrTransportUnavailable.Retry = false, want true")
	}
}

// TestErrTransportShutdown verifies the sentinel error.
func TestErrTransportShutdown(t *testing.T) {
	if !errors.Is(ErrTransportShutdown, ErrTransportShutdown) {
		t.Error("ErrTransportShutdown is not errors.Is itself")
	}
	var tErr *TransportError
	if !errors.As(ErrTransportShutdown, &tErr) {
		t.Error("ErrTransportShutdown is not a TransportError")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportConfigError tests
// ──────────────────────────────────────────────────────────────────────────────

// TestTransportConfigError verifies that TransportConfigError formats correctly.
func TestTransportConfigError(t *testing.T) {
	e := &TransportConfigError{Field: "Name", Reason: "must be non-empty"}
	s := e.Error()
	if !containsStr(s, "Name") {
		t.Errorf("Error() = %q, must contain field name", s)
	}
	if !containsStr(s, "must be non-empty") {
		t.Errorf("Error() = %q, must contain reason", s)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportShutdownError tests
// ──────────────────────────────────────────────────────────────────────────────

// TestTransportShutdownError verifies that TransportShutdownError wraps correctly.
func TestTransportShutdownError(t *testing.T) {
	underlying := fmt.Errorf("timeout during drain")
	e := &TransportShutdownError{Name: "udp", Err: underlying}

	if !errors.Is(e, underlying) {
		t.Error("errors.Is(e, underlying) = false, want true")
	}

	s := e.Error()
	if !containsStr(s, "udp") {
		t.Errorf("Error() = %q, must contain transport name", s)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Context cancellation on net.Pipe()
// ──────────────────────────────────────────────────────────────────────────────

// TestPipePeerConnContextCancelledAfterClose verifies that after ForceClose,
// reads and writes on a pipe-backed PeerConn fail.
func TestPipePeerConnContextCancelledAfterClose(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pc := NewPeerConn(client, "udp")
	pc.ForceClose()

	// Write should fail.
	_, err := pc.Write([]byte("data"))
	if err == nil {
		t.Error("Write() after ForceClose should fail")
	}

	// Read should fail.
	buf := make([]byte, 1)
	_, err = pc.Read(buf)
	if err == nil {
		t.Error("Read() after ForceClose should fail")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Concurrent access tests for net.Pipe() PeerConn
// ──────────────────────────────────────────────────────────────────────────────

// TestPipePeerConnConcurrentReadWrite verifies that concurrent reads and
// writes on a pipe-backed PeerConn are safe.
func TestPipePeerConnConcurrentReadWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewPeerConn(client, "udp")

	var wg sync.WaitGroup
	// Concurrent writers.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("msg-%d", id))
			pc.Write(msg)
		}(i)
	}

	// Server reads concurrently.
	go func() {
		buf := make([]byte, 1024)
		total := 0
		for total < 5*5 { // 5 messages of ~5 bytes each
			n, err := server.Read(buf[total:])
			if err != nil {
				return
			}
			total += n
		}
	}()

	wg.Wait()
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// containsStr reports whether s contains substr.
func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
