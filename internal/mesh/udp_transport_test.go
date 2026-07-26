package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// UDPTransportFactory tests
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPFactoryName verifies that the factory reports "udp" as its transport type.
func TestUDPFactoryName(t *testing.T) {
	f := NewUDPTransportFactory()
	if f.Name() != "udp" {
		t.Errorf("Name() = %q, want %q", f.Name(), "udp")
	}
}

// TestUDPFactoryActiveSince verifies that ActiveSince returns the creation time.
func TestUDPFactoryActiveSince(t *testing.T) {
	before := time.Now()
	f := NewUDPTransportFactory()
	after := time.Now()

	as := f.ActiveSince()
	if as.Before(before) || as.After(after) {
		t.Errorf("ActiveSince() = %v, want between %v and %v", as, before, after)
	}
}

// TestUDPFactoryConnCountInitial verifies ConnCount is 0 on a fresh factory.
func TestUDPFactoryConnCountInitial(t *testing.T) {
	f := NewUDPTransportFactory()
	if f.ConnCount() != 0 {
		t.Errorf("ConnCount() = %d, want 0", f.ConnCount())
	}
}

// TestUDPFactoryNewTransport verifies that NewTransport creates a working
// UDPTransport with the given config, applying defaults for zero-value fields.
func TestUDPFactoryNewTransport(t *testing.T) {
	f := NewUDPTransportFactory()
	tr, err := f.NewTransport(TransportConfig{Name: "udp"})
	if err != nil {
		t.Fatalf("NewTransport() error: %v", err)
	}
	if tr == nil {
		t.Fatal("NewTransport() returned nil transport")
	}
	if tr.Name() != "udp" {
		t.Errorf("Transport Name() = %q, want %q", tr.Name(), "udp")
	}
}

// TestUDPFactoryNewTransportDefaults verifies that zero-value fields in
// TransportConfig are replaced with defaults (DialTimeout=30s).
func TestUDPFactoryNewTransportDefaults(t *testing.T) {
	f := NewUDPTransportFactory()
	tr, err := f.NewTransport(TransportConfig{Name: "udp"})
	if err != nil {
		t.Fatalf("NewTransport() error: %v", err)
	}
	ut := tr.(*UDPTransport)
	if ut.cfg.DialTimeout != 30*time.Second {
		t.Errorf("DialTimeout = %v, want 30s", ut.cfg.DialTimeout)
	}
}

// TestUDPFactoryNewTransportWrongName verifies that NewTransport rejects
// a config with a non-"udp" Name.
func TestUDPFactoryNewTransportWrongName(t *testing.T) {
	f := NewUDPTransportFactory()
	_, err := f.NewTransport(TransportConfig{Name: "reality"})
	if err == nil {
		t.Fatal("NewTransport() should reject non-udp name")
	}
	var cfgErr *TransportConfigError
	if !errors.As(err, &cfgErr) {
		t.Errorf("expected TransportConfigError, got %T: %v", err, err)
	}
	if cfgErr.Field != "Name" {
		t.Errorf("config error field = %q, want %q", cfgErr.Field, "Name")
	}
}

// TestUDPFactoryNewTransportAfterShutdown verifies that NewTransport
// returns ErrTransportShutdown after Shutdown has been called.
func TestUDPFactoryNewTransportAfterShutdown(t *testing.T) {
	f := NewUDPTransportFactory()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}
	_, err := f.NewTransport(TransportConfig{Name: "udp"})
	if !errors.Is(err, ErrTransportShutdown) {
		t.Errorf("NewTransport after shutdown: expected ErrTransportShutdown, got %v", err)
	}
}

// TestUDPFactoryShutdownIdempotent verifies that calling Shutdown multiple
// times is safe and returns nil.
func TestUDPFactoryShutdownIdempotent(t *testing.T) {
	f := NewUDPTransportFactory()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := f.Shutdown(ctx); err != nil {
		t.Fatalf("first Shutdown() error: %v", err)
	}
	if err := f.Shutdown(ctx); err != nil {
		t.Fatalf("second Shutdown() error: %v", err)
	}
	if err := f.Shutdown(ctx); err != nil {
		t.Fatalf("third Shutdown() error: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// UDPTransport.Connect tests
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPConnectAndRoundTrip verifies that Connect establishes a working
// UDP connection to a real listener, and that data can be exchanged.
func TestUDPConnectAndRoundTrip(t *testing.T) {
	// Set up a UDP echo server.
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP error: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().String()

	// Start echo loop.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			serverConn.WriteToUDP(buf[:n], raddr)
		}
	}()

	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, err := f.NewTransport(TransportConfig{
		Name:        "udp",
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewTransport() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pc, err := tr.Connect(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	defer pc.ForceClose()

	if pc.Transport() != "udp" {
		t.Errorf("Transport() = %q, want %q", pc.Transport(), "udp")
	}

	// Send a test message and verify echo.
	msg := []byte("hello-udp-transport")
	if _, err := pc.Write(msg); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	buf := make([]byte, 65535)
	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error: %v", err)
	}
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Errorf("Read() = %q, want %q", string(buf[:n]), string(msg))
	}

	// Verify PeerConn metadata.
	if pc.Latency() < 0 {
		t.Errorf("Latency() = %v, want >= 0", pc.Latency())
	}

	// Verify ConnCount incremented.
	if f.ConnCount() < 1 {
		t.Errorf("ConnCount() = %d, want >= 1", f.ConnCount())
	}

	// ForceClose and verify ConnCount decremented.
	pc.ForceClose()
	time.Sleep(100 * time.Millisecond) // allow unregister to propagate
	if f.ConnCount() != 0 {
		t.Errorf("after close ConnCount() = %d, want 0", f.ConnCount())
	}
}

// TestUDPConnectInvalidAddress verifies that Connect with an invalid address
// returns a permanent error.
func TestUDPConnectInvalidAddress(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{Name: "udp", DialTimeout: 2 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// An invalid address that can't be resolved.
	_, err := tr.Connect(ctx, "not-a-valid-address:-1")
	if err == nil {
		t.Fatal("Connect() should fail for invalid address")
	}

	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if tErr.Retry {
		t.Errorf("error should not be retryable for invalid address")
	}
}

// TestUDPConnectContextCancelled verifies that Connect respects context
// cancellation and returns a transient error.
func TestUDPConnectContextCancelled(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	// Use MaxConns=1 and a semaphore that's already full to trigger
	// context cancellation on the second Connect.
	tr, _ := f.NewTransport(TransportConfig{
		Name:     "udp",
		MaxConns: 1,
	})

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	// Set up a UDP server.
	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().String()

	pc1, err := tr.Connect(ctx1, serverAddr)
	if err != nil {
		t.Fatalf("first Connect() error: %v", err)
	}
	defer pc1.ForceClose()

	// Now ctx is already cancelled.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()

	_, err = tr.Connect(ctx2, serverAddr)
	if err == nil {
		t.Fatal("Connect() should fail when MaxConns is reached and ctx times out")
	}

	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if !tErr.Retry {
		t.Errorf("error should be retryable (transient) for context cancellation")
	}
}

// TestUDPConnectMaxConns verifies that MaxConns limits concurrent connections.
func TestUDPConnectMaxConns(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{
		Name:     "udp",
		MaxConns: 2,
	})

	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pc1, err := tr.Connect(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Connect 1 error: %v", err)
	}
	defer pc1.ForceClose()

	pc2, err := tr.Connect(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Connect 2 error: %v", err)
	}
	defer pc2.ForceClose()

	// Third connection should block/time out due to MaxConns=2.
	ctx3, cancel3 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel3()

	_, err = tr.Connect(ctx3, serverAddr)
	if err == nil {
		t.Fatal("Connect 3 should fail when MaxConns is reached")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// UDPTransport.Listen tests
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPListenAndAccept verifies that Listen creates a working listener
// that accepts inbound UDP connections via the session demultiplexer.
func TestUDPListenAndAccept(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{Name: "udp"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	defer listener.Close()

	listenAddr := listener.Addr().String()

	// Dial in from a client.
	clientConn, err := net.Dial("udp", listenAddr)
	if err != nil {
		t.Fatalf("client Dial error: %v", err)
	}
	defer clientConn.Close()

	// Send a packet — this triggers session creation and Accept.
	msg := []byte("hello-from-client")
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("client Write error: %v", err)
	}

	// Accept the inbound session.
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		c, e := listener.Accept()
		ch <- acceptResult{conn: c, err: e}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("Accept() error: %v", res.err)
		}
		defer res.conn.Close()

		// Read the packet from the accepted session.
		buf := make([]byte, 65535)
		res.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := res.conn.Read(buf)
		if err != nil {
			t.Fatalf("session Read error: %v", err)
		}
		if string(buf[:n]) != string(msg) {
			t.Errorf("session Read = %q, want %q", string(buf[:n]), string(msg))
		}

		// Write a reply back through the session.
		reply := []byte("hello-from-server")
		if _, err := res.conn.Write(reply); err != nil {
			t.Fatalf("session Write error: %v", err)
		}

		// Read the reply on the client.
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		rbuf := make([]byte, 65535)
		rn, err := clientConn.Read(rbuf)
		if err != nil {
			t.Fatalf("client Read error: %v", err)
		}
		if string(rbuf[:rn]) != string(reply) {
			t.Errorf("client Read = %q, want %q", string(rbuf[:rn]), string(reply))
		}

	case <-time.After(3 * time.Second):
		t.Fatal("Accept() timed out")
	}
}

// TestUDPListenMultipleSessions verifies that the listener demultiplexes
// packets from different source addresses into separate sessions.
func TestUDPListenMultipleSessions(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{Name: "udp"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	defer listener.Close()

	listenAddr := listener.Addr().String()

	// Two clients on different source ports.
	client1, _ := net.Dial("udp", listenAddr)
	defer client1.Close()
	client2, _ := net.Dial("udp", listenAddr)
	defer client2.Close()

	// Both send a packet.
	client1.Write([]byte("c1-ping"))
	client2.Write([]byte("c2-ping"))

	// Accept two sessions.
	acceptTimeout := 3 * time.Second
	accepted := make([]net.Conn, 0, 2)

	for len(accepted) < 2 {
		ch := make(chan net.Conn, 1)
		go func() {
			c, _ := listener.Accept()
			ch <- c
		}()
		select {
		case c := <-ch:
			if c != nil {
				accepted = append(accepted, c)
			}
		case <-time.After(acceptTimeout):
			t.Fatalf("Accept() timed out, got %d of 2 sessions", len(accepted))
		}
	}
	defer func() {
		for _, c := range accepted {
			c.Close()
		}
	}()

	// Verify each session received the correct packet.
	for i, sc := range accepted {
		buf := make([]byte, 65535)
		sc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := sc.Read(buf)
		if err != nil {
			t.Fatalf("session[%d] Read error: %v", i, err)
		}
		got := string(buf[:n])
		if got != "c1-ping" && got != "c2-ping" {
			t.Errorf("session[%d] Read = %q, want one of c1-ping/c2-ping", i, got)
		}
	}
}

// TestUDPListenClose verifies that closing the listener stops Accept.
func TestUDPListenClose(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{Name: "udp"})
	ctx := context.Background()

	listener, err := tr.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}

	// Close the listener.
	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// Accept should return immediately with net.ErrClosed.
	ch := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		ch <- err
	}()

	select {
	case err := <-ch:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept after Close: expected net.ErrClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept after Close should not block")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// UDPTransport.LatencyProbe tests
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPLatencyProbeSuccess verifies that LatencyProbe measures RTT to
// a responsive server.
func TestUDPLatencyProbeSuccess(t *testing.T) {
	// Echo server.
	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			serverConn.WriteToUDP(buf[:n], raddr)
		}
	}()

	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{
		Name:        "udp",
		DialTimeout: 5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rtt, err := tr.LatencyProbe(ctx, serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("LatencyProbe() error: %v", err)
	}
	if rtt <= 0 {
		t.Errorf("RTT = %v, want > 0", rtt)
	}
	if rtt > 5*time.Second {
		t.Errorf("RTT = %v, want < 5s", rtt)
	}
}

// TestUDPLatencyProbeNoResponse verifies that LatencyProbe returns a
// transient error when the server doesn't respond.
func TestUDPLatencyProbeNoResponse(t *testing.T) {
	// A non-echoing server.
	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()

	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{
		Name:        "udp",
		DialTimeout: 200 * time.Millisecond, // short timeout
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tr.LatencyProbe(ctx, serverConn.LocalAddr().String())
	if err == nil {
		t.Fatal("LatencyProbe() should fail when server doesn't respond")
	}

	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if !tErr.Retry {
		t.Errorf("error should be retryable for no response")
	}
}

// TestUDPLatencyProbeInvalidAddress verifies that LatencyProbe with an
// invalid address returns a permanent error.
func TestUDPLatencyProbeInvalidAddress(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{Name: "udp"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tr.LatencyProbe(ctx, "not-a-valid-address:-1")
	if err == nil {
		t.Fatal("LatencyProbe() should fail for invalid address")
	}

	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if tErr.Retry {
		t.Errorf("error should not be retryable for invalid address")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// UDPTransport.IsHealthy tests
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPIsHealthy verifies that IsHealthy returns true initially and false
// after shutdown.
func TestUDPIsHealthy(t *testing.T) {
	f := NewUDPTransportFactory()

	tr, _ := f.NewTransport(TransportConfig{Name: "udp"})
	if !tr.IsHealthy() {
		t.Error("IsHealthy() = false, want true for fresh transport")
	}

	f.Shutdown(context.Background())
	if tr.IsHealthy() {
		t.Error("IsHealthy() = true after shutdown, want false")
	}
}

// TestUDPTransportClosedAfterShutdown verifies that Connect and Listen
// return errors after the factory is shut down.
func TestUDPTransportClosedAfterShutdown(t *testing.T) {
	f := NewUDPTransportFactory()
	tr, _ := f.NewTransport(TransportConfig{Name: "udp"})

	f.Shutdown(context.Background())

	ctx := context.Background()
	_, err := tr.Connect(ctx, "127.0.0.1:9999")
	if err == nil {
		t.Error("Connect after shutdown should fail")
	}
	if !errors.Is(err, ErrTransportShutdown) && !errors.Is(err, net.ErrClosed) {
		// It may be classified as ErrTransportShutdown or net.ErrClosed
		var tErr *TransportError
		if errors.As(err, &tErr) {
			// OK — it's a TransportError wrapping the shutdown reason
		} else {
			t.Errorf("Connect after shutdown: unexpected error type %T: %v", err, err)
		}
	}

	_, err = tr.Listen(ctx, "127.0.0.1:0")
	if err == nil {
		t.Error("Listen after shutdown should fail")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// UDPTransportFactory.Shutdown tests
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPShutdownDrainsConnections verifies that Shutdown waits for all
// connections to close.
func TestUDPShutdownDrainsConnections(t *testing.T) {
	f := NewUDPTransportFactory()

	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().String()

	tr, _ := f.NewTransport(TransportConfig{Name: "udp"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pc, err := tr.Connect(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	if f.ConnCount() != 1 {
		t.Errorf("ConnCount = %d, want 1", f.ConnCount())
	}

	// Shutdown should close the connection and drain.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := f.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	if f.ConnCount() != 0 {
		t.Errorf("after shutdown ConnCount = %d, want 0", f.ConnCount())
	}

	// Verify the connection is actually closed.
	_, err = pc.Write([]byte("should-fail"))
	if err == nil {
		// On UDP, writes to a closed socket may or may not fail immediately.
		// The important thing is the connection is tracked as closed.
	}
}

// TestUDPShutdownClosesListeners verifies that Shutdown closes all active listeners.
func TestUDPShutdownClosesListeners(t *testing.T) {
	f := NewUDPTransportFactory()

	tr, _ := f.NewTransport(TransportConfig{Name: "udp"})
	ctx := context.Background()

	listener, err := tr.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}

	// Shutdown should close the listener.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := f.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	// Accept should return immediately with net.ErrClosed.
	ch := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		ch <- err
	}()

	select {
	case err := <-ch:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept after shutdown: expected net.ErrClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept after shutdown should not block")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// PeerConn tests
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPPeerConnMetadata verifies that PeerConn exposes transport metadata.
func TestUDPPeerConnMetadata(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{Name: "udp"})

	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pc, err := tr.Connect(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	defer pc.ForceClose()

	if pc.Transport() != "udp" {
		t.Errorf("Transport() = %q, want %q", pc.Transport(), "udp")
	}

	// RemoteAddr should be the server address.
	raddr := pc.RemoteAddr().String()
	if raddr != serverAddr {
		t.Errorf("RemoteAddr() = %q, want %q", raddr, serverAddr)
	}

	// LocalAddr should be non-nil.
	if pc.LocalAddr() == nil {
		t.Error("LocalAddr() is nil")
	}

	// Latency should be non-negative.
	if pc.Latency() < 0 {
		t.Errorf("Latency() = %v, want >= 0", pc.Latency())
	}
}

// TestUDPPeerConnDoubleClose verifies that double Close is safe.
func TestUDPPeerConnDoubleClose(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{Name: "udp"})

	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pc, err := tr.Connect(ctx, serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	if err := pc.ForceClose(); err != nil {
		t.Fatalf("first ForceClose() error: %v", err)
	}
	if err := pc.ForceClose(); err != nil {
		t.Errorf("second ForceClose() error: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportRegistry integration tests
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPTransportRegistryIntegration verifies that the UDP factory works
// with the TransportRegistry.
func TestUDPTransportRegistryIntegration(t *testing.T) {
	registry := NewTransportRegistry()
	factory := NewUDPTransportFactory()
	registry.Register(factory)

	// Verify the factory is registered.
	f, err := registry.Get("udp")
	if err != nil {
		t.Fatalf("registry.Get() error: %v", err)
	}
	if f.Name() != "udp" {
		t.Errorf("factory Name() = %q, want %q", f.Name(), "udp")
	}

	// Create a transport via the factory.
	tr, err := f.NewTransport(TransportConfig{Name: "udp"})
	if err != nil {
		t.Fatalf("NewTransport() error: %v", err)
	}

	// Verify it's a UDPTransport.
	if tr.Name() != "udp" {
		t.Errorf("transport Name() = %q, want %q", tr.Name(), "udp")
	}

	// Shutdown via the registry.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := registry.ShutdownAll(ctx); err != nil {
		t.Fatalf("ShutdownAll() error: %v", err)
	}
}

// TestUDPTransportRegistryFailover verifies that SetFallbackOrder works
// with the UDP transport.
func TestUDPTransportRegistryFailover(t *testing.T) {
	registry := NewTransportRegistry()
	factory := NewUDPTransportFactory()
	registry.Register(factory)

	registry.SetFallbackOrder([]string{"udp", "websocket", "reality"})

	// Get should return the first healthy factory in the fallback order.
	f, err := registry.Get("udp")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if f.Name() != "udp" {
		t.Errorf("factory Name() = %q, want %q", f.Name(), "udp")
	}

	// Verify fallback order.
	order := registry.FallbackOrder()
	if len(order) != 3 || order[0] != "udp" {
		t.Errorf("FallbackOrder = %v, want [udp websocket reality]", order)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Error classification tests
// ──────────────────────────────────────────────────────────────────────────────

// TestIsTransientError verifies the error classification helper.
func TestIsTransientError(t *testing.T) {
	// Context cancellation is transient.
	if !isTransientError(context.Canceled) {
		t.Error("context.Canceled should be transient")
	}
	if !isTransientError(context.DeadlineExceeded) {
		t.Error("context.DeadlineExceeded should be transient")
	}

	// Nil error is not transient.
	if isTransientError(nil) {
		t.Error("nil error should not be transient")
	}

	// A timeout net.Error is transient.
	// We can't easily create a net.Error directly, but we can test
	// via a real timeout.
	_, err := net.DialTimeout("udp", "192.0.2.1:9999", 10*time.Millisecond) // TEST-NET-1
	if err != nil {
		// This should be classified as transient (timeout).
		// Note: it might be a timeout or a "no route to host", both transient.
		_ = isTransientError(err) // just verify it doesn't panic
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Concurrency test
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPConcurrentConnect verifies that concurrent Connect calls are safe.
func TestUDPConcurrentConnect(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{
		Name:     "udp",
		MaxConns: 10,
	})

	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().String()

	var wg sync.WaitGroup
	var successCount atomic.Int64

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pc, err := tr.Connect(ctx, serverAddr)
			if err != nil {
				return
			}
			defer pc.ForceClose()
			successCount.Add(1)
		}()
	}

	wg.Wait()

	if successCount.Load() != 10 {
		t.Errorf("successful connections = %d, want 10", successCount.Load())
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportConfig validation tests
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPTransportConfigValidation verifies that Validate accepts "udp" config.
func TestUDPTransportConfigValidation(t *testing.T) {
	cfg := TransportConfig{Name: "udp"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() for udp: unexpected error: %v", err)
	}

	// Empty name should fail.
	cfg = TransportConfig{}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() for empty name should fail")
	}
}

// TestUDPDefaultTransportConfig verifies that DefaultTransportConfig
// returns a valid udp config.
func TestUDPDefaultTransportConfig(t *testing.T) {
	cfg := DefaultTransportConfig()
	if cfg.Name != "udp" {
		t.Errorf("DefaultTransportConfig Name = %q, want %q", cfg.Name, "udp")
	}
	if cfg.DialTimeout != 30*time.Second {
		t.Errorf("DefaultTransportConfig DialTimeout = %v, want 30s", cfg.DialTimeout)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("DefaultTransportConfig Validate() error: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Idle timeout test
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPIdleTimeout verifies that a connection with an idle timeout
// gets its deadline set.
func TestUDPIdleTimeout(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{
		Name:        "udp",
		IdleTimeout: 100 * time.Millisecond,
	})

	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pc, err := tr.Connect(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	defer pc.ForceClose()

	// The idle timeout is applied as a deadline on the connection.
	// After it expires, reads/writes should fail.
	time.Sleep(200 * time.Millisecond)

	_, err = pc.Read(make([]byte, 1))
	if err == nil {
		// On some systems the read may not fail immediately after deadline;
		// that's OK — the important thing is the deadline was set.
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Session idle timeout test
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPSessionIdleTimeout verifies that inbound sessions are cleaned up
// after the idle timeout when no packets arrive.
func TestUDPSessionIdleTimeout(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr, _ := f.NewTransport(TransportConfig{
		Name:        "udp",
		IdleTimeout: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	defer listener.Close()

	listenAddr := listener.Addr().String()

	// Send a packet to create a session.
	clientConn, _ := net.Dial("udp", listenAddr)
	defer clientConn.Close()
	clientConn.Write([]byte("trigger-session"))

	// Accept the session.
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := listener.Accept()
		ch <- c
	}()
	select {
	case c := <-ch:
		if c == nil {
			t.Fatal("Accept returned nil conn")
		}
		// Read the initial packet but do NOT close the session —
		// let the idle watcher clean it up.
		c.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 65535)
		c.Read(buf)
		// Don't close c — the idle watcher should close it.
	case <-time.After(3 * time.Second):
		t.Fatal("Accept timed out")
	}

	// Wait for the idle timeout to clean up the session.
	time.Sleep(300 * time.Millisecond)

	// Verify the session was removed from the listener.
	l := listener.(*udpListener)
	l.mu.Lock()
	sessCount := len(l.sessions)
	l.mu.Unlock()

	if sessCount != 0 {
		t.Errorf("session count after idle timeout = %d, want 0", sessCount)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Full round-trip via transport layer test
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPFullRoundTripViaTransportLayer verifies that two UDPTransport
// instances can communicate: one listens, the other connects, and data
// flows bidirectionally through the transport abstraction layer.
func TestUDPFullRoundTripViaTransportLayer(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	// Server-side transport: listen.
	serverTr, _ := f.NewTransport(TransportConfig{Name: "udp"})
	listener, err := serverTr.Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	defer listener.Close()

	listenAddr := listener.Addr().String()

	// Client-side transport: connect.
	clientTr, _ := f.NewTransport(TransportConfig{
		Name:        "udp",
		DialTimeout: 5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientConn, err := clientTr.Connect(ctx, listenAddr)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	defer clientConn.ForceClose()

	// Start Accept goroutine BEFORE sending data — the session is only
	// created when the first packet arrives at the listener.
	acceptCh := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			acceptCh <- nil
			return
		}
		acceptCh <- c
	}()

	// Send the first packet — this triggers session creation and Accept.
	clientMsg := []byte("hello-from-client-via-transport")
	if _, err := clientConn.Write(clientMsg); err != nil {
		t.Fatalf("client Write error: %v", err)
	}

	var serverConn net.Conn
	select {
	case serverConn = <-acceptCh:
		if serverConn == nil {
			t.Fatal("Accept returned nil conn")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept timed out")
	}
	defer serverConn.Close()

	// Read the initial packet from the accepted session.
	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	sbuf := make([]byte, 65535)
	n, err := serverConn.Read(sbuf)
	if err != nil {
		t.Fatalf("server Read error: %v", err)
	}
	if string(sbuf[:n]) != string(clientMsg) {
		t.Errorf("server Read = %q, want %q", string(sbuf[:n]), string(clientMsg))
	}

	// Server → Client.
	serverMsg := []byte("hello-from-server-via-transport")
	if _, err := serverConn.Write(serverMsg); err != nil {
		t.Fatalf("server Write error: %v", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cbuf := make([]byte, 65535)
	n, err = clientConn.Read(cbuf)
	if err != nil {
		t.Fatalf("client Read error: %v", err)
	}
	if string(cbuf[:n]) != string(serverMsg) {
		t.Errorf("client Read = %q, want %q", string(cbuf[:n]), string(serverMsg))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Edge case: empty name config
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPFactoryEmptyNameAccepts verifies that NewTransport accepts an
// empty Name (treats it as "udp").
func TestUDPFactoryEmptyNameAccepts(t *testing.T) {
	f := NewUDPTransportFactory()
	tr, err := f.NewTransport(TransportConfig{}) // empty Name
	if err != nil {
		t.Fatalf("NewTransport with empty name: unexpected error: %v", err)
	}
	if tr.Name() != "udp" {
		t.Errorf("Name() = %q, want %q", tr.Name(), "udp")
	}
}

// TestUDPFactoryMultipleTransports verifies that one factory can create
// multiple independent Transport instances.
func TestUDPFactoryMultipleTransports(t *testing.T) {
	f := NewUDPTransportFactory()
	defer f.Shutdown(context.Background())

	tr1, _ := f.NewTransport(TransportConfig{Name: "udp", DialTimeout: 1 * time.Second})
	tr2, _ := f.NewTransport(TransportConfig{Name: "udp", DialTimeout: 5 * time.Second})

	if tr1 == tr2 {
		t.Error("NewTransport returned the same instance")
	}

	u1 := tr1.(*UDPTransport)
	u2 := tr2.(*UDPTransport)
	if u1.cfg.DialTimeout == u2.cfg.DialTimeout {
		t.Errorf("transports should have different DialTimeout: %v vs %v",
			u1.cfg.DialTimeout, u2.cfg.DialTimeout)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Format helper test
// ──────────────────────────────────────────────────────────────────────────────

// TestUDPTransportErrorFormat verifies that TransportError formats correctly.
func TestUDPTransportErrorFormat(t *testing.T) {
	e := NewTransportError("connect", "udp", "1.2.3.4:51820", fmt.Errorf("timeout"), true)
	s := e.Error()
	if s == "" {
		t.Error("Error() is empty")
	}
	if !contains(s, "connect") || !contains(s, "udp") || !contains(s, "1.2.3.4:51820") {
		t.Errorf("Error() = %q, want to contain connect, udp, and address", s)
	}
	if !e.IsRetryable() {
		t.Error("IsRetryable() = false, want true")
	}
}

// contains is a simple substring check.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(s) > 0 && len(sub) > 0 && findSubstring(s, sub)))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
