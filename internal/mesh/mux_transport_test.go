package mesh

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
)

// ──────────────────────────────────────────────────────────────────────────────
// Test helpers
// ──────────────────────────────────────────────────────────────────────────────

// newTestMuxTransport creates a MuxTransport bound to a random port on
// localhost. Returns the transport and the actual TCP address.
func newTestMuxTransport(t *testing.T) (*MuxTransport, net.Listener, string) {
	t.Helper()

	// Create a TCP listener on a random port.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	addr := tcpLn.Addr().String()

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener:   tcpLn,
		BindAddr:      "127.0.0.1",
		UDPPort:       0, // let OS pick
		AdvertiseAddr: "127.0.0.1",
	})
	if err != nil {
		tcpLn.Close()
		t.Fatalf("NewMuxTransport: %v", err)
	}

	return mt, tcpLn, addr
}

// ──────────────────────────────────────────────────────────────────────────────
// Construction tests
// ──────────────────────────────────────────────────────────────────────────────

func TestNewMuxTransport_NilTCPListenerOK(t *testing.T) {
	// Without a TCP listener, the transport should still be created
	// successfully — it operates in UDP-only mode. The OS picks a free
	// UDP port when UDPPort is 0.
	mt, err := NewMuxTransport(MuxTransportConfig{})
	if err != nil {
		t.Fatalf("NewMuxTransport with nil TCPListener: %v", err)
	}
	defer mt.Shutdown()
}

func TestNewMuxTransport_NoTCPListenerOK(t *testing.T) {
	// A MuxTransport created without a TCP listener should still
	// construct cleanly (Reality-only: no UDP sockets are created).
	mt, err := NewMuxTransport(MuxTransportConfig{
		BindAddr: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	// PacketCh is nil (UDP disabled — Reality-only).
	if mt.PacketCh() != nil {
		t.Fatal("PacketCh should be nil (UDP disabled)")
	}
	// StreamCh should return a non-nil channel (no panics).
	if mt.StreamCh() == nil {
		t.Fatal("StreamCh is nil")
	}
	// RealityListener should not panic.
	rl := mt.RealityListener()
	if rl == nil {
		t.Fatal("RealityListener is nil")
	}
}

func TestNewMuxTransport_StartsGoroutines(t *testing.T) {
	mt, _, _ := newTestMuxTransport(t)
	defer mt.Shutdown()

	// Verify the transport is usable by checking its channels are non-nil.
	if mt.StreamCh() == nil {
		t.Fatal("StreamCh is nil")
	}
	if mt.PacketCh() != nil {
		t.Fatal("PacketCh should be nil (UDP disabled — Reality-only)")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Protocol demux tests
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxDemux_TLSTrafficRoutedToReality(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	rl := mt.RealityListener()
	defer rl.Close()

	// Forward reality accepts to a channel for the select.
	realityCh := make(chan net.Conn, 1)
	go func() {
		conn, err := rl.Accept()
		if err != nil {
			close(realityCh)
			return
		}
		realityCh <- conn
	}()

	// Simulate a TLS ClientHello by sending the first byte 0x16.
	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer conn.Close()
		// Write TLS handshake record type byte.
		_, err = conn.Write([]byte{tlsHandshakeRecordType})
		if err != nil {
			t.Errorf("write tls byte: %v", err)
			return
		}
		// Write some dummy TLS-ish data.
		_, _ = conn.Write([]byte{0x03, 0x01})
		time.Sleep(100 * time.Millisecond)
	}()

	select {
	case conn := <-realityCh:
		// Got a Reality connection. Verify the peeked byte is replayed.
		buf := make([]byte, 3)
		n, err := io.ReadFull(conn, buf)
		if err != nil {
			t.Fatalf("read from reality conn: %v", err)
		}
		if n != 3 {
			t.Fatalf("expected 3 bytes, got %d", n)
		}
		if buf[0] != tlsHandshakeRecordType {
			t.Fatalf("expected first byte 0x%02x, got 0x%02x", tlsHandshakeRecordType, buf[0])
		}
		conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Reality connection")
	}
}

func TestMuxDemux_PlaintextGossipRefused(t *testing.T) {
	// Reality-only: a plaintext gossip connection (non-TLS first byte)
	// must be refused — the connection is closed, never delivered.
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// A memberlist-ish first byte (0x00) — no TLS.
	if _, err := conn.Write([]byte{0x00, 0x01}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The connection should be closed by the transport (no delivery).
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected plaintext connection to be closed, got data")
	}

	// And nothing must arrive on StreamCh.
	select {
	case sc := <-mt.StreamCh():
		sc.Close()
		t.Fatal("plaintext gossip was delivered — must be refused (Reality-only)")
	case <-time.After(500 * time.Millisecond):
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// WriteTo / PacketCh tests (UDP)

// ──────────────────────────────────────────────────────────────────────────────
// DialTimeout test
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_DialTimeout(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	// Reality-only: DialTimeout requires an injected Reality dialer.
	if _, err := mt.DialTimeout(addr, 2*time.Second); err == nil {
		t.Fatal("expected DialTimeout to fail without a Reality dialer")
	}

	// Inject a mock Reality dialer (local TCP tunnel simulates the
	// masked TLS connection — the server side is delivered to StreamCh
	// exactly as acceptLoop does for a protoMemberlist connection).
	dialed := make(chan struct{}, 1)
	mt.SetRealityDialer(func(a string, timeout time.Duration) (net.Conn, error) {
		dialed <- struct{}{}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		go func() {
			c, aerr := ln.Accept()
			if aerr == nil {
				mt.DeliverStream(c)
			}
			ln.Close()
		}()
		return net.Dial("tcp", ln.Addr().String())
	})

	conn, err := mt.DialTimeout(addr, 2*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout: %v", err)
	}
	defer conn.Close()
	select {
	case <-dialed:
	case <-time.After(time.Second):
		t.Fatal("Reality dialer was not invoked")
	}

	// Write a gossip byte; it should arrive on StreamCh.
	if _, err := conn.Write([]byte{0x00, 0x01}); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case sc := <-mt.StreamCh():
		buf := make([]byte, 2)
		n, _ := io.ReadFull(sc, buf)
		if n != 2 || buf[0] != 0x00 {
			t.Fatalf("unexpected stream data: %v", buf[:n])
		}
		sc.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("dialed connection not demuxed to StreamCh")
	}
}

func TestMuxTransport_DialTimeout_NoDialer(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	// Without an injected Reality dialer every dial fails
	// (Reality-only: no plaintext gossip dials allowed).
	_, err := mt.DialTimeout(addr, 2*time.Second)
	if err == nil {
		t.Fatal("expected DialTimeout to fail without a Reality dialer")
	}
}

func TestMuxTransport_FinalAdvertiseAddr_Explicit(t *testing.T) {
	tcpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer tcpLn.Close()

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener:   tcpLn,
		BindAddr:      "127.0.0.1",
		AdvertiseAddr: "10.0.0.5",
		AdvertisePort: 9999,
	})
	if err != nil {
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	ip, port, err := mt.FinalAdvertiseAddr("", 0)
	if err != nil {
		t.Fatalf("FinalAdvertiseAddr: %v", err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("expected 10.0.0.5, got %s", ip)
	}
	if port != 9999 {
		t.Fatalf("expected port 9999, got %d", port)
	}
}

func TestMuxTransport_FinalAdvertiseAddr_UserOverride(t *testing.T) {
	tcpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer tcpLn.Close()

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: tcpLn,
		BindAddr:    "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	// When ip is provided, it overrides the address but the port is
	// always the MuxTransport's own port (the shared TCP listener port).
	ip, port, err := mt.FinalAdvertiseAddr("192.168.1.1", 12345)
	if err != nil {
		t.Fatalf("FinalAdvertiseAddr: %v", err)
	}
	if !ip.Equal(net.ParseIP("192.168.1.1")) {
		t.Fatalf("expected 192.168.1.1, got %s", ip)
	}
	// Port should be the TCP listener's port, not the passed-in 12345.
	expectedPort := tcpLn.Addr().(*net.TCPAddr).Port
	if port != expectedPort {
		t.Fatalf("expected port %d (TCP listener port), got %d", expectedPort, port)
	}
}

func TestMuxTransport_FinalAdvertiseAddr_InvalidIP(t *testing.T) {
	tcpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer tcpLn.Close()

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: tcpLn,
		BindAddr:    "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	_, _, err = mt.FinalAdvertiseAddr("not-an-ip", 0)
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// RealityListener tests
// ──────────────────────────────────────────────────────────────────────────────

func TestRealityListener_AcceptAndClose(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	rl := mt.RealityListener()

	// Send a TLS connection.
	go func() {
		conn, _ := net.Dial("tcp", addr)
		defer conn.Close()
		conn.Write([]byte{tlsHandshakeRecordType, 0xAA, 0xBB})
		time.Sleep(100 * time.Millisecond)
	}()

	// Accept it.
	conn, err := rl.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 3)
	n, _ := io.ReadFull(conn, buf)
	if n != 3 || buf[0] != tlsHandshakeRecordType {
		t.Fatalf("unexpected data: %v", buf[:n])
	}

	// Close the listener.
	rl.Close()

	// Accept after close should return ErrClosed.
	_, err = rl.Accept()
	if err != net.ErrClosed {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Shutdown tests
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_ShutdownIsIdempotent(t *testing.T) {
	mt, tcpLn, _ := newTestMuxTransport(t)

	if err := mt.Shutdown(); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := mt.Shutdown(); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}

	// Verify TCP listener is closed.
	_, err := tcpLn.Accept()
	if err == nil {
		t.Fatal("expected error on closed listener")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// connWithPrefix integration test
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_PlaintextRefused(t *testing.T) {
	// Reality-only: a plaintext (non-TLS) connection is refused and
	// closed — memberlist gossip only arrives inside Reality TLS.
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	payload := []byte{0x06, 0xDE, 0xAD, 0xBE, 0xEF} // memberlist-ish, plaintext
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The transport must close the connection (refuse plaintext).
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected plaintext connection to be closed")
	}

	// Nothing arrives on StreamCh.
	select {
	case sc := <-mt.StreamCh():
		sc.Close()
		t.Fatal("plaintext delivered to StreamCh — must be refused")
	case <-time.After(500 * time.Millisecond):
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Large payload test
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_LargePlaintextRefused(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	// A large plaintext payload must also be refused (connection closed).
	payload := make([]byte, 4096)
	payload[0] = 0x06
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected plaintext connection to be closed")
	}
	select {
	case sc := <-mt.StreamCh():
		sc.Close()
		t.Fatal("plaintext delivered to StreamCh — must be refused")
	case <-time.After(500 * time.Millisecond):
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection that sends no data (timeout)
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_EmptyConnectionClosed(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	// Connect but don't send any data.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Wait for the peek deadline to expire. No data should be routed.
	// Start a forwarding goroutine for reality accepts.
	realityCh := make(chan net.Conn, 1)
	go func() {
		rl := mt.RealityListener()
		defer rl.Close()
		conn, err := rl.Accept()
		if err != nil {
			close(realityCh)
			return
		}
		realityCh <- conn
	}()

	select {
	case <-mt.StreamCh():
		t.Fatal("unexpected stream from empty connection")
	case <-realityCh:
		t.Fatal("unexpected reality connection from empty connection")
	case <-time.After(12 * time.Second):
		// Expected: the connection was closed after the read deadline.
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// memberlist.Transport interface conformance
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_ImplementsMemberlistTransport(t *testing.T) {
	var _ memberlist.Transport = (*MuxTransport)(nil)
}

// ──────────────────────────────────────────────────────────────────────────────
// Concurrent connection test
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_ConcurrentRealityConnections(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	const numConns = 20
	rl := mt.RealityListener()
	defer rl.Close()

	realityCh := make(chan net.Conn, numConns)
	go func() {
		for {
			conn, err := rl.Accept()
			if err != nil {
				close(realityCh)
				return
			}
			realityCh <- conn
		}
	}()

	// Half TLS (accepted), half plaintext (refused).
	for i := 0; i < numConns; i++ {
		go func(idx int) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			defer conn.Close()
			if idx%2 == 0 {
				conn.Write([]byte{tlsHandshakeRecordType, byte(idx)})
			} else {
				conn.Write([]byte{byte(idx % 100), byte(idx)}) // plaintext — refused
			}
			time.Sleep(200 * time.Millisecond)
		}(i)
	}

	// Only the TLS connections are delivered.
	gotReality := 0
	deadline := time.After(5 * time.Second)
	for gotReality < numConns/2 {
		select {
		case conn := <-realityCh:
			gotReality++
			conn.Close()
		case conn := <-mt.StreamCh():
			conn.Close()
			t.Fatal("plaintext delivered to StreamCh — must be refused")
		case <-deadline:
			t.Fatalf("timed out: got %d/%d reality", gotReality, numConns/2)
		}
	}
	t.Logf("received: %d reality connections (plaintext refused)", gotReality)
}

// ──────────────────────────────────────────────────────────────────────────────
// Helper: get the UDP port

// ──────────────────────────────────────────────────────────────────────────────
// tcpPortFromListener helper test
// ──────────────────────────────────────────────────────────────────────────────

func TestTcpPortFromListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	port := tcpPortFromListener(ln)
	if port == 0 {
		t.Fatal("expected non-zero port")
	}

	// Verify it matches the actual port.
	addr := ln.Addr().(*net.TCPAddr)
	if port != addr.Port {
		t.Fatalf("expected %d, got %d", addr.Port, port)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Verify RealityListener Addr returns the TCP listener address
// ──────────────────────────────────────────────────────────────────────────────

func TestRealityListener_Addr(t *testing.T) {
	tcpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer tcpLn.Close()

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: tcpLn,
		BindAddr:    "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	rl := mt.RealityListener()
	rlAddr := rl.Addr().String()
	tcpAddr := tcpLn.Addr().String()

	if rlAddr != tcpAddr {
		t.Fatalf("reality listener addr %q != tcp listener addr %q", rlAddr, tcpAddr)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// All memberlist message types are routed to StreamCh (not Reality)

// ──────────────────────────────────────────────────────────────────────────────
// Verify all 256 possible first bytes are routed correctly

// ──────────────────────────────────────────────────────────────────────────────
// Reality listener can be closed and recreated
// ──────────────────────────────────────────────────────────────────────────────

func TestRealityListener_CanCloseAndRecreate(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	rl1 := mt.RealityListener()
	rl1.Close()

	// Create a new listener.
	rl2 := mt.RealityListener()
	defer rl2.Close()

	// Forward rl2 accepts to a channel.
	rl2Ch := make(chan net.Conn, 1)
	go func() {
		conn, err := rl2.Accept()
		if err != nil {
			close(rl2Ch)
			return
		}
		rl2Ch <- conn
	}()

	// Send a TLS connection.
	go func() {
		conn, _ := net.Dial("tcp", addr)
		defer conn.Close()
		conn.Write([]byte{tlsHandshakeRecordType, 0x01})
		time.Sleep(100 * time.Millisecond)
	}()

	select {
	case conn := <-rl2Ch:
		buf := make([]byte, 2)
		n, _ := io.ReadFull(conn, buf)
		if n != 2 || buf[0] != tlsHandshakeRecordType {
			t.Fatalf("unexpected data: %v", buf[:n])
		}
		conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reality connection on rl2")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// WriteTo with invalid address
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_WriteToInvalidAddr(t *testing.T) {
	mt, _, _ := newTestMuxTransport(t)
	defer mt.Shutdown()

	_, err := mt.WriteTo([]byte("test"), "not-a-valid-address:99999")
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Multiple reality listeners
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_MultipleRealityListeners(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	// Create two reality listeners. Both read from the same realityCh
	// on the transport, so only one needs to be actively accepting.
	rl1 := mt.RealityListener()
	defer rl1.Close()

	rl2 := mt.RealityListener()
	defer rl2.Close()

	// Start a forwarding goroutine for rl1 (it will get the connections
	// since both listeners share the same underlying realityCh).
	realityCh := make(chan net.Conn, 4)
	go func() {
		for {
			conn, err := rl1.Accept()
			if err != nil {
				close(realityCh)
				return
			}
			realityCh <- conn
		}
	}()

	// Send two TLS connections.
	for i := 0; i < 2; i++ {
		go func() {
			conn, _ := net.Dial("tcp", addr)
			defer conn.Close()
			conn.Write([]byte{tlsHandshakeRecordType, 0x01})
			time.Sleep(100 * time.Millisecond)
		}()
	}

	// Both connections should be delivered via realityCh.
	got := 0
	for got < 2 {
		select {
		case conn := <-realityCh:
			conn.Close()
			got++
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out: got %d/2", got)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// fmt.Sprintf helper for debug
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_String(t *testing.T) {
	// Just verify we can construct and the transport works with a
	// fmt.Sprintf call (for logging purposes).
	mt, tcpLn, _ := newTestMuxTransport(t)
	defer mt.Shutdown()

	s := fmt.Sprintf("mux transport on %s", tcpLn.Addr())
	if s == "" {
		t.Fatal("empty string")
	}
}
