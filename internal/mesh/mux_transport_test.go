package mesh

import (
	"bytes"
	"crypto/rand"
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

func TestNewMuxTransport_UDPOnlyMode(t *testing.T) {
	// A MuxTransport created without a TCP listener should work in
	// UDP-only mode: PacketCh and WriteTo are functional, StreamCh
	// returns a valid (but never-delivering) channel, and Shutdown
	// is clean.
	mt, err := NewMuxTransport(MuxTransportConfig{
		BindAddr: "127.0.0.1",
		UDPPort:  0, // let OS pick a free port
	})
	if err != nil {
		t.Fatalf("NewMuxTransport UDP-only: %v", err)
	}
	defer mt.Shutdown()

	// StreamCh should return a non-nil channel (no panics).
	if mt.StreamCh() == nil {
		t.Fatal("StreamCh is nil in UDP-only mode")
	}
	// PacketCh should return a non-nil channel.
	if mt.PacketCh() == nil {
		t.Fatal("PacketCh is nil in UDP-only mode")
	}
	// RealityListener should not panic.
	rl := mt.RealityListener()
	if rl == nil {
		t.Fatal("RealityListener is nil")
	}
	// MeshListener should not panic.
	ml := mt.MeshListener()
	if ml == nil {
		t.Fatal("MeshListener is nil")
	}
	// Addr() on listeners should return nil, not panic.
	if rl.Addr() != nil {
		t.Fatalf("expected nil Addr in UDP-only mode, got %v", rl.Addr())
	}
	if ml.Addr() != nil {
		t.Fatalf("expected nil Addr in UDP-only mode, got %v", ml.Addr())
	}
}

func TestNewMuxTransport_StartsGoroutines(t *testing.T) {
	mt, _, _ := newTestMuxTransport(t)
	defer mt.Shutdown()

	// Verify the transport is usable by checking its channels are non-nil.
	if mt.StreamCh() == nil {
		t.Fatal("StreamCh is nil")
	}
	if mt.PacketCh() == nil {
		t.Fatal("PacketCh is nil")
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

func TestMuxDemux_GossipTrafficRoutedToStreamCh(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	// memberlist ping message type is 0 (pingMsg).
	gossipByte := byte(0)

	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte{gossipByte, 0x01, 0x02})
		if err != nil {
			t.Errorf("write gossip byte: %v", err)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}()

	select {
	case conn := <-mt.StreamCh():
		// Verify the peeked byte is replayed.
		buf := make([]byte, 3)
		n, err := io.ReadFull(conn, buf)
		if err != nil {
			t.Fatalf("read from stream conn: %v", err)
		}
		if n != 3 {
			t.Fatalf("expected 3 bytes, got %d", n)
		}
		if buf[0] != gossipByte {
			t.Fatalf("expected first byte 0x%02x, got 0x%02x", gossipByte, buf[0])
		}
		conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for gossip stream connection")
	}
}

func TestMuxDemux_MultipleConnectionsMixed(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	rl := mt.RealityListener()
	defer rl.Close()

	// Forward Reality connections to a channel for the select loop.
	realityCh := make(chan net.Conn, 4)
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

	// Send one TLS and one gossip connection concurrently.
	go func() {
		conn, _ := net.Dial("tcp", addr)
		defer conn.Close()
		conn.Write([]byte{tlsHandshakeRecordType, 0x01})
		time.Sleep(100 * time.Millisecond)
	}()

	go func() {
		conn, _ := net.Dial("tcp", addr)
		defer conn.Close()
		conn.Write([]byte{0x00, 0xAA, 0xBB}) // gossip ping
		time.Sleep(100 * time.Millisecond)
	}()

	gotStream := false
	gotReality := false

	for !gotStream || !gotReality {
		select {
		case conn := <-mt.StreamCh():
			buf := make([]byte, 3)
			n, _ := io.ReadFull(conn, buf)
			if n != 3 || buf[0] != 0x00 {
				t.Fatalf("unexpected gossip stream data: %v", buf[:n])
			}
			gotStream = true
			conn.Close()
		case conn := <-realityCh:
			buf := make([]byte, 2)
			n, _ := io.ReadFull(conn, buf)
			if n != 2 || buf[0] != tlsHandshakeRecordType {
				t.Fatalf("unexpected reality data: %v", buf[:n])
			}
			gotReality = true
			conn.Close()
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out: gotStream=%v gotReality=%v", gotStream, gotReality)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// WriteTo / PacketCh tests (UDP)
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_WriteToAndReceivePacket(t *testing.T) {
	mt, _, _ := newTestMuxTransport(t)
	defer mt.Shutdown()

	// Determine the UDP address.
	udpAddr := mt.udpConns[0].LocalAddr().String()

	// Write a packet to our own UDP listener.
	payload := []byte("hello-gossip")
	ts, err := mt.WriteTo(payload, udpAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if ts.IsZero() {
		t.Fatal("WriteTo returned zero timestamp")
	}

	// Read the packet from the channel.
	select {
	case pkt := <-mt.PacketCh():
		if string(pkt.Buf) != string(payload) {
			t.Fatalf("expected %q, got %q", payload, string(pkt.Buf))
		}
		if pkt.From == nil {
			t.Fatal("packet From is nil")
		}
		if pkt.Timestamp.IsZero() {
			t.Fatal("packet timestamp is zero")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for packet")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// DialTimeout test
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_DialTimeout(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	conn, err := mt.DialTimeout(addr, 2*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout: %v", err)
	}
	defer conn.Close()

	// Write a gossip byte; it should arrive on StreamCh.
	_, err = conn.Write([]byte{0x00, 0x01})
	if err != nil {
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

func TestMuxTransport_DialTimeout_Unreachable(t *testing.T) {
	mt, _, _ := newTestMuxTransport(t)
	defer mt.Shutdown()

	// Dial a port that is almost certainly not listening.
	_, err := mt.DialTimeout("127.0.0.1:1", 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected error for unreachable address")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// FinalAdvertiseAddr tests
// ──────────────────────────────────────────────────────────────────────────────

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

func TestMuxTransport_ShutdownClosesUDP(t *testing.T) {
	mt, _, _ := newTestMuxTransport(t)
	udpAddr := mt.udpConns[0].LocalAddr().String()

	mt.Shutdown()

	// After shutdown, the UDP listener should be closed. Verify by trying
	// to create a new UDP conn on the same port — it should succeed.
	// (The OS may take a moment to release the port.)
	// Instead, verify WriteTo returns an error.
	_, err := mt.WriteTo([]byte("test"), udpAddr)
	if err == nil {
		// On some OSes the write may succeed even after close, but the
		// read loop should have exited. Check that no packets arrive.
		select {
		case <-mt.PacketCh():
			t.Fatal("received packet after shutdown")
		case <-time.After(200 * time.Millisecond):
			// Good — no packets.
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// connWithPrefix integration test
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_PeekedByteReplayed(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	// Test that the peeked byte is correctly replayed.
	// Send a known memberlist message type (e.g. 6 = pushPullMsg).
	pushPullMsg := byte(6)
	payload := []byte{pushPullMsg, 0xDE, 0xAD, 0xBE, 0xEF}

	go func() {
		conn, _ := net.Dial("tcp", addr)
		defer conn.Close()
		conn.Write(payload)
		time.Sleep(100 * time.Millisecond)
	}()

	select {
	case conn := <-mt.StreamCh():
		// Read all bytes back — the peeked byte should be included.
		buf := make([]byte, len(payload))
		n, err := io.ReadFull(conn, buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if n != len(payload) {
			t.Fatalf("expected %d bytes, got %d", len(payload), n)
		}
		if !bytes.Equal(buf, payload) {
			t.Fatalf("data mismatch: got %v, want %v", buf, payload)
		}
		conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stream")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Large payload test
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_LargeGossipPayload(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	// Create a large payload (1KB) starting with a gossip byte.
	payload := make([]byte, 1024)
	rand.Read(payload[1:])
	payload[0] = 0x00 // pingMsg

	go func() {
		conn, _ := net.Dial("tcp", addr)
		defer conn.Close()
		conn.Write(payload)
		time.Sleep(200 * time.Millisecond)
	}()

	select {
	case conn := <-mt.StreamCh():
		buf := make([]byte, len(payload))
		n, err := io.ReadFull(conn, buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if n != len(payload) {
			t.Fatalf("expected %d bytes, got %d", len(payload), n)
		}
		if !bytes.Equal(buf, payload) {
			t.Fatal("data mismatch in large payload")
		}
		conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for large stream")
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

func TestMuxTransport_ConcurrentConnections(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	const numConns = 20
	rl := mt.RealityListener()
	defer rl.Close()

	// Forward Reality connections to a channel for the select loop.
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

	// Launch concurrent connections: half TLS, half gossip.
	for i := 0; i < numConns; i++ {
		go func(idx int) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Errorf("dial %d: %v", idx, err)
				return
			}
			defer conn.Close()

			if idx%2 == 0 {
				// TLS path
				conn.Write([]byte{tlsHandshakeRecordType, byte(idx)})
			} else {
				// Gossip path
				conn.Write([]byte{byte(idx % 100), byte(idx)})
			}
			time.Sleep(200 * time.Millisecond)
		}(i)
	}

	// Count received connections.
	gotStream := 0
	gotReality := 0
	deadline := time.After(5 * time.Second)

	for gotStream+gotReality < numConns {
		select {
		case conn := <-mt.StreamCh():
			gotStream++
			conn.Close()
		case conn := <-realityCh:
			gotReality++
			conn.Close()
		case <-deadline:
			t.Fatalf("timed out: got %d streams + %d reality = %d/%d",
				gotStream, gotReality, gotStream+gotReality, numConns)
		}
	}

	t.Logf("received: %d streams, %d reality", gotStream, gotReality)
}

// ──────────────────────────────────────────────────────────────────────────────
// Helper: get the UDP port
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxTransport_UDPPortAutoAssigned(t *testing.T) {
	tcpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer tcpLn.Close()

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: tcpLn,
		BindAddr:    "127.0.0.1",
		UDPPort:     0,
	})
	if err != nil {
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	udpAddr, ok := mt.udpConns[0].LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("expected *net.UDPAddr")
	}
	if udpAddr.Port == 0 {
		t.Fatal("UDP port not assigned")
	}

	t.Logf("TCP port: %d, UDP port: %d",
		tcpPortFromListener(tcpLn), udpAddr.Port)
}

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

func TestMuxDemux_AllMemberlistMessageTypes(t *testing.T) {
	// All memberlist message types (0-14, 244) should be routed to StreamCh,
	// not Reality. TLS record type 0x16 (22) should go to Reality.
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	rl := mt.RealityListener()
	defer rl.Close()

	// Start a background goroutine that forwards Reality connections to a channel.
	realityCh := make(chan net.Conn, 256)
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

	// Test a few representative message types.
	testTypes := []byte{0, 1, 5, 6, 7, 9, 10, 12, 13, 244}

	for _, msgType := range testTypes {
		go func(b byte) {
			conn, _ := net.Dial("tcp", addr)
			defer conn.Close()
			conn.Write([]byte{b, 0x01})
			time.Sleep(50 * time.Millisecond)
		}(msgType)
	}

	for i := 0; i < len(testTypes); i++ {
		select {
		case conn := <-mt.StreamCh():
			buf := make([]byte, 2)
			n, _ := io.ReadFull(conn, buf)
			if n != 2 {
				t.Fatalf("expected 2 bytes, got %d", n)
			}
			conn.Close()
		case <-realityCh:
			t.Fatal("memberlist message type was routed to Reality instead of StreamCh")
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out at iteration %d", i)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Verify all 256 possible first bytes are routed correctly
// ──────────────────────────────────────────────────────────────────────────────

func TestMuxDemux_AllByteValues(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	rl := mt.RealityListener()
	defer rl.Close()

	// Start a background goroutine that forwards Reality connections to a channel.
	realityCh := make(chan net.Conn, 256)
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

	// Also accept mesh-internal connections (0x4D marker).
	meshCh := mt.MeshListener()
	defer meshCh.Close()
	meshConnCh := make(chan net.Conn, 256)
	go func() {
		for {
			conn, err := meshCh.Accept()
			if err != nil {
				close(meshConnCh)
				return
			}
			meshConnCh <- conn
		}
	}()

	// Also accept HTTP connections (G/P/H first byte).
	httpLn := mt.HTTPListener()
	defer httpLn.Close()
	httpConnCh := make(chan net.Conn, 256)
	go func() {
		for {
			conn, err := httpLn.Accept()
			if err != nil {
				close(httpConnCh)
				return
			}
			httpConnCh <- conn
		}
	}()

	for b := 0; b < 256; b++ {
		firstByte := byte(b)

		go func(fb byte) {
			conn, _ := net.Dial("tcp", addr)
			defer conn.Close()
			conn.Write([]byte{fb, 0x01})
			time.Sleep(30 * time.Millisecond)
		}(firstByte)

		isTLS := firstByte == tlsHandshakeRecordType
		isMesh := firstByte == meshInternalMarker
		isHTTP := firstByte == 'G' || firstByte == 'P' || firstByte == 'H'

		select {
		case conn := <-mt.StreamCh():
			if isTLS {
				conn.Close()
				t.Fatalf("byte 0x%02x (TLS) was routed to StreamCh instead of Reality", firstByte)
			}
			if isMesh {
				conn.Close()
				t.Fatalf("byte 0x%02x (mesh) was routed to StreamCh instead of MeshCh", firstByte)
			}
			if isHTTP {
				conn.Close()
				t.Fatalf("byte 0x%02x (HTTP) was routed to StreamCh instead of HTTPCh", firstByte)
			}
			buf := make([]byte, 2)
			n, _ := io.ReadFull(conn, buf)
			if n != 2 || buf[0] != firstByte {
				t.Fatalf("byte 0x%02x: data mismatch (got %v)", firstByte, buf[:n])
			}
			conn.Close()
		case conn := <-realityCh:
			if !isTLS {
				conn.Close()
				t.Fatalf("byte 0x%02x was routed to Reality instead of StreamCh", firstByte)
			}
			buf := make([]byte, 2)
			n, _ := io.ReadFull(conn, buf)
			if n != 2 || buf[0] != firstByte {
				t.Fatalf("byte 0x%02x: data mismatch (got %v)", firstByte, buf[:n])
			}
			conn.Close()
		case conn := <-meshConnCh:
			if !isMesh {
				conn.Close()
				t.Fatalf("byte 0x%02x was routed to MeshCh instead of StreamCh", firstByte)
			}
			// Mesh-internal path: the 0x4D marker byte was consumed by
			// MuxTransport peek (no connWithPrefix replay), so only the
			// remaining data (0x01) is readable.
			buf := make([]byte, 1)
			n, _ := io.ReadFull(conn, buf)
			if n != 1 || buf[0] != 0x01 {
				t.Fatalf("byte 0x%02x: data mismatch (got %v)", firstByte, buf[:n])
			}
			conn.Close()
		case conn := <-httpConnCh:
			if !isHTTP {
				conn.Close()
				t.Fatalf("byte 0x%02x was routed to HTTPCh instead of StreamCh", firstByte)
			}
			// HTTP path: the first byte is replayed via bufferedConn, so
			// both the first byte and 0x01 are readable.
			buf := make([]byte, 2)
			n, _ := io.ReadFull(conn, buf)
			if n != 2 || buf[0] != firstByte {
				t.Fatalf("byte 0x%02x: data mismatch (got %v)", firstByte, buf[:n])
			}
			conn.Close()
		case <-time.After(3 * time.Second):
			t.Fatalf("byte 0x%02x: timed out", firstByte)
		}
	}
}

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

// ──────────────────────────────────────────────────────────────────────────────
// Dual-family UDP binding (fixed port)
// ──────────────────────────────────────────────────────────────────────────────

// TestMuxTransport_DualFamilyUDPFixedPort pins the dual-family binding:
// a fixed (non-zero) UDP port must produce TWO sockets — an IPv6 [::]
// socket (V6ONLY=1) and an IPv4 0.0.0.0 socket — and UDPConnFor must
// return the right socket per remote family. This path is only taken
// with a fixed port; the ephemeral (UDPPort=0) tests exercise the
// single-socket branch, so without this test the dual-family code has
// zero coverage.
func TestMuxTransport_DualFamilyUDPFixedPort(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer tcpLn.Close()
	port := tcpLn.Addr().(*net.TCPAddr).Port

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: tcpLn,
		BindAddr:    "0.0.0.0",
		UDPPort:     port,
	})
	if err != nil {
		t.Fatalf("NewMuxTransport (fixed port): %v", err)
	}
	defer mt.Shutdown()

	if len(mt.udpConns) != 2 {
		t.Fatalf("expected 2 UDP sockets, got %d", len(mt.udpConns))
	}
	var v4, v6 *net.UDPConn
	for _, c := range mt.udpConns {
		la := c.LocalAddr().(*net.UDPAddr)
		if la.IP.To4() != nil {
			v4 = c
		} else {
			v6 = c
		}
	}
	if v4 == nil || v6 == nil {
		t.Fatalf("expected one IPv4 and one IPv6 socket (v4=%v v6=%v)", v4 != nil, v6 != nil)
	}
	if p := v4.LocalAddr().(*net.UDPAddr).Port; p != port {
		t.Errorf("IPv4 socket port = %d, want %d", p, port)
	}
	if p := v6.LocalAddr().(*net.UDPAddr).Port; p != port {
		t.Errorf("IPv6 socket port = %d, want %d", p, port)
	}

	// UDPConnFor must select by family.
	if got := mt.UDPConnFor(net.ParseIP("8.8.8.8")); got != v4 {
		t.Error("UDPConnFor(IPv4) did not return the IPv4 socket")
	}
	if got := mt.UDPConnFor(net.ParseIP("2606:4700::1111")); got != v6 {
		t.Error("UDPConnFor(IPv6) did not return the IPv6 socket")
	}
	// v4-mapped IPv6 (::ffff:8.8.8.8) is treated as IPv4.
	if got := mt.UDPConnFor(net.ParseIP("::ffff:8.8.8.8")); got != v4 {
		t.Error("UDPConnFor(v4-mapped IPv6) did not return the IPv4 socket")
	}
}

// TestMuxTransport_UDPConnForNoMatch ensures a family mismatch returns
// nil (an explicit error upstream) instead of silently falling back to
// the first socket — the regression that made [::] sockets send IPv4
// frames with a ::ffff: mapped source that some firewalls drop.
func TestMuxTransport_UDPConnForNoMatch(t *testing.T) {
	mt, err := NewMuxTransport(MuxTransportConfig{
		BindAddr: "127.0.0.1",
		UDPPort:  0,
	})
	if err != nil {
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()
	// The loopback bind produces an IPv4 socket; a pure IPv6 remote
	// must NOT match it.
	if got := mt.UDPConnFor(net.ParseIP("2606:4700::1111")); got != nil {
		t.Errorf("UDPConnFor(IPv6) on IPv4-only transport = %v, want nil", got.LocalAddr())
	}
}
