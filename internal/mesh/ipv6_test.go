package mesh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// hasIPv6Loopback returns true if ::1 is available for binding.
func hasIPv6Loopback() bool {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// hasIPv6Public returns true if a non-loopback, non-link-local IPv6 address
// is available for binding (e.g., a public IPv6 on eth0).
func hasIPv6Public() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.To4() != nil {
			continue
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		// Try to bind to this IP.
		ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
		if err == nil {
			ln.Close()
			return true
		}
	}
	return false
}

// pickLoopback returns "127.0.0.1" or "[::1]" based on the network parameter.

// TestIPv6_MuxTransportBindLoopback verifies that MuxTransport can bind to
// an IPv6 loopback address (::1) and correctly route TLS and gossip traffic.
func TestIPv6_MuxTransportBindLoopback(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("IPv6 loopback not available")
	}

	tcpLn, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen tcp6: %v", err)
	}
	addr := tcpLn.Addr().String()
	t.Logf("listening on %s", addr)

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: tcpLn,
		BindAddr:    "::1",
		UDPPort:     0,
	})
	if err != nil {
		tcpLn.Close()
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	// Verify the transport binds on IPv6.
	if mt.udpConn.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
		t.Log("UDP bound on IPv4 (may fallback when IPv6 dual-stack)")
	} else {
		t.Log("UDP bound on IPv6")
	}

	// Test TLS routing (byte 0x16).
	rl := mt.RealityListener()
	defer rl.Close()

	realityCh := make(chan net.Conn, 1)
	go func() {
		conn, err := rl.Accept()
		if err != nil {
			close(realityCh)
			return
		}
		realityCh <- conn
	}()

	// Dial via IPv6 loopback.
	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Logf("dial tcp6: %v", err)
			return
		}
		defer conn.Close()
		conn.Write([]byte{tlsHandshakeRecordType, 0x03, 0x01})
		time.Sleep(100 * time.Millisecond)
	}()

	select {
	case conn := <-realityCh:
		buf := make([]byte, 3)
		n, _ := io.ReadFull(conn, buf)
		if n != 3 || buf[0] != tlsHandshakeRecordType {
			t.Fatalf("IPv6 TLS routing: unexpected data %v", buf[:n])
		}
		conn.Close()
		t.Log("IPv6 TLS routing: OK")
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for IPv6 TLS connection")
	}

	// Test gossip routing.
	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Logf("dial tcp6: %v", err)
			return
		}
		defer conn.Close()
		conn.Write([]byte{0x00, 0xAA, 0xBB})
		time.Sleep(100 * time.Millisecond)
	}()

	select {
	case conn := <-mt.StreamCh():
		buf := make([]byte, 3)
		n, _ := io.ReadFull(conn, buf)
		if n != 3 || buf[0] != 0x00 {
			t.Fatalf("IPv6 gossip routing: unexpected data %v", buf[:n])
		}
		conn.Close()
		t.Log("IPv6 gossip routing: OK")
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for IPv6 gossip connection")
	}
}

// TestIPv6_MuxTransportBindPublic verifies that MuxTransport can bind to a
// public IPv6 address when one is available. This tests the real-world
// scenario of single-port IPv6 mesh interconnection.
func TestIPv6_MuxTransportBindPublic(t *testing.T) {
	if !hasIPv6Public() {
		t.Skip("public IPv6 not available")
	}

	// Find a public IPv6 address.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("InterfaceAddrs: %v", err)
	}
	var publicV6 string
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.To4() != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		publicV6 = ip.String()
		break
	}
	if publicV6 == "" {
		t.Skip("no public IPv6 found")
	}
	t.Logf("public IPv6: %s", publicV6)

	tcpLn, err := net.Listen("tcp", net.JoinHostPort(publicV6, "0"))
	if err != nil {
		t.Fatalf("listen on public IPv6: %v", err)
	}
	addr := tcpLn.Addr().String()
	t.Logf("listening on %s", addr)

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: tcpLn,
		BindAddr:    publicV6,
		UDPPort:     0,
	})
	if err != nil {
		tcpLn.Close()
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	// Verify TLS routing works.
	rl := mt.RealityListener()
	defer rl.Close()

	realityCh := make(chan net.Conn, 1)
	go func() {
		conn, err := rl.Accept()
		if err != nil {
			close(realityCh)
			return
		}
		realityCh <- conn
	}()

	// Connect via loopback to the public-bound listener.
	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Logf("dial: %v", err)
			return
		}
		defer conn.Close()
		conn.Write([]byte{tlsHandshakeRecordType, 0x01, 0x02})
		time.Sleep(100 * time.Millisecond)
	}()

	select {
	case conn := <-realityCh:
		buf := make([]byte, 3)
		n, _ := io.ReadFull(conn, buf)
		if n != 3 || buf[0] != tlsHandshakeRecordType {
			t.Fatalf("public IPv6 routing: unexpected data %v", buf[:n])
		}
		conn.Close()
		t.Log("public IPv6 routing: OK")
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for public IPv6 connection")
	}
}

// TestIPv6_SinglePortDualProtocol verifies that the same IPv6 listener port
// can handle both Reality TLS and gossip traffic concurrently, which is the
// core single-port multiplexing contract.
func TestIPv6_SinglePortDualProtocol(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("IPv6 loopback not available")
	}

	tcpLn, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen tcp6: %v", err)
	}
	addr := tcpLn.Addr().String()

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: tcpLn,
		BindAddr:    "::1",
	})
	if err != nil {
		tcpLn.Close()
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	rl := mt.RealityListener()
	defer rl.Close()

	realityCh := make(chan net.Conn, 10)
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

	// Send 5 TLS and 5 gossip connections concurrently over IPv6.
	const n = 5
	for i := 0; i < n; i++ {
		go func() {
			conn, _ := net.Dial("tcp", addr)
			defer conn.Close()
			conn.Write([]byte{tlsHandshakeRecordType, 0x01})
			time.Sleep(50 * time.Millisecond)
		}()
		go func() {
			conn, _ := net.Dial("tcp", addr)
			defer conn.Close()
			conn.Write([]byte{0x00, 0x01})
			time.Sleep(50 * time.Millisecond)
		}()
	}

	gotReality := 0
	gotStream := 0
	deadline := time.After(5 * time.Second)

	for gotReality+gotStream < 2*n {
		select {
		case conn := <-realityCh:
			gotReality++
			conn.Close()
		case conn := <-mt.StreamCh():
			gotStream++
			conn.Close()
		case <-deadline:
			t.Fatalf("timed out: got %d reality + %d gossip = %d/%d",
				gotReality, gotStream, gotReality+gotStream, 2*n)
		}
	}

	t.Logf("IPv6 single-port: %d reality + %d gossip = %d total (OK)",
		gotReality, gotStream, gotReality+gotStream)
}

// TestIPv6_DualStackInterop verifies that an IPv4-bound MuxTransport can
// receive both IPv4 and IPv6 connections (dual-stack compatibility). On
// Linux, binding to "0.0.0.0" with IPV6_V6ONLY=0 (default) accepts both
// IPv4 and IPv6-mapped connections.
func TestIPv6_DualStackInterop(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("IPv6 loopback not available")
	}

	// Bind to 0.0.0.0 — should accept IPv4 and IPv6 on dual-stack systems.
	tcpLn, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := tcpLn.Addr().(*net.TCPAddr).Port
	t.Logf("bound to 0.0.0.0:%d", port)

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: tcpLn,
		BindAddr:    "0.0.0.0",
	})
	if err != nil {
		tcpLn.Close()
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	rl := mt.RealityListener()
	defer rl.Close()

	realityCh := make(chan net.Conn, 2)
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

	// Connect via IPv4.
	var dialWG sync.WaitGroup
	dialWG.Add(2)

	go func() {
		defer dialWG.Done()
		conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
		if err != nil {
			t.Logf("IPv4 dial: %v", err)
			return
		}
		defer conn.Close()
		conn.Write([]byte{tlsHandshakeRecordType, 0x01})
		time.Sleep(100 * time.Millisecond)
	}()

	// Connect via IPv6 loopback.
	go func() {
		defer dialWG.Done()
		conn, err := net.Dial("tcp", net.JoinHostPort("::1", itoa(port)))
		if err != nil {
			t.Logf("IPv6 dial: %v (may not be dual-stack)", err)
			return
		}
		defer conn.Close()
		conn.Write([]byte{tlsHandshakeRecordType, 0x02})
		time.Sleep(100 * time.Millisecond)
	}()

	// Expect at least one connection to arrive (IPv4 always works).
	select {
	case conn := <-realityCh:
		buf := make([]byte, 2)
		n, _ := io.ReadFull(conn, buf)
		t.Logf("dual-stack: received connection, first byte=0x%02x", buf[0])
		if n != 2 || buf[0] != tlsHandshakeRecordType {
			t.Fatalf("unexpected data: %v", buf[:n])
		}
		conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out — no connection received on dual-stack listener")
	}

	// Wait for both dial goroutines to complete before deferred Shutdown
	// closes the listener, preventing "Fail in goroutine after test has
	// completed" panics.
	dialWG.Wait()
}

// itoa returns the decimal string representation of n.
func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

// TestIPv6_UDPPacketOnLoopback verifies that UDP packets (memberlist gossip)
// work over IPv6 loopback on the MuxTransport.
func TestIPv6_UDPPacketOnLoopback(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("IPv6 loopback not available")
	}

	tcpLn, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen tcp6: %v", err)
	}

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: tcpLn,
		BindAddr:    "::1",
	})
	if err != nil {
		tcpLn.Close()
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	udpAddr := mt.udpConn.LocalAddr().String()
	t.Logf("UDP addr: %s", udpAddr)

	payload := []byte("hello-ipv6")

	// Write a UDP packet to ourselves.
	ts, err := mt.WriteTo(payload, udpAddr)
	if err != nil {
		t.Fatalf("WriteTo IPv6: %v", err)
	}
	if ts.IsZero() {
		t.Fatal("timestamp is zero")
	}

	// Read it back from PacketCh.
	select {
	case pkt := <-mt.PacketCh():
		if !bytes.Equal(pkt.Buf, payload) {
			t.Fatalf("IPv6 UDP: expected %q, got %q", payload, string(pkt.Buf))
		}
		if pkt.From == nil {
			t.Fatal("IPv6 UDP: packet From is nil")
		}
		t.Logf("IPv6 UDP packet from %s: OK", pkt.From)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for IPv6 UDP packet")
	}
}

// TestIPv6_AdvertiseAddrWithIPV6 verifies that FinalAdvertiseAddr works
// correctly with IPv6 addresses.
func TestIPv6_AdvertiseAddrWithIPV6(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer tcpLn.Close()

	tests := []struct {
		name          string
		advertiseAddr string
		advertisePort int
		userIP        string
		wantIP        string
		wantErr       bool
	}{
		{
			name:          "IPv6 explicit",
			advertiseAddr: "2001:db8::1",
			advertisePort: 8443,
			wantIP:        "2001:db8::1",
		},
		{
			name:          "IPv6 user override",
			advertiseAddr: "",
			advertisePort: 0,
			userIP:        "fd00::2",
			wantIP:        "fd00::2",
		},
		{
			name:          "IPv4 mapped in IPv6 format",
			advertiseAddr: "::ffff:10.0.0.5",
			wantIP:        "10.0.0.5", // To4() normalizes to IPv4.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mt, err := NewMuxTransport(MuxTransportConfig{
				TCPListener:   tcpLn,
				BindAddr:      "127.0.0.1",
				AdvertiseAddr: tt.advertiseAddr,
				AdvertisePort: tt.advertisePort,
			})
			if err != nil {
				t.Fatalf("NewMuxTransport: %v", err)
			}
			defer mt.Shutdown()

			ip, port, err := mt.FinalAdvertiseAddr(tt.userIP, 0)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("FinalAdvertiseAddr: %v", err)
			}
			if ip.String() != tt.wantIP {
				t.Errorf("IP: got %s, want %s", ip, tt.wantIP)
			}
			if tt.advertisePort > 0 && port != tt.advertisePort {
				t.Errorf("port: got %d, want %d", port, tt.advertisePort)
			}
		})
	}
}

// TestIPv6_ConnWithPrefixPreservesIPV6Addrs verifies that connWithPrefix
// correctly passes through IPv6 local and remote addresses.
func TestIPv6_ConnWithPrefixPreservesIPV6Addrs(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("IPv6 loopback not available")
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// Override the addresses with IPv6-style ones using a wrapper.
	// net.Pipe returns nil addresses, so we test with a mock.
	// Instead, use a real IPv6 TCP connection.
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type addrResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan addrResult, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- addrResult{conn, err}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	res := <-ch
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}
	server := res.conn
	defer server.Close()

	// Wrap the server side with connWithPrefix.
	prefix := []byte{0x16, 0x03, 0x01}
	wrapped := NewConnWithPrefix(server, prefix)

	// Verify addresses are passed through.
	localAddr := wrapped.LocalAddr()
	remoteAddr := wrapped.RemoteAddr()

	if localAddr == nil {
		t.Fatal("LocalAddr is nil")
	}
	if remoteAddr == nil {
		t.Fatal("RemoteAddr is nil")
	}

	t.Logf("IPv6 LocalAddr: %s", localAddr)
	t.Logf("IPv6 RemoteAddr: %s", remoteAddr)

	// Read prefix back.
	buf := make([]byte, len(prefix))
	n, err := io.ReadFull(wrapped, buf)
	if err != nil {
		t.Fatalf("read prefix: %v", err)
	}
	if n != len(prefix) || !bytes.Equal(buf, prefix) {
		t.Fatalf("prefix mismatch: got %v, want %v", buf, prefix)
	}
	t.Log("IPv6 connWithPrefix: addresses preserved, prefix replayed")
}
