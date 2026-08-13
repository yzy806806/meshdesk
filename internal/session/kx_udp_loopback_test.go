package session

import (
	"net"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/identity"
)

// TestKeyExchangeUDP_Loopback runs a full Client/Server key exchange
// over a real UDP loopback pair (not a pipe) — isolates wire-level
// framing from the mesh UDP ARQ layer. If this passes, the mesh-layer
// framing (routeMeshPacket/0x4D strip/udpStreamConn) is the suspect.
func TestKeyExchangeUDP_Loopback(t *testing.T) {
	// Two identities (A initiates, B responds).
	idA, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate A: %v", err)
	}
	idB, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate B: %v", err)
	}

	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()

	// Server goroutine: read one datagram (the 0x4D marker frame),
	// then run ServerKeyExchange on a conn wrapper that reads further
	// datagrams from the same socket (mimics udpStreamConn framing
	// minus ARQ: marker frame then raw msg1/msg2 datagrams).
	done := make(chan error, 1)
	go func() {
		// Read the marker frame.
		buf := make([]byte, 2048)
		n, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			done <- err
			return
		}
		if n < 1 || buf[0] != 0x4D {
			done <- errUDPMarker
			return
		}
		// Wrap: subsequent datagrams carry raw key-exchange frames.
		// Bind the peer (the client's address) so writes go back to it.
		srv := &udpLoopConn{c: serverConn, peer: addr}
		_, _, err = ServerKeyExchange(srv, idB)
		done <- err
	}()

	// Client: send the 0x4D marker frame, then ClientKeyExchange over
	// the same socket.
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientConn.Close()
	serverAddr2, _ := net.ResolveUDPAddr("udp", serverConn.LocalAddr().String())
	if _, err := clientConn.WriteToUDP([]byte{0x4D}, serverAddr2); err != nil {
		t.Fatalf("marker: %v", err)
	}
	cli := &udpLoopConn{c: clientConn, peer: serverAddr2}
	cli.SetDeadline(time.Now().Add(10 * time.Second))

	_, peerID, err := ClientKeyExchange(cli, idA)
	if err != nil {
		t.Fatalf("client kx: %v", err)
	}
	if peerID != idB.PublicKey {
		t.Fatalf("peer id mismatch")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server kx: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("server kx timeout")
	}
}

var errUDPMarker = &net.AddrError{Err: "bad marker", Addr: "udp"}

// udpLoopConn adapts a *net.UDPConn to net.Conn for key exchange over
// raw datagrams (one msg per datagram — the mesh layer's framing).
type udpLoopConn struct {
	c    *net.UDPConn
	peer *net.UDPAddr
	buf  []byte
}

func (u *udpLoopConn) Read(b []byte) (int, error) {
	if len(u.buf) > 0 {
		n := copy(b, u.buf)
		u.buf = u.buf[n:]
		return n, nil
	}
	n, _, err := u.c.ReadFromUDP(b)
	return n, err
}

func (u *udpLoopConn) Write(b []byte) (int, error) {
	if u.peer == nil {
		return u.c.Write(b)
	}
	return u.c.WriteToUDP(b, u.peer)
}

func (u *udpLoopConn) Close() error                       { return u.c.Close() }
func (u *udpLoopConn) LocalAddr() net.Addr                { return u.c.LocalAddr() }
func (u *udpLoopConn) RemoteAddr() net.Addr               { return u.c.RemoteAddr() }
func (u *udpLoopConn) SetDeadline(t time.Time) error      { return u.c.SetDeadline(t) }
func (u *udpLoopConn) SetReadDeadline(t time.Time) error  { return u.c.SetReadDeadline(t) }
func (u *udpLoopConn) SetWriteDeadline(t time.Time) error { return u.c.SetWriteDeadline(t) }
