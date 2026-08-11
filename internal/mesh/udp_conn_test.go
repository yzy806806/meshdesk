package mesh

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// newUDPStreamPair creates two connected UDP sockets and wraps each in
// a udpStreamConn pointing at the other, wired to route packets via
// handlePacket (simulating the shared listen loop).
func newUDPStreamPair(t *testing.T) (*udpStreamConn, *udpStreamConn) {
	t.Helper()
	c1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen c1: %v", err)
	}
	c2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen c2: %v", err)
	}
	addr1 := c1.LocalAddr().(*net.UDPAddr)
	addr2 := c2.LocalAddr().(*net.UDPAddr)

	s1 := newUDPStreamConn(c1, addr2)
	s2 := newUDPStreamConn(c2, addr1)

	// Wire the two sockets together: each conn's handlePacket is fed
	// from the OTHER socket's incoming datagrams. s1's peer is addr2,
	// so datagrams arriving on c1 (sent by c2) go to s1; datagrams on
	// c2 (sent by c1) go to s2.
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := c1.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if addr.String() == addr2.String() {
				s1.handlePacket(append([]byte(nil), buf[:n]...))
			}
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := c2.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if addr.String() == addr1.String() {
				s2.handlePacket(append([]byte(nil), buf[:n]...))
			}
		}
	}()

	return s1, s2
}

// TestUDPStream_Echo verifies a round-trip payload survives.
func TestUDPStream_Echo(t *testing.T) {
	a, b := newUDPStreamPair(t)
	defer a.Close()
	defer b.Close()

	msg := bytes.Repeat([]byte("hello-mesh-"), 100) // 1100 bytes, multi-frame
	go func() {
		a.Write(msg)
	}()

	got := make([]byte, len(msg))
	_, err := io.ReadFull(b, got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("data mismatch: got %d bytes, want %d", len(got), len(msg))
	}
}

// TestUDPStream_LargeTransfer verifies a multi-window transfer (many
// frames, exercising window blocking + ACK advance).
func TestUDPStream_LargeTransfer(t *testing.T) {
	a, b := newUDPStreamPair(t)
	defer a.Close()
	defer b.Close()

	size := 256 * 1024
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i * 31)
	}
	go func() {
		a.Write(data)
	}()

	got := make([]byte, size)
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("large transfer mismatch (%d bytes)", size)
	}
}

// TestUDPStream_OutOfOrder verifies frames arriving out of order are
// reordered by seq.
func TestUDPStream_OutOfOrder(t *testing.T) {
	a, b := newUDPStreamPair(t)
	defer a.Close()
	defer b.Close()

	// Write three small messages, then read them in order.
	go func() {
		a.Write([]byte("one"))
		a.Write([]byte("two"))
		a.Write([]byte("three"))
	}()

	var all []byte
	buf := make([]byte, 3)
	deadline := time.After(5 * time.Second)
	for len(all) < len("onetwothree") {
		n, err := b.Read(buf)
		if err != nil {
			t.Fatalf("read: %v (got %q)", err, all)
		}
		all = append(all, buf[:n]...)
		select {
		case <-deadline:
			t.Fatalf("timeout, got %q", all)
		default:
		}
	}
	if string(all) != "onetwothree" {
		t.Fatalf("order mismatch: %q", all)
	}
}

// TestUDPStream_Fin verifies EOF on FIN.
func TestUDPStream_Fin(t *testing.T) {
	a, b := newUDPStreamPair(t)
	defer a.Close()
	defer b.Close()

	a.Write([]byte("data"))
	a.Close()

	got := make([]byte, 4)
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read data: %v", err)
	}
	if _, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected EOF after FIN, got %v", err)
	}
}

// TestSeqBefore verifies the modular sequence comparison.
func TestSeqBefore(t *testing.T) {
	if !seqBefore(5, 10) {
		t.Fatal("5 should be before 10")
	}
	if seqBefore(10, 5) {
		t.Fatal("10 should not be before 5")
	}
	// Wrap-around: near max.
	if !seqBefore(udpMaxSeq-2, 1) {
		t.Fatal("wrap: max-2 should be before 1")
	}
	if seqBefore(1, udpMaxSeq-2) {
		t.Fatal("wrap: 1 should not be before max-2")
	}
}
