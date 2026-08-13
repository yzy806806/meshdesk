package mesh

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestUDPStreamFragmentedReassembly verifies that a large Write on one
// side (split into multiple sub-udpMaxPayload frames) is reassembled
// correctly by io.ReadFull on the other side — the fragmentation path
// introduced for restricted links (>~60B datagrams dropped).
func TestUDPStreamFragmentedReassembly(t *testing.T) {
	// Two real UDP sockets connected through a local loopback pair.
	addrA, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connA, err := net.ListenUDP("udp", addrA)
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	addrB, _ := net.ResolveUDPAddr("udp", connA.LocalAddr().String())

	scA := newUDPStreamConn(connA, addrB)
	scB := newUDPStreamConn(connA, addrA) // same socket pair for loopback

	// Feed loop: each side's socket delivers to the other's handlePacket.
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := connA.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			if from.String() == addrB.String() {
				scB.handlePacket(cp)
			} else {
				scA.handlePacket(cp)
			}
		}
	}()

	// 200B payload — must be split into ceil(200/40) = 5 frames.
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 200)
		_, err := io.ReadFull(scB, buf)
		if err != nil {
			done <- err
			return
		}
		for i := range buf {
			if buf[i] != byte(i) {
				done <- errFragMismatch
				return
			}
		}
		done <- nil
	}()

	time.Sleep(100 * time.Millisecond)
	if _, err := scA.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reassembly: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("reassembly timeout")
	}
}

var errFragMismatch = &net.AddrError{Err: "fragment payload mismatch", Addr: "test"}
