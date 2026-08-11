package mesh

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestUDPMesh_RouteAndStream verifies end-to-end: a datagram carrying
// the mesh marker on one transport is routed into a reliable ARQ stream
// and delivered (with the marker stripped) to the other side's meshCh.
func TestUDPMesh_RouteAndStream(t *testing.T) {
	// Two UDP sockets.
	c1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen c1: %v", err)
	}
	defer c1.Close()
	c2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen c2: %v", err)
	}
	defer c2.Close()

	addr1 := c1.LocalAddr().(*net.UDPAddr)
	addr2 := c2.LocalAddr().(*net.UDPAddr)

	meshCh1 := make(chan net.Conn, 8)
	meshCh2 := make(chan net.Conn, 8)
	m1 := newUDPMeshManager()
	m2 := newUDPMeshManager()

	// Relay: c1's incoming → m1 (peer addr2); c2's incoming → m2 (peer addr1).
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := c1.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if addr.String() == addr2.String() {
				m1.routeUDPPacket(c1, addr2, append([]byte(nil), buf[:n]...), meshCh1)
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
				m2.routeUDPPacket(c2, addr1, append([]byte(nil), buf[:n]...), meshCh2)
			}
		}
	}()

	// A sender on c1 writes a mesh frame: marker 0x4D + "hello".
	go func() {
		payload := append([]byte{meshInternalMarker}, []byte("hello")...)
		frame := make([]byte, udpFrameHeaderLen+len(payload))
		frame[0] = udpFrameTypeData
		binary.BigEndian.PutUint32(frame[1:5], 0)
		binary.BigEndian.PutUint32(frame[5:9], 0)
		binary.BigEndian.PutUint16(frame[9:11], uint16(len(payload)))
		copy(frame[udpFrameHeaderLen:], payload)
		c1.WriteToUDP(frame, addr2)
	}()

	// Receiver: m2's stream should appear on meshCh2 with "hello"
	// (the 0x4D marker stripped by the router).
	select {
	case sc := <-meshCh2:
		buf := make([]byte, 16)
		sc.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := sc.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("read stream: %v", err)
		}
		if string(buf[:n]) != "hello" {
			t.Fatalf("expected 'hello', got %q", buf[:n])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream not delivered to meshCh2")
	}
}
