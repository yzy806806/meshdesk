package mesh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/identity"
)

// Tests the multipath-D UDP TUN stream: first-frame Ed25519 auth,
// anti-replay timestamp, and framed TUN data flow between two UDP
// endpoints sharing one manager (as on a real node's shared 52888).
func TestTUNUDPStream_AuthAndData(t *testing.T) {
	idA, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity A: %v", err)
	}
	idB, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity B: %v", err)
	}
	_ = idB

	// Two loopback UDP sockets + one manager on each side.
	sa, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer sa.Close()
	sb, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer sb.Close()

	mgrA := newUDPMeshManager()
	mgrB := newUDPMeshManager()
	// B authenticates: A's pubkey must verify the signature.
	mgrB.SetTUNUDPAuthValidator(func(pubKeyHex string, data []byte, sigHex string) (string, bool) {
		t.Logf("B validator: pk=%s len(sig)=%d", pubKeyHex[:8], len(sigHex))
		if pubKeyHex != idA.PublicKey {
			t.Log("B validator: pubkey mismatch")
			return "", false
		}
		if !identity.Verify(pubKeyHex, data, sigHex) {
			t.Log("B validator: signature verify FAILED")
			return "", false
		}
		return pubKeyHex, true
	})

	// Pump B's socket into B's manager (routes TUN packets).
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := sb.ReadFromUDP(buf)
			if err != nil {
				t.Logf("B pump exit: %v", err)
				return
			}
			t.Logf("B pump: %d bytes from %s first=%02x", n, addr, buf[0])
			cp := make([]byte, n)
			copy(cp, buf[:n])
			mgrB.routeUDPPacket(sb, addr, cp, nil)
		}
	}()

	// A dials B with an auth header signed by A.
	authA := buildTestAuthHeader(t, idA)
	remoteB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sb.LocalAddr().(*net.UDPAddr).Port}
	t.Logf("A dialing B at %s", remoteB)

	// A-side pump: feeds A's manager so the peer's ACK of the
	// handshake frame is processed (DialTUNStream now waits for it).
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := sa.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			mgrA.routeUDPPacket(sa, addr, cp, nil)
		}
	}()

	streamA, err := mgrA.DialTUNStream(sa, remoteB, authA)
	if err != nil {
		t.Fatalf("DialTUNStream: %v", err)
	}
	defer streamA.Close()
	t.Log("A stream established, writing data frame")

	// A writes a framed TUN packet.
	payload := []byte{0x45, 0x00, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	if _, err := streamA.Write(frame); err != nil {
		t.Fatalf("stream write: %v", err)
	}

	// B should receive the authenticated stream and the framed packet.
	select {
	case conn := <-mgrB.TunCh():
		cp, ok := conn.(*connWithPeer)
		if !ok {
			t.Fatalf("expected connWithPeer, got %T", conn)
		}
		if cp.PeerID() != idA.PublicKey {
			t.Fatalf("peer id mismatch: %s", cp.PeerID())
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		got := make([]byte, 64)
		n, err := conn.Read(got)
		if err != nil {
			t.Fatalf("read from stream: %v", err)
		}
		if !bytes.Equal(got[:n], frame) {
			t.Fatalf("data mismatch: got %x want %x", got[:n], frame)
		}
		t.Logf("UDP TUN stream OK: authenticated peer %s..., got %d bytes", cp.PeerID()[:8], n)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TUN stream on B")
	}
}

// TestTUNUDPStream_RejectsUnauthenticated ensures a frame without a
// valid signature is silently dropped (no stream delivered).
func TestTUNUDPStream_RejectsUnauthenticated(t *testing.T) {
	sb, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sb.Close()

	mgrB := newUDPMeshManager()
	mgrB.SetTUNUDPAuthValidator(func(pubKeyHex string, data []byte, sigHex string) (string, bool) {
		return "", false // reject everything
	})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := sb.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			mgrB.routeUDPPacket(sb, addr, cp, nil)
		}
	}()

	// Attacker frame: marker + garbage auth.
	payload := append([]byte{tunUDPMarker}, bytes.Repeat([]byte{'x'}, tunUDPAuthLen)...)
	frame := make([]byte, udpFrameHeaderLen+len(payload))
	frame[0] = udpFrameTypeData
	binary.BigEndian.PutUint16(frame[9:11], uint16(len(payload)))
	copy(frame[udpFrameHeaderLen:], payload)
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sb.LocalAddr().(*net.UDPAddr).Port}
	if _, err := sb.WriteToUDP(frame, remote); err != nil {
		t.Fatalf("send attacker frame: %v", err)
	}

	select {
	case conn := <-mgrB.TunCh():
		conn.Close()
		t.Fatal("DEFECT: unauthenticated TUN stream was accepted")
	case <-time.After(500 * time.Millisecond):
		t.Log("unauthenticated frame correctly rejected")
	}
}

// TestTUNUDPStream_OversizedLengthNoPanic reproduces the critical
// crash: a tiny datagram (12 bytes) whose length field claims a large
// payload must be dropped — NOT sliced (slice bounds panic would kill
// the whole process).
func TestTUNUDPStream_OversizedLengthNoPanic(t *testing.T) {
	sb, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sb.Close()

	mgrB := newUDPMeshManager()
	mgrB.SetTUNUDPAuthValidator(func(pubKeyHex string, data []byte, sigHex string) (string, bool) {
		return "", false
	})
	pumped := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := sb.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			// A panic here would propagate to the test process.
			mgrB.routeUDPPacket(sb, addr, cp, nil)
			select {
			case pumped <- struct{}{}:
			default:
			}
		}
	}()

	// 12-byte datagram: header + marker only, but plen claims 203.
	frame := make([]byte, udpFrameHeaderLen+1)
	frame[0] = udpFrameTypeData
	binary.BigEndian.PutUint16(frame[9:11], 1+tunUDPAuthLen) // 203
	frame[udpFrameHeaderLen] = tunUDPMarker
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sb.LocalAddr().(*net.UDPAddr).Port}
	if _, err := sb.WriteToUDP(frame, remote); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case <-pumped:
		t.Log("oversized-length datagram dropped without panic")
	case <-time.After(2 * time.Second):
		t.Fatal("packet was not processed")
	}
}

// TestTUNUDPStream_NoAckFailsDial reproduces the firewall case: a UDP
// path where the peer never ACKs the handshake (datagrams dropped) must
// FAIL the dial so the tun-forwarder falls back to TCP — it must NOT
// return an "established" stream that silently black-holes traffic.
func TestTUNUDPStream_NoAckFailsDial(t *testing.T) {
	sa, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer sa.Close()

	// A UDP socket with no peer listening/responding on the other end.
	sb, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	// Do NOT pump B — nothing consumes/acks the handshake frame.
	_ = sb

	mgrA := newUDPMeshManager()
	authA := buildTestAuthHeader(t, mustIdentity(t))
	remoteB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sb.LocalAddr().(*net.UDPAddr).Port}

	start := time.Now()
	_, err = mgrA.DialTUNStream(sa, remoteB, authA)
	if err == nil {
		t.Fatal("DEFECT: dial succeeded with no ACK — UDP-preferred path would black-hole traffic")
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("dial took too long (%v) — confirmation wait is too generous", elapsed)
	}
	t.Logf("dial correctly failed after %v: %v", elapsed, err)
}

func mustIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	return id
}

func buildTestAuthHeader(t *testing.T, id *identity.Identity) []byte {
	t.Helper()
	now := time.Now().Unix()
	tsStr := fmt.Sprintf("%010d", now)
	pub := id.PublicKey
	signed := []byte(pub + tsStr)
	sig, err := id.Sign(signed)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	h := make([]byte, 0, tunUDPAuthLen)
	h = append(h, pub...)
	h = append(h, tsStr...)
	h = append(h, sig...)
	return h
}
