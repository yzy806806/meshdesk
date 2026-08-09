package mesh

import (
	"encoding/binary"
	"net"
	"sync"
)

// ──────────────────────────────────────────────────────────────────────────
// UDP mesh data plane (T0.1/T0.2)
//
// The shared 52888 UDP socket carries both gossip (memberlist) and mesh
// data. Datagrams are routed by first byte:
//   - 0x4D (meshInternalMarker) → reliable per-remote stream (ARQ) →
//     meshCh → key exchange + smux session
//   - anything else → packetChIn (gossip)
//
// A remote address maps to exactly one udpStreamConn (the ARQ stream).
// The first datagram (carrying 0x4D) creates the stream; subsequent
// datagrams from the same address feed its ARQ state machine.
// ──────────────────────────────────────────────────────────────────────────

// udpMeshManager tracks per-remote UDP mesh streams.
type udpMeshManager struct {
	mu      sync.Mutex
	streams map[string]*udpStreamConn
}

func newUDPMeshManager() *udpMeshManager {
	return &udpMeshManager{streams: make(map[string]*udpStreamConn)}
}

// routeMeshPacket handles a UDP datagram that carries the mesh marker.
// Returns true if the packet was consumed as mesh data.
func (m *udpMeshManager) routeMeshPacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte, meshCh chan net.Conn) bool {
	if len(data) < udpFrameHeaderLen+1 {
		return false
	}
	key := addr.String()

	m.mu.Lock()
	sc, exists := m.streams[key]
	if !exists {
		sc = newUDPStreamConn(conn, addr)
		m.streams[key] = sc
	}
	m.mu.Unlock()

	// Strip the 0x4D marker from the FIRST frame's payload so the mesh
	// key exchange sees a clean stream (mirrors TCP: the peek consumed
	// the marker before the connection reaches the mesh path).
	firstFrame := !exists
	if firstFrame {
		plen := int(binary.BigEndian.Uint16(data[9:11]))
		if plen > 0 && len(data) > udpFrameHeaderLen && data[udpFrameHeaderLen] == meshInternalMarker {
			// Shift payload left by one, decrement length.
			copy(data[udpFrameHeaderLen:], data[udpFrameHeaderLen+1:])
			binary.BigEndian.PutUint16(data[9:11], uint16(plen-1))
			data = data[:len(data)-1]
		}
	}

	sc.handlePacket(data)

	if firstFrame {
		// Deliver the stream to the mesh accept loop. It will block on
		// Read until the peer's key-exchange bytes arrive (reassembled
		// by the ARQ layer), exactly like a TCP mesh connection.
		select {
		case meshCh <- sc:
		default:
			// Backpressure: queue full — the stream is still fed by
			// subsequent packets, the accept loop drains meshCh.
			go func(s *udpStreamConn) { meshCh <- s }(sc)
		}
		// Clean up when the stream closes.
		go func(s *udpStreamConn, k string) {
			<-s.done
			m.mu.Lock()
			if cur, ok := m.streams[k]; ok && cur == s {
				delete(m.streams, k)
			}
			m.mu.Unlock()
		}(sc, key)
	}
	return true
}

// routeUDPPacket dispatches a datagram by first byte. Returns true if
// consumed (mesh data), false if it should go to gossip.
//
// A UDP datagram is an ARQ frame: [type][seq][ack][len][payload]. The
// mesh marker (0x4D) lives at the START of the payload (data[11]) on
// the FIRST frame of a stream. Subsequent frames from an established
// stream carry arbitrary mesh bytes — they must ALL feed the stream.
func (m *udpMeshManager) routeUDPPacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte, meshCh chan net.Conn) bool {
	if len(data) < 1 {
		return false
	}
	key := addr.String()

	m.mu.Lock()
	sc, exists := m.streams[key]
	m.mu.Unlock()
	if exists {
		// Established stream: feed everything from this addr.
		sc.handlePacket(data)
		return true
	}

	// New stream candidate: ARQ DATA frame whose payload starts with
	// the mesh marker.
	if len(data) >= udpFrameHeaderLen+1 && data[0] == udpFrameTypeData && data[udpFrameHeaderLen] == meshInternalMarker {
		return m.routeMeshPacket(conn, addr, data, meshCh)
	}
	return false
}
