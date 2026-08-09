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

// DialUDPStream initiates a UDP mesh stream to a remote address.
// Sends the 0x4D-marker first frame and registers the stream so the
// remote's replies are fed to its ARQ state machine. The caller then
// runs the mesh key exchange + smux over the returned conn.
func (m *udpMeshManager) DialUDPStream(local *net.UDPConn, remote *net.UDPAddr) (*udpStreamConn, error) {
	key := remote.String()

	m.mu.Lock()
	if existing, ok := m.streams[key]; ok {
		m.mu.Unlock()
		return existing, nil
	}
	sc := newUDPStreamConn(local, remote)
	m.streams[key] = sc
	m.mu.Unlock()

	// Send the first frame: ARQ DATA with payload = 0x4D marker.
	payload := []byte{meshInternalMarker}
	frame := make([]byte, udpFrameHeaderLen+len(payload))
	frame[0] = udpFrameTypeData
	binary.BigEndian.PutUint32(frame[1:5], 0)
	binary.BigEndian.PutUint32(frame[5:9], 0)
	binary.BigEndian.PutUint16(frame[9:11], uint16(len(payload)))
	copy(frame[udpFrameHeaderLen:], payload)
	if _, err := local.WriteToUDP(frame, remote); err != nil {
		m.mu.Lock()
		delete(m.streams, key)
		m.mu.Unlock()
		sc.Close()
		return nil, err
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

	return sc, nil
}

// HasStream reports whether a UDP mesh stream exists for the address.
func (m *udpMeshManager) HasStream(addr *net.UDPAddr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.streams[addr.String()]
	return ok
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
