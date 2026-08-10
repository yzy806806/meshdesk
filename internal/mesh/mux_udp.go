package mesh

import (
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// debugTUNAuth enables verbose logging for the UDP TUN stream auth path.
const debugTUNAuth = false

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
// tunUDPMarker is the first payload byte of a TUN-data UDP stream's
// first frame. It must not collide with meshInternalMarker (0x4D) or a
// valid IP version nibble (IPv4 = 0x45, IPv6 = 0x60). 0x54 = 'T'.
const tunUDPMarker = 0x54

// tunUDPAuthLen is the fixed authentication header carried in the FIRST
// frame of a TUN UDP stream, right after the marker:
//
//	[pubkey 64 hex][ts 10 ascii][sig 128 hex]
//
// The signature covers (pubkey + ts) with the sender's Ed25519 key; ts
// is a unix timestamp with a ±10min window (anti-replay). The header
// is deliberately larger than udpMaxPayload can share with a TUN frame,
// so the first frame carries auth only — data follows on frame 2+.
const tunUDPAuthLen = 64 + 10 + 128

// tunUDPAuthWindow is the accepted clock skew for the auth timestamp.
const tunUDPAuthWindow = 10 * time.Minute

type udpMeshManager struct {
	mu         sync.Mutex
	streams    map[string]*udpStreamConn // mesh key-exchange streams (by remote addr)
	tunStreams map[string]*udpStreamConn // TUN data streams (by remote addr)
	tunCh      chan net.Conn             // accepted TUN streams → tun-forwarder
	// tunAuthValidator authenticates the first-frame auth header and
	// returns the verified peer identity hex. Set by MeshNode.
	tunAuthValidator func(pubKeyHex string, data []byte, sigHex string) (string, bool)
}

func newUDPMeshManager() *udpMeshManager {
	return &udpMeshManager{
		streams:    make(map[string]*udpStreamConn),
		tunStreams: make(map[string]*udpStreamConn),
		tunCh:      make(chan net.Conn, 64),
	}
}

// SetTUNUDPAuthValidator installs the callback that authenticates a TUN
// UDP stream's first-frame auth header (Ed25519 signature) and returns
// the verified peer identity hex.
func (m *udpMeshManager) SetTUNUDPAuthValidator(fn func(pubKeyHex string, data []byte, sigHex string) (string, bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunAuthValidator = fn
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
// the FIRST frame of a mesh stream; the TUN marker (0x54) marks a
// TUN-data stream. Established streams of either kind receive every
// subsequent frame from that address.
func (m *udpMeshManager) routeUDPPacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte, meshCh chan net.Conn) bool {
	if len(data) < 1 {
		return false
	}
	key := addr.String()

	m.mu.Lock()
	sc, exists := m.streams[key]
	tun, tunExists := m.tunStreams[key]
	m.mu.Unlock()
	if exists {
		// Established mesh stream: feed everything from this addr.
		sc.handlePacket(data)
		return true
	}
	if tunExists {
		// Established TUN stream: feed everything from this addr.
		tun.handlePacket(data)
		return true
	}

	// New stream candidates: ARQ DATA frame whose payload starts with
	// the mesh marker (key exchange) or the TUN marker (TUN data).
	if len(data) >= udpFrameHeaderLen+1 && data[0] == udpFrameTypeData {
		switch data[udpFrameHeaderLen] {
		case meshInternalMarker:
			return m.routeMeshPacket(conn, addr, data, meshCh)
		case tunUDPMarker:
			return m.routeTUNPacket(conn, addr, data)
		}
	}
	return false
}

// routeTUNPacket handles a UDP datagram that carries the TUN marker:
// authenticates the first-frame auth header (Ed25519 signature over
// pubkey+ts), creates (or reuses) the per-address TUN UDP stream, and
// delivers it to the TUN accept channel once — wrapped with the verified
// peer identity so the tun-forwarder can run anti-spoof/ACL checks.
func (m *udpMeshManager) routeTUNPacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte) bool {
	if len(data) < udpFrameHeaderLen+1 {
		return false
	}
	key := addr.String()

	m.mu.Lock()
	sc, exists := m.tunStreams[key]
	m.mu.Unlock()
	if exists {
		// Established (authenticated) TUN stream: feed everything.
		sc.handlePacket(data)
		return true
	}

	// First frame: [marker][pubkey 64][ts 10][sig 128] — auth only.
	plen := int(binary.BigEndian.Uint16(data[9:11]))
	if plen < 1+tunUDPAuthLen {
		return true // malformed first frame; drop quietly (consumed)
	}
	payload := data[udpFrameHeaderLen : udpFrameHeaderLen+plen]
	if payload[0] != tunUDPMarker {
		return false
	}
	pubKeyHex := string(payload[1 : 1+64])
	tsStr := string(payload[1+64 : 1+64+10])
	sigHex := string(payload[1+64+10 : 1+tunUDPAuthLen])

	// Timestamp anti-replay window.
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return true
	}
	now := time.Now().Unix()
	if ts < now-int64(tunUDPAuthWindow.Seconds()) || ts > now+int64(tunUDPAuthWindow.Seconds()) {
		return true
	}

	// Verify Ed25519 signature over (pubkey + ts).
	m.mu.Lock()
	validator := m.tunAuthValidator
	m.mu.Unlock()
	if validator == nil {
		return true // no validator wired — refuse (security)
	}
	signedData := []byte(pubKeyHex + tsStr)
	peerID, ok := validator(pubKeyHex, signedData, sigHex)
	if !ok {
		return true // auth failed; drop quietly
	}
	if debugTUNAuth {
		log.Printf("[tun-udp] routeTUNPacket: auth OK peer=%s from=%s", peerID[:8], addr)
	}

	m.mu.Lock()
	sc, exists = m.tunStreams[key]
	if !exists {
		sc = newUDPStreamConn(conn, addr)
		m.tunStreams[key] = sc
	}
	m.mu.Unlock()
	if debugTUNAuth {
		log.Printf("[tun-udp] routeTUNPacket: stream registered exists=%v", exists)
	}

	// Strip the auth header so the tun-forwarder sees clean TUN frames.
	data = data[:udpFrameHeaderLen]
	binary.BigEndian.PutUint16(data[9:11], 0)
	sc.handlePacket(data)
	if debugTUNAuth {
		log.Printf("[tun-udp] routeTUNPacket: delivering to TunCh")
	}

	select {
	case m.tunCh <- &connWithPeer{Conn: sc, peerID: peerID}:
	default:
		go func(s *udpStreamConn, k string) { m.tunCh <- &connWithPeer{Conn: s, peerID: peerID} }(sc, key)
	}
	if debugTUNAuth {
		log.Printf("[tun-udp] routeTUNPacket: delivered")
	}
	// Clean up when the stream closes.
	go func(s *udpStreamConn, k string) {
		<-s.done
		m.mu.Lock()
		if cur, ok := m.tunStreams[k]; ok && cur == s {
			delete(m.tunStreams, k)
		}
		m.mu.Unlock()
	}(sc, key)
	return true
}

// TunCh returns the channel on which accepted TUN UDP streams are
// delivered (each is a net.Conn carrying framed TUN packets).
func (m *udpMeshManager) TunCh() <-chan net.Conn {
	return m.tunCh
}

// DialTUNStream initiates a TUN-data UDP stream to a remote address.
// authHeader is the first-frame authentication payload ([pubkey 64][ts
// 10][sig 128]) produced by the caller (MeshNode) — it proves identity
// and prevents UDP injection. Returns the existing stream if one is
// already established.
func (m *udpMeshManager) DialTUNStream(local *net.UDPConn, remote *net.UDPAddr, authHeader []byte) (*udpStreamConn, error) {
	key := remote.String()

	m.mu.Lock()
	if existing, ok := m.tunStreams[key]; ok {
		m.mu.Unlock()
		return existing, nil
	}
	sc := newUDPStreamConn(local, remote)
	m.tunStreams[key] = sc
	m.mu.Unlock()

	// Reserve seq 0 for the auth handshake frame so subsequent
	// Write() frames start at seq 1 (otherwise the data frame
	// collides with the handshake seq and is dropped as a duplicate
	// by the receiver's ARQ dedup).
	sc.sendMu.Lock()
	sc.nextSeq = 1
	sc.sendMu.Unlock()

	// Send the first frame: ARQ DATA with payload = TUN marker + auth.
	payload := make([]byte, 0, 1+len(authHeader))
	payload = append(payload, tunUDPMarker)
	payload = append(payload, authHeader...)
	frame := make([]byte, udpFrameHeaderLen+len(payload))
	frame[0] = udpFrameTypeData
	binary.BigEndian.PutUint32(frame[1:5], 0)
	binary.BigEndian.PutUint32(frame[5:9], 0)
	binary.BigEndian.PutUint16(frame[9:11], uint16(len(payload)))
	copy(frame[udpFrameHeaderLen:], payload)
	if _, err := local.WriteToUDP(frame, remote); err != nil {
		m.mu.Lock()
		delete(m.tunStreams, key)
		m.mu.Unlock()
		sc.Close()
		return nil, err
	}

	// Clean up when the stream closes.
	go func(s *udpStreamConn, k string) {
		<-s.done
		m.mu.Lock()
		if cur, ok := m.tunStreams[k]; ok && cur == s {
			delete(m.tunStreams, k)
		}
		m.mu.Unlock()
	}(sc, key)

	return sc, nil
}
