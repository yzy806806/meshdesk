package mesh

import (
	"encoding/binary"
	"fmt"
	"log"

	"net"

	"strconv"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────
// UDP mesh data plane (T0.1/T0.2)
//
// The shared mesh UDP socket (mesh port, 52888 by default from
// cfg.Mesh.Port) carries both gossip (memberlist) and mesh
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

// Tun UDP auth DoS protection: forging first frames costs the receiver
// an Ed25519 verification per datagram. Track per-source failures and
// block sources that exceed the threshold for a cooldown window.
const (
	tunAuthFailWindow   = 10 * time.Second
	tunAuthFailMax      = 5
	tunAuthFailCooldown = 60 * time.Second
)

type tunAuthFailState struct {
	count       int // failures within the window
	windowStart time.Time
	blockUntil  time.Time // active cooldown end
}

type udpMeshManager struct {
	mu         sync.Mutex
	streams    map[string]*udpStreamConn // mesh key-exchange streams (by remote addr)
	tunStreams map[string]*udpStreamConn // TUN data streams (by remote addr)
	tunCh      chan net.Conn             // accepted TUN streams → tun-forwarder
	// tunAuthValidator authenticates the first-frame auth header and
	// returns the verified peer identity hex. Set by MeshNode.
	tunAuthValidator func(pubKeyHex string, data []byte, sigHex string) (string, bool)
	// tunAuthFails tracks per-source auth failure state (DoS guard).
	tunAuthFails map[string]*tunAuthFailState
	// meshCreateGuard throttles unauthenticated UDP mesh stream
	// creation per source (key-exchange streams are created BEFORE
	// any authentication — a forger must not spawn unbounded
	// 2-goroutine streams).
	meshCreateGuard map[string]*tunAuthFailState
}

func newUDPMeshManager() *udpMeshManager {
	return &udpMeshManager{
		streams:         make(map[string]*udpStreamConn),
		tunStreams:      make(map[string]*udpStreamConn),
		tunCh:           make(chan net.Conn, 64),
		tunAuthFails:    make(map[string]*tunAuthFailState),
		meshCreateGuard: make(map[string]*tunAuthFailState),
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
	key := addr.String() + "|in"

	m.mu.Lock()
	sc, exists := m.streams[key]
	if !exists {
		// Throttle unauthenticated stream creation per source: a
		// forger must not spawn unbounded 2-goroutine streams.
		if st := m.meshCreateGuard[key]; st != nil && time.Now().Before(st.blockUntil) {
			m.mu.Unlock()
			return true
		}
		sc = newUDPStreamConn(conn, addr)
		m.streams[key] = sc
		m.recordMeshCreateLocked(key)
		log.Printf("[udpmesh] routeMeshPacket: NEW stream for %s (first frame len=%d)", key, len(data))
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
			// subsequent packets, the accept loop drains meshCh. Bound
			// the blocked handoff so a drained loop cannot leak the
			// goroutine forever after shutdown.
			go func(s *udpStreamConn) {
				select {
				case meshCh <- s:
				case <-time.After(30 * time.Second):
					s.Close()
				}
			}(sc)
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
	// Outbound stream — separate key from inbound (routeMeshPacket)
	// so simultaneous two-way key exchanges (both sides punch) don't
	// collide on the same ARQ state machine.
	key := remote.String() + "|out"

	m.mu.Lock()
	if existing, ok := m.streams[key]; ok {
		m.mu.Unlock()
		return existing, nil
	}
	sc := newUDPStreamConn(local, remote)
	m.streams[key] = sc
	m.mu.Unlock()

	// Reserve seq 0 for the 0x4D marker frame so subsequent Write()
	// frames start at seq 1 — otherwise the first key-exchange frame
	// collides with the marker's seq and is dropped as a duplicate by
	// the receiver's ARQ dedup (recvNext already advanced past 0),
	// corrupting msg1 → "Ed25519 signature verification failed" /
	// "key exchange ... unexpected EOF". Mirrors DialTUNStream.
	sc.sendMu.Lock()
	sc.nextSeq = 1
	sc.sendMu.Unlock()

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

	// Confirm the path: wait for the peer's ACK of the 0x4D
	// handshake frame (inflight drains when ACKed). A firewall
	// that drops UDP yields no ACK — fail the dial so the caller
	// falls back to TCP relay. Mirrors DialTUNStream confirmation.
	confirmDeadline := time.Now().Add(udpDialConfirmTimeout)
	for {
		sc.sendMu.Lock()
		pending := len(sc.inflight)
		sc.sendMu.Unlock()
		if pending == 0 {
			break
		}
		if time.Now().After(confirmDeadline) {
			m.mu.Lock()
			if cur, ok := m.streams[key]; ok && cur == sc {
				delete(m.streams, key)
			}
			m.mu.Unlock()
			sc.Close()
			return nil, fmt.Errorf("udp mesh stream: no ACK from %s within %s (path unusable)", remote, udpDialConfirmTimeout)
		}
		time.Sleep(50 * time.Millisecond)
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
	// Inbound mesh streams are keyed |in (outbound DialUDPStream uses
	// |out). Frames from this addr belong to whichever stream exists:
	// the inbound stream for OUR outbound dial's replies, or the
	// outbound stream for OUR initiated exchange's responses.
	meshKey := key + "|in"
	outKey := key + "|out"

	if debugEnabled {
		log.Printf("[udpmesh] routeUDPPacket %dB from %s (type=%d)", len(data), addr, data[0])
	}

	m.mu.Lock()
	sc, exists := m.streams[meshKey]
	if !exists {
		sc, exists = m.streams[outKey]
	}
	// Also check the plain key (punched stream registered by
	// RegisterPunchedStream — no |in/|out suffix).
	if !exists {
		sc, exists = m.streams[key]
	}
	tun, tunExists := m.tunStreams[key]
	m.mu.Unlock()

	// A DialUDPStream first frame (seq=0, payload=[0x4D marker])
	// signals the PEER INITIATED a new mesh kx stream. This is only
	// used by the legacy DialUDPPeer path (session_reconnect). The
	// EasyTier-style punched stream path does not send 0x4D — data
	// flows as ARQ frames directly on the registered stream.
	isNewStream := len(data) >= udpFrameHeaderLen+1 &&
		data[0] == udpFrameTypeData &&
		binary.BigEndian.Uint32(data[1:5]) == 0 &&
		data[udpFrameHeaderLen] == meshInternalMarker

	if exists && !isNewStream {
		// Established stream (punched or kx), continuation frame: feed it.
		sc.handlePacket(data)
		return true
	}
	if isNewStream {
		// Legacy kx path: route through the mesh packet handler
		// (creates the |in stream and strips the marker).
		return m.routeMeshPacket(conn, addr, data, meshCh)
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
	if !exists {
		// DoS guard: a source blocked for repeated auth failures is
		// dropped without any verification work (cheap reject).
		if st := m.tunAuthFails[key]; st != nil && time.Now().Before(st.blockUntil) {
			m.mu.Unlock()
			return true
		}
	}
	m.mu.Unlock()
	if exists {
		// Established (authenticated) TUN stream: feed everything.
		sc.handlePacket(data)
		return true
	}

	// First frame: [marker][pubkey 64][ts 10][sig 128] — auth only.
	plen := int(binary.BigEndian.Uint16(data[9:11]))
	// Both bounds are attacker-controlled wire values: reject undersized
	// auth headers AND oversized length claims (a 12-byte datagram lying
	// that plen=203 would slice out of range → panic → process crash).
	if plen < 1+tunUDPAuthLen || plen > len(data)-udpFrameHeaderLen {
		m.recordTUNAuthFail(key, "malformed first frame (plen out of range)")
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
		m.recordTUNAuthFail(key, "unparsable auth timestamp")
		return true
	}
	now := time.Now().Unix()
	if ts < now-int64(tunUDPAuthWindow.Seconds()) || ts > now+int64(tunUDPAuthWindow.Seconds()) {
		// Clock skew between the two hosts is the usual cause — the
		// TUN handshake then fails silently while mesh kx (no
		// timestamp) keeps working. Log it loudly.
		m.recordTUNAuthFail(key, fmt.Sprintf("timestamp outside ±10min window (ts=%d now=%d)", ts, now))
		return true
	}

	// Verify Ed25519 signature over (pubkey + ts).
	m.mu.Lock()
	validator := m.tunAuthValidator
	m.mu.Unlock()
	if validator == nil {
		log.Printf("[tun-udp-auth] %s: TUN UDP auth validator not wired — refusing (security)", key)
		return true // no validator wired — refuse (security)
	}
	signedData := []byte(pubKeyHex + tsStr)
	peerID, ok := validator(pubKeyHex, signedData, sigHex)
	if !ok {
		m.recordTUNAuthFail(key, "Ed25519 signature verification failed (unknown peer or bad sig)")
		return true // auth failed; drop quietly
	}

	m.mu.Lock()
	sc, exists = m.tunStreams[key]
	if !exists {
		sc = newUDPStreamConn(conn, addr)
		m.tunStreams[key] = sc
	}
	m.mu.Unlock()

	// Strip the auth header so the tun-forwarder sees clean TUN frames.
	data = data[:udpFrameHeaderLen]
	binary.BigEndian.PutUint16(data[9:11], 0)
	sc.handlePacket(data)

	select {
	case m.tunCh <- &connWithPeer{Conn: sc, peerID: peerID}:
	default:
		go func(s *udpStreamConn, k string) {
			select {
			case m.tunCh <- &connWithPeer{Conn: s, peerID: peerID}:
			case <-time.After(30 * time.Second):
				s.Close()
			}
		}(sc, key)
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

// recordTUNAuthFail counts an auth failure for a source address and
// blocks the source once the threshold is exceeded within the window.
// Caller must NOT hold m.mu.
func (m *udpMeshManager) recordTUNAuthFail(key, reason string) {
	now := time.Now()
	m.mu.Lock()
	st := m.tunAuthFails[key]
	if st == nil {
		st = &tunAuthFailState{}
		m.tunAuthFails[key] = st
	}
	if now.Sub(st.windowStart) > tunAuthFailWindow {
		// New window.
		st.count = 0
		st.windowStart = now
	}
	st.count++
	blocked := false
	if st.count >= tunAuthFailMax {
		st.blockUntil = now.Add(tunAuthFailCooldown)
		st.count = 0
		blocked = true
	}
	m.mu.Unlock()
	// Log the failure with its reason. Rate-limited by the DoS guard
	// itself (at most tunAuthFailMax logs per window per source), so
	// a flood cannot spam the log, and real handshake failures become
	// visible instead of vanishing silently — the classic "frames
	// arrive but no ACK" debugging black hole (clock skew, unknown
	// peer key, bad signature all look identical on the wire).
	if reason != "" {
		log.Printf("[tun-udp-auth] %s: %s (blocked=%v)", key, reason, blocked)
	}
	// Opportunistic cleanup: don't let the failure map grow unbounded.
	m.mu.Lock()
	if len(m.tunAuthFails) > 1024 {
		for k, s := range m.tunAuthFails {
			if now.After(s.windowStart.Add(tunAuthFailWindow)) && now.After(s.blockUntil) {
				delete(m.tunAuthFails, k)
			}
		}
	}
	m.mu.Unlock()
}

// recordMeshCreateLocked counts an unauthenticated mesh stream creation
// for a source and throttles it after the threshold within the window.
// Caller MUST hold m.mu.
func (m *udpMeshManager) recordMeshCreateLocked(key string) {
	now := time.Now()
	st := m.meshCreateGuard[key]
	if st == nil {
		st = &tunAuthFailState{}
		m.meshCreateGuard[key] = st
	}
	if now.Sub(st.windowStart) > tunAuthFailWindow {
		st.count = 0
		st.windowStart = now
	}
	st.count++
	if st.count >= tunAuthFailMax {
		st.blockUntil = now.Add(tunAuthFailCooldown)
		st.count = 0
	}
	// Opportunistic cleanup.
	if len(m.meshCreateGuard) > 1024 {
		for k, s := range m.meshCreateGuard {
			if now.After(s.windowStart.Add(tunAuthFailWindow)) && now.After(s.blockUntil) {
				delete(m.meshCreateGuard, k)
			}
		}
	}
}

// TunCh returns the channel on which accepted TUN UDP streams are
// delivered (each is a net.Conn carrying framed TUN packets).
func (m *udpMeshManager) TunCh() <-chan net.Conn {
	return m.tunCh
}

// RegisterPunchedStream creates a pre-authenticated ARQ stream over
// a hole-punched UDP socket. Unlike DialUDPStream/DialTUNStream, no
// key exchange or authentication handshake is sent — the hole punch
// coordination already verified the peer's identity via the smux
// session. The stream is registered under the peer's address so
// inbound ARQ frames from that address are fed to it.
//
// This is the EasyTier-style data plane: the punched socket becomes
// a transport directly, without a separate kx layer (which fails on
// networks that filter UDP packets >60B, e.g. Oracle Cloud VCN).
func (m *udpMeshManager) RegisterPunchedStream(local *net.UDPConn, remote *net.UDPAddr, peerID string, deliverTUN chan<- net.Conn) *udpStreamConn {
	key := remote.String()
	log.Printf("[udpmesh] RegisterPunchedStream: key=%s local=%s peer=%s", key, local.LocalAddr(), shortKey(peerID))

	m.mu.Lock()
	// Reuse existing stream if present (re-punch on same path). Do NOT
	// re-deliver to the TUN forwarder — the original handleInboundStream
	// goroutine is still reading it; a second reader would steal frames
	// and its eventual Close would kill the shared ARQ stream.
	if existing, ok := m.streams[key]; ok {
		m.mu.Unlock()
		return existing
	}
	sc := newUDPStreamConn(local, remote)
	m.streams[key] = sc
	m.mu.Unlock()

	// Deliver the punched stream to the TUN forwarder's accept path —
	// without this, inbound ARQ frames are fed to the ARQ layer but no
	// goroutine reads the stream and writes packets into the TUN device
	// (outbound works via getOutboundStream, inbound silently black-
	// holes). Wrapped in connWithPeer so the anti-spoof check sees the
	// verified peer identity from the hole-punch coordination.
	if deliverTUN != nil && peerID != "" {
		cw := &connWithPeer{Conn: sc, peerID: peerID}
		select {
		case deliverTUN <- cw:
		default:
			go func(c net.Conn) {
				select {
				case deliverTUN <- c:
				case <-time.After(10 * time.Second):
					log.Printf("[udpmesh] punched stream TUN delivery timeout for %s", shortKey(peerID))
				}
			}(cw)
		}
	}

	// EasyTier-style simultaneous punch: fire a few small probes in
	// BOTH directions immediately. Cloud-level firewalls (e.g. Oracle
	// VCN) drop inbound UDP unless the VM itself recently sent a packet
	// to that exact remote ip:port — both sides must send before any
	// data can flow. Raw WriteToUDP (NOT s.Write) — the peer's ARQ
	// layer would buffer the probe into the read queue, where the TUN
	// forwarder's framed-packet reader chokes on it (invalid length).
	go func(s *udpStreamConn) {
		probe := make([]byte, udpFrameHeaderLen+2)
		probe[0] = udpFrameTypeData
		binary.BigEndian.PutUint32(probe[1:5], 0xFFFFFFFF) // seq=reserved: not a data seq
		binary.BigEndian.PutUint32(probe[5:9], 0)
		binary.BigEndian.PutUint16(probe[9:11], 2)
		copy(probe[udpFrameHeaderLen:], []byte{0x50, 0x4A})
		for i := 0; i < 5; i++ {
			s.sendMu.Lock()
			closedNow := s.closed
			s.sendMu.Unlock()
			if closedNow {
				return
			}
			s.conn.WriteToUDP(probe, s.peer) // raw datagram, bypasses ARQ
			time.Sleep(100 * time.Millisecond)
		}
	}(sc)

	// Clean up when the stream closes.
	go func(s *udpStreamConn, k string) {
		<-s.done
		m.mu.Lock()
		if cur, ok := m.streams[k]; ok && cur == s {
			delete(m.streams, k)
		}
		m.mu.Unlock()
	}(sc, key)

	return sc
}

// GetPunchedStream returns the ARQ stream for a peer's address, or
// nil if none exists. Used by the TUN forwarder to route IP packets
// over a punched UDP path instead of TCP relay.
func (m *udpMeshManager) GetPunchedStream(addr string) *udpStreamConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streams[addr]
}

// udpDialConfirmTimeout is how long DialTUNStream waits for the peer's
// ARQ ACK of the handshake frame before declaring the path unusable.
// UDP dial is connectionless — WriteToUDP "succeeds" even when a
// firewall drops the datagram. Without confirmation the UDP-preferred
// data plane would silently black-hole traffic instead of falling back
// to TCP. 1s is plenty for real peers (RTT << 1s) and keeps the
// fallback stall imperceptible.
const udpDialConfirmTimeout = 1 * time.Second

// DialTUNStream initiates a TUN-data UDP stream to a remote address.
// authHeader is the first-frame authentication payload ([pubkey 64][ts
// 10][sig 128]) produced by the caller (MeshNode) — it proves identity
// and prevents UDP injection. Returns the existing stream if one is
// already established.
//
// The dial only succeeds once the peer's ARQ ACK for the handshake
// frame arrives (the receiver authenticates BEFORE acking), so an
// unreachable/firewalled UDP path fails here and the caller falls back
// to TCP.
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
	// Track the handshake frame in inflight so the ACK-confirmation
	// wait below observes it being acknowledged.
	sc.sendMu.Lock()
	sc.inflight[0] = udpInflightFrame{data: frame, sentAt: time.Now()}
	sc.sendMu.Unlock()
	if _, err := local.WriteToUDP(frame, remote); err != nil {
		m.mu.Lock()
		delete(m.tunStreams, key)
		m.mu.Unlock()
		sc.Close()
		return nil, err
	}
	// Debug: confirm the frame left through the intended socket.
	// Without this, a WriteToUDP that returns nil but never hits the
	// wire (wrong family socket, ::ffff: mapped source) surfaces only
	// as a silent "no ACK" timeout.
	if debugEnabled {
		log.Printf("[tun-udp] handshake frame sent via local=%s to %s (len=%d)", local.LocalAddr(), remote, len(frame))
	}

	// Confirm the path: wait for the peer's ACK of the handshake
	// frame (inflight drains when ACKed). A firewall that drops UDP
	// yields no ACK — fail the dial so the caller falls back to TCP.
	confirmDeadline := time.Now().Add(udpDialConfirmTimeout)
	for {
		sc.sendMu.Lock()
		pending := len(sc.inflight)
		sc.sendMu.Unlock()
		if pending == 0 {
			break
		}
		if time.Now().After(confirmDeadline) {
			m.mu.Lock()
			delete(m.tunStreams, key)
			m.mu.Unlock()
			sc.Close()
			return nil, fmt.Errorf("udp tun stream: no ACK from %s within %s (path unusable)", remote, udpDialConfirmTimeout)
		}
		time.Sleep(50 * time.Millisecond)
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
