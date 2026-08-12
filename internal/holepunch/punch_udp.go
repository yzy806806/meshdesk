package holepunch

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

// Coordinated UDP hole punch:
//
//  1. We dial the peer's coordination virtual port (over mesh smux /
//     relay) and exchange STUN-mapped endpoints + a punch nonce.
//  2. Both sides send UDP probes to the peer's mapped endpoint,
//     simultaneously (nonce carried in the probe payload).
//  3. When a probe from the peer arrives on our UDP socket, the hole
//     is open both ways — the mesh layer feeds the punched endpoint to
//     getUDPStream.
//
// Probing repeats briefly with a small jitter to cover the window
// where the two sides' NAT mappings race.

// punchMsg is the coordination payload (msgpack-free: fixed layout).
type punchMsg struct {
	Nonce    uint32 // punch session nonce
	MappedEP string // STUN-mapped public endpoint "host:port"
	NatType  byte
}

const (
	punchMsgSize    = 4 + 2 + 64 // nonce + mappedEP len + mappedEP buf
	punchProbeCount = 6
	punchProbeGap   = 120 * time.Millisecond
	punchTimeout    = 8 * time.Second
)

// punchUDP performs a coordinated two-way UDP hole punch. Returns the
// peer's punched endpoint on success, "" on failure.
func (e *Engine) punchUDP(peerKey string, endpoints []string) string {
	ctx, cancel := context.WithTimeout(context.Background(), punchTimeout)
	defer cancel()

	// 1. Exchange punch params over the coordination stream. With no
	//    advertised endpoints, the exchange itself is the discovery.
	fallback := ""
	if len(endpoints) > 0 {
		fallback = endpoints[0]
	}
	peerEP, nonce, err := e.exchangePunchParams(ctx, peerKey, fallback)
	if err != nil {
		log.Printf("[holepunch] %s: coordination exchange failed: %v", short(peerKey), err)
		return ""
	}
	if peerEP == "" {
		return ""
	}

	// 2. Open the local UDP socket (bind the punch port if configured).
	local := &net.UDPAddr{Port: e.PunchPort}
	conn, err := net.DialUDP("udp", local, mustUDPAddr(peerEP))
	if err != nil {
		conn, err = net.DialUDP("udp", nil, mustUDPAddr(peerEP))
		if err != nil {
			return ""
		}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(punchTimeout))

	// 3. Send probes carrying the nonce; wait for a reply.
	probe := make([]byte, 8)
	binary.BigEndian.PutUint32(probe, nonce)
	reply := make([]byte, 8)

	for i := 0; i < punchProbeCount; i++ {
		// Send outbound probe (creates/refreshes our NAT mapping).
		if _, err := conn.Write(probe); err == nil {
			// Try to read the peer's probe.
			conn.SetReadDeadline(time.Now().Add(punchProbeGap * 2))
			n, _, rerr := conn.ReadFrom(reply)
			if rerr == nil && n >= 4 && binary.BigEndian.Uint32(reply) == nonce {
				// Hole open both ways.
				return peerEP
			}
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(punchProbeGap):
		}
	}
	return ""
}

// exchangePunchParams dials the peer's coordination virtual port and
// exchanges mapped endpoints + nonce. Returns the peer's mapped
// endpoint (preferring our own local knowledge of its endpoint when
// the exchange fails).
func (e *Engine) exchangePunchParams(ctx context.Context, peerKey, fallbackEP string) (string, uint32, error) {
	nonce := uint32(time.Now().UnixNano() & 0xffffffff)

	conn, err := e.Dialer.DialVirtualPort(ctx, peerKey, HolePunchVirtualPort)
	if err != nil {
		// No coordination stream (peer unreachable) — fall back to a
		// blind punch at the advertised endpoint (still useful when
		// only one side is behind NAT).
		return fallbackEP, nonce, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send our mapped endpoint + nonce.
	our := e.LocalEP
	if our == "" {
		our = "0.0.0.0:0"
	}
	req := make([]byte, 4+len(our))
	binary.BigEndian.PutUint32(req, nonce)
	copy(req[4:], our)
	if _, err := conn.Write(req); err != nil {
		return fallbackEP, nonce, nil
	}

	// Read the peer's reply: nonce + their mapped endpoint.
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return fallbackEP, nonce, nil
	}
	peerNonce := binary.BigEndian.Uint32(buf)
	peerEP := string(buf[4:n])
	if peerNonce != nonce {
		return fallbackEP, nonce, nil
	}
	if peerEP == "" || peerEP == "0.0.0.0:0" {
		return fallbackEP, nonce, nil
	}
	log.Printf("[holepunch] %s: coordination exchanged — peer mapped %s", short(peerKey), peerEP)
	return peerEP, nonce, nil
}

func mustUDPAddr(ep string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", ep)
	if err != nil {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	return addr
}

// HandleCoordinatorStream serves the coordination virtual port: reads
// the peer's punch request and replies with our mapped endpoint.
// Registered by the app layer on shared nodes.
func (e *Engine) HandleCoordinatorStream(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return
	}
	nonce := binary.BigEndian.Uint32(buf)
	peerEP := string(buf[4:n])

	// Reply with our mapped endpoint (best-effort).
	our := e.LocalEP
	if our == "" {
		our = "0.0.0.0:0"
	}
	resp := make([]byte, 4+len(our))
	binary.BigEndian.PutUint32(resp, nonce)
	copy(resp[4:], our)
	if _, err := conn.Write(resp); err != nil {
		return
	}
	log.Printf("[holepunch] coordinator: peer %s (mapped %s) -> our %s", shortEP(peerEP), peerEP, our)

	// Two-way punch: after exchanging, ALSO send UDP probes to the
	// peer's mapped endpoint (blind side of the handshake). Without
	// this, only the initiator punches and the hole never opens both
	// ways.
	go e.blindPunch(peerEP, nonce)
}

// blindPunch sends UDP probes to the peer's mapped endpoint so our NAT
// mapping accepts its inbound probes too. Runs on the coordinator side
// (the peer that was dialed).
func (e *Engine) blindPunch(peerEP string, nonce uint32) {
	local := &net.UDPAddr{Port: e.PunchPort}
	conn, err := net.DialUDP("udp", local, mustUDPAddr(peerEP))
	if err != nil {
		conn, err = net.DialUDP("udp", nil, mustUDPAddr(peerEP))
		if err != nil {
			return
		}
	}
	defer conn.Close()

	probe := make([]byte, 8)
	binary.BigEndian.PutUint32(probe, nonce)
	for i := 0; i < punchProbeCount; i++ {
		conn.Write(probe)
		conn.SetReadDeadline(time.Now().Add(punchProbeGap * 2))
		reply := make([]byte, 8)
		if n, _, err := conn.ReadFrom(reply); err == nil && n >= 4 && binary.BigEndian.Uint32(reply) == nonce {
			log.Printf("[holepunch] blindPunch: hole open to %s", peerEP)
			return
		}
		time.Sleep(punchProbeGap)
	}
}

func shortEP(ep string) string {
	if len(ep) > 24 {
		return ep[:24] + "..."
	}
	return ep
}

var _ = fmt.Sprintf // keep fmt for future use
