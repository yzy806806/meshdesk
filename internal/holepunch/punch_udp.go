package holepunch

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
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
	TcpPort  uint16 // local TCP listen port for TCP hole punching
	SrcPort  uint16 // our outbound TCP source port (EasyTier-style conntrack punch)
}

const (
	punchMsgSize    = 4 + 2 + 64 // nonce + mappedEP len + mappedEP buf
	punchProbeCount = 6
	punchProbeGap   = 120 * time.Millisecond
	punchTimeout    = 20 * time.Second
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
	if peerEP == "" || peerEP == "0.0.0.0:0" || peerEP == "[::]:0" {
		// Mapped endpoint unavailable — fall back to the advertised
		// endpoint (still useful when one side is behind NAT).
		peerEP = fallback
	}
	if peerEP == "" {
		return ""
	}

	// 2. Open the local UDP socket — reuse the mesh mux socket when
	//    available (same NAT mapping as the data plane), else bind
	//    the punch port / ephemeral.
	var conn *net.UDPConn
	shared := false
	if e.PunchConnProvider != nil {
		if rc := mustUDPAddr(peerEP); rc != nil {
			conn = e.PunchConnProvider(rc.IP)
			shared = conn != nil
		}
	}
	if conn == nil {
		local := &net.UDPAddr{Port: e.PunchPort}
		var err error
		conn, err = net.DialUDP("udp", local, mustUDPAddr(peerEP))
		if err != nil {
			conn, err = net.DialUDP("udp", nil, mustUDPAddr(peerEP))
			if err != nil {
				return ""
			}
		}
	}
	// Only close sockets we created — the shared mux socket is owned
	// by the transport (closing it kills the mux UDP read loop).
	if !shared {
		defer conn.Close()
	}

	// 3. Send probes carrying the nonce; wait for a reply. On the
	//    SHARED mux socket we must NOT set deadlines (that would break
	//    the mux read loop) and must NOT block on ReadFrom (the mux
	//    loop owns reads) — fire probes only; hole verification happens
	//    when the data plane dials the punched endpoint.
	probe := make([]byte, 6) // [0x50 0x4A] + nonce(4) — mux sockets echo these
	probe[0], probe[1] = 0x50, 0x4A
	binary.BigEndian.PutUint32(probe[2:], nonce)
	reply := make([]byte, 16)

	peerUDP := mustUDPAddr(peerEP)
	for i := 0; i < punchProbeCount; i++ {
		// Send outbound probe (creates/refreshes our NAT mapping).
		// Shared mux sockets are UNCONNECTED — must use WriteTo.
		var werr error
		if shared {
			_, werr = conn.WriteTo(probe, peerUDP)
		} else {
			_, werr = conn.Write(probe)
		}
		if werr == nil && !shared {
			// Try to read the peer's probe (echoed by its mux loop).
			conn.SetReadDeadline(time.Now().Add(punchProbeGap * 2))
			n, _, rerr := conn.ReadFrom(reply)
			if rerr == nil && n >= 6 && reply[0] == 0x50 && reply[1] == 0x4A && binary.BigEndian.Uint32(reply[2:]) == nonce {
				// Hole open both ways.
				return peerEP
			}
		} else if err == nil && shared {
			// Shared socket: probes fired; the mux loop owns reads.
			// A brief pause lets the peer's probes land.
			time.Sleep(punchProbeGap)
			// Optimistically report the hole — the data plane will
			// verify it via DialUDPPeer and fall back to relay if
			// the punch did not actually open.
			if i == punchProbeCount-1 {
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
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Send our punch endpoint: public IP + mux port when known (this
	// is what the peer must punch at for the data-plane NAT mapping).
	our := e.PublicPunchEP
	if our == "" {
		our = e.LocalEP
	}
	if our == "" {
		if la := conn.LocalAddr(); la != nil {
			our = la.String()
		} else {
			our = "0.0.0.0:0"
		}
	}
	req := make([]byte, 4+len(our)+4)
	binary.BigEndian.PutUint32(req, nonce)
	copy(req[4:], our)
	binary.BigEndian.PutUint16(req[4+len(our):], uint16(e.TcpPort))
	binary.BigEndian.PutUint16(req[4+len(our)+2:], uint16(e.SrcPort))
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
	// Trailing bytes carry the peer's TCP punch port + outbound source
	// port (EasyTier-style conntrack punch).
	if n >= 8 {
		epLen := n - 4 - 4
		peerEP = string(buf[4 : 4+epLen])
		e.mu.Lock()
		e.peerTCPPort[peerKey] = int(binary.BigEndian.Uint16(buf[4+epLen:]))
		e.peerSrcPort[peerKey] = int(binary.BigEndian.Uint16(buf[4+epLen+2:]))
		e.mu.Unlock()
	}
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
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return
	}
	nonce := binary.BigEndian.Uint32(buf)
	peerEP := string(buf[4:n])
	peerTCP := 0
	peerSrc := 0
	// Trailing bytes carry the peer's TCP punch port + outbound source
	// port — strip them from the endpoint.
	if n >= 8 {
		epLen := n - 4 - 4
		peerEP = string(buf[4 : 4+epLen])
		peerTCP = int(binary.BigEndian.Uint16(buf[4+epLen:]))
		peerSrc = int(binary.BigEndian.Uint16(buf[4+epLen+2:]))
	}

	// Reply with our mapped endpoint (best-effort). Fall back to the
	// local conn address when STUN didn't provide a mapped endpoint —
	// "0.0.0.0:0" would make the peer's punch target invalid.
	our := e.PublicPunchEP
	if our == "" || our == "0.0.0.0:0" || our == "[::]:0" {
		our = e.LocalEP
	}
	if our == "" || our == "0.0.0.0:0" || our == "[::]:0" {
		if la := conn.LocalAddr(); la != nil {
			our = la.String()
		} else {
			our = "0.0.0.0:0"
		}
	}
	resp := make([]byte, 4+len(our)+4)
	binary.BigEndian.PutUint32(resp, nonce)
	copy(resp[4:], our)
	binary.BigEndian.PutUint16(resp[4+len(our):], uint16(e.TcpPort))
	binary.BigEndian.PutUint16(resp[4+len(our)+2:], uint16(e.SrcPort))
	if _, err := conn.Write(resp); err != nil {
		return
	}

	// TCP blind-connect: prefer the peer's outbound source port
	// (conntrack punch — stateful security groups pass ESTABLISHED),
	// else its punch listen port.
	if peerTCP > 0 || peerSrc > 0 {
		host, _, herr := net.SplitHostPort(peerEP)
		if herr == nil {
			port := peerSrc
			if port <= 0 {
				port = peerTCP
			}
			target := net.JoinHostPort(host, strconv.Itoa(port))
			go e.tcpBlindConnect(target, nonce)
		}
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
	var conn *net.UDPConn
	shared := false
	if e.PunchConnProvider != nil {
		if rc := mustUDPAddr(peerEP); rc != nil {
			conn = e.PunchConnProvider(rc.IP)
			shared = conn != nil
		}
	}
	if conn == nil {
		local := &net.UDPAddr{Port: e.PunchPort}
		var err error
		conn, err = net.DialUDP("udp", local, mustUDPAddr(peerEP))
		if err != nil {
			conn, err = net.DialUDP("udp", nil, mustUDPAddr(peerEP))
			if err != nil {
				return
			}
		}
	}
	if !shared {
		defer conn.Close()
	}

	probe := make([]byte, 6)
	probe[0], probe[1] = 0x50, 0x4A
	binary.BigEndian.PutUint32(probe[2:], nonce)
	peerUDP := mustUDPAddr(peerEP)
	for i := 0; i < punchProbeCount; i++ {
		if shared {
			conn.WriteTo(probe, peerUDP)
		} else {
			conn.Write(probe)
		}
		if shared {
			// Shared mux socket: no reads, no deadlines (mux loop owns).
			time.Sleep(punchProbeGap)
			continue
		}
		conn.SetReadDeadline(time.Now().Add(punchProbeGap * 2))
		reply := make([]byte, 16)
		if n, _, err := conn.ReadFrom(reply); err == nil && n >= 6 && reply[0] == 0x50 && reply[1] == 0x4A && binary.BigEndian.Uint32(reply[2:]) == nonce {
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
