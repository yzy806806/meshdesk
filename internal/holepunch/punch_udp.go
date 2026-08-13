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
	EasySym  byte   // 1 if symmetric NAT with predictable increment (NAT4E)
	Inc      byte   // mapped-port increment direction: 1=inc, 255=dec (0xFE)
	ObsPort  uint16 // observed peer outbound source port (conntrack-matched punch target)
}

const (
	punchMsgSize    = 4 + 2 + 64 // nonce + mappedEP len + mappedEP buf
	punchProbeCount = 6
	punchProbeGap   = 120 * time.Millisecond
	punchTimeout    = 20 * time.Second
)

// punchUDP performs a coordinated two-way UDP hole punch. Returns the
// peer's punched endpoint on success, "" on failure.
//
// EasyTier ordering (source-verified): the outbound socket opens FIRST
// and its source port is exchanged via the coordination message — the
// peer's data plane targets that source port, which its stateful
// security group passes as ESTABLISHED (conntrack). Reporting the
// listen address instead (as v1.6.1 did) makes the peer dial an
// inbound port that drops large datagrams.
func (e *Engine) punchUDP(peerKey string, endpoints []string) string {
	ctx, cancel := context.WithTimeout(context.Background(), punchTimeout)
	defer cancel()

	fallback := ""
	if len(endpoints) > 0 {
		fallback = endpoints[0]
	}
	if fallback == "" {
		return ""
	}

	// 1. Open the local UDP socket FIRST — reuse the mesh mux socket
	//    when available (same NAT mapping as the data plane), else
	//    bind the punch port / ephemeral. Its LocalAddr port is our
	//    outbound source port, exchanged as the conntrack target.
	var conn *net.UDPConn
	shared := false
	if e.PunchConnProvider != nil {
		if rc := mustUDPAddr(fallback); rc != nil {
			conn = e.PunchConnProvider(rc.IP)
			shared = conn != nil
		}
	}
	if conn == nil {
		local := &net.UDPAddr{Port: e.PunchPort}
		var err error
		conn, err = net.DialUDP("udp", local, mustUDPAddr(fallback))
		if err != nil {
			conn, err = net.DialUDP("udp", nil, mustUDPAddr(fallback))
			if err != nil {
				return ""
			}
		}
	}
	// Record our outbound source port for the coordination exchange.
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la.Port > 0 {
		e.mu.Lock()
		e.OutboundPort = la.Port
		e.mu.Unlock()
	}

	// 2. Exchange punch params over the coordination stream (carries
	//    our outbound source port now).
	peerEP, nonce, err := e.exchangePunchParams(ctx, peerKey, fallback)
	if err != nil {
		log.Printf("[holepunch] %s: coordination exchange failed: %v", short(peerKey), err)
		return ""
	}
	if peerEP == "" || peerEP == "0.0.0.0:0" || peerEP == "[::]:0" {
		peerEP = fallback
	}
	if peerEP == "" {
		return ""
	}
	// Only close sockets we created — the shared mux socket is owned
	// by the transport (closing it kills the mux UDP read loop).
	if !shared {
		defer conn.Close()
	}

	// 3. Probe from an INDEPENDENT socket (EasyTier-style): the shared
	//    mux socket's source port is 52888 (its listen port), so
	//    exchanging it is a no-op. An independent outbound socket gets
	//    a fresh source port whose NAT mapping the peer's stateful
	//    security group passes as ESTABLISHED (conntrack) — the data
	//    plane then targets that port and large datagrams flow.
	probe := make([]byte, 6) // [0x50 0x4A] + nonce(4) — mux sockets echo these
	probe[0], probe[1] = 0x50, 0x4A
	binary.BigEndian.PutUint32(probe[2:], nonce)
	reply := make([]byte, 16)

	peerUDP := mustUDPAddr(peerEP)
	// Independent probe socket — same family as the peer.
	dialer := &net.Dialer{}
	if shared {
		if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			dialer.LocalAddr = &net.UDPAddr{IP: la.IP}
		}
	}
	pconn, derr := dialer.Dial("udp", peerUDP.String())
	var pconnUDP *net.UDPConn
	if derr == nil {
		pconnUDP = pconn.(*net.UDPConn)
		// KEEP the socket alive (EasyTier keeps its tunnel socket):
		// the peer's data plane targets our source port, so the
		// conntrack mapping must stay live. The data plane dials
		// through this socket (AddPunchSocket).
		e.mu.Lock()
		e.punchConn[peerKey] = pconnUDP
		e.OutboundPort = 0
		if la, ok := pconnUDP.LocalAddr().(*net.UDPAddr); ok {
			e.OutboundPort = la.Port
		}
		e.mu.Unlock()
		if e.OutboundPort > 0 {
			log.Printf("[holepunch] %s: independent outbound src port %d (conntrack target)", short(peerKey), e.OutboundPort)
		}
	}
	if pconnUDP == nil {
		// Independent socket failed — fall back to the shared socket.
		pconnUDP = conn
	}

	for i := 0; i < punchProbeCount; i++ {
		var werr error
		if pconnUDP == conn {
			_, werr = conn.WriteTo(probe, peerUDP)
		} else {
			_, werr = pconnUDP.WriteToUDP(probe, peerUDP)
		}
		if werr == nil && pconnUDP != conn {
			// Independent socket: we own reads — look for the echo.
			pconnUDP.SetReadDeadline(time.Now().Add(punchProbeGap * 2))
			n, _, rerr := pconnUDP.ReadFromUDP(reply)
			if rerr == nil && n >= 6 && reply[0] == 0x50 && reply[1] == 0x4A && binary.BigEndian.Uint32(reply[2:]) == nonce {
				return peerEP
			}
			// No echo (peer behind NAT or probe lost): optimistic
			// report after the last probe — the data plane verifies
			// via DialUDPPeer and falls back to relay.
			if i == punchProbeCount-1 {
				return peerEP
			}
		} else if werr == nil && pconnUDP == conn {
			time.Sleep(punchProbeGap)
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
	// Optimistic report: the probes were fired from our independent
	// outbound socket (conntrack mapping established) — the data
	// plane verifies the hole via DialUDPPeer and falls back to
	// relay if the punch did not actually open.
	return peerEP
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
	req := make([]byte, 4+len(our)+8)
	binary.BigEndian.PutUint32(req, nonce)
	copy(req[4:], our)
	binary.BigEndian.PutUint16(req[4+len(our):], uint16(e.TcpPort))
	binary.BigEndian.PutUint16(req[4+len(our)+2:], uint16(e.SrcPort))
	req[4+len(our)+4] = 0
	if e.EasySym {
		req[4+len(our)+4] = 1
	}
	req[4+len(our)+5] = e.Inc
	binary.BigEndian.PutUint16(req[4+len(our)+6:], uint16(e.OutboundPort))
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
	// port + EasySym/Inc + observed source port (conntrack punch).
	if n >= 12 {
		epLen := n - 4 - 8
		peerEP = string(buf[4 : 4+epLen])
		e.mu.Lock()
		e.peerTCPPort[peerKey] = int(binary.BigEndian.Uint16(buf[4+epLen:]))
		e.peerSrcPort[peerKey] = int(binary.BigEndian.Uint16(buf[4+epLen+2:]))
		e.peerEasySym[peerKey] = buf[4+epLen+4] == 1
		e.peerInc[peerKey] = int(int8(buf[4+epLen+5]))
		e.peerObsPort[peerKey] = int(binary.BigEndian.Uint16(buf[4+epLen+6:]))
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
	peerEasySym := false
	peerInc := 0
	peerObs := 0
	// Trailing bytes carry the peer's TCP punch port + outbound source
	// port + EasySym/Inc + observed src port — strip them.
	if n >= 12 {
		epLen := n - 4 - 8
		peerEP = string(buf[4 : 4+epLen])
		peerTCP = int(binary.BigEndian.Uint16(buf[4+epLen:]))
		peerSrc = int(binary.BigEndian.Uint16(buf[4+epLen+2:]))
		peerEasySym = buf[4+epLen+4] == 1
		peerInc = int(int8(buf[4+epLen+5]))
		peerObs = int(binary.BigEndian.Uint16(buf[4+epLen+6:]))
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
	resp := make([]byte, 4+len(our)+8)
	binary.BigEndian.PutUint32(resp, nonce)
	copy(resp[4:], our)
	binary.BigEndian.PutUint16(resp[4+len(our):], uint16(e.TcpPort))
	binary.BigEndian.PutUint16(resp[4+len(our)+2:], uint16(e.SrcPort))
	resp[4+len(our)+4] = 0
	if e.EasySym {
		resp[4+len(our)+4] = 1
	}
	resp[4+len(our)+5] = e.Inc
	binary.BigEndian.PutUint16(resp[4+len(our)+6:], uint16(e.OutboundPort))
	if _, err := conn.Write(resp); err != nil {
		return
	}

	// NAT4E window punch: if the peer is an easy-symmetric NAT, fire
	// probes at its predicted mapped-port window (base + inc*k) so the
	// per-destination mapping is hit — the cone-side classic trick.
	if peerEasySym && peerInc != 0 {
		host, _, herr := net.SplitHostPort(peerEP)
		if herr == nil && e.PunchConnProvider != nil {
			_, portStr, _ := net.SplitHostPort(peerEP)
			base := atoiSafe(portStr)
			if base > 0 {
				go e.symWindowProbe(host, base, peerInc, nonce)
			}
		}
	}

	// The peer reports the source port it observed on OUR probes — the
	// conntrack-matched target for ITS data plane (informational here;
	// the coordinator has no peerKey to key it by).
	if peerObs > 0 {
		log.Printf("[holepunch] coordinator: peer observed our src port %d", peerObs)
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

// symWindowProbe fires UDP probes across the peer's predicted
// symmetric-NAT mapped-port window (EasyTier's NAT4E birthday attack):
// base + inc*k for k in [1, symPunchWindow]. The peer's per-destination
// mapping lands inside this window for predictable-increment NATs, so
// one probe hits and opens the hole. Uses the shared mux socket so the
// data-plane mapping is preserved.
func (e *Engine) symWindowProbe(host string, base, inc int, nonce uint32) {
	conn := e.PunchConnProvider(net.ParseIP(host))
	if conn == nil {
		return
	}
	probe := make([]byte, 6)
	probe[0], probe[1] = 0x50, 0x4A
	binary.BigEndian.PutUint32(probe[2:], uint32(nonce))
	for k := 1; k <= symPunchWindow; k++ {
		port := base + inc*k
		if port <= 0 || port > 65535 {
			continue
		}
		conn.WriteToUDP(probe, &net.UDPAddr{IP: net.ParseIP(host), Port: port})
		time.Sleep(symPunchGap)
	}
	log.Printf("[holepunch] sym window probe done: %s base=%d inc=%d x%d", host, base, inc, symPunchWindow)
}

// symPunchWindow is how many consecutive ports to scan for NAT4E
// (EasyTier uses 50).
const symPunchWindow = 50

// symPunchGap paces the window probes (EasyTier-style sustained fire,
// gentle enough not to burn CPU).
const symPunchGap = 20 * time.Millisecond

// observeProbe fires a probe from an EPHEMERAL socket so the peer can
// observe our outbound source port — that port becomes the peer's
// conntrack-matched data-plane target (EasyTier's trick: stateful
// security groups pass ESTABLISHED, and the restricted link carries
// large datagrams to conntrack-matched ports without loss). The peer
// echoes it back; we record its source as peerObsPort.
func (e *Engine) observeProbe(peerKey string, target *net.UDPAddr, nonce uint32) {
	// Use the shared mux socket (fixed source port 52888): it has an
	// existing conntrack entry toward the peer, so the probe passes
	// the peer's stateful security group. A random-source probe would
	// be dropped (no conntrack) — observed empirically.
	if e.PunchConnProvider == nil {
		return
	}
	conn := e.PunchConnProvider(target.IP)
	if conn == nil {
		return
	}
	probe := make([]byte, 6)
	probe[0], probe[1] = 0x50, 0x4C // 0x504C = observation probe (peer replies from an ephemeral socket)
	binary.BigEndian.PutUint32(probe[2:], nonce)
	conn.WriteToUDP(probe, target)
	// The peer's echo comes from its EPHEMERAL socket — its true
	// outbound source port. The shared mux read loop observes it and
	// records it via RecordObservedSource (the loop owns reads).
	log.Printf("[holepunch] %s: observation probe sent (echo observed by mux loop)", short(peerKey))
}
