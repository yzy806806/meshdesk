package holepunch

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
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

	// endpoints may be empty when META/gossip hasn't delivered the
	// peer's advertised endpoints yet (fresh boot, degraded memberlist).
	// The coordination exchange itself discovers the peer's mapped
	// address (the peer replies with its public punch endpoint), so a
	// blind punch still works — we just need SOMETHING to dial for the
	// initial socket setup. Use a placeholder host: the punch probes
	// target the mapped endpoint from coordination, not this fallback.
	fallback := ""
	if len(endpoints) > 0 {
		fallback = endpoints[0]
	}
	if fallback == "" {
		// No advertised endpoint: rely on coordination to learn the
		// peer's mapped address, then punch from the shared mux
		// socket (PunchConnProvider) so the NAT mapping matches the
		// data plane — an independent socket would open a hole the
		// data plane never sends from (conntrack mismatch, frames
		// dropped).
		peerEP, nonce, err := e.exchangePunchParams(ctx, peerKey, "")
		if err != nil || peerEP == "" || peerEP == "0.0.0.0:0" || peerEP == "[::]:0" {
			return ""
		}
		peerUDP := mustUDPAddr(peerEP)
		var conn *net.UDPConn
		if e.PunchConnProvider != nil {
			conn = e.PunchConnProvider(peerUDP.IP)
		}
		independent := conn == nil
		if independent {
			var derr error
			conn, derr = net.DialUDP("udp", nil, peerUDP)
			if derr != nil {
				return ""
			}
		}
		// Only close sockets we created — the shared mux socket is
		// owned by the transport.
		if independent {
			defer conn.Close()
		}
		if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la.Port > 0 {
			e.setOutboundPort(peerKey, la.Port)
		}
		// Register the socket with the transport so its reads are
		// drained (punchSocketPoller) — same as the normal path.
		if e.OnPunchSocket != nil {
			e.OnPunchSocket(peerKey, conn)
		}
		// Probe the mapped endpoint from this socket.
		probe := make([]byte, 6)
		probe[0] = 0x50
		probe[1] = 0x4A
		binary.BigEndian.PutUint32(probe[2:], nonce)
		for i := 0; i < punchProbeCount; i++ {
			var werr error
			if independent {
				_, werr = conn.Write(probe)
			} else {
				_, werr = conn.WriteToUDP(probe, peerUDP)
			}
			if werr != nil {
				break
			}
			if i == punchProbeCount-1 {
				return peerEP // optimistic — data plane verifies
			}
			select {
			case <-ctx.Done():
				return ""
			case <-time.After(punchProbeGap):
			}
		}
		return peerEP
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
		e.setOutboundPort(peerKey, la.Port)
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
	//    mux socket's source port is the mesh listen port (e.g. 52888
	//    by default — the actual port comes from cfg.Mesh.Port), so
	//    exchanging it is a no-op. An independent outbound socket gets
	//    a fresh source port whose NAT mapping the peer's stateful
	//    security group passes as ESTABLISHED (conntrack) — the data
	//    plane then targets that port and large datagrams flow.
	probe := make([]byte, 6) // [0x50 0x4A] + nonce(4) — mux sockets echo these
	probe[0], probe[1] = 0x50, 0x4A
	binary.BigEndian.PutUint32(probe[2:], nonce)
	reply := make([]byte, 16)

	peerUDP := mustUDPAddr(peerEP)
	// Probe socket: MUST be UNCONNECTED (ListenUDP) — the data plane
	// (udpStreamConn.Write → WriteToUDP, and routeUDPPacket readers)
	// writes to arbitrary peer addresses — Go returns EISCONN ("use
	// of WriteTo with pre-connected connection") on connected UDPConns.
	//
	// CRITICAL: when the shared mux socket is available, probe from
	// IT (not an independent socket). The probe creates the NAT/
	// conntrack mapping the peer's firewall uses to admit our frames —
	// the data plane (DialUDP kx, DialTUNUDP TUN frames) sends from
	// the SAME mux socket, so the mapping must be keyed on the mux
	// socket's source port (e.g. 52988 on ordinary nodes). An
	// independent probe socket with a random source port punches a
	// mapping the data plane never uses — the peer admits nothing and
	// every data-plane frame dies as a new connection (observed in
	// v1.6.2: kx worked via the mux socket while the independent
	// socket's hole carried nothing).
	var pconnUDP *net.UDPConn
	if shared {
		pconnUDP = conn
	} else {
		var derr error
		pconnUDP, derr = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if derr != nil {
			pconnUDP = conn
		} else {
			// KEEP the socket alive (EasyTier keeps its tunnel
			// socket): the peer's data plane targets our source
			// port, so the conntrack mapping must stay live.
			e.mu.Lock()
			// Replace the old punch conn reference without closing
			// it here — AddPunchSocket (called next via
			// OnPunchSocket) owns the Close to avoid a double-close
			// on the same conn (engine and transport both key by
			// the same peerKey and point to the same old conn).
			e.punchConn[peerKey] = pconnUDP
			obPort := 0
			if la, ok := pconnUDP.LocalAddr().(*net.UDPAddr); ok {
				obPort = la.Port
			}
			e.outboundPort[peerKey] = obPort
			e.mu.Unlock()
			if obPort > 0 {
				log.Printf("[holepunch] %s: independent outbound src port %d (conntrack target)", short(peerKey), obPort)
			}
			// Register the socket with the transport NOW — the
			// punchSocketPoller's reader loop must be running before
			// the peer's kx frames arrive (hole established → data
			// plane dials immediately). This was the missing link:
			// the socket lived only in e.punchConn, no reader ever
			// drained it.
			if e.OnPunchSocket != nil {
				e.OnPunchSocket(peerKey, pconnUDP)
			}
		}
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
// exchanges mapped endpoints + nonce + initiator identity. Returns the
// peer's mapped endpoint (preferring our own local knowledge of its
// endpoint when the exchange fails).
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
	// Frame format: [len u16][nonce u32][our][tcpPort u16][srcPort u16]
	// [easySym u8][inc u8][obsPort u16]. The len prefix lets the
	// receiver io.ReadFull the exact frame — a single conn.Read may
	// return a PARTIAL frame on a smux stream (real bug: N1 read
	// aliyun's endpoint as "203.0.113.10:528" and aliyun parsed
	// "[n1.example.com]:52888Ι" from a 1-byte-overread — the ep was
	// truncated/mangled by stream fragmentation).
	our := e.PublicPunchEP
	if our == "" {
		our = e.LocalEP
	}
	if our == "" {
		// conn here is the COORDINATION smux stream — its
		// LocalAddr() is a virtual address ("smux:local:<id>"),
		// NOT a real IP:port. Advertise nothing rather than a
		// garbage endpoint: the peer falls back to blind punching +
		// observed source ports (peerObsPort), which still works.
		// A bogus "smux:local:10" made the peer punch a nonsense
		// address and the hole never opened (observed on the
		// Redmi phone — STUN unreachable in CN, LocalEP empty).
		if la := conn.LocalAddr(); la != nil {
			our = la.String()
		}
		if our == "" || !isRealEndpoint(our) {
			our = "0.0.0.0:0"
		}
	}
	// CRITICAL: the advertised endpoint's PORT is the TCP mesh port
	// (52888) on ordinary nodes, but the peer must punch at our UDP
	// DATA port — ordinary nodes use an OS-assigned random UDP port
	// (UDPPort=-1, distinct from the TCP listener; Go breaks sends on
	// shared ports, verified on txcloud). Rewrite the port to the
	// punch socket's real outbound source port (per-peer, set
	// by punchUDP from the socket it opens), keeping the advertised
	// host. NOTE: conn here is the COORDINATION smux stream — its
	// LocalAddr is the TCP port, NOT the UDP data port, so we must
	// use the per-peer outbound port, never conn.LocalAddr().
	obPort := e.getOutboundPort(peerKey)
	if obPort > 0 {
		if host, _, herr := net.SplitHostPort(our); herr == nil {
			our = net.JoinHostPort(host, strconv.Itoa(obPort))
		}
		log.Printf("[holepunch] %s: coordination our=%s (outboundPort=%d)", short(peerKey), our, obPort)
	} else {
		log.Printf("[holepunch] %s: coordination our=%s (outboundPort unknown)", short(peerKey), our)
	}
	// Frame format: [len u16][nonce u32][ourLen u8][our][tcpPort u16]
	// [srcPort u16][easySym u8][inc u8][obsPort u16][initiatorKey 64B].
	// The ourLen byte lets the responder parse the variable-length
	// endpoint even with the trailing key field (v1.6.7+: epLen =
	// bodyLen-4-8 was wrong once the key was appended — the key leaked
	// into the endpoint and the responder's key offset shifted).
	if len(our) > 255 {
		// Endpoints are host:port strings, always < 255B — defensive
		// guard against uint8 truncation corrupting the frame.
		return fallbackEP, nonce, nil
	}
	body := make([]byte, 5+len(our)+8+len(e.IdentityKey))
	binary.BigEndian.PutUint32(body, nonce)
	body[4] = uint8(len(our))
	copy(body[5:], our)
	binary.BigEndian.PutUint16(body[5+len(our):], uint16(e.TcpPort))
	binary.BigEndian.PutUint16(body[5+len(our)+2:], uint16(e.SrcPort))
	body[5+len(our)+4] = 0
	if e.EasySym {
		body[5+len(our)+4] = 1
	}
	body[5+len(our)+5] = e.Inc
	binary.BigEndian.PutUint16(body[5+len(our)+6:], uint16(obPort))
	// Trailing field: initiator's public key (hex). The coordinator
	// (responder) uses it to key the hole and fire OnHoleEstablished —
	// without identity the responder can punch back but never
	// establishes the data plane (deadlock: both sides wait).
	copy(body[5+len(our)+8:], e.IdentityKey)
	req := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(req, uint16(len(body)))
	copy(req[2:], body)
	if _, err := conn.Write(req); err != nil {
		return fallbackEP, nonce, nil
	}

	// Read the peer's reply: [len u16][nonce u32][their endpoint]...
	// ReadFull the whole frame — partial reads corrupt the endpoint.
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return fallbackEP, nonce, nil
	}
	bodyLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if bodyLen < 4 || bodyLen > 512 {
		return fallbackEP, nonce, nil
	}
	body = make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return fallbackEP, nonce, nil
	}
	peerNonce := binary.BigEndian.Uint32(body)
	// Response format: [nonce u32][our][8 bytes trailing].
	// The 8 trailing bytes carry the peer's TCP punch port, outbound
	// source port, EasySym/Inc, and observed source port.
	peerEP := string(body[4:])
	if bodyLen >= 12 {
		epLen := bodyLen - 4 - 8
		peerEP = string(body[4 : 4+epLen])
		e.mu.Lock()
		e.peerTCPPort[peerKey] = int(binary.BigEndian.Uint16(body[4+epLen:]))
		e.peerSrcPort[peerKey] = int(binary.BigEndian.Uint16(body[4+epLen+2:]))
		e.peerEasySym[peerKey] = body[4+epLen+4] == 1
		e.peerInc[peerKey] = int(int8(body[4+epLen+5]))
		e.peerObsPort[peerKey] = int(binary.BigEndian.Uint16(body[4+epLen+6:]))
		e.mu.Unlock()
		log.Printf("[holepunch] %s: peer response n=%d peerObsPort=%d", short(peerKey), bodyLen, e.peerObsPort[peerKey])
	} else {
		log.Printf("[holepunch] %s: peer response n=%d (<12 — too short, no trailing fields)", short(peerKey), bodyLen)
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

	// Read the [len u16]-prefixed frame fully — a single conn.Read may
	// return a PARTIAL frame on a smux stream (fragmentation corrupted
	// the endpoint: N1 parsed aliyun's "203.0.113.10:52888" as
	// "203.0.113.10:528", and aliyun got "[n1.example.com]:52888Ι"
	// from a 1-byte overread).
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	bodyLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if bodyLen < 4 || bodyLen > 512 {
		return
	}
	buf := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	nonce := binary.BigEndian.Uint32(buf)
	peerEP := string(buf[4:])
	peerTCP := 0
	peerSrc := 0
	peerEasySym := false
	peerInc := 0
	peerObs := 0
	peerKey := ""
	// Frame: [nonce u32][ourLen u8][our][tcpPort u16][srcPort u16]
	// [easySym u8][inc u8][obsPort u16][initiatorKey 64B] (v1.6.8).
	// Legacy frames (pre-ourLen): [nonce u32][our][tcpPort...8][key?].
	// OurLen byte disambiguates the variable endpoint length — the
	// old epLen = bodyLen-4-8 leaked the trailing key into the
	// endpoint once the key field was added (v1.6.7 bug).
	if bodyLen >= 13 && buf[4] > 0 && int(buf[4]) < bodyLen-12 {
		// v1.6.8+ format: explicit endpoint length.
		epLen := int(buf[4])
		peerEP = string(buf[5 : 5+epLen])
		if bodyLen >= 5+epLen+12 {
			peerTCP = int(binary.BigEndian.Uint16(buf[5+epLen:]))
			peerSrc = int(binary.BigEndian.Uint16(buf[5+epLen+2:]))
			peerEasySym = buf[5+epLen+4] == 1
			peerInc = int(int8(buf[5+epLen+5]))
			peerObs = int(binary.BigEndian.Uint16(buf[5+epLen+6:]))
			if bodyLen > 5+epLen+12 {
				peerKey = string(buf[5+epLen+12:])
			}
		}
	} else if bodyLen >= 12 {
		// Legacy format: endpoint is everything between nonce and the
		// 8-byte tail (TCP port, src port, easySym, inc, obsPort).
		// The key (if present, v1.6.7) trails after — detect by
		// checking the tail bytes look like ports/flags, else treat
		// the whole tail as endpoint (pre-key frames).
		epLen := bodyLen - 4 - 8
		if epLen > 0 {
			peerEP = string(buf[4 : 4+epLen])
			peerTCP = int(binary.BigEndian.Uint16(buf[4+epLen:]))
			peerSrc = int(binary.BigEndian.Uint16(buf[4+epLen+2:]))
			peerEasySym = buf[4+epLen+4] == 1
			peerInc = int(int8(buf[4+epLen+5]))
			peerObs = int(binary.BigEndian.Uint16(buf[4+epLen+6:]))
			if bodyLen > 4+epLen+12 {
				peerKey = string(buf[4+epLen+12:])
			}
		}
	}
	if peerKey != "" {
		log.Printf("[holepunch] coordinator: initiator key %s", short(peerKey))
	}

	// Ensure our outbound source port is valid BEFORE answering: the
	// peer's data plane targets it (conntrack). If we haven't punched
	// yet (we answer first), open a socket toward the peer's endpoint
	// — the NAT mapping is created by the outbound probe and its
	// source port becomes the conntrack target.
	//
	// Prefer the SHARED mux socket (PunchConnProvider): the data
	// plane (DialUDP/DialTUNUDP) sends from the same socket, so its
	// source port (e.g. 52988 on ordinary nodes) must be the conntrack
	// target. An independent socket with a random port would make the
	// peer punch a port the data plane never sends from — conntrack
	// mismatch, frames dropped (observed in v1.6.2: kx succeeded via
	// the shared socket but the TUN plane's independent socket got no
	// ACK).
	if e.getOutboundPort(peerEP) == 0 && peerEP != "" && peerEP != "0.0.0.0:0" && peerEP != "[::]:0" {
		if pu := mustUDPAddr(peerEP); pu != nil {
			var pc *net.UDPConn
			if e.PunchConnProvider != nil {
				if rc := e.PunchConnProvider(pu.IP); rc != nil {
					pc = rc
				}
			}
			if pc == nil {
				// No shared socket (or family mismatch): open an
				// UNCONNECTED socket (ListenUDP) — the probe below
				// uses WriteToUDP, and the kept-alive socket must
				// accept WriteToUDP data-plane frames later (a
				// connected socket would EISCONN on every write).
				if p, derr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0}); derr == nil {
					pc = p
				}
			}
			if pc != nil {
				e.mu.Lock()
				if e.punchConn == nil {
					e.punchConn = make(map[string]*net.UDPConn)
				}
				obPort := 0
				if la, ok := pc.LocalAddr().(*net.UDPAddr); ok {
					obPort = la.Port
				}
				e.outboundPort[peerEP] = obPort
				// Replace the old punch conn reference without
					// closing it here — AddPunchSocketAddr (called
					// next via OnPunchSocket) owns the Close to
					// avoid a double-close on the same conn.
					e.punchConn[peerEP] = pc
				// Fire a probe to create the NAT mapping.
				pr := make([]byte, 6)
				pr[0], pr[1] = 0x50, 0x4A
				binary.BigEndian.PutUint32(pr[2:], nonce)
				pc.WriteToUDP(pr, pu)
				e.mu.Unlock()
				// Register with the transport so a reader loop
				// drains the peer's data-plane frames (kx/TUN).
				if e.OnPunchSocket != nil {
					e.OnPunchSocket(peerEP, pc)
				}
				log.Printf("[holepunch] coordinator: pre-answer outbound src port %d (conntrack target)", obPort)
			}
		}
	}

	// Reply with our mapped endpoint (best-effort). Fall back to the
	// local conn address when STUN didn't provide a mapped endpoint —
	// "0.0.0.0:0" would make the peer's punch target invalid.
	our := e.PublicPunchEP
	if our == "" || our == "0.0.0.0:0" || our == "[::]:0" {
		our = e.LocalEP
	}
	if our == "" || our == "0.0.0.0:0" || our == "[::]:0" {
		// conn is a COORDINATION smux stream — LocalAddr() is a
		// virtual address ("smux:local:<id>"), never a real IP:port.
		// Advertise 0.0.0.0:0 instead so the peer blind-punches +
		// uses observed source ports rather than a garbage target
		// (Redmi: STUN unreachable → LocalEP empty → "smux:local:10"
		// leaked into the reply → hole never opened).
		if la := conn.LocalAddr(); la != nil {
			our = la.String()
		}
		if our == "" || !isRealEndpoint(our) {
			our = "0.0.0.0:0"
		}
	}
	// CRITICAL (mirrors exchangePunchParams): the advertised port is
	// the TCP mesh port on ordinary nodes, but the peer must punch at
	// our UDP DATA port (ordinary nodes use an OS-assigned random UDP
	// port, distinct from the TCP listener — Go breaks sends on
	// shared ports). The punch socket's source port is the conntrack
	// target.
	//
	// Resolve the punch socket port FRESH for this peer's family:
	// outboundPort is per-peer keyed by endpoint, so a DIFFERENT
	// peer's punch (e.g. a v6 peer) does not overwrite this one —
	// but we still re-resolve via PunchConnProvider when available
	// (it returns the socket matched to the peer's IP family).
	if e.PunchConnProvider != nil {
		if pu := mustUDPAddr(peerEP); pu != nil {
			if rc := e.PunchConnProvider(pu.IP); rc != nil {
				if la, ok := rc.LocalAddr().(*net.UDPAddr); ok && la.Port > 0 {
					e.setOutboundPort(peerEP, la.Port)
				}
			}
		}
	}
	obPort := e.getOutboundPort(peerEP)
	if obPort > 0 {
		if host, _, herr := net.SplitHostPort(our); herr == nil {
			our = net.JoinHostPort(host, strconv.Itoa(obPort))
		}
		log.Printf("[holepunch] coordinator: reply our=%s (outboundPort=%d)", our, obPort)
	}
	// Response format: [nonce u32][our][tcpPort u16]
	// [srcPort u16][easySym u8][inc u8][obsPort u16] (8 trailing bytes).
	// Kept the same as the request MINUS the ourLen byte for backward
	// compatibility: a new-version coordinator may reply to an
	// old-version initiator, and the old parser uses epLen = bodyLen-4-8
	// — adding a ourLen byte would shift the endpoint by one. The
	// initiator parser below detects the ourLen byte heuristically.
	if len(our) > 255 {
		our = "0.0.0.0:0"
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
	binary.BigEndian.PutUint16(resp[4+len(our)+6:], uint16(obPort))
	// [len u16] prefix so the initiator can ReadFull the exact frame
	// (a single Read on a smux stream may fragment).
	framed := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(framed, uint16(len(resp)))
	copy(framed[2:], resp)
	if _, err := conn.Write(framed); err != nil {
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
	//
	// The responder-side OnHoleEstablished (below) must fire AFTER
	// blindPunch's probes leave the socket — otherwise the app layer
	// DialUDPPeer races ahead and its kx frames arrive before the
	// peer's conntrack entry exists (dropped). blindPunch is quick
	// (punchProbeCount × punchProbeGap), so run it inline-then-fire.
	go e.blindPunch(peerEP, nonce)

	// Responder-side hole establishment: the initiator's identity is
	// carried in the coordination frame (v1.6.7+). Record the hole on
	// our side too and fire OnHoleEstablished — without this the
	// responder punches back (blindPunch) but never keys the hole by
	// peer, so neither side dials the data plane (deadlock: both wait
	// for the other's kx).
	//
	// Fire asynchronously with a small delay: blindPunch is in-flight
	// (goroutine above); a 50ms head-start lets its probes create the
	// peer-side conntrack before DialUDPPeer's kx frames arrive.
	if peerKey != "" && e.OnHoleEstablished != nil {
		// our (this node's) mapped endpoint as seen by the initiator:
		// the reply we built above (our) already carries the UDP data
		// port (OutboundPort-resolved, lines 509-536). PublicPunchEP
		// alone may be the TCP mesh port (52888) — the peer's kx/data
		// egresses from our punch socket (the UDP data port), so the
		// hole must be keyed by that, not the TCP port.
		ourEP := our
		if ourEP == "" {
			ourEP = e.PublicPunchEP
		}
		if ourEP == "" {
			ourEP = e.LocalEP
		}
		if ourEP != "" && ourEP != "0.0.0.0:0" && ourEP != "[::]:0" {
			ep := ourEP
			key := peerKey
			// Give blindPunch (goroutine above) time to land its
			// probes — the peer's conntrack entry must exist before
			// DialUDPPeer's kx frames arrive, else they are dropped.
			go func() {
				time.Sleep(50 * time.Millisecond)
				log.Printf("[holepunch] coordinator: responder hole to %s (our %s)", short(key), ep)
				e.OnHoleEstablished(key, ep, "udp")
			}()
		}
	}
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

// isRealEndpoint reports whether s parses as a real IP:port endpoint.
// Rejects the smux virtual address form ("smux:local:<id>") that a
// coordination stream's LocalAddr() returns — advertising that as the
// punch target makes the peer punch a nonsense address and the hole
// never opens (Redmi: STUN unreachable → LocalEP empty → LocalAddr
// leaked "smux:local:10" into the coordination reply).
func isRealEndpoint(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	if host == "" || port == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Allow DNS names (e.g. n1.example.com) but not smux: pseudo-schemes.
		return !strings.Contains(host, ":") && !strings.Contains(host, "smux")
	}
	return true
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
