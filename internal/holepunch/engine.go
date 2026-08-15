// Package holepunch implements a memberlist-independent NAT
// hole-punching engine for meshdesk v1.6.
//
// Motivation: the old p2p/nat.go hole-punching only triggered from
// gossip NotifyJoin and relied on gossip NodeMeta for endpoints — with
// degraded memberlist it never ran ("约等于没有"). This engine:
//
//   - triggers from the meta exchange (0x4D45, memberlist-independent)
//     and lazily on first TUN traffic to a relayed peer
//   - coordinates through a dedicated virtual port (0x504A) on shared
//     nodes: peers exchange STUN-mapped addresses and punch
//     simultaneously (EasyTier-style)
//   - multi-strategy: two-way UDP first, TCP punch fallback, symmetric
//     NAT port prediction, IPv6 direct attempt
//   - feeds a successful hole into the mesh UDP multipath
//     (getUDPStream) for low-latency data plane
//
// Design: docs/DESIGN_V16_SPLIT_AND_HOLEPUNCH.md §3.
package holepunch

import (
	"context"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// HolePunchVirtualPort is the coordination virtual port (0x504A).
const HolePunchVirtualPort = 0x504A

// NatType mirrors the p2p NAT classification (kept local to avoid
// import cycles).
type NatType int

const (
	NatUnknown NatType = iota
	NatFullCone
	NatRestricted
	NatPortRestricted
	NatSymmetric
)

// Engine is the hole-punching state machine. Per-peer sessions are
// created on demand from meta-exchange / lazy triggers.
type Engine struct {
	mu              sync.Mutex
	sessions        map[string]*Session
	peerTCPPort     map[string]int // peerKey -> TCP punch port (from coordination)
	peerSrcPort     map[string]int // peerKey -> peer outbound TCP source port (conntrack punch)
	peerEasySym     map[string]bool
	peerInc         map[string]int
	peerObsPort     map[string]int
	punchConn       map[string]*net.UDPConn // kept-alive punch sockets (data plane dials through)
	observedSrcPort map[string]int          // our outbound src port the peer echoed back

	// Dialer is how the engine opens the coordination stream to a
	// peer (over an existing smux session or relay).
	Dialer Dialer

	// LocalEP is our STUN-discovered public endpoint (host:port).
	LocalEP string
	// LocalNAT is our detected NAT type.
	LocalNAT NatType
	// PunchPort is the local UDP port we punch from (0 = ephemeral).
	PunchPort int

	// OnHoleEstablished is called with the punched remote endpoint
	// and hole type ("udp" / "tcp") when a hole succeeds — the mesh
	// layer feeds it into the matching data path.
	OnHoleEstablished func(peerKey, punchedEndpoint, holeType string)

	// PunchConnProvider returns the shared UDP socket to punch from
	// (the mesh mux socket — same NAT mapping the data plane uses).
	// When nil, punch opens its own socket bound to PunchPort.
	PunchConnProvider func(remoteIP net.IP) *net.UDPConn

	// OnPunchSocket is called whenever the engine creates a kept-alive
	// punch socket (independent outbound socket in punchUDP, or the
	// pre-answer socket in HandleCoordinatorStream). The app layer
	// registers it with the transport (AddPunchSocket/AddPunchSocketAddr)
	// so the punchSocketPoller picks it up and its reader loop feeds
	// received datagrams (key exchange frames, TUN data) into the UDP
	// mesh manager. Without this registration the socket has NO reader
	// goroutine and the peer's kx frames arrive into a black hole —
	// the classic "hole established but key exchange EOF".
	// key is the peer key (punchUDP) or the remote endpoint string
	// (HandleCoordinatorStream pre-answer — no peer key there).
	OnPunchSocket func(key string, conn *net.UDPConn)

	// PublicPunchEP is the endpoint we advertise in the punch
	// coordination exchange: the public IP (from STUN) + the mux
	// socket port. This is the address the peer must punch at for the
	// hole to match our data-plane NAT mapping. When empty, LocalEP
	// or the conn local address is used as fallback.
	PublicPunchEP string

	// IdentityKey is our public key (hex). Carried in the punch
	// coordination frame so the RESPONDER can key the hole by peer
	// identity and fire OnHoleEstablished — without it the responder
	// punches back but never establishes the data plane (deadlock:
	// both sides wait for the other to dial).
	IdentityKey string

	// TcpPort is our local TCP listen port for TCP hole punching
	// (both sides listen + connect simultaneously — EasyTier-style).
	// Advertised in the punch coordination exchange so the peer knows
	// where to blind-connect.
	TcpPort int

	// SrcPort is our outbound TCP source port for the conntrack punch
	// (EasyTier-style): after our first outbound connect, the NAT
	// mapping is keyed by this source port; the peer connects to it
	// and stateful security groups pass it as ESTABLISHED.
	SrcPort int

	// EasySym marks our NAT as symmetric with a predictable mapped-port
	// increment (NAT4E) — the peer scans our base port ± window.
	EasySym bool
	// Inc is our mapped-port increment direction (+1 / -1).
	Inc byte

	// OutboundPort is OUR outbound socket source port (the punch
	// socket's LocalAddr). Exchanged in the coordination message so
	// the peer targets it for data — its stateful security group
	// passes it as ESTABLISHED (EasyTier's conntrack trick).
	OutboundPort int

	// Cooldown between punch attempts per peer (exponential).
	backoff map[string]time.Time
}

// Dialer abstracts the mesh session dial (implemented by the app layer).
type Dialer interface {
	// DialVirtualPort opens a stream to peer's virtual port.
	DialVirtualPort(ctx context.Context, peerKey string, port int) (net.Conn, error)
}

// Session tracks the hole-punch state for one peer.
type Session struct {
	peerKey string
	mu      sync.Mutex

	state     state
	attempts  int
	lastTry   time.Time
	endpoints []string // candidate remote endpoints (STUN-mapped)
	natType   NatType
}

type state int

const (
	stateIdle state = iota
	statePunching
	stateHoleEstablished
	stateFailed
)

// New creates a hole-punch engine.
func New(d Dialer) *Engine {
	return &Engine{
		sessions:        make(map[string]*Session),
		peerTCPPort:     make(map[string]int),
		peerSrcPort:     make(map[string]int),
		peerEasySym:     make(map[string]bool),
		peerInc:         make(map[string]int),
		peerObsPort:     make(map[string]int),
		punchConn:       make(map[string]*net.UDPConn),
		observedSrcPort: make(map[string]int),
		Dialer:          d,
		backoff:         make(map[string]time.Time),
	}
}

// SetLocalInfo sets our STUN-discovered endpoint + NAT type. The
// punch port is derived from the mapped endpoint so our NAT mapping
// (created by the STUN exchange) is reused for the punch probes —
// punching from an ephemeral port would open a different mapping.
func (e *Engine) SetLocalInfo(ep string, nat NatType) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.LocalEP = ep
	e.LocalNAT = nat
	if _, portStr, err := net.SplitHostPort(ep); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil {
			e.PunchPort = p
		}
	}
}

// Trigger starts a punch attempt for a peer (idempotent; respects
// cooldown). endpoints are the peer's candidate addresses.
func (e *Engine) Trigger(peerKey string, endpoints []string, peerNat NatType) {
	e.mu.Lock()
	if t, ok := e.backoff[peerKey]; ok && time.Now().Before(t) {
		e.mu.Unlock()
		return // in cooldown
	}
	s, ok := e.sessions[peerKey]
	if !ok {
		s = &Session{peerKey: peerKey, endpoints: endpoints, natType: peerNat}
		e.sessions[peerKey] = s
	}
	e.mu.Unlock()

	s.mu.Lock()
	if s.state == statePunching || s.state == stateHoleEstablished {
		s.mu.Unlock()
		return
	}
	s.state = statePunching
	s.attempts++
	s.lastTry = time.Now()
	s.endpoints = endpoints
	s.mu.Unlock()

	go e.punch(peerKey, endpoints, peerNat)
}

// punch runs the strategy chain for one attempt: UDP two-way → TCP →
// (future) symmetric prediction → IPv6.
func (e *Engine) punch(peerKey string, endpoints []string, peerNat NatType) {
	start := time.Now()
	log.Printf("[holepunch] %s: punch attempt (nat=%v, endpoints=%d)", short(peerKey), peerNat, len(endpoints))

	// Strategy 1: two-way UDP via coordinator. Keep the UDP hole as a
	// fallback: on some links UDP >60B datagrams are dropped (packet
	// length filtering) while the 6B probes pass — the TCP hole is the
	// reliable data plane there (EasyTier's tcp tunnel).
	udpEP := e.punchUDP(peerKey, endpoints)
	if udpEP != "" {
		log.Printf("[holepunch] %s: UDP hole open at %s — also trying TCP", short(peerKey), udpEP)
		if tcpEP := e.punchTCP(peerKey, endpoints); tcpEP != "" {
			log.Printf("[holepunch] %s: TCP hole open at %s — preferring TCP", short(peerKey), tcpEP)
			e.establishedTCP(peerKey, tcpEP)
			return
		}
		e.established(peerKey, udpEP)
		return
	}
	// Strategy 2: TCP punch.
	if ep := e.punchTCP(peerKey, endpoints); ep != "" {
		e.establishedTCP(peerKey, ep)
		return
	}

	// All strategies failed — exponential cooldown (30s × 2^n, cap 10m).
	e.mu.Lock()
	n := 1
	if s := e.sessions[peerKey]; s != nil {
		n = s.attempts
	}
	window := 30 * time.Second << (n - 1)
	if window > 10*time.Minute {
		window = 10 * time.Minute
	}
	e.backoff[peerKey] = time.Now().Add(window)
	e.mu.Unlock()

	e.mu.Lock()
	if s := e.sessions[peerKey]; s != nil {
		s.mu.Lock()
		s.state = stateFailed
		s.mu.Unlock()
	}
	e.mu.Unlock()
	log.Printf("[holepunch] %s: all strategies failed (%v), next try in %v", short(peerKey), time.Since(start).Round(time.Millisecond), window)
}

// established records a successful hole and hands the punched endpoint
// to the mesh layer (getUDPStream).
func (e *Engine) established(peerKey, ep string) {
	e.establishedTyped(peerKey, ep, "udp")
}

// establishedTCP records a TCP hole (the reliable data plane on links
// that drop UDP >60B).
func (e *Engine) establishedTCP(peerKey, ep string) {
	e.establishedTyped(peerKey, ep, "tcp")
}

// establishedTyped is the shared hole-success path; holeType is "udp"
// or "tcp" so the app layer can wire the right data path.
func (e *Engine) establishedTyped(peerKey, ep, holeType string) {
	e.mu.Lock()
	if s := e.sessions[peerKey]; s != nil {
		s.mu.Lock()
		s.state = stateHoleEstablished
		s.mu.Unlock()
	}
	delete(e.backoff, peerKey)
	e.mu.Unlock()
	log.Printf("[holepunch] %s: hole established via %s (%s)", short(peerKey), ep, holeType)
	if e.OnHoleEstablished != nil {
		e.OnHoleEstablished(peerKey, ep, holeType)
	}
}

// Forget removes a peer (session death / leave).
func (e *Engine) Forget(peerKey string) {
	e.mu.Lock()
	delete(e.sessions, peerKey)
	delete(e.backoff, peerKey)
	e.mu.Unlock()
}

// Status returns a snapshot for diagnostics.
func (e *Engine) Status() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]any, len(e.sessions))
	for k, s := range e.sessions {
		s.mu.Lock()
		out[k[:min(len(k), 8)]] = map[string]any{
			"state":    s.state.String(),
			"attempts": s.attempts,
			"nat":      s.natType.String(),
		}
		s.mu.Unlock()
	}
	return out
}

func (s state) String() string {
	switch s {
	case stateIdle:
		return "idle"
	case statePunching:
		return "punching"
	case stateHoleEstablished:
		return "hole_established"
	case stateFailed:
		return "failed"
	}
	return "unknown"
}

func (n NatType) String() string {
	switch n {
	case NatFullCone:
		return "full_cone"
	case NatRestricted:
		return "restricted"
	case NatPortRestricted:
		return "port_restricted"
	case NatSymmetric:
		return "symmetric"
	}
	return "unknown"
}

func short(k string) string {
	if len(k) <= 8 {
		return k
	}
	return k[:8]
}

// PeerObservedPort returns the peer's outbound source port observed on
// our probe socket (0 for unknown) — the conntrack-matched data-plane
// target.
func (e *Engine) PeerObservedPort(peerKey string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.peerObsPort[peerKey]
}
