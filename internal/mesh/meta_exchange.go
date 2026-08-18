package mesh

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// MetaVirtualPort is the smux virtual port for session-based peer
// metadata exchange (P1: VIP propagation independent of memberlist).
// 0x4D45 = 'M' 'E' — mnemonic for "META".
const MetaVirtualPort = 0x4D45

// maxMetaTTL caps the gossip flood depth to prevent cycles.
const maxMetaTTL = 4

// MetaMessage is exchanged over smux sessions between directly
// connected peers. It carries the sender's own metadata plus what the
// sender knows about other peers, so VirtualIP/hostname knowledge
// floods the session graph without depending on memberlist (which
// degrades for NAT'd / mixed-family nodes).
type MetaMessage struct {
	Type  string     `json:"t"`    // "meta"
	Self  PeerMeta   `json:"self"` // sender's own metadata
	Peers []PeerMeta `json:"peers"`
	Seq   uint64     `json:"seq"` // sender's meta sequence (dedup)
	TTL   uint8      `json:"ttl"` // flood hop limit
}

// PeerMeta is a single peer's identity + VirtualIP knowledge.
type PeerMeta struct {
	Key      string `json:"k"`
	VIP      string `json:"v"`
	Hostname string `json:"h"`
	// Zone is the peer's zone tag (transport-selection signal).
	Zone string `json:"z,omitempty"`
	// Endpoints are the peer's reachable IP:port endpoints — propagated
	// so same-zone peers can dial UDP/TCP directly even when memberlist
	// (the usual endpoint source) is degraded.
	Endpoints []string `json:"e,omitempty"`
	// Collector marks a peer that runs the dashboard/monitor aggregator
	// (CapCollector). Propagated via META so relay-attached nodes whose
	// memberlist is degraded still discover where to push metrics —
	// gossip-based CapCollector discovery never reaches them.
	Collector bool `json:"c,omitempty"`
	// Relay/NAT fields (memberlist-retirement phase 1): these used to
	// be gossip-NodeMeta-exclusive. Carrying them in META lets relay
	// selection and NAT-type awareness work when memberlist is
	// degraded or (eventually) gone.
	Role         string `json:"r,omitempty"`
	NatType      string `json:"nt,omitempty"`
	CapRelay     bool   `json:"cr,omitempty"`
	MaxCircuits  int    `json:"mc,omitempty"`
	LoadCircuits int    `json:"lc,omitempty"`
}

// MetaRelayInfo is the relay/NAT knowledge META carries about a node —
// the gossip-NodeMeta-exclusive fields migrated to the session meta
// plane (memberlist-retirement phase 1).
type MetaRelayInfo struct {
	Role         string
	NatType      string
	CapRelay     bool
	MaxCircuits  int
	LoadCircuits int
}

func (m MetaRelayInfo) empty() bool {
	return m.Role == "" && m.NatType == "" && !m.CapRelay && m.MaxCircuits == 0 && m.LoadCircuits == 0
}

// MetaExchanger maintains per-peer meta sequence numbers and floods
// VirtualIP knowledge over smux sessions.
type MetaExchanger struct {
	node *MeshNode

	mu       sync.Mutex
	peerSeq  map[string]uint64 // peer key → last processed meta seq
	seen     map[string]uint64 // "source|seq" dedup for flood
	listener net.Listener
	done     chan struct{}

	bcastMu       sync.Mutex
	lastBroadcast time.Time // throttle for Broadcast() (5s min spacing)
}

// RegisterMetaExchanger starts the session-based meta exchange.
// Called once at node startup (main.go).
func (n *MeshNode) RegisterMetaExchanger() (*MetaExchanger, error) {
	ln, err := n.ListenVirtualPort(MetaVirtualPort)
	if err != nil {
		return nil, err
	}
	me := &MetaExchanger{
		node:     n,
		peerSeq:  make(map[string]uint64),
		seen:     make(map[string]uint64),
		listener: ln,
		done:     make(chan struct{}),
	}
	go me.acceptLoop()
	log.Printf("[meta] session meta exchange listening on virtual port 0x%x", MetaVirtualPort)
	return me, nil
}

// Close stops the meta exchanger.
func (me *MetaExchanger) Close() {
	select {
	case <-me.done:
		return
	default:
		close(me.done)
	}
	if me.listener != nil {
		me.listener.Close()
	}
}

func (me *MetaExchanger) acceptLoop() {
	for {
		conn, err := me.listener.Accept()
		if err != nil {
			select {
			case <-me.done:
				return
			default:
				continue
			}
		}
		go me.handleIncoming(conn)
	}
}

// handleIncoming processes a meta message received from a connected
// peer: learns the sender's own meta + everything the sender knows,
// then floods the new knowledge to other peers (TTL-bounded).
func (me *MetaExchanger) handleIncoming(conn net.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Identify the remote peer from the smux stream wrapper.
	var remoteKey string
	if cp, ok := conn.(*connWithPeer); ok {
		remoteKey = cp.PeerID()
	}
	if remoteKey == "" {
		log.Printf("[meta] incoming meta with no peer identity, ignoring")
		return
	}

	var msg MetaMessage
	if err := json.NewDecoder(ioLimitReader(conn, 1<<20)).Decode(&msg); err != nil {
		log.Printf("[meta] decode from %s: %v", shortKey(remoteKey), err)
		return
	}

	me.apply(remoteKey, msg)
}

// apply learns the message content and floods new knowledge.
func (me *MetaExchanger) apply(fromKey string, msg MetaMessage) {
	if msg.Type != "meta" {
		return
	}
	me.mu.Lock()
	last, seen := me.peerSeq[fromKey]
	if seen && msg.Seq <= last {
		me.mu.Unlock()
		return // stale
	}
	me.peerSeq[fromKey] = msg.Seq
	dedup := msg.Self.Key + "|" + u64str(msg.Seq)
	if lastSeen, ok := me.seen[dedup]; ok && lastSeen >= msg.Seq {
		me.mu.Unlock()
		return
	}
	me.seen[dedup] = msg.Seq
	// Bound the dedup/sequence maps: a long-lived node with many peers
	// and frequent meta updates must not grow these forever.
	me.boundMapsLocked()
	me.mu.Unlock()

	// Learn the sender's own metadata.
	if msg.Self.Key != "" && msg.Self.VIP != "" {
		me.node.AddPeerVirtualIPRoute(msg.Self.Key, msg.Self.VIP)
		log.Printf("[meta] learned %s → %s (%s) from %s",
			shortKey(msg.Self.Key), msg.Self.VIP, msg.Self.Hostname, shortKey(fromKey))
	}
	if msg.Self.Key != "" && msg.Self.Hostname != "" {
		me.node.SetLearnedHostname(msg.Self.Key, msg.Self.Hostname)
	}
	// Learn the sender's zone (transport-selection signal) — cached
	// independently of memberlist health.
	if msg.Self.Key != "" && msg.Self.Zone != "" {
		me.node.SetLearnedZone(msg.Self.Key, msg.Self.Zone)
	}
	// Collector discovery via META: the sender runs the dashboard
	// aggregator — auto-add it as a metrics destination. This is the
	// relay-attached counterpart to gossip CapCollector discovery
	// (gossip never reaches nodes whose memberlist is degraded).
	if msg.Self.Collector {
		me.node.notifyCollectorDiscovered(msg.Self.Key)
	}
	// Learn everything the sender knows about other peers.
	for _, pm := range msg.Peers {
		if pm.Key != "" && pm.VIP != "" {
			me.node.AddPeerVirtualIPRoute(pm.Key, pm.VIP)
			// VIP conflict check: if the peer's VIP matches our
			// local VIP, trigger IPAM reallocation (gossip's
			// ReallocateAfterGossip did this; with gossip retired,
			// META must do it too).
			me.node.CheckVIPConflict(pm.VIP)
		}
		if pm.Key != "" && pm.Zone != "" {
			me.node.SetLearnedZone(pm.Key, pm.Zone)
		}
		if pm.Key != "" && pm.Hostname != "" {
			me.node.SetLearnedHostname(pm.Key, pm.Hostname)
		}
		if pm.Key != "" && len(pm.Endpoints) > 0 {
			me.node.SetLearnedEndpoints(pm.Key, pm.Endpoints)
		}
		// Collector capability floods through the peer list too — a
		// relay hop may learn the dashboard node from a third peer.
		if pm.Collector {
			me.node.notifyCollectorDiscovered(pm.Key)
		}
		// Relay/NAT knowledge (memberlist-retirement phase 1).
		if pm.Key != "" {
			me.node.RecordPeerRelayMeta(pm.Key, MetaRelayInfo{
				Role:         pm.Role,
				NatType:      pm.NatType,
				CapRelay:     pm.CapRelay,
				MaxCircuits:  pm.MaxCircuits,
				LoadCircuits: pm.LoadCircuits,
			})
			// Auto-connect relay-capable peers: a node that joins
			// via ONE shared node learns the OTHERS (CapRelay=true)
			// from meta and connects to them directly. Without this,
			// every node depends on its single seed shared node and
			// that node is a single point of failure (the phone only
			// ever sessions with aliyun even though N1 is a shared
			// node too — learned, but never dialed).
			if pm.CapRelay {
				me.node.AutoConnectRelayPeer(pm.Key)
			}
		}
	}
	// Also learn the sender's own endpoints.
	if msg.Self.Key != "" && len(msg.Self.Endpoints) > 0 {
		me.node.SetLearnedEndpoints(msg.Self.Key, msg.Self.Endpoints)
	}
	// ... and the sender's own relay/NAT knowledge.
	if msg.Self.Key != "" {
		me.node.RecordPeerRelayMeta(msg.Self.Key, MetaRelayInfo{
			Role:         msg.Self.Role,
			NatType:      msg.Self.NatType,
			CapRelay:     msg.Self.CapRelay,
			MaxCircuits:  msg.Self.MaxCircuits,
			LoadCircuits: msg.Self.LoadCircuits,
		})
		// The sender itself may be a relay-capable shared node we
		// have no session with (e.g. a relay-attached peer we only
		// know through a third node's flood) — connect to it too.
		if msg.Self.CapRelay {
			me.node.AutoConnectRelayPeer(msg.Self.Key)
		}
	}

	// Flood the new knowledge to our other peers (bounded TTL). The
	// TTL is incremented once per hop — not once per recipient (the
	// old code incremented inside the loop, so the Nth peer received
	// TTL=N and large meshes exhausted maxMetaTTL after a few hops).
	if msg.TTL >= maxMetaTTL {
		return
	}
	msg.TTL++
	var wg sync.WaitGroup
	for _, key := range me.node.SessionPeerKeys() {
		if key == fromKey || key == msg.Self.Key {
			continue
		}
		// Parallel sends: a slow peer must not block the flood to
		// the rest of the mesh.
		wg.Add(1)
		go func(k string, m MetaMessage) {
			defer wg.Done()
			me.sendTo(k, m)
		}(key, msg)
	}
	wg.Wait()
}

// boundMapsLocked caps the size of the dedup maps (caller holds me.mu).
// A full rebuild is coarse but cheap and bounded — these maps are pure
// dedup caches; dropping old entries only risks one redundant re-send.
func (me *MetaExchanger) boundMapsLocked() {
	if len(me.seen) > 4096 {
		me.seen = make(map[string]uint64)
	}
	if len(me.peerSeq) > 512 {
		me.peerSeq = make(map[string]uint64)
	}
}

// countCollectorPeers returns how many peers in a meta message carry
// the Collector flag (debug helper for the send path).
func countCollectorPeers(msg MetaMessage) int {
	n := 0
	for _, pm := range msg.Peers {
		if pm.Collector {
			n++
		}
	}
	return n
}

// NotifyPeerJoined is called when a session is established with a new
// peer (or reconnected): send our full knowledge to that peer.
func (me *MetaExchanger) NotifyPeerJoined(peerKey string) {
	msg := MetaMessage{
		Type:  "meta",
		Self:  me.localMeta(),
		Peers: me.knownPeers(),
		Seq:   uint64(time.Now().UnixNano()),
		TTL:   0,
	}
	me.sendTo(peerKey, msg)
}

// Broadcast re-sends our full knowledge to every session peer. Called
// when local state that peers must learn CHANGED (e.g. this node
// became/learned a collector, or a new session was established — the
// peer graph changed and peers that connected earlier must learn the
// newcomer's zone/endpoints/collector capability). Meta is otherwise
// only exchanged once per session establishment.
//
// Throttled: a flapping session (mobile reconnect every few minutes)
// would otherwise trigger a full broadcast per reconnect. 5s minimum
// spacing keeps the mesh quiet while still converging quickly.
func (me *MetaExchanger) Broadcast() {
	now := time.Now()
	me.bcastMu.Lock()
	if !me.lastBroadcast.IsZero() && now.Sub(me.lastBroadcast) < 5*time.Second {
		me.bcastMu.Unlock()
		return
	}
	me.lastBroadcast = now
	me.bcastMu.Unlock()

	msg := MetaMessage{
		Type:  "meta",
		Self:  me.localMeta(),
		Peers: me.knownPeers(),
		Seq:   uint64(time.Now().UnixNano()),
		TTL:   0,
	}
	// Parallel sends: a slow peer must not block the collector
	// broadcast to the rest of the mesh (mirrors apply's flood pattern).
	var wg sync.WaitGroup
	for _, key := range me.node.SessionPeerKeys() {
		if key == me.node.LocalPublicKey() {
			continue
		}
		wg.Add(1)
		go func(k string, m MetaMessage) {
			defer wg.Done()
			me.sendTo(k, m)
		}(key, msg)
	}
	wg.Wait()
}

// metaDebugEnabled is cached once at init — os.Getenv is a syscall
// and the send/localMeta path is hot during meta floods.
var metaDebugEnabled = os.Getenv("MESHDESK_DEBUG") == "1"

// localMeta returns this node's own identity metadata.
func (me *MetaExchanger) localMeta() PeerMeta {
	vip := me.node.LocalVirtualIP()
	isCol := me.node.localIsCollectorFlag()
	if metaDebugEnabled {
		log.Printf("[meta] localMeta: collector=%v", isCol)
	}
	return PeerMeta{
		Key:       me.node.LocalPublicKey(),
		VIP:       vip,
		Hostname:  me.node.LocalHostname(),
		Zone:      me.node.LocalZone(),
		Endpoints: me.node.LocalEndpoints(),
		Collector: isCol,
	}
}

// knownPeers returns metadata for all peers we have sessions with.
func (me *MetaExchanger) knownPeers() []PeerMeta {
	out := []PeerMeta{}
	for _, key := range me.node.SessionPeerKeys() {
		if key == me.node.LocalPublicKey() {
			continue
		}
		relay, _ := me.node.PeerRelayMetaInfo(key)
		out = append(out, PeerMeta{
			Key:       key,
			VIP:       me.node.PeerVirtualIP(key),
			Zone:      me.node.PeerZone(key),
			Endpoints: me.node.PeerEndpoints(key),
			// Flood the collector capability onward: a relay hop must
			// re-advertise the dashboard node's Collector=true to its
			// own peers, or relay-attached nodes never learn where to
			// push metrics (they only see msg.Self of direct peers).
			Collector: me.node.IsPeerCollector(key),
			// Same flooding for relay/NAT knowledge (memberlist-
			// retirement phase 1): a relay hop re-advertises what it
			// learned, so two-hop-away nodes can do RTT-sorted relay
			// selection without gossip.
			Role:         relay.Role,
			NatType:      relay.NatType,
			CapRelay:     relay.CapRelay,
			MaxCircuits:  relay.MaxCircuits,
			LoadCircuits: relay.LoadCircuits,
		})
	}
	return out
}

// sendTo delivers a meta message to a specific peer over its session.
func (me *MetaExchanger) sendTo(peerKey string, msg MetaMessage) {
	if metaDebugEnabled {
		log.Printf("[meta] sendTo %s: self.Collector=%v peersWithCollector=%d",
			shortKey(peerKey), msg.Self.Collector, countCollectorPeers(msg))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := me.node.DialVirtualPort(ctx, peerKey, MetaVirtualPort)
	if err != nil {
		return // no session / not reachable — skip
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if err := json.NewEncoder(conn).Encode(&msg); err != nil {
		log.Printf("[meta] send to %s: %v", shortKey(peerKey), err)
	}
}

// --- helpers ---

func ioLimitReader(r net.Conn, n int64) *bufio.Reader {
	return bufio.NewReader(&limitedReader{r: r, n: n})
}

type limitedReader struct {
	r net.Conn
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

func u64str(v uint64) string {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return string(b)
}
