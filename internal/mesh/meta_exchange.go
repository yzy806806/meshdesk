package mesh

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
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
	// Learn the sender's zone (transport-selection signal) — cached
	// independently of memberlist health.
	if msg.Self.Key != "" && msg.Self.Zone != "" {
		me.node.SetLearnedZone(msg.Self.Key, msg.Self.Zone)
	}
	// Learn everything the sender knows about other peers.
	for _, pm := range msg.Peers {
		if pm.Key != "" && pm.VIP != "" {
			me.node.AddPeerVirtualIPRoute(pm.Key, pm.VIP)
		}
		if pm.Key != "" && pm.Zone != "" {
			me.node.SetLearnedZone(pm.Key, pm.Zone)
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

// localMeta returns this node's own identity metadata.
func (me *MetaExchanger) localMeta() PeerMeta {
	vip := me.node.LocalVirtualIP()
	return PeerMeta{
		Key:      me.node.LocalPublicKey(),
		VIP:      vip,
		Hostname: me.node.LocalHostname(),
		Zone:     me.node.LocalZone(),
	}
}

// knownPeers returns metadata for all peers we have sessions with.
func (me *MetaExchanger) knownPeers() []PeerMeta {
	out := []PeerMeta{}
	for _, key := range me.node.SessionPeerKeys() {
		if key == me.node.LocalPublicKey() {
			continue
		}
		out = append(out, PeerMeta{
			Key: key,
			VIP: me.node.PeerVirtualIP(key),
		})
	}
	return out
}

// sendTo delivers a meta message to a specific peer over its session.
func (me *MetaExchanger) sendTo(peerKey string, msg MetaMessage) {
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
