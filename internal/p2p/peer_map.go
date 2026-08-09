package p2p

import (
	"container/heap"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// ──────────────────────────────────────────────────────────────────────────
// Peer Link Map (EasyTier-style global topology, decentralized)
// ──────────────────────────────────────────────────────────────────────────
//
// Every node periodically broadcasts PeerLinkMessages describing its
// DIRECT connections to other peers (peer key, RTT). Each node collects
// these into a local global topology map and runs Dijkstra to compute
// optimal next-hop routes (direct < 1-hop relay < multi-hop relay).
//
// This complements memberlist: memberlist handles membership/liveness,
// while PeerLinkMap carries the link-state data memberlist doesn't
// (which peers have sessions to which, and at what RTT).
//
// VirtualIPs ride along in the link messages so a restarted node
// restores TUN routes quickly (before gossip meta propagates).

// PeerLinkMessage is broadcast over gossip. It describes one DIRECT
// link from the sender to a peer.
type PeerLinkMessage struct {
	// Type discriminator (matches p2p message dispatch).
	Type string `msgpack:"t"`

	// From is the sender's public key.
	From string `msgpack:"f"`

	// To is the direct peer's public key.
	To string `msgpack:"to"`

	// RTTUs is the measured RTT in microseconds (0 if unknown).
	RTTUs int64 `msgpack:"r"`

	// ToVirtualIP is the direct peer's TUN VirtualIP (for route
	// restoration).
	ToVirtualIP string `msgpack:"v,omitempty"`

	// Seq increments per update for freshness.
	Seq uint64 `msgpack:"s"`

	// Timestamp for staleness handling.
	Ts int64 `msgpack:"ts"`
}

// IsPeerLinkMessage reports whether data is a PeerLinkMessage.
func IsPeerLinkMessage(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// msgpack map of our message: first key is "t" with value "plm".
	// Relaxed check: the bytes "plm" appear as the Type value.
	for i := 0; i+2 < len(data) && i < 32; i++ {
		if data[i] == 'p' && data[i+1] == 'l' && data[i+2] == 'm' {
			return true
		}
	}
	return false
}

// MarshalPeerLinkMessage encodes a PeerLinkMessage for gossip broadcast.
func MarshalPeerLinkMessage(m *PeerLinkMessage) ([]byte, error) {
	m.Type = "plm"
	return msgpack.Marshal(m)
}

// UnmarshalPeerLinkMessage decodes a PeerLinkMessage.
func UnmarshalPeerLinkMessage(data []byte) (*PeerLinkMessage, error) {
	var m PeerLinkMessage
	if err := msgpack.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// LinkInfo is the internal representation of a known direct link.
type LinkInfo struct {
	From      string
	To        string
	RTTUs     int64
	VirtualIP string
	LastSeen  time.Time
}

// PeerLinkMap holds the global topology: link[from][to] = LinkInfo.
type PeerLinkMap struct {
	mu      sync.RWMutex
	links   map[string]map[string]*LinkInfo // from → to → link
	selfKey string
	ttl     time.Duration
}

// NewPeerLinkMap creates an empty link map.
func NewPeerLinkMap(selfKey string) *PeerLinkMap {
	return &PeerLinkMap{
		links:   make(map[string]map[string]*LinkInfo),
		selfKey: selfKey,
		ttl:     90 * time.Second,
	}
}

// AddLink records a direct link from → to (observed locally or via gossip).
func (m *PeerLinkMap) AddLink(from, to, virtualIP string, rttUs int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inner, ok := m.links[from]
	if !ok {
		inner = make(map[string]*LinkInfo)
		m.links[from] = inner
	}
	inner[to] = &LinkInfo{
		From:      from,
		To:        to,
		RTTUs:     rttUs,
		VirtualIP: virtualIP,
		LastSeen:  time.Now(),
	}
}

// OnLinkMessage ingests a received PeerLinkMessage.
func (m *PeerLinkMap) OnLinkMessage(msg *PeerLinkMessage) {
	if msg.From == "" || msg.To == "" || msg.From == msg.To {
		return
	}
	m.AddLink(msg.From, msg.To, msg.ToVirtualIP, msg.RTTUs)
}

// Prune removes stale links (peer died or link dropped).
func (m *PeerLinkMap) Prune() {
	cutoff := time.Now().Add(-m.ttl)
	m.mu.Lock()
	defer m.mu.Unlock()
	for from, inner := range m.links {
		for to, li := range inner {
			if li.LastSeen.Before(cutoff) {
				delete(inner, to)
			}
		}
		if len(inner) == 0 {
			delete(m.links, from)
		}
	}
}

// VirtualIPs returns peer → VirtualIP from all known links.
func (m *PeerLinkMap) VirtualIPs() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string)
	for _, inner := range m.links {
		for _, li := range inner {
			if li.VirtualIP != "" {
				out[li.To] = li.VirtualIP
			}
		}
	}
	return out
}

// ──────────────────────────────────────────────────────────────────────────
// Dijkstra path computation
// ──────────────────────────────────────────────────────────────────────────

// dijkstraNode is a heap entry for Dijkstra.
type dijkstraNode struct {
	key  string
	cost int64
	// heap index (managed by container/heap)
	index int
}

type dijkstraHeap []*dijkstraNode

func (h dijkstraHeap) Len() int           { return len(h) }
func (h dijkstraHeap) Less(i, j int) bool { return h[i].cost < h[j].cost }
func (h dijkstraHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *dijkstraHeap) Push(x any) {
	n := x.(*dijkstraNode)
	n.index = len(*h)
	*h = append(*h, n)
}
func (h *dijkstraHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*h = old[:n-1]
	return item
}

// nextHopMap returns nextHop[target] = nextHopPeer for all reachable
// targets from selfKey, computed with Dijkstra over the link map.
// Direct links have cost RTT (or 1 if unknown); relayed paths cost
// RTT + relayPenalty per hop so direct links win.
func (m *PeerLinkMap) nextHopMap(relayPenalty int64) map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	const inf int64 = 1 << 60
	dist := make(map[string]int64)
	nextHop := make(map[string]string)
	visited := make(map[string]bool)

	h := &dijkstraHeap{}
	heap.Init(h)
	dist[m.selfKey] = 0
	heap.Push(h, &dijkstraNode{key: m.selfKey, cost: 0})

	for h.Len() > 0 {
		u := heap.Pop(h).(*dijkstraNode)
		if visited[u.key] {
			continue
		}
		visited[u.key] = true

		for v, li := range m.links[u.key] {
			if visited[v] {
				continue
			}
			cost := li.RTTUs
			if cost <= 0 {
				cost = 1
			}
			// Relaying through u (u != self) adds penalty.
			if u.key != m.selfKey {
				cost += relayPenalty
			}
			nd := dist[u.key] + cost
			if d, ok := dist[v]; !ok || nd < d {
				dist[v] = nd
				if u.key == m.selfKey {
					nextHop[v] = v
				} else {
					nextHop[v] = nextHop[u.key]
				}
				heap.Push(h, &dijkstraNode{key: v, cost: nd})
			}
		}
	}
	return nextHop
}

// NextHop returns the next-hop peer key for target ("" if unreachable).
func (m *PeerLinkMap) NextHop(target string) string {
	mh := m.nextHopMap(100_000) // 100ms relay penalty per hop
	return mh[target]
}

// RouteTable returns the full next-hop table (target → nextHop).
func (m *PeerLinkMap) RouteTable() map[string]string {
	return m.nextHopMap(100_000)
}

// Dump writes the link map for diagnostics.
func (m *PeerLinkMap) Dump() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.links))
	for k := range m.links {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for _, from := range keys {
		for to, li := range m.links[from] {
			out += "  " + from[:min(len(from), 8)] + " → " + to[:min(len(to), 8)] +
				" rtt=" + fmt.Sprintf("%v", time.Duration(li.RTTUs)*time.Microsecond) +
				" vip=" + li.VirtualIP + "\n"
		}
	}
	if out == "" {
		out = "  (no links)\n"
	}
	return out
}

// PeriodicBroadcaster sends link messages for this node's direct peers
// at the given interval. Returns a stop function.
func (m *PeerLinkMap) PeriodicBroadcaster(interval time.Duration, directLinks func() map[string]int64, broadcast func(*PeerLinkMessage)) func() {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var seq uint64
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				links := directLinks()
				for peer, rttUs := range links {
					seq++
					m.AddLink(m.selfKey, peer, "", rttUs)
					broadcast(&PeerLinkMessage{
						From:  m.selfKey,
						To:    peer,
						RTTUs: rttUs,
						Seq:   seq,
						Ts:    time.Now().Unix(),
					})
				}
			}
		}
	}()
	return func() { close(stop) }
}

// log is used by the package; keep the import honest.
var _ = log.Printf
