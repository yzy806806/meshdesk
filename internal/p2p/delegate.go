package p2p

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/memberlist"
	"github.com/vmihailenco/msgpack/v5"
)

// NodeMeta carries per-node metadata through the gossip protocol.
// This metadata is the foundation for relay selection, path building,
// and NAT traversal decisions.
//
// Wire format: MessagePack (compact binary). Serialized size is ~200-400
// bytes per node, well within memberlist's 512-byte indirect broadcast
// limit and ~64KB push/pull limit.
type NodeMeta struct {
	// --- Static identity ---

	// PublicKey is the Ed25519 public key (hex-encoded, 64 chars).
	PublicKey string `msgpack:"pk"`

	// Hostname is a human-readable name for the node.
	Hostname string `msgpack:"hn"`

	// Role describes the node's primary function:
	// "agent", "web", "relay", "exit", "entry".
	Role string `msgpack:"role"`

	// --- Capabilities ---

	// CapRelay indicates the node can forward relay circuits.
	CapRelay bool `msgpack:"cr"`

	// CapExit indicates the node can serve as a proxy exit.
	CapExit bool `msgpack:"ce"`

	// CapProxyEntry indicates the node can serve as a proxy entry point.
	CapProxyEntry bool `msgpack:"cpe"`

	// CapCollector indicates the node runs the web collector (monitor UI).
	// Set when the node is in web mode — enables monitor auto-routing.
	CapCollector bool `msgpack:"cc,omitempty"`

	// --- Connectivity ---

	// Endpoints are real IP:port pairs (not mesh IPs).
	// e.g., ["203.0.113.5:51820", "192.168.1.5:51820"]
	Endpoints []string `msgpack:"eps,omitempty"`

	// NatType describes the node's NAT situation:
	// "none", "full_cone", "restricted", "port_restricted", "symmetric", "unknown"
	NatType string `msgpack:"nt"`

	// --- Load metrics (refreshed every gossip interval) ---

	// LoadCPU is the fraction of CPU used (0.0–1.0).
	LoadCPU float64 `msgpack:"lcpu"`

	// LoadMem is the fraction of memory used (0.0–1.0).
	LoadMem float64 `msgpack:"lmem"`

	// LoadCircuits is the active relay circuit count (only if CapRelay).
	LoadCircuits int `msgpack:"lc,omitempty"`

	// LoadBW is the estimated available bandwidth in Mbps.
	LoadBW uint64 `msgpack:"lbw,omitempty"`

	// MaxCircuits is the maximum circuits this relay will accept.
	MaxCircuits int `msgpack:"mc,omitempty"`

	// --- Latency ---

	// RTTUs is the node's self-measured round-trip time to the gossip
	// mesh seed, in microseconds. Propagated via gossip so every peer
	// has a latency estimate for relay selection and path optimization.
	// Zero means no measurement available.
	RTTUs uint32 `msgpack:"rtt,omitempty"`

	// --- Version ---

	// Version is the semantic version for compatibility checks.
	Version string `msgpack:"ver"`

	// --- Sequence number ---

	// Seq is a monotonic sequence number for detecting stale metadata.
	Seq uint64 `msgpack:"seq"`

	// --- TUN / IPAM ---

	// VirtualIP is the TUN interface IP address assigned by the IPAM
	// deterministic allocator. Propagated via gossip so every node
	// knows every other node's mesh-subnet IP. Empty when TUN is disabled.
	VirtualIP string `msgpack:"vip,omitempty"`

	// SubnetProxies is the list of local CIDR subnets that this node
	// can route to (e.g. a LAN behind the node). Other nodes use this
	// to add kernel routes: traffic for these subnets goes via this
	// node's VirtualIP through the TUN interface. Empty when no
	// subnet proxies are configured.
	SubnetProxies []string `msgpack:"spx,omitempty"`

	// --- ACL (Access Control List) ---

	// ACLRules is the compact representation of this node's ACL rules,
	// propagated via gossip so every peer can enforce ingress policy
	// based on the sending node's declared rules. Each entry is a
	// compact string encoding: "action|src_cidr|dst_cidr|protocol|src_port|dst_port|peer_id|description".
	// Empty when ACL is disabled or no rules are configured.
	ACLRules []string `msgpack:"ar,omitempty"`

	// --- Traffic Statistics (refreshed every gossip interval) ---

	// TrafficInBytes is the total inbound bytes at the smux session level
	// (sum of all peer sessions' bytesReceived). Propagated via gossip
	// so every node can see the ingress volume of every other node.
	TrafficInBytes uint64 `msgpack:"tin,omitempty"`

	// TrafficOutBytes is the total outbound bytes at the smux session level
	// (sum of all peer sessions' bytesSent). Propagated via gossip
	// so every node can see the egress volume of every other node.
	TrafficOutBytes uint64 `msgpack:"tout,omitempty"`

	// SmuxStreams is the total number of active smux streams across all
	// peer sessions. Indicates how many concurrent mesh connections are active.
	SmuxStreams int `msgpack:"smux_s,omitempty"`

	// RelayForwards is the number of active relay tunnels being forwarded
	// by this node (only meaningful when CapRelay is true).
	RelayForwards int `msgpack:"rly,omitempty"`

	// TunRxPackets is the total number of packets received on the TUN device.
	TunRxPackets uint64 `msgpack:"trx,omitempty"`

	// TunTxPackets is the total number of packets sent through the TUN device.
	TunTxPackets uint64 `msgpack:"ttx,omitempty"`
}

// MarshalMeta serializes NodeMeta to MessagePack bytes.
func (m *NodeMeta) MarshalMeta() ([]byte, error) {
	return msgpack.Marshal(m)
}

// UnmarshalMeta deserializes NodeMeta from MessagePack bytes.
func UnmarshalMeta(data []byte) (*NodeMeta, error) {
	var m NodeMeta
	if err := msgpack.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal NodeMeta: %w", err)
	}
	return &m, nil
}

// relayMsgHandler is the callback for processing relay control messages.
// Set via SetRelayMessageHandler. When set, NotifyMsg checks if the
// incoming data is a relay message and dispatches it to this handler.
type relayMsgHandler func(msg *RelayMessage) error

// joinMsgHandler is the callback for processing join-protocol messages.
// Set via SetJoinMessageHandler. When set, NotifyMsg checks if the
// incoming data is a join message and dispatches it to this handler.
type joinMsgHandler func(msg *JoinMessage) error

// peerLinkMsgHandler is the callback for processing peer-link messages
// (global topology link-state). Set via SetPeerLinkMessageHandler.
type peerLinkMsgHandler func(msg *PeerLinkMessage) error

// memberlistDefaultMetaLimit is memberlist's default MetaMaxSize.
// NodeMeta must never exceed it; when the full meta does, we fall back
// to the pre-computed compact encoding (see marshalCompactMeta).
const memberlistDefaultMetaLimit = 512

// metaSnapshot is an immutable snapshot of the local node metadata,
// stored atomically.  It holds a deep copy of NodeMeta together with
// its pre-marshaled bytes so that memberlist Delegate callbacks
// (LocalState, NodeMeta) can return the bytes without holding any lock
// or performing serialization under pressure.
//
// This design eliminates the RWMutex reader-starvation cascade that
// caused DEFECT-A: under relay-tunnel load, frequent updateLocalMeta
// write-lock acquisitions starved RLock waiters in LocalState/NodeMeta,
// which in turn blocked memberlist's push/pull goroutines and cascaded
// into nodeLock contention (UpdateNode, Members, probe/reap).
type metaSnapshot struct {
	meta  *NodeMeta
	bytes []byte // pre-marshaled; safe to return directly (LocalState)
	// compact is a pre-marshaled encoding guaranteed to fit within
	// memberlist's NodeMeta limit (512 bytes). Used by NodeMeta(limit)
	// when the full bytes exceed the limit — truncating the msgpack
	// stream would corrupt it (byte misalignment defect).
	compact []byte
}

// meshDelegate implements memberlist.Delegate to carry NodeMeta through gossip.
type meshDelegate struct {
	// snapshot holds the current metadata snapshot atomically.
	// Readers (LocalState, NodeMeta, getLocalMeta) do a lock-free
	// atomic load and return a copy — no mutex acquisition, no
	// marshaling, O(1) hold time.
	snapshot atomic.Pointer[metaSnapshot]

	// mu serializes writers (updateLocalMeta, SetRelayMessageHandler,
	// SetJoinMessageHandler) so that the snapshot is never updated
	// concurrently.  Readers never contend on this lock.
	mu sync.Mutex

	// relayHandler is called when a relay control message is received
	// via NotifyMsg. If nil, relay messages are silently ignored.
	// Protected by handlerMu.
	relayHandler relayMsgHandler

	// joinHandler is called when a join-protocol message is received
	// via NotifyMsg. If nil, join messages are silently ignored.
	// Protected by handlerMu.
	joinHandler joinMsgHandler

	// peerLinkHandler is called when a peer-link (topology) message is
	// received via NotifyMsg. Protected by handlerMu.
	peerLinkHandler peerLinkMsgHandler

	// handlerMu protects relayHandler and joinHandler.
	handlerMu sync.RWMutex
}

// newMeshDelegate creates a new delegate with the given local metadata.
func newMeshDelegate(localMeta *NodeMeta) *meshDelegate {
	d := &meshDelegate{}
	d.storeSnapshot(localMeta)
	return d
}

// storeSnapshot creates a metaSnapshot from the given NodeMeta and
// atomically stores it.  The caller must hold d.mu or be in a
// single-threaded context (construction).
func (d *meshDelegate) storeSnapshot(meta *NodeMeta) {
	data, err := meta.MarshalMeta()
	if err != nil {
		// Marshal failure is unexpected for our compact encoding;
		// store empty bytes so LocalState still returns something.
		data = nil
	}
	// Pre-compute a compact variant that fits memberlist's NodeMeta
	// limit (default 512 bytes). NodeMeta(limit) must NEVER truncate
	// the msgpack stream mid-structure — that corrupts the document
	// and the receiver decodes misaligned fields (the "byte
	// misalignment" defect behind seed-join failures).
	var compact []byte
	if len(data) > memberlistDefaultMetaLimit {
		compact = marshalCompactMeta(meta, memberlistDefaultMetaLimit)
	}
	d.snapshot.Store(&metaSnapshot{meta: meta, bytes: data, compact: compact})
}

// marshalCompactMeta produces a valid (non-truncated) msgpack encoding
// of meta that fits within limit bytes. It drops progressively less
// critical fields until the document fits: traffic/load stats first,
// then ACL rules, subnet proxies, then endpoints (keeping the first
// two). Identity, VIP, capabilities and Seq are always kept.
func marshalCompactMeta(meta *NodeMeta, limit int) []byte {
	// Level 1: drop statistics and load metrics.
	c := *meta
	c.TrafficInBytes = 0
	c.TrafficOutBytes = 0
	c.SmuxStreams = 0
	c.RelayForwards = 0
	c.TunRxPackets = 0
	c.TunTxPackets = 0
	c.LoadCPU = 0
	c.LoadMem = 0
	c.LoadCircuits = 0
	c.LoadBW = 0
	c.MaxCircuits = 0
	c.RTTUs = 0
	if data, err := c.MarshalMeta(); err == nil && len(data) <= limit {
		return data
	}

	// Level 2: drop ACL rules.
	c.ACLRules = nil
	if data, err := c.MarshalMeta(); err == nil && len(data) <= limit {
		return data
	}

	// Level 3: drop subnet proxies.
	c.SubnetProxies = nil
	if data, err := c.MarshalMeta(); err == nil && len(data) <= limit {
		return data
	}

	// Level 4: keep at most 2 endpoints.
	if len(c.Endpoints) > 2 {
		c.Endpoints = c.Endpoints[:2]
	}
	if data, err := c.MarshalMeta(); err == nil && len(data) <= limit {
		return data
	}

	// Level 5: identity only — must fit (64-char key + hostname + VIP
	// + seq ≈ 120-160 bytes, always within 512).
	c.Endpoints = nil
	c.NatType = ""
	c.CapProxyEntry = false
	c.CapCollector = false
	if data, err := c.MarshalMeta(); err == nil && len(data) <= limit {
		return data
	}

	// Absolute last resort: strip hostname too.
	c.Hostname = ""
	if data, err := c.MarshalMeta(); err == nil && len(data) <= limit {
		return data
	}
	return nil
}

// SetRelayMessageHandler installs a callback for processing relay control
// messages received via gossip. The RelaySessionManager calls this during
// initialization to receive circuit setup/teardown/ping messages.
func (d *meshDelegate) SetRelayMessageHandler(h relayMsgHandler) {
	d.handlerMu.Lock()
	defer d.handlerMu.Unlock()
	d.relayHandler = h
}

// SetJoinMessageHandler installs a callback for processing join-protocol
// messages received via gossip. The JoinProtocol calls this during
// initialization to receive JoinRequest/JoinAccept/JoinReject/LeaveNotice.
func (d *meshDelegate) SetJoinMessageHandler(h joinMsgHandler) {
	d.handlerMu.Lock()
	defer d.handlerMu.Unlock()
	d.joinHandler = h
}

// SetPeerLinkMessageHandler installs the peer-link (topology) handler.
func (d *meshDelegate) SetPeerLinkMessageHandler(h peerLinkMsgHandler) {
	d.handlerMu.Lock()
	defer d.handlerMu.Unlock()
	d.peerLinkHandler = h
}

// NodeMeta is called by memberlist to get the local node's metadata.
// The returned bytes are distributed to all other nodes via gossip.
//
// Lock-free: returns the pre-marshaled bytes from the atomic snapshot.
// This is O(1) and never blocks, even under heavy updateLocalMeta
// contention — the key fix for DEFECT-A.
func (d *meshDelegate) NodeMeta(limit int) []byte {
	snap := d.snapshot.Load()
	if snap == nil {
		return nil
	}
	data := snap.bytes
	if len(data) <= limit {
		return data
	}
	// Full meta exceeds the limit. Return the pre-computed compact
	// encoding — a VALID msgpack document, never a truncation. (The
	// old `return data[:limit]` corrupted the stream and the receiver
	// decoded misaligned fields — the byte-misalignment defect.)
	if len(snap.compact) > 0 && len(snap.compact) <= limit {
		return snap.compact
	}
	// Defensive: compact should always fit; if it somehow doesn't,
	// return nil rather than corrupt bytes.
	return nil
}

// NotifyMsg is called when a user-level gossip message is received.
// We use this channel for relay circuit setup/teardown/ping messages
// (P2P_NETWORKING_SPEC.md §5.3) and join-protocol messages (§4).
// NodeMeta propagation is handled separately via the NodeMeta(limit) method.
//
// If the message is a relay control message and a relay handler is
// installed, it is dispatched to the handler. If it's a join-protocol
// message and a join handler is installed, it is dispatched there.
// Otherwise, it is ignored.
func (d *meshDelegate) NotifyMsg(data []byte) {
	if len(data) == 0 {
		return
	}

	// Check if this is a relay control message.
	if IsRelayMessage(data) {
		msg, err := UnmarshalRelayMessage(data)
		if err != nil {
			log.Printf("[p2p] failed to unmarshal relay message: %v", err)
			return
		}

		d.handlerMu.RLock()
		handler := d.relayHandler
		d.handlerMu.RUnlock()

		if handler != nil {
			if err := handler(msg); err != nil {
				log.Printf("[p2p] relay message handler error: %v", err)
			}
		}
		return
	}

	// Check if this is a peer-link (topology) message.
	if IsPeerLinkMessage(data) {
		msg, err := UnmarshalPeerLinkMessage(data)
		if err != nil {
			log.Printf("[p2p] failed to unmarshal peer-link message: %v", err)
			return
		}

		d.handlerMu.RLock()
		handler := d.peerLinkHandler
		d.handlerMu.RUnlock()

		if handler != nil {
			if err := handler(msg); err != nil {
				log.Printf("[p2p] peer-link message handler error: %v", err)
			}
		}
		return
	}

	// Check if this is a join-protocol message.
	if IsJoinMessage(data) {
		msg, err := UnmarshalJoinMessage(data)
		if err != nil {
			log.Printf("[p2p] failed to unmarshal join message: %v", err)
			return
		}

		d.handlerMu.RLock()
		handler := d.joinHandler
		d.handlerMu.RUnlock()

		if handler != nil {
			if err := handler(msg); err != nil {
				log.Printf("[p2p] join message handler error: %v", err)
			}
		}
		return
	}

	// Other user-level message types can be added here in the future.
}

// GetBroadcasts is called when user data messages can be broadcast.
// We return nil for now — relay circuit messages use targeted sends
// via memberlist.SendReliable, not broadcast. Metadata is propagated
// via NodeMeta, not user broadcasts.
func (d *meshDelegate) GetBroadcasts(overhead, limit int) [][]byte {
	return nil
}

// LocalState is called during state sync (push/pull). Returns local
// state for full state transfer on join/reconcile.
//
// Lock-free: returns the pre-marshaled bytes from the atomic snapshot.
// This is O(1) and never blocks — the key fix for DEFECT-A where
// RLock contention under relay load starved memberlist push/pull.
func (d *meshDelegate) LocalState(join bool) []byte {
	snap := d.snapshot.Load()
	if snap == nil {
		return nil
	}
	return snap.bytes
}

// MergeRemoteState is called to merge remote state received during push/pull.
// We merge by taking the metadata with the highest sequence number.
func (d *meshDelegate) MergeRemoteState(data []byte, join bool) {
	// Remote state is handled by the event delegate (NotifyJoin/NotifyUpdate)
	// which parses the per-node metadata. This method is for bulk state
	// transfer — we accept it but the actual caching happens in NotifyJoin.
	remoteMeta, err := UnmarshalMeta(data)
	if err != nil {
		return // malformed data, ignore
	}

	// If this is our own state echoed back, ignore it.
	// Lock-free atomic load — no contention with writers.
	snap := d.snapshot.Load()
	if snap != nil && snap.meta.PublicKey == remoteMeta.PublicKey {
		return
	}

	// Actual caching of remote node metadata happens in the event delegate.
}

// updateLocalMeta updates the local node's metadata (e.g., refreshed load metrics).
//
// This is the only writer path.  It holds d.mu (a plain Mutex, not RWMutex)
// only long enough to copy the current meta, apply the mutation, and store
// a new atomic snapshot.  The expensive marshaling happens inside
// storeSnapshot while holding the lock, but the lock is a writer-only
// Mutex — readers never contend on it.  This eliminates the reader/writer
// contention that caused DEFECT-A.
//
// The critical insight: readers (LocalState, NodeMeta, getLocalMeta) are
// completely lock-free via atomic.Pointer, so no amount of writer
// activity can starve them.
func (d *meshDelegate) updateLocalMeta(fn func(*NodeMeta)) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Copy current meta, apply mutation, store new snapshot.
	snap := d.snapshot.Load()
	var current *NodeMeta
	if snap != nil {
		// Shallow copy is sufficient — NodeMeta fields are value types
		// or slices that are replaced, not mutated in-place.
		copyMeta := *snap.meta
		current = &copyMeta
	} else {
		current = &NodeMeta{}
	}
	fn(current)
	d.storeSnapshot(current)
}

// getLocalMeta returns a copy of the local metadata.
//
// Lock-free: atomic load + shallow copy.  Never blocks.
func (d *meshDelegate) getLocalMeta() *NodeMeta {
	snap := d.snapshot.Load()
	if snap == nil {
		return &NodeMeta{}
	}
	copy := *snap.meta
	return &copy
}

// ParseNodeMeta extracts NodeMeta from a memberlist.Node's Meta field.
// Returns nil and an error if the metadata is empty or malformed.
func ParseNodeMeta(node *memberlist.Node) (*NodeMeta, error) {
	if len(node.Meta) == 0 {
		return nil, fmt.Errorf("node %s has no metadata", node.Name)
	}
	return UnmarshalMeta(node.Meta)
}
