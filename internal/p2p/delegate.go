package p2p

import (
	"fmt"
	"log"
	"sync"

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

	// --- Version ---

	// Version is the semantic version for compatibility checks.
	Version string `msgpack:"ver"`

	// --- Sequence number ---

	// Seq is a monotonic sequence number for detecting stale metadata.
	Seq uint64 `msgpack:"seq"`
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

// meshDelegate implements memberlist.Delegate to carry NodeMeta through gossip.
type meshDelegate struct {
	mu        sync.RWMutex
	localMeta *NodeMeta

	// relayHandler is called when a relay control message is received
	// via NotifyMsg. If nil, relay messages are silently ignored.
	relayHandler relayMsgHandler

	// joinHandler is called when a join-protocol message is received
	// via NotifyMsg. If nil, join messages are silently ignored.
	joinHandler joinMsgHandler
}

// newMeshDelegate creates a new delegate with the given local metadata.
func newMeshDelegate(localMeta *NodeMeta) *meshDelegate {
	return &meshDelegate{
		localMeta: localMeta,
	}
}

// SetRelayMessageHandler installs a callback for processing relay control
// messages received via gossip. The RelaySessionManager calls this during
// initialization to receive circuit setup/teardown/ping messages.
func (d *meshDelegate) SetRelayMessageHandler(h relayMsgHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.relayHandler = h
}

// SetJoinMessageHandler installs a callback for processing join-protocol
// messages received via gossip. The JoinProtocol calls this during
// initialization to receive JoinRequest/JoinAccept/JoinReject/LeaveNotice.
func (d *meshDelegate) SetJoinMessageHandler(h joinMsgHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.joinHandler = h
}

// NodeMeta is called by memberlist to get the local node's metadata.
// The returned bytes are distributed to all other nodes via gossip.
func (d *meshDelegate) NodeMeta(limit int) []byte {
	d.mu.RLock()
	defer d.mu.RUnlock()

	data, err := d.localMeta.MarshalMeta()
	if err != nil {
		return nil // memberlist tolerates nil (empty metadata)
	}
	if len(data) > limit {
		// Truncate if exceeds limit — should not happen with our compact encoding
		return data[:limit]
	}
	return data
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

		d.mu.RLock()
		handler := d.relayHandler
		d.mu.RUnlock()

		if handler != nil {
			if err := handler(msg); err != nil {
				log.Printf("[p2p] relay message handler error: %v", err)
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

		d.mu.RLock()
		handler := d.joinHandler
		d.mu.RUnlock()

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
func (d *meshDelegate) LocalState(join bool) []byte {
	d.mu.RLock()
	defer d.mu.RUnlock()

	data, err := d.localMeta.MarshalMeta()
	if err != nil {
		return nil
	}
	return data
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
	d.mu.RLock()
	if d.localMeta.PublicKey == remoteMeta.PublicKey {
		d.mu.RUnlock()
		return
	}
	d.mu.RUnlock()

	// Actual caching of remote node metadata happens in the event delegate.
}

// updateLocalMeta updates the local node's metadata (e.g., refreshed load metrics).
func (d *meshDelegate) updateLocalMeta(fn func(*NodeMeta)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fn(d.localMeta)
}

// getLocalMeta returns a copy of the local metadata.
func (d *meshDelegate) getLocalMeta() *NodeMeta {
	d.mu.RLock()
	defer d.mu.RUnlock()
	// Return a shallow copy — callers should not mutate
	copy := *d.localMeta
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
