package mesh

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"sort"
	"sync"
	"time"
)

// RelayPeerInfo carries the metadata needed by the relay dialer to make
// intelligent path selection decisions. It is populated from the gossip
// layer's NodeMeta cache and provided to the MeshNode via a callback
// to avoid an import cycle between the mesh and p2p packages.
type RelayPeerInfo struct {
	// PeerKey is the hex-encoded public key of the peer.
	PeerKey string

	// RTT is the advertised round-trip time to this peer.
	// Zero means no measurement available.
	RTT time.Duration

	// CapRelay indicates the node can forward relay circuits.
	CapRelay bool

	// MaxCircuits is the maximum circuits this relay will accept.
	// Zero means unknown (treated as unlimited).
	MaxCircuits int

	// LoadCircuits is the active relay circuit count.
	LoadCircuits int

	// NatType describes the node's NAT situation.
	// "symmetric" NAT can't relay reliably.
	NatType string
}

// SetRelayMetaProvider registers a callback that returns metadata for all
// known relay-capable peers from the gossip layer. When set, tryRelayFallback
// uses this to filter and sort relay candidates by RTT and health. If nil,
// tryRelayFallback falls back to the legacy behavior of trying all peers
// with active sessions.
func (n *MeshNode) SetRelayMetaProvider(cb func() []RelayPeerInfo) {
	n.relayMetaProvider = cb
}

// relayBackoffWindow is how long a failed (target, relay) attempt is
// remembered before the dialer tries that path again. Prevents dial
// storms against unreachable targets: previously every connection
// attempt to a dead peer (socks5 exit, monitor probe) fired multiple
// relay requests per second, and the slow failed connections
// accumulated on shared nodes — saturating memberlist's 128-slot
// push/pull queue and rejecting legitimate seed joins with EOF.
const relayBackoffWindow = 30 * time.Second

// relayBackoff tracks per-(target, relay) cooldowns for relay dials.
type relayBackoff struct {
	mu      sync.Mutex
	nextTry map[string]time.Time
}

func newRelayBackoff() *relayBackoff {
	return &relayBackoff{nextTry: make(map[string]time.Time)}
}

func relayBackoffKey(targetKey, relayKey string) string {
	return targetKey[:min(len(targetKey), 16)] + "|" + relayKey[:min(len(relayKey), 16)]
}

// allowed reports whether a relay attempt to target via relay may
// proceed (false while a failure cooldown is active).
func (b *relayBackoff) allowed(targetKey, relayKey string) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	// Opportunistic cleanup so the map cannot grow unbounded on
	// long-lived nodes with many (target, relay) combinations.
	if len(b.nextTry) > 1024 {
		for k, t := range b.nextTry {
			if now.After(t) {
				delete(b.nextTry, k)
			}
		}
	}
	return now.After(b.nextTry[relayBackoffKey(targetKey, relayKey)])
}

// markFailed records a failed attempt, starting a cooldown window
// during which the (target, relay) path is skipped.
func (b *relayBackoff) markFailed(targetKey, relayKey string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextTry[relayBackoffKey(targetKey, relayKey)] = time.Now().Add(relayBackoffWindow)
}

// RelayDialer provides DialViaRelay — a method to open a data stream
// to a target peer through an intermediate relay node.
//
// It runs on the initiating node (e.g. N1) that wants to reach a target
// peer (e.g. txcloud) via a relay node (e.g. aliyun). The dialer opens
// a smux stream to the relay on virtual port 0x524C, sends a
// MeshRelayRequest naming the target, waits for a MeshRelayResponse,
// and on success returns the stream as a net.Conn that is transparently
// relayed to the target.
type RelayDialer struct {
	node     *MeshNode
	localKey string
}

// NewRelayDialer creates a RelayDialer for the given node.
func NewRelayDialer(node *MeshNode, localKey string) *RelayDialer {
	return &RelayDialer{
		node:     node,
		localKey: localKey,
	}
}

// DialViaRelay opens a relayed data stream to targetKey through relayKey.
// It returns a net.Conn that is transparently relayed — the caller can
// read/write as if connected directly to the target.
//
// port is the virtual port to reach on the target (propagated through the
// relay chain so the target's OnRelayDial callback can dial the correct
// local service). Pass 0 for legacy/undefined behavior.
//
// Steps:
//  1. Look up smux session to relayKey
//  2. Open stream on port 0x524C
//  3. Send MeshRelayRequest{target=targetKey, port=port}
//  4. Wait for MeshRelayResponse (accept/reject)
//  5. On accept, return the stream as a net.Conn
//  6. On reject or timeout, return error
func (d *RelayDialer) DialViaRelay(
	ctx context.Context,
	relayKey string,
	targetKey string,
	port uint16,
) (net.Conn, error) {
	// Look up the smux session to the relay node.
	d.node.sessionsMu.Lock()
	sess, ok := d.node.clientSessions[relayKey]
	if !ok {
		sess, ok = d.node.sessions[relayKey]
	}
	d.node.sessionsMu.Unlock()

	if !ok {
		return nil, fmt.Errorf("mesh relay: no session to relay %s",
			relayKey[:min(len(relayKey), 16)]+"...")
	}

	// Open a smux stream on the relay's session.
	stream, err := sess.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("mesh relay: open stream to relay: %w", err)
	}

	// Write the virtual port frame for the relay port.
	if err := writePortFrame(stream, MeshRelayVirtualPort); err != nil {
		stream.Close()
		return nil, fmt.Errorf("mesh relay: write port frame: %w", err)
	}

	// Send the MeshRelayRequest.
	tunnelID := newTunnelID()
	req := &MeshRelayRequest{
		Type:         MsgRelayRequest,
		TunnelID:     tunnelID,
		TargetKey:    targetKey,
		InitiatorKey: d.localKey, // propagate initiator identity for target-side auth
		Port:         port,
		Timestamp:    nowNano(),
	}
	if err := writeRelayMessage(stream, req); err != nil {
		stream.Close()
		return nil, fmt.Errorf("mesh relay: send request: %w", err)
	}

	log.Printf("[mesh-relay] dialer: requesting relay tunnel=%s relay=%s target=%s",
		tunnelID[:16],
		relayKey[:min(len(relayKey), 16)]+"...",
		targetKey[:min(len(targetKey), 16)]+"...")

	// Wrap the stream in a bufferedConn so the msgpack Decoder's
	// internal bufio doesn't swallow coalesced bytes. After decoding
	// the response, any leftover buffered bytes are replayed on
	// subsequent reads via the bufferedConn.
	bufConn := &bufferedConn{
		Reader: bufio.NewReader(stream),
		conn:   stream,
	}

	// Wait for the relay's response with a timeout.
	resp, err := readRelayMessageWithContext(bufConn, relayResponseTimeout)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("mesh relay: read response: %w", err)
	}

	respMsg, ok := resp.(*MeshRelayResponse)
	if !ok {
		stream.Close()
		return nil, fmt.Errorf("mesh relay: unexpected response type %T", resp)
	}

	if respMsg.Type == MsgRelayReject {
		stream.Close()
		return nil, fmt.Errorf("mesh relay: relay rejected: %s", respMsg.RejectReason)
	}

	// Tunnel accepted. The stream is now a transparent data pipe to the target.
	// Return bufConn (not raw stream) so any bytes the msgpack Decoder's
	// bufio consumed beyond the response are replayed to the caller.
	log.Printf("[mesh-relay] dialer: tunnel=%s accepted", tunnelID[:16])
	return bufConn, nil
}

// relayResponseTimeout is the maximum time to wait for a relay response.
const relayResponseTimeout = 10 * time.Second

// RegisterRelayHandler registers a RelayHandler on virtual port 0x524C,
// enabling this node to act as a smux stream relay intermediary.
//
// The returned RelayHandler should be Closed when the node no longer
// wants to relay (e.g. during shutdown). The handler is also closed
// automatically when the node's Close() is called if it was registered
// via this method.
func (n *MeshNode) RegisterRelayHandler() (*RelayHandler, error) {
	localKey := ""
	if n.identity != nil {
		localKey = n.identity.PublicKey
	}

	handler := NewRelayHandler(n, localKey)

	// Register a virtual port listener for 0x524C.
	ln, err := n.ListenVirtualPort(int(MeshRelayVirtualPort))
	if err != nil {
		return nil, fmt.Errorf("mesh relay: register port 0x%x: %w", MeshRelayVirtualPort, err)
	}

	// Start the accept loop in a background goroutine.
	go n.serveRelay(handler, ln)

	// Store the handler so Close() can clean it up.
	n.mu.Lock()
	n.relayHandler = handler
	n.mu.Unlock()

	return handler, nil
}

// serveRelay runs the accept loop for the relay virtual port listener.
// It delivers each accepted stream to the RelayHandler for processing.
func (n *MeshNode) serveRelay(handler *RelayHandler, ln net.Listener) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed — exit.
			return
		}
		go handler.HandleStream(conn)
	}
}

// RelayStream bridges two connections bidirectionally using io.Copy.
// Data written by conn1 appears on conn2 and vice versa. When either
// direction completes (EOF or error), both connections are closed.
//
// This is the core relay primitive: it copies raw bytes between two
// streams without understanding the payload. The bytes are already
// encrypted by the SecureConn layer, so the relay cannot read or
// modify the data.
//
// The function blocks until both directions have completed. Call it
// in a goroutine if you need non-blocking behavior.
func RelayStream(conn1, conn2 net.Conn) {
	if conn1 == nil || conn2 == nil {
		return
	}

	done := make(chan struct{}, 2)

	// conn1 → conn2
	go func() {
		io.Copy(conn2, conn1)
		// Half-close conn2's write side if supported.
		if cw, ok := conn2.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	// conn2 → conn1
	go func() {
		io.Copy(conn1, conn2)
		// Half-close conn1's write side if supported.
		if cw, ok := conn1.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	// Wait for either direction to finish, then close both.
	<-done
	conn1.Close()
	conn2.Close()

	// Drain the second goroutine.
	<-done
}

// DialViaRelay is a convenience method on MeshNode that creates a
// RelayDialer and calls DialViaRelay. It tries each known relay-capable
// peer in order until one accepts.
//
// port is the virtual port to reach on the target, propagated through the
// relay chain. relayCandidates is a list of peer identity hex strings that
// are known to have relay capability. The caller is responsible for
// providing candidates in preference order (e.g. by RTT). If
// relayCandidates is empty, the method returns an error.
func (n *MeshNode) DialViaRelay(
	ctx context.Context,
	targetKey string,
	relayCandidates []string,
	port uint16,
) (net.Conn, error) {
	if len(relayCandidates) == 0 {
		return nil, fmt.Errorf("mesh relay: no relay candidates available")
	}

	localKey := ""
	if n.identity != nil {
		localKey = n.identity.PublicKey
	}

	dialer := NewRelayDialer(n, localKey)

	var lastErr error
	skipped := 0
	for _, relayKey := range relayCandidates {
		// Skip self.
		if relayKey == localKey {
			continue
		}

		// Cooldown check: skip paths that failed recently (A1 —
		// prevents relay dial storms against unreachable targets).
		if !n.relayBackoff.allowed(targetKey, relayKey) {
			skipped++
			continue
		}

		conn, err := dialer.DialViaRelay(ctx, relayKey, targetKey, port)
		if err != nil {
			lastErr = err
			n.relayBackoff.markFailed(targetKey, relayKey)
			log.Printf("[mesh-relay] relay %s failed: %v (backoff %s)",
				relayKey[:min(len(relayKey), 16)]+"...", err, relayBackoffWindow)
			continue
		}
		return conn, nil
	}

	if skipped > 0 && lastErr == nil {
		return nil, fmt.Errorf("mesh relay: all %d candidate(s) in cooldown for target %s",
			skipped, targetKey[:min(len(targetKey), 16)]+"...")
	}
	if lastErr != nil {
		return nil, fmt.Errorf("mesh relay: all candidates failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("mesh relay: no suitable relay candidate found")
}

// tryRelayFallback is called by DialVirtualPort when no direct session
// exists to the target peer. It collects relay candidates and tries
// DialViaRelay through each one.
//
// When a relayMetaProvider is set (wired from the gossip layer via
// SetRelayMetaProvider), candidates are:
//   - Filtered by CapRelay capability from gossip NodeMeta
//   - Filtered by health (at-capacity and symmetric-NAT relays excluded)
//   - Sorted by advertised RTT (lowest first) for optimal path selection
//
// When no relayMetaProvider is set, it falls back to the legacy behavior
// of trying all peers with active (non-closed) sessions.
//
// Filtering:
//   - The target peer is excluded (relaying to itself is nonsensical).
//   - Closed sessions are skipped (a dead session cannot relay).
//   - The local node's own key is excluded.
//   - Relay peers at capacity (LoadCircuits >= MaxCircuits) are skipped.
//   - Relay peers behind symmetric NAT are skipped.
func (n *MeshNode) tryRelayFallback(ctx context.Context, targetKey string, port uint16) (net.Conn, error) {
	localKey := ""
	if n.identity != nil {
		localKey = n.identity.PublicKey
	}

	var candidates []string

	// If we have a relay metadata provider (from the gossip layer),
	// use it for intelligent candidate selection.
	if n.relayMetaProvider != nil {
		relayPeers := n.relayMetaProvider()

		// Build a set of peers with active sessions for the final
		// connectivity check.
		n.sessionsMu.Lock()
		sessionOK := func(key string) bool {
			if sess, ok := n.sessions[key]; ok && !sess.IsClosed() {
				return true
			}
			if sess, ok := n.clientSessions[key]; ok && !sess.IsClosed() {
				return true
			}
			return false
		}
		n.sessionsMu.Unlock()

		// Filter and collect eligible relay candidates.
		type candidate struct {
			key string
			rtt time.Duration
		}
		var eligible []candidate
		for _, rp := range relayPeers {
			// Skip self.
			if rp.PeerKey == localKey {
				continue
			}
			// Skip the target peer.
			if rp.PeerKey == targetKey {
				continue
			}
			// Must have relay capability.
			if !rp.CapRelay {
				log.Printf("[mesh] relay candidate %s: no CapRelay", rp.PeerKey[:min(len(rp.PeerKey), 8)])
				continue
			}
			// Skip relays at capacity.
			if rp.MaxCircuits > 0 && rp.LoadCircuits >= rp.MaxCircuits {
				log.Printf("[mesh] relay candidate %s: at capacity %d/%d", rp.PeerKey[:min(len(rp.PeerKey), 8)], rp.LoadCircuits, rp.MaxCircuits)
				continue
			}
			// NOTE: symmetric-NAT relays are NOT filtered out. Relay
			// circuits here are smux-stream bridges over already-established
			// TCP sessions — the relay node dials out to the shared node,
			// so its own NAT type is irrelevant (no inbound hole-punching
			// needed). This matters for shared nodes behind CGNAT (e.g. N1:
			// IPv6 public + IPv4 CGNAT, STUN reports symmetric) which relay
			// perfectly well.
			// Must have an active session to the relay.
			if !sessionOK(rp.PeerKey) {
				log.Printf("[mesh] relay candidate %s: no active session", rp.PeerKey[:min(len(rp.PeerKey), 8)])
				continue
			}
			eligible = append(eligible, candidate{key: rp.PeerKey, rtt: rp.RTT})
		}

		// Sort by RTT ascending (lowest first). Peers with RTT=0
		// (unknown) go last but are still eligible.
		sort.Slice(eligible, func(i, j int) bool {
			ri, rj := eligible[i].rtt, eligible[j].rtt
			if ri == 0 {
				ri = time.Duration(math.MaxInt64)
			}
			if rj == 0 {
				rj = time.Duration(math.MaxInt64)
			}
			return ri < rj
		})

		candidates = make([]string, len(eligible))
		for i, c := range eligible {
			candidates[i] = c.key
		}

		if len(candidates) == 0 {
			// Degraded-gossip fallback: the relay metadata provider
			// returned nothing usable (memberlist down → no CapRelay
			// knowledge). Every node registers the relay handler, so
			// ANY peer with an active session can relay. Fall back to
			// session-based candidates.
			log.Printf("[mesh] tryRelayFallback: gossip relay metadata empty — falling back to session-based candidates for target %s...", targetKey[:min(len(targetKey), 8)])
			n.sessionsMu.Lock()
			for key := range n.sessions {
				if key != targetKey && key != localKey {
					candidates = append(candidates, key)
				}
			}
			for key := range n.clientSessions {
				if key != targetKey && key != localKey {
					candidates = append(candidates, key)
				}
			}
			n.sessionsMu.Unlock()
		}
		if len(candidates) == 0 {
			return nil, fmt.Errorf("no relay candidates (no eligible relay-capable peers)")
		}

		log.Printf("[mesh] tryRelayFallback: %d relay-capable candidate(s) for target %s (RTT-sorted)",
			len(candidates), targetKey[:min(len(targetKey), 16)]+"...")

		return n.DialViaRelay(ctx, targetKey, candidates, port)
	}

	// Legacy fallback: collect all peers we have sessions with.
	n.sessionsMu.Lock()
	candidates = make([]string, 0, len(n.sessions)+len(n.clientSessions))
	seen := make(map[string]bool)
	for k, sess := range n.sessions {
		if k == targetKey || k == localKey || seen[k] || sess.IsClosed() {
			continue
		}
		candidates = append(candidates, k)
		seen[k] = true
	}
	for k, sess := range n.clientSessions {
		if k == targetKey || k == localKey || seen[k] || sess.IsClosed() {
			continue
		}
		candidates = append(candidates, k)
		seen[k] = true
	}
	n.sessionsMu.Unlock()

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no relay candidates (no active sessions)")
	}

	log.Printf("[mesh] tryRelayFallback: %d candidate(s) for target %s",
		len(candidates), targetKey[:min(len(targetKey), 16)]+"...")

	return n.DialViaRelay(ctx, targetKey, candidates, port)
}
