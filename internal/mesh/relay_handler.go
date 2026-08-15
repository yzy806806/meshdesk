package mesh

import (
	"context"

	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// DefaultMaxRelayTunnels is the default maximum number of active relay tunnels.
// 256 gives headroom for per-request tunnels (SOCKS5, TUN, monitor) without
// exhausting on a busy relay. Zombie tunnels are reaped by the idle sweep
// (DefaultRelayIdleTimeout=30s) and half-open ones by evictStaleHalfOpen.
const DefaultMaxRelayTunnels = 256

// DefaultRelayIdleTimeout is the default idle timeout for relay tunnels.
// Tunnels with no traffic for this duration are reaped. Kept short (30s)
// because relay tunnels are typically short-lived (per-request): a SOCKS5
// or TUN request opens a tunnel, streams data, and closes. A tunnel that
// stays idle this long is a zombie (e.g. a half-finished handshake) and
// must not consume capacity.
const DefaultRelayIdleTimeout = 30 * time.Second

// DefaultRelayHeartbeatInterval is the legacy heartbeat interval for relay
// tunnels. The heartbeat mechanism has been removed (it polluted the data
// plane by writing msgpack bytes into raw data streams). This constant is
// retained for backward compatibility but is no longer used.
const DefaultRelayHeartbeatInterval = 30 * time.Second

// staleHalfOpenTimeout is how long a half-open tunnel (TargetConn still
// nil, waiting for target to dial back) is considered stale and eligible
// for eviction when the relay is at capacity.
const staleHalfOpenTimeout = 30 * time.Second

// relayTunnel tracks one active relay bridge between two smux streams.
type relayTunnel struct {
	ID           string
	InitiatorKey string
	TargetKey    string
	// initiatorConn is the stream from the initiator (N1) side.
	InitiatorConn net.Conn
	// targetConn is the stream from the target (txcloud) side.
	// May be nil until the target dials back or the relay opens a stream
	// to the target.
	TargetConn net.Conn

	// ready field removed (was dead code, caused double-close panic risk).

	CreatedAt    time.Time
	LastActivity atomic.Int64 // UnixNano

	// started ensures startBridge is only called once per tunnel,
	// preventing double io.Copy / heartbeat goroutines if both
	// handleRequest (same-stream response) and handleDialBack (new
	// stream) trigger for the same tunnel.
	started atomic.Bool

	closeOnce sync.Once
	done      chan struct{}
}

// RelayHandler processes inbound relay requests on virtual port 0x524C.
// It runs on relay-capable nodes and bridges streams between peers.
//
// Lifecycle:
//  1. RegisterRelayHandler creates a RelayHandler and registers it on
//     the virtual port mux for port 0x524C.
//  2. When a peer opens a stream on port 0x524C, the mux delivers it to
//     HandleStream.
//  3. HandleStream reads the relay handshake message and either:
//     a. Bridges the stream to the target peer (if this is a RelayRequest),
//     b. Matches it to a pending tunnel (if this is a dial-back response
//     from the target after receiving a RelayDial).
//  4. The relay starts two goroutines piping bytes between the two streams
//     via io.Copy. When either copy returns, both streams are closed.
//  5. Close() tears down all active tunnels.
type RelayHandler struct {
	node              *MeshNode
	localKey          string
	tunnels           map[string]*relayTunnel
	mu                sync.RWMutex
	maxTunnels        int
	idleTimeout       time.Duration
	heartbeatInterval time.Duration // deprecated: heartbeat removed, field retained for compat

	// OnRelayDial is called when a MeshRelayDial is received from a relay
	// node. The callback receives the dial message and the stream conn
	// (after the accept response has been sent). The callback takes
	// ownership of conn and is responsible for closing it.
	// If nil, the dial is accepted and the stream is echoed back via
	// io.Copy (useful for testing). In production, set this to forward
	// the stream to a local virtual port listener or application handler.
	OnRelayDial func(dial *MeshRelayDial, conn net.Conn)

	closed atomic.Bool
}

// NewRelayHandler creates a RelayHandler for the given node.
func NewRelayHandler(node *MeshNode, localKey string) *RelayHandler {
	h := &RelayHandler{
		node:              node,
		localKey:          localKey,
		tunnels:           make(map[string]*relayTunnel),
		maxTunnels:        DefaultMaxRelayTunnels,
		idleTimeout:       DefaultRelayIdleTimeout,
		heartbeatInterval: DefaultRelayHeartbeatInterval,
	}
	// Start idle tunnel cleanup goroutine.
	go h.cleanupIdleTunnels()
	return h
}

// HandleStream is called by the virtual port mux when a stream arrives
// on port 0x524C. It reads the relay handshake message and dispatches
// accordingly.
//
// This method satisfies the pattern used by VirtualListener.Accept():
// the caller (the virtual port mux) delivers a net.Conn that already has
// the 2-byte port frame consumed.
func (h *RelayHandler) HandleStream(conn net.Conn) {
	if h.closed.Load() {
		conn.Close()
		return
	}

	// Wrap conn in a bufferedConn so the msgpack Decoder's internal
	// bufio doesn't swallow coalesced bytes. The bufferedConn replays
	// any leftover buffered bytes on subsequent reads, preserving data
	// that was coalesced into the same TCP segment as the handshake
	// message (e.g. service banner, TUN frame, SOCKS5 greeting).
	bufConn := &bufferedConn{
		Reader: bufio.NewReader(conn),
		conn:   conn,
	}

	// Read the relay handshake message (msgpack-encoded).
	msg, err := readRelayMessage(bufConn)
	if err != nil {
		log.Printf("[mesh-relay] failed to read handshake: %v", err)
		conn.Close()
		return
	}

	switch m := msg.(type) {
	case *MeshRelayRequest:
		h.handleRequest(bufConn, m)
	case *MeshRelayResponse:
		// This is a dial-back response from the target — it accepted
		// our RelayDial and is now ready to be bridged.
		h.handleDialBack(bufConn, m)
	case *MeshRelayDial:
		h.handleDial(bufConn, m)
	case *MeshRelayTeardown:
		h.handleTeardown(bufConn, m)
	default:
		log.Printf("[mesh-relay] unexpected message type %T on relay port", msg)
		conn.Close()
	}
}

// handleRequest processes a MeshRelayRequest from an initiator. It:
//  1. Checks capacity.
//  2. Looks up the smux session to the target peer.
//  3. Opens a stream on the target's session (port 0x524C) and sends a
//     MeshRelayDial asking the target to dial back.
//  4. Waits for the target to respond (the target's response arrives as
//     a new stream on our relay port — handled by handleDialBack).
//  5. Once both sides are ready, starts the bidirectional io.Copy bridge.
func (h *RelayHandler) handleRequest(initiatorConn net.Conn, req *MeshRelayRequest) {
	tunnelID := req.TunnelID

	// Check capacity.
	h.mu.RLock()
	tunnelCount := len(h.tunnels)
	h.mu.RUnlock()
	if tunnelCount >= h.maxTunnels {
		// At capacity — evict stale half-open tunnels (TargetConn
		// still nil, been waiting longer than staleHalfOpenTimeout),
		// then the OLDEST tunnels regardless of state. Half-closed
		// streams (TCP FIN-WAIT-2) keep startBridge's io.Copy blocked
		// without EOF, so their tunnels never reap naturally and
		// LastActivity keeps getting refreshed by buffered writes —
		// zombie tunnels pile up and starve new requests.
		evicted := h.evictStaleHalfOpen()
		if evicted == 0 {
			evicted = h.evictOldest(4)
		}
		if evicted == 0 {
			h.sendResponse(initiatorConn, req.TunnelID, false, RelayRejectAtCapacity)
			initiatorConn.Close()
			return
		}
		log.Printf("[mesh-relay] evicted %d tunnel(s) to make room (half-open + oldest)", evicted)
	}

	// Check for duplicate tunnel.
	h.mu.Lock()
	if _, exists := h.tunnels[tunnelID]; exists {
		h.mu.Unlock()
		h.sendResponse(initiatorConn, tunnelID, false, RelayRejectDuplicateTunnel)
		initiatorConn.Close()
		return
	}

	// Create the tunnel entry.
	tunnel := &relayTunnel{
		ID:            tunnelID,
		InitiatorKey:  req.InitiatorKey, // propagated from the initiator's request
		TargetKey:     req.TargetKey,
		InitiatorConn: initiatorConn,
		CreatedAt:     time.Now(),
		done:          make(chan struct{}),
	}
	tunnel.LastActivity.Store(nowNano())
	h.tunnels[tunnelID] = tunnel
	h.mu.Unlock()

	log.Printf("[mesh-relay] relay request: tunnel=%s target=%s initiator=%s port=0x%x",
		tunnelID[:min(len(tunnelID), 16)], req.TargetKey[:min(len(req.TargetKey), 16)]+"...",
		req.InitiatorKey[:min(len(req.InitiatorKey), 16)]+"...", req.Port)

	// Try to open a stream to the target peer.
	targetSession := h.node.GetSession(req.TargetKey)
	if targetSession == nil {
		// Also check clientSessions.
		h.node.sessionsMu.Lock()
		targetSession = h.node.clientSessions[req.TargetKey]
		h.node.sessionsMu.Unlock()
	}
	if targetSession == nil {
		// Multi-hop relay: this node has no session to the target.
		// Recursively relay through another node (the path excludes
		// already-traversed relays, preventing loops).
		h.multiHopRelay(initiatorConn, req, tunnelID)
		return
	}

	// Open a stream on the target's session and send a RelayDial.
	targetStream, err := targetSession.OpenStream(h.node.ctx)
	if err != nil {
		log.Printf("[mesh-relay] failed to open stream to target: %v", err)
		h.sendResponse(initiatorConn, tunnelID, false, RelayRejectNoSessionToTarget)
		h.removeTunnel(tunnelID)
		initiatorConn.Close()
		return
	}

	// Write the virtual port frame for the relay port.
	if err := writePortFrame(targetStream, MeshRelayVirtualPort); err != nil {
		log.Printf("[mesh-relay] failed to write port frame to target: %v", err)
		targetStream.Close()
		h.sendResponse(initiatorConn, tunnelID, false, RelayRejectNoSessionToTarget)
		h.removeTunnel(tunnelID)
		initiatorConn.Close()
		return
	}

	// Send the RelayDial message to the target.
	dialMsg := &MeshRelayDial{
		Type:         MsgRelayDial,
		TunnelID:     tunnelID,
		InitiatorKey: req.InitiatorKey, // propagate initiator identity for target-side auth
		Port:         req.Port,
		Timestamp:    nowNano(),
	}
	if err := writeRelayMessage(targetStream, dialMsg); err != nil {
		log.Printf("[mesh-relay] failed to send dial to target: %v", err)
		targetStream.Close()
		h.sendResponse(initiatorConn, tunnelID, false, RelayRejectNoSessionToTarget)
		h.removeTunnel(tunnelID)
		initiatorConn.Close()
		return
	}

	// Wait for the target to respond. The target will open a NEW stream
	// back to us on port 0x524C with a MeshRelayResponse. That response
	// is handled by handleDialBack, which sets TargetConn and closes the
	//
	// However, in the simpler case, the target's response arrives on the
	// SAME stream we just opened (target writes back on the same stream).
	// Let's read the response from the target stream.
	//
	// Wrap targetStream in a bufferedConn so the msgpack Decoder's
	// internal bufio doesn't swallow coalesced bytes (e.g. if the
	// target writes accept response + first data bytes in one TCP
	// segment). The bufferedConn replays leftover bytes on subsequent
	// reads during the io.Copy bridge.
	bufTargetStream := &bufferedConn{
		Reader: bufio.NewReader(targetStream),
		conn:   targetStream,
	}
	resp, err := readRelayMessage(bufTargetStream)
	if err != nil {
		log.Printf("[mesh-relay] failed to read target response: %v", err)
		targetStream.Close()
		h.sendResponse(initiatorConn, tunnelID, false, RelayRejectTargetRejected)
		h.removeTunnel(tunnelID)
		initiatorConn.Close()
		return
	}

	respMsg, ok := resp.(*MeshRelayResponse)
	if !ok {
		log.Printf("[mesh-relay] unexpected message type %T from target", resp)
		targetStream.Close()
		h.sendResponse(initiatorConn, tunnelID, false, RelayRejectTargetRejected)
		h.removeTunnel(tunnelID)
		initiatorConn.Close()
		return
	}

	if respMsg.Type == MsgRelayReject {
		log.Printf("[mesh-relay] target rejected relay: %s", respMsg.RejectReason)
		targetStream.Close()
		h.sendResponse(initiatorConn, tunnelID, false, RelayRejectTargetRejected)
		h.removeTunnel(tunnelID)
		initiatorConn.Close()
		return
	}

	// Target accepted. Store the target stream and start bridging.
	// Use bufTargetStream so the io.Copy bridge reads through the
	// bufio.Reader, replaying any leftover bytes from the msgpack decode.
	h.mu.Lock()
	tunnel.TargetConn = bufTargetStream
	h.mu.Unlock()

	// Send accept to the initiator.
	h.sendResponse(initiatorConn, tunnelID, true, "")

	// Start the bidirectional bridge.
	h.startBridge(tunnel)
}

// handleDialBack processes a MeshRelayResponse that arrives as a new
// inbound stream on port 0x524C. This happens when the target, after
// receiving a RelayDial, opens a fresh stream back to the relay to
// participate in the tunnel.
//
// In the current implementation, the target responds on the same stream
// the relay opened (see handleRequest), so this path is a fallback for
// the dial-back case (Case C in the spec).
func (h *RelayHandler) handleDialBack(conn net.Conn, resp *MeshRelayResponse) {
	h.mu.Lock()
	tunnel, exists := h.tunnels[resp.TunnelID]
	h.mu.Unlock()

	if !exists {
		log.Printf("[mesh-relay] dial-back for unknown tunnel %s", resp.TunnelID[:min(len(resp.TunnelID), 16)])
		conn.Close()
		return
	}

	if resp.Type == MsgRelayReject {
		log.Printf("[mesh-relay] target dial-back rejected: %s", resp.RejectReason)
		conn.Close()
		h.removeTunnel(resp.TunnelID)
		return
	}

	// Target dialed back successfully. Store the target stream.
	h.mu.Lock()
	tunnel.TargetConn = conn
	h.mu.Unlock()

	log.Printf("[mesh-relay] dial-back accepted for tunnel %s, starting bridge",
		resp.TunnelID[:min(len(resp.TunnelID), 16)])

	// Start the bidirectional bridge now that both sides are connected.
	// Previously this was dead code — TargetConn was set but startBridge
	// was never called, leaving the tunnel hanging and leaking resources.
	h.startBridge(tunnel)
}

// multiHopRelay forwards a relay request to another relay node when
// this node has no session to the target — the core of multi-hop
// relay (A → R1 → R2 → B). The path (already-traversed relays) is
// propagated so loops are impossible; max_relay_hops bounds depth.
func (h *RelayHandler) multiHopRelay(initiatorConn net.Conn, req *MeshRelayRequest, tunnelID string) {
	// Append this relay to the path for the next hop.
	path := append([]string(nil), req.Path...)
	if h.node != nil {
		path = append(path, h.node.LocalPublicKey())
	}

	// Depth bound (default 2).
	maxHops := 2
	if len(path) > maxHops {
		log.Printf("[mesh-relay] multi-hop: max relay hops (%d) exceeded for target %s (tunnel=%s)",
			maxHops, req.TargetKey[:min(len(req.TargetKey), 16)]+"...", tunnelID[:min(len(tunnelID), 16)])
		h.sendResponse(initiatorConn, tunnelID, false, "max_relay_hops_exceeded")
		h.removeTunnel(tunnelID)
		initiatorConn.Close()
		return
	}

	// Recursively dial the target through another relay (path-aware).
	ctx, cancel := context.WithTimeout(h.node.ctx, 15*time.Second)
	defer cancel()
	nextHop, err := h.node.tryRelayFallback(ctx, req.TargetKey, req.Port, path)
	if err != nil {
		log.Printf("[mesh-relay] multi-hop relay to %s failed: %v (tunnel=%s)",
			req.TargetKey[:min(len(req.TargetKey), 16)]+"...", err, tunnelID[:min(len(tunnelID), 16)])
		h.sendResponse(initiatorConn, tunnelID, false, RelayRejectNoSessionToTarget)
		h.removeTunnel(tunnelID)
		initiatorConn.Close()
		return
	}

	// Bridge the initiator stream to the next-hop tunnel.
	h.mu.Lock()
	tunnel, exists := h.tunnels[tunnelID]
	if exists {
		tunnel.TargetConn = nextHop
	}
	h.mu.Unlock()
	if !exists {
		nextHop.Close()
		h.removeTunnel(tunnelID)
		initiatorConn.Close()
		return
	}

	log.Printf("[mesh-relay] multi-hop tunnel established via %d hop(s) to %s (tunnel=%s)",
		len(path), req.TargetKey[:min(len(req.TargetKey), 16)]+"...", tunnelID[:min(len(tunnelID), 16)])

	// Send the accept response to the initiator BEFORE bridging — the
	// initiator's DialViaRelay is blocked reading it; without this it
	// times out with EOF even though the tunnel is live.
	h.sendResponse(initiatorConn, tunnelID, true, "")
	h.startBridge(tunnel)
}

// handleDial processes a MeshRelayDial received from a relay node.
// The relay has opened a stream to us (the target) and asks us to
// participate in a relay tunnel. We send back a MeshRelayResponse
// (accept) on the same stream, then hand the stream to the OnRelayDial
// callback for data forwarding. If no callback is set, we echo data
// back via io.Copy (useful for testing).
func (h *RelayHandler) handleDial(conn net.Conn, dial *MeshRelayDial) {
	tunnelIDShort := dial.TunnelID
	if len(tunnelIDShort) > 16 {
		tunnelIDShort = tunnelIDShort[:16]
	}
	initiatorShort := dial.InitiatorKey
	if len(initiatorShort) > 16 {
		initiatorShort = initiatorShort[:16]
	}
	log.Printf("[mesh-relay] relay dial: tunnel=%s initiator=%s", tunnelIDShort, initiatorShort)

	// Send accept response on the same stream.
	h.sendResponse(conn, dial.TunnelID, true, "")

	if h.OnRelayDial != nil {
		// Hand off the stream to the callback — it takes ownership.
		go h.OnRelayDial(dial, conn)
		return
	}

	// No callback set — default behavior: echo data back via io.Copy.
	// This keeps the stream alive and is useful for testing. The stream
	// is closed when either side finishes.
	go func() {
		io.Copy(conn, conn)
		conn.Close()
	}()
}

// handleTeardown processes a MeshRelayTeardown message.
func (h *RelayHandler) handleTeardown(conn net.Conn, td *MeshRelayTeardown) {
	log.Printf("[mesh-relay] teardown for tunnel %s", td.TunnelID[:min(len(td.TunnelID), 16)])
	h.removeTunnel(td.TunnelID)
	conn.Close()
}

// startBridge starts two goroutines copying bytes between the initiator
// and target streams. When either copy returns (EOF or error), both
// streams are closed and the tunnel is removed.
//
// LastActivity is updated on each successful data transfer so that
// cleanupIdleTunnels does not reap tunnels with active traffic.
//
// The bridge is guarded by tunnel.started (atomic) to prevent double
// invocation from the handleRequest (same-stream response) and
// handleDialBack (new-stream response) paths.
//
// NOTE: A previous version sent MsgRelayHeartbeat via writeRelayMessage
// directly into the data streams. That polluted the data plane — peers
// treat the stream as a raw byte pipe and do not parse msgpack, so
// heartbeat bytes were delivered as garbage business data. The heartbeat
// has been removed. Tunnel liveness now relies on:
//  1. The relay idle sweep (cleanupIdleTunnels, DefaultRelayIdleTimeout = 5 min),
//     which reaps tunnels whose LastActivity is older than the threshold.
//  2. The activityWriter wrapper, which updates tunnel.LastActivity on
//     every successful data transfer, keeping active tunnels from being
//     reaped.
//
// Note: smux session-level keepalive (PingInterval) and StreamIdleTimeout
// are both disabled by default (DefaultConfig sets them to 0), so they do
// not contribute to tunnel liveness.
func (h *RelayHandler) startBridge(tunnel *relayTunnel) {
	// Guard against double invocation.
	if !tunnel.started.CompareAndSwap(false, true) {
		log.Printf("[mesh-relay] startBridge already called for tunnel %s, skipping", tunnel.ID[:16])
		return
	}

	initiator := tunnel.InitiatorConn
	target := tunnel.TargetConn

	if initiator == nil || target == nil {
		log.Printf("[mesh-relay] cannot bridge: nil stream (tunnel=%s)", tunnel.ID[:16])
		h.removeTunnel(tunnel.ID)
		return
	}

	go func() {
		defer h.removeTunnel(tunnel.ID)

		// Two goroutines: initiator → target, target → initiator.
		// Each uses an activity-tracking writer to update LastActivity.
		done := make(chan struct{}, 2)

		go func() {
			aw := &activityWriter{dst: target, tunnel: tunnel}
			_, err := io.Copy(aw, initiator)
			if err != nil {
				log.Printf("[mesh-relay] copy initiator→target: %v (tunnel=%s)", err, tunnel.ID[:16])
			}
			done <- struct{}{}
		}()

		go func() {
			aw := &activityWriter{dst: initiator, tunnel: tunnel}
			_, err := io.Copy(aw, target)
			if err != nil {
				log.Printf("[mesh-relay] copy target→initiator: %v (tunnel=%s)", err, tunnel.ID[:16])
			}
			done <- struct{}{}
		}()

		// Wait for either direction to finish.
		<-done

		// Close both streams.
		tunnel.closeOnce.Do(func() {
			close(tunnel.done)
			initiator.Close()
			target.Close()
		})

		// Drain the second goroutine.
		<-done
	}()
}

// activityWriter wraps an io.Writer and updates the tunnel's LastActivity
// timestamp on each successful Write, so cleanupIdleTunnels can
// distinguish idle tunnels from active ones.
type activityWriter struct {
	dst    io.Writer
	tunnel *relayTunnel
}

func (aw *activityWriter) Write(p []byte) (int, error) {
	n, err := aw.dst.Write(p)
	if n > 0 {
		aw.tunnel.LastActivity.Store(nowNano())
	}
	return n, err
}

// removeTunnel removes a tunnel from the active map and closes its streams.
func (h *RelayHandler) removeTunnel(tunnelID string) {
	h.mu.Lock()
	tunnel, exists := h.tunnels[tunnelID]
	if exists {
		delete(h.tunnels, tunnelID)
	}
	h.mu.Unlock()

	if tunnel != nil {
		tunnel.closeOnce.Do(func() {
			close(tunnel.done)
			if tunnel.InitiatorConn != nil {
				tunnel.InitiatorConn.Close()
			}
			if tunnel.TargetConn != nil {
				tunnel.TargetConn.Close()
			}
		})
	}
}

// sendResponse sends a MeshRelayResponse (accept or reject) on the given
// connection.
func (h *RelayHandler) sendResponse(conn net.Conn, tunnelID string, accept bool, reason string) {
	respType := MsgRelayAccept
	if !accept {
		respType = MsgRelayReject
	}
	resp := &MeshRelayResponse{
		Type:         respType,
		TunnelID:     tunnelID,
		RejectReason: reason,
		Timestamp:    nowNano(),
	}
	if err := writeRelayMessage(conn, resp); err != nil {
		log.Printf("[mesh-relay] failed to send response: %v", err)
	}
}

// Close tears down all active tunnels and stops the relay handler.
func (h *RelayHandler) Close() error {
	h.closed.Store(true)

	h.mu.Lock()
	tunnels := h.tunnels
	h.tunnels = make(map[string]*relayTunnel)
	h.mu.Unlock()

	for _, t := range tunnels {
		t.closeOnce.Do(func() {
			close(t.done)
			if t.InitiatorConn != nil {
				t.InitiatorConn.Close()
			}
			if t.TargetConn != nil {
				t.TargetConn.Close()
			}
		})
	}
	return nil
}

// TunnelCount returns the number of active relay tunnels.
func (h *RelayHandler) TunnelCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.tunnels)
}

// DumpTunnels writes a per-tunnel breakdown to w for diagnostics.
func (h *RelayHandler) DumpTunnels(w io.Writer) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for id, t := range h.tunnels {
		age := time.Since(t.CreatedAt).Round(time.Second)
		last := time.Unix(0, t.LastActivity.Load())
		idle := time.Since(last).Round(time.Second)
		status := "active"
		if t.TargetConn == nil {
			status = "half-open"
		}
		fmt.Fprintf(w, "  tunnel=%s init=%s target=%s status=%s age=%s idle=%s\n",
			id[:min(len(id), 16)], t.InitiatorKey[:min(len(t.InitiatorKey), 16)]+"...",
			t.TargetKey[:min(len(t.TargetKey), 16)]+"...", status, age, idle)
	}
}

// evictStaleHalfOpen removes tunnels that are half-open (TargetConn is
// still nil, meaning the target hasn't responded) and have been waiting
// longer than staleHalfOpenTimeout. Returns the number of tunnels evicted.
// This is called when the relay is at capacity to reclaim slots from
// abandoned retry attempts (DEFECT-B mitigation).
func (h *RelayHandler) evictStaleHalfOpen() int {
	cutoff := time.Now().Add(-staleHalfOpenTimeout)
	var evictedIDs []string

	h.mu.Lock()
	for id, t := range h.tunnels {
		if t.TargetConn == nil && t.CreatedAt.Before(cutoff) {
			evictedIDs = append(evictedIDs, id)
			delete(h.tunnels, id)
			t.closeOnce.Do(func() {
				close(t.done)
				if t.InitiatorConn != nil {
					t.InitiatorConn.Close()
				}
			})
		}
	}
	h.mu.Unlock()

	return len(evictedIDs)
}

// evictOldest removes the N oldest tunnels regardless of state —
// a safety valve for zombie tunnels whose half-closed streams keep
// startBridge's io.Copy blocked (no EOF) so they never reap and
// LastActivity keeps getting refreshed by buffered writes.
func (h *RelayHandler) evictOldest(n int) int {
	type aged struct {
		id   string
		time time.Time
	}
	var candidates []aged

	h.mu.Lock()
	for id, t := range h.tunnels {
		candidates = append(candidates, aged{id, t.CreatedAt})
	}
	// Sort by creation time, oldest first.
	for i := 1; i < len(candidates); i++ {
		for j := i; j > 0 && candidates[j].time.Before(candidates[j-1].time); j-- {
			candidates[j], candidates[j-1] = candidates[j-1], candidates[j]
		}
	}
	if len(candidates) > n {
		candidates = candidates[:n]
	}
	for _, c := range candidates {
		if t, ok := h.tunnels[c.id]; ok {
			delete(h.tunnels, c.id)
			t.closeOnce.Do(func() {
				close(t.done)
				if t.InitiatorConn != nil {
					t.InitiatorConn.Close()
				}
				if t.TargetConn != nil {
					t.TargetConn.Close()
				}
			})
		}
	}
	h.mu.Unlock()

	return len(candidates)
}

// --- Helpers for reading/writing relay messages on streams ---

// writeRelayMessage encodes a relay message as msgpack and writes it to conn.
func writeRelayMessage(conn net.Conn, msg any) error {
	data, err := marshalRelayMsg(msg)
	if err != nil {
		return fmt.Errorf("marshal relay message: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write relay message: %w", err)
	}
	return nil
}

// readRelayMessage reads one msgpack-encoded relay message from conn and
// decodes it into the appropriate relay message struct.
//
// Uses msgpack.NewDecoder which internally buffers reads and uses Skip()
// to consume exactly one complete msgpack value — this correctly handles
// TCP/smux framing where a single Read may return a partial message or
// multiple messages coalesced into one read.
func readRelayMessage(conn net.Conn) (any, error) {
	dec := msgpack.NewDecoder(conn)
	raw, err := dec.DecodeRaw()
	if err != nil {
		return nil, fmt.Errorf("read relay message: %w", err)
	}
	return unmarshalRelayMsg(raw)
}

// readRelayMessageWithContext reads a relay message with a timeout.
func readRelayMessageWithContext(conn net.Conn, timeout time.Duration) (any, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{})

	msg, err := readRelayMessage(conn)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// cleanupIdleTunnels periodically removes tunnels that have been idle
// (no activity) for longer than idleTimeout. Prevents unbounded growth
// from stuck io.Copy or abandoned tunnels.
func (h *RelayHandler) cleanupIdleTunnels() {
	ticker := time.NewTicker(h.idleTimeout / 2)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-h.idleTimeout)
		h.mu.Lock()
		for id, t := range h.tunnels {
			lastActivity := time.Unix(0, t.LastActivity.Load())
			if lastActivity.Before(cutoff) {
				if t.InitiatorConn != nil {
					t.InitiatorConn.Close()
				}
				if t.TargetConn != nil {
					t.TargetConn.Close()
				}
				delete(h.tunnels, id)
			}
		}
		h.mu.Unlock()
	}
}
