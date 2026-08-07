package mesh

import (
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
const DefaultMaxRelayTunnels = 64

// DefaultRelayIdleTimeout is the default idle timeout for relay tunnels.
const DefaultRelayIdleTimeout = 5 * time.Minute

// DefaultRelayHeartbeatInterval is the default heartbeat interval for relay tunnels.
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
	heartbeatInterval time.Duration

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

	// Read the relay handshake message (msgpack-encoded).
	msg, err := readRelayMessage(conn)
	if err != nil {
		log.Printf("[mesh-relay] failed to read handshake: %v", err)
		conn.Close()
		return
	}

	switch m := msg.(type) {
	case *MeshRelayRequest:
		h.handleRequest(conn, m)
	case *MeshRelayResponse:
		// This is a dial-back response from the target — it accepted
		// our RelayDial and is now ready to be bridged.
		h.handleDialBack(conn, m)
	case *MeshRelayDial:
		h.handleDial(conn, m)
	case *MeshRelayTeardown:
		h.handleTeardown(conn, m)
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
		// At capacity — try to evict stale half-open tunnels (TargetConn
		// still nil, been waiting longer than staleHalfOpenTimeout).
		// This mitigates DEFECT-B: retry storms where each attempt
		// generates a new tunnelID, causing half-open tunnels to pile up.
		evicted := h.evictStaleHalfOpen()
		if evicted == 0 {
			h.sendResponse(initiatorConn, req.TunnelID, false, RelayRejectAtCapacity)
			initiatorConn.Close()
			return
		}
		log.Printf("[mesh-relay] evicted %d stale half-open tunnels to make room", evicted)
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
		InitiatorKey:  "", // unknown from request; could be inferred from peer
		TargetKey:     req.TargetKey,
		InitiatorConn: initiatorConn,
		CreatedAt:     time.Now(),
		done:          make(chan struct{}),
	}
	tunnel.LastActivity.Store(nowNano())
	h.tunnels[tunnelID] = tunnel
	h.mu.Unlock()

	log.Printf("[mesh-relay] relay request: tunnel=%s target=%s",
		tunnelID[:min(len(tunnelID), 16)], req.TargetKey[:min(len(req.TargetKey), 16)]+"...")

	// Try to open a stream to the target peer.
	targetSession := h.node.GetSession(req.TargetKey)
	if targetSession == nil {
		// Also check clientSessions.
		h.node.sessionsMu.Lock()
		targetSession = h.node.clientSessions[req.TargetKey]
		h.node.sessionsMu.Unlock()
	}
	if targetSession == nil {
		h.sendResponse(initiatorConn, tunnelID, false, RelayRejectNoSessionToTarget)
		h.removeTunnel(tunnelID)
		initiatorConn.Close()
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
		InitiatorKey: "", // we don't know the initiator's key from the request
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
	resp, err := readRelayMessage(targetStream)
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
	h.mu.Lock()
	tunnel.TargetConn = targetStream
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
// A heartbeat goroutine sends MsgRelayHeartbeat at heartbeatInterval
// to both peers, keeping the tunnel alive during idle periods.
func (h *RelayHandler) startBridge(tunnel *relayTunnel) {
	initiator := tunnel.InitiatorConn
	target := tunnel.TargetConn

	if initiator == nil || target == nil {
		log.Printf("[mesh-relay] cannot bridge: nil stream (tunnel=%s)", tunnel.ID[:16])
		h.removeTunnel(tunnel.ID)
		return
	}

	go func() {
		defer h.removeTunnel(tunnel.ID)

		// Start heartbeat goroutine.
		heartbeatDone := make(chan struct{})
		go func() {
			if h.heartbeatInterval <= 0 {
				return
			}
			ticker := time.NewTicker(h.heartbeatInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					hb := &MeshRelayHeartbeat{
						Type:      MsgRelayHeartbeat,
						TunnelID:  tunnel.ID,
						Timestamp: nowNano(),
					}
					// Best-effort heartbeat — write errors are non-fatal.
					_ = writeRelayMessage(initiator, hb)
					_ = writeRelayMessage(target, hb)
					tunnel.LastActivity.Store(nowNano())
				case <-heartbeatDone:
					return
				}
			}
		}()
		defer close(heartbeatDone)

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
