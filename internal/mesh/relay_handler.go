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

	// ready is closed when both initiator and target streams are connected
	// and bridging can begin.
	ready chan struct{}

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
	node       *MeshNode
	localKey   string
	tunnels    map[string]*relayTunnel
	mu         sync.RWMutex
	maxTunnels int
	idleTimeout time.Duration
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
	return &RelayHandler{
		node:              node,
		localKey:         localKey,
		tunnels:          make(map[string]*relayTunnel),
		maxTunnels:       DefaultMaxRelayTunnels,
		idleTimeout:      DefaultRelayIdleTimeout,
		heartbeatInterval: DefaultRelayHeartbeatInterval,
	}
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
		h.sendResponse(initiatorConn, req.TunnelID, false, RelayRejectAtCapacity)
		initiatorConn.Close()
		return
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
		ID:           tunnelID,
		InitiatorKey: "", // unknown from request; could be inferred from peer
		TargetKey:    req.TargetKey,
		InitiatorConn: initiatorConn,
		ready:        make(chan struct{}),
		CreatedAt:    time.Now(),
		done:         make(chan struct{}),
	}
	tunnel.LastActivity.Store(nowNano())
	h.tunnels[tunnelID] = tunnel
	h.mu.Unlock()

	log.Printf("[mesh-relay] relay request: tunnel=%s target=%s",
		tunnelID[:16], req.TargetKey[:min(len(req.TargetKey), 16)]+"...")

	// Try to open a stream to the target peer.
	targetSession := h.node.GetSession(req.TargetKey)
	if targetSession == nil {
		// Also check clientSessions.
		h.node.sessionsMu.Lock()
		targetSession, _ = h.node.clientSessions[req.TargetKey]
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
	// ready channel.
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
		log.Printf("[mesh-relay] dial-back for unknown tunnel %s", resp.TunnelID[:16])
		conn.Close()
		return
	}

	if resp.Type == MsgRelayReject {
		log.Printf("[mesh-relay] target dial-back rejected: %s", resp.RejectReason)
		conn.Close()
		close(tunnel.ready) // unblock any waiter
		return
	}

	// Target dialed back successfully.
	h.mu.Lock()
	tunnel.TargetConn = conn
	h.mu.Unlock()

	close(tunnel.ready)
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
	log.Printf("[mesh-relay] teardown for tunnel %s", td.TunnelID[:16])
	h.removeTunnel(td.TunnelID)
	conn.Close()
}

// startBridge starts two goroutines copying bytes between the initiator
// and target streams. When either copy returns (EOF or error), both
// streams are closed and the tunnel is removed.
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

		// Two goroutines: initiator → target, target → initiator.
		done := make(chan struct{}, 2)

		go func() {
			_, err := io.Copy(target, initiator)
			if err != nil {
				log.Printf("[mesh-relay] copy initiator→target: %v (tunnel=%s)", err, tunnel.ID[:16])
			}
			done <- struct{}{}
		}()

		go func() {
			_, err := io.Copy(initiator, target)
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

// readRelayMessage reads msgpack bytes from conn and decodes them into
// the appropriate relay message struct.
func readRelayMessage(conn net.Conn) (any, error) {
	// Relay messages are small (< 512 bytes). Use a bounded reader.
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read relay message: %w", err)
	}
	return unmarshalRelayMsg(buf[:n])
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

// Ensure msgpack is imported (used by marshalRelayMsg via relay_protocol.go).
var _ = msgpack.Marshal
