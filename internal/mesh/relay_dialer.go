package mesh

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

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
// Steps:
//  1. Look up smux session to relayKey
//  2. Open stream on port 0x524C
//  3. Send MeshRelayRequest{target=targetKey}
//  4. Wait for MeshRelayResponse (accept/reject)
//  5. On accept, return the stream as a net.Conn
//  6. On reject or timeout, return error
func (d *RelayDialer) DialViaRelay(
	ctx context.Context,
	relayKey string,
	targetKey string,
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
		Type:      MsgRelayRequest,
		TunnelID:  tunnelID,
		TargetKey: targetKey,
		Timestamp: nowNano(),
	}
	if err := writeRelayMessage(stream, req); err != nil {
		stream.Close()
		return nil, fmt.Errorf("mesh relay: send request: %w", err)
	}

	log.Printf("[mesh-relay] dialer: requesting relay tunnel=%s relay=%s target=%s",
		tunnelID[:16],
		relayKey[:min(len(relayKey), 16)]+"...",
		targetKey[:min(len(targetKey), 16)]+"...")

	// Wait for the relay's response with a timeout.
	resp, err := readRelayMessageWithContext(stream, relayResponseTimeout)
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
	log.Printf("[mesh-relay] dialer: tunnel=%s accepted", tunnelID[:16])
	return stream, nil
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
// relayCandidates is a list of peer identity hex strings that are known
// to have relay capability. The caller is responsible for providing
// candidates in preference order (e.g. by RTT). If relayCandidates is
// empty, the method returns an error.
func (n *MeshNode) DialViaRelay(
	ctx context.Context,
	targetKey string,
	relayCandidates []string,
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
	for _, relayKey := range relayCandidates {
		// Skip self.
		if relayKey == localKey {
			continue
		}

		conn, err := dialer.DialViaRelay(ctx, relayKey, targetKey)
		if err != nil {
			lastErr = err
			log.Printf("[mesh-relay] relay %s failed: %v",
				relayKey[:min(len(relayKey), 16)]+"...", err)
			continue
		}
		return conn, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("mesh relay: all candidates failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("mesh relay: no suitable relay candidate found")
}

// tryRelayFallback is called by DialVirtualPort when no direct session
// exists to the target peer. It collects all known peers that have
// active sessions (potential relay candidates) and tries DialViaRelay
// through each one.
//
// This is a best-effort fallback — if no relay candidate succeeds, the
// original "no session" error is returned by the caller.
func (n *MeshNode) tryRelayFallback(ctx context.Context, targetKey string) (net.Conn, error) {
	// Collect all peers we have sessions with — they are potential
	// relay candidates. In a production system, we would filter by
	// CapMeshRelay capability from gossip NodeMeta, but for now we
	// try all connected peers.
	n.sessionsMu.Lock()
	candidates := make([]string, 0, len(n.sessions)+len(n.clientSessions))
	seen := make(map[string]bool)
	for k := range n.sessions {
		if !seen[k] {
			candidates = append(candidates, k)
			seen[k] = true
		}
	}
	for k := range n.clientSessions {
		if !seen[k] {
			candidates = append(candidates, k)
			seen[k] = true
		}
	}
	n.sessionsMu.Unlock()

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no relay candidates (no active sessions)")
	}

	return n.DialViaRelay(ctx, targetKey, candidates)
}
