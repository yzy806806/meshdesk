package mesh

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestRelayHeartbeat_NoDataPlanePollution verifies that the relay bridge
// does NOT inject msgpack heartbeat bytes into the data streams.
//
// This is the regression test for the CRITICAL defect identified in the
// reviewer's report (t_9b17b0fc): startBridge's heartbeat goroutine
// wrote MsgRelayHeartbeat via writeRelayMessage directly into the tunnel
// data streams. Peer applications treat the stream as a raw byte pipe and
// do not parse msgpack, so heartbeat bytes were delivered as garbage
// business data — corrupting any length-prefixed / fixed-header / magic-
// number protocol (SOCKS5 handshake, TUN frames, collector reports).
//
// The fix removed the heartbeat entirely. This test verifies:
//  1. No unexpected bytes appear on either end of the tunnel during idle
//     periods (when no application data is being sent).
//  2. Only application data written by one side appears on the other.
func TestRelayHeartbeat_NoDataPlanePollution(t *testing.T) {
	relayNode := createTestNode(t)
	// Construct manually with a short idle timeout and heartbeat interval
	// to maximize the chance of catching any heartbeat injection.
	// (heartbeatInterval is now deprecated/no-op, but we set it short
	// to prove the old code path is gone.)
	handler := &RelayHandler{
		node:              relayNode,
		localKey:          "localkey",
		tunnels:           make(map[string]*relayTunnel),
		maxTunnels:        DefaultMaxRelayTunnels,
		idleTimeout:       30 * time.Second, // long enough to not kill the tunnel
		heartbeatInterval: 50 * time.Millisecond, // would have fired ~20 times in 1s
	}
	go handler.cleanupIdleTunnels()
	defer handler.Close()

	tunnelID := newTunnelID()

	initRelay, initiator := net.Pipe()
	defer initiator.Close()
	targetRelay, target := net.Pipe()
	defer target.Close()

	tunnel := &relayTunnel{
		ID:            tunnelID,
		InitiatorConn: initRelay,
		TargetConn:    targetRelay,
		CreatedAt:     time.Now(),
		done:          make(chan struct{}),
	}
	tunnel.LastActivity.Store(nowNano())
	handler.mu.Lock()
	handler.tunnels[tunnelID] = tunnel
	handler.mu.Unlock()

	// Start the bridge.
	handler.startBridge(tunnel)

	// Let the tunnel sit idle for 500ms. With a 50ms heartbeat interval,
	// the old code would have injected ~10 heartbeat messages (~240+
	// bytes of msgpack garbage) into each end.
	time.Sleep(500 * time.Millisecond)

	// Neither end should have received any data during the idle period.
	// Set a short read deadline and verify 0 bytes.
	initiator.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1024)
	n, err := initiator.Read(buf)
	if n > 0 {
		t.Errorf("initiator received %d unexpected bytes during idle period (heartbeat pollution): %x", n, buf[:n])
	}
	// Timeout error is expected and OK.
	_ = err
	initiator.SetReadDeadline(time.Time{})

	target.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, err = target.Read(buf)
	if n > 0 {
		t.Errorf("target received %d unexpected bytes during idle period (heartbeat pollution): %x", n, buf[:n])
	}
	_ = err
	target.SetReadDeadline(time.Time{})

	// Now verify that real application data flows correctly.
	// Write from initiator → target.
	msg := []byte("real application data")
	go func() {
		initiator.Write(msg)
	}()

	target.SetReadDeadline(time.Now().Add(2 * time.Second))
	received := make([]byte, len(msg))
	_, err = io.ReadFull(target, received)
	if err != nil {
		t.Fatalf("target did not receive application data: %v", err)
	}
	if string(received) != string(msg) {
		t.Errorf("data mismatch: got %q, want %q", received, msg)
	}

	// Clean up.
	initiator.Close()
	target.Close()
}

// TestRelayDecoder_NoCoalescedDataLoss verifies that bytes coalesced into
// the same TCP segment as the relay handshake message are not lost.
//
// This is the regression test for the HIGH defect: msgpack.NewDecoder(conn)
// internally buffers reads (4096 byte bufio). DecodeRaw consumes only one
// complete msgpack value, but the bufio may have already read subsequent
// bytes. readRelayMessage created a new Decoder each call, so the buffered
// bytes were discarded with the Decoder → coalesced business data was
// silently lost.
//
// The fix wraps every relay stream in a bufferedConn (bufio.Reader) before
// decoding, so leftover buffered bytes are replayed on subsequent reads.
//
// This test simulates the coalescing scenario: a single Write containing
// both a MeshRelayResponse (accept) and a service banner ("SERVICE_BANNER")
// is sent on a pipe. readRelayMessage should decode the response, and the
// remaining bytes (the banner) should be readable from the same conn.
func TestRelayDecoder_NoCoalescedDataLoss(t *testing.T) {
	// Create a pipe to simulate a relay stream.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Prepare a coalesced payload: accept response + service banner
	// written in a single Write (simulating TCP coalescing).
	resp := &MeshRelayResponse{
		Type:      MsgRelayAccept,
		TunnelID:  newTunnelID(),
		Timestamp: nowNano(),
	}
	respBytes, err := marshalRelayMsg(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	banner := []byte("SERVICE_BANNER")
	coalesced := append(respBytes, banner...)

	// Write the coalesced payload from the client side.
	go func() {
		clientConn.Write(coalesced)
	}()

	// On the server side, wrap in bufferedConn (as the fix does).
	bufConn := &bufferedConn{
		Reader: bufio.NewReader(serverConn),
		conn:   serverConn,
	}

	// Read the relay message — should decode the response.
	msg, err := readRelayMessage(bufConn)
	if err != nil {
		t.Fatalf("readRelayMessage: %v", err)
	}
	respMsg, ok := msg.(*MeshRelayResponse)
	if !ok {
		t.Fatalf("expected *MeshRelayResponse, got %T", msg)
	}
	if respMsg.Type != MsgRelayAccept {
		t.Errorf("response type = %d, want %d (accept)", respMsg.Type, MsgRelayAccept)
	}

	// Now read the remaining bytes — the service banner should be there.
	// With the old code (throwaway Decoder), these bytes would be lost.
	bannerBuf := make([]byte, len(banner))
	bufConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadFull(bufConn, bannerBuf)
	if err != nil {
		t.Fatalf("failed to read coalesced banner after relay message (data was swallowed by Decoder bufio): read %d bytes, err=%v", n, err)
	}
	if string(bannerBuf) != string(banner) {
		t.Errorf("banner mismatch: got %q, want %q", bannerBuf, banner)
	}
}

// TestRelayDecoder_CoalescedDataInDialViaRelay verifies the end-to-end
// relay path: when the target sends an accept response coalesced with
// the first data bytes, the initiator receives both correctly.
//
// This exercises the DialViaRelay fix path: the stream returned to the
// caller is a bufferedConn that replays leftover bytes.
func TestRelayDecoder_CoalescedDataInDialViaRelay(t *testing.T) {
	nodeA, relayNode, nodeB, peerA, peerB := createTripleNodes(t)

	relayHandler, err := relayNode.RegisterRelayHandler()
	if err != nil {
		t.Fatalf("relay RegisterRelayHandler: %v", err)
	}
	defer relayHandler.Close()

	targetHandler, err := nodeB.RegisterRelayHandler()
	if err != nil {
		t.Fatalf("nodeB RegisterRelayHandler: %v", err)
	}
	defer targetHandler.Close()

	const servicePort = 0x4444
	const immediateData = "IMMEDIATE_DATA_AFTER_ACCEPT"

	svcLn, err := nodeB.ListenVirtualPort(servicePort)
	if err != nil {
		t.Fatalf("nodeB ListenVirtualPort(%d): %v", servicePort, err)
	}
	defer svcLn.Close()

	// The service immediately writes data after accepting the connection.
	// This data may be coalesced with the relay accept response in the
	// same TCP segment.
	go func() {
		conn, err := svcLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Write immediately — this is the "coalesced" data that could
		// be swallowed by the old Decoder bufio.
		conn.Write([]byte(immediateData))
	}()

	// Wire OnRelayDial on B (production wiring).
	targetHandler.OnRelayDial = func(dial *MeshRelayDial, conn net.Conn) {
		localConn, dErr := nodeB.DialLocalVirtualPort(int(dial.Port), dial.InitiatorKey)
		if dErr != nil {
			conn.Close()
			return
		}
		go RelayStream(conn, localConn)
	}

	dialer := NewRelayDialer(nodeA, peerA)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialer.DialViaRelay(ctx, peerA, peerB, servicePort)
	if err != nil {
		t.Fatalf("DialViaRelay: %v", err)
	}
	defer conn.Close()

	// Read the immediate data — if the Decoder bufio swallowed it,
	// this read will block until timeout.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read immediate data (coalesced bytes were swallowed by Decoder bufio): %v", err)
	}
	if string(buf[:n]) != immediateData {
		t.Errorf("data mismatch: got %q, want %q", buf[:n], immediateData)
	}
}

// TestRelayInitiatorKey_Propagation verifies that the initiator's identity
// key is propagated through the entire relay chain:
//
//	DialViaRelay → MeshRelayRequest.InitiatorKey → handleRequest →
//	MeshRelayDial.InitiatorKey → OnRelayDial → DialLocalVirtualPort
//
// This is the regression test for the MEDIUM defect: the relay always set
// InitiatorKey to "" in MeshRelayDial, so the target couldn't identify
// the real initiator for authorization (ACL, source allowlist).
func TestRelayInitiatorKey_Propagation(t *testing.T) {
	nodeA, relayNode, nodeB, peerA, peerB := createTripleNodes(t)

	// Give nodeA a distinct identity key.
	const initiatorKey = "initiator_identity_key_12345"
	nodeA.identity = nil // createTestNode doesn't set identity; we'll use peerA

	relayHandler, err := relayNode.RegisterRelayHandler()
	if err != nil {
		t.Fatalf("relay RegisterRelayHandler: %v", err)
	}
	defer relayHandler.Close()

	targetHandler, err := nodeB.RegisterRelayHandler()
	if err != nil {
		t.Fatalf("nodeB RegisterRelayHandler: %v", err)
	}
	defer targetHandler.Close()

	const servicePort = 0x5555

	svcLn, err := nodeB.ListenVirtualPort(servicePort)
	if err != nil {
		t.Fatalf("nodeB ListenVirtualPort(%d): %v", servicePort, err)
	}
	defer svcLn.Close()

	go func() {
		conn, err := svcLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		conn.Read(buf)
		conn.Write([]byte("ok"))
	}()

	// Capture the InitiatorKey received by the target's OnRelayDial callback.
	receivedInitiatorKey := make(chan string, 1)
	targetHandler.OnRelayDial = func(dial *MeshRelayDial, conn net.Conn) {
		receivedInitiatorKey <- dial.InitiatorKey
		localConn, dErr := nodeB.DialLocalVirtualPort(int(dial.Port), dial.InitiatorKey)
		if dErr != nil {
			conn.Close()
			return
		}
		go RelayStream(conn, localConn)
	}

	// Create a dialer with a known localKey (the initiator's identity).
	dialer := NewRelayDialer(nodeA, initiatorKey)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialer.DialViaRelay(ctx, peerA, peerB, servicePort)
	if err != nil {
		t.Fatalf("DialViaRelay: %v", err)
	}
	defer conn.Close()

	// Write some data to trigger the relay path.
	conn.Write([]byte("hello"))

	// Verify the target received the correct InitiatorKey.
	select {
	case gotKey := <-receivedInitiatorKey:
		if gotKey != initiatorKey {
			t.Errorf("InitiatorKey not propagated: got %q, want %q", gotKey, initiatorKey)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: OnRelayDial was not called (InitiatorKey could not be verified)")
	}
}

// TestStartBridge_NoDoubleInvocation verifies that startBridge can only
// be called once per tunnel, preventing double io.Copy goroutines.
//
// This tests the non-blocking fix: adding a `started` atomic.Bool guard
// to relayTunnel. Without it, if both handleRequest (same-stream response)
// and handleDialBack (new-stream response) triggered for the same tunnel,
// two sets of io.Copy goroutines and heartbeats would run simultaneously.
func TestStartBridge_NoDoubleInvocation(t *testing.T) {
	relayNode := createTestNode(t)
	handler := &RelayHandler{
		node:              relayNode,
		localKey:          "localkey",
		tunnels:           make(map[string]*relayTunnel),
		maxTunnels:        DefaultMaxRelayTunnels,
		idleTimeout:       30 * time.Second,
		heartbeatInterval: 0,
	}
	go handler.cleanupIdleTunnels()
	defer handler.Close()

	tunnelID := newTunnelID()
	initRelay, initiator := net.Pipe()
	defer initiator.Close()
	targetRelay, target := net.Pipe()
	defer target.Close()

	tunnel := &relayTunnel{
		ID:            tunnelID,
		InitiatorConn: initRelay,
		TargetConn:    targetRelay,
		CreatedAt:     time.Now(),
		done:          make(chan struct{}),
	}
	tunnel.LastActivity.Store(nowNano())
	handler.mu.Lock()
	handler.tunnels[tunnelID] = tunnel
	handler.mu.Unlock()

	// First call should succeed.
	handler.startBridge(tunnel)

	// Second call should be a no-op (logged and returned).
	// We verify by checking that started is true and the tunnel is still
	// in the map (not removed by the spurious second call).
	if !tunnel.started.Load() {
		t.Error("tunnel.started should be true after first startBridge call")
	}

	// Call again — should not panic or start duplicate goroutines.
	handler.startBridge(tunnel)

	// Tunnel should still be in the map.
	if count := handler.TunnelCount(); count != 1 {
		t.Errorf("tunnel count = %d, want 1 (double startBridge should not remove tunnel)", count)
	}

	// Clean up.
	initiator.Close()
	target.Close()
}

// TestRelayRequest_InitiatorKeySerialization verifies that the InitiatorKey
// field survives msgpack marshal/unmarshal round-trip, ensuring backward
// compatibility (old nodes that don't know about the field simply ignore it).
func TestRelayRequest_InitiatorKeySerialization(t *testing.T) {
	original := &MeshRelayRequest{
		Type:         MsgRelayRequest,
		TunnelID:     "test-tunnel-id",
		TargetKey:    "target-peer-key",
		InitiatorKey: "initiator-peer-key",
		Port:         0x2222,
		Timestamp:    nowNano(),
	}

	data, err := marshalRelayMsg(original)
	if err != nil {
		t.Fatalf("marshalRelayMsg: %v", err)
	}

	msg, err := unmarshalRelayMsg(data)
	if err != nil {
		t.Fatalf("unmarshalRelayMsg: %v", err)
	}

	req, ok := msg.(*MeshRelayRequest)
	if !ok {
		t.Fatalf("expected *MeshRelayRequest, got %T", msg)
	}

	if req.InitiatorKey != original.InitiatorKey {
		t.Errorf("InitiatorKey mismatch: got %q, want %q", req.InitiatorKey, original.InitiatorKey)
	}
	if req.TargetKey != original.TargetKey {
		t.Errorf("TargetKey mismatch: got %q, want %q", req.TargetKey, original.TargetKey)
	}
	if req.Port != original.Port {
		t.Errorf("Port mismatch: got %d, want %d", req.Port, original.Port)
	}
}
