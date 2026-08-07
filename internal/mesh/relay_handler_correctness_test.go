package mesh

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// --- Fix #1: handleDialBack dead code regression test ---

// TestHandleDialBack_StartsBridge verifies that when a MeshRelayResponse
// arrives via the dial-back path (handleDialBack), the relay starts the
// bidirectional bridge — data flows between initiator and target.
// Before the fix, handleDialBack set TargetConn but never called
// startBridge, leaving the tunnel hanging and leaking resources.
func TestHandleDialBack_StartsBridge(t *testing.T) {
	relayNode := createTestNode(t)

	handler := NewRelayHandler(relayNode, "localkey")
	defer handler.Close()

	tunnelID := newTunnelID()

	// initiator pipe — the relay's side is InitiatorConn.
	initRelay, initiator := net.Pipe()
	defer initiator.Close()

	// target dial-back pipe — the relay's side is TargetConn (set by
	// handleDialBack). We'll manually feed a MeshRelayResponse on this
	// pipe so handleDialBack matches it to the tunnel.
	targetRelay, targetSide := net.Pipe()
	defer targetSide.Close()

	// Pre-create the tunnel with the initiator conn already set.
	tunnel := &relayTunnel{
		ID:            tunnelID,
		InitiatorConn: initRelay,
		CreatedAt:     time.Now(),
		done:          make(chan struct{}),
	}
	tunnel.LastActivity.Store(nowNano())
	handler.mu.Lock()
	handler.tunnels[tunnelID] = tunnel
	handler.mu.Unlock()

	// Send a MeshRelayResponse (accept) on the target pipe so
	// handleDialBack picks it up.
	go func() {
		resp := &MeshRelayResponse{
			Type:      MsgRelayAccept,
			TunnelID:  tunnelID,
			Timestamp: nowNano(),
		}
		writeRelayMessage(targetSide, resp)
	}()

	// Feed the relay side of the target pipe to HandleStream, which will
	// read the response and dispatch to handleDialBack.
	go handler.HandleStream(targetRelay)

	// Wait a moment for the bridge to start, then write data from
	// initiator → target (through the relay bridge).
	time.Sleep(200 * time.Millisecond)

	msg := []byte("hello through dial-back bridge")
	if _, err := initiator.Write(msg); err != nil {
		t.Fatalf("initiator write: %v", err)
	}

	// Read on the target side.
	buf := make([]byte, len(msg))
	targetSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(targetSide, buf); err != nil {
		t.Fatalf("target read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("data mismatch: got %q, want %q", buf, msg)
	}
}

// TestHandleDialBack_RejectRemovesTunnel verifies that when handleDialBack
// receives a reject response, the tunnel is removed (previously it was
// left dangling).
func TestHandleDialBack_RejectRemovesTunnel(t *testing.T) {
	relayNode := createTestNode(t)
	handler := NewRelayHandler(relayNode, "localkey")
	defer handler.Close()

	tunnelID := newTunnelID()
	initRelay, initiator := net.Pipe()
	defer initiator.Close()
	targetRelay, targetSide := net.Pipe()
	defer targetSide.Close()

	tunnel := &relayTunnel{
		ID:            tunnelID,
		InitiatorConn: initRelay,
		CreatedAt:     time.Now(),
		done:          make(chan struct{}),
	}
	tunnel.LastActivity.Store(nowNano())
	handler.mu.Lock()
	handler.tunnels[tunnelID] = tunnel
	handler.mu.Unlock()

	// Send a reject response.
	go func() {
		resp := &MeshRelayResponse{
			Type:         MsgRelayReject,
			TunnelID:     tunnelID,
			RejectReason: "target_unreachable",
			Timestamp:    nowNano(),
		}
		writeRelayMessage(targetSide, resp)
	}()

	go handler.HandleStream(targetRelay)

	// Give a moment for processing.
	time.Sleep(200 * time.Millisecond)

	if count := handler.TunnelCount(); count != 0 {
		t.Errorf("tunnel count after reject = %d, want 0 (tunnel should be removed)", count)
	}
}

// --- Fix #2: readRelayMessage framing regression test ---

// TestReadRelayMessage_PartialRead verifies that readRelayMessage
// correctly handles the case where a msgpack message is split across
// multiple TCP reads (simulated via a slow reader that writes one byte
// at a time). Before the fix, a single conn.Read could return a partial
// msgpack payload, causing unmarshalRelayMsg to fail.
func TestReadRelayMessage_PartialRead(t *testing.T) {
	// Encode a relay message.
	req := &MeshRelayRequest{
		Type:      MsgRelayRequest,
		TunnelID:  newTunnelID(),
		TargetKey: "targetpeer1234567890abcdef",
		Port:      0x524C,
		Timestamp: nowNano(),
	}
	data, err := msgpack.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Create a pipe and write the data one byte at a time to simulate
	// fragmentation.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		for i := 0; i < len(data); i++ {
			clientConn.Write(data[i : i+1])
			// Small delay between bytes to ensure they arrive as
			// separate reads on the server side.
			time.Sleep(time.Millisecond)
		}
	}()

	// Read on the server side — should get the complete message despite
	// fragmentation.
	serverConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	msg, err := readRelayMessage(serverConn)
	if err != nil {
		t.Fatalf("readRelayMessage with fragmented writes: %v", err)
	}

	result, ok := msg.(*MeshRelayRequest)
	if !ok {
		t.Fatalf("expected *MeshRelayRequest, got %T", msg)
	}
	if result.TunnelID != req.TunnelID {
		t.Errorf("tunnel ID mismatch: got %q, want %q", result.TunnelID, req.TunnelID)
	}
	if result.TargetKey != req.TargetKey {
		t.Errorf("target key mismatch: got %q, want %q", result.TargetKey, req.TargetKey)
	}
	if result.Port != req.Port {
		t.Errorf("port mismatch: got %d, want %d", result.Port, req.Port)
	}
}

// TestReadRelayMessage_LargeMessage verifies that readRelayMessage
// correctly handles a msgpack message that is larger than the typical
// TCP segment size (simulating a message that requires multiple reads
// to fully assemble). Before the fix, a single conn.Read could return
// a partial payload, causing unmarshalRelayMsg to fail.
func TestReadRelayMessage_LargeMessage(t *testing.T) {
	// Encode a relay message with a long target key to produce a
	// larger payload.
	req := &MeshRelayRequest{
		Type:      MsgRelayRequest,
		TunnelID:  newTunnelID(),
		TargetKey: string(make([]byte, 512)), // 512-byte target key
		Port:      0x524C,
		Timestamp: nowNano(),
	}
	data, err := msgpack.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) < 100 {
		t.Fatalf("test data too small: %d bytes", len(data))
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write the data one byte at a time to force fragmentation.
	go func() {
		for i := 0; i < len(data); i++ {
			clientConn.Write(data[i : i+1])
		}
		time.Sleep(2 * time.Second) // keep pipe open
	}()

	serverConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	msg, err := readRelayMessage(serverConn)
	if err != nil {
		t.Fatalf("readRelayMessage with fragmented writes: %v", err)
	}

	result, ok := msg.(*MeshRelayRequest)
	if !ok {
		t.Fatalf("expected *MeshRelayRequest, got %T", msg)
	}
	if result.TunnelID != req.TunnelID {
		t.Errorf("tunnel ID mismatch: got %q, want %q", result.TunnelID, req.TunnelID)
	}
	if result.Port != req.Port {
		t.Errorf("port mismatch: got %d, want %d", result.Port, req.Port)
	}
}

// --- Fix #3: LastActivity updated during data flow regression test ---

// TestBridge_UpdatesLastActivity verifies that LastActivity is updated
// when data flows through the bridge, so cleanupIdleTunnels does not
// kill active tunnels.
func TestBridge_UpdatesLastActivity(t *testing.T) {
	relayNode := createTestNode(t)
	// Construct manually to set idleTimeout/heartbeatInterval before
	// the cleanupIdleTunnels goroutine starts, avoiding a data race.
	handler := &RelayHandler{
		node:              relayNode,
		localKey:          "localkey",
		tunnels:           make(map[string]*relayTunnel),
		maxTunnels:        DefaultMaxRelayTunnels,
		idleTimeout:       200 * time.Millisecond, // short for testing
		heartbeatInterval: 0,                      // disable heartbeat to test activityWriter path
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
	initialActivity := nowNano()
	// Set initial activity slightly in the past so we can detect updates.
	initialActivity = initialActivity - int64(time.Second)
	tunnel.LastActivity.Store(initialActivity)
	handler.mu.Lock()
	handler.tunnels[tunnelID] = tunnel
	handler.mu.Unlock()

	// Start the bridge.
	handler.startBridge(tunnel)

	// net.Pipe is synchronous: writes block until the other side reads.
	// Use concurrent read+write to keep data flowing.
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Reader on target side drains data from initiator.
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			select {
			case <-stop:
				return
			default:
			}
			target.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			target.Read(buf)
		}
	}()

	// Writer on initiator side sends data.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, err := initiator.Write([]byte("keepalive-data"))
			if err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Let data flow for 300ms (past the 200ms idle timeout).
	time.Sleep(300 * time.Millisecond)

	// Check that LastActivity has been updated (should be newer than
	// the initial value we set in the past).
	currentActivity := tunnel.LastActivity.Load()
	if currentActivity <= initialActivity {
		t.Errorf("LastActivity was not updated during data flow: got %d, want > %d",
			currentActivity, initialActivity)
	}

	// The tunnel should still be alive (not cleaned up) because we've
	// been sending data.
	if count := handler.TunnelCount(); count != 1 {
		t.Errorf("tunnel count = %d, want 1 (active tunnel should not be cleaned up)", count)
	}

	// Stop and clean up.
	close(stop)
	wg.Wait()
	initiator.Close()
	target.Close()
}

// TestBridge_ActiveTunnelSurvivesIdleTimeout verifies that a tunnel with
// active data flow survives the idle timeout, while an idle tunnel is
// cleaned up. This is the core regression test for Fix #3.
func TestBridge_ActiveTunnelSurvivesIdleTimeout(t *testing.T) {
	relayNode := createTestNode(t)
	// Construct manually to set fields before the cleanup goroutine starts.
	handler := &RelayHandler{
		node:              relayNode,
		localKey:          "localkey",
		tunnels:           make(map[string]*relayTunnel),
		maxTunnels:        DefaultMaxRelayTunnels,
		idleTimeout:       100 * time.Millisecond,
		heartbeatInterval: 0, // disable heartbeat to test only the activityWriter path
	}
	go handler.cleanupIdleTunnels()
	defer handler.Close()

	// Active tunnel — has data flowing.
	activeID := newTunnelID()
	aInitRelay, aInit := net.Pipe()
	defer aInit.Close()
	aTargetRelay, aTarget := net.Pipe()
	defer aTarget.Close()

	activeTunnel := &relayTunnel{
		ID:            activeID,
		InitiatorConn: aInitRelay,
		TargetConn:    aTargetRelay,
		CreatedAt:     time.Now(),
		done:          make(chan struct{}),
	}
	activeTunnel.LastActivity.Store(nowNano())
	handler.mu.Lock()
	handler.tunnels[activeID] = activeTunnel
	handler.mu.Unlock()
	handler.startBridge(activeTunnel)

	// Continuously send data through the active tunnel.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			select {
			case <-stop:
				return
			default:
			}
			aInit.Write([]byte("active-data"))
			aTarget.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			aTarget.Read(buf)
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Wait well past the idle timeout.
	time.Sleep(400 * time.Millisecond)

	// Active tunnel should still be alive.
	if count := handler.TunnelCount(); count != 1 {
		t.Errorf("tunnel count = %d, want 1 (active tunnel should survive idle timeout)", count)
	}

	// Stop the active tunnel.
	close(stop)
	wg.Wait()
	aInit.Close()
	aTarget.Close()
	time.Sleep(200 * time.Millisecond)

	// Now the active tunnel should be cleaned up.
	if count := handler.TunnelCount(); count != 0 {
		t.Errorf("tunnel count after close = %d, want 0", count)
	}
}

// --- Fix #4: DEFECT-B tunnel pile-up regression test ---

// TestEvictStaleHalfOpen verifies that when the relay is at capacity,
// stale half-open tunnels (TargetConn nil, older than staleHalfOpenTimeout)
// are evicted to make room for new requests.
func TestEvictStaleHalfOpen(t *testing.T) {
	relayNode := createTestNode(t)
	handler := NewRelayHandler(relayNode, "localkey")
	handler.maxTunnels = 3
	defer handler.Close()

	// Insert 3 stale half-open tunnels (TargetConn nil, old CreatedAt).
	staleTime := time.Now().Add(-2 * staleHalfOpenTimeout)
	for i := 0; i < 3; i++ {
		tunnelID := newTunnelID()
		_, dummy := net.Pipe()
		handler.mu.Lock()
		handler.tunnels[tunnelID] = &relayTunnel{
			ID:            tunnelID,
			InitiatorConn: dummy,
			CreatedAt:     staleTime,
			done:          make(chan struct{}),
		}
		handler.mu.Unlock()
	}

	// All 3 slots are full. A new request should trigger eviction.
	// We need a session to a target for the request to proceed past
	// capacity check. Use a real triple-node setup.
	nodeA, relayNode2, nodeB, peerA, peerB := createTripleNodes(t)

	// Replace the relay handler with our test handler (already configured
	// with maxTunnels=3 and 3 stale tunnels).
	// We need to register it on relayNode2's port.
	// Instead, let's just test evictStaleHalfOpen directly.

	// Call evictStaleHalfOpen — should evict all 3.
	evicted := handler.evictStaleHalfOpen()
	if evicted != 3 {
		t.Errorf("evicted = %d, want 3", evicted)
	}
	if count := handler.TunnelCount(); count != 0 {
		t.Errorf("tunnel count after eviction = %d, want 0", count)
	}

	// Clean up unused triple nodes.
	_ = nodeA
	_ = relayNode2
	_ = nodeB
	_ = peerA
	_ = peerB
}

// TestEvictStaleHalfOpen_KeepsActiveTunnels verifies that tunnels with
// TargetConn set (fully established) are NOT evicted even if old.
func TestEvictStaleHalfOpen_KeepsActiveTunnels(t *testing.T) {
	relayNode := createTestNode(t)
	handler := NewRelayHandler(relayNode, "localkey")
	defer handler.Close()

	staleTime := time.Now().Add(-2 * staleHalfOpenTimeout)

	// Active tunnel — has TargetConn set.
	activeID := newTunnelID()
	aPipe1, _ := net.Pipe()
	aPipe2, _ := net.Pipe()
	defer aPipe1.Close()
	defer aPipe2.Close()
	handler.mu.Lock()
	handler.tunnels[activeID] = &relayTunnel{
		ID:            activeID,
		InitiatorConn: aPipe1,
		TargetConn:    aPipe2,
		CreatedAt:     staleTime,
		done:          make(chan struct{}),
	}
	handler.mu.Unlock()

	// Half-open tunnel — TargetConn nil.
	halfOpenID := newTunnelID()
	hPipe, _ := net.Pipe()
	defer hPipe.Close()
	handler.mu.Lock()
	handler.tunnels[halfOpenID] = &relayTunnel{
		ID:            halfOpenID,
		InitiatorConn: hPipe,
		CreatedAt:     staleTime,
		done:          make(chan struct{}),
	}
	handler.mu.Unlock()

	evicted := handler.evictStaleHalfOpen()
	if evicted != 1 {
		t.Errorf("evicted = %d, want 1 (only half-open should be evicted)", evicted)
	}

	// Active tunnel should still be there.
	handler.mu.RLock()
	_, activeExists := handler.tunnels[activeID]
	_, halfOpenExists := handler.tunnels[halfOpenID]
	handler.mu.RUnlock()

	if !activeExists {
		t.Error("active tunnel was evicted (should have been kept)")
	}
	if halfOpenExists {
		t.Error("half-open tunnel was not evicted (should have been removed)")
	}
}

// TestEvictStaleHalfOpen_AtCapacityWithEviction verifies the end-to-end
// flow: when at capacity with only stale half-open tunnels, a new
// request triggers eviction and proceeds.
func TestEvictStaleHalfOpen_AtCapacityWithEviction(t *testing.T) {
	nodeA, relayNode, nodeB, peerA, peerB := createTripleNodes(t)

	// Register relay handler on relay node with maxTunnels=2.
	relayHandler, err := relayNode.RegisterRelayHandler()
	if err != nil {
		t.Fatalf("relay RegisterRelayHandler: %v", err)
	}
	relayHandler.maxTunnels = 2
	defer relayHandler.Close()

	// Register relay handler on target node B.
	targetHandler, err := nodeB.RegisterRelayHandler()
	if err != nil {
		t.Fatalf("nodeB RegisterRelayHandler: %v", err)
	}
	defer targetHandler.Close()

	// Insert 2 stale half-open tunnels to fill capacity.
	staleTime := time.Now().Add(-2 * staleHalfOpenTimeout)
	for i := 0; i < 2; i++ {
		tunnelID := newTunnelID()
		_, dummy := net.Pipe()
		relayHandler.mu.Lock()
		relayHandler.tunnels[tunnelID] = &relayTunnel{
			ID:            tunnelID,
			InitiatorConn: dummy,
			CreatedAt:     staleTime,
			done:          make(chan struct{}),
		}
		relayHandler.mu.Unlock()
	}

	// Now dial via relay — should evict stale tunnels and succeed.
	dialer := NewRelayDialer(nodeA, peerA)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := dialer.DialViaRelay(ctx, peerA, peerB, 0)
	if err != nil {
		t.Fatalf("DialViaRelay with stale eviction: %v", err)
	}
	defer conn.Close()

	// Verify data flows.
	msg := []byte("hello after stale eviction")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("data mismatch: got %q, want %q", buf, msg)
	}
}
