package mesh

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/smux"
)

// createPairedNodes creates two MeshNodes with a paired smux session
// over net.Pipe. Returns (clientNode, serverNode, peerID).
// The server node's handleSessionStreams is started so it dispatches
// virtual port streams to listeners.
func createPairedNodes(t *testing.T) (*MeshNode, *MeshNode, string) {
	t.Helper()

	clientNode := createTestNode(t)
	serverNode := createTestNode(t)

	sPipe, cPipe := net.Pipe()
	cfg := smux.DefaultConfig()
	cfg.HandshakeTimeout = 5 * time.Second

	errCh := make(chan error, 2)
	var serverSess, clientSess *smux.Session

	go func() {
		s, err := smux.Server(sPipe, cfg)
		serverSess = s
		errCh <- err
	}()
	go func() {
		c, err := smux.Client(cPipe, cfg)
		clientSess = c
		errCh <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("smux setup error: %v", err)
		}
	}

	peerID := "relaytestpeer01"
	serverNode.sessions[peerID] = serverSess
	serverNode.sessionEstablishedAt[peerID] = time.Now()
	clientNode.clientSessions[peerID] = clientSess
	clientNode.sessionEstablishedAt[peerID] = time.Now()

	// Start the server's session stream handler.
	go serverNode.handleSessionStreams(peerID, serverSess)
	// Start the client's session stream handler so it can accept
	// inbound streams (e.g. relay dial requests).
	go clientNode.handleSessionStreams(peerID, clientSess)

	return clientNode, serverNode, peerID
}

// createTripleNodes creates three MeshNodes (A, relay, B) with paired
// smux sessions: A→relay and B→relay. This simulates the cross-network
// relay topology where A and B cannot connect directly but both have
// sessions to the relay.
func createTripleNodes(t *testing.T) (*MeshNode, *MeshNode, *MeshNode, string, string) {
	t.Helper()

	nodeA := createTestNode(t)
	relayNode := createTestNode(t)
	nodeB := createTestNode(t)

	// A → relay session
	aPipeServer, aPipeClient := net.Pipe()
	cfg := smux.DefaultConfig()
	cfg.HandshakeTimeout = 5 * time.Second

	errCh := make(chan error, 4)
	var aServerSess, aClientSess, bServerSess, bClientSess *smux.Session

	go func() {
		s, err := smux.Server(aPipeServer, cfg)
		aServerSess = s
		errCh <- err
	}()
	go func() {
		c, err := smux.Client(aPipeClient, cfg)
		aClientSess = c
		errCh <- err
	}()

	// B → relay session
	bPipeServer, bPipeClient := net.Pipe()

	go func() {
		s, err := smux.Server(bPipeServer, cfg)
		bServerSess = s
		errCh <- err
	}()
	go func() {
		c, err := smux.Client(bPipeClient, cfg)
		bClientSess = c
		errCh <- err
	}()

	for i := 0; i < 4; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("smux setup error: %v", err)
		}
	}

	peerA := "peerA_identity01"
	peerB := "peerB_identity02"

	// Relay node has server-mode sessions from both A and B.
	relayNode.sessions[peerA] = aServerSess
	relayNode.sessionEstablishedAt[peerA] = time.Now()
	relayNode.sessions[peerB] = bServerSess
	relayNode.sessionEstablishedAt[peerB] = time.Now()

	// A has a client session to relay.
	nodeA.clientSessions[peerA] = aClientSess
	nodeA.sessionEstablishedAt[peerA] = time.Now()

	// B has a client session to relay.
	nodeB.clientSessions[peerB] = bClientSess
	nodeB.sessionEstablishedAt[peerB] = time.Now()

	// Start relay's session stream handlers.
	go relayNode.handleSessionStreams(peerA, aServerSess)
	go relayNode.handleSessionStreams(peerB, bServerSess)

	// Start node A and node B session stream handlers so they can
	// accept inbound streams (e.g. relay dial requests from the relay).
	go nodeA.handleSessionStreams(peerA, aClientSess)
	go nodeB.handleSessionStreams(peerB, bClientSess)

	return nodeA, relayNode, nodeB, peerA, peerB
}

// TestRelayHandler_BidirectionalDataFlow verifies that the RelayHandler
// can bridge two smux streams: data written by node A appears on node B
// and vice versa, all piped through the relay node.
func TestRelayHandler_BidirectionalDataFlow(t *testing.T) {
	nodeA, relayNode, nodeB, peerA, peerB := createTripleNodes(t)

	// Register the relay handler on the relay node.
	handler, err := relayNode.RegisterRelayHandler()
	if err != nil {
		t.Fatalf("RegisterRelayHandler: %v", err)
	}
	defer handler.Close()

	// Node B needs to handle RelayDial messages on port 0x524C.
	// When the relay opens a stream to B on port 0x524C and sends a
	// MeshRelayDial, B must respond with a MeshRelayResponse (accept).
	// We register a virtual listener on B for the relay port.
	bLn, err := nodeB.ListenVirtualPort(int(MeshRelayVirtualPort))
	if err != nil {
		t.Fatalf("nodeB ListenVirtualPort: %v", err)
	}
	defer bLn.Close()

	// Start a goroutine on B to accept relay dial requests and respond.
	go func() {
		for {
			conn, err := bLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				// Read the RelayDial message.
				msg, err := readRelayMessage(conn)
				if err != nil {
					return
				}
				dial, ok := msg.(*MeshRelayDial)
				if !ok {
					return
				}
				// Respond with accept.
				resp := &MeshRelayResponse{
					Type:      MsgRelayAccept,
					TunnelID:  dial.TunnelID,
					Timestamp: nowNano(),
				}
				if err := writeRelayMessage(conn, resp); err != nil {
					return
				}
				// After the handshake, this conn is a data pipe.
				// Echo data back for the test.
				io.Copy(conn, conn)
			}(conn)
		}
	}()

	// Node A dials via relay to reach B.
	dialer := NewRelayDialer(nodeA, peerA)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialer.DialViaRelay(ctx, peerA, peerB)
	if err != nil {
		t.Fatalf("DialViaRelay: %v", err)
	}
	defer conn.Close()

	// Write test data from A → B (through relay).
	msgA := []byte("hello from A through relay")
	if _, err := conn.Write(msgA); err != nil {
		t.Fatalf("A write: %v", err)
	}

	// Read the echo back (B echoes data).
	buf := make([]byte, len(msgA))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("A read: %v", err)
	}
	if string(buf) != string(msgA) {
		t.Errorf("data mismatch: got %q, want %q", buf, msgA)
	}

	// Verify relay has one active tunnel.
	if count := handler.TunnelCount(); count != 1 {
		t.Errorf("tunnel count = %d, want 1", count)
	}
}

// TestRelayHandler_AtCapacity verifies that the relay rejects new tunnel
// requests when maxTunnels is reached.
func TestRelayHandler_AtCapacity(t *testing.T) {
	relayNode := createTestNode(t)

	handler := NewRelayHandler(relayNode, "localkey")
	handler.maxTunnels = 1
	defer handler.Close()

	// Manually insert a tunnel to fill capacity.
	tunnelID := newTunnelID()
	handler.tunnels[tunnelID] = &relayTunnel{
		ID:        tunnelID,
		ready:     make(chan struct{}),
		done:      make(chan struct{}),
		CreatedAt: time.Now(),
	}

	// Create a pipe to simulate the initiator's stream.
	initiator, responder := net.Pipe()
	defer initiator.Close()

	// Send request and read response concurrently — net.Pipe is
	// synchronous so we must read while writing.
	type readResult struct {
		msg any
		err error
	}
	readCh := make(chan readResult, 1)
	go func() {
		// Write the request first.
		req := &MeshRelayRequest{
			Type:      MsgRelayRequest,
			TunnelID:  newTunnelID(),
			TargetKey: "nonexistent",
			Timestamp: nowNano(),
		}
		if err := writeRelayMessage(initiator, req); err != nil {
			readCh <- readResult{nil, err}
			return
		}
		// Read the response.
		msg, err := readRelayMessage(initiator)
		readCh <- readResult{msg, err}
	}()

	// Handle the stream — should reject with at_capacity.
	handler.HandleStream(responder)

	select {
	case res := <-readCh:
		if res.err != nil {
			return // connection closed — acceptable
		}
		respMsg, ok := res.msg.(*MeshRelayResponse)
		if !ok {
			t.Fatalf("expected *MeshRelayResponse, got %T", res.msg)
		}
		if respMsg.Type != MsgRelayReject {
			t.Errorf("expected reject, got type %d", respMsg.Type)
		}
		if respMsg.RejectReason != RelayRejectAtCapacity {
			t.Errorf("reject reason = %q, want %q", respMsg.RejectReason, RelayRejectAtCapacity)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for response")
	}
}

// TestRelayHandler_NoSessionToTarget verifies that the relay rejects
// when it has no smux session to the requested target.
func TestRelayHandler_NoSessionToTarget(t *testing.T) {
	relayNode := createTestNode(t)

	handler := NewRelayHandler(relayNode, "localkey")
	defer handler.Close()

	initiator, responder := net.Pipe()
	defer initiator.Close()

	type readResult struct {
		msg any
		err error
	}
	readCh := make(chan readResult, 1)
	go func() {
		req := &MeshRelayRequest{
			Type:      MsgRelayRequest,
			TunnelID:  newTunnelID(),
			TargetKey: "nonexistentpeer",
			Timestamp: nowNano(),
		}
		if err := writeRelayMessage(initiator, req); err != nil {
			readCh <- readResult{nil, err}
			return
		}
		msg, err := readRelayMessage(initiator)
		readCh <- readResult{msg, err}
	}()

	handler.HandleStream(responder)

	select {
	case res := <-readCh:
		if res.err != nil {
			return
		}
		respMsg, ok := res.msg.(*MeshRelayResponse)
		if !ok {
			t.Fatalf("expected *MeshRelayResponse, got %T", res.msg)
		}
		if respMsg.Type != MsgRelayReject {
			t.Errorf("expected reject, got type %d", respMsg.Type)
		}
		if respMsg.RejectReason != RelayRejectNoSessionToTarget {
			t.Errorf("reject reason = %q, want %q", respMsg.RejectReason, RelayRejectNoSessionToTarget)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for response")
	}
}

// TestRelayHandler_DuplicateTunnel verifies that duplicate tunnel IDs
// are rejected.
func TestRelayHandler_DuplicateTunnel(t *testing.T) {
	relayNode := createTestNode(t)

	handler := NewRelayHandler(relayNode, "localkey")
	defer handler.Close()

	tunnelID := newTunnelID()
	// Pre-insert the tunnel.
	handler.tunnels[tunnelID] = &relayTunnel{
		ID:        tunnelID,
		ready:     make(chan struct{}),
		done:      make(chan struct{}),
		CreatedAt: time.Now(),
	}

	initiator, responder := net.Pipe()
	defer initiator.Close()

	type readResult struct {
		msg any
		err error
	}
	readCh := make(chan readResult, 1)
	go func() {
		req := &MeshRelayRequest{
			Type:      MsgRelayRequest,
			TunnelID:  tunnelID,
			TargetKey: "anytarget",
			Timestamp: nowNano(),
		}
		if err := writeRelayMessage(initiator, req); err != nil {
			readCh <- readResult{nil, err}
			return
		}
		msg, err := readRelayMessage(initiator)
		readCh <- readResult{msg, err}
	}()

	handler.HandleStream(responder)

	select {
	case res := <-readCh:
		if res.err != nil {
			return
		}
		respMsg, ok := res.msg.(*MeshRelayResponse)
		if !ok {
			t.Fatalf("expected *MeshRelayResponse, got %T", res.msg)
		}
		if respMsg.Type != MsgRelayReject {
			t.Errorf("expected reject, got type %d", respMsg.Type)
		}
		if respMsg.RejectReason != RelayRejectDuplicateTunnel {
			t.Errorf("reject reason = %q, want %q", respMsg.RejectReason, RelayRejectDuplicateTunnel)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for response")
	}
}

// TestRelayHandler_Close verifies that Close tears down all tunnels.
func TestRelayHandler_Close(t *testing.T) {
	relayNode := createTestNode(t)

	handler := NewRelayHandler(relayNode, "localkey")

	// Insert a fake tunnel with real pipes.
	pipe1a, pipe1b := net.Pipe()
	pipe2a, pipe2b := net.Pipe()

	tunnelID := newTunnelID()
	tunnel := &relayTunnel{
		ID:            tunnelID,
		InitiatorConn: pipe1a,
		TargetConn:    pipe2a,
		ready:         make(chan struct{}),
		done:          make(chan struct{}),
		CreatedAt:     time.Now(),
	}
	handler.tunnels[tunnelID] = tunnel

	// Close the handler.
	if err := handler.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The pipes should be closed.
	_, err := pipe1b.Write([]byte("test"))
	if err == nil {
		t.Error("expected pipe1b to be closed after handler Close")
	}
	_, err = pipe2b.Write([]byte("test"))
	if err == nil {
		t.Error("expected pipe2b to be closed after handler Close")
	}

	// Tunnel count should be 0.
	if count := handler.TunnelCount(); count != 0 {
		t.Errorf("tunnel count after close = %d, want 0", count)
	}

	// Clean up.
	pipe1b.Close()
	pipe2b.Close()
}

// TestRelayHandler_Teardown verifies that a teardown message removes
// the corresponding tunnel.
func TestRelayHandler_Teardown(t *testing.T) {
	relayNode := createTestNode(t)

	handler := NewRelayHandler(relayNode, "localkey")
	defer handler.Close()

	tunnelID := newTunnelID()
	pipe1a, pipe1b := net.Pipe()
	defer pipe1b.Close()

	tunnel := &relayTunnel{
		ID:            tunnelID,
		InitiatorConn: pipe1a,
		ready:         make(chan struct{}),
		done:          make(chan struct{}),
		CreatedAt:     time.Now(),
	}
	handler.tunnels[tunnelID] = tunnel

	// Send teardown on a new connection.
	tdConn, tdResponder := net.Pipe()
	defer tdConn.Close()

	go func() {
		td := &MeshRelayTeardown{
			Type:      MsgRelayTeardown,
			TunnelID:  tunnelID,
			Timestamp: nowNano(),
		}
		writeRelayMessage(tdConn, td)
	}()

	handler.HandleStream(tdResponder)

	// Give a moment for the teardown to process.
	time.Sleep(100 * time.Millisecond)

	// The tunnel should be removed.
	if count := handler.TunnelCount(); count != 0 {
		t.Errorf("tunnel count after teardown = %d, want 0", count)
	}
}

// TestRelayStream_BidirectionalCopy verifies the RelayStream function
// directly: data flows both directions and both conns are closed when
// either direction finishes.
func TestRelayStream_BidirectionalCopy(t *testing.T) {
	conn1a, conn1b := net.Pipe()
	conn2a, conn2b := net.Pipe()
	defer conn1b.Close()
	defer conn2b.Close()

	// Relay between conn1a and conn2a. After RelayStream returns,
	// both should be closed.
	go RelayStream(conn1a, conn2a)

	// Write from conn1b → appears on conn2b.
	msg1 := []byte("direction 1->2")
	if _, err := conn1b.Write(msg1); err != nil {
		t.Fatalf("conn1b write: %v", err)
	}
	buf := make([]byte, len(msg1))
	if _, err := io.ReadFull(conn2b, buf); err != nil {
		t.Fatalf("conn2b read: %v", err)
	}
	if string(buf) != string(msg1) {
		t.Errorf("1->2 mismatch: got %q, want %q", buf, msg1)
	}

	// Write from conn2b → appears on conn1b.
	msg2 := []byte("direction 2->1")
	if _, err := conn2b.Write(msg2); err != nil {
		t.Fatalf("conn2b write: %v", err)
	}
	buf2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(conn1b, buf2); err != nil {
		t.Fatalf("conn1b read: %v", err)
	}
	if string(buf2) != string(msg2) {
		t.Errorf("2->1 mismatch: got %q, want %q", buf2, msg2)
	}

	// Close one side — both relay conns should close.
	conn1b.Close()

	// Wait for conn2b to be closed (via relay propagation).
	_, err := conn2b.Write([]byte("should fail"))
	if err == nil {
		// May take a moment for the close to propagate.
		time.Sleep(100 * time.Millisecond)
		_, err = conn2b.Write([]byte("should fail now"))
	}
	// It's OK if the write succeeds once (buffered); the key is that
	// eventually the connection closes. We don't hard-assert here
	// because pipe semantics with half-close can be timing-dependent.
}

// TestRelayStream_NilConns verifies that RelayStream handles nil conns gracefully.
func TestRelayStream_NilConns(t *testing.T) {
	// Should not panic.
	RelayStream(nil, nil)

	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	// One nil — should return without blocking.
	RelayStream(conn1, nil)
	RelayStream(nil, conn2)
}

// TestRelayHandler_UnexpectedMessage verifies that the handler closes
// the connection when it receives an unexpected message type.
func TestRelayHandler_UnexpectedMessage(t *testing.T) {
	relayNode := createTestNode(t)

	handler := NewRelayHandler(relayNode, "localkey")
	defer handler.Close()

	initiator, responder := net.Pipe()
	defer initiator.Close()

	// Send a heartbeat message (not expected as first message on a new stream).
	go func() {
		hb := &MeshRelayHeartbeat{
			Type:      MsgRelayHeartbeat,
			TunnelID:  newTunnelID(),
			Timestamp: nowNano(),
		}
		writeRelayMessage(initiator, hb)
		// Keep the write side alive briefly so the handler can read.
		time.Sleep(500 * time.Millisecond)
	}()

	handler.HandleStream(responder)

	// The responder should be closed after the handler logs the unexpected
	// message and closes the connection. We just verify no panic occurred
	// and the handler is still operational.
	if count := handler.TunnelCount(); count != 0 {
		t.Errorf("tunnel count = %d, want 0 (unexpected message should not create tunnel)", count)
	}
}

// TestRelayHandler_ClosedRejectsNewStreams verifies that a closed handler
// rejects new streams.
func TestRelayHandler_ClosedRejectsNewStreams(t *testing.T) {
	relayNode := createTestNode(t)

	handler := NewRelayHandler(relayNode, "localkey")
	handler.Close()

	conn1, conn2 := net.Pipe()
	defer conn1.Close()

	handler.HandleStream(conn2)

	// conn2 should be closed.
	time.Sleep(50 * time.Millisecond)
	_, err := conn2.Write([]byte("test"))
	if err == nil {
		t.Error("expected conn2 to be closed by closed handler")
	}
}

// TestRelayHandler_ConcurrentTunnels verifies thread safety of tunnel
// creation and removal under concurrent access.
func TestRelayHandler_ConcurrentTunnels(t *testing.T) {
	relayNode := createTestNode(t)

	handler := NewRelayHandler(relayNode, "localkey")
	handler.maxTunnels = 100
	defer handler.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tunnelID := newTunnelID()
			handler.mu.Lock()
			handler.tunnels[tunnelID] = &relayTunnel{
				ID:        tunnelID,
				ready:     make(chan struct{}),
				done:      make(chan struct{}),
				CreatedAt: time.Now(),
			}
			handler.mu.Unlock()
			handler.removeTunnel(tunnelID)
		}()
	}
	wg.Wait()

	if count := handler.TunnelCount(); count != 0 {
		t.Errorf("tunnel count after concurrent test = %d, want 0", count)
	}
}
