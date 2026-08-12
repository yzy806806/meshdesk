package mesh

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestRelay_PortPreservation_ProductionPath is the CRITICAL regression
// test for the relay fallback port-loss bug.
//
// Bug: DialVirtualPort(ctx, peerKey, port) → tryRelayFallback dropped the
// port → DialViaRelay had no port → MeshRelayRequest had no Port field →
// MeshRelayDial had no Port field → OnRelayDial was never wired in main.go
// → handleDial fell back to io.Copy echo. Real services (collector 0x105F,
// TUN 0x4D, SOCKS5 0x5350) never received data.
//
// Fix: Port field added to MeshRelayRequest and MeshRelayDial, threaded
// through the entire chain, OnRelayDial wired in main.go to dial the local
// virtual port via DialLocalVirtualPort and bridge with RelayStream.
//
// This test verifies the fix end-to-end:
//  1. Triple-node topology: A → relay → B (A and B have no direct session)
//  2. B registers a real virtual port service on port 2222 that responds
//     with a fixed payload (NOT echo)
//  3. B wires OnRelayDial to DialLocalVirtualPort + RelayStream (same as
//     main.go production wiring)
//  4. A calls DialVirtualPort(ctx, peerB, 2222) which triggers relay fallback
//  5. Assert: A receives the service's fixed payload, NOT its own echo
//
// Before the fix, step 5 fails — A receives its own data echoed back
// because the port was lost and OnRelayDial was never called.
func TestRelay_PortPreservation_ProductionPath(t *testing.T) {
	nodeA, relayNode, nodeB, _, peerB := createTripleNodes(t)

	// Register relay handler on the relay node.
	relayHandler, err := relayNode.RegisterRelayHandler()
	if err != nil {
		t.Fatalf("relay RegisterRelayHandler: %v", err)
	}
	defer relayHandler.Close()

	// Register relay handler on the target node (B) — this is the
	// production path where B uses RelayHandler.HandleStream.
	targetHandler, err := nodeB.RegisterRelayHandler()
	if err != nil {
		t.Fatalf("nodeB RegisterRelayHandler: %v", err)
	}
	defer targetHandler.Close()

	// Register a real virtual port service on B (port 2222).
	// The service reads a request and responds with a fixed payload.
	const servicePort = 2222
	const serviceResponse = "HELLO_FROM_SERVICE_2222"

	svcLn, err := nodeB.ListenVirtualPort(servicePort)
	if err != nil {
		t.Fatalf("nodeB ListenVirtualPort(%d): %v", servicePort, err)
	}
	defer svcLn.Close()

	go func() {
		for {
			conn, err := svcLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read the request (drain whatever the client sends).
				buf := make([]byte, 1024)
				c.Read(buf)
				// Respond with the fixed payload.
				c.Write([]byte(serviceResponse))
			}(conn)
		}
	}()

	// Wire OnRelayDial on B — this is the production wiring from main.go.
	// The callback dials the local virtual port service and bridges the
	// relay stream to it with bidirectional io.Copy.
	targetHandler.OnRelayDial = func(dial *MeshRelayDial, conn net.Conn) {
		if dial.Port == 0 {
			// Legacy path — should not happen in this test.
			t.Error("OnRelayDial: dial.Port is 0, expected service port")
			go func() {
				io.Copy(conn, conn)
				conn.Close()
			}()
			return
		}

		localConn, dErr := nodeB.DialLocalVirtualPort(int(dial.Port), dial.InitiatorKey)
		if dErr != nil {
			t.Errorf("OnRelayDial: DialLocalVirtualPort(%d): %v", dial.Port, dErr)
			conn.Close()
			return
		}

		// Bridge bidirectionally.
		go RelayStream(conn, localConn)
	}

	// Node A dials B's virtual port 2222 via relay fallback.
	// A has no direct session to B, so DialVirtualPort falls through to
	// tryRelayFallback(ctx, peerB, 2222, nil).
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := nodeA.DialVirtualPort(ctx, peerB, servicePort)
	if err != nil {
		t.Fatalf("DialVirtualPort(ctx, %s, %d): %v", peerB, servicePort, err)
	}
	defer conn.Close()

	// Send a request to the service.
	requestMsg := []byte("ping from A via relay")
	if _, err := conn.Write(requestMsg); err != nil {
		t.Fatalf("A write: %v", err)
	}

	// Read the response. If the bug is present, we'll get our own
	// request echoed back instead of the service's response.
	respBuf := make([]byte, 256)
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("A read response: %v", err)
	}
	resp := string(respBuf[:n])

	if resp == string(requestMsg) {
		t.Fatalf("BUG: received echo of own data (port was lost, OnRelayDial not called or fell back to echo). got %q", resp)
	}

	if resp != serviceResponse {
		t.Fatalf("response mismatch: got %q, want %q", resp, serviceResponse)
	}

	t.Logf("SUCCESS: A received service response %q via relay (port preserved end-to-end)", resp)

	// Verify relay has one active tunnel.
	if count := relayHandler.TunnelCount(); count != 1 {
		t.Errorf("relay tunnel count = %d, want 1", count)
	}
}

// TestDialLocalVirtualPort_Basic verifies that DialLocalVirtualPort
// correctly dispatches to a local virtual port listener and data flows
// bidirectionally through the pipe.
func TestDialLocalVirtualPort_Basic(t *testing.T) {
	node := createTestNode(t)

	const port = 3333
	ln, err := node.ListenVirtualPort(port)
	if err != nil {
		t.Fatalf("ListenVirtualPort(%d): %v", port, err)
	}
	defer ln.Close()

	// Start a service that echoes data back.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(conn, conn)
		conn.Close()
	}()

	// Dial the local virtual port.
	conn, err := node.DialLocalVirtualPort(port, "testpeer")
	if err != nil {
		t.Fatalf("DialLocalVirtualPort(%d): %v", port, err)
	}
	defer conn.Close()

	// Write and read echo.
	msg := []byte("hello local virtual port")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(msg) {
		t.Errorf("data mismatch: got %q, want %q", buf, msg)
	}
}

// TestDialLocalVirtualPort_NoListener verifies that DialLocalVirtualPort
// returns an error when no listener is registered for the port.
func TestDialLocalVirtualPort_NoListener(t *testing.T) {
	node := createTestNode(t)

	_, err := node.DialLocalVirtualPort(9999, "")
	if err == nil {
		t.Fatal("expected error when no listener registered, got nil")
	}
}

// TestRelay_PortPreservation_MsgpackCompat verifies that a MeshRelayRequest
// encoded by an old node (without the Port field) can be decoded by the
// new struct, and vice versa. This ensures rolling upgrades don't break.
func TestRelay_PortPreservation_MsgpackCompat(t *testing.T) {
	// Simulate old-format request (no Port field in msgpack map).
	// We encode a map that only has t, tid, tgk, ts — no "pt" key.
	oldData, err := marshalRelayMsg(map[string]any{
		"t":   uint8(MsgRelayRequest),
		"tid": "oldtunnel123",
		"tgk": "oldtarget",
		"ts":  int64(12345),
	})
	if err != nil {
		t.Fatalf("marshal old-format: %v", err)
	}

	msg, err := unmarshalRelayMsg(oldData)
	if err != nil {
		t.Fatalf("decode old-format: %v", err)
	}

	req, ok := msg.(*MeshRelayRequest)
	if !ok {
		t.Fatalf("expected *MeshRelayRequest, got %T", msg)
	}

	if req.Port != 0 {
		t.Errorf("Port should default to 0 for old format, got %d", req.Port)
	}
	if req.TunnelID != "oldtunnel123" {
		t.Errorf("TunnelID mismatch: got %q, want %q", req.TunnelID, "oldtunnel123")
	}

	// Now encode a new-format request (with Port) and verify it round-trips.
	newReq := &MeshRelayRequest{
		Type:      MsgRelayRequest,
		TunnelID:  "newtunnel456",
		TargetKey: "newtarget",
		Port:      2222,
		Timestamp: 99999,
	}
	newData, err := marshalRelayMsg(newReq)
	if err != nil {
		t.Fatalf("marshal new-format: %v", err)
	}

	msg2, err := unmarshalRelayMsg(newData)
	if err != nil {
		t.Fatalf("decode new-format: %v", err)
	}

	req2, ok := msg2.(*MeshRelayRequest)
	if !ok {
		t.Fatalf("expected *MeshRelayRequest, got %T", msg2)
	}

	if req2.Port != 2222 {
		t.Errorf("Port mismatch: got %d, want 2222", req2.Port)
	}
	if req2.TunnelID != "newtunnel456" {
		t.Errorf("TunnelID mismatch: got %q, want %q", req2.TunnelID, "newtunnel456")
	}
}
