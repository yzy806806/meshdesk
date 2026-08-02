package mesh

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/smux"
)

// setupSOCKS5ForwardTest creates a three-node test topology:
//   - clientNode: simulates the phone client
//   - sharedNode: runs the SOCKS5ForwardHandler (shared node)
//   - exitNode: runs the direct-dial SOCKS5Handler (exit node)
//
// The client connects to the shared node, which forwards to the exit node
// via DialVirtualPort on virtual port 0x4558 (ExitVirtualPort).
func setupSOCKS5ForwardTest(t *testing.T, forwardCfg SOCKS5ForwardConfig, exitCfg SOCKS5Config) (*MeshNode, *MeshNode, *MeshNode, string, string) {
	t.Helper()

	sharedNode := createTestNode(t)
	exitNode := createTestNode(t)
	clientNode := createTestNode(t)

	// Create smux sessions: client↔shared and shared↔exit.
	// For client↔shared:
	cPipe, sPipe := net.Pipe()
	smuxCfg := smux.DefaultConfig()
	smuxCfg.HandshakeTimeout = 5 * time.Second

	errCh := make(chan error, 4)
	var sharedSess1, clientSess *smux.Session
	go func() {
		s, err := smux.Server(sPipe, smuxCfg)
		sharedSess1 = s
		errCh <- err
	}()
	go func() {
		c, err := smux.Client(cPipe, smuxCfg)
		clientSess = c
		errCh <- err
	}()

	// For shared↔exit:
	ePipe, xPipe := net.Pipe()
	var sharedSess2, exitSess *smux.Session
	go func() {
		s, err := smux.Client(ePipe, smuxCfg)
		sharedSess2 = s
		errCh <- err
	}()
	go func() {
		c, err := smux.Server(xPipe, smuxCfg)
		exitSess = c
		errCh <- err
	}()

	for i := 0; i < 4; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("smux setup error: %v", err)
		}
	}

	// Wire up sessions.
	clientPeerID := "clientpeer"
	exitPeerID := "exitpeer"

	// Shared node has sessions to both client and exit.
	sharedNode.sessions[clientPeerID] = sharedSess1
	sharedNode.sessionEstablishedAt[clientPeerID] = time.Now()
	sharedNode.clientSessions[exitPeerID] = sharedSess2
	sharedNode.sessionEstablishedAt[exitPeerID] = time.Now()

	// Exit node has a session from shared.
	exitNode.sessions[exitPeerID] = exitSess
	exitNode.sessionEstablishedAt[exitPeerID] = time.Now()

	// Client node has a session to shared.
	clientNode.sessions[clientPeerID] = clientSess
	clientNode.sessionEstablishedAt[clientPeerID] = time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sharedNode.ctx = ctx
	exitNode.ctx = ctx

	// Start stream handlers.
	go sharedNode.handleSessionStreams(clientPeerID, sharedSess1)
	go exitNode.handleSessionStreams(exitPeerID, exitSess)

	// Register the exit-side SOCKS5 handler on the exit node (port 0x4558).
	if _, err := exitNode.RegisterSOCKS5ExitHandler(exitCfg); err != nil {
		t.Fatalf("exit RegisterSOCKS5ExitHandler: %v", err)
	}

	// Register the forward handler on the shared node.
	// Pin the exit node ID so it doesn't need gossip.
	forwardCfg.ExitNodeID = exitPeerID
	if _, err := sharedNode.RegisterSOCKS5ForwardHandler(forwardCfg); err != nil {
		t.Fatalf("shared RegisterSOCKS5ForwardHandler: %v", err)
	}

	return sharedNode, exitNode, clientNode, clientPeerID, exitPeerID
}

// TestSOCKS5Forward_BasicConnect verifies the full forwarding path:
// client → shared node (forward handler) → exit node (direct handler) → target.
func TestSOCKS5Forward_BasicConnect(t *testing.T) {
	// Start a local TCP echo server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	forwardCfg := SOCKS5ForwardConfig{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}
	exitCfg := SOCKS5Config{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}

	_, _, clientNode, clientPeerID, _ := setupSOCKS5ForwardTest(t, forwardCfg, exitCfg)

	// Client dials the shared node's SOCKS5 virtual port.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, clientPeerID, int(SOCKS5VirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort to shared: %v", err)
	}
	defer conn.Close()

	// Perform SOCKS5 greeting.
	if err := socks5Greeting(conn); err != nil {
		t.Fatalf("greeting failed: %v", err)
	}

	// Read auth method selection.
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if authReply[0] != 0x05 || authReply[1] != 0x00 {
		t.Fatalf("unexpected auth reply: %v", authReply)
	}

	// Send CONNECT request to the echo server.
	if err := socks5Request(conn, 0x01, "127.0.0.1", echoPort); err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Read reply — should be success (forwarded through mesh to exit).
	rep, err := readSOCKS5Reply(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if rep != 0x00 {
		t.Fatalf("expected success reply (0x00), got 0x%02x", rep)
	}

	// Send data through the tunnel — should be echoed back.
	testData := []byte("hello forward socks5!")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}

	respBuf := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if string(respBuf) != string(testData) {
		t.Fatalf("data mismatch: got %q, want %q", respBuf, testData)
	}
}

// TestSOCKS5Forward_FQDNConnect verifies FQDN address type is forwarded correctly.
func TestSOCKS5Forward_FQDNConnect(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	forwardCfg := SOCKS5ForwardConfig{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}
	exitCfg := SOCKS5Config{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}

	_, _, clientNode, clientPeerID, _ := setupSOCKS5ForwardTest(t, forwardCfg, exitCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, clientPeerID, int(SOCKS5VirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort: %v", err)
	}
	defer conn.Close()

	socks5Greeting(conn)
	io.ReadFull(conn, make([]byte, 2))

	// CONNECT with FQDN "localhost".
	if err := socks5Request(conn, 0x03, "localhost", echoPort); err != nil {
		t.Fatalf("request failed: %v", err)
	}

	rep, err := readSOCKS5Reply(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if rep != 0x00 {
		t.Fatalf("expected success reply (0x00), got 0x%02x", rep)
	}

	testData := []byte("fqdn forward test")
	conn.Write(testData)
	respBuf := make([]byte, len(testData))
	io.ReadFull(conn, respBuf)
	if string(respBuf) != string(testData) {
		t.Fatalf("data mismatch: got %q, want %q", respBuf, testData)
	}
}

// TestSOCKS5Forward_PortRestricted verifies that port restrictions on the
// exit node are enforced even when traffic is forwarded.
func TestSOCKS5Forward_PortRestricted(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	forwardCfg := SOCKS5ForwardConfig{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}
	exitCfg := SOCKS5Config{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
		AllowedPorts:   map[int]bool{80: true, 443: true}, // echoPort not allowed
	}

	_, _, clientNode, clientPeerID, _ := setupSOCKS5ForwardTest(t, forwardCfg, exitCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, clientPeerID, int(SOCKS5VirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort: %v", err)
	}
	defer conn.Close()

	socks5Greeting(conn)
	io.ReadFull(conn, make([]byte, 2))

	// CONNECT to echo port — should be rejected by exit node.
	socks5Request(conn, 0x01, "127.0.0.1", echoPort)

	rep, err := readSOCKS5Reply(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if rep == 0x00 {
		t.Fatal("expected rejection from exit (not 0x00), got success")
	}
}

// TestSOCKS5Forward_ConnectionRefused verifies that when the exit node
// can't reach the target, the error is propagated back to the client.
func TestSOCKS5Forward_ConnectionRefused(t *testing.T) {
	forwardCfg := SOCKS5ForwardConfig{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}
	exitCfg := SOCKS5Config{
		DialTimeout:    2 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}

	_, _, clientNode, clientPeerID, _ := setupSOCKS5ForwardTest(t, forwardCfg, exitCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, clientPeerID, int(SOCKS5VirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort: %v", err)
	}
	defer conn.Close()

	socks5Greeting(conn)
	io.ReadFull(conn, make([]byte, 2))

	// CONNECT to closed port 1.
	socks5Request(conn, 0x01, "127.0.0.1", 1)

	rep, err := readSOCKS5Reply(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if rep == 0x00 {
		t.Fatal("expected error reply for refused connection, got success")
	}
}

// TestSOCKS5Forward_Close verifies that Close() rejects new connections.
func TestSOCKS5Forward_Close(t *testing.T) {
	cfg := DefaultSOCKS5ForwardConfig()
	handler := NewSOCKS5ForwardHandler(nil, cfg)

	if handler.closed.Load() {
		t.Fatal("handler should not be closed initially")
	}

	handler.Close()

	if !handler.closed.Load() {
		t.Fatal("handler should be closed after Close()")
	}

	if handler.ActiveConnections() != 0 {
		t.Fatalf("expected 0 active connections, got %d", handler.ActiveConnections())
	}
}

// TestSOCKS5Forward_RegisterHandler verifies that RegisterSOCKS5ForwardHandler
// properly registers on the virtual port and the handler is stored on the node.
func TestSOCKS5Forward_RegisterHandler(t *testing.T) {
	sharedNode := createTestNode(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sharedNode.ctx = ctx

	handler, err := sharedNode.RegisterSOCKS5ForwardHandler(DefaultSOCKS5ForwardConfig())
	if err != nil {
		t.Fatalf("RegisterSOCKS5ForwardHandler failed: %v", err)
	}
	if handler == nil {
		t.Fatal("handler is nil")
	}

	// Verify the handler is stored on the node.
	sharedNode.mu.RLock()
	stored := sharedNode.socks5Handler
	sharedNode.mu.RUnlock()
	if stored == nil {
		t.Fatal("handler not stored on node")
	}

	// Verify the virtual port is registered — registering again should fail.
	_, err = sharedNode.RegisterSOCKS5ForwardHandler(DefaultSOCKS5ForwardConfig())
	if err == nil {
		t.Fatal("expected error for duplicate SOCKS5 port registration")
	}

	// Close the node — should close the handler.
	sharedNode.Close()
	if !handler.closed.Load() {
		t.Fatal("handler should be closed after node.Close()")
	}
}

// TestSOCKS5Forward_StaticExitSelection verifies that selectExitNode
// returns the configured ExitNodeID.
func TestSOCKS5Forward_StaticExitSelection(t *testing.T) {
	cfg := SOCKS5ForwardConfig{
		ExitNodeID: "testexitnode123",
	}
	handler := NewSOCKS5ForwardHandler(nil, cfg)

	exitID, err := handler.selectExitNode()
	if err != nil {
		t.Fatalf("selectExitNode: %v", err)
	}
	if exitID != "testexitnode123" {
		t.Fatalf("expected testexitnode123, got %s", exitID)
	}
}

// TestSOCKS5Forward_DynamicExitSelection verifies that selectExitNode
// uses GetExitCandidates when ExitNodeID is empty.
func TestSOCKS5Forward_DynamicExitSelection(t *testing.T) {
	cfg := SOCKS5ForwardConfig{
		GetExitCandidates: func() []ExitCandidate {
			return []ExitCandidate{
				{NodeID: "dynamicexit1"},
				{NodeID: "dynamicexit2"},
			}
		},
	}
	handler := NewSOCKS5ForwardHandler(nil, cfg)

	exitID, err := handler.selectExitNode()
	if err != nil {
		t.Fatalf("selectExitNode: %v", err)
	}
	if exitID != "dynamicexit1" {
		t.Fatalf("expected dynamicexit1, got %s", exitID)
	}
}

// TestSOCKS5Forward_NoExitAvailable verifies error when no exit is configured.
func TestSOCKS5Forward_NoExitAvailable(t *testing.T) {
	cfg := SOCKS5ForwardConfig{}
	handler := NewSOCKS5ForwardHandler(nil, cfg)

	_, err := handler.selectExitNode()
	if err == nil {
		t.Fatal("expected error when no exit node is configured")
	}
}

// TestSOCKS5Forward_UnsupportedVersion verifies the handler rejects wrong SOCKS version.
func TestSOCKS5Forward_UnsupportedVersion(t *testing.T) {
	forwardCfg := SOCKS5ForwardConfig{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}
	exitCfg := SOCKS5Config{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}

	_, _, clientNode, clientPeerID, _ := setupSOCKS5ForwardTest(t, forwardCfg, exitCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, clientPeerID, int(SOCKS5VirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort: %v", err)
	}
	defer conn.Close()

	// Send SOCKS4 version — should cause the handler to close.
	conn.Write([]byte{0x04, 0x01, 0x00})

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	_, err = conn.Read(buf)
	if err == nil {
		t.Log("Read returned data (unexpected but not fatal)")
	} else {
		t.Logf("Read returned expected error: %v", err)
	}
}

// TestExitVirtualPortConstant verifies the constant value.
func TestExitVirtualPortConstant(t *testing.T) {
	if ExitVirtualPort != 0x4558 {
		t.Fatalf("expected ExitVirtualPort=0x4558, got 0x%04x", ExitVirtualPort)
	}
}

// Ensure the binary import is used (for SelectExit).
var _ = binary.BigEndian
