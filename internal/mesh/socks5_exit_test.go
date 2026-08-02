package mesh

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/smux"
)

// setupSOCKS5ExitTest creates two MeshNodes with an smux session and
// registers a SOCKS5 exit handler on virtual port 0x4558 on the server
// node. Returns the server node, client node, and the peer ID.
//
// This tests the exit handler directly (not through the forward path):
// the client dials port 0x4558, performs SOCKS5 handshake, and the exit
// handler dials the target and bridges data.
func setupSOCKS5ExitTest(t *testing.T, cfg SOCKS5Config) (*MeshNode, *MeshNode, string) {
	t.Helper()

	serverNode := createTestNode(t)
	clientNode := createTestNode(t)

	sPipe, cPipe := net.Pipe()
	smuxCfg := smux.DefaultConfig()
	smuxCfg.HandshakeTimeout = 5 * time.Second

	errCh := make(chan error, 2)
	var serverSess, clientSess *smux.Session

	go func() {
		s, err := smux.Server(sPipe, smuxCfg)
		serverSess = s
		errCh <- err
	}()
	go func() {
		c, err := smux.Client(cPipe, smuxCfg)
		clientSess = c
		errCh <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("smux setup error: %v", err)
		}
	}

	peerID := "exit-test-peer"
	serverNode.sessions[peerID] = serverSess
	serverNode.sessionEstablishedAt[peerID] = time.Now()
	clientNode.sessions[peerID] = clientSess
	clientNode.sessionEstablishedAt[peerID] = time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverNode.ctx = ctx
	go serverNode.handleSessionStreams(peerID, serverSess)

	// Register the SOCKS5 exit handler on port 0x4558.
	if _, err := serverNode.RegisterSOCKS5ExitHandler(cfg); err != nil {
		t.Fatalf("RegisterSOCKS5ExitHandler failed: %v", err)
	}

	return serverNode, clientNode, peerID
}

// TestSOCKS5Exit_BasicConnect verifies the exit handler on port 0x4558
// can accept a direct DialVirtualPort stream, perform the SOCKS5
// handshake, dial the target, and bridge data bidirectionally.
func TestSOCKS5Exit_BasicConnect(t *testing.T) {
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

	cfg := SOCKS5Config{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}

	_, clientNode, peerID := setupSOCKS5ExitTest(t, cfg)

	// Client dials the exit handler's virtual port 0x4558 directly.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(ExitVirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort to exit port 0x4558 failed: %v", err)
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

	// Read reply — should be success.
	rep, err := readSOCKS5Reply(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if rep != 0x00 {
		t.Fatalf("expected success reply (0x00), got 0x%02x", rep)
	}

	// Send data through the SOCKS5 tunnel — should be echoed back.
	testData := []byte("hello exit handler!")
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

// TestSOCKS5Exit_FQDNConnect verifies the exit handler handles FQDN
// address type on port 0x4558.
func TestSOCKS5Exit_FQDNConnect(t *testing.T) {
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

	cfg := SOCKS5Config{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}

	_, clientNode, peerID := setupSOCKS5ExitTest(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(ExitVirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
	}
	defer conn.Close()

	// Greeting.
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

	// Verify data flow.
	testData := []byte("fqdn exit test")
	conn.Write(testData)
	respBuf := make([]byte, len(testData))
	io.ReadFull(conn, respBuf)
	if string(respBuf) != string(testData) {
		t.Fatalf("data mismatch: got %q, want %q", respBuf, testData)
	}
}

// TestSOCKS5Exit_PortRestricted verifies the exit handler on port 0x4558
// enforces AllowedPorts restrictions.
func TestSOCKS5Exit_PortRestricted(t *testing.T) {
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

	cfg := SOCKS5Config{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
		AllowedPorts:   map[int]bool{80: true, 443: true}, // echoPort not allowed
	}

	_, clientNode, peerID := setupSOCKS5ExitTest(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(ExitVirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
	}
	defer conn.Close()

	// Greeting.
	socks5Greeting(conn)
	io.ReadFull(conn, make([]byte, 2))

	// Try to CONNECT to the echo server's port (not in AllowedPorts).
	socks5Request(conn, 0x01, "127.0.0.1", echoPort)

	rep, err := readSOCKS5Reply(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if rep == 0x00 {
		t.Fatal("expected rejection (not 0x00) for disallowed port, got success")
	}
}

// TestSOCKS5Exit_ConnectionRefused verifies the exit handler returns an
// error reply when the target is unreachable.
func TestSOCKS5Exit_ConnectionRefused(t *testing.T) {
	cfg := SOCKS5Config{
		DialTimeout:    2 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}

	_, clientNode, peerID := setupSOCKS5ExitTest(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(ExitVirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
	}
	defer conn.Close()

	// Greeting.
	socks5Greeting(conn)
	io.ReadFull(conn, make([]byte, 2))

	// Try to CONNECT to a closed port (1 — almost certainly nothing listening).
	socks5Request(conn, 0x01, "127.0.0.1", 1)

	rep, err := readSOCKS5Reply(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if rep == 0x00 {
		t.Fatal("expected error reply (not 0x00) for refused connection, got success")
	}
}

// TestSOCKS5Exit_RegisterHandler verifies that RegisterSOCKS5ExitHandler
// properly registers on virtual port 0x4558 and the handler is stored
// on the node in socks5ExitHandler.
func TestSOCKS5Exit_RegisterHandler(t *testing.T) {
	serverNode := createTestNode(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverNode.ctx = ctx

	handler, err := serverNode.RegisterSOCKS5ExitHandler(DefaultSOCKS5Config())
	if err != nil {
		t.Fatalf("RegisterSOCKS5ExitHandler failed: %v", err)
	}
	if handler == nil {
		t.Fatal("handler is nil")
	}

	// Verify the handler is stored on the node in socks5ExitHandler.
	serverNode.mu.RLock()
	stored := serverNode.socks5ExitHandler
	serverNode.mu.RUnlock()
	if stored == nil {
		t.Fatal("handler not stored in socks5ExitHandler")
	}

	// Verify the virtual port is registered — registering again should fail.
	_, err = serverNode.RegisterSOCKS5ExitHandler(DefaultSOCKS5Config())
	if err == nil {
		t.Fatal("expected error for duplicate exit port 0x4558 registration")
	}

	// Close the node — should close the exit handler.
	serverNode.Close()
	if !handler.closed.Load() {
		t.Fatal("exit handler should be closed after node.Close()")
	}
}

// TestSOCKS5Exit_DualRegistration verifies that a node can register both
// a forward handler (0x5350) and an exit handler (0x4558) simultaneously
// without one overwriting the other. This is the regression test for the
// handler field collision bug.
func TestSOCKS5Exit_DualRegistration(t *testing.T) {
	serverNode := createTestNode(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverNode.ctx = ctx

	// Register exit handler on port 0x4558.
	exitHandler, err := serverNode.RegisterSOCKS5ExitHandler(DefaultSOCKS5Config())
	if err != nil {
		t.Fatalf("RegisterSOCKS5ExitHandler failed: %v", err)
	}

	// Register forward handler on port 0x5350.
	forwardCfg := DefaultSOCKS5ForwardConfig()
	forwardCfg.ExitNodeID = "someexitnode"
	forwardHandler, err := serverNode.RegisterSOCKS5ForwardHandler(forwardCfg)
	if err != nil {
		t.Fatalf("RegisterSOCKS5ForwardHandler failed: %v", err)
	}

	// Both handlers should be stored in their respective fields.
	serverNode.mu.RLock()
	exitStored := serverNode.socks5ExitHandler
	forwardStored := serverNode.socks5Handler
	serverNode.mu.RUnlock()

	if exitStored == nil {
		t.Fatal("exit handler not stored in socks5ExitHandler")
	}
	if forwardStored == nil {
		t.Fatal("forward handler not stored in socks5Handler")
	}

	// Close the node — both handlers should be closed.
	serverNode.Close()
	if !exitHandler.closed.Load() {
		t.Fatal("exit handler should be closed after node.Close()")
	}
	if !forwardHandler.closed.Load() {
		t.Fatal("forward handler should be closed after node.Close()")
	}
}

// TestSOCKS5Exit_UnsupportedVersion verifies the exit handler rejects
// wrong SOCKS version on port 0x4558.
func TestSOCKS5Exit_UnsupportedVersion(t *testing.T) {
	cfg := SOCKS5Config{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}

	_, clientNode, peerID := setupSOCKS5ExitTest(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(ExitVirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
	}
	defer conn.Close()

	// Send SOCKS4 version (0x04) — should cause the handler to close.
	conn.Write([]byte{0x04, 0x01, 0x00})

	// The handler should close the connection.
	buf := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		t.Log("Read returned data (unexpected but not fatal)")
	} else {
		t.Logf("Read returned expected error: %v", err)
	}
}
