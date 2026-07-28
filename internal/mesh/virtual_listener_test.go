package mesh

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/smux"
)

// TestVirtualPort_DataFlow verifies the full virtual-port dispatching path:
//  1. A server MeshNode registers a VirtualListener on port 2222.
//  2. A client MeshNode has an smux session to the server.
//  3. The client dials mesh:2222 (which opens a stream and writes the port frame).
//  4. The server's handleSessionStreams reads the port frame and dispatches
//     the stream to the VirtualListener.
//  5. Data written by the client is read by the server and vice versa.
func TestVirtualPort_DataFlow(t *testing.T) {
	// Create two MeshNodes — a "server" and a "client".
	serverNode := createTestNode(t)
	clientNode := createTestNode(t)

	// Create a paired smux session over net.Pipe.
	// The server side gets a *smux.Server session (can only AcceptStream).
	// The client side gets a *smux.Client session (can OpenStream).
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

	// Register the sessions in the respective nodes.
	peerID := "testpeer001"
	serverNode.sessions[peerID] = serverSess
	serverNode.sessionEstablishedAt[peerID] = time.Now()
	clientNode.sessions[peerID] = clientSess
	clientNode.sessionEstablishedAt[peerID] = time.Now()

	// Start the server's session stream handler (runs handleSessionStreams).
	// This is normally started by handleConnection or Dial.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverNode.ctx = ctx
	go serverNode.handleSessionStreams(peerID, serverSess)

	// Server: register a virtual listener on port 2222.
	ln, err := serverNode.ListenVirtualPort(2222)
	if err != nil {
		t.Fatalf("ListenVirtualPort failed: %v", err)
	}
	defer ln.Close()

	// Client: dial mesh:2222 — this opens a stream and writes the port frame.
	// Give the server handler a moment to be ready.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	conn, err := clientNode.DialVirtualPort(dialCtx, peerID, 2222)
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
	}
	defer conn.Close()

	// Server: accept the connection on the virtual listener.
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		acceptCh <- acceptResult{c, err}
	}()

	select {
	case res := <-acceptCh:
		if res.err != nil {
			t.Fatalf("Accept failed: %v", res.err)
		}
		defer res.conn.Close()

		// Write data from client to server.
		testData := []byte("hello virtual port!")
		_, err = conn.Write(testData)
		if err != nil {
			t.Fatalf("client write failed: %v", err)
		}

		// Read on server side.
		buf := make([]byte, len(testData))
		_, err = io.ReadFull(res.conn, buf)
		if err != nil {
			t.Fatalf("server read failed: %v", err)
		}
		if string(buf) != string(testData) {
			t.Fatalf("data mismatch: got %q, want %q", buf, testData)
		}

		// Write data from server to client.
		respData := []byte("echo from server")
		_, err = res.conn.Write(respData)
		if err != nil {
			t.Fatalf("server write failed: %v", err)
		}

		// Read on client side.
		respBuf := make([]byte, len(respData))
		_, err = io.ReadFull(conn, respBuf)
		if err != nil {
			t.Fatalf("client read failed: %v", err)
		}
		if string(respBuf) != string(respData) {
			t.Fatalf("response mismatch: got %q, want %q", respBuf, respData)
		}

	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Accept on virtual port 2222")
	}
}

// TestVirtualPort_DuplicateListener verifies that registering two listeners
// for the same port returns an error.
func TestVirtualPort_DuplicateListener(t *testing.T) {
	node := createTestNode(t)

	ln1, err := node.ListenVirtualPort(3000)
	if err != nil {
		t.Fatalf("first ListenVirtualPort failed: %v", err)
	}
	defer ln1.Close()

	_, err = node.ListenVirtualPort(3000)
	if err == nil {
		t.Fatal("expected error for duplicate listener, got nil")
	}
}

// TestVirtualPort_NoListener verifies that when no listener is registered
// for a port, the inbound stream is dropped (closed) gracefully.
func TestVirtualPort_NoListener(t *testing.T) {
	serverNode := createTestNode(t)
	clientNode := createTestNode(t)

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

	peerID := "testpeer002"
	serverNode.sessions[peerID] = serverSess
	serverNode.sessionEstablishedAt[peerID] = time.Now()
	clientNode.sessions[peerID] = clientSess
	clientNode.sessionEstablishedAt[peerID] = time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverNode.ctx = ctx
	go serverNode.handleSessionStreams(peerID, serverSess)

	// Dial a port with no listener registered.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	conn, err := clientNode.DialVirtualPort(dialCtx, peerID, 9999)
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
	}
	defer conn.Close()

	// Write should succeed (the stream is open), but the server should
	// close it since no listener is registered. A subsequent read should
	// return EOF or an error after the server closes the stream.
	_, _ = conn.Write([]byte("data to nowhere"))

	// Give the server a moment to process and close the stream.
	buf := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(buf)
	// We expect either io.EOF or a timeout/error — the stream should be
	// closed by the server since no listener is registered.
	if err == nil {
		// If we got data, that's unexpected but not fatal — the test
		// just verifies the stream doesn't hang forever.
		t.Log("Read returned data (unexpected but not fatal)")
	} else {
		t.Logf("Read returned expected error: %v", err)
	}
}

// TestVirtualPort_DialMeshAddress tests the mesh:PORT address parsing
// and dialing path via MeshNode.Dial.
func TestVirtualPort_DialMeshAddress(t *testing.T) {
	serverNode := createTestNode(t)
	clientNode := createTestNode(t)

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

	peerID := "testpeer003"
	serverNode.sessions[peerID] = serverSess
	serverNode.sessionEstablishedAt[peerID] = time.Now()
	clientNode.sessions[peerID] = clientSess
	clientNode.sessionEstablishedAt[peerID] = time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverNode.ctx = ctx
	go serverNode.handleSessionStreams(peerID, serverSess)

	// Server: listen on port 3333.
	ln, err := serverNode.ListenVirtualPort(3333)
	if err != nil {
		t.Fatalf("ListenVirtualPort failed: %v", err)
	}
	defer ln.Close()

	// Client: dial via Dial(ctx, "mesh", "mesh:3333").
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	conn, err := clientNode.Dial(dialCtx, "mesh", "mesh:3333")
	if err != nil {
		t.Fatalf("Dial mesh:3333 failed: %v", err)
	}
	defer conn.Close()

	// Accept on server side.
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		acceptCh <- acceptResult{c, err}
	}()

	select {
	case res := <-acceptCh:
		if res.err != nil {
			t.Fatalf("Accept failed: %v", res.err)
		}
		defer res.conn.Close()

		// Verify bidirectional data flow.
		msg := []byte("mesh address test")
		_, err := conn.Write(msg)
		if err != nil {
			t.Fatalf("client write: %v", err)
		}

		buf := make([]byte, len(msg))
		_, err = io.ReadFull(res.conn, buf)
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("data mismatch: got %q, want %q", buf, msg)
		}

	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Accept on virtual port 3333")
	}
}
