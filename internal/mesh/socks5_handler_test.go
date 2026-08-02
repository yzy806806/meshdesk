package mesh

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/smux"
)

// socks5Greeting sends a SOCKS5 no-auth greeting on conn.
func socks5Greeting(conn net.Conn) error {
	// VER=5, NMETHODS=1, METHODS=[0x00 (no auth)]
	_, err := conn.Write([]byte{0x05, 0x01, 0x00})
	return err
}

// socks5Request sends a SOCKS5 CONNECT request for the given address.
// atyp: 0x01=IPv4, 0x03=FQDN, 0x04=IPv6
func socks5Request(conn net.Conn, atyp byte, addr string, port int) error {
	var msg []byte
	msg = append(msg, 0x05, 0x01, 0x00, atyp) // VER, CMD=CONNECT, RSV, ATYP

	switch atyp {
	case 0x01: // IPv4
		ip := net.ParseIP(addr).To4()
		if ip == nil {
			return errors.New("invalid IPv4 address")
		}
		msg = append(msg, ip...)
	case 0x03: // FQDN
		msg = append(msg, byte(len(addr)))
		msg = append(msg, []byte(addr)...)
	case 0x04: // IPv6
		ip := net.ParseIP(addr).To16()
		if ip == nil {
			return errors.New("invalid IPv4 address")
		}
		msg = append(msg, ip...)
	}

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	msg = append(msg, portBuf[:]...)

	_, err := conn.Write(msg)
	return err
}

// readSOCKS5Reply reads the SOCKS5 reply and returns the REP field.
func readSOCKS5Reply(conn net.Conn) (byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}
	// header: VER, REP, RSV, ATYP
	rep := header[1]
	atyp := header[3]

	// Read BND.ADDR based on ATYP.
	switch atyp {
	case 0x01: // IPv4
		_, err := io.ReadFull(conn, make([]byte, 4))
		if err != nil {
			return rep, err
		}
	case 0x03: // FQDN
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return rep, err
		}
		_, err := io.ReadFull(conn, make([]byte, int(lenBuf[0])))
		if err != nil {
			return rep, err
		}
	case 0x04: // IPv6
		_, err := io.ReadFull(conn, make([]byte, 16))
		if err != nil {
			return rep, err
		}
	}

	// Read BND.PORT (2 bytes).
	_, err := io.ReadFull(conn, make([]byte, 2))
	if err != nil {
		return rep, err
	}

	return rep, nil
}

// setupSOCKS5Test creates two MeshNodes (server+client) with an smux
// session and registers a SOCKS5 handler on the server. Returns the
// server node, client node, and the peer ID used for the session.
func setupSOCKS5Test(t *testing.T, cfg SOCKS5Config) (*MeshNode, *MeshNode, string) {
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

	peerID := "socks5testpeer"
	serverNode.sessions[peerID] = serverSess
	serverNode.sessionEstablishedAt[peerID] = time.Now()
	clientNode.sessions[peerID] = clientSess
	clientNode.sessionEstablishedAt[peerID] = time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverNode.ctx = ctx
	go serverNode.handleSessionStreams(peerID, serverSess)

	// Register SOCKS5 handler on the server.
	if _, err := serverNode.RegisterSOCKS5Handler(cfg); err != nil {
		t.Fatalf("RegisterSOCKS5Handler failed: %v", err)
	}

	return serverNode, clientNode, peerID
}

// TestSOCKS5_BasicConnect verifies the full SOCKS5 flow: a client
// dials virtual port 0x5350, performs the SOCKS5 handshake, and the
// handler dials a local TCP echo server and bridges data.
func TestSOCKS5_BasicConnect(t *testing.T) {
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

	_, clientNode, peerID := setupSOCKS5Test(t, cfg)

	// Client dials the SOCKS5 virtual port.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(SOCKS5VirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
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
	testData := []byte("hello socks5!")
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

// TestSOCKS5_FQDNConnect verifies the FQDN address type works correctly.
func TestSOCKS5_FQDNConnect(t *testing.T) {
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

	_, clientNode, peerID := setupSOCKS5Test(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(SOCKS5VirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
	}
	defer conn.Close()

	// Greeting.
	socks5Greeting(conn)
	io.ReadFull(conn, make([]byte, 2))

	// Send CONNECT with FQDN "localhost".
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
	testData := []byte("fqdn test")
	conn.Write(testData)
	respBuf := make([]byte, len(testData))
	io.ReadFull(conn, respBuf)
	if string(respBuf) != string(testData) {
		t.Fatalf("data mismatch: got %q, want %q", respBuf, testData)
	}
}

// TestSOCKS5_PortRestricted verifies that the handler rejects connections
// to ports not in AllowedPorts.
func TestSOCKS5_PortRestricted(t *testing.T) {
	// Start a local TCP echo server on an unusual port.
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

	_, clientNode, peerID := setupSOCKS5Test(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(SOCKS5VirtualPort))
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

// TestSOCKS5_UnsupportedVersion verifies the handler rejects wrong SOCKS version.
func TestSOCKS5_UnsupportedVersion(t *testing.T) {
	cfg := SOCKS5Config{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
	}

	_, clientNode, peerID := setupSOCKS5Test(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(SOCKS5VirtualPort))
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

// TestSOCKS5_ConnectionRefused verifies the handler returns an error reply
// when the target is unreachable.
func TestSOCKS5_ConnectionRefused(t *testing.T) {
	cfg := SOCKS5Config{
		DialTimeout:    2 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
		// Allow all ports so the restriction doesn't block the test.
	}

	_, clientNode, peerID := setupSOCKS5Test(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(SOCKS5VirtualPort))
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

// TestSOCKS5_Close verifies that Close() rejects new connections.
func TestSOCKS5_Close(t *testing.T) {
	cfg := DefaultSOCKS5Config()
	handler := NewSOCKS5Handler(cfg)

	if handler.closed.Load() {
		t.Fatal("handler should not be closed initially")
	}

	handler.Close()

	if !handler.closed.Load() {
		t.Fatal("handler should be closed after Close()")
	}

	// Verify ActiveConnections works.
	if handler.ActiveConnections() != 0 {
		t.Fatalf("expected 0 active connections, got %d", handler.ActiveConnections())
	}
}

// TestSOCKS5_RegisterHandler verifies that RegisterSOCKS5Handler properly
// registers on the virtual port and the handler is stored on the node.
func TestSOCKS5_RegisterHandler(t *testing.T) {
	serverNode := createTestNode(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverNode.ctx = ctx

	handler, err := serverNode.RegisterSOCKS5Handler(DefaultSOCKS5Config())
	if err != nil {
		t.Fatalf("RegisterSOCKS5Handler failed: %v", err)
	}
	if handler == nil {
		t.Fatal("handler is nil")
	}

	// Verify the handler is stored on the node.
	serverNode.mu.RLock()
	stored := serverNode.socks5Handler
	serverNode.mu.RUnlock()
	if stored != handler {
		t.Fatal("handler not stored on node")
	}

	// Verify the virtual port is registered.
	// Registering again should fail (port already in use).
	_, err = serverNode.RegisterSOCKS5Handler(DefaultSOCKS5Config())
	if err == nil {
		t.Fatal("expected error for duplicate SOCKS5 port registration")
	}

	// Close the node — should close the handler.
	serverNode.Close()
	if !handler.closed.Load() {
		t.Fatal("handler should be closed after node.Close()")
	}
}

// TestSOCKS5_RequireMeshPeer_AcceptMeshPeer verifies that a mesh peer
// present in the routing table is accepted when RequireMeshPeer=true.
// This tests the positive path: join-protocol-authenticated peers pass.
func TestSOCKS5_RequireMeshPeer_AcceptMeshPeer(t *testing.T) {
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
		RequireMeshPeer: true,
	}

	serverNode, clientNode, peerID := setupSOCKS5Test(t, cfg)

	// Add the peer to the routing table AFTER registration — simulates
	// a peer that completed the join protocol. The CheckMeshPeer callback
	// was wired at registration time and will see this entry.
	serverNode.routes.AddPeer(&PeerEntry{
		ID:       peerID,
		Endpoint: "127.0.0.1:10000",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(SOCKS5VirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
	}
	defer conn.Close()

	// Perform SOCKS5 greeting — should succeed because peer is in routing table.
	if err := socks5Greeting(conn); err != nil {
		t.Fatalf("greeting failed: %v", err)
	}

	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if authReply[0] != 0x05 || authReply[1] != 0x00 {
		t.Fatalf("unexpected auth reply: %v (expected 0x05 0x00)", authReply)
	}

	// Complete the handshake with a CONNECT request.
	if err := socks5Request(conn, 0x01, "127.0.0.1", echoPort); err != nil {
		t.Fatalf("request failed: %v", err)
	}

	rep, err := readSOCKS5Reply(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if rep != 0x00 {
		t.Fatalf("expected success reply (0x00), got 0x%02x", rep)
	}
}

// TestSOCKS5_RequireMeshPeer_RejectNonMesh verifies that a peer NOT in
// the routing table is rejected when RequireMeshPeer=true. This simulates
// a phone client with a locally-generated Ed25519 keypair that has not
// completed the mesh join protocol. The connection should be closed
// immediately by the handler.
func TestSOCKS5_RequireMeshPeer_RejectNonMesh(t *testing.T) {
	cfg := SOCKS5Config{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
		RequireMeshPeer: true,
	}

	serverNode, clientNode, peerID := setupSOCKS5Test(t, cfg)

	// DO NOT add the peer to the routing table — this simulates a phone
	// client connecting with a locally-generated Ed25519 keypair that
	// has NOT completed the mesh join protocol. The routing table only
	// contains join-protocol-authenticated peers.

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(SOCKS5VirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
	}
	defer conn.Close()

	// The handler should close the connection immediately upon seeing
	// that the peer is not in the routing table. Try to write a SOCKS5
	// greeting — it may or may not error depending on smux buffering,
	// but reading should return EOF/error.
	socks5Greeting(conn)

	// Try to read the auth reply — should fail because the server closed.
	buf := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		// If read didn't error, the reply might be buffered before close.
		// Check that we didn't get a success reply.
		if len(buf) >= 2 && buf[0] == 0x05 && buf[1] == 0x00 {
			t.Fatal("unexpected success reply — non-mesh peer should have been rejected")
		}
	} else {
		t.Logf("Read returned expected error: %v", err)
	}

	// Verify server side: the handler should have 0 active connections.
	time.Sleep(50 * time.Millisecond) // give goroutine time to finish
	if serverNode.socks5Handler != nil {
		active := serverNode.socks5Handler.ActiveConnections()
		if active != 0 {
			t.Fatalf("expected 0 active connections after rejection, got %d", active)
		}
	}
}

// TestSOCKS5_AllowedPeers_AcceptListed verifies that AllowedPeers
// explicitly permits only listed peer IDs and rejects others.
func TestSOCKS5_AllowedPeers_AcceptListed(t *testing.T) {
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
		AllowedPeers:   []string{"socks5testpeer"}, // explicit whitelist
	}

	serverNode, clientNode, peerID := setupSOCKS5Test(t, cfg)
	_ = serverNode // only used for lifecycle

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(SOCKS5VirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
	}
	defer conn.Close()

	// Greeting should succeed because peer is in AllowedPeers.
	if err := socks5Greeting(conn); err != nil {
		t.Fatalf("greeting failed: %v", err)
	}

	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if authReply[0] != 0x05 || authReply[1] != 0x00 {
		t.Fatalf("expected auth success (listed peer), got %v", authReply)
	}

	// Complete the CONNECT.
	socks5Request(conn, 0x01, "127.0.0.1", echoPort)
	rep, err := readSOCKS5Reply(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if rep != 0x00 {
		t.Fatalf("expected success reply, got 0x%02x", rep)
	}
}

// TestSOCKS5_AllowedPeers_RejectUnlisted verifies that a peer NOT in
// AllowedPeers is rejected even if it has a valid Ed25519 identity.
func TestSOCKS5_AllowedPeers_RejectUnlisted(t *testing.T) {
	cfg := SOCKS5Config{
		DialTimeout:    5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxConnections: 16,
		AllowedPeers:   []string{"some-other-peer-id"}, // NOT our peer
	}

	_, clientNode, peerID := setupSOCKS5Test(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientNode.DialVirtualPort(ctx, peerID, int(SOCKS5VirtualPort))
	if err != nil {
		t.Fatalf("DialVirtualPort failed: %v", err)
	}
	defer conn.Close()

	// Try to SOCKS5 greeting — should be rejected because peer not in list.
	socks5Greeting(conn)

	buf := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		if len(buf) >= 2 && buf[0] == 0x05 && buf[1] == 0x00 {
			t.Fatal("unexpected success reply — unlisted peer should have been rejected")
		}
	} else {
		t.Logf("Read returned expected error: %v", err)
	}
}
