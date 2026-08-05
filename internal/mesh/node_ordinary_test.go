package mesh

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
)

// TestStart_OrdinaryNodeCreatesTCPListener verifies that an ordinary
// node (P2P enabled, Reality disabled) creates a TCP listener on the
// gossip port. This is required for memberlist push/pull sync —
// without it, other nodes cannot initiate TCP state sync and mark
// this node as failed within seconds.
func TestStart_OrdinaryNodeCreatesTCPListener(t *testing.T) {
	// Find a free port for the gossip port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := &config.Config{
		Node: config.NodeConfig{
			IdentityFile: t.TempDir() + "/identity.pem",
		},
		Mesh: config.MeshConfig{
			GossipPort: port,
		},
		P2P: config.P2pConfig{
			Enabled: true,
		},
		// Reality intentionally NOT enabled → ordinary node mode
	}

	node, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer node.Close()

	if err := node.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Verify the MuxTransport has a TCP listener by checking that
	// we can dial the gossip port.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Fatalf("could not connect to ordinary node TCP listener on port %d: %v", port, err)
	}
	conn.Close()

	// Verify muxTransport is non-nil.
	node.mu.RLock()
	mt := node.muxTransport
	node.mu.RUnlock()
	if mt == nil {
		t.Fatal("muxTransport is nil for ordinary node")
	}
}

// TestStart_OrdinaryNodeMemberlistStreamCh verifies that memberlist
// TCP traffic (non-TLS, non-0x4D) is delivered to the MuxTransport's
// StreamCh, which is what memberlist reads from for push/pull sync.
func TestStart_OrdinaryNodeMemberlistStreamCh(t *testing.T) {
	// Find a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := &config.Config{
		Node: config.NodeConfig{
			IdentityFile: t.TempDir() + "/identity.pem",
		},
		Mesh: config.MeshConfig{
			GossipPort: port,
		},
		P2P: config.P2pConfig{
			Enabled: true,
		},
	}

	node, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer node.Close()

	if err := node.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	node.mu.RLock()
	mt := node.muxTransport
	node.mu.RUnlock()
	if mt == nil {
		t.Fatal("muxTransport is nil")
	}

	// Dial the TCP listener and send a non-TLS, non-0x4D byte.
	// memberlist message types are 0–13 or 244, so 0x01 is a valid
	// memberlist ping type that should be routed to StreamCh.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a memberlist-style byte (0x01 = ping).
	_, err = conn.Write([]byte{0x01})
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// The MuxTransport should deliver the connection to StreamCh.
	select {
	case streamConn := <-mt.StreamCh():
		// Verify the peeked byte is replayed.
		buf := make([]byte, 1)
		n, err := streamConn.Read(buf)
		if err != nil || n != 1 {
			t.Fatalf("read replayed byte: n=%d err=%v", n, err)
		}
		if buf[0] != 0x01 {
			t.Fatalf("expected replayed byte 0x01, got 0x%02x", buf[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for connection on StreamCh")
	}
}
