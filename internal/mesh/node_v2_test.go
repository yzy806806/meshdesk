package mesh

import (
	"net"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/smux"
)

// createTestNode creates a MeshNode suitable for testing session management.
func createTestNode(t *testing.T) *MeshNode {
	t.Helper()
	cfg := &config.Config{}
	node := &MeshNode{
		cfg:                  cfg,
		routes:               NewRoutingTable(),
		sessions:             make(map[string]*smux.Session),
		sessionEstablishedAt: make(map[string]time.Time),
		peerManagers:         make(map[string]*PeerManager),
	}
	return node
}

// newSmuxServerSession creates a connected smux server session by pairing
// a client and server over net.Pipe(). The client session is returned too
// so the test can close it on cleanup.
func newSmuxServerSession(t *testing.T) (*smux.Session, *smux.Session) {
	t.Helper()
	cPipe, sPipe := net.Pipe()

	cfg := smux.DefaultConfig()
	cfg.HandshakeTimeout = 5 * time.Second

	errCh := make(chan error, 2)
	var client *smux.Session
	var server *smux.Session

	go func() {
		c, e := smux.Client(cPipe, cfg)
		client = c
		errCh <- e
	}()

	go func() {
		s, e := smux.Server(sPipe, cfg)
		server = s
		errCh <- e
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("smux setup error: %v", err)
		}
	}

	if client == nil || server == nil {
		t.Fatal("smux setup returned nil session")
	}
	return server, client
}

func TestRemovePeer_NoSession(t *testing.T) {
	node := createTestNode(t)
	peerKey := "abc123"

	// Add to routing table first.
	node.routes.AddPeer(&PeerEntry{ID: peerKey, Endpoint: "1.2.3.4:443"})

	// RemovePeer should not panic even without a session.
	err := node.RemovePeer(peerKey)
	if err != nil {
		t.Fatalf("RemovePeer failed: %v", err)
	}

	// Peer should be removed from routing table.
	if _, ok := node.routes.GetPeer(peerKey); ok {
		t.Fatal("peer should be removed from routing table")
	}
}

func TestRemovePeer_WithSession(t *testing.T) {
	node := createTestNode(t)
	peerKey := "deadbeef"

	// Create a connected smux server session.
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	// Manually insert session into node.
	node.sessions[peerKey] = sess
	node.sessionEstablishedAt[peerKey] = time.Now()
	node.routes.AddPeer(&PeerEntry{ID: peerKey, Endpoint: "1.2.3.4:443"})

	// RemovePeer should close the session and clean up.
	err := node.RemovePeer(peerKey)
	if err != nil {
		t.Fatalf("RemovePeer failed: %v", err)
	}

	// Session should be removed from map.
	if _, ok := node.sessions[peerKey]; ok {
		t.Fatal("session should be removed from sessions map")
	}

	// sessionEstablishedAt should be cleaned up.
	if _, ok := node.sessionEstablishedAt[peerKey]; ok {
		t.Fatal("sessionEstablishedAt should be cleaned up")
	}

	// Session should be closed.
	if !sess.IsClosed() {
		t.Fatal("smux session should be closed")
	}

	// Peer should be removed from routing table.
	if _, ok := node.routes.GetPeer(peerKey); ok {
		t.Fatal("peer should be removed from routing table")
	}
}

func TestRemovePeer_Idempotent(t *testing.T) {
	node := createTestNode(t)
	peerKey := "abc123"

	// RemovePeer on a non-existent peer should not error.
	err := node.RemovePeer(peerKey)
	if err != nil {
		t.Fatalf("first RemovePeer failed: %v", err)
	}

	// Second call should also succeed.
	err = node.RemovePeer(peerKey)
	if err != nil {
		t.Fatalf("second RemovePeer failed: %v", err)
	}
}

func TestGetPeerHandshakeInfo_NoSession(t *testing.T) {
	node := createTestNode(t)
	info := node.GetPeerHandshakeInfo("nonexistent")
	if info != nil {
		t.Fatal("GetPeerHandshakeInfo should return nil for non-existent peer")
	}
}

func TestGetPeerHandshakeInfo_WithSession(t *testing.T) {
	node := createTestNode(t)
	peerKey := "cafebabe"

	// Create a connected smux server session.
	sess, client := newSmuxServerSession(t)
	defer client.Close()
	defer sess.Close()

	// Manually insert.
	node.sessions[peerKey] = sess
	node.sessionEstablishedAt[peerKey] = time.Now()

	info := node.GetPeerHandshakeInfo(peerKey)
	if info == nil {
		t.Fatal("GetPeerHandshakeInfo should return non-nil for peer with session")
	}

	if info.PublicKey != peerKey {
		t.Errorf("PublicKey = %q, want %q", info.PublicKey, peerKey)
	}

	if info.LastHandshakeTime.IsZero() {
		t.Fatal("LastHandshakeTime should not be zero")
	}

	if info.LastHandshakeNano == 0 {
		t.Fatal("LastHandshakeNano should not be zero")
	}
}

func TestGetPeerHandshakeInfo_ClosedSession(t *testing.T) {
	node := createTestNode(t)
	peerKey := "closedkey"

	// Create and immediately close a session.
	sess, client := newSmuxServerSession(t)
	client.Close()
	sess.Close()

	node.sessions[peerKey] = sess
	node.sessionEstablishedAt[peerKey] = time.Now()

	// Should return nil because session is closed.
	info := node.GetPeerHandshakeInfo(peerKey)
	if info != nil {
		t.Fatal("GetPeerHandshakeInfo should return nil for closed session")
	}
}
