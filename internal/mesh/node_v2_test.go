package mesh

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/identity"
	"github.com/yzy806806/meshdesk/internal/smux"
)

// createTestNode creates a MeshNode suitable for testing session management.
func createTestNode(t *testing.T) *MeshNode {
	t.Helper()
	cfg := &config.Config{}
	ctx, cancel := context.WithCancel(context.Background())
	node := &MeshNode{
		cfg:                  cfg,
		routes:               NewRoutingTable(),
		sessions:             make(map[string]*smux.Session),
		sessionEstablishedAt: make(map[string]time.Time),
		peerManagers:         make(map[string]*PeerManager),
		clientSessions:       make(map[string]*smux.Session),
		portMux:              newVirtualPortMux(),
		reconnectState:       make(map[string]*reconnectTracker),
		ctx:                  ctx,
		cancel:               cancel,
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

// TestIdentityPersistenceSurvivesRestart verifies that an Ed25519 identity
// survives a save/load round-trip through PEM encoding:
//  1. Generate a new Ed25519 keypair.
//  2. Write it to a PEM file via saveIdentityPEM.
//  3. Reload it via identity.IdentityFromPEM (simulating a process restart).
//  4. Verify the public key matches (the identity is intact).
//
// This is the contract that guarantees a node restarts with the same identity.
func TestIdentityPersistenceSurvivesRestart(t *testing.T) {
	// Generate a fresh identity.
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	// Save to a temp PEM file, simulating first-run persistence.
	tmpDir := t.TempDir()
	pemPath := filepath.Join(tmpDir, "identity.pem")
	if err := saveIdentityPEM(pemPath, id); err != nil {
		t.Fatalf("saveIdentityPEM() error: %v", err)
	}

	// Simulate restart: read the PEM file back.
	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", pemPath, err)
	}

	restored, err := identity.IdentityFromPEM(pemData)
	if err != nil {
		t.Fatalf("IdentityFromPEM() error: %v", err)
	}

	// The public key must match — this is the identity invariant.
	if restored.PublicKey != id.PublicKey {
		t.Errorf("PublicKey mismatch after restart: got %s, want %s", restored.PublicKey, id.PublicKey)
	}

	// The private key must also match (same key material).
	if restored.PrivateKey != id.PrivateKey {
		t.Errorf("PrivateKey mismatch after restart: got %s, want %s", restored.PrivateKey, id.PrivateKey)
	}

	// Verify the restored identity can still sign and verify.
	msg := []byte("persistence test message")
	sig, err := restored.Sign(msg)
	if err != nil {
		t.Fatalf("Sign() after restart error: %v", err)
	}
	if !identity.Verify(restored.PublicKey, msg, sig) {
		t.Error("Verify() failed after restart — restored identity is broken")
	}
}