package mesh

import (
	"testing"
	"time"
)

// TestHasActiveSession_AliveSession tests that HasActiveSession returns true
// when a peer has a live smux session.
func TestHasActiveSession_AliveSession(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	node.sessionsMu.Lock()
	node.sessions[peerKey] = sess
	node.sessionsMu.Unlock()

	if !node.HasActiveSession(peerKey) {
		t.Error("HasActiveSession should return true for a live session")
	}
}

// TestHasActiveSession_NoSession tests that HasActiveSession returns false
// when no session exists for the peer.
func TestHasActiveSession_NoSession(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if node.HasActiveSession(peerKey) {
		t.Error("HasActiveSession should return false when no session exists")
	}
}

// TestHasActiveSession_ClosedSession tests that HasActiveSession returns false
// when the session exists but is closed.
func TestHasActiveSession_ClosedSession(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	node.sessionsMu.Lock()
	node.sessions[peerKey] = sess
	node.sessionsMu.Unlock()

	// Close the session
	sess.Close()

	// Give it a moment to register as closed
	time.Sleep(100 * time.Millisecond)

	if node.HasActiveSession(peerKey) {
		t.Error("HasActiveSession should return false for a closed session")
	}
}

// TestHasActiveSession_ClientSession tests that HasActiveSession returns true
// when the peer has a live client (outbound) session.
func TestHasActiveSession_ClientSession(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	node.sessionsMu.Lock()
	node.clientSessions[peerKey] = sess
	node.sessionsMu.Unlock()

	if !node.HasActiveSession(peerKey) {
		t.Error("HasActiveSession should return true for a live client session")
	}
}

// TestSessionDeathHandler_FiresOnSessionClose tests that the session death
// handler is called when a session dies (detected by the reconnect watcher).
func TestSessionDeathHandler_FiresOnSessionClose(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef"
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	node.sessions[peerKey] = sess
	node.sessionEstablishedAt[peerKey] = time.Now()
	node.routes.AddPeer(&PeerEntry{ID: peerKey, Endpoint: "127.0.0.1:9999"})

	// Set up the death handler.
	deathCalled := make(chan string, 1)
	node.SetSessionDeathHandler(func(pk string) {
		deathCalled <- pk
	})

	// Start the watcher.
	node.startSessionWatcher(peerKey, "127.0.0.1:9999", true)
	time.Sleep(100 * time.Millisecond)

	// Close the session to trigger the death handler.
	sess.Close()

	select {
	case pk := <-deathCalled:
		if pk != peerKey {
			t.Errorf("death handler called with %q, want %q", pk, peerKey)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session death handler was not called within 2s")
	}

	node.stopReconnectWatcher(peerKey)
}

// TestGetSession_PrefersClientSession tests that GetSession returns the client
// (outbound) session when both a server and client session exist.
func TestGetSession_PrefersClientSession(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	sess1, client1 := newSmuxServerSession(t)
	defer client1.Close()
	sess2, client2 := newSmuxServerSession(t)
	defer client2.Close()

	node.sessionsMu.Lock()
	node.sessions[peerKey] = sess1       // server session
	node.clientSessions[peerKey] = sess2 // client session
	node.sessionsMu.Unlock()

	got := node.GetSession(peerKey)
	if got != sess2 {
		t.Error("GetSession should prefer client session over server session")
	}
}
