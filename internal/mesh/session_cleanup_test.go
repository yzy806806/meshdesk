package mesh

import (
	"context"
	"testing"
	"time"
)

// TestRemovePeer_CleansUpClientSessions verifies that RemovePeer removes
// the peer's client session from the clientSessions map, not just the
// sessions map. This was the root cause of scenario 3's metrics failover
// failure: after killing the relay node, the dead client session to the
// remaining collector (via the relay) stayed in clientSessions, causing
// DialVirtualPort to find it and fail with ErrSessionClosed.
func TestRemovePeer_CleansUpClientSessions(t *testing.T) {
	node := createTestNode(t)
	peerKey := "deadbeef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef"

	// Create a dead session and put it in both maps.
	serverSess, clientSess := newSmuxServerSession(t)
	defer serverSess.Close()
	defer clientSess.Close()

	node.sessionsMu.Lock()
	node.sessions[peerKey] = serverSess
	node.clientSessions[peerKey] = clientSess
	node.sessionEstablishedAt[peerKey] = time.Now()
	node.sessionsMu.Unlock()

	// Close both sessions to simulate a dead peer.
	serverSess.Close()
	clientSess.Close()

	// RemovePeer should clean up both maps.
	err := node.RemovePeer(peerKey)
	if err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}

	node.sessionsMu.Lock()
	_, hasSession := node.sessions[peerKey]
	_, hasClientSession := node.clientSessions[peerKey]
	_, hasEstablishedAt := node.sessionEstablishedAt[peerKey]
	node.sessionsMu.Unlock()

	if hasSession {
		t.Error("sessions map still has entry after RemovePeer")
	}
	if hasClientSession {
		t.Error("clientSessions map still has entry after RemovePeer")
	}
	if hasEstablishedAt {
		t.Error("sessionEstablishedAt map still has entry after RemovePeer")
	}
}

// TestCleanupDeadSessions_RemovesOnlyDead verifies that CleanupDeadSessions
// removes closed sessions but preserves live ones.
func TestCleanupDeadSessions_RemovesOnlyDead(t *testing.T) {
	node := createTestNode(t)
	deadKey := "deadpeer00000000000000000000000000000000000000000000000000000000"
	liveKey := "livepeer000000000000000000000000000000000000000000000000000000000"

	// Create sessions.
	deadServer, deadClient := newSmuxServerSession(t)
	liveServer, liveClient := newSmuxServerSession(t)
	defer liveServer.Close()
	defer liveClient.Close()

	// Close the dead session.
	deadServer.Close()
	deadClient.Close()

	node.sessionsMu.Lock()
	node.sessions[deadKey] = deadServer
	node.clientSessions[deadKey] = deadClient
	node.sessions[liveKey] = liveServer
	node.clientSessions[liveKey] = liveClient
	node.sessionsMu.Unlock()

	// Cleanup dead sessions for deadKey.
	node.CleanupDeadSessions(deadKey)

	node.sessionsMu.Lock()
	_, deadInSessions := node.sessions[deadKey]
	_, deadInClient := node.clientSessions[deadKey]
	_, liveInSessions := node.sessions[liveKey]
	_, liveInClient := node.clientSessions[liveKey]
	node.sessionsMu.Unlock()

	if deadInSessions {
		t.Error("dead session should be removed from sessions map")
	}
	if deadInClient {
		t.Error("dead client session should be removed from clientSessions map")
	}
	if !liveInSessions {
		t.Error("live session should be preserved in sessions map")
	}
	if !liveInClient {
		t.Error("live client session should be preserved in clientSessions map")
	}

	// Cleanup dead sessions for liveKey should not remove live sessions.
	node.CleanupDeadSessions(liveKey)

	node.sessionsMu.Lock()
	_, liveInSessions2 := node.sessions[liveKey]
	_, liveInClient2 := node.clientSessions[liveKey]
	node.sessionsMu.Unlock()

	if !liveInSessions2 {
		t.Error("live session should still be preserved after CleanupDeadSessions")
	}
	if !liveInClient2 {
		t.Error("live client session should still be preserved after CleanupDeadSessions")
	}
}

// TestTryRelayFallback_SkipsDeadSessions verifies that tryRelayFallback
// does not include peers with closed sessions as relay candidates.
func TestTryRelayFallback_SkipsDeadSessions(t *testing.T) {
	node := createTestNode(t)
	deadKey := "deadpeer00000000000000000000000000000000000000000000000000000000"

	// Create a dead session.
	deadServer, deadClient := newSmuxServerSession(t)
	deadServer.Close()
	deadClient.Close()

	node.sessionsMu.Lock()
	node.sessions[deadKey] = deadServer
	node.clientSessions[deadKey] = deadClient
	node.sessionsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := node.tryRelayFallback(ctx, "targetkey", 0, nil)
	if err == nil {
		t.Fatal("expected error with only dead sessions, got nil")
	}
}

// TestTryRelayFallback_ExcludesTargetAndSelf verifies that tryRelayFallback
// does not include the target peer or the local node as relay candidates.
func TestTryRelayFallback_ExcludesTargetAndSelf(t *testing.T) {
	node := createTestNode(t)
	targetKey := "target0000000000000000000000000000000000000000000000000000000000"

	// Create a live session to the target.
	targetServer, targetClient := newSmuxServerSession(t)
	defer targetServer.Close()
	defer targetClient.Close()

	node.sessionsMu.Lock()
	node.sessions[targetKey] = targetServer
	node.clientSessions[targetKey] = targetClient
	node.sessionsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// tryRelayFallback for targetKey should not use targetKey as a relay.
	// With only the target in sessions, it should return "no relay candidates".
	_, err := node.tryRelayFallback(ctx, targetKey, 0, nil)
	if err == nil {
		t.Fatal("expected error when only session is to the target itself, got nil")
	}
}

// TestDialVirtualPort_SkipsDeadClientSession verifies that DialVirtualPort
// does not return a dead client session — it should skip it and fall through
// to the relay fallback or "no session" error path.
func TestDialVirtualPort_SkipsDeadClientSession(t *testing.T) {
	node := createTestNode(t)
	peerKey := "deadpeer00000000000000000000000000000000000000000000000000000000"

	// Create a dead client session.
	_, deadClient := newSmuxServerSession(t)
	deadClient.Close()

	node.sessionsMu.Lock()
	node.clientSessions[peerKey] = deadClient
	node.sessionsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// DialVirtualPort should not try to OpenStream on the dead session.
	_, err := node.DialVirtualPort(ctx, peerKey, 100)
	if err == nil {
		t.Fatal("expected error for dead client session, got nil")
	}

	// Verify the dead session was cleaned up from clientSessions.
	node.sessionsMu.Lock()
	_, hasClient := node.clientSessions[peerKey]
	node.sessionsMu.Unlock()

	if hasClient {
		t.Error("dead client session should have been cleaned up by DialVirtualPort")
	}
}

// TestRemovePeer_NoClientSession verifies that RemovePeer works correctly
// when the peer only has a client session (no server session).
func TestRemovePeer_NoClientSession(t *testing.T) {
	node := createTestNode(t)
	peerKey := "clientonly0000000000000000000000000000000000000000000000000000000"

	// Only put a client session, no server session.
	serverSess, clientSess := newSmuxServerSession(t)
	defer serverSess.Close()
	defer clientSess.Close()

	node.sessionsMu.Lock()
	node.clientSessions[peerKey] = clientSess
	node.sessionEstablishedAt[peerKey] = time.Now()
	node.sessionsMu.Unlock()

	err := node.RemovePeer(peerKey)
	if err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}

	node.sessionsMu.Lock()
	_, hasClient := node.clientSessions[peerKey]
	node.sessionsMu.Unlock()

	if hasClient {
		t.Error("clientSessions map should not have entry after RemovePeer")
	}
}

// TestRemovePeer_IdempotentMultiple verifies that calling RemovePeer
// multiple times on a peer that has client sessions is safe.
func TestRemovePeer_IdempotentMultiple(t *testing.T) {
	node := createTestNode(t)
	peerKey := "idempeer000000000000000000000000000000000000000000000000000000000"

	serverSess, clientSess := newSmuxServerSession(t)
	defer serverSess.Close()
	defer clientSess.Close()

	node.sessionsMu.Lock()
	node.clientSessions[peerKey] = clientSess
	node.sessionEstablishedAt[peerKey] = time.Now()
	node.sessionsMu.Unlock()

	// First call should succeed and clean up.
	err := node.RemovePeer(peerKey)
	if err != nil {
		t.Fatalf("First RemovePeer: %v", err)
	}

	// Second call should be safe (idempotent).
	err = node.RemovePeer(peerKey)
	if err != nil {
		t.Fatalf("Second RemovePeer: %v", err)
	}
}
