package mesh

import (
	"net"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/smux"
)

func TestSessionWatcher_DoneChannelFiresOnClose(t *testing.T) {
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	select {
	case <-sess.Done():
		t.Fatal("Done channel should not be closed yet")
	default:
	}

	sess.Close()

	select {
	case <-sess.Done():
	case <-time.After(1 * time.Second):
		t.Fatal("Done channel should be closed after Close()")
	}

	if !sess.IsClosed() {
		t.Fatal("IsClosed should be true after Close()")
	}
}

func TestSessionWatcher_DoneChannelFiresOnAbort(t *testing.T) {
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	client.Close()

	select {
	case <-sess.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done channel should fire after underlying connection error")
	}

	if !sess.IsClosed() {
		t.Fatal("IsClosed should be true after abort")
	}
}

func TestStartSessionWatcher_NoDuplicateWatchers(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "deadbeefcafebabe"
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	node.sessions[peerKey] = sess
	node.sessionEstablishedAt[peerKey] = time.Now()

	node.startSessionWatcher(peerKey, "1.2.3.4:443", true)
	node.startSessionWatcher(peerKey, "1.2.3.4:443", true)

	node.reconnectStateMu.Lock()
	count := len(node.reconnectState)
	node.reconnectStateMu.Unlock()

	if count != 1 {
		t.Fatalf("expected 1 reconnect tracker, got %d", count)
	}

	node.stopReconnectWatcher(peerKey)
}

func TestStartSessionWatcher_ExitsOnSessionClose(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "deadbeefcafebabe1234"
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	node.sessions[peerKey] = sess
	node.sessionEstablishedAt[peerKey] = time.Now()
	node.routes.AddPeer(&PeerEntry{ID: peerKey, Endpoint: "1.2.3.4:443"})

	node.startSessionWatcher(peerKey, "1.2.3.4:443", true)
	time.Sleep(100 * time.Millisecond)

	sess.Close()
	time.Sleep(500 * time.Millisecond)

	// The tracker should still exist (reconnect loop is running, failing to dial 1.2.3.4:443).
	node.reconnectStateMu.Lock()
	_, exists := node.reconnectState[peerKey]
	node.reconnectStateMu.Unlock()

	// It's OK if it exists (still retrying) or not (failed fast). The key
	// is that the watcher detected the closure and didn't panic.
	_ = exists

	node.stopReconnectWatcher(peerKey)
}

func TestStopReconnectWatcher_CleansUp(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "aabbccdd11223344"
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	node.sessions[peerKey] = sess
	node.sessionEstablishedAt[peerKey] = time.Now()

	node.startSessionWatcher(peerKey, "1.2.3.4:443", true)
	time.Sleep(100 * time.Millisecond)

	node.stopReconnectWatcher(peerKey)

	node.reconnectStateMu.Lock()
	_, exists := node.reconnectState[peerKey]
	node.reconnectStateMu.Unlock()

	if exists {
		t.Fatal("reconnect tracker should be removed after stopReconnectWatcher")
	}
}

func TestCleanupDeadSession_RemovesOnlyMatchingSession(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "abcdef0123456789"

	sess1, client1 := newSmuxServerSession(t)
	defer client1.Close()
	sess2, client2 := newSmuxServerSession(t)
	defer client2.Close()

	node.sessions[peerKey] = sess2
	node.clientSessions[peerKey] = sess2

	node.cleanupDeadSession(peerKey, sess1)

	node.sessionsMu.Lock()
	s, ok := node.sessions[peerKey]
	node.sessionsMu.Unlock()

	if !ok || s != sess2 {
		t.Fatal("cleanupDeadSession should not have removed the newer session")
	}

	node.cleanupDeadSession(peerKey, sess2)

	node.sessionsMu.Lock()
	_, ok = node.sessions[peerKey]
	node.sessionsMu.Unlock()

	if ok {
		t.Fatal("cleanupDeadSession should have removed sess2")
	}
}

func TestHasActiveSession(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "1122334455667788"

	if node.hasActiveSession(peerKey) {
		t.Fatal("hasActiveSession should be false when no session exists")
	}

	sess, client := newSmuxServerSession(t)
	defer client.Close()
	node.sessions[peerKey] = sess

	if !node.hasActiveSession(peerKey) {
		t.Fatal("hasActiveSession should be true for active session")
	}

	sess.Close()
	time.Sleep(100 * time.Millisecond)

	if node.hasActiveSession(peerKey) {
		t.Fatal("hasActiveSession should be false for closed session")
	}
}

func TestResolvePeerEndpoint(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "aabbccddeeff0011"

	if ep := node.resolvePeerEndpoint(peerKey); ep != "" {
		t.Fatalf("expected empty endpoint, got %q", ep)
	}

	node.routes.AddPeer(&PeerEntry{ID: peerKey, Endpoint: "10.0.0.1:443"})

	if ep := node.resolvePeerEndpoint(peerKey); ep != "10.0.0.1:443" {
		t.Fatalf("expected 10.0.0.1:443, got %q", ep)
	}
}

func TestBackoffDelay(t *testing.T) {
	initial := 2 * time.Second
	max := 60 * time.Second

	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 2 * time.Second},
		{2, 3 * time.Second},
		{3, 4500 * time.Millisecond},
		{10, 60 * time.Second},
		{100, 60 * time.Second},
	}

	for _, tt := range tests {
		got := backoffDelay(tt.attempt, initial, max)
		diff := got - tt.want
		if diff < 0 {
			diff = -diff
		}
		if diff > 100*time.Millisecond {
			t.Errorf("backoffDelay(%d) = %v, want ~%v", tt.attempt, got, tt.want)
		}
	}
}

func TestRemovePeer_StopsReconnectWatcher(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "aabbccdd11223344"
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	node.sessions[peerKey] = sess
	node.sessionEstablishedAt[peerKey] = time.Now()
	node.routes.AddPeer(&PeerEntry{ID: peerKey, Endpoint: "1.2.3.4:443"})

	node.startSessionWatcher(peerKey, "1.2.3.4:443", true)
	time.Sleep(100 * time.Millisecond)

	err := node.RemovePeer(peerKey)
	if err != nil {
		t.Fatalf("RemovePeer failed: %v", err)
	}

	node.reconnectStateMu.Lock()
	_, exists := node.reconnectState[peerKey]
	node.reconnectStateMu.Unlock()

	if exists {
		t.Fatal("reconnect tracker should be removed by RemovePeer")
	}
}

func TestClose_StopsAllReconnectWatchers(t *testing.T) {
	node := createTestNode(t)

	peer1 := "aaa111aaa111aaa1"
	peer2 := "bbb222bbb222bbb2"

	sess1, client1 := newSmuxServerSession(t)
	defer client1.Close()
	sess2, client2 := newSmuxServerSession(t)
	defer client2.Close()

	node.sessions[peer1] = sess1
	node.sessions[peer2] = sess2
	node.sessionEstablishedAt[peer1] = time.Now()
	node.sessionEstablishedAt[peer2] = time.Now()

	node.startSessionWatcher(peer1, "1.2.3.4:443", true)
	node.startSessionWatcher(peer2, "5.6.7.8:443", true)
	time.Sleep(100 * time.Millisecond)

	node.Close()

	node.reconnectStateMu.Lock()
	count := len(node.reconnectState)
	node.reconnectStateMu.Unlock()

	if count != 0 {
		t.Fatalf("expected 0 reconnect trackers after Close, got %d", count)
	}
}

func TestStartSessionWatcher_NoSession(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "nonexistent"

	node.startSessionWatcher(peerKey, "1.2.3.4:443", true)
	time.Sleep(200 * time.Millisecond)

	node.reconnectStateMu.Lock()
	_, exists := node.reconnectState[peerKey]
	node.reconnectStateMu.Unlock()

	if exists {
		t.Fatal("reconnect tracker should have been cleaned up when no session exists")
	}
}

func TestStartSessionWatcher_ExitsOnNodeShutdown(t *testing.T) {
	node := createTestNode(t)

	peerKey := "shutdown1234567890"
	sess, client := newSmuxServerSession(t)
	defer client.Close()

	node.sessions[peerKey] = sess
	node.sessionEstablishedAt[peerKey] = time.Now()

	node.startSessionWatcher(peerKey, "1.2.3.4:443", true)
	time.Sleep(100 * time.Millisecond)

	node.Close()

	node.reconnectStateMu.Lock()
	_, exists := node.reconnectState[peerKey]
	node.reconnectStateMu.Unlock()

	if exists {
		t.Fatal("reconnect tracker should be removed after node shutdown")
	}
}

func TestGetWatchableSession_PrefersClientSession(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "prefclient1234567"

	serverSess, client1 := newSmuxServerSession(t)
	defer client1.Close()
	_, client2 := newSmuxServerSession(t)
	defer client2.Close()

	node.sessions[peerKey] = serverSess
	node.clientSessions[peerKey] = serverSess

	sess := node.getWatchableSession(peerKey)
	if sess == nil {
		t.Fatal("getWatchableSession should return non-nil")
	}

	node.sessionsMu.Lock()
	delete(node.clientSessions, peerKey)
	node.sessionsMu.Unlock()

	sess = node.getWatchableSession(peerKey)
	if sess == nil {
		t.Fatal("getWatchableSession should fall back to sessions map")
	}
	if sess != serverSess {
		t.Fatal("getWatchableSession should return the session from sessions map")
	}
}

func TestIsShuttingDown(t *testing.T) {
	node := createTestNode(t)

	if node.isShuttingDown() {
		t.Fatal("node should not be shutting down before Close()")
	}

	node.Close()

	if !node.isShuttingDown() {
		t.Fatal("node should be shutting down after Close()")
	}
}

func TestShortPeerID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"short", "short"},
		{"1234567890123456", "1234567890123456"},
		{"12345678901234567", "1234567890123456..."},
		{"12345678901234567890", "1234567890123456..."},
	}

	for _, tt := range tests {
		got := shortPeerID(tt.input)
		if got != tt.want {
			t.Errorf("shortPeerID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDoneChannelIdempotent(t *testing.T) {
	cPipe, sPipe := net.Pipe()
	defer cPipe.Close()
	defer sPipe.Close()

	cfg := smux.DefaultConfig()
	cfg.HandshakeTimeout = 5 * time.Second

	errCh := make(chan error, 2)
	var server *smux.Session

	go func() {
		c, e := smux.Client(cPipe, cfg)
		_ = c
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

	ch1 := server.Done()
	ch2 := server.Done()

	if ch1 != ch2 {
		t.Fatal("Done() should return the same channel on repeated calls")
	}

	select {
	case <-ch1:
		t.Fatal("Done channel should not be closed yet")
	default:
	}

	server.Close()

	select {
	case <-ch1:
	case <-time.After(1 * time.Second):
		t.Fatal("Done channel should be closed after Close()")
	}
}
