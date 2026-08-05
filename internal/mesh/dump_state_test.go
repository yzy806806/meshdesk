package mesh

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestDumpState_NoSessions verifies that DumpState produces well-formed
// output even when there are no peers, sessions, or TUN integration.
func TestDumpState_NoSessions(t *testing.T) {
	node := createTestNode(t)

	var buf bytes.Buffer
	node.DumpState(&buf)

	out := buf.String()

	// Must contain routing table header with 0 peers.
	if !strings.Contains(out, "=== Routing Table (0 peers) ===") {
		t.Errorf("expected routing table header, got:\n%s", out)
	}

	// Must contain sessions header with 0 server and 0 client sessions.
	if !strings.Contains(out, "=== Sessions (server=0, client=0) ===") {
		t.Errorf("expected sessions header, got:\n%s", out)
	}

	// TUN should be disabled (no tunIntegration set).
	if !strings.Contains(out, "=== TUN: disabled ===") {
		t.Errorf("expected TUN disabled, got:\n%s", out)
	}

	// Relay should be disabled.
	if !strings.Contains(out, "=== Relay: disabled ===") {
		t.Errorf("expected Relay disabled, got:\n%s", out)
	}
}

// TestDumpState_WithPeersAndSessions verifies that DumpState includes
// routing table peers and active smux sessions.
func TestDumpState_WithPeersAndSessions(t *testing.T) {
	node := createTestNode(t)

	// Add a peer to the routing table.
	node.RoutingTable().AddPeer(&PeerEntry{
		ID:         "abc123def456",
		Endpoint:   "192.168.1.10:51820",
		AllowedIPs: []string{"10.0.0.2/32"},
	})

	// Create a mock smux session pair.
	serverSess, clientSess := newSmuxServerSession(t)
	defer serverSess.Close()
	defer clientSess.Close()

	// Register the session in the node.
	peerID := "peer1hexkey"
	node.sessionsMu.Lock()
	node.clientSessions[peerID] = clientSess
	node.sessionEstablishedAt[peerID] = time.Now().Add(-1 * time.Minute)
	node.sessionsMu.Unlock()

	var buf bytes.Buffer
	node.DumpState(&buf)

	out := buf.String()

	// Must show 1 peer in the routing table.
	if !strings.Contains(out, "=== Routing Table (1 peers) ===") {
		t.Errorf("expected 1 peer in routing table, got:\n%s", out)
	}

	// Must show the peer ID.
	if !strings.Contains(out, "abc123def456") {
		t.Errorf("expected peer ID in output, got:\n%s", out)
	}

	// Must show 1 client session.
	if !strings.Contains(out, "=== Sessions (server=0, client=1) ===") {
		t.Errorf("expected 1 client session, got:\n%s", out)
	}

	// Must show the session peer ID.
	if !strings.Contains(out, peerID) {
		t.Errorf("expected session peer ID in output, got:\n%s", out)
	}

	// Must show [client] prefix.
	if !strings.Contains(out, "[client]") {
		t.Errorf("expected [client] prefix in output, got:\n%s", out)
	}

	// Must show streams count.
	if !strings.Contains(out, "streams=") {
		t.Errorf("expected streams= in output, got:\n%s", out)
	}
}

// TestDumpState_ClosedSession verifies that closed sessions are marked CLOSED.
func TestDumpState_ClosedSession(t *testing.T) {
	node := createTestNode(t)

	serverSess, clientSess := newSmuxServerSession(t)
	serverSess.Close()
	clientSess.Close()

	peerID := "closedpeer"
	node.sessionsMu.Lock()
	node.clientSessions[peerID] = clientSess
	node.sessionsMu.Unlock()

	var buf bytes.Buffer
	node.DumpState(&buf)

	out := buf.String()

	if !strings.Contains(out, "CLOSED") {
		t.Errorf("expected CLOSED in output for closed session, got:\n%s", out)
	}
}

// TestDumpState_ServerSession verifies that server-side sessions are labeled [server].
func TestDumpState_ServerSession(t *testing.T) {
	node := createTestNode(t)

	serverSess, clientSess := newSmuxServerSession(t)
	defer serverSess.Close()
	defer clientSess.Close()

	peerID := "serverpeer"
	node.sessionsMu.Lock()
	node.sessions[peerID] = serverSess
	node.sessionEstablishedAt[peerID] = time.Now().Add(-2 * time.Minute)
	node.sessionsMu.Unlock()

	var buf bytes.Buffer
	node.DumpState(&buf)

	out := buf.String()

	if !strings.Contains(out, "=== Sessions (server=1, client=0) ===") {
		t.Errorf("expected 1 server session, got:\n%s", out)
	}

	if !strings.Contains(out, "[server]") {
		t.Errorf("expected [server] prefix in output, got:\n%s", out)
	}
}

// TestDumpState_MultiplePeers verifies multiple peers in routing table.
func TestDumpState_MultiplePeers(t *testing.T) {
	node := createTestNode(t)

	for i := 0; i < 5; i++ {
		node.RoutingTable().AddPeer(&PeerEntry{
			ID:       "peer" + string(rune('A'+i)),
			Endpoint: "10.0.0." + string(rune('1'+i)) + ":51820",
		})
	}

	var buf bytes.Buffer
	node.DumpState(&buf)

	out := buf.String()

	if !strings.Contains(out, "=== Routing Table (5 peers) ===") {
		t.Errorf("expected 5 peers in routing table, got:\n%s", out)
	}
}

// TestDumpState_RelayHandler verifies relay handler status in dump.
func TestDumpState_RelayHandler(t *testing.T) {
	node := createTestNode(t)

	var buf bytes.Buffer
	node.DumpState(&buf)

	out := buf.String()

	// Without relay handler, should show disabled.
	if !strings.Contains(out, "=== Relay: disabled ===") {
		t.Errorf("expected Relay disabled, got:\n%s", out)
	}
}

// TestDumpState_DoesNotPanicOnNilFields verifies DumpState doesn't panic
// when optional fields like sessionEstablishedAt are nil or partially populated.
func TestDumpState_DoesNotPanicOnNilFields(t *testing.T) {
	node := createTestNode(t)

	// Add a session without a corresponding sessionEstablishedAt entry.
	serverSess, clientSess := newSmuxServerSession(t)
	defer serverSess.Close()
	defer clientSess.Close()

	peerID := "noTimestamp"
	node.sessionsMu.Lock()
	node.clientSessions[peerID] = clientSess
	// Deliberately don't set sessionEstablishedAt[peerID]
	node.sessionsMu.Unlock()

	var buf bytes.Buffer
	node.DumpState(&buf) // Should not panic.

	if !strings.Contains(buf.String(), peerID) {
		t.Errorf("expected peer ID in output, got:\n%s", buf.String())
	}
}
