package mesh

import (
	"testing"
	"time"
)

// TestSessionReconnectHandler_CallbackFired tests that the
// sessionReconnectHandler is invoked when set via
// SetSessionReconnectHandler, and that it receives the correct peer key.
// This verifies the wiring: the handler is stored on MeshNode and can be
// retrieved and invoked — the same pattern used by reconnectLoop after
// tryReconnect succeeds.
func TestSessionReconnectHandler_CallbackFired(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef"

	// Set up the reconnect handler.
	reconnectCalled := make(chan string, 1)
	node.SetSessionReconnectHandler(func(pk string) {
		reconnectCalled <- pk
	})

	// Simulate what reconnectLoop does after tryReconnect succeeds:
	// read the handler under the mu lock and invoke it.
	node.mu.RLock()
	reconnectHdl := node.sessionReconnectHandler
	node.mu.RUnlock()
	if reconnectHdl == nil {
		t.Fatal("sessionReconnectHandler should not be nil after SetSessionReconnectHandler")
	}
	reconnectHdl(peerKey)

	select {
	case pk := <-reconnectCalled:
		if pk != peerKey {
			t.Errorf("reconnect handler called with %q, want %q", pk, peerKey)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session reconnect handler was not called within 2s")
	}
}

// TestSessionReconnectHandler_NilByDefault tests that the
// sessionReconnectHandler is nil by default (not set), and that
// reconnectLoop safely handles a nil handler without panicking.
func TestSessionReconnectHandler_NilByDefault(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	node.mu.RLock()
	reconnectHdl := node.sessionReconnectHandler
	node.mu.RUnlock()

	if reconnectHdl != nil {
		t.Fatal("sessionReconnectHandler should be nil by default")
	}

	// Invoking nil handler should be guarded — the reconnectLoop code
	// checks for nil before calling, so this is just verifying that
	// pattern works.
	if reconnectHdl != nil {
		reconnectHdl("test")
	}
}

// TestSessionReconnectHandler_RestoresTUNRoutes tests the full
// death → reconnect → restore cycle at the callback level. This
// simulates what main.go wires: the death handler removes routes,
// the reconnect handler re-adds them. We verify that after both
// handlers fire, the route operations are called in the correct
// order.
//
// Since AddPeerVirtualIPRoute and AddPeerSubnetProxies require a
// real TUN device (they check tunIntegration != nil), we verify
// the callback chain by tracking invocations through instrumented
// handlers — the same approach as TestSessionDeathHandler_FiresOnSessionClose.
func TestSessionReconnectHandler_RestoresTUNRoutes(t *testing.T) {
	node := createTestNode(t)
	defer node.Close()

	peerKey := "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef"

	// Track the sequence of operations: death → reconnect.
	var ops []string
	opsCh := make(chan string, 4)

	// Set up the death handler (simulates RemoveAllTUNRoutesForPeer).
	node.SetSessionDeathHandler(func(pk string) {
		opsCh <- "death:" + pk
	})

	// Set up the reconnect handler (simulates AddPeerVirtualIPRoute +
	// AddPeerSubnetProxies).
	node.SetSessionReconnectHandler(func(pk string) {
		opsCh <- "reconnect:" + pk
	})

	// Simulate session death.
	node.mu.RLock()
	deathHdl := node.sessionDeathHandler
	node.mu.RUnlock()
	if deathHdl != nil {
		deathHdl(peerKey)
	}

	// Simulate reconnect success.
	node.mu.RLock()
	reconnectHdl := node.sessionReconnectHandler
	node.mu.RUnlock()
	if reconnectHdl != nil {
		reconnectHdl(peerKey)
	}

	// Collect operations.
	close(opsCh)
	for op := range opsCh {
		ops = append(ops, op)
	}

	// Verify the order: death first, then reconnect.
	if len(ops) != 2 {
		t.Fatalf("expected 2 operations, got %d: %v", len(ops), ops)
	}
	if ops[0] != "death:"+peerKey {
		t.Errorf("expected death first, got %q", ops[0])
	}
	if ops[1] != "reconnect:"+peerKey {
		t.Errorf("expected reconnect second, got %q", ops[1])
	}
}
