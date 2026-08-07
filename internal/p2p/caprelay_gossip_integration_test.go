package p2p

import (
	"fmt"
	"testing"
	"time"
)

// ============================================================================
// CapRelay gossip meta integration test (task t_521d82d7)
// ============================================================================
//
// Gap being closed: config switch (config.go) -> gossip meta
// (EnableRelayMode sets CapRelay) -> candidate filtering
// (GetRelayCandidates / tryRelayFallback filter !CapRelay) only had
// scattered unit tests. This test exercises the full chain end-to-end
// with two REAL in-process GossipLayer instances (real memberlist over
// TCP/UDP on 127.0.0.1), mirroring production startup ordering from
// cmd/meshdesk/main.go:
//
//   - node A (relay.enabled=true):  SetLocalCapabilities(true,...) before
//     Start() (main.go:430), then EnableRelayMode after Start() — the same
//     order production uses (main.go:437 Start, main.go:456 EnableRelayMode).
//   - node B (relay.enabled=false, default): CapRelay never set.
//
// Assertions:
//   1. A's CapRelay=true propagates via gossip to B's metaCache.
//   2. B's CapRelay stays false; B is NOT added to A's relayPool
//      (GetRelayCandidates from A's perspective filters B out).
//   3. Reverse: A calls DisableRelayMode -> CapRelay=false -> the updated
//      meta propagates -> GetRelayCandidates (from B's perspective, which
//      tracks A) no longer includes A.
//
// Reuses the freePort/newTestGossipLayer/waitForMemberCount harness from
// gossip_v2_smoke_test.go.

// waitForCapRelay polls until the peer's CapRelay flag (as seen by the
// observer node) matches want, or the timeout expires.
func waitForCapRelay(t *testing.T, observer *GossipLayer, peerKey string, want bool, timeout time.Duration, label string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		meta := observer.Events().GetPeerMeta(peerKey)
		if meta != nil && meta.CapRelay == want {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	meta := observer.Events().GetPeerMeta(peerKey)
	if meta == nil {
		t.Fatalf("[%s] no metadata for peer %s (timeout %v)", label, shortKey(peerKey), timeout)
	}
	t.Fatalf("[%s] peer %s CapRelay = %v, want %v (timeout %v)",
		label, shortKey(peerKey), meta.CapRelay, want, timeout)
}

// waitForRelayPoolCount polls GetRelayCandidates on the observer until its
// length matches want or the timeout expires.
func waitForRelayPoolCount(t *testing.T, observer *GossipLayer, want int, timeout time.Duration, label string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(observer.Events().GetRelayCandidates()) == want {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("[%s] relay candidate count = %d, want %d (timeout %v)",
		label, len(observer.Events().GetRelayCandidates()), want, timeout)
}

// relayCandidateKeys returns the set of PublicKeys currently in the
// observer's relay candidate pool.
func relayCandidateKeys(observer *GossipLayer) map[string]bool {
	keys := make(map[string]bool)
	for _, c := range observer.Events().GetRelayCandidates() {
		keys[c.PublicKey] = true
	}
	return keys
}

// TestCapRelayGossipIntegration is the end-to-end integration test for the
// CapRelay gossip meta chain:
//
//	node A relay.enabled=true  -> CapRelay=true in gossip meta
//	node B relay.enabled=false -> CapRelay absent (false)
//	GetRelayCandidates from A's view: B filtered out, A self-excluded
//	GetRelayCandidates from B's view: A included (B uses A as relay)
//	reverse: A disables relay -> meta refreshes -> candidate list changes
func TestCapRelayGossipIntegration(t *testing.T) {
	portA := freePort(t)
	portB := freePort(t)

	// Node A: relay.enabled=true. Production ordering from main.go:
	//   gl.SetLocalCapabilities(cfg.Proxy.Relay.Enabled, ...) BEFORE Start
	//   (main.go:430-435), then EnableRelayMode AFTER Start (main.go:456).
	nodeA := newTestGossipLayer(t, "nodeA-relay", portA, nil)
	defer nodeA.Stop()

	// Node A's layer is started with CapRelay=false (harness default).
	if nodeA.LocalMeta().CapRelay {
		t.Fatal("nodeA should start with CapRelay=false before EnableRelayMode")
	}

	// Enable relay mode — this is what production does when
	// proxy.relay.enabled=true (SetLocalCapabilities(true,...) +
	// updateLocalMeta Seq++ via EnableRelayMode, gossip.go:1232-1239).
	if err := nodeA.EnableRelayMode(1024); err != nil {
		t.Fatalf("nodeA EnableRelayMode failed: %v", err)
	}
	if !nodeA.LocalMeta().CapRelay {
		t.Fatal("nodeA LocalMeta.CapRelay should be true after EnableRelayMode")
	}

	// Node B: relay.enabled=false (default) — CapRelay stays false.
	nodeB := newTestGossipLayer(t, "nodeB-norelay", portB, []string{fmt.Sprintf("127.0.0.1:%d", portA)})
	defer nodeB.Stop()

	pubA := nodeA.LocalMeta().PublicKey
	pubB := nodeB.LocalMeta().PublicKey

	// Wait for both nodes to discover each other.
	waitForMemberCount(t, nodeA, 2, 10*time.Second, "nodeA-relay")
	waitForMemberCount(t, nodeB, 2, 10*time.Second, "nodeB-norelay")

	// --- Assertion 1: A's CapRelay=true propagates to B's meta cache. ---
	// B sees A as relay-capable: A advertised CapRelay via gossip meta.
	waitForCapRelay(t, nodeB, pubA, true, 15*time.Second, "nodeB sees nodeA")

	// --- Assertion 2: B's CapRelay is false and B is filtered out. ---
	metaBOnA := nodeA.Events().GetPeerMeta(pubB)
	if metaBOnA == nil {
		t.Fatalf("nodeA has no metadata for nodeB")
	}
	if metaBOnA.CapRelay {
		t.Errorf("nodeB CapRelay = true, want false (relay disabled node must not advertise CapRelay)")
	}

	// GetRelayCandidates from A's perspective: B (CapRelay=false) must be
	// filtered out, and A itself (self key) must not be in the pool either.
	waitForRelayPoolCount(t, nodeA, 0, 10*time.Second, "nodeA candidates after B join")

	// GetRelayCandidates from B's perspective: A (CapRelay=true) must be
	// present — B can use A as a relay.
	waitForRelayPoolCount(t, nodeB, 1, 15*time.Second, "nodeB candidates after A enable")

	// --- Assertion 3 (reverse): A disables relay -> meta refreshes. ---
	// DisableRelayMode clears CapRelay (gossip.go:1262) and the updated
	// meta propagates via memberlist UpdateNode (SetLocalCapabilities ->
	// delegate.updateLocalMeta -> Seq++ -> gossip re-broadcast).
	if err := nodeA.DisableRelayMode(); err != nil {
		t.Fatalf("nodeA DisableRelayMode failed: %v", err)
	}
	if nodeA.LocalMeta().CapRelay {
		t.Fatal("nodeA LocalMeta.CapRelay should be false after DisableRelayMode")
	}

	// B must observe A's CapRelay flip to false via gossip.
	waitForCapRelay(t, nodeB, pubA, false, 15*time.Second, "nodeB sees nodeA disabled")

	// A's own relay pool must be empty (B still non-relay, A no longer relay).
	waitForRelayPoolCount(t, nodeA, 0, 10*time.Second, "nodeA candidates after disable")

	// B's relay pool must now be empty — A was removed from B's relay
	// candidates once its CapRelay went false (NotifyUpdate pool removal).
	waitForRelayPoolCount(t, nodeB, 0, 15*time.Second, "nodeB candidates after A disable")

	// Final explicit assertions (beyond the polling helpers).
	if got := relayCandidateKeys(nodeA); len(got) != 0 {
		t.Errorf("nodeA relay candidates = %v, want empty (B filtered, self excluded)", got)
	}
	if got := relayCandidateKeys(nodeB); len(got) != 0 {
		t.Errorf("nodeB relay candidates = %v, want empty after A disabled relay", got)
	}
}
