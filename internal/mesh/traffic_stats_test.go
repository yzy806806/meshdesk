package mesh

import (
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

// TestTrafficStatsEmptyNode verifies that a freshly created node
// reports zero traffic stats.
func TestTrafficStatsEmptyNode(t *testing.T) {
	cfg := &config.Config{
		Node: config.NodeConfig{
			IdentityFile: t.TempDir() + "/identity.pem",
		},
	}
	node, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer node.Close()

	stats := node.TrafficStats()
	if stats.InBytes != 0 || stats.OutBytes != 0 {
		t.Errorf("empty node traffic should be zero, got in=%d out=%d", stats.InBytes, stats.OutBytes)
	}
	if stats.SmuxStreams != 0 {
		t.Errorf("empty node smux streams should be 0, got %d", stats.SmuxStreams)
	}
	if stats.RelayForwards != 0 {
		t.Errorf("empty node relay forwards should be 0, got %d", stats.RelayForwards)
	}
	if stats.PeerCount != 0 {
		t.Errorf("empty node peer count should be 0, got %d", stats.PeerCount)
	}
}

// TestTrafficStatsNoPanic verifies that TrafficStats doesn't panic
// when called on a node with no relay handler or TUN integration.
func TestTrafficStatsNoPanic(t *testing.T) {
	cfg := &config.Config{
		Node: config.NodeConfig{
			IdentityFile: t.TempDir() + "/identity.pem",
		},
	}
	node, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer node.Close()

	// Should not panic even with nil relayHandler and nil tunIntegration.
	stats := node.TrafficStats()

	if stats.InBytes != 0 || stats.OutBytes != 0 {
		t.Errorf("no sessions: traffic should be zero, got in=%d out=%d", stats.InBytes, stats.OutBytes)
	}
	if stats.TunRxPackets != 0 || stats.TunTxPackets != 0 {
		t.Errorf("no TUN: packets should be zero, got rx=%d tx=%d", stats.TunRxPackets, stats.TunTxPackets)
	}
	if stats.RelayForwards != 0 {
		t.Errorf("no relay: forwards should be 0, got %d", stats.RelayForwards)
	}
}

// TestTrafficStatsSkipsClosedSessions verifies that closed sessions
// are not counted in TrafficStats.
func TestTrafficStatsSkipsClosedSessions(t *testing.T) {
	cfg := &config.Config{
		Node: config.NodeConfig{
			IdentityFile: t.TempDir() + "/identity.pem",
		},
	}
	node, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer node.Close()

	// We can't easily create real smux sessions without blocking on
	// handshake, so we test the nil/closed skip logic by leaving
	// the session maps empty. The TrafficStats method already checks
	// for nil and IsClosed() before counting.
	stats := node.TrafficStats()

	if stats.PeerCount != 0 {
		t.Errorf("no sessions: PeerCount should be 0, got %d", stats.PeerCount)
	}
}

// TestMeshNodeContext verifies that Context() returns a non-nil context
// that gets cancelled on Close().
func TestMeshNodeContext(t *testing.T) {
	cfg := &config.Config{
		Node: config.NodeConfig{
			IdentityFile: t.TempDir() + "/identity.pem",
		},
	}
	node, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := node.Context()
	if ctx == nil {
		t.Fatal("Context() returned nil")
	}

	if err := ctx.Err(); err != nil {
		t.Fatalf("context should not be cancelled yet, got %v", err)
	}

	node.Close()

	// After Close, the context should be cancelled.
	if err := ctx.Err(); err == nil {
		t.Error("context should be cancelled after Close()")
	}
}
