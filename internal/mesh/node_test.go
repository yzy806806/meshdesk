package mesh

import (
	"context"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
)

// TestMeshNodeCreateAndStart verifies that a MeshNode can be created with
// auto-generated identity and started successfully. This exercises the full
// wireguard-go + gVisor netstack integration.
func TestMeshNodeCreateAndStart(t *testing.T) {
	cfg := config.Default()
	cfg.Mesh.Port = 0 // random port to avoid conflicts

	node, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer node.Close()

	if node.Identity() == nil {
		t.Fatal("Identity() is nil")
	}
	if node.Identity().PublicKey == "" {
		t.Error("PublicKey is empty")
	}
	if node.Identity().PrivateKey == "" {
		t.Error("PrivateKey is empty")
	}

	if err := node.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// The routing table should be empty (no peers configured).
	if node.RoutingTable().PeerCount() != 0 {
		t.Errorf("PeerCount = %d, want 0", node.RoutingTable().PeerCount())
	}

	// Net() should return a non-nil gVisor netstack.
	if node.Net() == nil {
		t.Error("Net() is nil")
	}
}

// TestMeshNodeAddRemovePeer tests adding and removing a peer.
func TestMeshNodeAddRemovePeer(t *testing.T) {
	cfg := config.Default()
	cfg.Mesh.Port = 0

	node, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer node.Close()

	if err := node.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Generate a peer keypair for the fake peer.
	peerCfg := config.PeerConfig{
		PublicKey:   "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Endpoint:    "127.0.0.1:51821",
		AllowedIPs:  []string{"10.10.1.1/32"},
		Obfuscation: "padded",
	}

	if err := node.AddPeer(peerCfg); err != nil {
		t.Fatalf("AddPeer() error: %v", err)
	}

	if node.RoutingTable().PeerCount() != 1 {
		t.Errorf("PeerCount = %d, want 1", node.RoutingTable().PeerCount())
	}

	// Verify the peer is in the routing table.
	p, ok := node.RoutingTable().GetPeer(peerCfg.PublicKey)
	if !ok {
		t.Fatal("GetPeer failed")
	}
	if p.Obfuscation != ObfuscationPadded {
		t.Errorf("Obfuscation = %v, want %v", p.Obfuscation, ObfuscationPadded)
	}

	// Remove the peer.
	if err := node.RemovePeer(peerCfg.PublicKey); err != nil {
		t.Fatalf("RemovePeer() error: %v", err)
	}

	if node.RoutingTable().PeerCount() != 0 {
		t.Errorf("After removal, PeerCount = %d, want 0", node.RoutingTable().PeerCount())
	}
}

// TestMeshNodeClose tests that the node can be closed cleanly.
func TestMeshNodeClose(t *testing.T) {
	cfg := config.Default()
	cfg.Mesh.Port = 0

	node, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := node.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	if err := node.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// Double close should be safe.
	if err := node.Close(); err != nil {
		t.Fatalf("Double Close() error: %v", err)
	}
}

// TestMeshNodeDialTimeout verifies that a Dial to a non-existent peer
// times out rather than hanging forever.
func TestMeshNodeDialTimeout(t *testing.T) {
	cfg := config.Default()
	cfg.Mesh.Port = 0

	node, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer node.Close()

	if err := node.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Dial to a non-existent address should fail/timeout.
	_, err = node.Dial(ctx, "tcp", "10.99.99.99:9999")
	if err == nil {
		t.Error("Dial to non-existent address should fail")
	}
}

// TestMeshNodeGenerateIdentity tests the package-level GenerateIdentity.
func TestMeshNodeGenerateIdentity(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}
	if id.PublicKey == "" || id.PrivateKey == "" {
		t.Error("GenerateIdentity returned empty keys")
	}
}
