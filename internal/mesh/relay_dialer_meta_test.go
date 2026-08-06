package mesh

import (
	"context"
	"testing"
	"time"
)

// TestMeshNode_TryRelayFallback_WithMetaProvider_NoRelayCapable verifies
// that tryRelayFallback returns an error when the relay meta provider
// reports no relay-capable peers.
func TestMeshNode_TryRelayFallback_WithMetaProvider_NoRelayCapable(t *testing.T) {
	node := createTestNode(t)

	node.SetRelayMetaProvider(func() []RelayPeerInfo {
		return []RelayPeerInfo{
			{PeerKey: "peer1", CapRelay: false},
			{PeerKey: "peer2", CapRelay: false},
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := node.tryRelayFallback(ctx, "targetkey", 0)
	if err == nil {
		t.Fatal("expected error when no relay-capable peers")
	}
}

// TestMeshNode_TryRelayFallback_WithMetaProvider_AtCapacity verifies
// that tryRelayFallback skips relays that are at capacity.
func TestMeshNode_TryRelayFallback_WithMetaProvider_AtCapacity(t *testing.T) {
	node := createTestNode(t)

	node.SetRelayMetaProvider(func() []RelayPeerInfo {
		return []RelayPeerInfo{
			{PeerKey: "relay1", CapRelay: true, MaxCircuits: 10, LoadCircuits: 10},
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := node.tryRelayFallback(ctx, "targetkey", 0)
	if err == nil {
		t.Fatal("expected error when relay is at capacity")
	}
}

// TestMeshNode_TryRelayFallback_WithMetaProvider_SymmetricNAT verifies
// that tryRelayFallback skips relays behind symmetric NAT.
func TestMeshNode_TryRelayFallback_WithMetaProvider_SymmetricNAT(t *testing.T) {
	node := createTestNode(t)

	node.SetRelayMetaProvider(func() []RelayPeerInfo {
		return []RelayPeerInfo{
			{PeerKey: "relay1", CapRelay: true, NatType: "symmetric"},
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := node.tryRelayFallback(ctx, "targetkey", 0)
	if err == nil {
		t.Fatal("expected error when only relay is symmetric NAT")
	}
}

// TestMeshNode_TryRelayFallback_WithMetaProvider_SkipsSelf verifies
// that tryRelayFallback skips the local node's own key.
func TestMeshNode_TryRelayFallback_WithMetaProvider_SkipsSelf(t *testing.T) {
	node := createTestNode(t)

	localKey := ""
	if node.identity != nil {
		localKey = node.identity.PublicKey
	}

	node.SetRelayMetaProvider(func() []RelayPeerInfo {
		return []RelayPeerInfo{
			{PeerKey: localKey, CapRelay: true},
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := node.tryRelayFallback(ctx, "targetkey", 0)
	if err == nil {
		t.Fatal("expected error when only candidate is self")
	}
}

// TestMeshNode_TryRelayFallback_WithMetaProvider_SkipsTarget verifies
// that tryRelayFallback skips the target peer.
func TestMeshNode_TryRelayFallback_WithMetaProvider_SkipsTarget(t *testing.T) {
	node := createTestNode(t)

	node.SetRelayMetaProvider(func() []RelayPeerInfo {
		return []RelayPeerInfo{
			{PeerKey: "targetkey", CapRelay: true},
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := node.tryRelayFallback(ctx, "targetkey", 0)
	if err == nil {
		t.Fatal("expected error when only candidate is the target")
	}
}

// TestMeshNode_TryRelayFallback_LegacyFallback verifies that when no
// relayMetaProvider is set, the legacy behavior still works (trying
// all peers with active sessions).
func TestMeshNode_TryRelayFallback_LegacyFallback(t *testing.T) {
	node := createTestNode(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// No relayMetaProvider set → legacy path.
	_, err := node.tryRelayFallback(ctx, "targetkey", 0)
	if err == nil {
		t.Fatal("expected error for no sessions in legacy mode")
	}
}

// TestRelayPeerInfo_ZeroValues verifies that a zero-value RelayPeerInfo
// is safe to use.
func TestRelayPeerInfo_ZeroValues(t *testing.T) {
	var r RelayPeerInfo
	if r.CapRelay != false {
		t.Error("CapRelay should default to false")
	}
	if r.RTT != 0 {
		t.Error("RTT should default to 0")
	}
	if r.MaxCircuits != 0 {
		t.Error("MaxCircuits should default to 0")
	}
}
