package p2p

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// testGossipPortBase is the starting port for gossip smoke tests.
// Tests use consecutive ports from this base to avoid collisions.
const testGossipPortBase = 17946

// newTestIdentity generates an Ed25519 key pair and returns the private key
// bytes (for GossipLayer identity) and the hex-encoded public key.
func newTestIdentity(t *testing.T) ([]byte, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return priv, hex.EncodeToString(pub)
}

// newTestGossipLayer creates a GossipLayer bound to 127.0.0.1 on the given
// port, with the given seeds. The layer is started and returned; the caller
// must call Stop() to clean up.
func newTestGossipLayer(t *testing.T, name string, port int, seeds []string) *GossipLayer {
	t.Helper()

	identity, pubKey := newTestIdentity(t)

	cfg := P2pConfig{
		Enabled:             true,
		Seeds:               seeds,
		GossipBindAddr:      "127.0.0.1",
		GossipPort:          port,
		GossipInterval:      1, // fast state sync for tests
		GossipProbeInterval: 1,
		MaxPeers:            256,
		JoinApproval:        "auto",
		AuthorizedKeys:      []string{pubKey},
		AdvertiseEndpoint:   fmt.Sprintf("127.0.0.1:%d", port),
	}

	pm := newMockPeerManager()
	gl, err := NewGossipLayer(cfg, identity, pm)
	if err != nil {
		t.Fatalf("[%s] NewGossipLayer: %v", name, err)
	}

	gl.SetLocalIdentity(name, "agent")
	gl.SetLocalCapabilities(false, false, false)

	// Override the announceLocalEndpoint auto-detection by setting endpoints
	// explicitly — AdvertiseEndpoint is already set, but announceLocalEndpoint
	// uses detectOutboundIP which may return a non-loopback address in CI.
	// We rely on AdvertiseEndpoint in the config instead.

	if err := gl.Start(); err != nil {
		t.Fatalf("[%s] Start: %v", name, err)
	}

	return gl
}

// waitForMemberCount polls MemberCount on the given layer until it reaches
// the target or the timeout expires.
func waitForMemberCount(t *testing.T, gl *GossipLayer, target int, timeout time.Duration, label string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if gl.MemberCount() >= target {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("[%s] member count = %d, want >= %d (timeout %v)", label, gl.MemberCount(), target, timeout)
}

// TestGossipV2_TwoNodeDiscovery verifies that two GossipLayer instances can
// discover each other via memberlist NetTransport over standard TCP on
// localhost. This corresponds to acceptance criteria AC-2 from the
// GOSSIP_REDESIGN_SPEC.md.
func TestGossipV2_TwoNodeDiscovery(t *testing.T) {
	portA := testGossipPortBase     // 17946
	portB := testGossipPortBase + 1 // 17947

	nodeA := newTestGossipLayer(t, "nodeA", portA, nil)
	defer nodeA.Stop()

	nodeB := newTestGossipLayer(t, "nodeB", portB, []string{fmt.Sprintf("127.0.0.1:%d", portA)})
	defer nodeB.Stop()

	// Wait for both nodes to see 2 members (self + peer).
	waitForMemberCount(t, nodeA, 2, 10*time.Second, "nodeA")
	waitForMemberCount(t, nodeB, 2, 10*time.Second, "nodeB")

	// Assert: B's metadata is visible to A (hostname, endpoints, capabilities).
	pubB := nodeB.LocalMeta().PublicKey
	metaBOnA := nodeA.Events().GetPeerMeta(pubB)
	if metaBOnA == nil {
		t.Fatalf("nodeA does not have metadata for nodeB (pubKey=%s)", shortKey(pubB))
	}
	if metaBOnA.Hostname != "nodeB" {
		t.Errorf("nodeA sees nodeB hostname = %q, want %q", metaBOnA.Hostname, "nodeB")
	}
	if metaBOnA.Role != "agent" {
		t.Errorf("nodeA sees nodeB role = %q, want %q", metaBOnA.Role, "agent")
	}
	t.Logf("nodeA sees nodeB: hostname=%s, endpoints=%v, capRelay=%v, capExit=%v, capProxyEntry=%v",
		metaBOnA.Hostname, metaBOnA.Endpoints, metaBOnA.CapRelay, metaBOnA.CapExit, metaBOnA.CapProxyEntry)

	// Assert: A's metadata is visible to B.
	pubA := nodeA.LocalMeta().PublicKey
	metaAOnB := nodeB.Events().GetPeerMeta(pubA)
	if metaAOnB == nil {
		t.Fatalf("nodeB does not have metadata for nodeA (pubKey=%s)", shortKey(pubA))
	}
	if metaAOnB.Hostname != "nodeA" {
		t.Errorf("nodeB sees nodeA hostname = %q, want %q", metaAOnB.Hostname, "nodeA")
	}
	if metaAOnB.Role != "agent" {
		t.Errorf("nodeB sees nodeA role = %q, want %q", metaAOnB.Role, "agent")
	}
	t.Logf("nodeB sees nodeA: hostname=%s, endpoints=%v, capRelay=%v, capExit=%v, capProxyEntry=%v",
		metaAOnB.Hostname, metaAOnB.Endpoints, metaAOnB.CapRelay, metaAOnB.CapExit, metaAOnB.CapProxyEntry)
}

// TestGossipV2_EndpointPropagation verifies that when node A calls
// SetLocalEndpoints, the new endpoints are visible to node B via gossip
// within a reasonable timeout. This corresponds to acceptance criteria AC-3
// from the GOSSIP_REDESIGN_SPEC.md.
func TestGossipV2_EndpointPropagation(t *testing.T) {
	portA := testGossipPortBase + 2 // 17948
	portB := testGossipPortBase + 3 // 17949

	nodeA := newTestGossipLayer(t, "nodeA-ep", portA, nil)
	defer nodeA.Stop()

	nodeB := newTestGossipLayer(t, "nodeB-ep", portB, []string{fmt.Sprintf("127.0.0.1:%d", portA)})
	defer nodeB.Stop()

	// Wait for discovery first.
	waitForMemberCount(t, nodeA, 2, 10*time.Second, "nodeA-ep")
	waitForMemberCount(t, nodeB, 2, 10*time.Second, "nodeB-ep")

	pubA := nodeA.LocalMeta().PublicKey

	// A sets local endpoints to a new value.
	newEndpoints := []string{"127.0.0.1:443"}
	nodeA.SetLocalEndpoints(newEndpoints, "none")

	t.Logf("nodeA set endpoints to %v, waiting for propagation to nodeB...", newEndpoints)

	// Wait up to 15 seconds for B to see A's updated endpoints.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		meta := nodeB.Events().GetPeerMeta(pubA)
		if meta != nil && len(meta.Endpoints) > 0 && meta.Endpoints[0] == "127.0.0.1:443" {
			t.Logf("nodeB sees nodeA endpoints = %v (natType=%s)", meta.Endpoints, meta.NatType)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Final assertion with full detail.
	meta := nodeB.Events().GetPeerMeta(pubA)
	if meta == nil {
		t.Fatalf("nodeB has no metadata for nodeA")
	}
	t.Errorf("endpoint propagation failed: nodeB sees nodeA endpoints = %v, want [127.0.0.1:443] (timeout 15s)",
		meta.Endpoints)
}

// TestGossipV2_NodeMetaNoMeshIP verifies that the NodeMeta struct, when
// marshaled to msgpack and unmarshaled, does not contain a MeshIP field
// or an ExitLatency field. These were removed in the v2 gossip redesign
// (task: Remove MeshIP and ExitLatency from NodeMeta schema).
func TestGossipV2_NodeMetaNoMeshIP(t *testing.T) {
	original := &NodeMeta{
		PublicKey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Hostname:  "test-no-meship",
		Role:      "agent",
		Endpoints: []string{"10.0.0.1:51820"},
		NatType:   "none",
		Version:   "1.0.0",
		Seq:       1,
	}

	data, err := original.MarshalMeta()
	if err != nil {
		t.Fatalf("MarshalMeta: %v", err)
	}

	decoded, err := UnmarshalMeta(data)
	if err != nil {
		t.Fatalf("UnmarshalMeta: %v", err)
	}

	// Assert: no MeshIP field. The struct doesn't have one, so the decoded
	// value should simply not have any mesh IP data. We verify by checking
	// that there's no field in the msgpack payload that could map to MeshIP.
	// Since Go structs are strongly typed, the absence of the field at compile
	// time is the primary guarantee. Here we verify the round-trip preserves
	// the expected fields and that no mesh IP data sneaks in.
	if decoded.PublicKey != original.PublicKey {
		t.Errorf("PublicKey: got %q, want %q", decoded.PublicKey, original.PublicKey)
	}
	if decoded.Hostname != original.Hostname {
		t.Errorf("Hostname: got %q, want %q", decoded.Hostname, original.Hostname)
	}
	if len(decoded.Endpoints) != 1 || decoded.Endpoints[0] != "10.0.0.1:51820" {
		t.Errorf("Endpoints: got %v, want [10.0.0.1:51820]", decoded.Endpoints)
	}

	// Verify the raw msgpack bytes do not contain a "mesh_ip" or "exit_latency" key.
	// msgpack encodes map keys as strings; if the fields existed they'd appear in the byte stream.
	rawStr := string(data)
	if contains(rawStr, "mesh_ip") {
		t.Errorf("msgpack payload contains 'mesh_ip' key — MeshIP field was not removed")
	}
	if contains(rawStr, "exit_latency") {
		t.Errorf("msgpack payload contains 'exit_latency' key — ExitLatency field was not removed")
	}

	// Verify NodeMeta struct has no MeshIP or ExitLatency fields by name.
	// This is a compile-time guarantee — if someone adds them back, this test
	// won't catch it at runtime, but the struct definition is the source of truth.
	// The msgpack tag check above is the runtime guard.
	t.Logf("NodeMeta round-trip OK: %d bytes, no MeshIP or ExitLatency fields detected", len(data))
}

// contains is a simple substring check (avoids pulling in strings package
// just for this one test).
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
