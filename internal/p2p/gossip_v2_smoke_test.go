package p2p

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// freePort returns an available TCP port on 127.0.0.1.
// It binds to port 0, gets the assigned port, closes the listener,
// and returns the port number. The TOCTOU race between close and
// rebind is acceptable because newTestGossipLayer retries on bind
// failure with a fresh port.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

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
//
// If the given port is already in use (TOCTOU race from freePort), the
// function retries with a fresh port up to 3 times before giving up.
func newTestGossipLayer(t *testing.T, name string, port int, seeds []string) *GossipLayer {
	t.Helper()

	const maxRetries = 3
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// On retries, get a fresh port to avoid the same conflict.
		// Note: we must NOT rewrite seeds — they point to the remote
		// peer's port, not our own. Only our bind port changes.
		if attempt > 0 {
			port = freePort(t)
		}

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
			AdvertiseEndpoints: []string{
				fmt.Sprintf("127.0.0.1:%d", port),
				fmt.Sprintf("[::1]:%d", port),
			},
		}

		pm := newMockPeerManager()
		gl, err := NewGossipLayer(cfg, identity, pm)
		if err != nil {
			lastErr = err
			continue
		}

		gl.SetLocalIdentity(name, "agent")
		gl.SetLocalCapabilities(false, false, false, false)

		if err := gl.Start(); err != nil {
			lastErr = err
			gl = nil
			continue // port conflict — retry with a fresh port
		}

		return gl
	}

	t.Fatalf("[%s] newTestGossipLayer failed after %d retries: %v", name, maxRetries, lastErr)
	return nil
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
	portA := freePort(t)
	portB := freePort(t)

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
	portA := freePort(t)
	portB := freePort(t)

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

// TestGossipV2_NodeMetaCapCollectorCompat verifies cross-version msgpack
// compatibility for the CapCollector field. When an older node serializes
// NodeMeta without the "cc" (CapCollector) field, the current code must:
//   1. Successfully unmarshal the payload (no parse errors).
//   2. Default CapCollector to false (zero value).
//   3. Correctly parse all other fields.
//
// When a newer node sends "cc":true, the current code must:
//   1. Correctly set CapCollector to true.
//
// This test extends TestGossipV2_NodeMetaNoMeshIP by adding cross-version
// compatibility coverage for the CapCollector field added in commit d489512.
func TestGossipV2_NodeMetaCapCollectorCompat(t *testing.T) {
	// Case 1: Old format — msgpack WITHOUT the "cc" field.
	// This simulates a node running code before commit d489512 that did not
	// include the CapCollector flag.
	oldFormat := map[string]interface{}{
		"pk":   "oldnode000000000000000000000000000000000000000000000000000000",
		"hn":   "old-agent",
		"role": "agent",
		"cr":   false,
		"ce":   false,
		"cpe":  false,
		"eps":  []string{"10.0.0.5:51820"},
		"nt":   "full_cone",
		"lcpu": 0.3,
		"lmem": 0.5,
		"ver":  "1.0.0",
		"seq":  uint64(1),
		// NOTE: No "cc" field — old version did not have CapCollector.
	}

	data, err := msgpack.Marshal(oldFormat)
	if err != nil {
		t.Fatalf("msgpack marshal old format: %v", err)
	}

	// Verify the raw msgpack bytes do NOT contain "cc" key.
	rawStr := string(data)
	if contains(rawStr, "\x02\xa2\x63\x63") || contains(rawStr, "cc") {
		t.Error("old format msgpack contains 'cc' key — should not for cross-version test")
	}

	// Unmarshal with current code — must succeed and default CapCollector to false.
	meta, err := UnmarshalMeta(data)
	if err != nil {
		t.Fatalf("UnmarshalMeta old format (no cc field): %v", err)
	}
	if meta.CapCollector != false {
		t.Error("CapCollector should default to false when 'cc' field is absent in msgpack")
	}
	if meta.PublicKey != "oldnode000000000000000000000000000000000000000000000000000000" {
		t.Errorf("PublicKey mismatch: got %q", meta.PublicKey)
	}
	if meta.Hostname != "old-agent" {
		t.Errorf("Hostname mismatch: got %q, want 'old-agent'", meta.Hostname)
	}
	if meta.Role != "agent" {
		t.Errorf("Role mismatch: got %q, want 'agent'", meta.Role)
	}
	if len(data) > 512 {
		t.Errorf("old format serialized size %d exceeds 512-byte memberlist limit", len(data))
	}

	// Case 2: New format — msgpack WITH "cc" field set to true.
	// This simulates a node running the latest code with CapCollector=true.
	newFormat := map[string]interface{}{
		"pk":   "newnode000000000000000000000000000000000000000000000000000000",
		"hn":   "new-dashboard",
		"role": "web",
		"cc":   true,
		"eps":  []string{"10.0.0.6:51820"},
		"nt":   "full_cone",
		"ver":  "1.1.0",
		"seq":  uint64(2),
	}

	data2, err := msgpack.Marshal(newFormat)
	if err != nil {
		t.Fatalf("msgpack marshal new format: %v", err)
	}

	meta2, err := UnmarshalMeta(data2)
	if err != nil {
		t.Fatalf("UnmarshalMeta new format (cc=true): %v", err)
	}
	if meta2.CapCollector != true {
		t.Error("CapCollector should be true when 'cc' field is present and true in msgpack")
	}
	if meta2.PublicKey != "newnode000000000000000000000000000000000000000000000000000000" {
		t.Errorf("PublicKey mismatch: got %q", meta2.PublicKey)
	}
	if meta2.Hostname != "new-dashboard" {
		t.Errorf("Hostname mismatch: got %q, want 'new-dashboard'", meta2.Hostname)
	}
	if meta2.Role != "web" {
		t.Errorf("Role mismatch: got %q, want 'web'", meta2.Role)
	}
	if len(data2) > 512 {
		t.Errorf("new format serialized size %d exceeds 512-byte memberlist limit", len(data2))
	}

	t.Logf("Cross-version compat OK: old format %d bytes (no cc → CapCollector=false), new format %d bytes (cc=true → CapCollector=true)", len(data), len(data2))
}
