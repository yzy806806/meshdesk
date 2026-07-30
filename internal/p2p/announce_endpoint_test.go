package p2p

import (
	"strings"
	"testing"
)

// TestAnnounceLocalEndpointWithAdvertiseEndpoints tests that when
// AdvertiseEndpoints is set in the config, announceLocalEndpoint uses them
// verbatim and populates NodeMeta.Endpoints.
func TestAnnounceLocalEndpointWithAdvertiseEndpoints(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		Endpoints: []string{},
		NatType:   "unknown",
		Seq:       1,
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg: P2pConfig{
			AdvertiseEndpoints: []string{"203.0.113.99:51820"},
			WgPort:             51820,
		},
		delegate: delegate,
	}

	gl.announceLocalEndpoint()

	meta := delegate.getLocalMeta()
	if len(meta.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(meta.Endpoints))
	}
	if meta.Endpoints[0] != "203.0.113.99:51820" {
		t.Errorf("expected endpoint 203.0.113.99:51820, got %s", meta.Endpoints[0])
	}
	if meta.Seq != 2 {
		t.Errorf("expected Seq=2 after announce, got %d", meta.Seq)
	}
}

// TestAnnounceLocalEndpointWithWgPort tests that when no AdvertiseEndpoints
// is set but WgPort is configured, announceLocalEndpoint auto-detects the
// outbound IP and appends the WgPort.
func TestAnnounceLocalEndpointWithWgPort(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		Endpoints: []string{},
		NatType:   "unknown",
		Seq:       1,
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg: P2pConfig{
			WgPort: 51820,
		},
		delegate: delegate,
	}

	gl.announceLocalEndpoint()

	meta := delegate.getLocalMeta()
	if len(meta.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint from auto-detection, got %d", len(meta.Endpoints))
	}
	// The endpoint should end with :51820
	if !strings.HasSuffix(meta.Endpoints[0], ":51820") {
		t.Errorf("expected endpoint ending with :51820, got %s", meta.Endpoints[0])
	}
	// The IP should be non-empty and not 0.0.0.0
	ep := meta.Endpoints[0]
	if strings.HasPrefix(ep, "0.0.0.0:") || strings.HasPrefix(ep, ":") {
		t.Errorf("expected a real IP in endpoint, got %s", ep)
	}
}

// TestAnnounceLocalEndpointNoConfig tests that when neither AdvertiseEndpoints
// nor WgPort is set, announceLocalEndpoint does nothing (endpoints stay empty).
func TestAnnounceLocalEndpointNoConfig(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		Endpoints: []string{},
		NatType:   "unknown",
		Seq:       1,
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg:      P2pConfig{},
		delegate: delegate,
	}

	gl.announceLocalEndpoint()

	meta := delegate.getLocalMeta()
	if len(meta.Endpoints) != 0 {
		t.Errorf("expected 0 endpoints with no config, got %d", len(meta.Endpoints))
	}
	if meta.Seq != 1 {
		t.Errorf("Seq should not change when no endpoint announced, got %d", meta.Seq)
	}
}

// TestAnnounceLocalEndpointAdvertiseOverridesAutoDetect tests that
// AdvertiseEndpoints takes priority over auto-detection.
func TestAnnounceLocalEndpointAdvertiseOverridesAutoDetect(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		Endpoints: []string{},
		NatType:   "unknown",
		Seq:       1,
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg: P2pConfig{
			AdvertiseEndpoints: []string{"198.51.100.1:12345"},
			WgPort:             51820,
		},
		delegate: delegate,
	}

	gl.announceLocalEndpoint()

	meta := delegate.getLocalMeta()
	if len(meta.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(meta.Endpoints))
	}
	// Should use the explicit endpoint, not the auto-detected one with WgPort
	if meta.Endpoints[0] != "198.51.100.1:12345" {
		t.Errorf("expected advertised endpoint 198.51.100.1:12345, got %s", meta.Endpoints[0])
	}
}

// TestAnnounceLocalEndpointMultipleAdvertiseEndpoints tests that when
// multiple AdvertiseEndpoints are set, all of them are announced.
func TestAnnounceLocalEndpointMultipleAdvertiseEndpoints(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		Endpoints: []string{},
		NatType:   "unknown",
		Seq:       1,
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg: P2pConfig{
			AdvertiseEndpoints: []string{"203.0.113.99:51820", "[2001:db8::1]:51820"},
			WgPort:             51820,
		},
		delegate: delegate,
	}

	gl.announceLocalEndpoint()

	meta := delegate.getLocalMeta()
	if len(meta.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(meta.Endpoints))
	}
	if meta.Endpoints[0] != "203.0.113.99:51820" {
		t.Errorf("expected first endpoint 203.0.113.99:51820, got %s", meta.Endpoints[0])
	}
	if meta.Endpoints[1] != "[2001:db8::1]:51820" {
		t.Errorf("expected second endpoint [2001:db8::1]:51820, got %s", meta.Endpoints[1])
	}
	if meta.Seq != 2 {
		t.Errorf("expected Seq=2 after announce, got %d", meta.Seq)
	}
}

// TestAnnounceLocalEndpointPreservesDiscoveredEndpoints verifies that
// announceLocalEndpoint does NOT erase endpoints previously added by
// OnEndpointDiscovered.  This is the core regression test for the bug where
// SetLocalEndpoints was called with only the advertised endpoints, wiping
// reactively-learned addresses.
func TestAnnounceLocalEndpointPreservesDiscoveredEndpoints(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		Endpoints: []string{},
		NatType:   "unknown",
		Seq:       1,
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg: P2pConfig{
			AdvertiseEndpoints: []string{"203.0.113.99:51820"},
			WgPort:             51820,
		},
		delegate: delegate,
	}

	// 1. Simulate a discovered endpoint from the WireGuard receive path.
	gl.OnEndpointDiscovered("peerkey123", "192.0.2.50:51820")

	meta := delegate.getLocalMeta()
	if len(meta.Endpoints) != 1 {
		t.Fatalf("after OnEndpointDiscovered: expected 1 endpoint, got %d", len(meta.Endpoints))
	}
	if meta.Endpoints[0] != "192.0.2.50:51820" {
		t.Errorf("expected discovered endpoint 192.0.2.50:51820, got %s", meta.Endpoints[0])
	}

	// 2. Now call announceLocalEndpoint — it should MERGE, not replace.
	gl.announceLocalEndpoint()

	meta = delegate.getLocalMeta()
	if len(meta.Endpoints) != 2 {
		t.Fatalf("after announceLocalEndpoint: expected 2 endpoints (merged), got %d: %v", len(meta.Endpoints), meta.Endpoints)
	}

	// The advertised endpoint should be first (primary), discovered second.
	if meta.Endpoints[0] != "203.0.113.99:51820" {
		t.Errorf("expected first endpoint to be advertised 203.0.113.99:51820, got %s", meta.Endpoints[0])
	}
	if meta.Endpoints[1] != "192.0.2.50:51820" {
		t.Errorf("expected second endpoint to be discovered 192.0.2.50:51820, got %s", meta.Endpoints[1])
	}
}

// TestAnnounceLocalEndpointDeduplicatesOverlappingEndpoints verifies that
// when an advertised endpoint is the same as an already-discovered one,
// announceLocalEndpoint does not duplicate it.
func TestAnnounceLocalEndpointDeduplicatesOverlappingEndpoints(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		Endpoints: []string{"203.0.113.99:51820"}, // already discovered
		NatType:   "unknown",
		Seq:       1,
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg: P2pConfig{
			AdvertiseEndpoints: []string{"203.0.113.99:51820"}, // same as existing
			WgPort:             51820,
		},
		delegate: delegate,
	}

	gl.announceLocalEndpoint()

	meta := delegate.getLocalMeta()
	if len(meta.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint after dedup, got %d: %v", len(meta.Endpoints), meta.Endpoints)
	}
	if meta.Endpoints[0] != "203.0.113.99:51820" {
		t.Errorf("expected endpoint 203.0.113.99:51820, got %s", meta.Endpoints[0])
	}
}

// TestMergeEndpoints tests the mergeEndpoints helper directly.
func TestMergeEndpoints(t *testing.T) {
	tests := []struct {
		name    string
		primary []string
		extra   []string
		want    []string
	}{
		{
			name:    "both empty",
			primary: nil,
			extra:   nil,
			want:    []string{},
		},
		{
			name:    "primary only",
			primary: []string{"a:1", "b:2"},
			extra:   nil,
			want:    []string{"a:1", "b:2"},
		},
		{
			name:    "extra only",
			primary: nil,
			extra:   []string{"c:3"},
			want:    []string{"c:3"},
		},
		{
			name:    "no overlap",
			primary: []string{"a:1", "b:2"},
			extra:   []string{"c:3", "d:4"},
			want:    []string{"a:1", "b:2", "c:3", "d:4"},
		},
		{
			name:    "full overlap",
			primary: []string{"a:1", "b:2"},
			extra:   []string{"a:1", "b:2"},
			want:    []string{"a:1", "b:2"},
		},
		{
			name:    "partial overlap",
			primary: []string{"a:1", "b:2"},
			extra:   []string{"b:2", "c:3"},
			want:    []string{"a:1", "b:2", "c:3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeEndpoints(tt.primary, tt.extra)
			if len(got) != len(tt.want) {
				t.Fatalf("expected %d items, got %d: %v", len(tt.want), len(got), got)
			}
			for i, ep := range got {
				if ep != tt.want[i] {
					t.Errorf("index %d: expected %s, got %s", i, tt.want[i], ep)
				}
			}
		})
	}
}

// TestDetectOutboundIP tests that detectOutboundIP returns a non-empty,
// non-loopback IPv4 address (or empty string if no network is available,
// which shouldn't happen in CI).
func TestDetectOutboundIP(t *testing.T) {
	ip := detectOutboundIP()
	if ip == "" {
		t.Skip("no outbound IP detected (likely no network in CI)")
	}
	if ip == "0.0.0.0" {
		t.Error("detectOutboundIP returned 0.0.0.0")
	}
	if strings.HasPrefix(ip, "127.") {
		t.Errorf("detectOutboundIP returned loopback address: %s", ip)
	}
}
