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
