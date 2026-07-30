package p2p

import (
	"testing"
)

// TestSetLocalEndpointsNilMemberlistNoCrash verifies that SetLocalEndpoints
// does not crash when memberlist is nil (e.g., in unit tests or before Start).
// This is important because the DEFECT-02 fix adds an UpdateNode call that
// must be guarded when memberlist hasn't been initialized yet.
func TestSetLocalEndpointsNilMemberlistNoCrash(t *testing.T) {
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
		// memberlist is nil — simulates pre-Start or unit test context
	}

	// Should not panic despite nil memberlist
	gl.SetLocalEndpoints([]string{"203.0.113.5:51820"}, "full_cone")

	meta := delegate.getLocalMeta()
	if len(meta.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(meta.Endpoints))
	}
	if meta.Endpoints[0] != "203.0.113.5:51820" {
		t.Errorf("expected endpoint 203.0.113.5:51820, got %s", meta.Endpoints[0])
	}
	if meta.NatType != "full_cone" {
		t.Errorf("expected NAT type full_cone, got %s", meta.NatType)
	}
	if meta.Seq != 2 {
		t.Errorf("expected Seq=2 after SetLocalEndpoints, got %d", meta.Seq)
	}
}

// TestSetLocalEndpointsUpdatesSeqAndNatType verifies that repeated calls
// to SetLocalEndpoints increment the sequence number and update NAT type,
// ensuring peers can detect metadata changes.
func TestSetLocalEndpointsUpdatesSeqAndNatType(t *testing.T) {
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

	// First call: set endpoints and NAT type
	gl.SetLocalEndpoints([]string{"10.0.0.1:51820"}, "restricted_cone")

	meta := delegate.getLocalMeta()
	if meta.Seq != 2 {
		t.Errorf("after first call: expected Seq=2, got %d", meta.Seq)
	}
	if meta.NatType != "restricted_cone" {
		t.Errorf("after first call: expected NAT restricted_cone, got %s", meta.NatType)
	}

	// Second call: update with different endpoints and NAT type
	gl.SetLocalEndpoints([]string{"10.0.0.2:51821"}, "symmetric")

	meta = delegate.getLocalMeta()
	if meta.Seq != 3 {
		t.Errorf("after second call: expected Seq=3, got %d", meta.Seq)
	}
	if meta.NatType != "symmetric" {
		t.Errorf("after second call: expected NAT symmetric, got %s", meta.NatType)
	}
	if len(meta.Endpoints) != 1 || meta.Endpoints[0] != "10.0.0.2:51821" {
		t.Errorf("after second call: expected endpoint 10.0.0.2:51821, got %v", meta.Endpoints)
	}
}

// TestSetLocalEndpointsEmptyEndpointsClears verifies that setting empty
// endpoints clears the Endpoints field and updates NAT type.
func TestSetLocalEndpointsEmptyEndpointsClears(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		Endpoints: []string{"203.0.113.5:51820"},
		NatType:   "full_cone",
		Seq:       5,
	}
	delegate := newMeshDelegate(localMeta)

	gl := &GossipLayer{
		cfg:      P2pConfig{},
		delegate: delegate,
	}

	gl.SetLocalEndpoints([]string{}, "unknown")

	meta := delegate.getLocalMeta()
	if len(meta.Endpoints) != 0 {
		t.Errorf("expected 0 endpoints after clearing, got %d", len(meta.Endpoints))
	}
	if meta.NatType != "unknown" {
		t.Errorf("expected NAT type unknown, got %s", meta.NatType)
	}
	if meta.Seq != 6 {
		t.Errorf("expected Seq=6, got %d", meta.Seq)
	}
}

// TestAnnounceLocalEndpointWithNilMemberlist verifies that announceLocalEndpoint
// works correctly when memberlist is nil (the DEFECT-02 fix path where
// SetLocalEndpoints is called but memberlist hasn't been started yet).
func TestAnnounceLocalEndpointWithNilMemberlist(t *testing.T) {
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
			WgPort:            51820,
		},
		delegate: delegate,
		// memberlist is nil — should still work, just skip UpdateNode
	}

	// announceLocalEndpoint calls SetLocalEndpoints internally
	gl.announceLocalEndpoint()

	meta := delegate.getLocalMeta()
	if len(meta.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(meta.Endpoints))
	}
	if meta.Endpoints[0] != "203.0.113.99:51820" {
		t.Errorf("expected endpoint 203.0.113.99:51820, got %s", meta.Endpoints[0])
	}
}
