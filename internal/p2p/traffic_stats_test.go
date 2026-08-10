package p2p

import (
	"testing"
)

// TestNodeMetaTrafficStatsRoundTrip verifies that traffic stats fields
// survive a marshal/unmarshal cycle.
func TestNodeMetaTrafficStatsRoundTrip(t *testing.T) {
	original := &NodeMeta{
		PublicKey:       "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Hostname:        "test-traffic",
		Role:            "relay",
		CapRelay:        true,
		Version:         "1.0.0",
		Seq:             1,
		TrafficInBytes:  123456,
		TrafficOutBytes: 789012,
		SmuxStreams:     7,
		RelayForwards:   3,
		TunRxPackets:    1000,
		TunTxPackets:    2000,
	}

	data, err := original.MarshalMeta()
	if err != nil {
		t.Fatalf("MarshalMeta: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("MarshalMeta returned empty data")
	}

	// Verify size is within memberlist's 512-byte limit.
	if len(data) > 512 {
		t.Errorf("NodeMeta serialized size %d exceeds 512-byte limit", len(data))
	}

	decoded, err := UnmarshalMeta(data)
	if err != nil {
		t.Fatalf("UnmarshalMeta: %v", err)
	}

	if decoded.TrafficInBytes != 123456 {
		t.Errorf("TrafficInBytes = %d, want 123456", decoded.TrafficInBytes)
	}
	if decoded.TrafficOutBytes != 789012 {
		t.Errorf("TrafficOutBytes = %d, want 789012", decoded.TrafficOutBytes)
	}
	if decoded.SmuxStreams != 7 {
		t.Errorf("SmuxStreams = %d, want 7", decoded.SmuxStreams)
	}
	if decoded.RelayForwards != 3 {
		t.Errorf("RelayForwards = %d, want 3", decoded.RelayForwards)
	}
	if decoded.TunRxPackets != 1000 {
		t.Errorf("TunRxPackets = %d, want 1000", decoded.TunRxPackets)
	}
	if decoded.TunTxPackets != 2000 {
		t.Errorf("TunTxPackets = %d, want 2000", decoded.TunTxPackets)
	}
}

// TestNodeMetaTrafficStatsZeroByDefault verifies that traffic stats
// default to zero when not set (omitempty).
func TestNodeMetaTrafficStatsZeroByDefault(t *testing.T) {
	original := &NodeMeta{
		PublicKey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Hostname:  "test-zero-traffic",
		Role:      "agent",
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

	if decoded.TrafficInBytes != 0 || decoded.TrafficOutBytes != 0 {
		t.Errorf("traffic should be zero by default, got in=%d out=%d", decoded.TrafficInBytes, decoded.TrafficOutBytes)
	}
	if decoded.SmuxStreams != 0 || decoded.RelayForwards != 0 {
		t.Errorf("streams/relay should be zero, got smux=%d relay=%d", decoded.SmuxStreams, decoded.RelayForwards)
	}
}

// TestSetLocalTrafficStats verifies that SetLocalTrafficStats updates
// the local metadata correctly.
func TestSetLocalTrafficStats(t *testing.T) {
	meta := &NodeMeta{
		PublicKey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Hostname:  "test-stats",
		Role:      "agent",
		Version:   "1.0.0",
		Seq:       1,
	}
	d := newMeshDelegate(meta)

	d.updateLocalMeta(func(m *NodeMeta) {
		m.TrafficInBytes = 500
		m.TrafficOutBytes = 600
		m.SmuxStreams = 2
		m.RelayForwards = 1
		m.TunRxPackets = 50
		m.TunTxPackets = 60
		m.Seq++
	})

	got := d.getLocalMeta()
	if got.TrafficInBytes != 500 {
		t.Errorf("TrafficInBytes = %d, want 500", got.TrafficInBytes)
	}
	if got.TrafficOutBytes != 600 {
		t.Errorf("TrafficOutBytes = %d, want 600", got.TrafficOutBytes)
	}
	if got.SmuxStreams != 2 {
		t.Errorf("SmuxStreams = %d, want 2", got.SmuxStreams)
	}
	if got.RelayForwards != 1 {
		t.Errorf("RelayForwards = %d, want 1", got.RelayForwards)
	}
	if got.TunRxPackets != 50 {
		t.Errorf("TunRxPackets = %d, want 50", got.TunRxPackets)
	}
	if got.TunTxPackets != 60 {
		t.Errorf("TunTxPackets = %d, want 60", got.TunTxPackets)
	}
	if got.Seq != 2 {
		t.Errorf("Seq = %d, want 2", got.Seq)
	}
}
