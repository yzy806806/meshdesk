package monitor

import (
	"testing"
	"time"
)

// TestTrafficProviderEnrichment verifies that the reporter correctly
// enriches metrics with traffic stats when a traffic provider is set.
func TestTrafficProviderEnrichment(t *testing.T) {
	// Create a reporter with a traffic provider that returns known values.
	reporter := NewReporter(ReporterConfig{
		NodeID:   "test-node",
		Hostname: "test-host",
		Interval: 60,
	})

	reporter.SetTrafficProvider(func() TrafficSnapshot {
		return TrafficSnapshot{
			InBytes:       1024,
			OutBytes:      2048,
			SmuxStreams:   3,
			RelayForwards: 1,
			TunRxPackets:  100,
			TunTxPackets:  200,
			PeerCount:     5,
		}
	})

	// Call collectAndPush directly (it won't push without collectors).
	reporter.collectAndPush()

	// Verify the local store has the enriched metrics.
	m := reporter.LocalStore().Latest("test-node")
	if m == nil {
		t.Fatal("expected metrics in local store")
	}

	if m.Traffic.InBytes != 1024 {
		t.Errorf("InBytes = %d, want 1024", m.Traffic.InBytes)
	}
	if m.Traffic.OutBytes != 2048 {
		t.Errorf("OutBytes = %d, want 2048", m.Traffic.OutBytes)
	}
	if m.Traffic.SmuxStreams != 3 {
		t.Errorf("SmuxStreams = %d, want 3", m.Traffic.SmuxStreams)
	}
	if m.Traffic.RelayForwards != 1 {
		t.Errorf("RelayForwards = %d, want 1", m.Traffic.RelayForwards)
	}
	if m.Traffic.TunRxPackets != 100 {
		t.Errorf("TunRxPackets = %d, want 100", m.Traffic.TunRxPackets)
	}
	if m.Traffic.TunTxPackets != 200 {
		t.Errorf("TunTxPackets = %d, want 200", m.Traffic.TunTxPackets)
	}
	if m.Traffic.PeerCount != 5 {
		t.Errorf("PeerCount = %d, want 5", m.Traffic.PeerCount)
	}
}

// TestTrafficProviderZeroWhenNotSet verifies that metrics have zero
// traffic stats when no provider is set.
func TestTrafficProviderZeroWhenNotSet(t *testing.T) {
	reporter := NewReporter(ReporterConfig{
		NodeID:   "test-node",
		Hostname: "test-host",
		Interval: 60,
	})

	// Don't set a traffic provider.
	reporter.collectAndPush()

	m := reporter.LocalStore().Latest("test-node")
	if m == nil {
		t.Fatal("expected metrics in local store")
	}

	if m.Traffic.InBytes != 0 || m.Traffic.OutBytes != 0 {
		t.Errorf("traffic should be zero without provider, got in=%d out=%d", m.Traffic.InBytes, m.Traffic.OutBytes)
	}
	if m.Traffic.PeerCount != 0 {
		t.Errorf("PeerCount should be 0, got %d", m.Traffic.PeerCount)
	}
}

// TestTrafficMetricsJSON verifies that TrafficMetrics serializes to JSON correctly.
func TestTrafficMetricsJSON(t *testing.T) {
	m := &Metrics{
		Timestamp: time.Now().UTC(),
		NodeID:    "test",
		Hostname:  "host",
		Traffic: TrafficMetrics{
			InBytes:       12345,
			OutBytes:      67890,
			SmuxStreams:   2,
			RelayForwards: 1,
			TunRxPackets:  100,
			TunTxPackets:  200,
			PeerCount:     3,
		},
	}

	data, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := DecodeMetrics(data)
	if err != nil {
		t.Fatalf("DecodeMetrics: %v", err)
	}

	if decoded.Traffic.InBytes != 12345 {
		t.Errorf("InBytes = %d, want 12345", decoded.Traffic.InBytes)
	}
	if decoded.Traffic.OutBytes != 67890 {
		t.Errorf("OutBytes = %d, want 67890", decoded.Traffic.OutBytes)
	}
	if decoded.Traffic.SmuxStreams != 2 {
		t.Errorf("SmuxStreams = %d, want 2", decoded.Traffic.SmuxStreams)
	}
	if decoded.Traffic.RelayForwards != 1 {
		t.Errorf("RelayForwards = %d, want 1", decoded.Traffic.RelayForwards)
	}
	if decoded.Traffic.PeerCount != 3 {
		t.Errorf("PeerCount = %d, want 3", decoded.Traffic.PeerCount)
	}
}
