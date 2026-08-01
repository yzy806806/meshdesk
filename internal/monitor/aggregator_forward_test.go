package monitor

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// mockCollectorLister is a test CollectorLister that returns a preset
// list of collector peer IDs.
type mockCollectorLister struct {
	mu     sync.Mutex
	peers  []string
	called bool
}

func (m *mockCollectorLister) CollectorPeerIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.called = true
	return m.peers
}

func (m *mockCollectorLister) wasCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.called
}

func (m *mockCollectorLister) setPeers(peers []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers = peers
}

// captureDialer is a test MeshDialer that captures forwarded envelopes.
// Each DialMesh call creates a net.Pipe; the dialer reads the envelope
// from its end and stores it for inspection.
type captureDialer struct {
	mu        sync.Mutex
	forwarded []*MetricEnvelope
	dialed    []string // peer IDs that were dialed
}

func (d *captureDialer) DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error) {
	c1, c2 := net.Pipe()

	d.mu.Lock()
	d.dialed = append(d.dialed, peerID)
	d.mu.Unlock()

	// Read the envelope from c2 in a goroutine.
	go func() {
		defer c2.Close()
		env, err := ReadEnvelope(c2)
		if err != nil {
			return
		}
		d.mu.Lock()
		d.forwarded = append(d.forwarded, env)
		d.mu.Unlock()
	}()

	return c1, nil
}

func (d *captureDialer) getForwarded() []*MetricEnvelope {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.forwarded
}

func (d *captureDialer) getDialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dialed
}

// TestAggregatorForwardsToCollectors verifies that the aggregator forwards
// non-forwarded envelopes to all known collector peers, setting Forwarded=true.
func TestAggregatorForwardsToCollectors(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	dialer := &captureDialer{}
	lister := &mockCollectorLister{
		peers: []string{"collector-B", "collector-C"},
	}
	agg := NewAggregator(AggregatorConfig{
		Store:           store,
		Dialer:          mesh,
		Port:            4201,
		MeshDialer:      dialer,
		CollectorLister: lister,
		SelfPeerID:      "collector-A",
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("agg Start: %v", err)
	}
	defer agg.Stop()

	// Push a non-forwarded envelope.
	env := &MetricEnvelope{
		SourceID: "agent-1",
		Sequence: 42,
		Metrics: &Metrics{
			NodeID:    "agent-1",
			Hostname:  "host-1",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 75.0, CoreCount: 4},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test-sender", 4201)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	if err := WriteEnvelope(conn, env); err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}

	// Wait for forwarding to complete.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(dialer.getForwarded()) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify local store.
	samples := store.Range("agent-1", time.Time{}, time.Time{})
	if len(samples) == 0 {
		t.Error("aggregator should have stored the metric locally")
	}

	// Verify forwarding.
	forwarded := dialer.getForwarded()
	if len(forwarded) != 2 {
		t.Fatalf("expected 2 forwarded envelopes, got %d", len(forwarded))
	}
	for _, fwd := range forwarded {
		if !fwd.Forwarded {
			t.Error("forwarded envelope should have Forwarded=true")
		}
		if fwd.SourceID != "agent-1" {
			t.Errorf("forwarded SourceID: got %s, want agent-1", fwd.SourceID)
		}
		if fwd.Sequence != 42 {
			t.Errorf("forwarded Sequence: got %d, want 42", fwd.Sequence)
		}
		if fwd.Metrics.CPU.UsagePercent != 75.0 {
			t.Errorf("forwarded CPU: got %.1f, want 75.0", fwd.Metrics.CPU.UsagePercent)
		}
	}

	// Verify both peers were dialed.
	dialed := dialer.getDialed()
	if len(dialed) != 2 {
		t.Fatalf("expected 2 dials, got %d", len(dialed))
	}
	// Both collector-B and collector-C should be dialed (not collector-A).
	for _, id := range dialed {
		if id == "collector-A" {
			t.Error("should not have dialed self (collector-A)")
		}
	}
}

// TestAggregatorSkipsForwardedEnvelopes verifies that envelopes with
// Forwarded=true are NOT re-forwarded (loop prevention).
func TestAggregatorSkipsForwardedEnvelopes(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	dialer := &captureDialer{}
	lister := &mockCollectorLister{
		peers: []string{"collector-B"},
	}
	agg := NewAggregator(AggregatorConfig{
		Store:           store,
		Dialer:          mesh,
		Port:            4202,
		MeshDialer:      dialer,
		CollectorLister: lister,
		SelfPeerID:      "collector-A",
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("agg Start: %v", err)
	}
	defer agg.Stop()

	// Push a Forwarded=true envelope.
	env := &MetricEnvelope{
		SourceID:  "agent-1",
		Sequence:  99,
		Forwarded: true,
		Metrics: &Metrics{
			NodeID:    "agent-1",
			Hostname:  "host-1",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 30.0, CoreCount: 2},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test-sender", 4202)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	if err := WriteEnvelope(conn, env); err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}

	// Give the aggregator time to process.
	time.Sleep(500 * time.Millisecond)

	// Should have stored locally.
	samples := store.Range("agent-1", time.Time{}, time.Time{})
	if len(samples) == 0 {
		t.Error("should have stored the forwarded metric locally")
	}

	// Should NOT have forwarded anything.
	if len(dialer.getForwarded()) != 0 {
		t.Errorf("should not re-forward a Forwarded envelope, got %d forwards", len(dialer.getForwarded()))
	}
}

// TestAggregatorSkipsSelfInForwarding verifies that the aggregator does
// not forward envelopes to itself.
func TestAggregatorSkipsSelfInForwarding(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	dialer := &captureDialer{}
	lister := &mockCollectorLister{
		peers: []string{"collector-A", "collector-B"},
	}
	agg := NewAggregator(AggregatorConfig{
		Store:           store,
		Dialer:          mesh,
		Port:            4203,
		MeshDialer:      dialer,
		CollectorLister: lister,
		SelfPeerID:      "collector-A",
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("agg Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: "agent-1",
		Sequence: 7,
		Metrics: &Metrics{
			NodeID:    "agent-1",
			Hostname:  "host-1",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 60.0, CoreCount: 4},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test-sender", 4203)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	if err := WriteEnvelope(conn, env); err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}

	// Wait for forwarding.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(dialer.getDialed()) >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Should have dialed only collector-B, not collector-A (self).
	dialed := dialer.getDialed()
	if len(dialed) != 1 {
		t.Fatalf("expected 1 dial (collector-B only), got %d: %v", len(dialed), dialed)
	}
	if dialed[0] != "collector-B" {
		t.Errorf("expected dial to collector-B, got %s", dialed[0])
	}
}

// TestAggregatorNoForwardingWithoutConfig verifies that the aggregator
// does not attempt forwarding when MeshDialer or CollectorLister is nil.
func TestAggregatorNoForwardingWithoutConfig(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	// No MeshDialer or CollectorLister — forwarding disabled.
	agg := NewAggregator(AggregatorConfig{
		Store: store,
		Dialer: mesh,
		Port:  4204,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("agg Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: "agent-1",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "agent-1",
			Hostname:  "host-1",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 50.0, CoreCount: 4},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test-sender", 4204)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	if err := WriteEnvelope(conn, env); err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}

	// Give it a moment to process.
	time.Sleep(300 * time.Millisecond)

	// Should have stored locally.
	samples := store.Range("agent-1", time.Time{}, time.Time{})
	if len(samples) == 0 {
		t.Error("should have stored the metric locally even without forwarding config")
	}
}

// Ensure unused imports are referenced (json, io used indirectly via ReadEnvelope).
var _ = json.Marshal
var _ io.Reader
