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

// portMappedDialer wraps a MeshDialer and translates the port when dialing
// specific peer IDs. Used to test end-to-end forwarding between two
// aggregators that listen on different ports.
type portMappedDialer struct {
	underlying MeshDialer
	portMap    map[string]int // peerID → actual port
}

func (d *portMappedDialer) DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error) {
	if actual, ok := d.portMap[peerID]; ok {
		port = actual
	}
	return d.underlying.DialMesh(ctx, peerID, port)
}

// TestAggregatorForwarding_ForwardsToOtherCollectors verifies the
// end-to-end forwarding path: aggregator A receives an envelope from
// an agent, stores it locally, and forwards it to aggregator B.
// B receives the forwarded envelope, stores it locally, and does NOT
// re-forward it (because Forwarded=true).
func TestAggregatorForwarding_ForwardsToOtherCollectors(t *testing.T) {
	mesh := NewInProcMesh()

	storeA := NewStore()
	storeB := NewStore()

	// Aggregator B listens on port 4402 — it will receive forwarded
	// envelopes but does not forward itself.
	aggB := NewAggregator(AggregatorConfig{
		Store:  storeB,
		Dialer: mesh,
		Port:   4402,
	})
	if err := aggB.Start(); err != nil {
		t.Fatalf("aggB Start: %v", err)
	}
	defer aggB.Stop()

	// Aggregator A listens on port 4401 and forwards to collector B.
	// We use a portMappedDialer so that A's DialMesh to port 4401
	// is translated to B's actual port 4402.
	pDialer := &portMappedDialer{
		underlying: mesh,
		portMap:    map[string]int{"collector-B": 4402},
	}
	lister := &mockCollectorLister{
		peers: []string{"collector-B"},
	}
	aggA := NewAggregator(AggregatorConfig{
		Store:           storeA,
		Dialer:          mesh,
		Port:            4401,
		MeshDialer:      pDialer,
		CollectorLister: lister,
		SelfPeerID:      "collector-A",
	})
	if err := aggA.Start(); err != nil {
		t.Fatalf("aggA Start: %v", err)
	}
	defer aggA.Stop()

	// Simulate an agent pushing an envelope to aggregator A.
	env := &MetricEnvelope{
		SourceID: "agent-1",
		Sequence: 100,
		Metrics: &Metrics{
			NodeID:    "agent-1",
			Hostname:  "host-1",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 80.0, CoreCount: 8},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "agent-1", 4401)
	if err != nil {
		t.Fatalf("DialMesh to aggA: %v", err)
	}
	defer conn.Close()

	if err := WriteEnvelope(conn, env); err != nil {
		t.Fatalf("WriteEnvelope to aggA: %v", err)
	}

	// Wait for forwarding to complete.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if storeB.NodeCount() >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify A stored the metric locally.
	samplesA := storeA.Range("agent-1", time.Time{}, time.Time{})
	if len(samplesA) == 0 {
		t.Error("aggA should have stored the metric locally")
	}

	// Verify B received the forwarded envelope.
	samplesB := storeB.Range("agent-1", time.Time{}, time.Time{})
	if len(samplesB) == 0 {
		t.Fatal("aggB should have received the forwarded metric from aggA")
	}
	if got := samplesB[0].CPU.UsagePercent; got != 80.0 {
		t.Errorf("aggB CPU usage: got %.1f, want 80.0", got)
	}
	if got := samplesB[0].Hostname; got != "host-1" {
		t.Errorf("aggB Hostname: got %s, want host-1", got)
	}

	// Verify B has exactly one sample (no duplicates).
	if len(samplesB) != 1 {
		t.Errorf("aggB should have exactly 1 sample, got %d", len(samplesB))
	}
}

// TestAggregatorForwarding_ForwardedEnvelopeNotReForwarded verifies that
// an envelope with Forwarded=true is stored locally but NOT forwarded
// to other collectors (loop prevention at the receiving side).
func TestAggregatorForwarding_ForwardedEnvelopeNotReForwarded(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	dialer := &captureDialer{}
	lister := &mockCollectorLister{
		peers: []string{"collector-C"},
	}
	agg := NewAggregator(AggregatorConfig{
		Store:           store,
		Dialer:          mesh,
		Port:            4410,
		MeshDialer:      dialer,
		CollectorLister: lister,
		SelfPeerID:      "collector-B",
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("agg Start: %v", err)
	}
	defer agg.Stop()

	// Push an envelope that was already forwarded by another collector.
	env := &MetricEnvelope{
		SourceID:  "agent-2",
		Sequence:  200,
		Forwarded: true,
		Metrics: &Metrics{
			NodeID:    "agent-2",
			Hostname:  "host-2",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 55.0, CoreCount: 4},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "forwarder", 4410)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	if err := WriteEnvelope(conn, env); err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}

	// Wait a bit for processing.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if store.NodeCount() >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify local storage: the envelope was stored despite being Forwarded=true.
	samples := store.Range("agent-2", time.Time{}, time.Time{})
	if len(samples) == 0 {
		t.Fatal("should have stored the forwarded metric locally")
	}
	if got := samples[0].CPU.UsagePercent; got != 55.0 {
		t.Errorf("CPU usage: got %.1f, want 55.0", got)
	}

	// Verify no forwarding: Forwarded=true must NOT be re-forwarded.
	if len(dialer.getForwarded()) != 0 {
		t.Errorf("should NOT re-forward a Forwarded envelope, got %d forwards", len(dialer.getForwarded()))
	}
	if len(dialer.getDialed()) != 0 {
		t.Errorf("should NOT have dialed any peer, got %d dials", len(dialer.getDialed()))
	}
}

// TestAggregatorForwarding_DedupBySourceIDSequence verifies that the
// aggregator deduplicates envelopes by (SourceID, Sequence): when the
// same agent pushes an envelope directly and another collector forwards
// the same envelope, the receiving aggregator stores it only once.
func TestAggregatorForwarding_DedupBySourceIDSequence(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	agg := NewAggregator(AggregatorConfig{
		Store:  store,
		Dialer: mesh,
		Port:   4420,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("agg Start: %v", err)
	}
	defer agg.Stop()

	// Push the SAME envelope twice — simulating an agent that pushes
	// to two collectors, and one collector forwards to this one, so
	// the same (SourceID, Sequence) arrives twice.
	env1 := &MetricEnvelope{
		SourceID: "agent-3",
		Sequence: 42,
		Metrics: &Metrics{
			NodeID:    "agent-3",
			Hostname:  "host-3",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 33.0, CoreCount: 2},
		},
	}

	// Second push: same SourceID + Sequence but Forwarded=true
	// (simulates the copy forwarded by another collector).
	env2 := &MetricEnvelope{
		SourceID:  "agent-3",
		Sequence:  42,
		Forwarded: true,
		Metrics: &Metrics{
			NodeID:    "agent-3",
			Hostname:  "host-3",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 33.0, CoreCount: 2},
		},
	}

	for i, env := range []*MetricEnvelope{env1, env2} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := mesh.DialMesh(ctx, "sender", 4420)
		if err != nil {
			cancel()
			t.Fatalf("push %d DialMesh: %v", i+1, err)
		}
		if err := WriteEnvelope(conn, env); err != nil {
			conn.Close()
			cancel()
			t.Fatalf("push %d WriteEnvelope: %v", i+1, err)
		}
		conn.Close()
		cancel()
		// Small delay to let the aggregator process each push.
		time.Sleep(100 * time.Millisecond)
	}

	// Wait for processing to settle.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if store.NodeCount() >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The store should have exactly ONE entry for agent-3 (dedup).
	samples := store.Range("agent-3", time.Time{}, time.Time{})
	if len(samples) == 0 {
		t.Fatal("should have stored agent-3 metrics at least once")
	}
	if len(samples) != 1 {
		t.Errorf("dedup failed: expected 1 sample for agent-3, got %d (duplicate was stored)", len(samples))
	}
	if got := samples[0].CPU.UsagePercent; got != 33.0 {
		t.Errorf("CPU usage: got %.1f, want 33.0", got)
	}
}

// Ensure unused imports are referenced (json, io used indirectly via ReadEnvelope).
var _ = json.Marshal
var _ io.Reader
