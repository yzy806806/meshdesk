package monitor

import (
	"context"
	"sync"
	"testing"
	"time"
)

// mockMonitorAuthChecker is a test AuthChecker that allows/denies
// based on a preset map. It is safe for concurrent use.
type mockMonitorAuthChecker struct {
	mu          sync.Mutex
	allowedPeers map[string]bool
	called      bool
}

func (m *mockMonitorAuthChecker) AuthorizeMonitorWrite(sourcePeer string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.called = true
	return m.allowedPeers[sourcePeer]
}

func (m *mockMonitorAuthChecker) wasCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.called
}

// TestAggregatorRejectsUnauthorizedPush verifies that the aggregator
// with an auth checker rejects metric pushes from peers without the
// monitor_write capability.
func TestAggregatorRejectsUnauthorizedPush(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	checker := &mockMonitorAuthChecker{
		allowedPeers: map[string]bool{
			"authorized-agent": true,
			// "unauthorized-agent" is NOT in the map
		},
	}

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4201,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	// Push metrics from an unauthorized peer
	env := &MetricEnvelope{
		SourceID: "unauthorized-agent",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "unauthorized-agent",
			Hostname:  "host",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 50.0, CoreCount: 4},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4201)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	// Write in goroutine — net.Pipe is synchronous
	go func() {
		WriteEnvelope(conn, env)
	}()

	// Give the aggregator time to process
	time.Sleep(500 * time.Millisecond)

	// Verify auth checker was called
	if !checker.wasCalled() {
		t.Error("expected auth checker to be called")
	}

	// Verify metrics were NOT stored
	latest := store.Latest("unauthorized-agent")
	if latest != nil {
		t.Error("metrics from unauthorized peer should not be stored")
	}
}

// TestAggregatorAcceptsAuthorizedPush verifies that the aggregator
// with an auth checker accepts metric pushes from authorized peers.
func TestAggregatorAcceptsAuthorizedPush(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	checker := &mockMonitorAuthChecker{
		allowedPeers: map[string]bool{
			"authorized-agent": true,
		},
	}

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4202,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: "authorized-agent",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "authorized-agent",
			Hostname:  "host",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 42.0, CoreCount: 8},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4202)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	go func() {
		WriteEnvelope(conn, env)
	}()

	time.Sleep(500 * time.Millisecond)

	// Verify auth checker was called
	if !checker.wasCalled() {
		t.Error("expected auth checker to be called")
	}

	// Verify metrics WERE stored
	latest := store.Latest("authorized-agent")
	if latest == nil {
		t.Fatal("metrics from authorized peer should be stored")
	}
	if latest.CPU.UsagePercent != 42.0 {
		t.Errorf("CPU = %f, want 42.0", latest.CPU.UsagePercent)
	}
}

// TestAggregatorNilAuthCheckerAcceptsAll verifies that a nil auth checker
// (testing mode) accepts all pushes.
func TestAggregatorNilAuthCheckerAcceptsAll(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	agg := NewAggregator(AggregatorConfig{
		Store:  store,
		Dialer: mesh,
		Port:   4203,
		// no AuthChecker — nil
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: "any-agent",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "any-agent",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 10.0},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4203)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	go func() {
		WriteEnvelope(conn, env)
	}()

	time.Sleep(500 * time.Millisecond)

	latest := store.Latest("any-agent")
	if latest == nil {
		t.Fatal("nil auth checker should accept all pushes")
	}
}
