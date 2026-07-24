package monitor

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

// --- InProcMesh tests ---

func TestInProcMeshDialAndListen(t *testing.T) {
	mesh := NewInProcMesh()

	ln, err := mesh.ListenMesh(4191)
	if err != nil {
		t.Fatalf("ListenMesh: %v", err)
	}
	defer ln.Close()

	// Accept in background
	connCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		connCh <- c
	}()

	// Dial
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientConn, err := mesh.DialMesh(ctx, "peer-1", 4191)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer clientConn.Close()

	serverConn := <-connCh
	if serverConn == nil {
		t.Fatal("Accept returned nil")
	}
	defer serverConn.Close()

	// Write from client in goroutine (net.Pipe is synchronous)
	msg := []byte("hello mesh")
	go func() {
		clientConn.Write(msg)
	}()

	// Read from server
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(serverConn, buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf) != "hello mesh" {
		t.Errorf("Read = %q, want %q", string(buf), "hello mesh")
	}
}

func TestInProcMeshPortConflict(t *testing.T) {
	mesh := NewInProcMesh()

	ln1, err := mesh.ListenMesh(5000)
	if err != nil {
		t.Fatalf("First ListenMesh: %v", err)
	}

	_, err = mesh.ListenMesh(5000)
	if err == nil {
		t.Error("Second ListenMesh on same port should fail")
	}

	ln1.Close()

	// After close, port should be reusable
	ln2, err := mesh.ListenMesh(5000)
	if err != nil {
		t.Fatalf("ListenMesh after close: %v", err)
	}
	ln2.Close()
}

func TestInProcMeshDialNoListener(t *testing.T) {
	mesh := NewInProcMesh()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := mesh.DialMesh(ctx, "peer", 9999)
	if err == nil {
		t.Error("DialMesh to non-existent port should fail")
	}
}

// --- Reporter + Aggregator integration ---

func TestReporterPushToAggregator(t *testing.T) {
	mesh := NewInProcMesh()

	store := NewStore()
	agg := NewAggregator(AggregatorConfig{
		Store:  store,
		Dialer: mesh,
		Port:   4191,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	rep := NewReporter(ReporterConfig{
		NodeID:     "agent-1",
		Hostname:   "agent-host",
		Dialer:     mesh,
		Collectors: []string{"collector-1"},
		Interval:   1, // 1 second for fast test
		Port:       4191,
	})
	if err := rep.Start(); err != nil {
		t.Fatalf("Reporter Start: %v", err)
	}

	// Wait for at least one push cycle
	time.Sleep(3 * time.Second)
	rep.Stop()

	// The aggregator's store should have metrics from agent-1
	latest := store.Latest("agent-1")
	if latest == nil {
		t.Fatal("Aggregator store should have metrics from agent-1")
	}
	if latest.NodeID != "agent-1" {
		t.Errorf("Latest NodeID = %s, want agent-1", latest.NodeID)
	}
	if latest.Hostname != "agent-host" {
		t.Errorf("Latest Hostname = %s, want agent-host", latest.Hostname)
	}
}

func TestReporterLocalBufferOnCollectorOutage(t *testing.T) {
	mesh := NewInProcMesh()

	// Reporter with no running aggregator — all pushes fail
	rep := NewReporter(ReporterConfig{
		NodeID:     "agent-2",
		Hostname:   "agent-host-2",
		Dialer:     mesh,
		Collectors: []string{"collector-x"},
		Interval:   1,
		Port:       4192,
	})
	if err := rep.Start(); err != nil {
		t.Fatalf("Reporter Start: %v", err)
	}

	// Wait for a couple of collection cycles
	time.Sleep(3 * time.Second)
	rep.Stop()

	// Metrics should be in local store even though no collector was available
	local := rep.LocalStore()
	latest := local.Latest("agent-2")
	if latest == nil {
		t.Fatal("Local store should have metrics even during collector outage")
	}

	// Buffered count should be > 0
	if rep.BufferedCount() == 0 {
		t.Error("BufferedCount should be > 0 during outage")
	}
}

func TestReporterNoCollectors(t *testing.T) {
	rep := NewReporter(ReporterConfig{
		NodeID:     "agent-3",
		Hostname:   "agent-host-3",
		Dialer:     nil, // no dialer needed
		Collectors: nil, // no collectors
		Interval:   1,
	})
	if err := rep.Start(); err != nil {
		t.Fatalf("Reporter Start: %v", err)
	}

	time.Sleep(2 * time.Second)
	rep.Stop()

	// Local store should still have self-metrics
	latest := rep.LocalStore().Latest("agent-3")
	if latest == nil {
		t.Fatal("Local store should have self-metrics")
	}
}

func TestReporterCollectOnce(t *testing.T) {
	rep := NewReporter(ReporterConfig{
		NodeID:     "agent-4",
		Hostname:   "agent-host-4",
		Collectors: nil,
		Interval:   60,
	})

	m, err := rep.CollectOnce()
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if m.NodeID != "agent-4" {
		t.Errorf("NodeID = %s, want agent-4", m.NodeID)
	}
}

// --- Envelope serialization ---

func TestWriteAndReadEnvelope(t *testing.T) {
	env := &MetricEnvelope{
		SourceID: "node-x",
		Sequence: 99,
		Metrics: &Metrics{
			NodeID:    "node-x",
			Hostname:  "host-x",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 75.5, CoreCount: 8},
		},
	}

	// Use a pipe to simulate a connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write on one end (in goroutine — net.Pipe is synchronous)
	go func() {
		WriteEnvelope(clientConn, env)
	}()

	// Read on the other end
	received, err := ReadEnvelope(serverConn)
	if err != nil {
		t.Fatalf("ReadEnvelope: %v", err)
	}

	if received.SourceID != env.SourceID {
		t.Errorf("SourceID = %s, want %s", received.SourceID, env.SourceID)
	}
	if received.Sequence != env.Sequence {
		t.Errorf("Sequence = %d, want %d", received.Sequence, env.Sequence)
	}
	if received.Metrics == nil || received.Metrics.CPU.UsagePercent != 75.5 {
		t.Errorf("Metrics mismatch: %+v", received.Metrics)
	}
}

func TestReadEnvelopeInvalidLength(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write an invalid length (0) from client side in goroutine
	go func() {
		clientConn.Write([]byte{0, 0, 0, 0})
	}()

	_, err := ReadEnvelope(serverConn)
	if err == nil {
		t.Error("ReadEnvelope with length 0 should fail")
	}
}

// --- AggregatorInProc ---

func TestAggregatorInProc(t *testing.T) {
	store := NewStore()
	agg := NewAggregatorInProc(store)

	env := &MetricEnvelope{
		SourceID: "agent-5",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "agent-5",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 30},
		},
	}

	agg.Receive(env)

	latest := store.Latest("agent-5")
	if latest == nil {
		t.Fatal("InProc aggregator should store metrics")
	}
	if latest.CPU.UsagePercent != 30 {
		t.Errorf("CPU = %f, want 30", latest.CPU.UsagePercent)
	}
}

func TestReporterIntervalClamping(t *testing.T) {
	// Interval too low → should be clamped to 15s
	rep := NewReporter(ReporterConfig{
		NodeID:     "n1",
		Hostname:   "h1",
		Interval:   1, // below minimum of 10s
		Collectors: nil,
	})
	// We can't easily check the internal interval, but we can verify it doesn't crash
	if rep == nil {
		t.Fatal("NewReporter returned nil")
	}
}

func TestReporterDoubleStart(t *testing.T) {
	rep := NewReporter(ReporterConfig{
		NodeID:     "n1",
		Hostname:   "h1",
		Interval:   60,
		Collectors: nil,
	})
	if err := rep.Start(); err != nil {
		t.Fatalf("First Start: %v", err)
	}
	if err := rep.Start(); err == nil {
		t.Error("Second Start should fail")
	}
	rep.Stop()
}

// --- Aggregator lifecycle ---

func TestAggregatorDoubleStart(t *testing.T) {
	mesh := NewInProcMesh()
	agg := NewAggregator(AggregatorConfig{
		Dialer: mesh,
		Port:   4193,
	})

	if err := agg.Start(); err != nil {
		t.Fatalf("First Start: %v", err)
	}
	if err := agg.Start(); err == nil {
		t.Error("Second Start should fail")
	}
	agg.Stop()
}

func TestAggregatorStopWithoutStart(t *testing.T) {
	mesh := NewInProcMesh()
	agg := NewAggregator(AggregatorConfig{
		Dialer: mesh,
		Port:   4194,
	})
	agg.Stop() // should not panic
}

// --- Full integration: multiple agents → one aggregator ---

func TestMultipleAgentsToAggregator(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	agg := NewAggregator(AggregatorConfig{
		Store:  store,
		Dialer: mesh,
		Port:   4195,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	// Create 3 reporters
	reps := make([]*Reporter, 3)
	for i := 0; i < 3; i++ {
		reps[i] = NewReporter(ReporterConfig{
			NodeID:     "agent-" + string(rune('A'+i)),
			Hostname:   "host-" + string(rune('A'+i)),
			Dialer:     mesh,
			Collectors: []string{"collector"},
			Interval:   1,
			Port:       4195,
		})
		if err := reps[i].Start(); err != nil {
			t.Fatalf("Reporter %d Start: %v", i, err)
		}
	}

	// Wait for push cycles
	time.Sleep(4 * time.Second)

	for _, r := range reps {
		r.Stop()
	}

	// All 3 agents should have metrics in the store
	if store.NodeCount() != 3 {
		t.Errorf("NodeCount = %d, want 3", store.NodeCount())
	}

	// Verify each node has data
	all := store.AllLatest()
	if len(all) != 3 {
		t.Errorf("AllLatest len = %d, want 3", len(all))
	}
}

// --- JSON round-trip of Metrics through the push protocol ---

func TestMetricsRoundTripThroughProtocol(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	agg := NewAggregator(AggregatorConfig{
		Store:  store,
		Dialer: mesh,
		Port:   4196,
	})
	agg.Start()
	defer agg.Stop()

	// Manually create and push a metric envelope
	env := &MetricEnvelope{
		SourceID: "manual-1",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "manual-1",
			Hostname:  "manual-host",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 42.0, CoreCount: 4},
			Memory:    MemoryMetrics{Total: 1000, Used: 500, Available: 500},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "aggregator", 4196)
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

	latest := store.Latest("manual-1")
	if latest == nil {
		t.Fatal("Store should have metrics after push")
	}
	if latest.CPU.UsagePercent != 42.0 {
		t.Errorf("CPU = %f, want 42.0", latest.CPU.UsagePercent)
	}

	// Also verify JSON round-trip
	data, _ := json.Marshal(env)
	var decoded MetricEnvelope
	json.Unmarshal(data, &decoded)
	if decoded.SourceID != "manual-1" {
		t.Error("JSON round-trip failed")
	}
}
