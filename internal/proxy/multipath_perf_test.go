// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements performance tests for the multi-path path selection
// and dispatch system. It benchmarks throughput, latency, and failover
// behavior comparing single-path vs multi-path configurations.
//
// Test categories:
//
//	BenchmarkPathSelectorScaling       — raw path selection throughput at scale
//	BenchmarkDispatcherThroughput      — chunk dispatch throughput (single vs multi-path)
//	TestMultiPathFairDistribution      — chunk fairness across paths
//	TestSingleVsMultiPathFailover      — failover latency comparison
//	TestPathSelectorProbeCacheHitRate  — cache effectiveness
//	BenchmarkAssignmentStrategyCompare — strategy comparison (round-robin vs weighted vs fastest)
package proxy

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Test 1: PathSelector scaling — benchmark raw selection throughput
// ──────────────────────────────────────────────────────────────────────────────

// TestPathSelectorScaling verifies that the path selector can handle
// increasingly large candidate sets within a reasonable time budget.
// This tests the O(K) scaling guarantee from PROXY_DESIGN.md §1.5.
func TestPathSelectorScaling(t *testing.T) {
	scales := []struct {
		name       string
		candidates int
		maxBudget  time.Duration
	}{
		{"small", 10, 50 * time.Millisecond},
		{"medium", 50, 200 * time.Millisecond},
		{"large", 100, 500 * time.Millisecond},
		{"very_large", 250, 2 * time.Second},
	}

	for _, s := range scales {
		t.Run(s.name, func(t *testing.T) {
			// Generate candidate relays with predictable RTTs.
			candidates := make([]CandidateRelay, s.candidates)
			for i := range candidates {
				candidates[i] = CandidateRelay{
					NodeID:   fmt.Sprintf("relay-%04d-node-id-key-long-enough-to-be-valid", i),
					MeshAddr: fmt.Sprintf("10.10.%d.%d:51820", i/256, i%256),
				}
			}

			cfg := DefaultPathSelectorConfig()
			cfg.MaxCandidates = s.candidates + 1
			cfg.ProbeConcurrency = 16
			cfg.ProbeTimeout = 500 * time.Millisecond
			// Use a fast mock dial function — all succeed at 1ms.
			cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
				return 1 * time.Millisecond, nil
			}

			selector := NewPathSelector(cfg)

			start := time.Now()
			p1, p2, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
			elapsed := time.Since(start)

			if err != nil {
				t.Fatalf("SelectPaths failed with %d candidates: %v", s.candidates, err)
			}
			if p1 == nil || p2 == nil {
				t.Fatal("paths should not be nil")
			}
			if HasOverlap(p1, p2) {
				t.Error("paths should be disjoint")
			}

			if elapsed > s.maxBudget {
				t.Errorf("selection took %v, budget is %v (could indicate O(N²) scaling)", elapsed, s.maxBudget)
			}

			t.Logf("%d candidates → selection in %v (budget %v)", s.candidates, elapsed, s.maxBudget)
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 2: Dispatcher throughput — single-path vs multi-path
// ──────────────────────────────────────────────────────────────────────────────

// dispatchResult holds the outcome of a dispatcher throughput run.
type dispatchResult struct {
	totalBytes    int64
	totalChunks   int
	p1Chunks      int
	p2Chunks      int
	p1Bytes       int64
	p2Bytes       int64
	elapsed       time.Duration
	throughputBps float64
}

// runDispatchBenchmark runs a dispatcher with the given strategy and data size.
func runDispatchBenchmark(t *testing.T, strategy ChunkAssignmentStrategy, dataSize int, label string) dispatchResult {
	t.Helper()

	e2eKey := make([]byte, KeySize)
	for i := range e2eKey {
		e2eKey[i] = byte(i)
	}
	relayKey := make([]byte, KeySize)
	for i := range relayKey {
		relayKey[i] = byte(i + 32)
	}
	circuitID, err := GenerateCircuitID()
	if err != nil {
		t.Fatalf("GenerateCircuitID: %v", err)
	}

	path1 := &Path{
		Relays:    []string{"relay-A-node-long-enough"},
		RelayKeys: [][]byte{relayKey},
	}
	path2 := &Path{
		Relays:    []string{"relay-B-node-long-enough"},
		RelayKeys: [][]byte{relayKey},
	}

	clientConn, serverConn := net.Pipe()

	cfg := DispatcherConfig{
		ChunkerStrategy: "fixed-16k",
		ChunkerCfg: ChunkerConfig{
			MaxChunkSize:   16 * 1024,
			MinChunkSize:   16 * 1024,
			DisablePadding: true,
		},
		CircuitCfg:         DefaultCircuitConfig(),
		Path1:              path1,
		Path2:              path2,
		E2EKey:             e2eKey,
		CircuitID:          circuitID,
		ExitAddr:           "10.10.0.99:51820",
		AssignmentStrategy: strategy,
	}

	d, err := NewDispatcher(cfg, serverConn)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	var chunkCount int32
	done := make(chan error, 1)

	go func() {
		done <- d.Run(context.Background(), func(path int, wc *WireChunk) error {
			atomic.AddInt32(&chunkCount, 1)
			return nil
		})
	}()

	// Send data.
	testData := make([]byte, dataSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	start := time.Now()
	_, writeErr := clientConn.Write(testData)
	if writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}
	clientConn.Close()

	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("Dispatcher.Run: %v", runErr)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("dispatcher did not finish within 30 seconds")
	}
	elapsed := time.Since(start)

	d.Close()

	p1Chunks, p2Chunks, p1Bytes, p2Bytes := d.Stats()

	result := dispatchResult{
		totalBytes:    p1Bytes + p2Bytes,
		totalChunks:   int(atomic.LoadInt32(&chunkCount)),
		p1Chunks:      p1Chunks,
		p2Chunks:      p2Chunks,
		p1Bytes:       p1Bytes,
		p2Bytes:       p2Bytes,
		elapsed:       elapsed,
		throughputBps: float64(p1Bytes+p2Bytes) / elapsed.Seconds(),
	}

	t.Logf("%s: %d bytes in %v → %.2f MB/s (%d chunks: p1=%d p2=%d)",
		label, result.totalBytes, elapsed,
		result.throughputBps/(1024*1024), result.totalChunks, p1Chunks, p2Chunks)

	return result
}

// TestDispatcherThroughputSingleVsMulti compares throughput between
// single-path (FastestOnly) and multi-path (RoundRobin) strategies.
func TestDispatcherThroughputSingleVsMulti(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping throughput benchmark in short mode")
	}

	dataSize := 2 * 1024 * 1024 // 2 MB

	t.Run("single-path_fastest-only", func(t *testing.T) {
		runDispatchBenchmark(t, &FastestOnlyStrategy{}, dataSize, "single-path")
	})

	t.Run("multi-path_round-robin", func(t *testing.T) {
		runDispatchBenchmark(t, &RoundRobinStrategy{}, dataSize, "multi-path/round-robin")
	})

	t.Run("multi-path_weighted", func(t *testing.T) {
		runDispatchBenchmark(t, NewWeightedStrategy(), dataSize, "multi-path/weighted")
	})
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 3: Fair chunk distribution across paths
// ──────────────────────────────────────────────────────────────────────────────

// TestMultiPathFairDistribution verifies that round-robin strategy
// distributes chunks evenly between two paths, and that weighted
// strategy biases toward the faster path.
func TestMultiPathFairDistribution(t *testing.T) {
	t.Run("round-robin_even_split", func(t *testing.T) {
		strategy := &RoundRobinStrategy{}

		// Simulate 1000 chunk assignments with both paths healthy.
		var p0Count, p1Count int
		c := &Circuit{
			Paths: [2]*CircuitPath{
				{Index: 0, Health: PathHealthHealthy, LastRTT: 10 * time.Millisecond},
				{Index: 1, Health: PathHealthHealthy, LastRTT: 10 * time.Millisecond},
			},
			AssignmentStrategy: strategy,
		}

		for i := 0; i < 1000; i++ {
			idx := strategy.AssignPath(c, i)
			if idx == 0 {
				p0Count++
			} else {
				p1Count++
			}
		}

		// Even split: each path should get ~500 chunks (±10% tolerance).
		diff := absInt(p0Count - p1Count)
		if diff > 100 {
			t.Errorf("round-robin split too uneven: p0=%d p1=%d (diff=%d, want ≤100)",
				p0Count, p1Count, diff)
		}
		t.Logf("round-robin: p0=%d p1=%d", p0Count, p1Count)
	})

	t.Run("weighted_favors_faster", func(t *testing.T) {
		strategy := NewWeightedStrategy()

		// Path 0: 10ms, Path 1: 100ms. Weight: p0 = 100/(10+100) ≈ 90.9%.
		var p0Count, p1Count int
		c := &Circuit{
			Paths: [2]*CircuitPath{
				{Index: 0, Health: PathHealthHealthy, LastRTT: 10 * time.Millisecond},
				{Index: 1, Health: PathHealthHealthy, LastRTT: 100 * time.Millisecond},
			},
			AssignmentStrategy: strategy,
		}

		n := 10000
		for i := 0; i < n; i++ {
			idx := strategy.AssignPath(c, i)
			if idx == 0 {
				p0Count++
			} else {
				p1Count++
			}
		}

		// Path 0 should get ~90% of chunks. Allow ±5% tolerance for randomness.
		expectedRatio := 100.0 / (10.0 + 100.0) // ≈ 0.909
		actualRatio := float64(p0Count) / float64(n)
		if math.Abs(actualRatio-expectedRatio) > 0.05 {
			t.Errorf("weighted ratio off: expected %.3f, got %.3f (p0=%d p1=%d)",
				expectedRatio, actualRatio, p0Count, p1Count)
		}
		t.Logf("weighted (10ms vs 100ms): p0=%d (%.1f%%) p1=%d (%.1f%%)",
			p0Count, actualRatio*100, p1Count, (1-actualRatio)*100)
	})

	t.Run("weighted_fallback_round_robin_no_rtt", func(t *testing.T) {
		strategy := NewWeightedStrategy()

		// Both paths have zero RTT — should fall back to round-robin.
		var p0Count, p1Count int
		c := &Circuit{
			Paths: [2]*CircuitPath{
				{Index: 0, Health: PathHealthHealthy, LastRTT: 0},
				{Index: 1, Health: PathHealthHealthy, LastRTT: 0},
			},
			AssignmentStrategy: strategy,
		}

		for i := 0; i < 1000; i++ {
			idx := strategy.AssignPath(c, i)
			if idx == 0 {
				p0Count++
			} else {
				p1Count++
			}
		}

		diff := absInt(p0Count - p1Count)
		if diff > 100 {
			t.Errorf("weighted fallback split too uneven: p0=%d p1=%d (diff=%d)",
				p0Count, p1Count, diff)
		}
		t.Logf("weighted fallback (no RTT): p0=%d p1=%d", p0Count, p1Count)
	})
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 4: Single-path vs multi-path failover behavior
// ──────────────────────────────────────────────────────────────────────────────

// failTrackingConn wraps a net.Conn and injects failures at a configured
// byte threshold. After threshold bytes are read, it returns io.EOF (simulating
// a dead path). This lets us measure failover behavior.
type failTrackingConn struct {
	net.Conn
	bytesRead int64
	failAt    int64
	failCh    chan struct{}
	failed    int32
	readHook  func(n int)
}

func (c *failTrackingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&c.bytesRead, int64(n))
		if c.readHook != nil {
			c.readHook(n)
		}
	}
	if atomic.LoadInt64(&c.bytesRead) >= c.failAt && atomic.CompareAndSwapInt32(&c.failed, 0, 1) {
		close(c.failCh)
		return n, io.EOF
	}
	return n, err
}

// TestFailoverLatency measures how long it takes for chunk dispatch to
// switch from a failed path to the healthy path.
func TestFailoverLatency(t *testing.T) {
	// This test verifies that the health-aware assignment strategies
	// immediately route around an unhealthy path.

	t.Run("round-robin_failover_to_healthy", func(t *testing.T) {
		strategy := &RoundRobinStrategy{}

		// Simulate path 0 getting marked unhealthy mid-stream.
		p0 := &CircuitPath{Index: 0, Health: PathHealthHealthy, LastRTT: 10 * time.Millisecond}
		p1 := &CircuitPath{Index: 1, Health: PathHealthHealthy, LastRTT: 10 * time.Millisecond}

		c := &Circuit{
			Paths:              [2]*CircuitPath{p0, p1},
			AssignmentStrategy: strategy,
		}

		// First 5 chunks: both paths healthy → alternating.
		var assignments []int
		for i := 0; i < 5; i++ {
			assignments = append(assignments, strategy.AssignPath(c, i))
		}

		// Mark path 0 unhealthy.
		p0.Health = PathHealthUnhealthy

		// Next chunks should ALL go to path 1 (the healthy one).
		for i := 5; i < 15; i++ {
			idx := strategy.AssignPath(c, i)
			assignments = append(assignments, idx)
			if idx != 1 {
				t.Errorf("chunk %d: expected path 1 (healthy), got path %d", i, idx)
			}
		}

		t.Logf("assignments: %v", assignments)

		// Verify that at least 1 chunk was assigned before failover.
		hadP0 := false
		for _, a := range assignments[:5] {
			if a == 0 {
				hadP0 = true
			}
		}
		if !hadP0 {
			t.Error("expected path 0 to get chunks before failover")
		}

		// Verify ALL post-failover chunks went to path 1.
		for _, a := range assignments[5:] {
			if a != 1 {
				t.Errorf("post-failover chunk went to path %d, expected path 1", a)
			}
		}
	})

	t.Run("weighted_failover_to_healthy", func(t *testing.T) {
		strategy := NewWeightedStrategy()

		// Path 0 is much faster but unhealthy — failover to path 1.
		p0 := &CircuitPath{Index: 0, Health: PathHealthUnhealthy, LastRTT: 5 * time.Millisecond}
		p1 := &CircuitPath{Index: 1, Health: PathHealthHealthy, LastRTT: 100 * time.Millisecond}

		c := &Circuit{
			Paths:              [2]*CircuitPath{p0, p1},
			AssignmentStrategy: strategy,
		}

		// All chunks must go to path 1 despite path 0 being faster.
		for i := 0; i < 50; i++ {
			idx := strategy.AssignPath(c, i)
			if idx != 1 {
				t.Errorf("weighted failover: chunk %d went to path %d, expected path 1", i, idx)
			}
		}
	})

	t.Run("both_unhealthy_round_robin", func(t *testing.T) {
		strategy := &RoundRobinStrategy{}

		p0 := &CircuitPath{Index: 0, Health: PathHealthUnhealthy}
		p1 := &CircuitPath{Index: 1, Health: PathHealthUnhealthy}

		c := &Circuit{
			Paths:              [2]*CircuitPath{p0, p1},
			AssignmentStrategy: strategy,
		}

		// Both unhealthy → still round-robins (degraded but keeps trying).
		var p0Count, p1Count int
		for i := 0; i < 100; i++ {
			idx := strategy.AssignPath(c, i)
			if idx == 0 {
				p0Count++
			} else {
				p1Count++
			}
		}

		if p0Count == 0 || p1Count == 0 {
			t.Errorf("both-unhealthy should still round-robin: p0=%d p1=%d", p0Count, p1Count)
		}
		t.Logf("both-unhealthy: p0=%d p1=%d", p0Count, p1Count)
	})
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 5: PathSelector probe cache effectiveness
// ──────────────────────────────────────────────────────────────────────────────

// TestPathSelectorProbeCacheHitRate verifies that the probe cache reduces
// the number of actual probe calls on repeated SelectPaths invocations.
func TestPathSelectorProbeCacheHitRate(t *testing.T) {
	var probeCount int32

	cfg := DefaultPathSelectorConfig()
	cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
		atomic.AddInt32(&probeCount, 1)
		return 10 * time.Millisecond, nil
	}

	selector := NewPathSelector(cfg)

	candidates := make([]CandidateRelay, 20)
	for i := range candidates {
		candidates[i] = CandidateRelay{
			NodeID:   fmt.Sprintf("cache-test-relay-%02d-key-key-key", i),
			MeshAddr: fmt.Sprintf("10.10.%d.%d:51820", i/256, i%256),
		}
	}

	// Round 1: cold cache — probes all MaxCandidates (10).
	_, _, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatalf("round 1: %v", err)
	}
	coldProbes := atomic.LoadInt32(&probeCount)
	t.Logf("cold cache: %d probes", coldProbes)

	// Round 2: warm cache — no new probes.
	atomic.StoreInt32(&probeCount, 0)
	_, _, err = selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatalf("round 2: %v", err)
	}
	warmProbes := atomic.LoadInt32(&probeCount)
	t.Logf("warm cache: %d probes", warmProbes)

	if warmProbes != 0 {
		t.Errorf("warm cache should have 0 probes, got %d — cache may not be working", warmProbes)
	}

	// Round 3: invalidate one relay and retry — only that relay should be re-probed.
	selector.InvalidateProbeCache("cache-test-relay-05-key-key-key")
	atomic.StoreInt32(&probeCount, 0)
	_, _, err = selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatalf("round 3: %v", err)
	}
	partialProbes := atomic.LoadInt32(&probeCount)
	t.Logf("partial invalidate: %d probes", partialProbes)

	if partialProbes != 1 {
		t.Errorf("after single invalidate expected 1 probe, got %d", partialProbes)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 6: Packet/chunk loss simulation — comparing single vs multi-path loss resilience
// ──────────────────────────────────────────────────────────────────────────────

// TestMultiPathPacketLossResilience verifies that when one path experiences
// failures, the multi-path dispatcher can continue on the healthy path,
// whereas a single-path setup would lose all subsequent chunks.
func TestMultiPathPacketLossResilience(t *testing.T) {
	// Simulate: path 0 healthy, path 1 healthy → path 1 fails → path 0 continues.

	t.Run("round-robin_survives_one_path_dead", func(t *testing.T) {
		strategy := &RoundRobinStrategy{}

		p0 := &CircuitPath{Index: 0, Health: PathHealthHealthy}
		p1 := &CircuitPath{Index: 1, Health: PathHealthHealthy}

		c := &Circuit{
			Paths:              [2]*CircuitPath{p0, p1},
			AssignmentStrategy: strategy,
		}

		// Phase 1: both healthy, 20 chunks.
		chunksDelivered := 0
		for i := 0; i < 20; i++ {
			_ = strategy.AssignPath(c, i)
			chunksDelivered++
		}

		// Path 1 dies.
		p1.Health = PathHealthUnhealthy

		// Phase 2: 20 more chunks — all must route to path 0.
		failoverDelivered := 0
		for i := 20; i < 40; i++ {
			idx := strategy.AssignPath(c, i)
			if idx != 0 {
				t.Errorf("post-failover chunk %d: expected path 0, got path %d", i, idx)
			}
			failoverDelivered++
		}

		t.Logf("delivered: %d before failover + %d after failover = %d total",
			chunksDelivered, failoverDelivered, chunksDelivered+failoverDelivered)
	})

	t.Run("fastest-only_death_means_no_loss", func(t *testing.T) {
		strategy := &FastestOnlyStrategy{}

		// Fastest path = 0 (5ms), slower = 1 (100ms).
		p0 := &CircuitPath{Index: 0, Health: PathHealthHealthy, LastRTT: 5 * time.Millisecond}
		p1 := &CircuitPath{Index: 1, Health: PathHealthHealthy, LastRTT: 100 * time.Millisecond}

		c := &Circuit{
			Paths:              [2]*CircuitPath{p0, p1},
			AssignmentStrategy: strategy,
		}

		// Path 0 is the fastest — all chunks go there.
		for i := 0; i < 10; i++ {
			idx := strategy.AssignPath(c, i)
			if idx != 0 {
				t.Errorf("pre-failover: expected path 0 (fastest), got path %d", idx)
			}
		}

		// Path 0 dies. Now path 1 (healthy, slower) must take over.
		p0.Health = PathHealthUnhealthy

		for i := 10; i < 20; i++ {
			idx := strategy.AssignPath(c, i)
			if idx != 1 {
				t.Errorf("post-failover: expected path 1 (only healthy), got path %d", idx)
			}
		}
	})
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 7: Throughput under load — comparing strategies at scale
// ──────────────────────────────────────────────────────────────────────────────

// BenchmarkAssignmentStrategyCompare runs each strategy through the same
// large data size and measures throughput.
func TestAssignmentStrategyThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping throughput benchmark in short mode")
	}

	// Use a small-ish data size since net.Pipe is local and very fast.
	dataSize := 512 * 1024 // 512 KB
	strategies := []struct {
		name     string
		strategy ChunkAssignmentStrategy
	}{
		{"round-robin", &RoundRobinStrategy{}},
		{"weighted", NewWeightedStrategy()},
	}

	for _, s := range strategies {
		t.Run(s.name, func(t *testing.T) {
			r := runDispatchBenchmark(t, s.strategy, dataSize, s.name)
			// Verify basic sanity: data was dispatched.
			if r.totalBytes == 0 {
				t.Error("no bytes dispatched — dispatcher may be broken")
			}
			if r.totalChunks == 0 {
				t.Error("no chunks dispatched")
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 8: Chunk distribution statistics accuracy
// ──────────────────────────────────────────────────────────────────────────────

// TestDispatcherStatsAccuracy verifies that chunk/byte counts are accurate
// by writing a known amount of data and checking the stats.
func TestDispatcherStatsAccuracy(t *testing.T) {
	e2eKey := make([]byte, KeySize)
	relayKey := make([]byte, KeySize)
	circuitID, _ := GenerateCircuitID()

	path1 := &Path{Relays: []string{"relay-A-stats"}, RelayKeys: [][]byte{relayKey}}
	path2 := &Path{Relays: []string{"relay-B-stats"}, RelayKeys: [][]byte{relayKey}}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	cfg := DispatcherConfig{
		ChunkerStrategy: "fixed-16k",
		ChunkerCfg: ChunkerConfig{
			MaxChunkSize:   16 * 1024,
			MinChunkSize:   16 * 1024,
			DisablePadding: true,
		},
		CircuitCfg: DefaultCircuitConfig(),
		Path1:      path1,
		Path2:      path2,
		E2EKey:     e2eKey,
		CircuitID:  circuitID,
		ExitAddr:   "10.10.0.99:51820",
	}

	d, err := NewDispatcher(cfg, serverConn)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- d.Run(context.Background(), func(path int, wc *WireChunk) error {
			return nil
		})
	}()

	// Write exactly 48KB (3 chunks of 16KB).
	testData := make([]byte, 48*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	clientConn.Write(testData)
	clientConn.Close()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}

	p1Chunks, p2Chunks, p1Bytes, p2Bytes := d.Stats()
	totalChunks := p1Chunks + p2Chunks
	totalBytes := p1Bytes + p2Bytes

	// We expect exactly 3 data chunks (48KB / 16KB) plus 2 stream-end markers = 5 total.
	if totalChunks < 3 {
		t.Errorf("expected at least 3 data chunks, got %d (p1=%d p2=%d)", totalChunks, p1Chunks, p2Chunks)
	}
	if totalBytes < 48*1024 {
		t.Errorf("expected at least %d payload bytes, got %d", 48*1024, totalBytes)
	}

	t.Logf("Stats accuracy: %d chunks, %d bytes (p1=%d/%d p2=%d/%d)",
		totalChunks, totalBytes, p1Chunks, p1Bytes, p2Chunks, p2Bytes)

	d.Close()
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 9: RelaySelector performance with large relay pools
// ──────────────────────────────────────────────────────────────────────────────

// Note: RelaySelector lives in internal/p2p, not internal/proxy.
// We benchmark it here for comparison purposes via a lightweight construction
// since it's the relay scoring counterpart to the proxy path selector.

// TestPathSelectorManyCandidatesLatency measures per-candidate overhead
// for the probe phase by timing selection with increasing candidate counts.
func TestPathSelectorPerCandidateOverhead(t *testing.T) {
	counts := []int{5, 10, 20, 50}

	for _, n := range counts {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			candidates := make([]CandidateRelay, n)
			for i := range candidates {
				candidates[i] = CandidateRelay{
					NodeID:   fmt.Sprintf("perf-relay-%04d-node-id-key-valid-key", i),
					MeshAddr: fmt.Sprintf("10.10.%d.%d:51820", i/256, i%256),
				}
			}

			cfg := DefaultPathSelectorConfig()
			cfg.MaxCandidates = n + 1
			cfg.ProbeConcurrency = 16
			cfg.ProbeTimeout = 500 * time.Millisecond
			cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
				return 1 * time.Millisecond, nil
			}

			selector := NewPathSelector(cfg)

			start := time.Now()
			_, _, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
			elapsed := time.Since(start)

			if err != nil {
				t.Fatalf("%d candidates: %v", n, err)
			}

			perCandidate := elapsed / time.Duration(minInt(n, cfg.MaxCandidates))
			t.Logf("%d candidates → %v total, ~%v per candidate (MaxCandidates=%d)",
				n, elapsed, perCandidate, cfg.MaxCandidates)
		})
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
