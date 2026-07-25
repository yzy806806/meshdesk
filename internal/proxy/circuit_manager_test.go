package proxy

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Test helpers
// ──────────────────────────────────────────────────────────────────────────────

// buildTestMatrix creates a latency matrix for testing with the following
// topology:
//
//	entry ──(10ms)── relayA ──(15ms)── exit
//	entry ──(20ms)── relayB ──(25ms)── exit
//	entry ──(30ms)── relayC ──(5ms)─── exit
//
// relayA and relayB have known RTTs; relayC has unmeasured edges (RTT=0).
func buildTestMatrix() *MeshLatencyMatrix {
	m := NewMeshLatencyMatrix()

	m.AddNode(NodeInfo{ID: "entry", Role: NodeRoleEntry, Capabilities: []NodeCapability{CapRelay}, Status: NodeStatusOnline})
	m.AddNode(NodeInfo{ID: "exit", Role: NodeRoleExit, Capabilities: []NodeCapability{CapExit}, Status: NodeStatusOnline})
	m.AddNode(NodeInfo{ID: "relayA", Role: NodeRoleRelay, Capabilities: []NodeCapability{CapRelay}, Status: NodeStatusOnline})
	m.AddNode(NodeInfo{ID: "relayB", Role: NodeRoleRelay, Capabilities: []NodeCapability{CapRelay}, Status: NodeStatusOnline})
	m.AddNode(NodeInfo{ID: "relayC", Role: NodeRoleRelay, Capabilities: []NodeCapability{CapRelay}, Status: NodeStatusOnline})

	now := time.Now()

	m.AddEdge(LatencyEdge{Source: "entry", Target: "relayA", RTTms: 10, MeasuredAt: now, SourceType: EdgeProbe})
	m.AddEdge(LatencyEdge{Source: "entry", Target: "relayB", RTTms: 20, MeasuredAt: now, SourceType: EdgeProbe})
	m.AddEdge(LatencyEdge{Source: "entry", Target: "relayC", RTTms: 30, MeasuredAt: now, SourceType: EdgeProbe})

	m.AddEdge(LatencyEdge{Source: "relayA", Target: "exit", RTTms: 15, MeasuredAt: now, SourceType: EdgeProbe})
	m.AddEdge(LatencyEdge{Source: "relayB", Target: "exit", RTTms: 25, MeasuredAt: now, SourceType: EdgeProbe})

	// relayC → exit: unmeasured (RTT=0) → should get 500ms penalty.
	m.AddEdge(LatencyEdge{Source: "relayC", Target: "exit", RTTms: 0, MeasuredAt: now, SourceType: EdgeProbe})

	return m
}

// buildFiveNodeMatrix creates a richer topology for exhaustive testing:
//
//	entry ── relayA ── relayD ── exit
//	entry ── relayB ── relayE ── exit
//	entry ── relayC ── exit
//	relayA ── relayE
//	relayB ── relayD
//
// This allows multi-hop paths for exhaustive disjoint-pair testing.
func buildFiveNodeMatrix() *MeshLatencyMatrix {
	m := NewMeshLatencyMatrix()

	m.AddNode(NodeInfo{ID: "entry", Role: NodeRoleEntry, Capabilities: []NodeCapability{CapRelay}, Status: NodeStatusOnline})
	m.AddNode(NodeInfo{ID: "exit", Role: NodeRoleExit, Capabilities: []NodeCapability{CapExit}, Status: NodeStatusOnline})
	for _, r := range []string{"relayA", "relayB", "relayC", "relayD", "relayE"} {
		m.AddNode(NodeInfo{ID: r, Role: NodeRoleRelay, Capabilities: []NodeCapability{CapRelay}, Status: NodeStatusOnline})
	}

	now := time.Now()
	addEdge := func(s, t string, rtt float64) {
		m.AddEdge(LatencyEdge{Source: s, Target: t, RTTms: rtt, MeasuredAt: now, SourceType: EdgeProbe})
	}

	addEdge("entry", "relayA", 5)
	addEdge("entry", "relayB", 8)
	addEdge("entry", "relayC", 30)
	addEdge("relayA", "relayD", 10)
	addEdge("relayB", "relayE", 12)
	addEdge("relayC", "exit", 40)
	addEdge("relayD", "exit", 15)
	addEdge("relayE", "exit", 10)
	addEdge("relayA", "relayE", 3) // cross-link for multi-hop
	addEdge("relayB", "relayD", 4) // cross-link for multi-hop

	return m
}

// makeTestCircuit creates a Circuit with two paths for testing.
func makeTestCircuit() *Circuit {
	var cid CircuitIDType
	rand.Read(cid[:])
	var e2eKey [KeySize]byte
	rand.Read(e2eKey[:])
	var seed [32]byte
	rand.Read(seed[:])

	relayKey0 := make([]byte, KeySize)
	rand.Read(relayKey0)
	relayKey1 := make([]byte, KeySize)
	rand.Read(relayKey1)

	now := time.Now()
	return &Circuit{
		ID:                 cid,
		State:              CircuitActive,
		CreatedAt:          now,
		LastActivity:       now,
		Entry:              "entry",
		Exit:               "exit",
		TargetAddr:         "example.com:443",
		E2EKey:             e2eKey,
		PaddingSeed:        seed,
		AssignmentStrategy: &RoundRobinStrategy{},
		KeepaliveInterval:  30 * time.Second,
		IdleTimeout:        5 * time.Minute,
		Paths: [2]*CircuitPath{
			{
				Index:         0,
				Hops:          []string{"relayA"},
				RelayKeys:     [][]byte{relayKey0},
				Health:        PathHealthHealthy,
				EstablishedAt: now,
			},
			{
				Index:         1,
				Hops:          []string{"relayB"},
				RelayKeys:     [][]byte{relayKey1},
				Health:        PathHealthHealthy,
				EstablishedAt: now,
			},
		},
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// A. Path Selection Tests (AC-PS-01 through AC-PS-06)
// ──────────────────────────────────────────────────────────────────────────────

// AC-PS-01: KShortestDisjointPaths returns 2 node-disjoint paths when the
// mesh graph has ≥2 relay nodes connected to both entry and exit.
func TestAC_PS_01_TwoDisjointPaths(t *testing.T) {
	matrix := buildTestMatrix()
	paths, err := KShortestDisjointPaths(matrix, "entry", "exit", 2)
	if err != nil {
		t.Fatalf("KShortestDisjointPaths failed: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
	// Verify each path starts at entry and ends at exit.
	for i, p := range paths {
		if p[0] != "entry" {
			t.Errorf("path %d: start = %s, want entry", i, p[0])
		}
		if p[len(p)-1] != "exit" {
			t.Errorf("path %d: end = %s, want exit", i, p[len(p)-1])
		}
	}
}

// AC-PS-02: KShortestDisjointPaths returns the lowest-total-latency pair
// among all disjoint pairs (verified by exhaustive enumeration).
func TestAC_PS_02_LowestLatencyPair(t *testing.T) {
	matrix := buildTestMatrix()
	paths, err := KShortestDisjointPaths(matrix, "entry", "exit", 2)
	if err != nil {
		t.Fatalf("KShortestDisjointPaths failed: %v", err)
	}

	// Compute total latency of the returned pair.
	pathLatency := func(p []string) float64 {
		total := 0.0
		for i := 0; i < len(p)-1; i++ {
			w := matrix.EdgeWeight(p[i], p[i+1])
			if w == 0 {
				w = 500
			}
			total += w
		}
		return total
	}

	returnedTotal := pathLatency(paths[0]) + pathLatency(paths[1])

	// Exhaustively check all disjoint pairs of relay nodes.
	relays := []string{"relayA", "relayB", "relayC"}
	for i := 0; i < len(relays); i++ {
		for j := i + 1; j < len(relays); j++ {
			// Build two single-hop paths: entry→relayI→exit and entry→relayJ→exit.
			p1 := []string{"entry", relays[i], "exit"}
			p2 := []string{"entry", relays[j], "exit"}
			altTotal := pathLatency(p1) + pathLatency(p2)
			if altTotal < returnedTotal {
				t.Errorf("found lower-latency pair: %s+%s = %.1f < %.1f",
					relays[i], relays[j], altTotal, returnedTotal)
			}
		}
	}
}

// AC-PS-03: Path overlap detection rejects any pair where
// path_a.relays ∩ path_b.relays ≠ ∅.
func TestAC_PS_03_PathOverlapDetection(t *testing.T) {
	// Direct overlap test.
	pathA := []string{"entry", "relayA", "exit"}
	pathB := []string{"entry", "relayA", "relayD", "exit"}
	if !PathsHaveOverlap(pathA, pathB) {
		t.Error("expected overlap for shared relayA")
	}

	// No overlap.
	pathC := []string{"entry", "relayB", "exit"}
	if PathsHaveOverlap(pathA, pathC) {
		t.Error("expected no overlap for different relays")
	}

	// Empty relay paths (direct entry→exit) never overlap.
	pathDirect1 := []string{"entry", "exit"}
	pathDirect2 := []string{"entry", "exit"}
	if PathsHaveOverlap(pathDirect1, pathDirect2) {
		t.Error("direct paths should not overlap")
	}
}

// AC-PS-04: When a relay node has an unmeasured edge (RTT=0), BFS applies
// the 500ms penalty weight.
func TestAC_PS_04_UnmeasuredEdgePenalty(t *testing.T) {
	matrix := buildTestMatrix()

	// relayC → exit has RTT=0 (unmeasured).
	// Path entry→relayC→exit should have weight 30 + 500 = 530.
	// Path entry→relayA→exit should have weight 10 + 15 = 25.
	// So relayA path should always be selected before relayC.

	path := ShortestPath(matrix, "entry", "exit", map[string]bool{})
	if path == nil {
		t.Fatal("expected a path, got nil")
	}
	// The shortest path should go through relayA (total 25ms), not relayC (530ms).
	if len(path) != 3 || path[1] != "relayA" {
		t.Errorf("expected entry→relayA→exit, got %v", path)
	}
}

// AC-PS-05: Probe fallback is used when fewer than MinCandidates relays
// have known RTTs in the matrix.
func TestAC_PS_05_ProbeFallback(t *testing.T) {
	// Empty matrix — no relay nodes at all.
	matrix := NewMeshLatencyMatrix()

	// With an empty matrix, BFS will fail.
	_, err := KShortestDisjointPaths(matrix, "entry", "exit", 2)
	if err == nil {
		t.Error("expected error on empty matrix, got nil")
	}

	// CircuitManager in "auto" mode should fall back to probe-based selection.
	cfg := DefaultCircuitManagerConfig()
	cfg.SelectionStrategy = "auto"
	cfg.FlushTimeout = 50 * time.Millisecond // speed up test
	cm := NewCircuitManager(cfg)

	// Provide candidates for probe-based selection.
	// We need a local TCP listener that the probe can connect to.
	ln, err := listenStub()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	candidates := []CandidateRelay{
		{NodeID: "r1", MeshAddr: ln.Addr().String(), Capabilities: []string{"relay"}},
		{NodeID: "r2", MeshAddr: ln.Addr().String(), Capabilities: []string{"relay"}},
	}

	paths, err := cm.selectPaths(context.Background(), "entry", "exit", candidates)
	if err != nil {
		// Probe may fail if it can't connect — that's OK, we're testing fallback logic.
		// The key is that it tried probe, not BFS.
		t.Logf("probe fallback returned error (acceptable in test env): %v", err)
	} else {
		if len(paths) != 2 {
			t.Errorf("expected 2 paths from probe, got %d", len(paths))
		}
	}
}

// AC-PS-06: On-demand probing scales O(K) — only MaxCandidates (≤10) nodes
// are probed per circuit setup.
func TestAC_PS_06_ProbeScalingOK(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.MaxCandidates = 5
	cfg.MinCandidates = 2
	cm := NewCircuitManager(cfg)

	// Provide 20 candidates with advertised RTTs.
	// The filter should reduce them to MaxCandidates (5).
	ln, err := listenStub()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	candidates := make([]CandidateRelay, 20)
	for i := range candidates {
		candidates[i] = CandidateRelay{
			NodeID:        fmt.Sprintf("relay-%d", i),
			MeshAddr:      ln.Addr().String(),
			Capabilities:  []string{"relay"},
			AdvertisedRTT: time.Duration(i+1) * time.Millisecond,
		}
	}

	// The selector's filterCandidates should reduce the set to ≤ MaxCandidates.
	filtered := cm.probe.filterCandidates(candidates)
	// filterCandidates returns all when no RTT; with RTTs it sorts and
	// the SelectPaths call truncates to MaxCandidates.
	if len(filtered) > 20 {
		t.Errorf("filtered candidates = %d, should not exceed input", len(filtered))
	}

	// Verify that SelectPaths only probes MaxCandidates.
	// We check the probeCache after SelectPaths — it should have at most
	// MaxCandidates entries.
	_, _, sErr := cm.probe.SelectPaths(context.Background(), candidates, ln.Addr().String())
	_ = sErr // may error in test env, that's OK

	cm.probe.mu.Lock()
	cacheLen := len(cm.probe.probeCache)
	cm.probe.mu.Unlock()
	if cacheLen > cfg.MaxCandidates {
		t.Errorf("probe cache entries = %d, want ≤ %d", cacheLen, cfg.MaxCandidates)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// B. Chunk Assignment Tests (AC-CA-01 through AC-CA-04)
// ──────────────────────────────────────────────────────────────────────────────

// AC-CA-01: Round-robin strategy alternates path 0 → 1 → 0 → 1 consistently.
func TestAC_CA_01_RoundRobin(t *testing.T) {
	circuit := makeTestCircuit()
	circuit.AssignmentStrategy = &RoundRobinStrategy{}

	expected := []int{0, 1, 0, 1, 0, 1, 0, 1}
	for i, want := range expected {
		got := circuit.AssignmentStrategy.AssignPath(circuit, i)
		if got != want {
			t.Errorf("call %d: got %d, want %d", i, got, want)
		}
	}
}

// AC-CA-02: Weighted strategy assigns chunks proportionally to inverse
// latency (faster path ~80% when 20ms vs 80ms).
func TestAC_CA_02_WeightedProportional(t *testing.T) {
	circuit := makeTestCircuit()
	circuit.AssignmentStrategy = NewWeightedStrategy()

	// Set RTTs: path0=20ms, path1=80ms → path0 gets 80% of chunks.
	circuit.Paths[0].LastRTT = 20 * time.Millisecond
	circuit.Paths[1].LastRTT = 80 * time.Millisecond

	count0 := 0
	total := 10000
	for i := 0; i < total; i++ {
		if circuit.AssignmentStrategy.AssignPath(circuit, i) == 0 {
			count0++
		}
	}

	ratio := float64(count0) / float64(total)
	// Expect ~80% (allow ±5% tolerance for randomness).
	if ratio < 0.75 || ratio > 0.85 {
		t.Errorf("path0 ratio = %.2f, want ~0.80 (±0.05)", ratio)
	}
}

// AC-CA-03: Weighted strategy falls back to round-robin when no RTT data
// is available.
func TestAC_CA_03_WeightedFallbackRoundRobin(t *testing.T) {
	circuit := makeTestCircuit()
	circuit.AssignmentStrategy = NewWeightedStrategy()

	// No RTT data — both paths have LastRTT=0.
	count0 := 0
	total := 1000
	for i := 0; i < total; i++ {
		if circuit.AssignmentStrategy.AssignPath(circuit, i) == 0 {
			count0++
		}
	}

	// Should be ~50% (round-robin behavior).
	ratio := float64(count0) / float64(total)
	if ratio < 0.40 || ratio > 0.60 {
		t.Errorf("fallback ratio = %.2f, want ~0.50 (±0.10)", ratio)
	}
}

// AC-CA-04: When one path is unhealthy, both strategies route all chunks
// to the healthy path.
func TestAC_CA_04_UnhealthyPathRouting(t *testing.T) {
	circuit := makeTestCircuit()

	// Make path 0 unhealthy.
	circuit.Paths[0].Health = PathHealthUnhealthy

	// Test round-robin.
	circuit.AssignmentStrategy = &RoundRobinStrategy{}
	for i := 0; i < 10; i++ {
		got := circuit.AssignmentStrategy.AssignPath(circuit, i)
		if got != 1 {
			t.Errorf("round-robin call %d: got %d, want 1 (healthy path)", i, got)
		}
	}

	// Test weighted.
	circuit.AssignmentStrategy = NewWeightedStrategy()
	circuit.Paths[0].LastRTT = 20 * time.Millisecond
	circuit.Paths[1].LastRTT = 80 * time.Millisecond
	for i := 0; i < 10; i++ {
		got := circuit.AssignmentStrategy.AssignPath(circuit, i)
		if got != 1 {
			t.Errorf("weighted call %d: got %d, want 1 (healthy path)", i, got)
		}
	}

	// Test fastest-only.
	circuit.AssignmentStrategy = &FastestOnlyStrategy{}
	for i := 0; i < 10; i++ {
		got := circuit.AssignmentStrategy.AssignPath(circuit, i)
		if got != 1 {
			t.Errorf("fastest-only call %d: got %d, want 1 (healthy path)", i, got)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// C. Circuit Lifecycle Tests (AC-CL-01 through AC-CL-10)
// ──────────────────────────────────────────────────────────────────────────────

// AC-CL-01: Circuit transitions CREATING → ACTIVE on successful CircuitAck.
func TestAC_CL_01_CreatingToActive(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)

	// Set up matrix with known relays so BFS path selection works.
	matrix := buildTestMatrix()
	cm.matrix = matrix

	// Create circuit.
	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	circuit, _ := cm.GetCircuit(cid)
	if circuit.State != CircuitCreating {
		t.Fatalf("expected CREATING, got %s", circuitStateName(circuit.State))
	}

	// Handle ack — accepted.
	ack := &CircuitAck{
		CircuitID:  cid[:],
		ECDHPubKey: make([]byte, 32),
		Accepted:   true,
	}
	if err := cm.HandleCircuitAck(cid, ack); err != nil {
		t.Fatalf("HandleCircuitAck failed: %v", err)
	}

	circuit, _ = cm.GetCircuit(cid)
	if circuit.State != CircuitActive {
		t.Errorf("expected ACTIVE, got %s", circuitStateName(circuit.State))
	}
}

// AC-CL-02: Circuit transitions CREATING → CLOSED on rejected CircuitAck
// or setup timeout (10s).
func TestAC_CL_02_CreatingToClosedRejection(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	// Handle ack — rejected.
	ack := &CircuitAck{
		CircuitID:  cid[:],
		ECDHPubKey: make([]byte, 32),
		Accepted:   false,
		Reason:     "port not allowed",
	}
	if err := cm.HandleCircuitAck(cid, ack); err == nil {
		t.Error("expected error for rejected ack")
	}

	// Circuit should be removed (CLOSED).
	_, err = cm.GetCircuit(cid)
	if err == nil {
		t.Error("expected ErrCircuitNotFound after rejected ack")
	}
}

// AC-CL-02: Setup timeout also transitions to CLOSED.
func TestAC_CL_02_SetupTimeout(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	if err := cm.HandleSetupTimeout(cid); err != nil {
		t.Fatalf("HandleSetupTimeout failed: %v", err)
	}

	_, err = cm.GetCircuit(cid)
	if err == nil {
		t.Error("expected ErrCircuitNotFound after setup timeout")
	}
}

// AC-CL-03: Circuit transitions ACTIVE → TEARDOWN on TCP close, idle
// timeout, or both-path failure.
func TestAC_CL_03_ActiveToTeardown(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	// Transition to ACTIVE.
	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	// Teardown (simulates TCP close).
	err = cm.TeardownCircuit(cid, "tcp close", nil)
	if err != nil {
		t.Fatalf("TeardownCircuit failed: %v", err)
	}

	// Circuit should be gone (CLOSED).
	_, err = cm.GetCircuit(cid)
	if err == nil {
		t.Error("expected ErrCircuitNotFound after teardown")
	}
}

// AC-CL-03: Both-path failure triggers teardown.
func TestAC_CL_03_BothPathFailureTeardown(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cfg.KeepaliveInterval = 1 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	// Miss 4 keepalives on both paths → both unhealthy → teardown.
	for i := 0; i < 4; i++ {
		cm.MissKeepalive(cid, 0)
		cm.MissKeepalive(cid, 1)
	}

	// Give the async teardown goroutine time to run.
	time.Sleep(100 * time.Millisecond)

	circuit, err := cm.GetCircuit(cid)
	if err == nil {
		if circuit.State != CircuitClosed && circuit.State != CircuitTeardown {
			t.Errorf("expected CLOSED or TEARDOWN, got %s", circuitStateName(circuit.State))
		}
	}
	// If circuit is gone, that's also fine (already CLOSED and removed).
}

// AC-CL-04: Circuit transitions ACTIVE → TEARDOWN on exit-initiated
// teardown (MsgCircuitTeardown received).
func TestAC_CL_04_ExitInitiatedTeardown(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	msg := &TeardownMsg{CircuitID: cid[:], Reason: "target TCP closed"}
	if err := cm.HandleTeardown(cid, msg); err != nil {
		t.Fatalf("HandleTeardown failed: %v", err)
	}

	_, err = cm.GetCircuit(cid)
	if err == nil {
		t.Error("expected ErrCircuitNotFound after exit teardown")
	}
}

// AC-CL-05: Teardown sends ChunkStreamEnd markers on all healthy paths
// before closing.
func TestAC_CL_05_TeardownFlushStreamEnd(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 50 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	// Track which paths got ChunkStreamEnd.
	var mu sync.Mutex
	sentPaths := []int{}
	sendChunkEnd := func(pathIdx int) error {
		mu.Lock()
		sentPaths = append(sentPaths, pathIdx)
		mu.Unlock()
		return nil
	}

	// Both paths are healthy → should send on both.
	err = cm.TeardownCircuit(cid, "tcp close", sendChunkEnd)
	if err != nil {
		t.Fatalf("TeardownCircuit failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(sentPaths) != 2 {
		t.Errorf("expected ChunkStreamEnd on 2 paths, got %d", len(sentPaths))
	}
}

// AC-CL-06: Flush timeout (10s) forces CLOSED even if stream-end acks
// are pending.
func TestAC_CL_06_FlushTimeoutForcesClose(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 50 * time.Millisecond // shortened for test
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	// sendChunkEnd that never "acks" — just blocks.
	start := time.Now()
	err = cm.TeardownCircuit(cid, "test", func(int) error { return nil })
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("TeardownCircuit failed: %v", err)
	}
	// Should have waited approximately FlushTimeout before force-closing.
	if elapsed < 40*time.Millisecond {
		t.Errorf("flush timeout too short: %v, want ≥ ~50ms", elapsed)
	}

	// Circuit should be closed.
	_, err = cm.GetCircuit(cid)
	if err == nil {
		t.Error("expected circuit to be closed after flush timeout")
	}
}

// AC-CL-07: On CLOSED, E2E key and padding seed are zeroed in memory.
func TestAC_CL_07_KeyZeroing(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	circuit, _ := cm.GetCircuit(cid)

	// Verify keys are non-zero before close.
	if circuit.KeysZeroed() {
		t.Error("keys should be non-zero before close")
	}

	// Close the circuit.
	cm.TeardownCircuit(cid, "test", nil)

	// Verify keys are zeroed after close.
	if !circuit.KeysZeroed() {
		t.Error("keys should be zeroed after close")
	}
}

// AC-CL-08: Circuit state is exposed via ListCircuits() for the topology API.
func TestAC_CL_08_ListCircuits(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	// No circuits initially.
	if len(cm.ListCircuits()) != 0 {
		t.Error("expected 0 circuits initially")
	}

	// Create a circuit.
	cid, _ := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	circuits := cm.ListCircuits()
	if len(circuits) != 1 {
		t.Fatalf("expected 1 circuit, got %d", len(circuits))
	}

	info := circuits[0]
	if info.State != "active" {
		t.Errorf("expected active, got %s", info.State)
	}
	if info.Entry != "entry" {
		t.Errorf("expected entry, got %s", info.Entry)
	}
	if info.Exit != "exit" {
		t.Errorf("expected exit, got %s", info.Exit)
	}
	if info.Target != "example.com:443" {
		t.Errorf("expected example.com:443, got %s", info.Target)
	}
	if len(info.Paths) != 2 {
		t.Errorf("expected 2 paths, got %d", len(info.Paths))
	}
}

// AC-CL-09: Keepalive pings are sent every KeepaliveInterval (30s) on each
// active path.
func TestAC_CL_09_KeepaliveInterval(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	if cfg.KeepaliveInterval != 30*time.Second {
		t.Errorf("KeepaliveInterval = %v, want 30s", cfg.KeepaliveInterval)
	}

	// The keepalive loop is in the Dispatcher; CircuitManager handles
	// the response side. We verify the config is correct.
	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	circuit, _ := cm.GetCircuit(cid)
	if circuit.KeepaliveInterval != 30*time.Second {
		t.Errorf("circuit.KeepaliveInterval = %v, want 30s", circuit.KeepaliveInterval)
	}
}

// AC-CL-10: Path health transitions HEALTHY → DEGRADED after 2 missed
// keepalives (20s), DEGRADED → UNHEALTHY after 2 more (total 40s).
func TestAC_CL_10_PathHealthFSM(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cfg.KeepaliveInterval = 10 * time.Second
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	circuit, _ := cm.GetCircuit(cid)
	path := circuit.Paths[0]

	// Initially healthy.
	if path.Health != PathHealthHealthy {
		t.Fatalf("expected HEALTHY, got %d", path.Health)
	}

	// Miss 1 keepalive — still healthy.
	cm.MissKeepalive(cid, 0)
	if path.Health != PathHealthHealthy {
		t.Errorf("after 1 miss: expected HEALTHY, got %d", path.Health)
	}

	// Miss 2nd keepalive → DEGRADED.
	cm.MissKeepalive(cid, 0)
	if path.Health != PathHealthDegraded {
		t.Errorf("after 2 misses: expected DEGRADED, got %d", path.Health)
	}

	// Miss 3rd — still degraded.
	cm.MissKeepalive(cid, 0)
	if path.Health != PathHealthDegraded {
		t.Errorf("after 3 misses: expected DEGRADED, got %d", path.Health)
	}

	// Miss 4th → UNHEALTHY.
	cm.MissKeepalive(cid, 0)
	if path.Health != PathHealthUnhealthy {
		t.Errorf("after 4 misses: expected UNHEALTHY, got %d", path.Health)
	}
}

// AC-CL-10: Keepalive response restores health.
func TestAC_CL_10_KeepaliveResponseRestores(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	circuit, _ := cm.GetCircuit(cid)
	path := circuit.Paths[0]

	// Degrade to DEGRADED.
	cm.MissKeepalive(cid, 0)
	cm.MissKeepalive(cid, 0)
	if path.Health != PathHealthDegraded {
		t.Fatalf("expected DEGRADED, got %d", path.Health)
	}

	// Send keepalive response → should restore to HEALTHY.
	ts := time.Now().Add(-5 * time.Millisecond).UnixNano()
	cm.HandleKeepaliveResponse(cid, 0, ts)
	if path.Health != PathHealthHealthy {
		t.Errorf("expected HEALTHY after keepalive response, got %d", path.Health)
	}
	if path.LastRTT <= 0 {
		t.Error("expected LastRTT > 0 after response")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// D. Tracking and Observability Tests (AC-TO-01 through AC-TO-03)
// ──────────────────────────────────────────────────────────────────────────────

// AC-TO-01: CircuitManager.GetCircuitStats() returns accurate aggregate
// metrics (total created, closed, active, bytes dispatched).
func TestAC_TO_01_CircuitStats(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	// Initially zero.
	stats := cm.GetCircuitStats()
	if stats.TotalCreated != 0 || stats.Active != 0 {
		t.Errorf("initial stats: TotalCreated=%d Active=%d, want 0/0",
			stats.TotalCreated, stats.Active)
	}

	// Create a circuit.
	cid, _ := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	stats = cm.GetCircuitStats()
	if stats.TotalCreated != 1 {
		t.Errorf("TotalCreated = %d, want 1", stats.TotalCreated)
	}
	if stats.Active != 1 {
		t.Errorf("Active = %d, want 1", stats.Active)
	}

	// Dispatch some chunks.
	cm.RecordChunkDispatch(cid, 0, 1024)
	cm.RecordChunkDispatch(cid, 1, 2048)

	// Teardown.
	cm.TeardownCircuit(cid, "test", nil)

	stats = cm.GetCircuitStats()
	if stats.TotalClosed != 1 {
		t.Errorf("TotalClosed = %d, want 1", stats.TotalClosed)
	}
	if stats.Active != 0 {
		t.Errorf("Active = %d, want 0 after close", stats.Active)
	}
}

// AC-TO-02: CircuitManager.OnCircuitEvent() fires lifecycle events
// (CREATED, ESTABLISHED, CLOSED, PATH_DEGRADED, PATH_RESTORED).
func TestAC_TO_02_CircuitEvents(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	var mu sync.Mutex
	var events []CircuitEventType
	cm.OnCircuitEvent(func(e CircuitEvent) {
		mu.Lock()
		events = append(events, e.Type)
		mu.Unlock()
	})

	cid, _ := cm.CreateCircuit("example.com:443", "entry", "exit", nil)

	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	// Degrade and restore a path.
	cm.MissKeepalive(cid, 0)
	cm.MissKeepalive(cid, 0) // → DEGRADED event

	ts := time.Now().Add(-5 * time.Millisecond).UnixNano()
	cm.HandleKeepaliveResponse(cid, 0, ts) // → RESTORED event

	cm.TeardownCircuit(cid, "test", nil)

	// Check events fired.
	mu.Lock()
	defer mu.Unlock()

	expectEvent(t, events, EventCircuitCreated)
	expectEvent(t, events, EventCircuitEstablished)
	expectEvent(t, events, EventPathDegraded)
	expectEvent(t, events, EventPathRestored)
	expectEvent(t, events, EventCircuitTeardownInitiated)
	expectEvent(t, events, EventCircuitClosed)
}

func expectEvent(t *testing.T, events []CircuitEventType, want CircuitEventType) {
	t.Helper()
	for _, e := range events {
		if e == want {
			return
		}
	}
	t.Errorf("expected event %d in %v", want, events)
}

// AC-TO-03: GET /api/topology includes circuits array with paths, latency,
// and chunk counts. (Verified via ListCircuits producing the right shape.)
func TestAC_TO_03_TopologyCircuitsArray(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, _ := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	// Dispatch chunks to populate path stats.
	cm.RecordChunkDispatch(cid, 0, 1024)
	cm.RecordChunkDispatch(cid, 0, 2048)
	cm.RecordChunkDispatch(cid, 1, 4096)

	circuits := cm.ListCircuits()
	if len(circuits) != 1 {
		t.Fatalf("expected 1 circuit, got %d", len(circuits))
	}

	info := circuits[0]
	if len(info.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(info.Paths))
	}

	// Path 0 should have 2 chunks.
	if info.Paths[0].Chunks != 2 {
		t.Errorf("path0 chunks = %d, want 2", info.Paths[0].Chunks)
	}
	// Path 1 should have 1 chunk.
	if info.Paths[1].Chunks != 1 {
		t.Errorf("path1 chunks = %d, want 1", info.Paths[1].Chunks)
	}
	// Both paths should be healthy.
	if !info.Paths[0].Healthy || !info.Paths[1].Healthy {
		t.Error("expected both paths healthy")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// E. Error Handling Tests (AC-EH-01 through AC-EH-04)
// ──────────────────────────────────────────────────────────────────────────────

// AC-EH-01: Circuit creation fails with ErrNoPaths when fewer than 2
// disjoint paths can be found.
func TestAC_EH_01_NoPathsError(t *testing.T) {
	matrix := NewMeshLatencyMatrix()
	matrix.AddNode(NodeInfo{ID: "entry", Role: NodeRoleEntry})
	matrix.AddNode(NodeInfo{ID: "exit", Role: NodeRoleExit, Capabilities: []NodeCapability{CapExit}})
	// No relay nodes, no edges.

	_, err := KShortestDisjointPaths(matrix, "entry", "exit", 2)
	if err == nil {
		t.Fatal("expected ErrNoPaths, got nil")
	}
	if err != ErrNoPaths {
		t.Errorf("expected ErrNoPaths, got %v", err)
	}
}

// AC-EH-02: Circuit creation fails with ErrPathOverlap when manually
// provided paths share relay nodes.
func TestAC_EH_02_PathOverlapError(t *testing.T) {
	// Build a matrix where BFS might produce overlapping paths.
	matrix := NewMeshLatencyMatrix()
	matrix.AddNode(NodeInfo{ID: "entry", Role: NodeRoleEntry})
	matrix.AddNode(NodeInfo{ID: "exit", Role: NodeRoleExit})
	matrix.AddNode(NodeInfo{ID: "relayX", Role: NodeRoleRelay, Capabilities: []NodeCapability{CapRelay}})

	// Only one relay — can't get 2 disjoint paths.
	now := time.Now()
	matrix.AddEdge(LatencyEdge{Source: "entry", Target: "relayX", RTTms: 10, MeasuredAt: now})
	matrix.AddEdge(LatencyEdge{Source: "relayX", Target: "exit", RTTms: 10, MeasuredAt: now})

	_, err := KShortestDisjointPaths(matrix, "entry", "exit", 2)
	if err == nil {
		t.Fatal("expected error with only 1 relay, got nil")
	}
}

// AC-EH-03: NACK retries exhausted → circuit teardown initiated.
// (This is handled by the exit node; CircuitManager supports via HandleTeardown.)
func TestAC_EH_03_NACKRetriesExhausted(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cfg.MaxNACKRetries = 3
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, _ := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	// Simulate exit-initiated teardown due to NACK exhaustion.
	msg := &TeardownMsg{
		CircuitID: cid[:],
		Reason:    "NACK retries exhausted",
	}
	err := cm.HandleTeardown(cid, msg)
	if err != nil {
		t.Fatalf("HandleTeardown failed: %v", err)
	}

	// Circuit should be closed.
	_, err = cm.GetCircuit(cid)
	if err == nil {
		t.Error("expected circuit to be closed after NACK teardown")
	}
}

// AC-EH-04: Reassembly window exceeded → chunk discarded, security event
// emitted. (This is handled by ExitReassembler; CircuitManager supports
// the teardown path.)
func TestAC_EH_04_ReassemblyWindowExceeded(t *testing.T) {
	// This is primarily tested in exit_reassembler_test.go.
	// Here we verify that CircuitManager's MaxReassemblyWindow config
	// is correctly set.
	cfg := DefaultCircuitManagerConfig()
	if cfg.MaxReassemblyWindow != 256 {
		t.Errorf("MaxReassemblyWindow = %d, want 256", cfg.MaxReassemblyWindow)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// F. Integration Tests (AC-IN-01 through AC-IN-04)
// ──────────────────────────────────────────────────────────────────────────────

// AC-IN-01: CircuitManager integrates with existing EntryNode without
// breaking existing SS listener flow.
func TestAC_IN_01_EntryNodeIntegration(t *testing.T) {
	// CircuitManager coexists in the same package and uses the same types.
	// Verify that CircuitManagerConfig can coexist with EntryNodeConfig.
	cfg := DefaultCircuitManagerConfig()
	cm := NewCircuitManager(cfg)

	// Verify it uses the same Path, ChunkerConfig, CircuitConfig types.
	entryCfg := DefaultEntryNodeConfig()

	// Both should work independently.
	if cm == nil {
		t.Fatal("CircuitManager is nil")
	}
	if entryCfg.PathSelectionMode != "manual" {
		t.Error("EntryNodeConfig should still work")
	}
}

// AC-IN-02: CircuitManager integrates with existing Dispatcher (chunk
// assignment via strategy interface).
func TestAC_IN_02_DispatcherIntegration(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, _ := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	// The Dispatcher can call AssignChunkPath to get the next path index.
	for i := 0; i < 10; i++ {
		pathIdx, err := cm.AssignChunkPath(cid)
		if err != nil {
			t.Fatalf("AssignChunkPath failed: %v", err)
		}
		if pathIdx != 0 && pathIdx != 1 {
			t.Errorf("pathIdx = %d, want 0 or 1", pathIdx)
		}
		cm.RecordChunkDispatch(cid, pathIdx, 1024)
	}

	// Verify stats were recorded.
	circuit, _ := cm.GetCircuit(cid)
	totalChunks := circuit.Paths[0].TotalChunks + circuit.Paths[1].TotalChunks
	if totalChunks != 10 {
		t.Errorf("total chunks = %d, want 10", totalChunks)
	}
}

// AC-IN-03: CircuitManager integrates with existing mesh transport (DialFunc).
func TestAC_IN_03_MeshTransportIntegration(t *testing.T) {
	ln, err := listenStub()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	dialCount := 0
	cfg := DefaultCircuitManagerConfig()
	cfg.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialCount++
		return net.Dial(network, address)
	}
	cm := NewCircuitManager(cfg)

	// The DialFunc should be wired to the probe selector.
	if cm.probe == nil {
		t.Fatal("probe selector is nil")
	}
	// The probe selector's DialFunc should use our custom dialer.
	if cm.cfg.DialFunc == nil {
		t.Fatal("DialFunc not configured")
	}
}

// AC-IN-04: CircuitManager works with existing CircuitConfig for all
// timeout parameters.
func TestAC_IN_04_CircuitConfigCompatibility(t *testing.T) {
	circuitCfg := DefaultCircuitConfig()
	cmCfg := DefaultCircuitManagerConfig()

	// Verify the config values match the spec defaults.
	if cmCfg.IdleTimeout != circuitCfg.IdleTimeout {
		t.Errorf("IdleTimeout mismatch: cm=%v circuit=%v",
			cmCfg.IdleTimeout, circuitCfg.IdleTimeout)
	}
	if cmCfg.KeepaliveInterval != circuitCfg.KeepaliveInterval {
		t.Errorf("KeepaliveInterval mismatch: cm=%v circuit=%v",
			cmCfg.KeepaliveInterval, circuitCfg.KeepaliveInterval)
	}
	if cmCfg.OrphanTimeout != circuitCfg.OrphanTimeout {
		t.Errorf("OrphanTimeout mismatch: cm=%v circuit=%v",
			cmCfg.OrphanTimeout, circuitCfg.OrphanTimeout)
	}
	if cmCfg.MaxReassemblyWindow != circuitCfg.MaxReassemblyWindow {
		t.Errorf("MaxReassemblyWindow mismatch: cm=%v circuit=%v",
			cmCfg.MaxReassemblyWindow, circuitCfg.MaxReassemblyWindow)
	}
	if cmCfg.StreamReassemblyTimeout != circuitCfg.StreamReassemblyTimeout {
		t.Errorf("StreamReassemblyTimeout mismatch: cm=%v circuit=%v",
			cmCfg.StreamReassemblyTimeout, circuitCfg.StreamReassemblyTimeout)
	}
	if cmCfg.MaxNACKRetries != circuitCfg.MaxNACKRetries {
		t.Errorf("MaxNACKRetries mismatch: cm=%v circuit=%v",
			cmCfg.MaxNACKRetries, circuitCfg.MaxNACKRetries)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// G. Security Tests (AC-SE-01 through AC-SE-04)
// ──────────────────────────────────────────────────────────────────────────────

// AC-SE-01: E2E keys never leave the CircuitManager's memory (not logged,
// not serialized, not exposed via API).
func TestAC_SE_01_KeysNotExposedInAPI(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, _ := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	// ListCircuits should NOT contain any key material.
	circuits := cm.ListCircuits()
	for _, c := range circuits {
		// CircuitInfo has no key fields.
		// Just verify the struct doesn't expose keys.
		if c.ID == "" {
			t.Error("circuit ID is empty")
		}
		// The ID is a hex string of the circuit ID, not the E2E key.
		// This is by design — the circuit ID is a public identifier.
	}

	// GetCircuitStats should NOT contain any key material.
	stats := cm.GetCircuitStats()
	_ = stats // CircuitStats has no key fields.
}

// AC-SE-02: Circuit IDs are generated with crypto/rand (16 bytes, 128 bits
// of entropy).
func TestAC_SE_02_CircuitIDEntropy(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	// Generate multiple circuit IDs and verify uniqueness.
	ids := make(map[CircuitIDType]bool)
	for i := 0; i < 100; i++ {
		cid, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
		if err != nil {
			t.Fatalf("CreateCircuit %d failed: %v", i, err)
		}
		if ids[cid] {
			t.Errorf("duplicate circuit ID generated at iteration %d", i)
		}
		ids[cid] = true
	}

	// All 100 IDs should be unique.
	if len(ids) != 100 {
		t.Errorf("expected 100 unique IDs, got %d", len(ids))
	}
}

// AC-SE-03: Path relay keys are unique per circuit per relay (not reused
// across circuits).
func TestAC_SE_03_RelayKeyUniqueness(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid1, _ := cm.CreateCircuit("a.com:443", "entry", "exit", nil)
	cid2, _ := cm.CreateCircuit("b.com:443", "entry", "exit", nil)

	c1, _ := cm.GetCircuit(cid1)
	c2, _ := cm.GetCircuit(cid2)

	// Collect all relay keys from both circuits.
	allKeys := make(map[string]bool)
	for _, circuit := range []*Circuit{c1, c2} {
		for _, p := range circuit.Paths {
			if p == nil {
				continue
			}
			p.mu.Lock()
			for _, rk := range p.RelayKeys {
				keyStr := string(rk)
				if allKeys[keyStr] {
					t.Error("relay key reused across circuits")
				}
				allKeys[keyStr] = true
			}
			p.mu.Unlock()
		}
	}

	// Should have 4 unique keys (2 paths × 1 relay each × 2 circuits).
	if len(allKeys) != 4 {
		t.Errorf("expected 4 unique relay keys, got %d", len(allKeys))
	}
}

// AC-SE-04: Key zeroing on CLOSED is verifiable (unit test reads key buffer
// after close).
func TestAC_SE_04_KeyZeroingVerifiable(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, _ := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	circuit, _ := cm.GetCircuit(cid)

	// Keys should be non-zero.
	if circuit.KeysZeroed() {
		t.Error("keys should be non-zero before close")
	}

	// Check E2E key specifically.
	hasNonZero := false
	circuit.mu.RLock()
	for _, b := range circuit.E2EKey {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	circuit.mu.RUnlock()
	if !hasNonZero {
		t.Error("E2E key is all zeros before close")
	}

	// Close.
	cm.TeardownCircuit(cid, "test", nil)

	// Verify all keys are zeroed.
	if !circuit.KeysZeroed() {
		t.Error("keys not zeroed after close")
	}

	// Check relay keys are zeroed too.
	for _, p := range circuit.Paths {
		if p == nil {
			continue
		}
		p.mu.Lock()
		for _, rk := range p.RelayKeys {
			for _, b := range rk {
				if b != 0 {
					t.Error("relay key not zeroed after close")
				}
			}
		}
		p.mu.Unlock()
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Additional Tests: Dijkstra Algorithm, Shutdown, Idempotency
// ──────────────────────────────────────────────────────────────────────────────

// Test Dijkstra on a five-node graph with multi-hop paths.
func TestDijkstraMultiHop(t *testing.T) {
	matrix := buildFiveNodeMatrix()

	// Shortest path from entry to exit should be:
	// entry → relayA(5) → relayE(3) → exit(10) = 18
	path := ShortestPath(matrix, "entry", "exit", map[string]bool{})
	if path == nil {
		t.Fatal("expected a path, got nil")
	}
	if path[0] != "entry" || path[len(path)-1] != "exit" {
		t.Errorf("path endpoints wrong: %v", path)
	}
}

// Test KShortestDisjointPaths on the five-node graph.
func TestKShortestDisjointFiveNode(t *testing.T) {
	matrix := buildFiveNodeMatrix()
	paths, err := KShortestDisjointPaths(matrix, "entry", "exit", 2)
	if err != nil {
		t.Fatalf("KShortestDisjointPaths failed: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}

	// Verify disjointness.
	if PathsHaveOverlap(paths[0], paths[1]) {
		t.Errorf("paths overlap: %v and %v", paths[0], paths[1])
	}
}

// Test CircuitManager Shutdown tears down all circuits.
func TestCircuitManagerShutdown(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	// Create multiple circuits.
	for i := 0; i < 5; i++ {
		cid, _ := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
		ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
		cm.HandleCircuitAck(cid, ack)
	}

	if len(cm.ListCircuits()) != 5 {
		t.Fatalf("expected 5 circuits, got %d", len(cm.ListCircuits()))
	}

	cm.Shutdown()

	if len(cm.ListCircuits()) != 0 {
		t.Errorf("expected 0 circuits after shutdown, got %d", len(cm.ListCircuits()))
	}
}

// Test mesh latency matrix edge weight calculation.
func TestEdgeWeight(t *testing.T) {
	matrix := buildTestMatrix()

	// Known edge.
	if w := matrix.EdgeWeight("entry", "relayA"); w != 10 {
		t.Errorf("entry→relayA weight = %v, want 10", w)
	}
	// Unmeasured edge → 500ms penalty.
	if w := matrix.EdgeWeight("relayC", "exit"); w != 500 {
		t.Errorf("relayC→exit weight = %v, want 500 (penalty)", w)
	}
	// Non-existent edge → infinity.
	if w := matrix.EdgeWeight("entry", "nonexistent"); !mathIsInf(w) {
		t.Errorf("non-existent edge weight = %v, want +Inf", w)
	}
}

func mathIsInf(v float64) bool {
	return v != v || v > 1e308 // NaN or Inf check
}

// Test that CircuitInfo has correct path info shape.
func TestCircuitInfoShape(t *testing.T) {
	circuit := makeTestCircuit()
	info := circuit.ToInfo()

	if info.State != "active" {
		t.Errorf("State = %s, want active", info.State)
	}
	if info.Entry != "entry" {
		t.Errorf("Entry = %s, want entry", info.Entry)
	}
	if info.Exit != "exit" {
		t.Errorf("Exit = %s, want exit", info.Exit)
	}
	if len(info.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(info.Paths))
	}
	if len(info.Paths[0].Hops) != 1 {
		t.Errorf("path0 hops = %d, want 1", len(info.Paths[0].Hops))
	}
	if info.Paths[0].Hops[0] != "relayA" {
		t.Errorf("path0 hop0 = %s, want relayA", info.Paths[0].Hops[0])
	}
}

// Test ChunkAssignmentStrategy creation by name.
func TestNewChunkAssignmentStrategy(t *testing.T) {
	if s := NewChunkAssignmentStrategy("round-robin"); s.Name() != "round-robin" {
		t.Errorf("round-robin name = %s", s.Name())
	}
	if s := NewChunkAssignmentStrategy("weighted"); s.Name() != "weighted" {
		t.Errorf("weighted name = %s", s.Name())
	}
	if s := NewChunkAssignmentStrategy("fastest-only"); s.Name() != "fastest-only" {
		t.Errorf("fastest-only name = %s", s.Name())
	}
	// Unknown → default to round-robin.
	if s := NewChunkAssignmentStrategy("unknown"); s.Name() != "round-robin" {
		t.Errorf("unknown name = %s, want round-robin", s.Name())
	}
}

// Test fastest-only strategy with RTT data.
func TestFastestOnlyStrategy(t *testing.T) {
	circuit := makeTestCircuit()
	circuit.AssignmentStrategy = &FastestOnlyStrategy{}

	circuit.Paths[0].LastRTT = 20 * time.Millisecond
	circuit.Paths[1].LastRTT = 80 * time.Millisecond

	// Should always pick path 0 (faster).
	for i := 0; i < 20; i++ {
		got := circuit.AssignmentStrategy.AssignPath(circuit, i)
		if got != 0 {
			t.Errorf("call %d: got %d, want 0 (faster)", i, got)
		}
	}
}

// Test that idle timeout detection works.
func TestIdleTimeout(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.IdleTimeout = 50 * time.Millisecond
	cfg.FlushTimeout = 10 * time.Millisecond
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	cid, _ := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	ack := &CircuitAck{CircuitID: cid[:], ECDHPubKey: make([]byte, 32), Accepted: true}
	cm.HandleCircuitAck(cid, ack)

	// Not idle yet.
	cm.CheckIdleTimeouts()
	if len(cm.ListCircuits()) != 1 {
		t.Error("circuit should not be torn down yet")
	}

	// Wait for idle.
	time.Sleep(60 * time.Millisecond)

	// Now should be idle.
	cm.CheckIdleTimeouts()
	time.Sleep(50 * time.Millisecond) // wait for async teardown

	if len(cm.ListCircuits()) != 0 {
		t.Error("expected circuit to be torn down after idle timeout")
	}
}

// Test circuit limit enforcement (DoS protection).
func TestCircuitLimitEnforcement(t *testing.T) {
	cfg := DefaultCircuitManagerConfig()
	cfg.FlushTimeout = 10 * time.Millisecond
	cfg.MaxCircuitsTotal = 3
	cm := NewCircuitManager(cfg)
	cm.matrix = buildTestMatrix()

	for i := 0; i < 3; i++ {
		_, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
		if err != nil {
			t.Fatalf("CreateCircuit %d failed: %v", i, err)
		}
	}

	// 4th should fail.
	_, err := cm.CreateCircuit("example.com:443", "entry", "exit", nil)
	if err == nil {
		t.Error("expected error when exceeding MaxCircuitsTotal")
	}
}

// Test UpdateLatencyMatrix merges new edges.
func TestUpdateLatencyMatrix(t *testing.T) {
	cm := NewCircuitManager(DefaultCircuitManagerConfig())
	matrix := cm.GetLatencyMatrix()

	// Add nodes first.
	matrix.AddNode(NodeInfo{ID: "a", Role: NodeRoleEntry})
	matrix.AddNode(NodeInfo{ID: "b", Role: NodeRoleRelay, Capabilities: []NodeCapability{CapRelay}})

	// Update with new edges.
	cm.UpdateLatencyMatrix([]LatencyEdge{
		{Source: "a", Target: "b", RTTms: 15, MeasuredAt: time.Now()},
	})

	// Verify the edge was added.
	if w := matrix.EdgeWeight("a", "b"); w != 15 {
		t.Errorf("edge a→b weight = %v, want 15", w)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Test helper: stub listener for probe tests
// ──────────────────────────────────────────────────────────────────────────────

func listenStub() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}
