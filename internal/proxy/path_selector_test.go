package proxy

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestComputePathScore verifies the path quality scoring formula.
func TestComputePathScore(t *testing.T) {
	tests := []struct {
		name     string
		rtt      time.Duration
		hops     int
		capacity int
		want     float64
	}{
		{
			name:     "low_rtt_single_hop_high_cap",
			rtt:      10 * time.Millisecond,
			hops:     1,
			capacity: 1024,
			want:     10.0 + 50.0 + 0.0, // 60
		},
		{
			name:     "high_rtt_multi_hop",
			rtt:      100 * time.Millisecond,
			hops:     3,
			capacity: 512,
			want:     100.0 + 150.0 + 0.0, // 250 (capacity >= 256, no penalty)
		},
		{
			name:     "unknown_capacity",
			rtt:      20 * time.Millisecond,
			hops:     1,
			capacity: 0,
			want:     20.0 + 50.0 + 10.0, // 80 (unknown cap penalty)
		},
		{
			name:     "low_capacity",
			rtt:      20 * time.Millisecond,
			hops:     1,
			capacity: 100,
			want:     20.0 + 50.0 + 15.6, // 85.6 (256-100=156, *0.1=15.6)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputePathScore(tt.rtt, tt.hops, tt.capacity)
			if abs(got-tt.want) > 0.01 {
				t.Errorf("ComputePathScore(%v, %d, %d) = %.2f, want %.2f",
					tt.rtt, tt.hops, tt.capacity, got, tt.want)
			}
		})
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// TestPathSelectorSelectPaths verifies that the selector produces
// two disjoint paths from candidates with a mock probe function.
func TestPathSelectorSelectPaths(t *testing.T) {
	// Create a mock dial function that returns different RTTs.
	rtts := map[string]time.Duration{
		"10.10.0.1:51820": 10 * time.Millisecond,
		"10.10.0.2:51820": 20 * time.Millisecond,
		"10.10.0.3:51820": 30 * time.Millisecond,
		"10.10.0.4:51820": 40 * time.Millisecond,
	}

	dialFunc := func(ctx context.Context, addr string) (time.Duration, error) {
		rtt, ok := rtts[addr]
		if !ok {
			return 0, fmt.Errorf("unknown addr")
		}
		return rtt, nil
	}

	cfg := PathSelectorConfig{
		MaxRelaysPerPath: 1,
		ProbeTimeout:     1 * time.Second,
		ProbeConcurrency: 4,
		MinCandidates:    2,
		MaxCandidates:    10,
		PathCount:        2,
		DialFunc:         dialFunc,
	}

	selector := NewPathSelector(cfg)

	candidates := []CandidateRelay{
		{NodeID: "relayA", MeshAddr: "10.10.0.1:51820"},
		{NodeID: "relayB", MeshAddr: "10.10.0.2:51820"},
		{NodeID: "relayC", MeshAddr: "10.10.0.3:51820"},
		{NodeID: "relayD", MeshAddr: "10.10.0.4:51820"},
	}

	p1, p2, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatal(err)
	}

	// Verify paths are disjoint.
	if HasOverlap(p1, p2) {
		t.Error("selected paths overlap — must be disjoint")
	}

	// Verify each path has at least one relay.
	if len(p1.Relays) == 0 {
		t.Error("path1 has no relays")
	}
	if len(p2.Relays) == 0 {
		t.Error("path2 has no relays")
	}

	// Verify relay keys are correct size.
	for i, key := range p1.RelayKeys {
		if len(key) != KeySize {
			t.Errorf("p1.RelayKeys[%d] length = %d, want %d", i, len(key), KeySize)
		}
	}
	for i, key := range p2.RelayKeys {
		if len(key) != KeySize {
			t.Errorf("p2.RelayKeys[%d] length = %d, want %d", i, len(key), KeySize)
		}
	}

	// The selector should pick the two lowest-RTT relays.
	t.Logf("path1 relays: %v", p1.Relays)
	t.Logf("path2 relays: %v", p2.Relays)
}

// TestPathSelectorInsufficientCandidates verifies error on too few candidates.
func TestPathSelectorInsufficientCandidates(t *testing.T) {
	cfg := DefaultPathSelectorConfig()
	cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	}
	selector := NewPathSelector(cfg)

	_, _, err := selector.SelectPaths(context.Background(), []CandidateRelay{
		{NodeID: "relayA", MeshAddr: "10.10.0.1:51820"},
	}, "10.10.0.99:51820")
	if err == nil {
		t.Error("expected error for insufficient candidates")
	}
}

// TestPathSelectorAllProbesFail verifies error when all probes fail.
func TestPathSelectorAllProbesFail(t *testing.T) {
	cfg := DefaultPathSelectorConfig()
	cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
		return 0, fmt.Errorf("connection refused")
	}
	selector := NewPathSelector(cfg)

	candidates := []CandidateRelay{
		{NodeID: "relayA", MeshAddr: "10.10.0.1:51820"},
		{NodeID: "relayB", MeshAddr: "10.10.0.2:51820"},
	}

	_, _, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err == nil {
		t.Error("expected error when all probes fail")
	}
}

// TestPathSelectorProbeCache verifies that cached probe results
// are used on subsequent selections.
func TestPathSelectorProbeCache(t *testing.T) {
	var probeCount int32

	cfg := DefaultPathSelectorConfig()
	cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
		atomic.AddInt32(&probeCount, 1)
		return 10 * time.Millisecond, nil
	}

	selector := NewPathSelector(cfg)

	candidates := []CandidateRelay{
		{NodeID: "relayA", MeshAddr: "10.10.0.1:51820"},
		{NodeID: "relayB", MeshAddr: "10.10.0.2:51820"},
	}

	// First selection: probes all candidates.
	_, _, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatal(err)
	}
	firstCount := atomic.LoadInt32(&probeCount)
	if firstCount != 2 {
		t.Errorf("first selection: expected 2 probes, got %d", firstCount)
	}

	// Second selection: should use cached results.
	_, _, err = selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatal(err)
	}
	secondCount := atomic.LoadInt32(&probeCount)
	if secondCount != firstCount {
		t.Errorf("second selection: expected %d probes (cached), got %d", firstCount, secondCount)
	}
}

// TestPathSelectorInvalidateCache verifies that invalidating a cache
// entry forces a re-probe.
func TestPathSelectorInvalidateCache(t *testing.T) {
	var probeCount int32

	cfg := DefaultPathSelectorConfig()
	cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
		atomic.AddInt32(&probeCount, 1)
		return 10 * time.Millisecond, nil
	}

	selector := NewPathSelector(cfg)

	candidates := []CandidateRelay{
		{NodeID: "relayA", MeshAddr: "10.10.0.1:51820"},
		{NodeID: "relayB", MeshAddr: "10.10.0.2:51820"},
	}

	// First selection.
	_, _, _ = selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	firstCount := atomic.LoadInt32(&probeCount)

	// Invalidate cache for relayA.
	selector.InvalidateProbeCache("relayA")

	// Second selection: relayA should be re-probed.
	_, _, _ = selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	secondCount := atomic.LoadInt32(&probeCount)

	if secondCount != firstCount+1 {
		t.Errorf("after invalidate: expected %d probes, got %d", firstCount+1, secondCount)
	}
}

// TestPathSelectorFilterCandidates verifies that candidates are
// pre-filtered by advertised RTT and sorted best-first.
func TestPathSelectorFilterCandidates(t *testing.T) {
	cfg := DefaultPathSelectorConfig()
	cfg.MaxCandidates = 3
	selector := NewPathSelector(cfg)

	candidates := []CandidateRelay{
		{NodeID: "relayA", MeshAddr: "10.10.0.1:51820", AdvertisedRTT: 50 * time.Millisecond},
		{NodeID: "relayB", MeshAddr: "10.10.0.2:51820", AdvertisedRTT: 10 * time.Millisecond},
		{NodeID: "relayC", MeshAddr: "10.10.0.3:51820", AdvertisedRTT: 30 * time.Millisecond},
		{NodeID: "relayD", MeshAddr: "10.10.0.4:51820", AdvertisedRTT: 20 * time.Millisecond},
		{NodeID: "relayE", MeshAddr: "10.10.0.5:51820", AdvertisedRTT: 40 * time.Millisecond},
	}

	filtered := selector.filterCandidates(candidates)

	// filterCandidates sorts by advertised RTT (best first).
	// MaxCandidates limit is applied in SelectPaths, not in filterCandidates.
	// Verify the ordering is correct.
	if filtered[0].NodeID != "relayB" {
		t.Errorf("expected relayB first (10ms), got %s", filtered[0].NodeID)
	}
	if filtered[1].NodeID != "relayD" {
		t.Errorf("expected relayD second (20ms), got %s", filtered[1].NodeID)
	}
	if filtered[2].NodeID != "relayC" {
		t.Errorf("expected relayC third (30ms), got %s", filtered[2].NodeID)
	}
}

// TestSelectExit verifies exit node selection based on latency matrix.
func TestSelectExit(t *testing.T) {
	exitProbes := map[string]map[string]time.Duration{
		"exit-tokyo": {
			"jp":      5 * time.Millisecond,
			"us-west": 120 * time.Millisecond,
			"eu":      200 * time.Millisecond,
		},
		"exit-uswest": {
			"jp":      110 * time.Millisecond,
			"us-west": 8 * time.Millisecond,
			"eu":      150 * time.Millisecond,
		},
		"exit-fra": {
			"jp":      250 * time.Millisecond,
			"us-west": 180 * time.Millisecond,
			"eu":      12 * time.Millisecond,
		},
	}

	tests := []struct {
		region string
		want   string
	}{
		{"jp", "exit-tokyo"},
		{"us-west", "exit-uswest"},
		{"eu", "exit-fra"},
	}

	for _, tt := range tests {
		t.Run(tt.region, func(t *testing.T) {
			got, err := SelectExit(exitProbes, tt.region)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("SelectExit(%s) = %s, want %s", tt.region, got, tt.want)
			}
		})
	}
}

// TestSelectExitFallback verifies fallback when no exact region match.
func TestSelectExitFallback(t *testing.T) {
	exitProbes := map[string]map[string]time.Duration{
		"exit-a": {"jp": 10 * time.Millisecond, "us": 100 * time.Millisecond},
		"exit-b": {"jp": 20 * time.Millisecond, "us": 50 * time.Millisecond},
	}

	// Region "eu" has no data — should fall back to best average.
	got, err := SelectExit(exitProbes, "eu")
	if err != nil {
		t.Fatal(err)
	}
	// exit-a avg = (10+100)/2 = 55ms
	// exit-b avg = (20+50)/2 = 35ms
	// Should pick exit-b (lower average)
	if got != "exit-b" {
		t.Errorf("SelectExit(eu) fallback = %s, want exit-b", got)
	}
}

// TestSelectExitNoData verifies error on empty probe data.
func TestSelectExitNoData(t *testing.T) {
	_, err := SelectExit(map[string]map[string]time.Duration{}, "jp")
	if err == nil {
		t.Error("expected error for empty probe data")
	}
}

// TestPathSelectorDefaultProbe verifies the default TCP probe works.
func TestPathSelectorDefaultProbe(t *testing.T) {
	// Start two local TCP listeners to probe (one per relay candidate).
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln1.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()

	// Accept connections in background.
	go func() {
		for {
			conn, err := ln1.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	go func() {
		for {
			conn, err := ln2.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	cfg := DefaultPathSelectorConfig()
	cfg.ProbeTimeout = 2 * time.Second
	// No DialFunc — uses default TCP probe.
	selector := NewPathSelector(cfg)

	candidates := []CandidateRelay{
		{NodeID: "relayA", MeshAddr: ln1.Addr().String()},
		{NodeID: "relayB", MeshAddr: ln2.Addr().String()},
	}

	p1, p2, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatal(err)
	}

	if p1 == nil || p2 == nil {
		t.Fatal("paths should not be nil")
	}

	// Paths use different relay MeshAddrs, so they should be disjoint.
	if HasOverlap(p1, p2) {
		t.Error("paths should be disjoint (different relay addresses)")
	}
}
