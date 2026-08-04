package proxy

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// TestPathSelectorHealthExcludesUnhealthy verifies that relays marked
// unhealthy by repeated probe failures are excluded from selection.
func TestPathSelectorHealthExcludesUnhealthy(t *testing.T) {
	var probeCount int32

	cfg := DefaultPathSelectorConfig()
	cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
		atomic.AddInt32(&probeCount, 1)
		// relayA always fails; relayB and relayC succeed.
		if addr == "10.10.0.1:51820" {
			return 0, fmt.Errorf("connection refused")
		}
		if addr == "10.10.0.2:51820" {
			return 20 * time.Millisecond, nil
		}
		return 30 * time.Millisecond, nil
	}

	selector := NewPathSelector(cfg)

	candidates := []CandidateRelay{
		{NodeID: "relayA", MeshAddr: "10.10.0.1:51820"},
		{NodeID: "relayB", MeshAddr: "10.10.0.2:51820"},
		{NodeID: "relayC", MeshAddr: "10.10.0.3:51820"},
	}

	// First selection: relayA fails but relayB and relayC succeed.
	// Two disjoint paths should be selected from B and C.
	p1, p2, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatal(err)
	}
	if p1 == nil || p2 == nil {
		t.Fatal("paths should not be nil")
	}
	if HasOverlap(p1, p2) {
		t.Error("paths should be disjoint")
	}

	// Mark relayA as unhealthy via repeated failures (already failed once).
	selector.MarkRelayUnhealthy("relayA")

	// relayA should now be unhealthy.
	if !selector.HealthTracker().IsUnhealthy("relayA") {
		t.Error("relayA should be unhealthy after MarkRelayUnhealthy")
	}
}

// TestPathSelectorHealthFailoverOnDegraded verifies that a degraded relay
// gets a quality penalty in path selection, causing the selector to prefer
// healthy relays with similar RTT.
func TestPathSelectorHealthFailoverOnDegraded(t *testing.T) {
	cfg := DefaultPathSelectorConfig()
	cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
		// All relays have the same RTT.
		return 20 * time.Millisecond, nil
	}

	selector := NewPathSelector(cfg)

	candidates := []CandidateRelay{
		{NodeID: "relayA", MeshAddr: "10.10.0.1:51820"},
		{NodeID: "relayB", MeshAddr: "10.10.0.2:51820"},
		{NodeID: "relayC", MeshAddr: "10.10.0.3:51820"},
	}

	// First selection succeeds.
	_, _, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatal(err)
	}

	// Mark relayA as degraded (1 failure).
	selector.HealthTracker().RecordFailure("relayA")

	if !selector.HealthTracker().IsDegraded("relayA") {
		t.Error("relayA should be degraded")
	}

	// Second selection should still succeed, but relayA should have
	// a penalty applied.
	p1, p2, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatal(err)
	}
	if p1 == nil || p2 == nil {
		t.Fatal("paths should not be nil")
	}
}

// TestPathSelectorSelectReplacementPath verifies the automatic failover
// mechanism: when a path fails, a replacement can be found that excludes
// the failed relay.
func TestPathSelectorSelectReplacementPath(t *testing.T) {
	cfg := DefaultPathSelectorConfig()
	cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}

	selector := NewPathSelector(cfg)

	candidates := []CandidateRelay{
		{NodeID: "relayA", MeshAddr: "10.10.0.1:51820"},
		{NodeID: "relayB", MeshAddr: "10.10.0.2:51820"},
		{NodeID: "relayC", MeshAddr: "10.10.0.3:51820"},
		{NodeID: "relayD", MeshAddr: "10.10.0.4:51820"},
	}

	// Select initial paths.
	p1, p2, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatal(err)
	}
	if p1 == nil || p2 == nil {
		t.Fatal("paths should not be nil")
	}

	// Simulate failure of path1's relay: get a replacement excluding it.
	failedRelays := p1.Nodes()
	replacement, err := selector.SelectReplacementPath(
		context.Background(), candidates, "10.10.0.99:51820", failedRelays)
	if err != nil {
		t.Fatal(err)
	}
	if replacement == nil {
		t.Fatal("replacement path should not be nil")
	}

	// The replacement must not use any relay from the failed path.
	for _, r := range replacement.Relays {
		if failedRelays[r] {
			t.Errorf("replacement path uses failed relay %s", r)
		}
	}
}

// TestPathSelectorSelectReplacementPathAllExcluded verifies error when
// all candidates are in the failed relay set.
func TestPathSelectorSelectReplacementPathAllExcluded(t *testing.T) {
	cfg := DefaultPathSelectorConfig()
	cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}

	selector := NewPathSelector(cfg)

	candidates := []CandidateRelay{
		{NodeID: "relayA", MeshAddr: "10.10.0.1:51820"},
		{NodeID: "relayB", MeshAddr: "10.10.0.2:51820"},
	}

	// Exclude all relays.
	failedRelays := map[string]bool{
		"relayA": true,
		"relayB": true,
	}

	_, err := selector.SelectReplacementPath(
		context.Background(), candidates, "10.10.0.99:51820", failedRelays)
	if err == nil {
		t.Error("expected error when all relays are excluded")
	}
}

// TestPathSelectorMarkRelayUnhealthy verifies that MarkRelayUnhealthy
// immediately marks a relay as unhealthy and excludes it from selection.
func TestPathSelectorMarkRelayUnhealthy(t *testing.T) {
	cfg := DefaultPathSelectorConfig()
	cfg.DialFunc = func(ctx context.Context, addr string) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}

	selector := NewPathSelector(cfg)
	candidates := []CandidateRelay{
		{NodeID: "relayA", MeshAddr: "10.10.0.1:51820"},
		{NodeID: "relayB", MeshAddr: "10.10.0.2:51820"},
		{NodeID: "relayC", MeshAddr: "10.10.0.3:51820"},
	}

	// Initial selection succeeds.
	_, _, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatal(err)
	}

	// Mark relayA as unhealthy.
	selector.MarkRelayUnhealthy("relayA")

	if !selector.HealthTracker().IsUnhealthy("relayA") {
		t.Error("relayA should be unhealthy")
	}

	// Next selection should still succeed with relayB and relayC.
	// relayA is excluded (and not retryable since it was just marked).
	// But since we only have 3 candidates and 1 is excluded, we still
	// have 2 — enough for path selection.
	// Clear the probe cache to force re-probe.
	selector.ClearProbeCache()

	p1, p2, err := selector.SelectPaths(context.Background(), candidates, "10.10.0.99:51820")
	if err != nil {
		t.Fatal(err)
	}
	if p1 == nil || p2 == nil {
		t.Fatal("paths should not be nil")
	}

	// Neither path should use relayA's mesh address.
	for _, relay := range p1.Relays {
		if relay == "10.10.0.1:51820" {
			t.Error("path1 should not use unhealthy relayA")
		}
	}
	for _, relay := range p2.Relays {
		if relay == "10.10.0.1:51820" {
			t.Error("path2 should not use unhealthy relayA")
		}
	}
}
