// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the dynamic path selection algorithm for the
// multi-path dispersed anonymous proxy. It replaces the Phase 1
// manual path configuration with automatic, latency-aware selection.
//
// Design (PROXY_DESIGN.md §1.5, §1.6):
//
//   - PHASE 2 AUTO SELECTION: RTT probing, automatically select two
//     lowest-latency disjoint paths.
//   - ON-DEMAND PROBING: Entry queries mesh for relay-capable nodes,
//     picks K candidates via advertised latency estimates, probes only
//     those K. Scales O(K) instead of O(N²).
//   - PATH OVERLAP DETECTION (hard requirement): The path selection
//     algorithm must reject any circuit where two candidate paths share
//     a relay node. A relay appearing on both paths can correlate
//     entry↔exit via timing even with ciphertext-only access.
//   - EXIT LATENCY MATRIX: Each exit node periodically probes target
//     regions for latency, propagated via mesh gossip protocol.
//     Entry node receives target URL → DNS resolution → GeoIP region
//     → lookup latency matrix → select optimal exit.
//
// The path selector is transport-agnostic: it operates on a candidate
// list (relay node IDs + mesh addresses) and a probe function. The
// caller wires the actual mesh transport (MeshNode.Dial) via the
// PathSelectorConfig.DialFunc field.
package proxy

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

// PathProbeResult holds the measured RTT and metadata for a probed
// relay candidate. Used by the path selector to rank candidates.
type PathProbeResult struct {
	// NodeID is the relay node's hex public key (mesh identity).
	NodeID string

	// MeshAddr is the mesh IP:port of the relay node.
	MeshAddr string

	// RTT is the measured round-trip time to this relay.
	// Zero if the probe failed.
	RTT time.Duration

	// HopCount is the number of relay hops in a multi-hop path.
	// 1 for single-hop paths. The selector uses this to balance
	// latency vs anonymity depth.
	HopCount int

	// Error is the probe error, if any. Non-nil means the relay
	// is unreachable or timed out.
	Error error
}

// PathQualityScore combines multiple factors into a single sortable
// metric for path ranking. Lower is better.
type PathQualityScore struct {
	// RTT is the total path RTT (sum of per-hop RTTs).
	RTT time.Duration

	// HopCount is the number of relay hops.
	HopCount int

	// Capacity is the relay's reported capacity (0 = unknown).
	// Higher capacity is better; we prefer paths with more headroom.
	Capacity int

	// Score is the composite quality metric. Lower is better.
	// Formula: RTT_ms * 1.0 + HopCount * 50 + capacity_penalty
	// where capacity_penalty = max(0, 1024 - capacity) * 0.1
	Score float64
}

// ComputePathScore computes the composite quality score for a path
// based on RTT, hop count, and capacity. Lower score = better path.
func ComputePathScore(rtt time.Duration, hopCount, capacity int) float64 {
	rttMs := float64(rtt.Milliseconds())
	hopPenalty := float64(hopCount) * 50.0

	// Capacity penalty: paths with unknown capacity (0) get a mild
	// penalty; paths with low capacity get penalized more.
	capPenalty := 0.0
	if capacity <= 0 {
		capPenalty = 10.0 // unknown capacity — mild penalty
	} else if capacity < 256 {
		capPenalty = float64(256-capacity) * 0.1
	}

	return rttMs + hopPenalty + capPenalty
}

// CandidateRelay describes a relay node available for path selection.
type CandidateRelay struct {
	// NodeID is the hex public key of the relay node.
	NodeID string

	// MeshAddr is the mesh IP:port for probing and connection.
	MeshAddr string

	// Capabilities is the set of capabilities this node advertises.
	// Must include "relay" for it to be a valid relay candidate.
	Capabilities []string

	// AdvertisedRTT is the relay's self-reported latency estimate.
	// Used for initial filtering before active probing. Zero means
	// no estimate available; the selector will probe directly.
	AdvertisedRTT time.Duration

	// MaxCircuits is the relay's advertised circuit capacity.
	// Used for load-aware selection. Zero means unknown.
	MaxCircuits int
}

// PathSelectorConfig holds configuration for the path selector.
type PathSelectorConfig struct {
	// MaxRelaysPerPath is the maximum number of relay hops per path.
	// Default: 2 (entry → relay₁ → relay₂ → exit).
	// Higher values increase anonymity but add latency.
	MaxRelaysPerPath int

	// ProbeTimeout is the timeout for each individual relay probe.
	// Default: 3 seconds.
	ProbeTimeout time.Duration

	// ProbeConcurrency limits the number of concurrent probes.
	// Default: 8.
	ProbeConcurrency int

	// MinCandidates is the minimum number of candidates needed
	// to run selection. If fewer candidates are available, the
	// selector falls back to whatever paths it can build.
	// Default: 2.
	MinCandidates int

	// MaxCandidates is the maximum number of candidates to probe.
	// This implements the O(K) scaling from PROXY_DESIGN.md §1.5.
	// Default: 10.
	MaxCandidates int

	// PathCount is the number of disjoint paths to select.
	// Currently fixed at 2 per the design. Configurable for future.
	PathCount int

	// DialFunc is used to probe relay RTTs. If nil, a TCP-based
	// dial+close probe is used. In production, this should be
	// wired to MeshNode.Dial for mesh-internal probing.
	DialFunc func(ctx context.Context, addr string) (time.Duration, error)

	// ExitProbeResults holds RTT measurements from exit nodes to
	// target regions. Used for exit selection (PROXY_DESIGN.md §1.6).
	// Map key: exitNodeID → map[region]RTT
	ExitProbeResults map[string]map[string]time.Duration
}

// DefaultPathSelectorConfig returns sensible defaults.
func DefaultPathSelectorConfig() PathSelectorConfig {
	return PathSelectorConfig{
		MaxRelaysPerPath: 2,
		ProbeTimeout:     3 * time.Second,
		ProbeConcurrency: 8,
		MinCandidates:    2,
		MaxCandidates:    10,
		PathCount:        2,
	}
}

// PathSelector implements dynamic path selection for the multi-path
// dispersed proxy. It:
//  1. Filters relay candidates by advertised latency (O(K) scaling)
//  2. Actively probes K candidates in parallel
//  3. Selects N disjoint paths with the lowest composite quality score
//  4. Rejects any pair with overlapping relay nodes (hard requirement)
type PathSelector struct {
	cfg PathSelectorConfig
	mu  sync.Mutex

	// probeCache caches recent probe results to avoid re-probing
	// the same relay on every circuit setup. Entries expire after
	// probeCacheTTL.
	probeCache map[string]*probeCacheEntry

	// probeCacheTTL is how long cached probe results are valid.
	probeCacheTTL time.Duration
}

type probeCacheEntry struct {
	result  PathProbeResult
	expires time.Time
}

const defaultProbeCacheTTL = 30 * time.Second

// NewPathSelector creates a new path selector with the given config.
func NewPathSelector(cfg PathSelectorConfig) *PathSelector {
	if cfg.MaxRelaysPerPath <= 0 {
		cfg.MaxRelaysPerPath = 2
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 3 * time.Second
	}
	if cfg.ProbeConcurrency <= 0 {
		cfg.ProbeConcurrency = 8
	}
	if cfg.MinCandidates <= 0 {
		cfg.MinCandidates = 2
	}
	if cfg.MaxCandidates <= 0 {
		cfg.MaxCandidates = 10
	}
	if cfg.PathCount <= 0 {
		cfg.PathCount = 2
	}

	return &PathSelector{
		cfg:           cfg,
		probeCache:    make(map[string]*probeCacheEntry),
		probeCacheTTL: defaultProbeCacheTTL,
	}
}

// SelectPaths is the main entry point. Given a list of candidate relays
// and the exit address, it probes candidates, ranks them, and selects
// two disjoint paths with the best quality scores.
//
// Returns (path1, path2, error). Error is non-nil if fewer than two
// disjoint paths can be constructed from the candidates.
func (ps *PathSelector) SelectPaths(ctx context.Context, candidates []CandidateRelay, exitAddr string) (*Path, *Path, error) {
	if len(candidates) < ps.cfg.MinCandidates {
		return nil, nil, fmt.Errorf("insufficient relay candidates: %d (need %d)",
			len(candidates), ps.cfg.MinCandidates)
	}

	// Step 1: Filter candidates by advertised RTT (pre-probe filtering).
	// This reduces the probe set from N to K (O(K) scaling).
	filtered := ps.filterCandidates(candidates)
	if len(filtered) > ps.cfg.MaxCandidates {
		filtered = filtered[:ps.cfg.MaxCandidates]
	}

	// Step 2: Probe candidates in parallel.
	probed := ps.probeCandidates(ctx, filtered)

	// Step 3: Sort by RTT (best first).
	sort.Slice(probed, func(i, j int) bool {
		// Failed probes go to the end.
		if probed[i].Error != nil && probed[j].Error == nil {
			return false
		}
		if probed[i].Error == nil && probed[j].Error != nil {
			return true
		}
		if probed[i].Error != nil && probed[j].Error != nil {
			return false // both failed, order doesn't matter
		}
		return probed[i].RTT < probed[j].RTT
	})

	// Remove failed probes.
	valid := make([]PathProbeResult, 0, len(probed))
	for _, p := range probed {
		if p.Error == nil {
			valid = append(valid, p)
		}
	}

	if len(valid) < 2 {
		return nil, nil, fmt.Errorf("only %d relays responded to probe (need 2)", len(valid))
	}

	// Step 4: Select two disjoint paths.
	// For v1, we select single-hop paths (entry → relay → exit) and
	// ensure the two relay sets are disjoint. Multi-hop path construction
	// is supported but requires more candidates.
	return ps.selectDisjointPaths(valid, exitAddr)
}

// filterCandidates reduces the candidate set by advertised RTT estimates.
// If no advertised RTTs are available, all candidates are returned.
func (ps *PathSelector) filterCandidates(candidates []CandidateRelay) []CandidateRelay {
	// If no candidates have advertised RTTs, return all.
	hasRTT := false
	for _, c := range candidates {
		if c.AdvertisedRTT > 0 {
			hasRTT = true
			break
		}
	}
	if !hasRTT {
		return candidates
	}

	// Sort by advertised RTT and take the top MaxCandidates.
	sorted := make([]CandidateRelay, len(candidates))
	copy(sorted, candidates)
	sort.Slice(sorted, func(i, j int) bool {
		// Candidates with no RTT estimate go after those with estimates.
		if sorted[i].AdvertisedRTT == 0 && sorted[j].AdvertisedRTT > 0 {
			return false
		}
		if sorted[i].AdvertisedRTT > 0 && sorted[j].AdvertisedRTT == 0 {
			return true
		}
		return sorted[i].AdvertisedRTT < sorted[j].AdvertisedRTT
	})

	return sorted
}

// probeCandidates probes all candidates in parallel, respecting the
// concurrency limit. Returns results in the same order as candidates.
func (ps *PathSelector) probeCandidates(ctx context.Context, candidates []CandidateRelay) []PathProbeResult {
	results := make([]PathProbeResult, len(candidates))

	// Use a semaphore to limit concurrency.
	sem := make(chan struct{}, ps.cfg.ProbeConcurrency)
	var wg sync.WaitGroup

	for i, c := range candidates {
		wg.Add(1)
		go func(idx int, candidate CandidateRelay) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check cache first.
			ps.mu.Lock()
			if cached, ok := ps.probeCache[candidate.NodeID]; ok && time.Now().Before(cached.expires) {
				results[idx] = cached.result
				ps.mu.Unlock()
				return
			}
			ps.mu.Unlock()

			// Probe.
			rtt, err := ps.probeRelay(ctx, candidate)
			result := PathProbeResult{
				NodeID:   candidate.NodeID,
				MeshAddr: candidate.MeshAddr,
				RTT:      rtt,
				HopCount: 1, // single-hop for v1
				Error:    err,
			}

			// Cache the result.
			ps.mu.Lock()
			ps.probeCache[candidate.NodeID] = &probeCacheEntry{
				result:  result,
				expires: time.Now().Add(ps.probeCacheTTL),
			}
			ps.mu.Unlock()

			results[idx] = result
		}(i, c)
	}

	wg.Wait()
	return results
}

// probeRelay measures the RTT to a single relay candidate.
// It uses the configured DialFunc if available, otherwise falls back
// to a simple TCP connect probe.
func (ps *PathSelector) probeRelay(ctx context.Context, c CandidateRelay) (time.Duration, error) {
	if ps.cfg.DialFunc != nil {
		return ps.cfg.DialFunc(ctx, c.MeshAddr)
	}

	// Default probe: TCP connect + immediate close.
	// This measures the mesh-internal connection setup time.
	probeCtx, cancel := context.WithTimeout(ctx, ps.cfg.ProbeTimeout)
	defer cancel()

	start := time.Now()
	dialer := &net.Dialer{Timeout: ps.cfg.ProbeTimeout}
	conn, err := dialer.DialContext(probeCtx, "tcp", c.MeshAddr)
	rtt := time.Since(start)
	if err != nil {
		return 0, fmt.Errorf("probe relay %s: %w", c.NodeID[:8], err)
	}
	conn.Close()
	return rtt, nil
}

// selectDisjointPaths selects two paths from probed candidates such that
// the paths share no relay nodes. It tries all pairs and picks the one
// with the best combined quality score.
func (ps *PathSelector) selectDisjointPaths(candidates []PathProbeResult, exitAddr string) (*Path, *Path, error) {
	if len(candidates) < 2 {
		return nil, nil, fmt.Errorf("need at least 2 candidates, got %d", len(candidates))
	}

	var bestP1, bestP2 *Path
	var bestScore float64 = -1

	// Try all pairs of candidates. Since candidates are sorted by RTT,
	// the first disjoint pair is likely optimal. But we check a few
	// more to account for capacity differences.
	for i := 0; i < len(candidates) && i < 5; i++ {
		for j := i + 1; j < len(candidates) && j < 5; j++ {
			c1 := candidates[i]
			c2 := candidates[j]

			// Hard requirement: paths must be node-disjoint.
			// Since we're building single-hop paths (one relay each),
			// two different relay IDs are always disjoint.
			if c1.NodeID == c2.NodeID {
				continue
			}

			// Compute composite scores.
			score1 := ComputePathScore(c1.RTT, c1.HopCount, 0)
			score2 := ComputePathScore(c2.RTT, c2.HopCount, 0)
			totalScore := score1 + score2

			if bestScore < 0 || totalScore < bestScore {
				bestScore = totalScore
				bestP1 = ps.buildPath(c1, exitAddr)
				bestP2 = ps.buildPath(c2, exitAddr)
			}
		}
	}

	if bestP1 == nil || bestP2 == nil {
		return nil, nil, fmt.Errorf("no disjoint path pair found among %d candidates", len(candidates))
	}

	return bestP1, bestP2, nil
}

// buildPath constructs a Path from a probe result. The path goes:
// entry → relay → exit.
// Relay keys are generated randomly (Phase 1; production uses ECDH).
func (ps *PathSelector) buildPath(r PathProbeResult, exitAddr string) *Path {
	relayKey := make([]byte, KeySize)
	rand.Read(relayKey)

	return &Path{
		Relays:    []string{r.MeshAddr},
		RelayKeys: [][]byte{relayKey},
	}
}

// SelectExit selects the best exit node for a given target region
// based on the exit latency matrix (PROXY_DESIGN.md §1.6).
//
// exitProbes: map[exitNodeID]map[region]RTT
// targetRegion: the GeoIP region of the destination
//
// Returns the exit node ID with the lowest RTT to the target region.
func SelectExit(exitProbes map[string]map[string]time.Duration, targetRegion string) (string, error) {
	if len(exitProbes) == 0 {
		return "", fmt.Errorf("no exit probe data available")
	}
	if targetRegion == "" {
		return "", fmt.Errorf("target region is required")
	}

	var bestExit string
	var bestRTT time.Duration = -1

	for exitID, regions := range exitProbes {
		rtt, ok := regions[targetRegion]
		if !ok {
			continue
		}
		if bestRTT < 0 || rtt < bestRTT {
			bestExit = exitID
			bestRTT = rtt
		}
	}

	if bestExit == "" {
		// Fallback: if no exit has data for the target region, pick
		// the exit with the best average RTT across all regions.
		bestAvg := time.Duration(-1)
		for exitID, regions := range exitProbes {
			if len(regions) == 0 {
				continue
			}
			var total time.Duration
			count := 0
			for _, rtt := range regions {
				total += rtt
				count++
			}
			if count > 0 {
				avg := total / time.Duration(count)
				if bestAvg < 0 || avg < bestAvg {
					bestExit = exitID
					bestAvg = avg
				}
			}
		}
	}

	if bestExit == "" {
		return "", fmt.Errorf("no exit node found for region %s", targetRegion)
	}
	return bestExit, nil
}

// InvalidateProbeCache removes a specific relay from the probe cache.
// Call this when a relay is known to have failed or changed state.
func (ps *PathSelector) InvalidateProbeCache(nodeID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.probeCache, nodeID)
}

// ClearProbeCache removes all cached probe results.
func (ps *PathSelector) ClearProbeCache() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.probeCache = make(map[string]*probeCacheEntry)
}
