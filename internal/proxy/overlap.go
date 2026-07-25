// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the enhanced path overlap detection mechanism.
// While the basic HasOverlap function in dispatcher.go checks single-hop
// paths, this module provides comprehensive multi-hop overlap detection
// and path quality assessment.
//
// Design (PROXY_DESIGN.md §1.5, §1.7):
//
//   - HARD REQUIREMENT: Path selection must reject any circuit where
//     two candidate paths share a relay node. A relay appearing on
//     both paths can correlate entry↔exit via timing even with
//     ciphertext-only access.
//   - MULTI-HOP SUPPORT: For paths with multiple relay hops, we must
//     check all intermediate nodes, not just the first relay.
//   - QUALITY SCORING: Beyond binary overlap detection, this module
//     scores path pairs by their combined quality (RTT, hop count,
//     diversity) to help the selector pick the best disjoint pair.
package proxy

import (
	"fmt"
	"math"
)

// PathPair represents two candidate paths for overlap checking.
type PathPair struct {
	Path1 *Path
	Path2 *Path
}

// OverlapReport details the overlap analysis between two paths.
type OverlapReport struct {
	// HasOverlap is true if the paths share any relay node.
	HasOverlap bool

	// SharedNodes lists the node IDs that appear on both paths.
	SharedNodes []string

	// Path1Nodes is the set of relay nodes on path 1.
	Path1Nodes map[string]bool

	// Path2Nodes is the set of relay nodes on path 2.
	Path2Nodes map[string]bool

	// DiversityScore measures how diverse the two paths are.
	// 0.0 = identical paths (maximum overlap).
	// 1.0 = completely disjoint paths (no overlap).
	// For multi-hop paths, this is computed as:
	//   1.0 - (2.0 * sharedCount) / (len1 + len2)
	DiversityScore float64
}

// AnalyzeOverlap performs a comprehensive overlap analysis between
// two paths. It checks all relay nodes on both paths and produces
// a detailed report including shared nodes and diversity score.
//
// This is the enhanced version of HasOverlap (dispatcher.go) that
// supports multi-hop paths and provides diagnostic information.
func AnalyzeOverlap(p1, p2 *Path) *OverlapReport {
	nodes1 := p1.Nodes()
	nodes2 := p2.Nodes()

	var shared []string
	for node := range nodes1 {
		if nodes2[node] {
			shared = append(shared, node)
		}
	}

	hasOverlap := len(shared) > 0

	// Compute diversity score.
	// Jaccard distance: 1 - |A ∩ B| / |A ∪ B|
	// For disjoint sets, |A ∩ B| = 0, so score = 1.0.
	// For identical sets, |A ∩ B| = |A| = |B|, so score = 0.0.
	diversityScore := 1.0
	unionSize := len(nodes1) + len(nodes2) - len(shared)
	if unionSize > 0 {
		diversityScore = 1.0 - float64(len(shared))/float64(unionSize)
	}

	return &OverlapReport{
		HasOverlap:     hasOverlap,
		SharedNodes:    shared,
		Path1Nodes:     nodes1,
		Path2Nodes:     nodes2,
		DiversityScore: diversityScore,
	}
}

// RejectIfOverlap checks two paths for overlap and returns an error
// if they share any relay node. This enforces the PROXY_DESIGN.md §1.5
// hard requirement at every path selection point.
//
// The error message includes the shared node IDs for debugging.
func RejectIfOverlap(p1, p2 *Path) error {
	report := AnalyzeOverlap(p1, p2)
	if report.HasOverlap {
		return fmt.Errorf("path overlap detected: shared relay nodes %v "+
			"(PROXY_DESIGN.md §1.5 hard requirement: paths must be node-disjoint)",
			report.SharedNodes)
	}
	return nil
}

// FindDisjointPair searches through a list of candidate paths and
// returns the first pair that is node-disjoint. If no disjoint pair
// exists, it returns the pair with the highest diversity score
// (least overlap) and an error.
//
// This is used when the selector has many candidate paths and needs
// to find the best disjoint pair. The candidates should be pre-sorted
// by quality (best first).
func FindDisjointPair(candidates []*Path) (*Path, *Path, error) {
	if len(candidates) < 2 {
		return nil, nil, fmt.Errorf("need at least 2 candidate paths, got %d", len(candidates))
	}

	var bestP1, bestP2 *Path
	bestDiversity := -1.0

	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			report := AnalyzeOverlap(candidates[i], candidates[j])
			if !report.HasOverlap {
				// Found a disjoint pair — return immediately.
				return candidates[i], candidates[j], nil
			}
			// Track the best (least overlapping) pair as fallback.
			if report.DiversityScore > bestDiversity {
				bestDiversity = report.DiversityScore
				bestP1 = candidates[i]
				bestP2 = candidates[j]
			}
		}
	}

	// No fully disjoint pair found. Return the best pair with an error.
	return bestP1, bestP2, fmt.Errorf("no fully disjoint path pair found among %d candidates "+
		"(best diversity score: %.2f)", len(candidates), bestDiversity)
}

// FindBestDisjointPair searches through candidates and returns the
// disjoint pair with the best combined quality score. Unlike
// FindDisjointPair (which returns the first match), this function
// evaluates all disjoint pairs and picks the optimal one.
//
// qualityFn computes a quality score for a path (lower = better).
// The pair with the lowest combined score is returned.
func FindBestDisjointPair(candidates []*Path, qualityFn func(*Path) float64) (*Path, *Path, error) {
	if len(candidates) < 2 {
		return nil, nil, fmt.Errorf("need at least 2 candidate paths, got %d", len(candidates))
	}

	var bestP1, bestP2 *Path
	bestScore := math.MaxFloat64
	foundDisjoint := false

	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			report := AnalyzeOverlap(candidates[i], candidates[j])
			if report.HasOverlap {
				continue // skip overlapping pairs
			}

			foundDisjoint = true
			score := qualityFn(candidates[i]) + qualityFn(candidates[j])
			if score < bestScore {
				bestScore = score
				bestP1 = candidates[i]
				bestP2 = candidates[j]
			}
		}
	}

	if !foundDisjoint {
		return nil, nil, fmt.Errorf("no disjoint path pair found among %d candidates", len(candidates))
	}

	return bestP1, bestP2, nil
}

// PathQualityMetric computes a quality metric for a path based on
// its properties. This is a convenience function for use with
// FindBestDisjointPair's qualityFn parameter.
//
// The metric considers:
//   - Number of hops (fewer is better for latency)
//   - Path "width" (more relay nodes = more anonymity but more latency)
//
// Lower score = better path. The caller should augment this with
// actual RTT measurements for a complete quality picture.
func PathQualityMetric(p *Path) float64 {
	hopCount := len(p.Relays)
	// Base score: 10 per hop (latency proxy).
	score := float64(hopCount) * 10.0
	return score
}

// MultiHopOverlap checks overlap specifically for multi-hop paths.
// In a multi-hop path (entry → r1 → r2 → ... → exit), we must ensure
// that NO relay appears on both paths, including intermediate hops.
//
// This is functionally equivalent to AnalyzeOverlap but is provided
// as a separate function for clarity at call sites where multi-hop
// overlap checking is the explicit intent.
func MultiHopOverlap(p1, p2 *Path) bool {
	return AnalyzeOverlap(p1, p2).HasOverlap
}

// ValidatePathPair performs comprehensive validation of a path pair:
//  1. Both paths must have at least one relay (or be direct)
//  2. Paths must be node-disjoint (hard requirement)
//  3. Each path must have matching relay keys
//
// Returns nil if valid, error describing the issue otherwise.
func ValidatePathPair(p1, p2 *Path) error {
	// Check relay key counts match relay counts.
	if len(p1.RelayKeys) != len(p1.Relays) {
		return fmt.Errorf("path1: relay key count (%d) != relay count (%d)",
			len(p1.RelayKeys), len(p1.Relays))
	}
	if len(p2.RelayKeys) != len(p2.Relays) {
		return fmt.Errorf("path2: relay key count (%d) != relay count (%d)",
			len(p2.RelayKeys), len(p2.Relays))
	}

	// Check key sizes.
	for i, key := range p1.RelayKeys {
		if len(key) != KeySize {
			return fmt.Errorf("path1 relay %d: key size %d != %d", i, len(key), KeySize)
		}
	}
	for i, key := range p2.RelayKeys {
		if len(key) != KeySize {
			return fmt.Errorf("path2 relay %d: key size %d != %d", i, len(key), KeySize)
		}
	}

	// Check for overlap.
	return RejectIfOverlap(p1, p2)
}
