package p2p

import (
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// RelaySelector scores and selects relay-capable peers for circuit building.
// The scoring formula is from P2P_NETWORKING_SPEC.md §5.2:
//
//	relayScore = normalizeRTTScore * 0.6 + normalizeLoadScore * 0.4
//
//	normalizeRTTScore = 1.0 - (rtt_us - minRTT) / (maxRTT - minRTT + 1)
//	    // Normalized inverse RTT: faster relays score higher
//
//	normalizeLoadScore = 1.0 - loadFactor
//	    loadFactor = 0.5 * LoadCPU + 0.3 * (LoadCircuits / MaxCircuits) + 0.2 * LoadMem
//	    // Load factor 0.0 = completely idle (best)
//	    // Load factor 1.0 = fully loaded (worst)
//
// Additionally, from §3.7, relay scores 0 if:
//   - CapRelay == false
//   - LoadCircuits >= MaxCircuits
//   - NatType == "symmetric"
type RelaySelector struct {
	mu     sync.Mutex
	rng    *rand.Rand
	events *meshEventDelegate
}

// NewRelaySelector creates a new relay selector.
func NewRelaySelector(events *meshEventDelegate) *RelaySelector {
	return &RelaySelector{
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
		events: events,
	}
}

// RelayCandidate is a relay peer with a computed score.
type RelayCandidate struct {
	Meta  *NodeMeta
	Score float64
	RTT   time.Duration // measured or estimated RTT
}

// SelectRelays returns the top-K relay candidates sorted by score (descending).
// If fewer than K candidates are available, returns all available.
// If shuffleTopN > 0 and there are more than K candidates with similar scores,
// one is randomly selected from the top shuffleTopN to spread load.
func (rs *RelaySelector) SelectRelays(k int, shuffleTopN int, rttEstimator func(peerKey string) time.Duration) []*RelayCandidate {
	candidates := rs.scoreCandidates(rttEstimator)

	if len(candidates) == 0 {
		return nil
	}

	// Sort by score descending.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Score > candidates[j].Score
	})

	// Optionally shuffle among top-N for load spreading (§3.7).
	if shuffleTopN > 0 && len(candidates) > shuffleTopN {
		// Pick k from the top shuffleTopN randomly.
		topN := candidates[:shuffleTopN]
		rs.mu.Lock()
		rs.rng.Shuffle(len(topN), func(i, j int) {
			topN[i], topN[j] = topN[j], topN[i]
		})
		rs.mu.Unlock()
		candidates = append(topN, candidates[shuffleTopN:]...)
	}

	if k > len(candidates) {
		k = len(candidates)
	}

	result := make([]*RelayCandidate, k)
	copy(result, candidates[:k])
	return result
}

// SelectBestRelay returns the single best relay candidate, or nil if none available.
func (rs *RelaySelector) SelectBestRelay(rttEstimator func(peerKey string) time.Duration) *RelayCandidate {
	candidates := rs.scoreCandidates(rttEstimator)
	if len(candidates) == 0 {
		return nil
	}

	// Sort by score descending.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Score > candidates[j].Score
	})

	return candidates[0]
}

// scoreCandidates computes relay scores for all relay-capable peers.
func (rs *RelaySelector) scoreCandidates(rttEstimator func(peerKey string) time.Duration) []*RelayCandidate {
	peers := rs.events.GetRelayCandidates()
	if len(peers) == 0 {
		return nil
	}

	// Gather candidates and filter out ineligible ones.
	type peerRTT struct {
		meta *NodeMeta
		rtt  time.Duration
	}

	var eligible []peerRTT
	for _, m := range peers {
		// Skip ineligible relays (§3.7).
		if !m.CapRelay {
			continue
		}
		if m.MaxCircuits > 0 && m.LoadCircuits >= m.MaxCircuits {
			continue // at capacity
		}
		if m.NatType == "symmetric" {
			continue // symmetric NAT can't relay reliably
		}

		rtt := time.Duration(0)
		if rttEstimator != nil {
			rtt = rttEstimator(m.PublicKey)
		}
		eligible = append(eligible, peerRTT{meta: m, rtt: rtt})
	}

	if len(eligible) == 0 {
		return nil
	}

	// Find min/max RTT for normalization.
	minRTT := eligible[0].rtt
	maxRTT := eligible[0].rtt
	for _, p := range eligible {
		if p.rtt < minRTT {
			minRTT = p.rtt
		}
		if p.rtt > maxRTT {
			maxRTT = p.rtt
		}
	}

	// Compute scores.
	candidates := make([]*RelayCandidate, 0, len(eligible))
	for _, p := range eligible {
		// normalizeRTTScore = 1.0 - (rtt - minRTT) / (maxRTT - minRTT + 1)
		var normRTT float64
		if maxRTT == minRTT {
			normRTT = 1.0 // all same RTT
		} else {
			rttRange := float64(maxRTT - minRTT)
			normRTT = 1.0 - float64(p.rtt-minRTT)/(rttRange+1.0)
		}

		// loadFactor = 0.5 * LoadCPU + 0.3 * (LoadCircuits / MaxCircuits) + 0.2 * LoadMem
		loadFactor := 0.5*clampFloat(p.meta.LoadCPU) +
			0.3*loadCircuitsRatio(p.meta) +
			0.2*clampFloat(p.meta.LoadMem)
		loadFactor = clampFloat(loadFactor) // ensure [0, 1]

		// normalizeLoadScore = 1.0 - loadFactor
		normLoad := 1.0 - loadFactor

		// relayScore = normalizeRTTScore * 0.6 + normalizeLoadScore * 0.4
		score := normRTT*0.6 + normLoad*0.4

		candidates = append(candidates, &RelayCandidate{
			Meta:  p.meta,
			Score: score,
			RTT:   p.rtt,
		})
	}

	return candidates
}

// clampFloat clamps a value to [0.0, 1.0].
func clampFloat(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	if math.IsNaN(v) {
		return 0
	}
	return v
}

// loadCircuitsRatio computes LoadCircuits/MaxCircuits, handling defaults.
func loadCircuitsRatio(m *NodeMeta) float64 {
	if m.MaxCircuits <= 0 {
		// Default MaxCircuits is 1024 per config defaults.
		if m.LoadCircuits <= 0 {
			return 0
		}
		return float64(m.LoadCircuits) / 1024.0
	}
	return float64(m.LoadCircuits) / float64(m.MaxCircuits)
}
