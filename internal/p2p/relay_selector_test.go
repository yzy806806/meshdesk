package p2p

import (
	"testing"
	"time"
)

// TestRelaySelectorScoring verifies AC-11: relay scoring by RTT*Load.
//
//	GIVEN three relay-capable nodes R1 (RTT=10ms, CPU=0.1),
//	  R2 (RTT=5ms, CPU=0.9), R3 (RTT=50ms, CPU=0.1)
//	WHEN entry node computes relayScore for each
//	THEN R1 scores highest (good RTT + low load)
//	AND R2 scores lower despite low RTT (high load penalty)
//	AND R3 scores lowest (high RTT)
func TestRelaySelectorScoring(t *testing.T) {
	// Create a mock event delegate with relay candidates.
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:    "10.10.0.1",
	}
	delegate := newMeshDelegate(localMeta)
	wg := &WireGuardDelegate{health: make(map[string]*PeerHealth), staticKeys: make(map[string]bool)}
	events := newMeshEventDelegate(delegate, wg)

	// R1: RTT=10ms, CPU=0.1 (should score highest)
	r1 := &NodeMeta{
		PublicKey:    "r1publickey0000000000000000000000000000000000000000000000000000",
		MeshIP:       "10.10.1.1",
		CapRelay:     true,
		LoadCPU:      0.1,
		LoadMem:      0.1,
		LoadCircuits: 0,
		MaxCircuits:  1024,
		NatType:      "none",
	}

	// R2: RTT=5ms, CPU=0.9 (low RTT but high load)
	r2 := &NodeMeta{
		PublicKey:    "r2publickey0000000000000000000000000000000000000000000000000000",
		MeshIP:       "10.10.1.2",
		CapRelay:     true,
		LoadCPU:      0.9,
		LoadMem:      0.5,
		LoadCircuits: 900,
		MaxCircuits:  1024,
		NatType:      "none",
	}

	// R3: RTT=50ms, CPU=0.1 (low load but high latency)
	r3 := &NodeMeta{
		PublicKey:    "r3publickey0000000000000000000000000000000000000000000000000000",
		MeshIP:       "10.10.1.3",
		CapRelay:     true,
		LoadCPU:      0.1,
		LoadMem:      0.1,
		LoadCircuits: 0,
		MaxCircuits:  1024,
		NatType:      "none",
	}

	// Populate relay pool.
	events.mu.Lock()
	events.relayPool[r1.PublicKey] = r1
	events.relayPool[r2.PublicKey] = r2
	events.relayPool[r3.PublicKey] = r3
	events.mu.Unlock()

	// RTT estimator: returns fixed RTT per peer.
	rttMap := map[string]time.Duration{
		r1.PublicKey: 10 * time.Millisecond,
		r2.PublicKey: 5 * time.Millisecond,
		r3.PublicKey: 50 * time.Millisecond,
	}
	rttEstimator := func(peerKey string) time.Duration {
		return rttMap[peerKey]
	}

	selector := NewRelaySelector(events)
	candidates := selector.scoreCandidates(rttEstimator)
	if len(candidates) != 3 {
		t.Fatalf("expected 3 candidates, got %d", len(candidates))
	}

	// Find scores by public key.
	var r1Score, r2Score, r3Score float64
	for _, c := range candidates {
		switch c.Meta.PublicKey {
		case r1.PublicKey:
			r1Score = c.Score
		case r2.PublicKey:
			r2Score = c.Score
		case r3.PublicKey:
			r3Score = c.Score
		}
	}

	// R1 should score highest (good RTT + low load).
	if r1Score <= r2Score {
		t.Errorf("R1 (RTT=10ms, CPU=0.1) should outscore R2 (RTT=5ms, CPU=0.9): R1=%.3f, R2=%.3f",
			r1Score, r2Score)
	}
	if r1Score <= r3Score {
		t.Errorf("R1 (RTT=10ms, CPU=0.1) should outscore R3 (RTT=50ms, CPU=0.1): R1=%.3f, R3=%.3f",
			r1Score, r3Score)
	}
	// R2 should score lower despite low RTT (high load penalty).
	if r2Score >= r1Score {
		t.Errorf("R2 should score lower than R1 due to high load: R2=%.3f, R1=%.3f",
			r2Score, r1Score)
	}
	// R3 should score lowest (high RTT).
	if r3Score >= r1Score {
		t.Errorf("R3 should score lowest due to high RTT: R3=%.3f, R1=%.3f",
			r3Score, r1Score)
	}

	t.Logf("Scores: R1=%.4f, R2=%.4f, R3=%.4f", r1Score, r2Score, r3Score)
}

func TestRelaySelectorSelectBest(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:    "10.10.0.1",
	}
	delegate := newMeshDelegate(localMeta)
	wg := &WireGuardDelegate{health: make(map[string]*PeerHealth), staticKeys: make(map[string]bool)}
	events := newMeshEventDelegate(delegate, wg)

	// Add one relay candidate.
	best := &NodeMeta{
		PublicKey:   "bestkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:      "10.10.1.1",
		CapRelay:    true,
		LoadCPU:     0.1,
		MaxCircuits: 1024,
		NatType:     "none",
	}
	events.mu.Lock()
	events.relayPool[best.PublicKey] = best
	events.mu.Unlock()

	selector := NewRelaySelector(events)
	result := selector.SelectBestRelay(nil)
	if result == nil {
		t.Fatal("SelectBestRelay returned nil with available candidates")
	}
	if result.Meta.PublicKey != best.PublicKey {
		t.Errorf("SelectBestRelay returned wrong peer: got %s", result.Meta.PublicKey)
	}
}

func TestRelaySelectorEmptyPool(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:    "10.10.0.1",
	}
	delegate := newMeshDelegate(localMeta)
	wg := &WireGuardDelegate{health: make(map[string]*PeerHealth), staticKeys: make(map[string]bool)}
	events := newMeshEventDelegate(delegate, wg)

	selector := NewRelaySelector(events)
	result := selector.SelectBestRelay(nil)
	if result != nil {
		t.Error("SelectBestRelay should return nil with empty pool")
	}
}

func TestRelaySelectorFiltersIneligible(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:    "10.10.0.1",
	}
	delegate := newMeshDelegate(localMeta)
	wg := &WireGuardDelegate{health: make(map[string]*PeerHealth), staticKeys: make(map[string]bool)}
	events := newMeshEventDelegate(delegate, wg)

	// At-capacity relay (should be filtered).
	atCapacity := &NodeMeta{
		PublicKey:    "atcapacity000000000000000000000000000000000000000000000000000000",
		MeshIP:       "10.10.1.1",
		CapRelay:     true,
		LoadCircuits: 1024,
		MaxCircuits:  1024,
		NatType:      "none",
	}

	// Symmetric NAT relay (should be filtered).
	symmetricNAT := &NodeMeta{
		PublicKey:   "symmetric00000000000000000000000000000000000000000000000000000",
		MeshIP:      "10.10.1.2",
		CapRelay:    true,
		MaxCircuits: 1024,
		NatType:     "symmetric",
	}

	// Eligible relay.
	eligible := &NodeMeta{
		PublicKey:   "eligible000000000000000000000000000000000000000000000000000000",
		MeshIP:      "10.10.1.3",
		CapRelay:    true,
		MaxCircuits: 1024,
		NatType:     "none",
	}

	events.mu.Lock()
	events.relayPool[atCapacity.PublicKey] = atCapacity
	events.relayPool[symmetricNAT.PublicKey] = symmetricNAT
	events.relayPool[eligible.PublicKey] = eligible
	events.mu.Unlock()

	selector := NewRelaySelector(events)
	candidates := selector.scoreCandidates(nil)
	if len(candidates) != 1 {
		t.Fatalf("expected 1 eligible candidate, got %d", len(candidates))
	}
	if candidates[0].Meta.PublicKey != eligible.PublicKey {
		t.Errorf("expected eligible candidate, got %s", candidates[0].Meta.PublicKey)
	}
}

func TestRelaySelectorSelectK(t *testing.T) {
	localMeta := &NodeMeta{
		PublicKey: "localkey00000000000000000000000000000000000000000000000000000000",
		MeshIP:    "10.10.0.1",
	}
	delegate := newMeshDelegate(localMeta)
	wg := &WireGuardDelegate{health: make(map[string]*PeerHealth), staticKeys: make(map[string]bool)}
	events := newMeshEventDelegate(delegate, wg)

	// Add 5 relay candidates with unique keys.
	for i := 0; i < 5; i++ {
		key := string(rune('A'+i)) + "key0000000000000000000000000000000000000000000000000000000000000"
		meta := &NodeMeta{
			PublicKey:   key,
			CapRelay:    true,
			MaxCircuits: 1024,
			NatType:     "none",
			LoadCPU:     float64(i) * 0.1,
		}
		events.mu.Lock()
		events.relayPool[meta.PublicKey] = meta
		events.mu.Unlock()
	}

	selector := NewRelaySelector(events)

	// Select top 3.
	result := selector.SelectRelays(3, 0, nil)
	if len(result) != 3 {
		t.Fatalf("expected 3 selected relays, got %d", len(result))
	}

	// Results should be sorted by score descending.
	for i := 1; i < len(result); i++ {
		if result[i].Score > result[i-1].Score {
			t.Errorf("results not sorted by score: [%d]=%.3f > [%d]=%.3f",
				i, result[i].Score, i-1, result[i-1].Score)
		}
	}
}

func TestClampFloat(t *testing.T) {
	tests := []struct {
		input float64
		want  float64
	}{
		{0.0, 0.0},
		{0.5, 0.5},
		{1.0, 1.0},
		{-0.1, 0.0},
		{1.5, 1.0},
		{0, 0},
	}

	for _, tt := range tests {
		got := clampFloat(tt.input)
		if got != tt.want {
			t.Errorf("clampFloat(%f) = %f, want %f", tt.input, got, tt.want)
		}
	}
}

func TestLoadCircuitsRatio(t *testing.T) {
	tests := []struct {
		name        string
		circuits    int
		maxCircuits int
		want        float64
	}{
		{"normal", 512, 1024, 0.5},
		{"zero", 0, 1024, 0.0},
		{"full", 1024, 1024, 1.0},
		{"no_max", 512, 0, 0.5}, // defaults to 1024
		{"no_max_no_circuits", 0, 0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &NodeMeta{
				LoadCircuits: tt.circuits,
				MaxCircuits:  tt.maxCircuits,
			}
			got := loadCircuitsRatio(m)
			if got != tt.want {
				t.Errorf("loadCircuitsRatio() = %f, want %f", got, tt.want)
			}
		})
	}
}
