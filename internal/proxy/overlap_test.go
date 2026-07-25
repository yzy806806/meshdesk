package proxy

import (
	"testing"
)

// TestAnalyzeOverlapDisjoint verifies overlap detection for disjoint paths.
func TestAnalyzeOverlapDisjoint(t *testing.T) {
	p1 := &Path{Relays: []string{"relayA", "relayB"}}
	p2 := &Path{Relays: []string{"relayC", "relayD"}}

	report := AnalyzeOverlap(p1, p2)

	if report.HasOverlap {
		t.Error("disjoint paths should not have overlap")
	}
	if len(report.SharedNodes) != 0 {
		t.Errorf("shared nodes should be empty, got %v", report.SharedNodes)
	}
	if report.DiversityScore != 1.0 {
		t.Errorf("diversity score = %.2f, want 1.0", report.DiversityScore)
	}
}

// TestAnalyzeOverlapShared verifies overlap detection for shared relays.
func TestAnalyzeOverlapShared(t *testing.T) {
	p1 := &Path{Relays: []string{"relayA", "relayB"}}
	p2 := &Path{Relays: []string{"relayC", "relayB"}} // relayB shared

	report := AnalyzeOverlap(p1, p2)

	if !report.HasOverlap {
		t.Error("paths with shared relay should have overlap")
	}
	if len(report.SharedNodes) != 1 {
		t.Errorf("expected 1 shared node, got %d", len(report.SharedNodes))
	}
	if report.SharedNodes[0] != "relayB" {
		t.Errorf("shared node = %s, want relayB", report.SharedNodes[0])
	}
	if report.DiversityScore >= 1.0 {
		t.Errorf("diversity score should be < 1.0 for overlapping paths, got %.2f", report.DiversityScore)
	}
}

// TestAnalyzeOverlapIdentical verifies overlap detection for identical paths.
func TestAnalyzeOverlapIdentical(t *testing.T) {
	p1 := &Path{Relays: []string{"relayA", "relayB"}}
	p2 := &Path{Relays: []string{"relayA", "relayB"}}

	report := AnalyzeOverlap(p1, p2)

	if !report.HasOverlap {
		t.Error("identical paths should have overlap")
	}
	if len(report.SharedNodes) != 2 {
		t.Errorf("expected 2 shared nodes, got %d", len(report.SharedNodes))
	}
	if report.DiversityScore != 0.0 {
		t.Errorf("diversity score = %.2f, want 0.0 for identical paths", report.DiversityScore)
	}
}

// TestAnalyzeOverlapMultiHop verifies overlap detection for multi-hop paths.
func TestAnalyzeOverlapMultiHop(t *testing.T) {
	// Path 1: entry → r1 → r2 → r3 → exit
	p1 := &Path{Relays: []string{"r1", "r2", "r3"}}
	// Path 2: entry → r4 → r2 → r5 → exit (shares r2)
	p2 := &Path{Relays: []string{"r4", "r2", "r5"}}

	report := AnalyzeOverlap(p1, p2)

	if !report.HasOverlap {
		t.Error("multi-hop paths sharing r2 should have overlap")
	}
	if len(report.SharedNodes) != 1 {
		t.Errorf("expected 1 shared node, got %d", len(report.SharedNodes))
	}
	if report.SharedNodes[0] != "r2" {
		t.Errorf("shared node = %s, want r2", report.SharedNodes[0])
	}
}

// TestAnalyzeOverlapEmpty verifies overlap detection for empty paths.
func TestAnalyzeOverlapEmpty(t *testing.T) {
	p1 := &Path{Relays: nil}
	p2 := &Path{Relays: nil}

	report := AnalyzeOverlap(p1, p2)

	if report.HasOverlap {
		t.Error("empty paths should not have overlap")
	}
	if report.DiversityScore != 1.0 {
		t.Errorf("diversity score = %.2f, want 1.0 for empty paths", report.DiversityScore)
	}
}

// TestRejectIfOverlapPass verifies no error for disjoint paths.
func TestRejectIfOverlapPass(t *testing.T) {
	p1 := &Path{Relays: []string{"r1", "r2"}}
	p2 := &Path{Relays: []string{"r3", "r4"}}

	if err := RejectIfOverlap(p1, p2); err != nil {
		t.Errorf("expected no error for disjoint paths, got: %v", err)
	}
}

// TestRejectIfOverlapFail verifies error for overlapping paths.
func TestRejectIfOverlapFail(t *testing.T) {
	p1 := &Path{Relays: []string{"r1", "r2"}}
	p2 := &Path{Relays: []string{"r3", "r2"}}

	err := RejectIfOverlap(p1, p2)
	if err == nil {
		t.Error("expected error for overlapping paths")
	}
}

// TestFindDisjointPairFound verifies finding a disjoint pair.
func TestFindDisjointPairFound(t *testing.T) {
	candidates := []*Path{
		{Relays: []string{"r1", "r2"}},
		{Relays: []string{"r3", "r4"}}, // disjoint with candidate[0]
		{Relays: []string{"r5", "r1"}}, // shares r1 with candidate[0]
	}

	p1, p2, err := FindDisjointPair(candidates)
	if err != nil {
		t.Fatal(err)
	}
	if HasOverlap(p1, p2) {
		t.Error("returned pair should be disjoint")
	}
}

// TestFindDisjointPairNotFound verifies error when no disjoint pair exists.
func TestFindDisjointPairNotFound(t *testing.T) {
	candidates := []*Path{
		{Relays: []string{"r1"}},
		{Relays: []string{"r1"}}, // identical, not disjoint
		{Relays: []string{"r1"}}, // identical, not disjoint
	}

	_, _, err := FindDisjointPair(candidates)
	if err == nil {
		t.Error("expected error when no disjoint pair exists")
	}
}

// TestFindBestDisjointPair verifies finding the best disjoint pair by quality.
func TestFindBestDisjointPair(t *testing.T) {
	// Create candidates with different hop counts.
	candidates := []*Path{
		{Relays: []string{"r1"}},                     // 1 hop
		{Relays: []string{"r2"}},                     // 1 hop
		{Relays: []string{"r3", "r4", "r5"}},        // 3 hops
		{Relays: []string{"r6", "r7", "r8"}},        // 3 hops
	}

	// Quality function: lower hop count = better.
	qualityFn := func(p *Path) float64 {
		return float64(len(p.Relays)) * 10.0
	}

	p1, p2, err := FindBestDisjointPair(candidates, qualityFn)
	if err != nil {
		t.Fatal(err)
	}

	if HasOverlap(p1, p2) {
		t.Error("returned pair should be disjoint")
	}

	// The best pair should be the two 1-hop paths.
	if len(p1.Relays) != 1 || len(p2.Relays) != 1 {
		t.Errorf("expected 1-hop paths, got %d and %d hops", len(p1.Relays), len(p2.Relays))
	}
}

// TestFindBestDisjointPairNoDisjoint verifies error when no disjoint pair.
func TestFindBestDisjointPairNoDisjoint(t *testing.T) {
	candidates := []*Path{
		{Relays: []string{"r1", "r2"}},
		{Relays: []string{"r2", "r3"}}, // shares r2
	}

	qualityFn := func(p *Path) float64 { return 1.0 }

	_, _, err := FindBestDisjointPair(candidates, qualityFn)
	if err == nil {
		t.Error("expected error when no disjoint pair exists")
	}
}

// TestPathQualityMetric verifies the quality metric calculation.
func TestPathQualityMetric(t *testing.T) {
	tests := []struct {
		relays []string
		want   float64
	}{
		{[]string{"r1"}, 10.0},
		{[]string{"r1", "r2"}, 20.0},
		{[]string{"r1", "r2", "r3"}, 30.0},
	}

	for _, tt := range tests {
		p := &Path{Relays: tt.relays}
		got := PathQualityMetric(p)
		if got != tt.want {
			t.Errorf("PathQualityMetric(%v) = %.1f, want %.1f", tt.relays, got, tt.want)
		}
	}
}

// TestMultiHopOverlap verifies the multi-hop overlap function.
func TestMultiHopOverlap(t *testing.T) {
	tests := []struct {
		name    string
		p1      []string
		p2      []string
		overlap bool
	}{
		{"disjoint", []string{"r1", "r2"}, []string{"r3", "r4"}, false},
		{"shared_intermediate", []string{"r1", "r2", "r3"}, []string{"r4", "r2", "r5"}, true},
		{"shared_first", []string{"r1", "r2"}, []string{"r1", "r3"}, true},
		{"shared_last", []string{"r1", "r2"}, []string{"r3", "r2"}, true},
		{"identical", []string{"r1", "r2"}, []string{"r1", "r2"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p1 := &Path{Relays: tt.p1}
			p2 := &Path{Relays: tt.p2}
			if got := MultiHopOverlap(p1, p2); got != tt.overlap {
				t.Errorf("MultiHopOverlap = %v, want %v", got, tt.overlap)
			}
		})
	}
}

// TestValidatePathPair verifies comprehensive path pair validation.
func TestValidatePathPair(t *testing.T) {
	t.Run("valid_pair", func(t *testing.T) {
		p1 := &Path{Relays: []string{"r1"}, RelayKeys: [][]byte{make([]byte, KeySize)}}
		p2 := &Path{Relays: []string{"r2"}, RelayKeys: [][]byte{make([]byte, KeySize)}}
		if err := ValidatePathPair(p1, p2); err != nil {
			t.Errorf("valid pair should not error: %v", err)
		}
	})

	t.Run("key_count_mismatch", func(t *testing.T) {
		p1 := &Path{Relays: []string{"r1", "r2"}, RelayKeys: [][]byte{make([]byte, KeySize)}} // 2 relays, 1 key
		p2 := &Path{Relays: []string{"r3"}, RelayKeys: [][]byte{make([]byte, KeySize)}}
		if err := ValidatePathPair(p1, p2); err == nil {
			t.Error("expected error for key count mismatch")
		}
	})

	t.Run("key_size_mismatch", func(t *testing.T) {
		p1 := &Path{Relays: []string{"r1"}, RelayKeys: [][]byte{make([]byte, 16)}} // wrong size
		p2 := &Path{Relays: []string{"r2"}, RelayKeys: [][]byte{make([]byte, KeySize)}}
		if err := ValidatePathPair(p1, p2); err == nil {
			t.Error("expected error for key size mismatch")
		}
	})

	t.Run("overlap", func(t *testing.T) {
		p1 := &Path{Relays: []string{"r1"}, RelayKeys: [][]byte{make([]byte, KeySize)}}
		p2 := &Path{Relays: []string{"r1"}, RelayKeys: [][]byte{make([]byte, KeySize)}}
		if err := ValidatePathPair(p1, p2); err == nil {
			t.Error("expected error for overlapping paths")
		}
	})
}
