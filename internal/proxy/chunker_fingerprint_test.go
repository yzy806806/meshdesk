// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements traffic fingerprint comparison tests: fixed vs
// random chunking side-by-side analysis. These tests verify that the
// bounded random chunker produces variable chunk sizes (resistant to
// traffic analysis) while the fixed chunker produces uniform sizes
// (suitable for debugging but fingerprintable in production).
//
// Key properties tested:
//   1. Bounded chunker produces variable-sized chunks (entropy > 0 in sizes)
//   2. Fixed chunker produces uniform-sized chunks (all same size except tail)
//   3. DebugFixedChunks flag forces uniform sizing at the exit node level
//   4. Per-circuit PaddingSeed produces deterministic reproducible padding
//   5. Chunk sizes stay within [MinChunkSize, MaxChunkSize] bounds
//   6. Identical input with different seeds produces different chunk layouts
package proxy

import (
	"bytes"
	"math"
	"testing"
)

// =============================================================================
// Section 1: Basic Size Distribution Tests
// =============================================================================

// TestFingerprintBoundedVariableSizes verifies that the bounded random
// chunker actually produces variable-sized chunks (not all uniform).
// A traffic analyst seeing uniform chunk sizes could fingerprint the
// proxy; variable sizes are essential for protocol mimicry.
func TestFingerprintBoundedVariableSizes(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize: 4 * 1024,
		MaxChunkSize: 64 * 1024,
		DisablePadding: true,
	}

	// Generate enough data to get multiple chunks.
	data := make([]byte, 500*1024) // 500KB — should get ~10-30 chunks
	for i := range data {
		data[i] = byte(i % 256)
	}

	chunker := NewChunkerWithConfig("bounded-4k-64k", cfg)
	chunks := chunker.Split(data)

	if len(chunks) < 5 {
		t.Fatalf("too few chunks (%d) for statistical analysis", len(chunks))
	}

	// Collect all chunk sizes.
	sizes := make([]int, len(chunks))
	for i, c := range chunks {
		sizes[i] = len(c.Payload)
	}

	// Verify all sizes are within bounds.
	for i, sz := range sizes {
		if sz < cfg.MinChunkSize && i < len(chunks)-1 {
			t.Errorf("chunk %d size %d below minimum %d", i, sz, cfg.MinChunkSize)
		}
		if sz > cfg.MaxChunkSize {
			t.Errorf("chunk %d size %d exceeds maximum %d", i, sz, cfg.MaxChunkSize)
		}
	}

	// Verify at least 2 distinct sizes (non-uniform distribution).
	seen := make(map[int]bool)
	for _, sz := range sizes {
		seen[sz] = true
	}
	if len(seen) < 2 {
		t.Errorf("bounded chunker produced only %d distinct sizes — looks uniform (fingerprintable)", len(seen))
	}

	// Verify the distribution isn't all clustered at one extreme.
	// Count chunks that are "significantly different" from the mean.
	var sum int
	for _, sz := range sizes {
		sum += sz
	}
	mean := sum / len(sizes)

	varianceCount := 0
	for _, sz := range sizes {
		diff := sz - mean
		if diff < 0 {
			diff = -diff
		}
		if float64(diff) > float64(mean)*0.2 { // > 20% deviation from mean
			varianceCount++
		}
	}
	if varianceCount == 0 {
		t.Errorf("all %d chunk sizes within 20%% of mean %d — distribution looks uniform (fingerprintable)", len(sizes), mean)
	}
}

// TestFingerprintFixedUniformSizes verifies that the fixed-16k chunker
// produces uniform-sized chunks (every full chunk is exactly MaxChunkSize).
// This is the fingerprintable mode that DebugFixedChunks enables — it
// should ONLY be used in testing.
func TestFingerprintFixedUniformSizes(t *testing.T) {
	cfg := ChunkerConfig{
		MaxChunkSize: 16 * 1024,
		MinChunkSize: 16 * 1024,
		DisablePadding: true,
	}

	// Generate a lot of data to get many chunks.
	data := make([]byte, 500*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	chunker := NewChunkerWithConfig("fixed-16k", cfg)
	chunks := chunker.Split(data)

	if len(chunks) < 5 {
		t.Fatalf("too few chunks (%d) for analysis", len(chunks))
	}

	// All full chunks must have exactly MaxChunkSize bytes.
	for i, c := range chunks {
		if i == len(chunks)-1 {
			// Last chunk may be smaller.
			if len(c.Payload) > cfg.MaxChunkSize {
				t.Errorf("last chunk size %d exceeds max %d", len(c.Payload), cfg.MaxChunkSize)
			}
		} else {
			if len(c.Payload) != cfg.MaxChunkSize {
				t.Errorf("fixed chunk %d size = %d, want %d (uniform)", i, len(c.Payload), cfg.MaxChunkSize)
			}
		}
	}

	// All non-last chunks should have exactly the same size.
	if len(chunks) > 1 {
		expected := cfg.MaxChunkSize
		distinctSizes := make(map[int]bool)
		for i := 0; i < len(chunks)-1; i++ {
			sz := len(chunks[i].Payload)
			if sz != expected {
				distinctSizes[sz] = true
			}
		}
		if len(distinctSizes) > 0 {
			t.Errorf("fixed chunker produced non-uniform sizes: %v", distinctSizes)
		}
	}
}

// TestFingerprintCompareDistributions verifies that the fixed and bounded
// chunkers produce significantly different size distributions, confirming
// that bounded mode provides real anti-fingerprinting value.
func TestFingerprintCompareDistributions(t *testing.T) {
	cfg := ChunkerConfig{
		MaxChunkSize: 16 * 1024,
		MinChunkSize: 4 * 1024,
		DisablePadding: true,
	}

	data := make([]byte, 500*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Fixed chunker: all chunks should be exactly MaxChunkSize (except last).
	fixedChunker := NewChunkerWithConfig("fixed-16k", cfg)
	fixedChunks := fixedChunker.Split(data)

	// Bounded chunker: variable sizes.
	boundedChunker := NewChunkerWithConfig("bounded-4k-64k", cfg)
	boundedChunks := boundedChunker.Split(data)

	// Collect fixed sizes (excluding last chunk).
	fixedSizes := make(map[int]int)
	for i := 0; i < len(fixedChunks)-1; i++ {
		fixedSizes[len(fixedChunks[i].Payload)]++
	}

	// Collect bounded sizes (excluding last chunk).
	boundedSizes := make(map[int]int)
	for i := 0; i < len(boundedChunks)-1; i++ {
		boundedSizes[len(boundedChunks[i].Payload)]++
	}

	// Fixed mode should have exactly 1 distinct size for non-last chunks.
	if len(fixedSizes) != 1 {
		t.Errorf("fixed chunker produced %d distinct sizes — expected exactly 1", len(fixedSizes))
	}

	// Bounded mode should have MORE distinct sizes than fixed mode.
	if len(boundedSizes) <= 1 {
		t.Errorf("bounded chunker produced only %d distinct sizes — expected > 1 for anti-fingerprinting", len(boundedSizes))
	}

	// Fixed and bounded should differ.
	if len(boundedSizes) <= len(fixedSizes) {
		t.Errorf("bounded variety (%d distinct sizes) not greater than fixed (%d) — anti-fingerprinting ineffective",
			len(boundedSizes), len(fixedSizes))
	}
}

// =============================================================================
// Section 2: Per-Circuit Padding Seed Tests
// =============================================================================

// TestFingerprintPaddingSeedDeterministic verifies that the same
// PaddingSeed produces identical padding across two chunking runs.
// This enables deterministic replay for debugging.
func TestFingerprintPaddingSeedDeterministic(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	cfg := ChunkerConfig{
		MaxChunkSize: 1024,
		MinChunkSize: 1024,
		PaddingMin:   100,
		PaddingMax:   200,
		PaddingSeed:  seed,
	}
	// (DisablePadding is false → padding is active)

	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Run 1.
	chunker1 := NewChunkerWithConfig("fixed-16k", cfg)
	chunks1 := chunker1.Split(data)

	// Run 2 (fresh chunker, same seed).
	chunker2 := NewChunkerWithConfig("fixed-16k", cfg)
	chunks2 := chunker2.Split(data)

	if len(chunks1) != len(chunks2) {
		t.Fatalf("chunk count differs: run1=%d, run2=%d", len(chunks1), len(chunks2))
	}

	// All properties should be identical (payload + padding lengths).
	for i := range chunks1 {
		if !bytes.Equal(chunks1[i].Payload, chunks2[i].Payload) {
			t.Errorf("chunk %d payload differs", i)
		}
		if chunks1[i].PaddingLen != chunks2[i].PaddingLen {
			t.Errorf("chunk %d padding differs: run1=%d, run2=%d", i,
				chunks1[i].PaddingLen, chunks2[i].PaddingLen)
		}
		if chunks1[i].Sequence != chunks2[i].Sequence {
			t.Errorf("chunk %d sequence differs", i)
		}
	}
}

// TestFingerprintPaddingSeedIsolation verifies that different
// PaddingSeeds produce different padding (no cross-circuit correlation).
func TestFingerprintPaddingSeedIsolation(t *testing.T) {
	seedA := make([]byte, 32)
	seedB := make([]byte, 32)
	for i := range seedB {
		seedB[i] = 0xFF
	}

	cfgA := ChunkerConfig{
		MaxChunkSize: 1024,
		MinChunkSize: 1024,
		PaddingMin:   50,
		PaddingMax:   500,
		PaddingSeed:  seedA,
	}
	cfgB := ChunkerConfig{
		MaxChunkSize: 1024,
		MinChunkSize: 1024,
		PaddingMin:   50,
		PaddingMax:   500,
		PaddingSeed:  seedB,
	}

	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i % 256)
	}

	chunkerA := NewChunkerWithConfig("fixed-16k", cfgA)
	chunkerB := NewChunkerWithConfig("fixed-16k", cfgB)

	chunksA := chunkerA.Split(data)
	chunksB := chunkerB.Split(data)

	if len(chunksA) != len(chunksB) {
		t.Fatalf("chunk count differs: A=%d, B=%d", len(chunksA), len(chunksB))
	}

	// Payloads should match (same data, same chunk sizes).
	// Padding lengths should DIFFER (different seeds → different pad streams).
	paddingMatchCount := 0
	for i := range chunksA {
		if !bytes.Equal(chunksA[i].Payload, chunksB[i].Payload) {
			t.Errorf("chunk %d payload differs — should be identical for same data", i)
		}
		if chunksA[i].PaddingLen == chunksB[i].PaddingLen {
			paddingMatchCount++
		}
	}

	// With strong probability, padding should differ on most chunks.
	// Allow a few collisions (random chance).
	if paddingMatchCount > len(chunksA)/2 {
		t.Errorf("padding matched on %d/%d chunks — different seeds should produce mostly different padding",
			paddingMatchCount, len(chunksA))
	}
}

// =============================================================================
// Section 3: Debug Mode Fingerprint Tests
// =============================================================================

// TestFingerprintDebugFixedChunksProducesUniformChunks verifies that
// the bounded chunker in debug mode (DebugFixedSizes=true) produces
// uniform chunks at exactly MaxChunkSize. This is the contract
// requirement from CHUNKER_CONTRACT.md §6.5.
func TestFingerprintDebugFixedChunksProducesUniformChunks(t *testing.T) {
	debugCfg := ChunkerConfig{
		MaxChunkSize:    16 * 1024,
		MinChunkSize:    4 * 1024,
		DisablePadding:  true,
		DebugFixedSizes: true, // should force uniform sizes
	}
	proCfg := ChunkerConfig{
		MaxChunkSize:    16 * 1024,
		MinChunkSize:    4 * 1024,
		DisablePadding:  true,
		DebugFixedSizes: false,
	}

	data := make([]byte, 200*1024) // 200KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	debugChunker := NewChunkerWithConfig("bounded-4k-64k", debugCfg)
	debugChunks := debugChunker.Split(data)

	proChunker := NewChunkerWithConfig("bounded-4k-64k", proCfg)
	proChunks := proChunker.Split(data)

	// Debug mode: DebugFixedSizes=true MUST force uniform sizes at MaxChunkSize.
	// All non-last chunks must be exactly MaxChunkSize.
	if len(debugChunks) < 2 {
		t.Fatalf("debug chunker produced %d chunks — expected at least 2 for uniform size test", len(debugChunks))
	}
	for i := 0; i < len(debugChunks)-1; i++ {
		sz := len(debugChunks[i].Payload)
		if sz != debugCfg.MaxChunkSize {
			t.Errorf("debug chunk %d size = %d, want %d (DebugFixedSizes must force uniform MaxChunkSize)",
				i, sz, debugCfg.MaxChunkSize)
		}
	}
	// Last chunk may be smaller (remainder).
	lastSize := len(debugChunks[len(debugChunks)-1].Payload)
	if lastSize > debugCfg.MaxChunkSize {
		t.Errorf("debug last chunk size %d exceeds max %d", lastSize, debugCfg.MaxChunkSize)
	}

	// Production mode: should produce variable sizes.
	if len(proChunks) > 5 {
		sizes := make(map[int]int)
		for i := 0; i < len(proChunks)-1; i++ {
			sizes[len(proChunks[i].Payload)]++
		}
		if len(sizes) < 2 {
			t.Errorf("production bounded chunker produced only %d distinct sizes — expected > 1", len(sizes))
		}
	}

	if len(debugChunks) == 0 {
		t.Error("debug chunker produced no chunks")
	}
	if len(proChunks) == 0 {
		t.Error("production chunker produced no chunks")
	}
}

// =============================================================================
// Section 4: Boundary Condition Tests
// =============================================================================

// TestFingerprintChunkSizeBounds verifies that chunks always respect
// [MinChunkSize, MaxChunkSize] bounds for both strategies.
func TestFingerprintChunkSizeBounds(t *testing.T) {
	testCases := []struct {
		name     string
		strategy string
		minSize  int
		maxSize  int
	}{
		{"bounded-4k", "bounded-4k-64k", 4 * 1024, 8 * 1024},
		{"bounded-64k", "bounded-4k-64k", 32 * 1024, 64 * 1024},
		{"fixed-16k", "fixed-16k", 16 * 1024, 16 * 1024},
		{"fixed-4k", "fixed-16k", 4 * 1024, 4 * 1024},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ChunkerConfig{
				MinChunkSize:   tc.minSize,
				MaxChunkSize:   tc.maxSize,
				DisablePadding: true,
			}

			// Generate data that's a multiple of the max chunk size to get clean boundaries.
			dataSize := tc.maxSize * 10
			data := make([]byte, dataSize)
			for i := range data {
				data[i] = byte(i % 256)
			}

			chunker := NewChunkerWithConfig(tc.strategy, cfg)
			chunks := chunker.Split(data)

			if len(chunks) == 0 {
				t.Fatal("chunker produced no chunks")
			}

			for i, c := range chunks {
				sz := len(c.Payload)
				isLast := i == len(chunks)-1

				if sz > tc.maxSize {
					t.Errorf("chunk %d size %d exceeds max %d", i, sz, tc.maxSize)
				}

				// Non-last chunks must respect minimum.
				if !isLast && sz < tc.minSize {
					t.Errorf("chunk %d size %d below min %d (non-last chunk)", i, sz, tc.minSize)
				}

				// Last chunk can be smaller if remaining data < minSize.
				if isLast && dataSize%tc.maxSize != 0 {
					// Last chunk may legitimately be smaller.
				}
			}
		})
	}
}

// TestFingerprintSmallPayloadProducesSingleChunk verifies that small
// payloads produce exactly one chunk (not split into sub-minimum chunks).
func TestFingerprintSmallPayloadProducesSingleChunk(t *testing.T) {
	tinyData := []byte("hello")

	for _, strategy := range []string{"fixed-16k", "bounded-4k-64k"} {
		t.Run(strategy, func(t *testing.T) {
			cfg := ChunkerConfig{
				MaxChunkSize:   16 * 1024,
				MinChunkSize:   4 * 1024,
				DisablePadding: true,
			}

			chunker := NewChunkerWithConfig(strategy, cfg)
			chunks := chunker.Split(tinyData)

			if len(chunks) == 0 {
				t.Error("chunker produced no chunks for small payload")
			}
			if len(chunks) > 1 {
				t.Errorf("small payload produced %d chunks — expected 1", len(chunks))
			}

			// The single chunk should contain all the data.
			if !bytes.Equal(chunks[0].Payload, tinyData) {
				t.Errorf("chunk payload mismatch: got %q, want %q", chunks[0].Payload, tinyData)
			}
		})
	}
}

// TestFingerprintEmptyPayloadProducesNoChunks verifies that empty input
// produces zero chunks (not a zero-byte chunk).
func TestFingerprintEmptyPayloadProducesNoChunks(t *testing.T) {
	for _, strategy := range []string{"fixed-16k", "bounded-4k-64k"} {
		t.Run(strategy, func(t *testing.T) {
			cfg := ChunkerConfig{
				MaxChunkSize:   16 * 1024,
				MinChunkSize:   4 * 1024,
				DisablePadding: true,
			}

			chunker := NewChunkerWithConfig(strategy, cfg)
			chunks := chunker.Split(nil)

			if len(chunks) != 0 {
				t.Errorf("nil payload produced %d chunks — expected 0", len(chunks))
			}

			chunks = chunker.Split([]byte{})
			if len(chunks) != 0 {
				t.Errorf("empty payload produced %d chunks — expected 0", len(chunks))
			}
		})
	}
}

// =============================================================================
// Section 5: Distribution Shape Tests
// =============================================================================

// TestFingerprintClusteringCoefficient verifies that the bounded chunker
// produces a distribution with sufficient spread (not all values in a
// narrow band). A narrow-band distribution is fingerprintable.
//
// This is a statistical test — it uses large enough data to get a
// meaningful sample. We check the standard deviation is above a
// minimum threshold relative to the range.
func TestFingerprintClusteringCoefficient(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   64 * 1024,
		DisablePadding: true,
	}

	// Generate 2MB to get statistically meaningful chunk count.
	data := make([]byte, 2*1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	chunker := NewChunkerWithConfig("bounded-4k-64k", cfg)
	chunks := chunker.Split(data)

	if len(chunks) < 20 {
		t.Fatalf("only %d chunks — need more for statistical analysis", len(chunks))
	}

	// Compute mean and standard deviation of chunk sizes.
	var sum, sumSq float64
	n := float64(len(chunks))
	for _, c := range chunks {
		sz := float64(len(c.Payload))
		sum += sz
		sumSq += sz * sz
	}
	mean := sum / n
	variance := (sumSq / n) - (mean * mean)
	if variance < 0 {
		variance = 0
	}

	// Standard deviation should be non-trivial for bounded mode.
	// A uniform distribution would have stddev near 0.
	// A Pareto with α=1.5 spanning 4KB-64KB has significant variance.
	rangeSize := float64(cfg.MaxChunkSize - cfg.MinChunkSize)
	cv := 0.0
	if mean > 0 {
		cv = variance / mean // coefficient of variation squared
	}

	// The bounded distribution should span at least 10% of the range
	// (very lenient — real Pareto distributions span far more).
	if variance < rangeSize*rangeSize*0.01 {
		t.Errorf("chunk size variance too low (%.0f) for range %.0f — distribution appears uniform",
			variance, rangeSize)
	}

	// Document statistical properties for review.
	_ = cv
}

// TestFingerprintNoSizeZeroChunks verifies that the chunker never
// produces chunks with payload size 0. Size-0 chunks would be a
// protocol violation per CHUNKER_CONTRACT.md §6.
func TestFingerprintNoSizeZeroChunks(t *testing.T) {
	for _, strategy := range []string{"fixed-16k", "bounded-4k-64k"} {
		t.Run(strategy, func(t *testing.T) {
			cfg := ChunkerConfig{
				MaxChunkSize:   16 * 1024,
				MinChunkSize:   4 * 1024,
				DisablePadding: true,
			}

			// Test with various data sizes.
			dataSizes := []int{1, 16, 100, 1024, 4096, 16384, 65536, 100000}
			for _, sz := range dataSizes {
				data := make([]byte, sz)
				for i := range data {
					data[i] = byte(i % 256)
				}

				chunker := NewChunkerWithConfig(strategy, cfg)
				chunks := chunker.Split(data)

				for i, c := range chunks {
					if len(c.Payload) == 0 {
						t.Errorf("strategy=%s dataSize=%d chunk %d has empty payload",
							strategy, sz, i)
					}
				}
			}
		})
	}
}

// =============================================================================
// Section 6: Sequence and Metadata Integrity Tests
// =============================================================================

// TestFingerprintChunkSequencesAreMonotonic verifies that each chunk's
// Sequence field is monotonically increasing within a stream, starting
// from 0.
func TestFingerprintChunkSequencesAreMonotonic(t *testing.T) {
	for _, strategy := range []string{"fixed-16k", "bounded-4k-64k"} {
		t.Run(strategy, func(t *testing.T) {
			cfg := ChunkerConfig{
				MaxChunkSize:   1024,
				MinChunkSize:   512,
				DisablePadding: true,
			}

			data := make([]byte, 100*1024)
			for i := range data {
				data[i] = byte(i % 256)
			}

			chunker := NewChunkerWithConfig(strategy, cfg)
			chunks := chunker.Split(data)

			if len(chunks) == 0 {
				t.Fatal("no chunks produced")
			}

			for i, c := range chunks {
				if c.Sequence != uint32(i) {
					t.Errorf("chunk %d has sequence %d, expected %d", i, c.Sequence, i)
				}
			}
		})
	}
}

// TestFingerprintChunkStreamIDDefault verifies that chunks default to
// stream ID 0 when not configured.
func TestFingerprintChunkStreamIDDefault(t *testing.T) {
	cfg := ChunkerConfig{
		MaxChunkSize:   1024,
		MinChunkSize:   1024,
		DisablePadding: true,
	}

	data := []byte("default stream test")
	chunker := NewChunkerWithConfig("fixed-16k", cfg)
	chunks := chunker.Split(data)

	if len(chunks) == 0 {
		t.Fatal("no chunks produced")
	}

	// StreamID should default to 0.
	for i, c := range chunks {
		if c.StreamID != 0 {
			t.Errorf("chunk %d has StreamID=%d, expected 0 (default)", i, c.StreamID)
		}
	}
}

// =============================================================================
// Section 7: Statistical Fingerprinting Mitigation Tests (§6.7–§6.9)
// =============================================================================
//
// These tests verify the three statistical fingerprinting mitigations
// documented in CHUNKER_CONTRACT.md §6 that were previously untested:
//   - §6.7: Chunk count distribution (non-deterministic chunk counts)
//   - §6.8: Padding-size independence (no correlation between payload
//     size and padding length)
//   - §6.9: Dispatch timing (no fixed intervals — this is a transport-
//     layer concern, tested via configuration validation, not here)

// TestFingerprintChunkCountDistribution verifies that for a fixed-size
// input, the bounded chunker produces a non-deterministic number of
// chunks across multiple runs. Two streams of identical payload length
// should not produce the same chunk count on every run — that would
// create a recognizable fingerprint.
//
// Contract reference: CHUNKER_CONTRACT.md §6.7
func TestFingerprintChunkCountDistribution(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   64 * 1024,
		DisablePadding: true,
	}

	data := make([]byte, 256*1024) // 256KB — enough to produce 4–64 chunks
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Run the chunker 20 times with the same input.
	const runs = 20
	counts := make(map[int]int)
	for i := 0; i < runs; i++ {
		chunker := NewChunkerWithConfig("bounded-4k-64k", cfg)
		chunks := chunker.Split(data)
		counts[len(chunks)]++
	}

	t.Logf("chunk count distribution over %d runs: %v", runs, counts)

	// We expect at least 2 distinct chunk counts — if every run produced
	// the same count, the chunker would be fingerprintable.
	if len(counts) < 2 {
		t.Errorf("all %d runs produced the same chunk count (%d) — chunk count is deterministic (fingerprintable)",
			runs, func() int {
				for k := range counts {
					return k
				}
				return -1
			}())
	}

	// Verify no single count dominates (>90% of runs would indicate
	// very low variance, which is weak but not a hard failure).
	maxFreq := 0
	for _, freq := range counts {
		if freq > maxFreq {
			maxFreq = freq
		}
	}
	if maxFreq == runs && runs > 1 {
		t.Errorf("100%% of runs produced the same chunk count — distribution is degenerate")
	}
}

// TestFingerprintPaddingSizeIndependence verifies that there is no
// correlation between payload size and padding length. A passive
// adversary who can observe a correlation between the two dimensions
// could fingerprint the implementation.
//
// We compute the Pearson correlation coefficient between payload sizes
// and padding lengths across many chunks. The null hypothesis (no
// correlation) must not be rejected at p < 0.05 — in practice, we
// check that |r| < 0.5 (a very lenient threshold; real independence
// produces |r| < 0.1).
//
// Contract reference: CHUNKER_CONTRACT.md §6.8
func TestFingerprintPaddingSizeIndependence(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   64 * 1024,
		PaddingMin:     256,
		PaddingMax:     2048,
		DisablePadding: false, // padding active
	}

	// 2MB of data → enough chunks for statistical significance.
	data := make([]byte, 2*1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	chunker := NewChunkerWithConfig("bounded-4k-64k", cfg)
	chunks := chunker.Split(data)

	if len(chunks) < 30 {
		t.Fatalf("only %d chunks — need at least 30 for correlation test", len(chunks))
	}

	// Collect (payloadSize, paddingLen) pairs for non-last chunks.
	n := len(chunks) - 1 // exclude last (remainder chunk)
	x := make([]float64, n) // payload sizes
	y := make([]float64, n) // padding lengths
	for i := 0; i < n; i++ {
		x[i] = float64(len(chunks[i].Payload))
		y[i] = float64(chunks[i].PaddingLen)
	}

	// Compute Pearson correlation coefficient.
	var sumX, sumY, sumXY, sumX2, sumY2 float64
	for i := 0; i < n; i++ {
		sumX += x[i]
		sumY += y[i]
		sumXY += x[i] * y[i]
		sumX2 += x[i] * x[i]
		sumY2 += y[i] * y[i]
	}
	meanX := sumX / float64(n)
	meanY := sumY / float64(n)

	numerator := sumXY - float64(n)*meanX*meanY
	denominator := math.Sqrt((sumX2 - float64(n)*meanX*meanX) * (sumY2 - float64(n)*meanY*meanY))

	var r float64
	if denominator > 0 {
		r = numerator / denominator
	}

	t.Logf("Pearson r(payloadSize, paddingLen) = %.4f over %d chunks", r, n)

	// |r| must be below 0.5 (very lenient — true independence gives |r| < 0.1).
	// A value above 0.5 would indicate a strong linear correlation between
	// the two dimensions, which is a fingerprinting vulnerability.
	if r > 0.5 || r < -0.5 {
		t.Errorf("strong correlation between payload size and padding length (r=%.4f) — fingerprinting vulnerability", r)
	}
}