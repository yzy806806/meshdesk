package proxy

import (
	"testing"
)

// TestFixedChunkerTotalComputed verifies that Split() sets chunk.Total
// to ceil(len(data) / MaxChunkSize) on all produced chunks when no
// explicit Total has been set via SetTotal(). This is the core fix for
// Chunker Gap 1: the Reassembler needs Total to know how many chunks
// to expect without waiting for a ChunkStreamEnd marker.
func TestFixedChunkerTotalComputed(t *testing.T) {
	cfg := ChunkerConfig{
		MaxChunkSize:   16 * 1024,
		MinChunkSize:   16 * 1024,
		DisablePadding: true, // deterministic
	}

	tests := []struct {
		name      string
		dataLen   int
		wantTotal uint32
	}{
		{"exact multiple", 48 * 1024, 3},       // 3 x 16KB = 48KB → 3 chunks
		{"partial last chunk", 40 * 1024, 3},   // 2 full + 1 partial → 3 chunks
		{"single full chunk", 16 * 1024, 1},    // 1 chunk
		{"single partial chunk", 100, 1},       // 1 chunk (smaller than MaxChunkSize)
		{"two full chunks", 32 * 1024, 2},      // 2 chunks
		{"partial last chunk 2", 17 * 1024, 2}, // 1 full + 1 partial → 2 chunks
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the chunker for each subtest.
			c := newFixedChunker(cfg)
			data := make([]byte, tt.dataLen)
			chunks := c.Split(data)

			if len(chunks) == 0 {
				t.Fatal("expected non-zero chunks")
			}

			if uint32(len(chunks)) != tt.wantTotal {
				t.Fatalf("got %d chunks, want %d", len(chunks), tt.wantTotal)
			}

			for i, ch := range chunks {
				if ch.Total != tt.wantTotal {
					t.Errorf("chunk[%d].Total = %d, want %d", i, ch.Total, tt.wantTotal)
				}
			}
		})
	}
}

// TestFixedChunkerTotalNotOverriddenBySplit verifies that when SetTotal
// has been called, Split() respects the explicitly-set Total instead of
// computing its own. This preserves backward compatibility with callers
// that set Total via SetTotal.
func TestFixedChunkerTotalNotOverriddenBySplit(t *testing.T) {
	cfg := ChunkerConfig{
		MaxChunkSize:   16 * 1024,
		MinChunkSize:   16 * 1024,
		DisablePadding: true,
	}
	c := newFixedChunker(cfg)
	c.SetTotal(999) // explicit total, should take priority

	data := make([]byte, 48*1024) // 3 chunks
	chunks := c.Split(data)

	for i, ch := range chunks {
		if ch.Total != 999 {
			t.Errorf("chunk[%d].Total = %d, want 999 (explicitly set)", i, ch.Total)
		}
	}
}

// TestFixedChunkerReassemblerCompletesWithoutStreamEnd verifies the
// actual end-to-end fix: when the full data buffer is split in one call,
// the reassembler signals completion purely from Total, without needing
// a ChunkStreamEnd marker. This is the scenario that was broken before
// the fix — the reassembler would wait forever.
func TestFixedChunkerReassemblerCompletesWithoutStreamEnd(t *testing.T) {
	cfg := ChunkerConfig{
		MaxChunkSize:   16 * 1024,
		MinChunkSize:   16 * 1024,
		DisablePadding: true,
	}
	c := newFixedChunker(cfg)
	r := NewExitReassembler(cfg)

	// 48KB of data → 3 chunks of 16KB each.
	original := make([]byte, 48*1024)
	for i := range original {
		original[i] = byte(i % 256)
	}

	chunks := c.Split(original)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}

	// Verify Total is set on all chunks.
	for i, ch := range chunks {
		if ch.Total != 3 {
			t.Fatalf("chunk[%d].Total = %d, want 3", i, ch.Total)
		}
	}

	// Feed chunks to reassembler WITHOUT a ChunkStreamEnd marker.
	// Completion should come from Total alone.
	var reassembled []byte
	var done bool
	for i, ch := range chunks {
		var err error
		reassembled, done, err = r.Add(ch)
		if err != nil {
			t.Fatalf("chunk %d: unexpected error: %v", i, err)
		}
	}

	if !done {
		t.Fatal("reassembler did not signal completion from Total alone (ChunkStreamEnd not sent)")
	}

	if len(reassembled) != len(original) {
		t.Fatalf("reassembled length %d != original %d", len(reassembled), len(original))
	}

	for i := range original {
		if reassembled[i] != original[i] {
			t.Errorf("byte %d mismatch: got %d, want %d", i, reassembled[i], original[i])
			break
		}
	}
}

// TestFixedChunkerReassemblerCompletesPartialLastChunk verifies that
// when the data length is not a multiple of MaxChunkSize, the last
// partial chunk is correctly handled: Total includes it and the
// reassembler completes when it arrives.
func TestFixedChunkerReassemblerCompletesPartialLastChunk(t *testing.T) {
	cfg := ChunkerConfig{
		MaxChunkSize:   16 * 1024,
		MinChunkSize:   16 * 1024,
		DisablePadding: true,
	}
	c := newFixedChunker(cfg)
	r := NewExitReassembler(cfg)

	// 17KB → 1 full chunk (16KB) + 1 partial (1KB) → Total=2
	original := make([]byte, 17*1024)
	for i := range original {
		original[i] = byte(i % 256)
	}

	chunks := c.Split(original)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}

	// Last chunk should be smaller (partial).
	if len(chunks[1].Payload) != 1024 {
		t.Errorf("last chunk payload = %d bytes, want 1024 (partial)", len(chunks[1].Payload))
	}

	var reassembled []byte
	var done bool
	for i, ch := range chunks {
		var err error
		reassembled, done, err = r.Add(ch)
		if err != nil {
			t.Fatalf("chunk %d: unexpected error: %v", i, err)
		}
	}

	if !done {
		t.Fatal("reassembler did not complete with partial last chunk")
	}

	if len(reassembled) != len(original) {
		t.Fatalf("reassembled length %d != original %d", len(reassembled), len(original))
	}
}

// TestBoundedChunkerTotalComputed verifies that the bounded chunker
// sets chunk.Total to len(chunks) on all produced chunks.
func TestBoundedChunkerTotalComputed(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   8 * 1024,
		DisablePadding: true,
	}
	c := newBoundedChunker(cfg)

	data := make([]byte, 64*1024)
	chunks := c.Split(data)

	if len(chunks) == 0 {
		t.Fatal("expected non-zero chunks")
	}

	wantTotal := uint32(len(chunks))
	for i, ch := range chunks {
		if ch.Total != wantTotal {
			t.Errorf("chunk[%d].Total = %d, want %d", i, ch.Total, wantTotal)
		}
	}
}

// TestBoundedChunkerReassemblerCompletesWithoutStreamEnd verifies the
// end-to-end fix for the bounded chunker: reassembler completes from
// Total alone, without a ChunkStreamEnd marker.
func TestBoundedChunkerReassemblerCompletesWithoutStreamEnd(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   8 * 1024,
		DisablePadding: true,
	}
	c := newBoundedChunker(cfg)
	r := NewExitReassembler(cfg)

	original := make([]byte, 32*1024)
	for i := range original {
		original[i] = byte(i % 256)
	}

	chunks := c.Split(original)
	if len(chunks) == 0 {
		t.Fatal("expected non-zero chunks")
	}

	// Verify Total is set.
	wantTotal := uint32(len(chunks))
	for i, ch := range chunks {
		if ch.Total != wantTotal {
			t.Fatalf("chunk[%d].Total = %d, want %d", i, ch.Total, wantTotal)
		}
	}

	// Feed to reassembler WITHOUT StreamEnd.
	var reassembled []byte
	var done bool
	for i, ch := range chunks {
		var err error
		reassembled, done, err = r.Add(ch)
		if err != nil {
			t.Fatalf("chunk %d: unexpected error: %v", i, err)
		}
	}

	if !done {
		t.Fatal("bounded reassembler did not complete from Total alone")
	}

	if len(reassembled) != len(original) {
		t.Fatalf("reassembled length %d != original %d", len(reassembled), len(original))
	}

	for i := range original {
		if reassembled[i] != original[i] {
			t.Errorf("byte %d mismatch: got %d, want %d", i, reassembled[i], original[i])
			break
		}
	}
}

// TestBoundedChunkerTotalNotOverriddenBySplit verifies that SetTotal
// takes priority over the computed total for the bounded chunker.
func TestBoundedChunkerTotalNotOverriddenBySplit(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   8 * 1024,
		DisablePadding: true,
	}
	c := newBoundedChunker(cfg)
	c.SetTotal(42)

	data := make([]byte, 32*1024)
	chunks := c.Split(data)

	for i, ch := range chunks {
		if ch.Total != 42 {
			t.Errorf("chunk[%d].Total = %d, want 42 (explicitly set)", i, ch.Total)
		}
	}
}
