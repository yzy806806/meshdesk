package proxy

import (
	"testing"
)

// TestBoundedChunkerBasicSplit verifies the bounded chunker produces
// chunks with variable sizes in the [4KB, 64KB] range.
func TestBoundedChunkerBasicSplit(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   64 * 1024,
		DisablePadding: true, // deterministic test without padding
	}
	c := newBoundedChunker(cfg)

	// 1MB of data → should produce 16–256 chunks depending on sizes.
	data := make([]byte, 1024*1024)
	chunks := c.Split(data)

	if len(chunks) == 0 {
		t.Fatal("expected non-zero chunks for 1MB input")
	}

	// Verify all chunks are within bounds (except possibly the last).
	for i, ch := range chunks {
		if ch.Type != ChunkData {
			t.Errorf("chunk[%d]: expected ChunkData, got %v", i, ch.Type)
		}
		if len(ch.Payload) == 0 {
			t.Errorf("chunk[%d]: empty payload", i)
		}
		if len(ch.Payload) > cfg.MaxChunkSize {
			t.Errorf("chunk[%d]: payload %d > max %d", i, len(ch.Payload), cfg.MaxChunkSize)
		}
		// Non-last chunks must be >= minSize (last can be smaller).
		if i < len(chunks)-1 && len(ch.Payload) < cfg.MinChunkSize {
			t.Errorf("chunk[%d]: payload %d < min %d (non-last)", i, len(ch.Payload), cfg.MinChunkSize)
		}
	}

	t.Logf("1MB → %d chunks, avg size: %.0f bytes", len(chunks),
		float64(len(data))/float64(len(chunks)))
}

// TestBoundedChunkerVariableSizes verifies that the bounded chunker
// produces chunks with DIFFERENT sizes (i.e., it is not fixed-size).
// This validates the anti-fingerprinting property: uniform sizing
// creates a detectable pattern.
func TestBoundedChunkerVariableSizes(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   64 * 1024,
		DisablePadding: true,
	}
	c := newBoundedChunker(cfg)

	// 4MB of data → enough chunks to see size variation.
	data := make([]byte, 4*1024*1024)
	chunks := c.Split(data)

	if len(chunks) < 10 {
		t.Fatalf("expected at least 10 chunks, got %d", len(chunks))
	}

	// Count distinct sizes (excluding the last chunk which may be a remainder).
	sizes := make(map[int]bool)
	for i := 0; i < len(chunks)-1; i++ {
		sizes[len(chunks[i].Payload)] = true
	}

	if len(sizes) < 3 {
		t.Errorf("expected at least 3 distinct chunk sizes for anti-fingerprinting, got %d: %v",
			len(sizes), sizes)
	}

	t.Logf("distinct chunk sizes (excluding last): %d out of %d chunks", len(sizes), len(chunks)-1)
}

// TestBoundedChunkerParetoDistribution verifies that the chunk sizes
// roughly follow a Pareto distribution: most chunks should be in the
// lower portion of the range, with a long tail of larger chunks.
func TestBoundedChunkerParetoDistribution(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   64 * 1024,
		DisablePadding: true,
	}
	c := newBoundedChunker(cfg)

	// 16MB of data for statistical significance.
	data := make([]byte, 16*1024*1024)
	chunks := c.Split(data)

	if len(chunks) < 100 {
		t.Fatalf("expected at least 100 chunks for statistical test, got %d", len(chunks))
	}

	// Count chunks in each quartile of the range [4KB, 64KB].
	// Pareto should produce more chunks in the lower quartile.
	rangeSize := cfg.MaxChunkSize - cfg.MinChunkSize
	q1 := cfg.MinChunkSize + rangeSize/4    // 20KB
	q2 := cfg.MinChunkSize + rangeSize/2    // 34KB
	q3 := cfg.MinChunkSize + 3*rangeSize/4  // 48KB

	var q1Count, q2Count, q3Count, q4Count int
	for i := 0; i < len(chunks)-1; i++ { // exclude last (remainder)
		size := len(chunks[i].Payload)
		switch {
		case size <= q1:
			q1Count++
		case size <= q2:
			q2Count++
		case size <= q3:
			q3Count++
		default:
			q4Count++
		}
	}

	total := q1Count + q2Count + q3Count + q4Count
	t.Logf("Pareto distribution: Q1(4-20K)=%d (%.1f%%), Q2(20-34K)=%d (%.1f%%), Q3(34-48K)=%d (%.1f%%), Q4(48-64K)=%d (%.1f%%)",
		q1Count, float64(q1Count)/float64(total)*100,
		q2Count, float64(q2Count)/float64(total)*100,
		q3Count, float64(q3Count)/float64(total)*100,
		q4Count, float64(q4Count)/float64(total)*100)

	// For a Pareto distribution with α=1.5, the majority of chunks
	// should be in Q1 (lower quartile). At minimum, Q1 should have
	// more chunks than Q4 (heavy-tailed = more small than large).
	if q1Count <= q4Count {
		t.Errorf("Pareto property violated: Q1 (%d) should have more chunks than Q4 (%d)",
			q1Count, q4Count)
	}
}

// TestBoundedChunkerSequenceMonotonic verifies sequence numbers are
// monotonically increasing starting from 0.
func TestBoundedChunkerSequenceMonotonic(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   8 * 1024, // small range for more chunks
		DisablePadding: true,
	}
	c := newBoundedChunker(cfg)

	data := make([]byte, 64*1024)
	chunks := c.Split(data)

	for i, ch := range chunks {
		if ch.Sequence != uint32(i) {
			t.Errorf("chunk[%d].Sequence = %d, want %d", i, ch.Sequence, i)
		}
	}
}

// TestBoundedReassemblerRoundTrip verifies that data split by the
// bounded chunker can be correctly reassembled.
func TestBoundedReassemblerRoundTrip(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   8 * 1024,
		DisablePadding: true,
	}
	c := newBoundedChunker(cfg)
	r := newBoundedReassembler(cfg)

	// Create test data with a known pattern.
	data := make([]byte, 32*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	chunks := c.Split(data)
	if len(chunks) == 0 {
		t.Fatal("expected non-zero chunks")
	}

	// Set Total on each chunk so the reassembler knows when complete.
	total := uint32(len(chunks))
	var reassembled []byte
	var done bool
	var err error

	for _, ch := range chunks {
		ch.Total = total
		reassembled, done, err = r.Add(ch)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !done {
			continue
		}
	}

	if !done {
		t.Fatal("reassembler did not signal completion")
	}

	if len(reassembled) != len(data) {
		t.Fatalf("reassembled length %d != original %d", len(reassembled), len(data))
	}

	for i := range data {
		if reassembled[i] != data[i] {
			t.Errorf("byte %d mismatch: got %d, want %d", i, reassembled[i], data[i])
			break
		}
	}
}

// TestBoundedReassemblerOutOfOrder verifies that chunks arriving out
// of order are correctly reassembled.
func TestBoundedReassemblerOutOfOrder(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize:   4 * 1024,
		MaxChunkSize:   8 * 1024,
		DisablePadding: true,
	}
	c := newBoundedChunker(cfg)
	r := newBoundedReassembler(cfg)

	data := []byte("This is test data for out-of-order reassembly with the bounded chunker.")
	chunks := c.Split(data)
	total := uint32(len(chunks))

	// Set Total and shuffle delivery order.
	for i := range chunks {
		chunks[i].Total = total
	}

	// Reverse order.
	for i, j := 0, len(chunks)-1; i < j; i, j = i+1, j-1 {
		chunks[i], chunks[j] = chunks[j], chunks[i]
	}

	var reassembled []byte
	var done bool
	var err error
	for _, ch := range chunks {
		reassembled, done, err = r.Add(ch)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if !done {
		t.Fatal("reassembler did not signal completion")
	}

	if string(reassembled) != string(data) {
		t.Errorf("reassembled %q != original %q", string(reassembled), string(data))
	}
}

// TestBoundedChunkerEmptyInput verifies empty input produces no chunks.
func TestBoundedChunkerEmptyInput(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize: 4 * 1024,
		MaxChunkSize: 64 * 1024,
	}
	c := newBoundedChunker(cfg)

	if chunks := c.Split(nil); len(chunks) != 0 {
		t.Errorf("Split(nil) returned %d chunks, want 0", len(chunks))
	}
	if chunks := c.Split([]byte{}); len(chunks) != 0 {
		t.Errorf("Split([]byte{}) returned %d chunks, want 0", len(chunks))
	}
}

// TestBoundedChunkerSmallInput verifies that data smaller than minSize
// is still produced as a single (small) chunk.
func TestBoundedChunkerSmallInput(t *testing.T) {
	cfg := ChunkerConfig{
		MinChunkSize: 4 * 1024,
		MaxChunkSize: 64 * 1024,
	}
	c := newBoundedChunker(cfg)

	data := []byte("tiny")
	chunks := c.Split(data)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk for 4 bytes, got %d", len(chunks))
	}
	if string(chunks[0].Payload) != "tiny" {
		t.Errorf("payload = %q, want %q", string(chunks[0].Payload), "tiny")
	}
}

// TestBoundedReassemblerRegistered verifies the bounded strategy is
// registered and can be created via the registry.
func TestBoundedReassemblerRegistered(t *testing.T) {
	c := NewChunker("bounded-4k-64k")
	if c == nil {
		t.Fatal("NewChunker(bounded-4k-64k) returned nil")
	}

	r := NewReassembler("bounded-4k-64k")
	if r == nil {
		t.Fatal("NewReassembler(bounded-4k-64k) returned nil")
	}

	// Verify both strategies appear in registry names.
	names := ChunkerRegistry.Names()
	found := false
	for _, n := range names {
		if n == "bounded-4k-64k" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("bounded-4k-64k not found in registry names: %v", names)
	}
}
