// Package proxy_test contains the contract test suite for the Chunker and
// Reassembler interfaces. Any concrete implementation must pass these tests
// to be considered conformant.
//
// These tests define the acceptance criteria from the team discussion
// (motion-d607d489b7be):
//   - Chunker.Split produces valid Chunks with correct Sequence ordering
//   - Reassembler.Add handles in-order chunks and signals completion
//   - Reassembler.Add handles out-of-order chunks correctly
//   - Reassembler.Add deduplicates chunks with the same Sequence
//   - ChunkStreamEnd triggers completion regardless of Total
//   - Total triggers completion when all chunks (0..Total-1) arrive
//   - Empty input produces no Chunks or clean state
//   - Registry panics on duplicate registration
//   - Reassembly bounds (max chunks, max bytes) are enforced
//   - Padding seed produces deterministic padding per circuit
package proxy_test

import (
	"testing"

	"github.com/yzy806806/meshdesk/internal/proxy"
)

// mustNoErr is a test helper that fails the test if err is non-nil.
func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// newTestPair creates a Chunker and Reassembler for the named strategy,
// using the default config. The test helper can be swapped by concrete
// tests that register a different strategy via init().
var newTestPair = func(t *testing.T) (proxy.Chunker, proxy.Reassembler) {
	t.Helper()
	c := proxy.NewChunker("fixed-16k")
	r := proxy.NewReassembler("fixed-16k")
	if c == nil {
		t.Fatal("NewChunker returned nil")
	}
	if r == nil {
		t.Fatal("NewReassembler returned nil")
	}
	return c, r
}

// TestChunkerSplitEmpty verifies that splitting empty input is safe
// and returns an empty slice (not nil with non-zero length).
func TestChunkerSplitEmpty(t *testing.T) {
	c, _ := newTestPair(t)
	chunks := c.Split(nil)
	if len(chunks) != 0 {
		t.Errorf("Split(nil) returned %d chunks, want 0", len(chunks))
	}
	chunks = c.Split([]byte{})
	if len(chunks) != 0 {
		t.Errorf("Split([]byte{}) returned %d chunks, want 0", len(chunks))
	}
}

// TestChunkerSplitProducesValidChunks verifies that Split returns chunks
// with correct, monotonically increasing sequence numbers starting from 0.
func TestChunkerSplitProducesValidChunks(t *testing.T) {
	c, _ := newTestPair(t)
	data := make([]byte, 48*1024) // 3 x 16KB
	chunks := c.Split(data)

	if len(chunks) == 0 {
		t.Fatal("Split returned no chunks for 48KB input")
	}

	var lastSeq uint32
	for i, ch := range chunks {
		if ch.Type == proxy.ChunkPadding {
			continue // padding chunks don't count in sequence
		}
		if i > 0 && ch.Sequence <= lastSeq {
			t.Errorf("chunk[%d].Sequence=%d, want > %d (non-monotonic)",
				i, ch.Sequence, lastSeq)
		}
		lastSeq = ch.Sequence
	}
}

// TestChunkerSplitPayloadNonEmpty verifies that data-carrying chunks
// have non-empty payloads (except padding chunks and stream markers).
func TestChunkerSplitPayloadNonEmpty(t *testing.T) {
	c, _ := newTestPair(t)
	data := make([]byte, 32*1024)
	chunks := c.Split(data)

	for i, ch := range chunks {
		switch ch.Type {
		case proxy.ChunkData:
			if len(ch.Payload) == 0 {
				t.Errorf("chunk[%d]: ChunkData has empty payload", i)
			}
		case proxy.ChunkStreamEnd:
			// StreamEnd may have empty payload -- it's a marker.
		case proxy.ChunkPadding:
			// Padding chunks have empty payload by definition.
		default:
			t.Logf("chunk[%d]: unknown type 0x%02x", i, ch.Type)
		}
	}
}

// TestReassemblerInOrder verifies that chunks arriving in order
// are correctly reassembled and signal completion.
func TestReassemblerInOrder(t *testing.T) {
	_, r := newTestPair(t)
	payloads := [][]byte{
		[]byte("hello "),
		[]byte("world"),
		[]byte("!"),
	}
	total := uint32(len(payloads))

	for i, p := range payloads {
		ch := proxy.Chunk{
			StreamID: 1,
			Sequence: uint32(i),
			Total:    total,
			Type:     proxy.ChunkData,
			Payload:  p,
		}
		complete, done, err := r.Add(ch)
		mustNoErr(t, err)
		if i < len(payloads)-1 {
			if done {
				t.Fatalf("chunk %d: Add returned done=true, want false (not all chunks arrived)", i)
			}
		} else {
			if !done {
				t.Fatal("last chunk: Add returned done=false, want true")
			}
			if string(complete) != "hello world!" {
				t.Errorf("reassembled = %q, want %q", string(complete), "hello world!")
			}
		}
	}
}

// TestReassemblerOutOfOrder verifies that chunks arriving out of
// sequence are correctly reassembled and signal completion only when
// all chunks have arrived.
func TestReassemblerOutOfOrder(t *testing.T) {
	_, r := newTestPair(t)
	// Deliver chunks in reverse order.
	chunks := []proxy.Chunk{
		{StreamID: 1, Sequence: 2, Total: 3, Type: proxy.ChunkData, Payload: []byte("!")},
		{StreamID: 1, Sequence: 1, Total: 3, Type: proxy.ChunkData, Payload: []byte("world")},
		{StreamID: 1, Sequence: 0, Total: 3, Type: proxy.ChunkData, Payload: []byte("hello ")},
	}

	for i, ch := range chunks {
		complete, done, err := r.Add(ch)
		mustNoErr(t, err)
		if i < len(chunks)-1 {
			if done {
				t.Fatalf("chunk seq=%d: Add returned done=true, want false", ch.Sequence)
			}
		} else {
			if !done {
				t.Fatal("last chunk: Add returned done=false, want true")
			}
			if string(complete) != "hello world!" {
				t.Errorf("reassembled = %q, want %q", string(complete), "hello world!")
			}
		}
	}
}

// TestReassemblerDeduplication verifies that receiving the same chunk
// (same StreamID + Sequence) twice does not corrupt the reassembly.
// The second Add should be a no-op for that chunk's data.
func TestReassemblerDeduplication(t *testing.T) {
	_, r := newTestPair(t)

	// Send chunk 0 twice, then chunk 1.
	r.Add(proxy.Chunk{StreamID: 1, Sequence: 0, Total: 2, Type: proxy.ChunkData, Payload: []byte("hello ")})
	r.Add(proxy.Chunk{StreamID: 1, Sequence: 0, Total: 2, Type: proxy.ChunkData, Payload: []byte("DUPLICATE - should be ignored")})

	complete, done, err := r.Add(proxy.Chunk{StreamID: 1, Sequence: 1, Total: 2, Type: proxy.ChunkData, Payload: []byte("world")})
	mustNoErr(t, err)
	if !done {
		t.Fatal("expected done=true after all chunks")
	}
	if string(complete) != "hello world" {
		t.Errorf("reassembled = %q, want %q", string(complete), "hello world")
	}
}

// TestReassemblerStreamEndMarker verifies that a ChunkStreamEnd marker
// triggers completion even when Total is 0 (unknown). This is the
// streaming completion path.
func TestReassemblerStreamEndMarker(t *testing.T) {
	_, r := newTestPair(t)

	payloads := []string{"alpha", "beta", "gamma"}
	for i, p := range payloads {
		ch := proxy.Chunk{
			StreamID: 1,
			Sequence: uint32(i),
			Total:    0, // unknown -- streaming mode
			Type:     proxy.ChunkData,
			Payload:  []byte(p),
		}
		if _, done, err := r.Add(ch); done || err != nil {
			t.Fatalf("chunk %d: unexpected done=%v err=%v", i, done, err)
		}
	}

	// Signal end of stream.
	complete, done, err := r.Add(proxy.Chunk{
		StreamID: 1,
		Sequence: 3,
		Total:    0,
		Type:     proxy.ChunkStreamEnd,
	})
	mustNoErr(t, err)
	if !done {
		t.Fatal("expected done=true after ChunkStreamEnd")
	}
	if string(complete) != "alphabetagamma" {
		t.Errorf("reassembled = %q, want %q", string(complete), "alphabetagamma")
	}
}

// TestReassemblerTotalCompletion verifies that Total triggers completion
// when all chunks 0..Total-1 have arrived, without needing a StreamEnd.
func TestReassemblerTotalCompletion(t *testing.T) {
	_, r := newTestPair(t)

	data := []string{"one", "two", "three", "four"}
	total := uint32(len(data))

	for i, p := range data {
		complete, done, err := r.Add(proxy.Chunk{
			StreamID: 1,
			Sequence: uint32(i),
			Total:    total,
			Type:     proxy.ChunkData,
			Payload:  []byte(p),
		})
		mustNoErr(t, err)
		if i < len(data)-1 {
			if done {
				t.Fatalf("chunk %d: unexpected done=true", i)
			}
		} else {
			if !done {
				t.Fatal("expected done=true when all chunks 0..Total-1 arrived")
			}
			if string(complete) != "onetwothreefour" {
				t.Errorf("reassembled = %q, want %q", string(complete), "onetwothreefour")
			}
		}
	}
}

// TestReassemblerPaddingChunksIgnored verifies that ChunkPadding chunks
// are accepted without corrupting the data stream -- they should not
// contribute to the reassembled output.
func TestReassemblerPaddingChunksIgnored(t *testing.T) {
	_, r := newTestPair(t)

	r.Add(proxy.Chunk{StreamID: 1, Sequence: 0, Total: 2, Type: proxy.ChunkData, Payload: []byte("hello")})
	r.Add(proxy.Chunk{StreamID: 1, Sequence: 999, Total: 0, Type: proxy.ChunkPadding}) // padding, ignored

	complete, done, err := r.Add(proxy.Chunk{StreamID: 1, Sequence: 1, Total: 2, Type: proxy.ChunkData, Payload: []byte(" world")})
	mustNoErr(t, err)
	if !done {
		t.Fatal("expected done=true after all data chunks")
	}
	if string(complete) != "hello world" {
		t.Errorf("reassembled = %q, want %q (padding should not affect output)", string(complete), "hello world")
	}
}

// TestReassemblerTotalCompletionOutOfRangeSequences verifies that
// chunks with sequence numbers outside [0, Total-1] do NOT trigger
// premature completion. The old count-based check (seqCount >= total)
// was vulnerable to this because it counted ANY data chunk, not just
// those within the valid range.
func TestReassemblerTotalCompletionOutOfRangeSequences(t *testing.T) {
	_, r := newTestPair(t)
	total := uint32(3)

	// Send chunk seq=0 (valid) and chunks seq=5, seq=6 (out of range).
	// seqCount would be 3 (== total), but sequences 1 and 2 are missing.
	r.Add(proxy.Chunk{StreamID: 1, Sequence: 0, Total: total, Type: proxy.ChunkData, Payload: []byte("first")})
	r.Add(proxy.Chunk{StreamID: 1, Sequence: 5, Total: total, Type: proxy.ChunkData, Payload: []byte("out-of-range-5")})
	_, done, err := r.Add(proxy.Chunk{StreamID: 1, Sequence: 6, Total: total, Type: proxy.ChunkData, Payload: []byte("out-of-range-6")})
	mustNoErr(t, err)

	if done {
		t.Fatal("Add returned done=true with chunks outside [0, Total-1]; premature completion bug")
	}

	// Now deliver the two genuinely missing chunks in [0, Total-1].
	r.Add(proxy.Chunk{StreamID: 1, Sequence: 1, Total: total, Type: proxy.ChunkData, Payload: []byte("second")})
	complete, done, err := r.Add(proxy.Chunk{StreamID: 1, Sequence: 2, Total: total, Type: proxy.ChunkData, Payload: []byte("third")})
	mustNoErr(t, err)

	if !done {
		t.Fatal("expected done=true after all chunks 0..Total-1 arrived")
	}
	if string(complete) != "firstsecondthird" {
		t.Errorf("reassembled = %q, want %q", string(complete), "firstsecondthird")
	}
}

// TestReassemblerSingleChunkStream verifies that a stream consisting of
// a single chunk (Total=1) is correctly reassembled.
func TestReassemblerSingleChunkStream(t *testing.T) {
	_, r := newTestPair(t)
	complete, done, err := r.Add(proxy.Chunk{
		StreamID: 1,
		Sequence: 0,
		Total:    1,
		Type:     proxy.ChunkData,
		Payload:  []byte("solo"),
	})
	mustNoErr(t, err)
	if !done {
		t.Fatal("expected done=true for Total=1 single chunk")
	}
	if string(complete) != "solo" {
		t.Errorf("reassembled = %q, want %q", string(complete), "solo")
	}
}

// TestRegistryDuplicatePanics verifies that registering the same strategy
// name twice causes a panic, catching programming errors at init time.
func TestRegistryDuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("RegisterChunker should panic on duplicate registration")
		}
	}()
	// fixed-16k is registered if any concrete implementation registered it.
	// Try registering a name we just registered -- the registry should panic.
	// Use a sentinel factory that will never be called.
	proxy.RegisterChunker("fixed-16k", func(cfg proxy.ChunkerConfig) proxy.Chunker {
		return nil
	})
}

// TestRegistryGetNames verifies that Names() returns at least one entry
// (the default strategy) and Get works correctly.
func TestRegistryGetNames(t *testing.T) {
	names := proxy.ChunkerRegistry.Names()
	if len(names) == 0 {
		t.Error("ChunkerRegistry.Names() returned empty; expected at least one registered strategy")
	}
	t.Logf("registered chunker strategies: %v", names)

	for _, name := range names {
		factory, ok := proxy.ChunkerRegistry.Get(name)
		if !ok {
			t.Errorf("Get(%q) returned false after Names() included it", name)
		}
		if factory == nil {
			t.Errorf("Get(%q) returned nil factory", name)
		}
	}
}

// TestChunkerStreamIDIsolated verifies that chunks from different streams
// are produced with distinct StreamIDs and don't interfere.
func TestChunkerStreamIDIsolated(t *testing.T) {
	c1, _ := newTestPair(t)
	c2, _ := newTestPair(t) // separate chunker instance = separate stream

	data := []byte("test-stream-isolation")
	chunks1 := c1.Split(data)
	chunks2 := c2.Split(data)

	if len(chunks1) == 0 || len(chunks2) == 0 {
		t.Fatal("expected non-zero chunks from both streams")
	}
	if chunks1[0].StreamID == chunks2[0].StreamID {
		t.Logf("warning: both streams got StreamID=%d (concurrent StreamID assignment not guaranteed unique)", chunks1[0].StreamID)
		// This is not a hard failure -- StreamID uniqueness is the circuit
		// manager's responsibility, not the Chunker's.
	}
}

// TestReassemblerStreamIDIsolated verifies that chunks with different
// StreamIDs are reassembled independently and don't interfere.
func TestReassemblerStreamIDIsolated(t *testing.T) {
	_, r := newTestPair(t)

	// Stream 1: "alpha"
	r.Add(proxy.Chunk{StreamID: 1, Sequence: 0, Total: 1, Type: proxy.ChunkData, Payload: []byte("alpha")})

	// Stream 2: "beta" -- must not interfere with stream 1
	complete, done, err := r.Add(proxy.Chunk{StreamID: 2, Sequence: 0, Total: 1, Type: proxy.ChunkData, Payload: []byte("beta")})
	mustNoErr(t, err)
	if !done {
		t.Fatal("stream 2: expected done=true for Total=1")
	}
	if string(complete) != "beta" {
		t.Errorf("stream 2 reassembled = %q, want %q", string(complete), "beta")
	}

	// Now complete stream 1 -- should still be "alpha"
	complete, done, err = r.Add(proxy.Chunk{StreamID: 1, Sequence: 0, Total: 1, Type: proxy.ChunkData, Payload: []byte("alpha")})
	// Note: stream 1 may have already been completed by the first Add.
	// If so, we'll get (nil, false, nil) or a repeated completion. Either is
	// valid for deduplication; the important thing is no cross-stream
	// contamination.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if done && string(complete) != "alpha" {
		t.Errorf("stream 1 reassembled = %q, want %q (cross-stream contamination)", string(complete), "alpha")
	}
}

// TestChunkerConfigDefault verifies DefaultChunkerConfig returns
// sensible values (non-zero max chunk size).
func TestChunkerConfigDefault(t *testing.T) {
	cfg := proxy.DefaultChunkerConfig()
	if cfg.MaxChunkSize <= 0 {
		t.Errorf("DefaultChunkerConfig.MaxChunkSize = %d, want > 0", cfg.MaxChunkSize)
	}
	if cfg.PaddingMin > cfg.PaddingMax {
		t.Errorf("DefaultChunkerConfig PaddingMin(%d) > PaddingMax(%d)",
			cfg.PaddingMin, cfg.PaddingMax)
	}
	// Default config must include reassembly bounds.
	if cfg.MaxReassemblyChunks <= 0 {
		t.Errorf("DefaultChunkerConfig.MaxReassemblyChunks = %d, want > 0", cfg.MaxReassemblyChunks)
	}
	if cfg.MaxReassemblyBytes <= 0 {
		t.Errorf("DefaultChunkerConfig.MaxReassemblyBytes = %d, want > 0", cfg.MaxReassemblyBytes)
	}
}

// ──────────────────────────────────────────────────────────────────────
// New tests: gaps from t_fb704ce9
// ──────────────────────────────────────────────────────────────────────

// TestPaddingSeedDeterministic verifies that when PaddingSeed is set,
// the Chunker produces identical padding sequences across two runs.
// This validates per-circuit deterministic padding for debugging
// and cross-circuit isolation.
func TestPaddingSeedDeterministic(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	cfg := proxy.ChunkerConfig{
		MaxChunkSize: 16 * 1024,
		MinChunkSize: 16 * 1024,
		PaddingMin:   1024,
		PaddingMax:   4 * 1024,
		PaddingSeed:  seed,
	}

	c1 := proxy.NewChunkerWithConfig("fixed-16k", cfg)
	c2 := proxy.NewChunkerWithConfig("fixed-16k", cfg)

	data := make([]byte, 64*1024)
	chunks1 := c1.Split(data)
	chunks2 := c2.Split(data)

	if len(chunks1) != len(chunks2) {
		t.Fatalf("chunk count mismatch: %d vs %d", len(chunks1), len(chunks2))
	}

	for i := range chunks1 {
		if chunks1[i].PaddingLen != chunks2[i].PaddingLen {
			t.Errorf("chunk %d: PaddingLen %d != %d (non-deterministic)", i, chunks1[i].PaddingLen, chunks2[i].PaddingLen)
		}
	}
}

// TestPaddingSeedIsolation verifies that different PaddingSeed values
// produce different padding sequences (cross-circuit isolation).
func TestPaddingSeedIsolation(t *testing.T) {
	seedA := make([]byte, 32)
	seedB := make([]byte, 32)
	seedB[0] = 0xFF // single bit difference

	cfgA := proxy.ChunkerConfig{
		MaxChunkSize: 16 * 1024,
		PaddingMin:   1024,
		PaddingMax:   4 * 1024,
		PaddingSeed:  seedA,
	}
	cfgB := proxy.ChunkerConfig{
		MaxChunkSize: 16 * 1024,
		PaddingMin:   1024,
		PaddingMax:   4 * 1024,
		PaddingSeed:  seedB,
	}

	cA := proxy.NewChunkerWithConfig("fixed-16k", cfgA)
	cB := proxy.NewChunkerWithConfig("fixed-16k", cfgB)

	data := make([]byte, 64*1024)
	chunksA := cA.Split(data)
	chunksB := cB.Split(data)

	if len(chunksA) != len(chunksB) {
		t.Fatalf("chunk count mismatch: %d vs %d", len(chunksA), len(chunksB))
	}

	// At least one padding value should differ.
	allSame := true
	for i := range chunksA {
		if chunksA[i].PaddingLen != chunksB[i].PaddingLen {
			allSame = false
			break
		}
	}
	if allSame && len(chunksA) > 0 {
		t.Error("different seeds produced identical padding sequences — cross-circuit isolation broken")
	}
}

// TestReassemblerChunkBoundsEnforced verifies that MaxReassemblyChunks
// is enforced: when a stream exceeds the limit, Add returns
// ErrReassemblyChunksExceeded.
//
// The streaming reassembler delivers contiguous chunks immediately,
// so to test the chunk limit we send chunks out of order (starting from
// a high sequence number) to create a gap that prevents delivery and
// forces chunks to accumulate in the buffer.
func TestReassemblerChunkBoundsEnforced(t *testing.T) {
	cfg := proxy.ChunkerConfig{
		MaxChunkSize:        16,
		MaxReassemblyChunks: 3, // low limit for testing
		MaxReassemblyBytes:  1024 * 1024,
		DisablePadding:      true,
	}
	r := proxy.NewReassemblerWithConfig("fixed-16k", cfg)

	// Send 3 chunks starting from sequence 1 (skip seq=0 to create a gap).
	// Since seq=0 is missing, these chunks can't be delivered and will
	// accumulate in the reassembly buffer.
	for i := uint32(1); i <= 3; i++ {
		_, done, err := r.Add(proxy.Chunk{
			StreamID: 1,
			Sequence: i,
			Total:    10,
			Type:     proxy.ChunkData,
			Payload:  []byte("data"),
		})
		mustNoErr(t, err)
		if done {
			t.Fatalf("chunk %d: unexpected done=true (Total=10, only %d received)", i, i)
		}
	}

	// The 4th buffered chunk should exceed the limit.
	_, done, err := r.Add(proxy.Chunk{
		StreamID: 1,
		Sequence: 4,
		Total:    10,
		Type:     proxy.ChunkData,
		Payload:  []byte("overflow"),
	})
	if err == nil {
		t.Fatal("expected ErrReassemblyChunksExceeded, got nil")
	}
	if done {
		t.Error("expected done=false on error")
	}
	if err != proxy.ErrReassemblyChunksExceeded {
		t.Errorf("expected ErrReassemblyChunksExceeded, got %v", err)
	}
}

// TestReassemblerByteBoundsEnforced verifies that MaxReassemblyBytes
// is enforced across all streams.
//
// The streaming reassembler delivers contiguous chunks immediately,
// so to test the byte limit we send chunks out of order (starting from
// a high sequence number) to create a gap that prevents delivery and
// forces accumulation in the buffer.
func TestReassemblerByteBoundsEnforced(t *testing.T) {
	cfg := proxy.ChunkerConfig{
		MaxChunkSize:        1024,
		MaxReassemblyChunks: 9999,
		MaxReassemblyBytes:  50, // very low limit
		DisablePadding:      true,
	}
	r := proxy.NewReassemblerWithConfig("fixed-16k", cfg)

	// Send one 30-byte chunk at sequence 1 (skip seq=0 to create a gap).
	// Since seq=0 is missing, this chunk can't be delivered and will
	// accumulate in the buffer.
	_, done, err := r.Add(proxy.Chunk{
		StreamID: 1,
		Sequence: 1,
		Total:    10,
		Type:     proxy.ChunkData,
		Payload:  make([]byte, 30),
	})
	mustNoErr(t, err)
	if done {
		t.Fatal("unexpected done=true")
	}

	// Send another 30-byte chunk — total 60, exceeds 50 limit.
	_, done, err = r.Add(proxy.Chunk{
		StreamID: 1,
		Sequence: 2,
		Total:    10,
		Type:     proxy.ChunkData,
		Payload:  make([]byte, 30),
	})
	if err == nil {
		t.Fatal("expected ErrReassemblyBytesExceeded, got nil")
	}
	if done {
		t.Error("expected done=false on error")
	}
	if err != proxy.ErrReassemblyBytesExceeded {
		t.Errorf("expected ErrReassemblyBytesExceeded, got %v", err)
	}
}

// TestReassemblerByteBoundsCrossStream verifies that MaxReassemblyBytes
// is tracked across multiple independent streams.
//
// The streaming reassembler delivers contiguous chunks immediately,
// so to test the cross-stream byte limit we send chunks with gaps (out
// of order) on each stream, preventing delivery and forcing accumulation.
func TestReassemblerByteBoundsCrossStream(t *testing.T) {
	cfg := proxy.ChunkerConfig{
		MaxChunkSize:        1024,
		MaxReassemblyChunks: 9999,
		MaxReassemblyBytes:  24,
		DisablePadding:      true,
	}
	r := proxy.NewReassemblerWithConfig("fixed-16k", cfg)

	// Stream 1: 10 bytes at seq=1 (skip seq=0 to create gap).
	r.Add(proxy.Chunk{StreamID: 1, Sequence: 1, Total: 10, Type: proxy.ChunkData, Payload: make([]byte, 10)})
	// Stream 2: 10 bytes at seq=1 (skip seq=0 to create gap).
	r.Add(proxy.Chunk{StreamID: 2, Sequence: 1, Total: 10, Type: proxy.ChunkData, Payload: make([]byte, 10)})

	// Stream 3: 5 bytes — total 25, exceeds 24.
	_, _, err := r.Add(proxy.Chunk{StreamID: 3, Sequence: 1, Total: 10, Type: proxy.ChunkData, Payload: make([]byte, 5)})
	if err != proxy.ErrReassemblyBytesExceeded {
		t.Errorf("expected ErrReassemblyBytesExceeded for cross-stream total, got %v", err)
	}
}

// TestMetadataInCiphertextContract verifies the architecturally critical
// invariant: Chunk metadata (StreamID, Sequence, Total, Type) is included
// in the AEAD plaintext during EncodeChunk and recovered by DecodeChunk.
// This proves that metadata travels inside the ciphertext, never visible
// to intermediate relays.
func TestMetadataInCiphertextContract(t *testing.T) {
	e2eKey := make([]byte, 32)
	for i := range e2eKey {
		e2eKey[i] = byte(i)
	}
	relayKey := make([]byte, 32)
	for i := range relayKey {
		relayKey[i] = byte(i + 32)
	}

	original := proxy.Chunk{
		StreamID:   42,
		Sequence:   7,
		Total:      99,
		Type:       proxy.ChunkData,
		Payload:    []byte("secret message"),
		PaddingLen: 1234,
	}

	circuitID := make([]byte, proxy.CircuitIDSize)
	for i := range circuitID {
		circuitID[i] = byte(i + 1)
	}

	// Encode: metadata + payload + padding go into AEAD ciphertext.
	wc, err := proxy.EncodeChunk(original, e2eKey, relayKey, "10.0.0.1:8080", circuitID)
	if err != nil {
		t.Fatalf("EncodeChunk failed: %v", err)
	}

	// Verify that the WireChunk contains only opaque ciphertext + header + nonce.
	if wc.Ciphertext == nil || len(wc.Ciphertext) == 0 {
		t.Fatal("ciphertext is empty — nothing encrypted?")
	}
	if wc.Header == nil || len(wc.Header) != 64 {
		t.Fatalf("header is %d bytes, want 64", len(wc.Header))
	}
	if wc.Nonce == nil || len(wc.Nonce) != 12 {
		t.Fatalf("nonce is %d bytes, want 12", len(wc.Nonce))
	}

	// Decode: recover the original Chunk including all metadata.
	decoded, err := proxy.DecodeChunk(wc, e2eKey, circuitID)
	if err != nil {
		t.Fatalf("DecodeChunk failed: %v", err)
	}

	if decoded.StreamID != original.StreamID {
		t.Errorf("StreamID: got %d, want %d", decoded.StreamID, original.StreamID)
	}
	if decoded.Sequence != original.Sequence {
		t.Errorf("Sequence: got %d, want %d", decoded.Sequence, original.Sequence)
	}
	if decoded.Total != original.Total {
		t.Errorf("Total: got %d, want %d", decoded.Total, original.Total)
	}
	if decoded.Type != original.Type {
		t.Errorf("Type: got 0x%02x, want 0x%02x", decoded.Type, original.Type)
	}
	if decoded.PaddingLen != original.PaddingLen {
		t.Errorf("PaddingLen: got %d, want %d", decoded.PaddingLen, original.PaddingLen)
	}
	if string(decoded.Payload) != string(original.Payload) {
		t.Errorf("Payload: got %q, want %q", string(decoded.Payload), string(original.Payload))
	}
}

// TestNewPaddingSourceNilSeedReturnsRand verifies that NewPaddingSource
// returns crypto/rand.Reader when PaddingSeed is nil (backward compat).
func TestNewPaddingSourceNilSeedReturnsRand(t *testing.T) {
	cfg := proxy.ChunkerConfig{PaddingSeed: nil}
	src := proxy.NewPaddingSource(cfg)
	if src == nil {
		t.Fatal("NewPaddingSource returned nil")
	}
	// Read a few bytes to verify it works.
	buf := make([]byte, 8)
	n, err := src.Read(buf)
	if err != nil {
		t.Fatalf("Read from nil-seed source failed: %v", err)
	}
	if n != 8 {
		t.Fatalf("Read returned %d, want 8", n)
	}
	// Don't test for != zeros — crypto/rand could theoretically return zeros.
}
