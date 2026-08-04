// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file contains tests for the ExitReassembler — the exit-side
// streaming reassembler that keys on chunk sequence/total for correct
// reassembly and handles arbitrary chunk sizes.
//
// Test coverage:
//  1. Streaming delivery: data delivered incrementally as chunks arrive
//  2. Sequence/total keying: correct completion via both paths
//  3. Arbitrary chunk sizes: variable payload sizes work correctly
//  4. Out-of-order reassembly with incremental delivery
//  5. Deduplication in streaming mode
//  6. Bounds enforcement with streaming delivery
//  7. Multi-stream isolation
//  8. NextExpected / HasGap / MissingSequences diagnostics
//  9. Backward compatibility: Add returns full stream on completion
package proxy

import (
	"bytes"
	"testing"
)

// testChunk creates a Chunk with the given parameters for testing.
func testChunk(streamID, seq, total uint32, chunkType ChunkType, payload []byte) Chunk {
	return Chunk{
		StreamID: streamID,
		Sequence: seq,
		Total:    total,
		Type:     chunkType,
		Payload:  payload,
	}
}

// =============================================================================
// Section 1: Streaming Delivery Tests
// =============================================================================

// TestExitReassemblerStreamingDelivery verifies that AddStreaming delivers
// contiguous data incrementally — not all at once on completion.
func TestExitReassemblerStreamingDelivery(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunk 0 — should be delivered immediately (contiguous from 0).
	delivered, done, err := r.AddStreaming(testChunk(1, 0, 0, ChunkData, []byte("hello")))
	if err != nil {
		t.Fatalf("chunk 0: %v", err)
	}
	if done {
		t.Fatal("chunk 0: unexpected done=true (Total=0, streaming mode)")
	}
	if string(delivered) != "hello" {
		t.Errorf("chunk 0: delivered=%q, want %q", string(delivered), "hello")
	}

	// Send chunk 1 — should be delivered immediately (contiguous from 1).
	delivered, done, err = r.AddStreaming(testChunk(1, 1, 0, ChunkData, []byte(" ")))
	if err != nil {
		t.Fatalf("chunk 1: %v", err)
	}
	if done {
		t.Fatal("chunk 1: unexpected done=true")
	}
	if string(delivered) != " " {
		t.Errorf("chunk 1: delivered=%q, want %q", string(delivered), " ")
	}

	// Send StreamEnd — should deliver any remaining data and signal done.
	delivered, done, err = r.AddStreaming(testChunk(1, 2, 0, ChunkStreamEnd, nil))
	if err != nil {
		t.Fatalf("streamend: %v", err)
	}
	if !done {
		t.Fatal("streamend: expected done=true")
	}
	if len(delivered) != 0 {
		t.Errorf("streamend: delivered=%q, want empty (no remaining data)", string(delivered))
	}
}

// TestExitReassemblerStreamingOutOfOrder verifies that out-of-order chunks
// are not delivered until the gap is filled, then delivered incrementally.
func TestExitReassemblerStreamingOutOfOrder(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunk 1 first — should NOT be delivered (gap at seq 0).
	delivered, done, err := r.AddStreaming(testChunk(1, 1, 3, ChunkData, []byte("world")))
	if err != nil {
		t.Fatalf("chunk 1: %v", err)
	}
	if done {
		t.Fatal("chunk 1: unexpected done=true")
	}
	if len(delivered) != 0 {
		t.Errorf("chunk 1: delivered=%q, want empty (gap at seq 0)", string(delivered))
	}

	// Send chunk 0 — should deliver both chunk 0 AND chunk 1 (now contiguous).
	delivered, done, err = r.AddStreaming(testChunk(1, 0, 3, ChunkData, []byte("hello ")))
	if err != nil {
		t.Fatalf("chunk 0: %v", err)
	}
	if done {
		t.Fatal("chunk 0: unexpected done=true (Total=3, only 2 received)")
	}
	if string(delivered) != "hello world" {
		t.Errorf("chunk 0: delivered=%q, want %q", string(delivered), "hello world")
	}

	// Send chunk 2 — should deliver chunk 2 and trigger Total-based completion.
	delivered, done, err = r.AddStreaming(testChunk(1, 2, 3, ChunkData, []byte("!")))
	if err != nil {
		t.Fatalf("chunk 2: %v", err)
	}
	if !done {
		t.Fatal("chunk 2: expected done=true (all 0..2 arrived)")
	}
	if string(delivered) != "!" {
		t.Errorf("chunk 2: delivered=%q, want %q", string(delivered), "!")
	}
}

// =============================================================================
// Section 2: Arbitrary Chunk Size Tests
// =============================================================================

// TestExitReassemblerArbitraryChunkSizes verifies that the reassembler
// handles variable payload sizes correctly — a key future-proofing
// requirement. The reassembler must NOT assume a fixed chunk size.
func TestExitReassemblerArbitraryChunkSizes(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Mix of different payload sizes: 1 byte, 100 bytes, 1 byte, 50KB.
	payloads := [][]byte{
		[]byte("A"),
		bytes.Repeat([]byte("B"), 100),
		[]byte("C"),
		bytes.Repeat([]byte("D"), 50*1024),
	}

	var accumulated []byte
	for i, p := range payloads {
		chunkType := ChunkData
		if i == len(payloads)-1 {
			chunkType = ChunkStreamEnd
		}
		delivered, _, err := r.AddStreaming(testChunk(1, uint32(i), 0, chunkType, p))
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		accumulated = append(accumulated, delivered...)
	}

	// Verify the reassembled data matches.
	expected := bytes.Join(payloads, nil)
	if !bytes.Equal(accumulated, expected) {
		t.Errorf("reassembled data mismatch: got %d bytes, want %d bytes", len(accumulated), len(expected))
	}
}

// TestExitReassemblerSingleByteChunks verifies that 1-byte payloads work.
func TestExitReassemblerSingleByteChunks(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	data := []byte("hello world!")
	var accumulated []byte

	for i, b := range data {
		chunkType := ChunkData
		if i == len(data)-1 {
			chunkType = ChunkStreamEnd
		}
		delivered, _, err := r.AddStreaming(testChunk(1, uint32(i), 0, chunkType, []byte{b}))
		if err != nil {
			t.Fatalf("byte %d: %v", i, err)
		}
		accumulated = append(accumulated, delivered...)
	}

	if string(accumulated) != "hello world!" {
		t.Errorf("reassembled=%q, want %q", string(accumulated), "hello world!")
	}
}

// TestExitReassemblerEmptyPayloadChunk verifies that a data chunk with
// empty payload is handled gracefully (not a crash, not data corruption).
func TestExitReassemblerEmptyPayloadChunk(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Chunk 0 with empty payload — should be delivered (empty, but valid).
	_, _, err := r.AddStreaming(testChunk(1, 0, 0, ChunkData, []byte{}))
	if err != nil {
		t.Fatalf("empty payload chunk: %v", err)
	}

	// Chunk 1 with data.
	delivered, _, err := r.AddStreaming(testChunk(1, 1, 0, ChunkData, []byte("data")))
	if err != nil {
		t.Fatalf("chunk 1: %v", err)
	}
	if string(delivered) != "data" {
		t.Errorf("delivered=%q, want %q", string(delivered), "data")
	}
}

// =============================================================================
// Section 3: Sequence/Total Keying Tests
// =============================================================================

// TestExitReassemblerTotalCompletion verifies Total-based completion:
// when all chunks 0..Total-1 arrive, the stream is complete.
func TestExitReassemblerTotalCompletion(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	data := []string{"one", "two", "three", "four"}
	total := uint32(len(data))

	for i, p := range data {
		delivered, done, err := r.AddStreaming(testChunk(1, uint32(i), total, ChunkData, []byte(p)))
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		if i < len(data)-1 {
			if done {
				t.Fatalf("chunk %d: unexpected done=true", i)
			}
		} else {
			if !done {
				t.Fatal("last chunk: expected done=true")
			}
			if string(delivered) != "four" {
				t.Errorf("last delivered=%q, want %q", string(delivered), "four")
			}
		}
	}
}

// TestExitReassemblerStreamEndCompletion verifies StreamEnd-based completion.
func TestExitReassemblerStreamEndCompletion(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Streaming mode (Total=0).
	r.AddStreaming(testChunk(1, 0, 0, ChunkData, []byte("alpha")))
	r.AddStreaming(testChunk(1, 1, 0, ChunkData, []byte("beta")))

	// StreamEnd — should trigger completion.
	delivered, done, err := r.AddStreaming(testChunk(1, 2, 0, ChunkStreamEnd, nil))
	if err != nil {
		t.Fatalf("streamend: %v", err)
	}
	if !done {
		t.Fatal("expected done=true after StreamEnd")
	}
	if len(delivered) != 0 {
		t.Errorf("streamend delivered=%q, want empty (data already delivered)", string(delivered))
	}
}

// TestExitReassemblerStreamEndWithPayload verifies that a StreamEnd chunk
// carrying a final data payload delivers that payload before completion.
func TestExitReassemblerStreamEndWithPayload(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	r.AddStreaming(testChunk(1, 0, 0, ChunkData, []byte("hello ")))

	// StreamEnd with payload — should deliver the payload.
	delivered, done, err := r.AddStreaming(testChunk(1, 1, 0, ChunkStreamEnd, []byte("world")))
	if err != nil {
		t.Fatalf("streamend with payload: %v", err)
	}
	if !done {
		t.Fatal("expected done=true")
	}
	if string(delivered) != "world" {
		t.Errorf("streamend delivered=%q, want %q", string(delivered), "world")
	}
}

// TestExitReassemblerTotalOutOfRangeSequences verifies that chunks outside
// [0, Total-1] do NOT trigger premature completion.
func TestExitReassemblerTotalOutOfRangeSequences(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	total := uint32(3)

	// Send seq=0 (valid) and seq=5 (out of range).
	r.AddStreaming(testChunk(1, 0, total, ChunkData, []byte("first")))
	_, done, err := r.AddStreaming(testChunk(1, 5, total, ChunkData, []byte("out-of-range")))
	if err != nil {
		t.Fatalf("out-of-range chunk: %v", err)
	}
	if done {
		t.Fatal("unexpected done=true with out-of-range sequences")
	}

	// Send seq=1 and seq=2 — should trigger completion.
	r.AddStreaming(testChunk(1, 1, total, ChunkData, []byte("second")))
	_, done, err = r.AddStreaming(testChunk(1, 2, total, ChunkData, []byte("third")))
	if err != nil {
		t.Fatalf("chunk 2: %v", err)
	}
	if !done {
		t.Fatal("expected done=true after all valid chunks arrived")
	}
}

// =============================================================================
// Section 4: Deduplication Tests
// =============================================================================

// TestExitReassemblerDeduplication verifies that duplicate (StreamID, Sequence)
// pairs are silently ignored in streaming mode.
func TestExitReassemblerDeduplication(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunk 0 — delivered.
	delivered, _, _ := r.AddStreaming(testChunk(1, 0, 2, ChunkData, []byte("hello")))
	if string(delivered) != "hello" {
		t.Errorf("first delivery: %q, want %q", string(delivered), "hello")
	}

	// Send duplicate chunk 0 — should be ignored, no delivery.
	delivered, _, _ = r.AddStreaming(testChunk(1, 0, 2, ChunkData, []byte("DUPLICATE")))
	if len(delivered) != 0 {
		t.Errorf("duplicate delivery: %q, want empty", string(delivered))
	}

	// Send chunk 1 — should deliver and complete.
	delivered, done, _ := r.AddStreaming(testChunk(1, 1, 2, ChunkData, []byte(" world")))
	if !done {
		t.Fatal("expected done=true after all chunks")
	}
	if string(delivered) != " world" {
		t.Errorf("chunk 1 delivery: %q, want %q", string(delivered), " world")
	}
}

// =============================================================================
// Section 5: Bounds Enforcement Tests
// =============================================================================

// TestExitReassemblerChunkBoundsEnforced verifies MaxReassemblyChunks.
func TestExitReassemblerChunkBoundsEnforced(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 3,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send 3 out-of-order chunks (gap at seq 0, so they buffer).
	for i := uint32(1); i <= 3; i++ {
		_, _, err := r.AddStreaming(testChunk(1, i, 10, ChunkData, []byte("x")))
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}

	// 4th buffered chunk should exceed limit.
	_, _, err := r.AddStreaming(testChunk(1, 4, 10, ChunkData, []byte("overflow")))
	if err != ErrReassemblyChunksExceeded {
		t.Errorf("expected ErrReassemblyChunksExceeded, got %v", err)
	}
}

// TestExitReassemblerByteBoundsEnforced verifies MaxReassemblyBytes.
func TestExitReassemblerByteBoundsEnforced(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 9999,
		MaxReassemblyBytes:  50,
	})

	// 30-byte chunk at seq 1 (gap at 0, buffers).
	_, _, err := r.AddStreaming(testChunk(1, 1, 10, ChunkData, make([]byte, 30)))
	if err != nil {
		t.Fatalf("first chunk: %v", err)
	}

	// Another 30-byte chunk — total 60, exceeds 50.
	_, _, err = r.AddStreaming(testChunk(1, 2, 10, ChunkData, make([]byte, 30)))
	if err != ErrReassemblyBytesExceeded {
		t.Errorf("expected ErrReassemblyBytesExceeded, got %v", err)
	}
}

// TestExitReassemblerByteBoundsCrossStream verifies cross-stream byte tracking.
func TestExitReassemblerByteBoundsCrossStream(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 9999,
		MaxReassemblyBytes:  24,
	})

	r.AddStreaming(testChunk(1, 1, 10, ChunkData, make([]byte, 10)))
	r.AddStreaming(testChunk(2, 1, 10, ChunkData, make([]byte, 10)))

	_, _, err := r.AddStreaming(testChunk(3, 1, 10, ChunkData, make([]byte, 5)))
	if err != ErrReassemblyBytesExceeded {
		t.Errorf("expected ErrReassemblyBytesExceeded, got %v", err)
	}
}

// =============================================================================
// Section 6: Multi-Stream Isolation Tests
// =============================================================================

// TestExitReassemblerMultiStreamIsolation verifies that chunks from different
// streams are reassembled independently.
func TestExitReassemblerMultiStreamIsolation(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Interleave chunks from two streams.
	d1, _, _ := r.AddStreaming(testChunk(1, 0, 2, ChunkData, []byte("hello")))
	d2, _, _ := r.AddStreaming(testChunk(2, 0, 2, ChunkData, []byte("world")))

	if string(d1) != "hello" {
		t.Errorf("stream 1: %q, want %q", string(d1), "hello")
	}
	if string(d2) != "world" {
		t.Errorf("stream 2: %q, want %q", string(d2), "world")
	}

	// Complete both streams.
	d1, done1, _ := r.AddStreaming(testChunk(1, 1, 2, ChunkData, []byte(" stream1")))
	d2, done2, _ := r.AddStreaming(testChunk(2, 1, 2, ChunkData, []byte(" stream2")))

	if !done1 {
		t.Error("stream 1: expected done=true")
	}
	if !done2 {
		t.Error("stream 2: expected done=true")
	}
	if string(d1) != " stream1" {
		t.Errorf("stream 1 final: %q", string(d1))
	}
	if string(d2) != " stream2" {
		t.Errorf("stream 2 final: %q", string(d2))
	}
}

// =============================================================================
// Section 7: Diagnostic Methods Tests
// =============================================================================

// TestExitReassemblerNextExpected verifies the NextExpected diagnostic.
func TestExitReassemblerNextExpected(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// No stream yet.
	_, ok := r.NextExpected(1)
	if ok {
		t.Error("NextExpected should return false for non-existent stream")
	}

	// Send chunk 0 — nextExpected should be 1.
	r.AddStreaming(testChunk(1, 0, 0, ChunkData, []byte("a")))
	next, ok := r.NextExpected(1)
	if !ok {
		t.Fatal("NextExpected should return true after chunk 0")
	}
	if next != 1 {
		t.Errorf("NextExpected=%d, want 1", next)
	}

	// Send chunk 2 (gap) — nextExpected should still be 1.
	r.AddStreaming(testChunk(1, 2, 0, ChunkData, []byte("c")))
	next, _ = r.NextExpected(1)
	if next != 1 {
		t.Errorf("NextExpected=%d, want 1 (gap not filled)", next)
	}

	// Send chunk 1 — nextExpected should advance to 3.
	r.AddStreaming(testChunk(1, 1, 0, ChunkData, []byte("b")))
	next, _ = r.NextExpected(1)
	if next != 3 {
		t.Errorf("NextExpected=%d, want 3 (gap filled)", next)
	}
}

// TestExitReassemblerHasGap verifies the HasGap diagnostic.
func TestExitReassemblerHasGap(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// No stream — no gap.
	if r.HasGap(1) {
		t.Error("HasGap should be false for non-existent stream")
	}

	// Send chunk 0 — no gap (contiguous).
	r.AddStreaming(testChunk(1, 0, 0, ChunkData, []byte("a")))
	if r.HasGap(1) {
		t.Error("HasGap should be false after in-order chunk")
	}

	// Send chunk 2 — gap exists.
	r.AddStreaming(testChunk(1, 2, 0, ChunkData, []byte("c")))
	if !r.HasGap(1) {
		t.Error("HasGap should be true after out-of-order chunk")
	}

	// Send chunk 1 — gap filled.
	r.AddStreaming(testChunk(1, 1, 0, ChunkData, []byte("b")))
	if r.HasGap(1) {
		t.Error("HasGap should be false after gap filled")
	}
}

// TestExitReassemblerMissingSequences verifies the MissingSequences diagnostic.
func TestExitReassemblerMissingSequences(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunk 0 and chunk 4 — gaps at 1, 2, 3.
	r.AddStreaming(testChunk(1, 0, 10, ChunkData, []byte("a")))
	r.AddStreaming(testChunk(1, 4, 10, ChunkData, []byte("e")))

	missing := r.MissingSequences(1)
	if len(missing) != 3 {
		t.Fatalf("missing sequences: got %d, want 3", len(missing))
	}
	expected := []uint32{1, 2, 3}
	for i, m := range missing {
		if m != expected[i] {
			t.Errorf("missing[%d]=%d, want %d", i, m, expected[i])
		}
	}
}

// =============================================================================
// Section 8: Backward Compatibility Tests
// =============================================================================

// TestExitReassemblerAddReturnsFullStream verifies that the Add method
// (Reassembler interface) returns the FULL reassembled stream on completion,
// not just incremental data.
func TestExitReassemblerAddReturnsFullStream(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunks in order — Add should accumulate and return full stream on done.
	r.Add(testChunk(1, 0, 3, ChunkData, []byte("hello ")))
	r.Add(testChunk(1, 1, 3, ChunkData, []byte("world")))
	complete, done, err := r.Add(testChunk(1, 2, 3, ChunkData, []byte("!")))
	if err != nil {
		t.Fatalf("chunk 2: %v", err)
	}
	if !done {
		t.Fatal("expected done=true")
	}
	if string(complete) != "hello world!" {
		t.Errorf("complete=%q, want %q", string(complete), "hello world!")
	}
}

// TestExitReassemblerAddWithStreamEnd verifies Add + StreamEnd.
func TestExitReassemblerAddWithStreamEnd(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	r.Add(testChunk(1, 0, 0, ChunkData, []byte("alpha")))
	r.Add(testChunk(1, 1, 0, ChunkData, []byte("beta")))
	complete, done, err := r.Add(testChunk(1, 2, 0, ChunkStreamEnd, nil))
	if err != nil {
		t.Fatalf("streamend: %v", err)
	}
	if !done {
		t.Fatal("expected done=true")
	}
	if string(complete) != "alphabeta" {
		t.Errorf("complete=%q, want %q", string(complete), "alphabeta")
	}
}

// TestExitReassemblerRegistry verifies that "exit-streaming" is registered.
func TestExitReassemblerRegistry(t *testing.T) {
	r := NewReassembler("exit-streaming")
	if r == nil {
		t.Fatal("NewReassembler(\"exit-streaming\") returned nil")
	}

	// Verify it works as a Reassembler.
	_, done, err := r.Add(Chunk{
		StreamID: 1,
		Sequence: 0,
		Total:    1,
		Type:     ChunkData,
		Payload:  []byte("solo"),
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !done {
		t.Fatal("expected done=true for Total=1")
	}
}

// =============================================================================
// Section 9: Large Data / Stress Tests
// =============================================================================

// TestExitReassemblerLargeData verifies reassembly of a large data stream
// with many small chunks.
func TestExitReassemblerLargeData(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 10000,
		MaxReassemblyBytes:  10 * 1024 * 1024,
	})

	// 1000 chunks of 100 bytes each = 100KB.
	chunkData := bytes.Repeat([]byte("abcdefghij"), 10) // 100 bytes

	for i := 0; i < 1000; i++ {
		chunkType := ChunkData
		if i == 999 {
			chunkType = ChunkStreamEnd
		}
		_, _, err := r.AddStreaming(testChunk(1, uint32(i), 0, chunkType, chunkData))
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}
}

// TestExitReassemblerMemoryFreedAfterDelivery verifies that delivered chunks
// are removed from the buffer, freeing memory.
func TestExitReassemblerMemoryFreedAfterDelivery(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 10000,
		MaxReassemblyBytes:  100 * 1024 * 1024,
	})

	// Send 100 in-order chunks.
	for i := 0; i < 100; i++ {
		r.AddStreaming(testChunk(1, uint32(i), 0, ChunkData, make([]byte, 1024)))
	}

	// After delivery, buffered bytes should be 0 (all delivered).
	if r.BufferedBytes() != 0 {
		t.Errorf("BufferedBytes=%d, want 0 (all chunks delivered)", r.BufferedBytes())
	}
}

// TestExitReassemblerPaddingChunksIgnored verifies padding chunks are ignored.
func TestExitReassemblerPaddingChunksIgnored(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	r.AddStreaming(testChunk(1, 0, 2, ChunkData, []byte("hello")))
	// Padding chunk — should be ignored.
	r.AddStreaming(testChunk(1, 999, 0, ChunkPadding, []byte("padding")))

	delivered, done, _ := r.AddStreaming(testChunk(1, 1, 2, ChunkData, []byte(" world")))
	if !done {
		t.Fatal("expected done=true")
	}
	if string(delivered) != " world" {
		t.Errorf("delivered=%q, want %q", string(delivered), " world")
	}
}

// TestExitReassemblerLateChunkAfterCompletion verifies that chunks arriving
// after stream completion are silently ignored.
func TestExitReassemblerLateChunkAfterCompletion(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Complete the stream.
	r.AddStreaming(testChunk(1, 0, 1, ChunkData, []byte("done")))
	if r.ActiveStreamCount() != 0 {
		t.Errorf("ActiveStreamCount=%d after completion, want 0", r.ActiveStreamCount())
	}

	// Late chunk — should be silently ignored, no error.
	_, _, err := r.AddStreaming(testChunk(1, 1, 0, ChunkData, []byte("late")))
	if err != nil {
		t.Errorf("late chunk: unexpected error: %v", err)
	}
}

// TestExitReassemblerFlushRemainingPreservesGlobalBytes verifies the gap fix
// for the flushRemaining bug: previously flushRemaining zeroed r.totalBytes
// instead of subtracting the stream's bytes, corrupting the global byte
// counter when multiple streams were active. This test creates two streams,
// completes one via StreamEnd (triggering flushRemaining), and verifies
// the other stream's bytes are still correctly tracked.
func TestExitReassemblerFlushRemainingPreservesGlobalBytes(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Stream 1: send two out-of-order chunks (not contiguous from 0,
	// so they stay buffered).
	r.AddStreaming(testChunk(1, 1, 0, ChunkData, make([]byte, 100)))
	r.AddStreaming(testChunk(1, 2, 0, ChunkData, make([]byte, 100)))

	// Stream 2: send two out-of-order chunks.
	r.AddStreaming(testChunk(2, 1, 0, ChunkData, make([]byte, 100)))
	r.AddStreaming(testChunk(2, 2, 0, ChunkData, make([]byte, 100)))

	// At this point, 4 chunks are buffered = 400 bytes.
	if r.BufferedBytes() != 400 {
		t.Fatalf("BufferedBytes=%d, want 400 (before flush)", r.BufferedBytes())
	}

	// Complete stream 1 with ChunkStreamEnd. This triggers flushRemaining
	// which delivers the buffered chunks for stream 1 and cleans up.
	// The bug was that flushRemaining zeroed r.totalBytes, which would
	// lose the 200 bytes still buffered for stream 2.
	r.AddStreaming(testChunk(1, 0, 0, ChunkStreamEnd, nil))

	// After stream 1 completes, only stream 2's 200 bytes should remain.
	if r.BufferedBytes() != 200 {
		t.Errorf("BufferedBytes=%d after flush, want 200 (stream 2 bytes preserved)",
			r.BufferedBytes())
	}
}

// TestEncodeChunkPaddingBytesInCiphertext verifies the encryptedMetadata gap
// fix: actual random padding bytes are now included inside the AEAD
// ciphertext, making PaddingLen self-verifying. The receiver reads exactly
// PaddingLen bytes from the decrypted plaintext.
func TestEncodeChunkPaddingBytesInCiphertext(t *testing.T) {
	e2eKey := make([]byte, KeySize)
	relayKey := make([]byte, KeySize)
	circuitID, _ := GenerateCircuitID()

	chunk := Chunk{
		StreamID:   1,
		Sequence:   0,
		Total:      1,
		Type:       ChunkData,
		Payload:    []byte("test payload"),
		PaddingLen: 256,
	}

	wc, err := EncodeChunk(chunk, e2eKey, relayKey, "10.0.0.1", circuitID)
	if err != nil {
		t.Fatalf("EncodeChunk: %v", err)
	}

	// The ciphertext must be larger than just metadata + payload because
	// it now contains the 256 padding bytes + 16-byte AEAD tag.
	// Metadata: 35 bytes, Payload: 12 bytes, Padding: 256 bytes, Tag: 16 bytes
	minCiphertextLen := 35 + 12 + 256 + 16
	if len(wc.Ciphertext) < minCiphertextLen {
		t.Errorf("ciphertext length = %d, want >= %d (must include padding bytes)",
			len(wc.Ciphertext), minCiphertextLen)
	}

	// Decode should succeed and recover the original PaddingLen.
	decoded, err := DecodeChunk(wc, e2eKey, circuitID)
	if err != nil {
		t.Fatalf("DecodeChunk: %v", err)
	}

	if decoded.PaddingLen != chunk.PaddingLen {
		t.Errorf("decoded PaddingLen = %d, want %d", decoded.PaddingLen, chunk.PaddingLen)
	}
	if !bytesEqual(decoded.Payload, chunk.Payload) {
		t.Errorf("payload mismatch after round-trip")
	}
}

// TestEncodeChunkZeroPaddingWorks verifies that a chunk with PaddingLen=0
// still works correctly after the wire format change.
func TestEncodeChunkZeroPaddingWorks(t *testing.T) {
	e2eKey := make([]byte, KeySize)
	relayKey := make([]byte, KeySize)
	circuitID, _ := GenerateCircuitID()

	chunk := Chunk{
		StreamID:   1,
		Sequence:   0,
		Total:      1,
		Type:       ChunkData,
		Payload:    []byte("no padding"),
		PaddingLen: 0,
	}

	wc, err := EncodeChunk(chunk, e2eKey, relayKey, "10.0.0.1", circuitID)
	if err != nil {
		t.Fatalf("EncodeChunk: %v", err)
	}

	decoded, err := DecodeChunk(wc, e2eKey, circuitID)
	if err != nil {
		t.Fatalf("DecodeChunk: %v", err)
	}

	if decoded.PaddingLen != 0 {
		t.Errorf("PaddingLen = %d, want 0", decoded.PaddingLen)
	}
	if string(decoded.Payload) != "no padding" {
		t.Errorf("Payload = %q, want %q", string(decoded.Payload), "no padding")
	}
}
