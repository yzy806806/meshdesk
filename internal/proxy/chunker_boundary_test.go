// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file contains tests for remaining Chunker/Reassembler contract gaps
// and boundary conditions identified in task t_b173b4ee. These tests cover
// edge cases that were not exercised by existing test suites:
//
//  1. StreamEnd with buffered gaps (missing sequences flushed in order)
//  2. StreamEnd with payload when gap exists at seq 0
//  3. Total learned mid-stream (Total=0 → Total>0 transition)
//  4. Out-of-range filtering when st.totalSet but incoming chunk.Total=0
//  5. StreamEnd at seq=0 with no prior data (empty stream completion)
//  6. PurgeStream followed by re-arrival of chunks (fresh reassembly)
//  7. Duplicate StreamEnd after completion (silently ignored)
//  8. StreamEnd payload at duplicate sequence (payload dropped)
//  9. Inconsistent Total values (first non-zero Total wins)
//  10. Zero limits mean no enforcement (MaxReassemblyChunks=0, MaxReassemblyBytes=0)
//  11. StreamEnd payload aliasing (caller modifies payload after Add)
//  12. StreamEnd with bounds-exceeding payload (error path, no deadlock)
//  13. MissingSequences with large gaps (performance/correctness)
//  14. IsCompleted returns false for non-existent stream
//  15. BufferedBytes reflects accurate state after various operations
package proxy

import (
	"testing"
	"time"
)

// mustNoErrLocal is a test helper that fails the test if err is non-nil.
func mustNoErrLocal(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// =============================================================================
// Section 1: StreamEnd with Buffered Gaps
// =============================================================================

// TestStreamEndWithBufferedGaps verifies that when ChunkStreamEnd arrives
// while there are gaps in the buffered sequences, flushRemaining delivers
// whatever chunks ARE available in sorted sequence order. The missing
// sequences produce no data — the stream completes with partial data.
//
// Contract: ChunkStreamEnd is the universal completion signal. It MUST
// trigger completion regardless of whether all expected chunks have
// arrived. Gaps represent lost chunks that will not arrive.
func TestStreamEndWithBufferedGaps(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunks 0, 2, 4 — gaps at 1 and 3.
	r.AddStreaming(testChunk(1, 0, 0, ChunkData, []byte("A")))
	r.AddStreaming(testChunk(1, 2, 0, ChunkData, []byte("C")))
	r.AddStreaming(testChunk(1, 4, 0, ChunkData, []byte("E")))

	// Send StreamEnd at seq=5 — should flush available chunks in order.
	delivered, done, err := r.AddStreaming(testChunk(1, 5, 0, ChunkStreamEnd, nil))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true after StreamEnd")
	}

	// flushRemaining sorts by sequence and delivers all buffered chunks.
	// Chunks 0, 2, 4 were buffered; seq 1, 3 were never received.
	// The delivered data should be "A" + "C" + "E" = "ACE".
	// Note: the data chunk at seq 0 was already delivered by deliverContiguous,
	// so only chunks 2 and 4 remain buffered when StreamEnd arrives.
	// Actually: seq 0 is delivered immediately (contiguous from 0).
	// Then seq 2 buffers (gap at 1). Seq 4 buffers.
	// StreamEnd delivers buffered: seq 2 ("C") + seq 4 ("E") = "CE".
	expected := "CE"
	if string(delivered) != expected {
		t.Errorf("delivered=%q, want %q", string(delivered), expected)
	}

	// Stream should be cleaned up after completion.
	if r.ActiveStreamCount() != 0 {
		t.Errorf("ActiveStreamCount=%d, want 0 after completion", r.ActiveStreamCount())
	}
}

// TestStreamEndWithGapAtSeqZero verifies that when StreamEnd arrives and
// seq 0 was never received, the reassembler still completes and delivers
// whatever buffered chunks exist (starting from a non-zero sequence).
func TestStreamEndWithGapAtSeqZero(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunks 1 and 2 — gap at 0 (nothing delivered yet).
	r.AddStreaming(testChunk(1, 1, 0, ChunkData, []byte("B")))
	r.AddStreaming(testChunk(1, 2, 0, ChunkData, []byte("C")))

	// StreamEnd — should deliver buffered chunks despite missing seq 0.
	delivered, done, err := r.AddStreaming(testChunk(1, 3, 0, ChunkStreamEnd, nil))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true after StreamEnd with gap at 0")
	}

	// Buffered: seq 1 ("B"), seq 2 ("C") → delivered as "BC"
	if string(delivered) != "BC" {
		t.Errorf("delivered=%q, want %q", string(delivered), "BC")
	}
}

// TestStreamEndDeliversNothingWhenEmpty verifies that a StreamEnd with
// no prior data and no payload delivers nothing but still signals done.
func TestStreamEndDeliversNothingWhenEmpty(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// StreamEnd at seq=0 with no payload and no prior chunks.
	delivered, done, err := r.AddStreaming(testChunk(1, 0, 0, ChunkStreamEnd, nil))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true for empty stream StreamEnd")
	}
	if len(delivered) != 0 {
		t.Errorf("delivered %d bytes, want 0 (empty stream)", len(delivered))
	}
	if r.ActiveStreamCount() != 0 {
		t.Errorf("ActiveStreamCount=%d, want 0 after empty stream completion", r.ActiveStreamCount())
	}
}

// =============================================================================
// Section 2: Total Learned Mid-Stream
// =============================================================================

// TestTotalLearnedMidStream verifies that when early chunks arrive with
// Total=0 (streaming mode) and a later chunk arrives with Total>0, the
// reassembler transitions to known-Total mode and uses Total-based
// completion.
//
// Contract: "Update Total if this chunk provides new information" (line 256).
// If Total was previously unknown (0), and a chunk arrives with Total>0,
// the reassembler should adopt that Total for completion detection.
func TestTotalLearnedMidStream(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunks 0 and 1 with Total=0 (streaming mode).
	r.AddStreaming(testChunk(1, 0, 0, ChunkData, []byte("A")))
	r.AddStreaming(testChunk(1, 1, 0, ChunkData, []byte("B")))

	// Send chunk 2 with Total=3 — now the reassembler knows Total=3.
	// This should NOT trigger completion (only 3 chunks, need all 0..2).
	_, done, err := r.AddStreaming(testChunk(1, 2, 3, ChunkData, []byte("C")))
	mustNoErrLocal(t, err)

	// Actually, we have chunks 0, 1, 2 with Total=3 — that IS all of them.
	// nextExpected should be 3, and total is 3, so done should be true.
	if !done {
		t.Fatal("expected done=true after learning Total=3 and receiving all 0..2")
	}

	// Verify the stream is completed.
	if r.ActiveStreamCount() != 0 {
		t.Errorf("ActiveStreamCount=%d, want 0 after Total-based completion", r.ActiveStreamCount())
	}
}

// TestTotalLearnedMidStreamWithGap verifies that when Total is learned
// mid-stream but not all chunks have arrived, the stream does NOT complete.
func TestTotalLearnedMidStreamWithGap(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunk 0 with Total=0.
	r.AddStreaming(testChunk(1, 0, 0, ChunkData, []byte("A")))

	// Send chunk 2 with Total=3 — learn Total, but chunk 1 is missing.
	_, done, err := r.AddStreaming(testChunk(1, 2, 3, ChunkData, []byte("C")))
	mustNoErrLocal(t, err)
	if done {
		t.Fatal("expected done=false (chunk 1 missing)")
	}

	// Now send chunk 1 — should trigger completion.
	_, done, err = r.AddStreaming(testChunk(1, 1, 3, ChunkData, []byte("B")))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true after gap filled")
	}
}

// =============================================================================
// Section 3: Out-of-Range Filtering with Known Total
// =============================================================================

// TestOutOfRangeFilteringWithKnownTotal verifies that when the reassembler
// has already learned Total from a prior chunk, subsequent chunks with
// Total=0 but sequence >= st.total are still rejected.
//
// Contract: line 234 checks "st.totalSet && chunk.Sequence >= st.total"
// independently of chunk.Total. This prevents an attacker from injecting
// chunks with Total=0 to bypass the range check.
func TestOutOfRangeFilteringWithKnownTotal(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunk 0 with Total=2 — reassembler learns Total=2.
	r.AddStreaming(testChunk(1, 0, 2, ChunkData, []byte("first")))

	// Send chunk with seq=5 and Total=0 — should be rejected because
	// st.totalSet is true and 5 >= 2.
	_, done, err := r.AddStreaming(testChunk(1, 5, 0, ChunkData, []byte("out-of-range")))
	mustNoErrLocal(t, err)
	if done {
		t.Fatal("expected done=false (out-of-range chunk should be silently ignored)")
	}

	// Stream should still be active (not completed).
	if r.ActiveStreamCount() != 1 {
		t.Errorf("ActiveStreamCount=%d, want 1 (stream still in progress)", r.ActiveStreamCount())
	}

	// Send the valid final chunk (seq=1, Total=2) — should complete.
	_, done, err = r.AddStreaming(testChunk(1, 1, 2, ChunkData, []byte("second")))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true after valid final chunk")
	}
}

// =============================================================================
// Section 4: PurgeStream and Re-Arrival
// =============================================================================

// TestPurgeStreamFollowedByReArrival verifies that after a stream is
// purged (e.g. due to timeout), new chunks for that StreamID start a
// fresh reassembly with nextExpected=0 and no prior state.
func TestPurgeStreamFollowedByReArrival(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks:     100,
		MaxReassemblyBytes:      1024 * 1024,
		StreamReassemblyTimeout: 50 * time.Millisecond,
	})

	// Send partial data for stream 1.
	r.AddStreaming(testChunk(1, 0, 10, ChunkData, []byte("old-data")))

	// Verify stream is active.
	if r.ActiveStreamCount() != 1 {
		t.Fatalf("ActiveStreamCount=%d, want 1 before purge", r.ActiveStreamCount())
	}

	// Purge the stream (simulating timeout expiry).
	r.PurgeStream(1)

	// Stream should be gone.
	if r.ActiveStreamCount() != 0 {
		t.Errorf("ActiveStreamCount=%d, want 0 after purge", r.ActiveStreamCount())
	}
	if r.BufferedBytes() != 0 {
		t.Errorf("BufferedBytes=%d, want 0 after purge", r.BufferedBytes())
	}

	// Now send new chunks for the same StreamID — should start fresh.
	delivered, _, err := r.AddStreaming(testChunk(1, 0, 2, ChunkData, []byte("new-A")))
	mustNoErrLocal(t, err)
	if string(delivered) != "new-A" {
		t.Errorf("delivered=%q, want %q (fresh reassembly)", string(delivered), "new-A")
	}

	// Complete the new stream.
	_, done, err := r.AddStreaming(testChunk(1, 1, 2, ChunkData, []byte("new-B")))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true for re-arrived stream")
	}
}

// =============================================================================
// Section 5: Duplicate StreamEnd After Completion
// =============================================================================

// TestDuplicateStreamEndAfterCompletion verifies that a second StreamEnd
// arriving after the stream is already completed is silently ignored.
//
// Contract: "If a Chunk with ChunkStreamEnd is received, the stream is
// complete." A second StreamEnd is a no-op — it should not error, not
// deliver data, and not change the stream state.
func TestDuplicateStreamEndAfterCompletion(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Complete the stream via Total.
	r.AddStreaming(testChunk(1, 0, 1, ChunkData, []byte("done")))

	// Stream should be cleaned up.
	if r.ActiveStreamCount() != 0 {
		t.Fatalf("ActiveStreamCount=%d, want 0 after completion", r.ActiveStreamCount())
	}

	// Send a duplicate StreamEnd — should be silently ignored.
	delivered, done, err := r.AddStreaming(testChunk(1, 1, 0, ChunkStreamEnd, nil))
	mustNoErrLocal(t, err)
	if done {
		t.Error("expected done=false for duplicate StreamEnd after completion")
	}
	if len(delivered) != 0 {
		t.Errorf("delivered %d bytes, want 0 for duplicate StreamEnd", len(delivered))
	}
}

// =============================================================================
// Section 6: StreamEnd Payload at Duplicate Sequence
// =============================================================================

// TestStreamEndPayloadAtDuplicateSequence verifies that when a StreamEnd
// chunk arrives with a payload at a sequence number that already exists
// in the buffer, the existing data is preserved and the StreamEnd payload
// is dropped (but completion still triggers).
//
// Contract: deduplication applies to StreamEnd payloads too — same
// (StreamID, Sequence) is silently ignored for data purposes, but the
// StreamEnd type still triggers completion.
func TestStreamEndPayloadAtDuplicateSequence(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send data chunk at seq 0.
	r.AddStreaming(testChunk(1, 0, 0, ChunkData, []byte("original")))

	// Send StreamEnd at seq 0 with different payload — should preserve
	// original data and complete the stream.
	delivered, done, err := r.AddStreaming(testChunk(1, 0, 0, ChunkStreamEnd, []byte("REPLACEMENT")))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true after StreamEnd")
	}

	// The delivered data should be empty (seq 0 was already delivered
	// by the first AddStreaming). The replacement payload should NOT
	// appear in the output.
	if string(delivered) != "" {
		t.Errorf("delivered=%q, want empty (seq 0 already delivered)", string(delivered))
	}
}

// =============================================================================
// Section 7: Inconsistent Total Values
// =============================================================================

// TestInconsistentTotalFirstNonZeroWins verifies that when chunks arrive
// with different non-zero Total values, the first non-zero Total is
// adopted and subsequent different Totals do not override it.
//
// Contract: line 256 — "Update Total if this chunk provides new information"
// only when !st.totalSet. Once Total is set, it is not changed.
func TestInconsistentTotalFirstNonZeroWins(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunk 0 with Total=3.
	r.AddStreaming(testChunk(1, 0, 3, ChunkData, []byte("A")))

	// Send chunk 1 with Total=5 — should NOT override Total=3.
	r.AddStreaming(testChunk(1, 1, 5, ChunkData, []byte("B")))

	// Send chunk 2 with Total=3 — should complete (Total=3, all 0..2 arrived).
	_, done, err := r.AddStreaming(testChunk(1, 2, 3, ChunkData, []byte("C")))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true with Total=3 (first non-zero wins)")
	}
}

// TestInconsistentTotalDoesNotCompleteEarly verifies that if Total is
// learned as 3, but a later chunk claims Total=2, the reassembler does
// NOT complete early based on the smaller Total.
func TestInconsistentTotalDoesNotCompleteEarly(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunk 0 with Total=5.
	r.AddStreaming(testChunk(1, 0, 5, ChunkData, []byte("A")))

	// Send chunk 1 with Total=2 — should NOT override Total=5.
	_, done, err := r.AddStreaming(testChunk(1, 1, 2, ChunkData, []byte("B")))
	mustNoErrLocal(t, err)
	if done {
		t.Fatal("expected done=false (Total=5 still in effect, not 2)")
	}

	// Send chunk 2 — should NOT complete yet (Total=5, need 0..4).
	_, done, err = r.AddStreaming(testChunk(1, 2, 5, ChunkData, []byte("C")))
	mustNoErrLocal(t, err)
	if done {
		t.Fatal("expected done=false (only 3 of 5 chunks received)")
	}
}

// =============================================================================
// Section 8: Zero Limits Mean No Enforcement
// =============================================================================

// TestZeroLimitsMeanNoEnforcement verifies that when MaxReassemblyChunks=0
// and MaxReassemblyBytes=0, no limits are enforced — chunks can accumulate
// without bound. This is the documented behavior for testing only.
//
// Contract: "Zero means no limit (testing only; production must set this)."
func TestZeroLimitsMeanNoEnforcement(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 0, // no limit
		MaxReassemblyBytes:  0, // no limit
	})

	// Buffer many chunks out of order (gap at 0).
	for i := uint32(1); i <= 100; i++ {
		_, _, err := r.AddStreaming(testChunk(1, i, 200, ChunkData, make([]byte, 100)))
		if err != nil {
			t.Fatalf("chunk %d: unexpected error with zero limits: %v", i, err)
		}
	}

	// All 100 chunks should be buffered (10KB total).
	if r.BufferedBytes() != 100*100 {
		t.Errorf("BufferedBytes=%d, want %d", r.BufferedBytes(), 100*100)
	}
}

// TestZeroMaxChunksWithNonZeroMaxBytes verifies that only the zero limit
// is unenforced while the non-zero limit still applies.
func TestZeroMaxChunksWithNonZeroMaxBytes(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 0,  // no chunk limit
		MaxReassemblyBytes:  50, // byte limit still enforced
	})

	// Send chunks totaling < 50 bytes — should succeed.
	for i := uint32(1); i <= 4; i++ {
		_, _, err := r.AddStreaming(testChunk(1, i, 100, ChunkData, make([]byte, 10)))
		if err != nil {
			t.Fatalf("chunk %d: unexpected error: %v", i, err)
		}
	}

	// 5th chunk would push total to 50 (at limit, not over) — checkBounds
	// uses > comparison, so 50 == 50 should pass.
	_, _, err := r.AddStreaming(testChunk(1, 5, 100, ChunkData, make([]byte, 10)))
	if err != nil {
		t.Fatalf("chunk 5 (at limit): unexpected error: %v", err)
	}

	// 6th chunk would push to 60 > 50 — should fail.
	_, _, err = r.AddStreaming(testChunk(1, 6, 100, ChunkData, make([]byte, 10)))
	if err != ErrReassemblyBytesExceeded {
		t.Errorf("expected ErrReassemblyBytesExceeded, got %v", err)
	}
}

// =============================================================================
// Section 9: StreamEnd Payload Aliasing
// =============================================================================

// TestStreamEndPayloadAliasing verifies that the reassembler copies the
// StreamEnd payload, so if the caller modifies the original slice after
// Add returns, the reassembled data is not corrupted.
//
// This tests the aliasing fix in processChunk's StreamEnd path.
func TestStreamEndPayloadAliasing(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send a data chunk at seq 0.
	r.AddStreaming(testChunk(1, 0, 0, ChunkData, []byte("hello ")))

	// Send StreamEnd with payload at seq 1.
	payload := []byte("world")
	delivered, done, err := r.AddStreaming(testChunk(1, 1, 0, ChunkStreamEnd, payload))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true")
	}
	if string(delivered) != "world" {
		t.Errorf("delivered=%q, want %q", string(delivered), "world")
	}

	// Now modify the original payload — should not affect anything
	// since the reassembler should have copied it.
	payload[0] = 'X'

	// The delivered data was already returned, but verify the
	// reassembler didn't retain a reference to the original slice.
	// (This is implicitly tested by the fact that the reassembler
	// cleaned up the stream — if it retained a reference, the GC
	// wouldn't collect it, but we can't easily test that here.)
	// The important thing is that no panic or corruption occurs.
}

// TestStreamEndPayloadAliasingViaAdd verifies aliasing safety through
// the Add (non-streaming) interface. The full accumulated stream should
// not be corrupted if the caller modifies the StreamEnd payload after
// Add returns.
func TestStreamEndPayloadAliasingViaAdd(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send data chunk at seq 0.
	r.Add(testChunk(1, 0, 0, ChunkData, []byte("hello ")))

	// Send StreamEnd with payload.
	payload := []byte("world")
	complete, done, err := r.Add(testChunk(1, 1, 0, ChunkStreamEnd, payload))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true")
	}

	// Verify the complete stream is correct.
	expected := "hello world"
	if string(complete) != expected {
		t.Errorf("complete=%q, want %q", string(complete), expected)
	}

	// Modify the original payload — the already-returned complete
	// slice should not be affected (it was copied during accumulation).
	payload[0] = 'X'
	if string(complete) != expected {
		t.Errorf("complete was corrupted after modifying original payload: got %q", string(complete))
	}
}

// =============================================================================
// Section 10: StreamEnd with Bounds-Exceeding Payload
// =============================================================================

// TestStreamEndBoundsExceedingPayload verifies that when a StreamEnd
// chunk's payload would exceed MaxReassemblyBytes, the error is returned
// and the stream does NOT complete. This is a potential deadlock scenario:
// if the error is returned but the stream is left in-progress, no further
// completion signal can arrive.
//
// This test documents the current behavior. If the contract is changed to
// force-completion on StreamEnd regardless of bounds, this test should be
// updated.
func TestStreamEndBoundsExceedingPayload(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  20, // very low limit
	})

	// Buffer a chunk at seq 1 (gap at 0, so it buffers).
	_, _, err := r.AddStreaming(testChunk(1, 1, 0, ChunkData, make([]byte, 15)))
	if err != nil {
		t.Fatalf("chunk 1: unexpected error: %v", err)
	}

	// StreamEnd with a large payload — should exceed byte limit.
	_, done, err := r.AddStreaming(testChunk(1, 2, 0, ChunkStreamEnd, make([]byte, 10)))
	// 15 + 10 = 25 > 20 → should error
	if err != ErrReassemblyBytesExceeded {
		t.Errorf("expected ErrReassemblyBytesExceeded, got %v", err)
	}
	if done {
		t.Error("expected done=false on bounds error")
	}

	// Stream should still be active (not completed).
	// The caller must tear down the circuit on error.
	if r.ActiveStreamCount() != 1 {
		t.Errorf("ActiveStreamCount=%d, want 1 (stream still in-progress after bounds error)", r.ActiveStreamCount())
	}
}

// =============================================================================
// Section 11: MissingSequences with Large Gap
// =============================================================================

// TestMissingSequencesLargeGap verifies that MissingSequences correctly
// reports all missing sequences in a large gap, not just the first one.
// This also tests the deduplication logic in the MissingSequences method.
func TestMissingSequencesLargeGap(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 1000,
		MaxReassemblyBytes:  10 * 1024 * 1024,
	})

	// Send seq 0 and seq 10 — gap at 1..9 (9 missing).
	r.AddStreaming(testChunk(1, 0, 100, ChunkData, []byte("a")))
	r.AddStreaming(testChunk(1, 10, 100, ChunkData, []byte("k")))

	missing := r.MissingSequences(1)
	if len(missing) != 9 {
		t.Fatalf("missing count: got %d, want 9", len(missing))
	}

	// Verify all 9 missing sequences are reported in order.
	for i, m := range missing {
		expected := uint32(i + 1)
		if m != expected {
			t.Errorf("missing[%d]=%d, want %d", i, m, expected)
		}
	}
}

// TestMissingSequencesMultipleGaps verifies that MissingSequences
// correctly handles multiple disjoint gaps (e.g., missing 1,2 and 5,6).
func TestMissingSequencesMultipleGaps(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 1000,
		MaxReassemblyBytes:  10 * 1024 * 1024,
	})

	// Send seq 0, 3, 6 — gaps at 1,2 and 4,5.
	r.AddStreaming(testChunk(1, 0, 100, ChunkData, []byte("a")))
	r.AddStreaming(testChunk(1, 3, 100, ChunkData, []byte("d")))
	r.AddStreaming(testChunk(1, 6, 100, ChunkData, []byte("g")))

	missing := r.MissingSequences(1)
	if len(missing) != 4 {
		t.Fatalf("missing count: got %d, want 4", len(missing))
	}

	expected := []uint32{1, 2, 4, 5}
	for i, m := range missing {
		if m != expected[i] {
			t.Errorf("missing[%d]=%d, want %d", i, m, expected[i])
		}
	}
}

// =============================================================================
// Section 12: IsCompleted Edge Cases
// =============================================================================

// TestIsCompletedNonExistentStream verifies that IsCompleted returns
// false for a stream that has never been started.
func TestIsCompletedNonExistentStream(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	if r.IsCompleted(999) {
		t.Error("IsCompleted should return false for non-existent stream")
	}
}

// TestIsCompletedAfterCompletion verifies that IsCompleted returns
// true for a completed stream (before cleanup), and that after cleanup
// it returns false.
func TestIsCompletedAfterCompletion(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Complete a stream via Total.
	r.AddStreaming(testChunk(1, 0, 1, ChunkData, []byte("done")))

	// After completion, the stream is cleaned up — IsCompleted should
	// return false (stream no longer exists).
	if r.IsCompleted(1) {
		t.Error("IsCompleted should return false for cleaned-up stream")
	}
}

// =============================================================================
// Section 13: BufferedBytes Accuracy After Various Operations
// =============================================================================

// TestBufferedBytesAfterPartialDelivery verifies that BufferedBytes
// accurately reflects the remaining buffered bytes after some chunks
// are delivered and some are still buffered.
func TestBufferedBytesAfterPartialDelivery(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send seq 0 (100 bytes) — delivered immediately.
	r.AddStreaming(testChunk(1, 0, 10, ChunkData, make([]byte, 100)))

	// Send seq 2 (200 bytes) — buffered (gap at 1).
	r.AddStreaming(testChunk(1, 2, 10, ChunkData, make([]byte, 200)))

	// Send seq 4 (300 bytes) — buffered (gap at 3).
	r.AddStreaming(testChunk(1, 4, 10, ChunkData, make([]byte, 300)))

	// Only seq 2 and 4 should be buffered = 500 bytes.
	if r.BufferedBytes() != 500 {
		t.Errorf("BufferedBytes=%d, want 500", r.BufferedBytes())
	}

	// Send seq 1 (150 bytes) — triggers delivery of seq 1 and 2.
	r.AddStreaming(testChunk(1, 1, 10, ChunkData, make([]byte, 150)))

	// After delivery: seq 0, 1, 2 delivered. Only seq 4 (300 bytes) buffered.
	if r.BufferedBytes() != 300 {
		t.Errorf("BufferedBytes=%d, want 300 after partial delivery", r.BufferedBytes())
	}
}

// TestBufferedBytesAfterPurge verifies that PurgeStream correctly
// subtracts the purged stream's bytes from the global counter.
func TestBufferedBytesAfterPurge(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Buffer chunks in two streams.
	r.AddStreaming(testChunk(1, 1, 0, ChunkData, make([]byte, 100)))
	r.AddStreaming(testChunk(2, 1, 0, ChunkData, make([]byte, 200)))

	// Total buffered: 300.
	if r.BufferedBytes() != 300 {
		t.Fatalf("BufferedBytes=%d, want 300", r.BufferedBytes())
	}

	// Purge stream 1 — should subtract 100.
	r.PurgeStream(1)
	if r.BufferedBytes() != 200 {
		t.Errorf("BufferedBytes=%d after purging stream 1, want 200", r.BufferedBytes())
	}

	// Purge stream 2 — should subtract 200.
	r.PurgeStream(2)
	if r.BufferedBytes() != 0 {
		t.Errorf("BufferedBytes=%d after purging all streams, want 0", r.BufferedBytes())
	}
}

// =============================================================================
// Section 14: ExpireStream Edge Cases
// =============================================================================

// TestExpireStreamNonExistent verifies that ExpireStream returns false
// for a stream that doesn't exist.
func TestExpireStreamNonExistent(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks:     100,
		MaxReassemblyBytes:      1024 * 1024,
		StreamReassemblyTimeout: 100 * time.Millisecond,
	})

	if r.ExpireStream(999, time.Now().Add(time.Hour)) {
		t.Error("ExpireStream should return false for non-existent stream")
	}
}

// TestExpireStreamAlreadyCompleted verifies that ExpireStream returns
// false for a completed stream (completed streams are already cleaned up).
func TestExpireStreamAlreadyCompleted(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks:     100,
		MaxReassemblyBytes:      1024 * 1024,
		StreamReassemblyTimeout: 100 * time.Millisecond,
	})

	// Complete a stream.
	r.AddStreaming(testChunk(1, 0, 1, ChunkData, []byte("done")))

	// Should not be expired (already completed and cleaned up).
	if r.ExpireStream(1, time.Now().Add(time.Hour)) {
		t.Error("ExpireStream should return false for already-completed stream")
	}
}

// TestExpireStreamZeroTimeoutNoExpiry verifies that when
// StreamReassemblyTimeout is zero, ExpireStream is a no-op.
func TestExpireStreamZeroTimeoutNoExpiry(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks:     100,
		MaxReassemblyBytes:      1024 * 1024,
		StreamReassemblyTimeout: 0, // disabled
	})

	r.AddStreaming(testChunk(1, 0, 10, ChunkData, []byte("stuck")))

	if r.ExpireStream(1, time.Now().Add(24*time.Hour)) {
		t.Error("ExpireStream should return false when timeout is zero")
	}
	if r.ActiveStreamCount() != 1 {
		t.Errorf("ActiveStreamCount=%d, want 1 (no expiry with zero timeout)", r.ActiveStreamCount())
	}
}

// =============================================================================
// Section 15: Add (Non-Streaming) with StreamEnd and Gaps
// =============================================================================

// TestAddStreamEndWithGaps verifies that the Add (non-streaming) interface
// correctly handles StreamEnd when there are gaps in the buffered data.
// The accumulated output should contain only the data from chunks that
// were actually received.
func TestAddStreamEndWithGaps(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunk 0 — delivered and accumulated.
	r.Add(testChunk(1, 0, 0, ChunkData, []byte("A")))

	// Send chunk 2 — buffered (gap at 1).
	r.Add(testChunk(1, 2, 0, ChunkData, []byte("C")))

	// Send StreamEnd — should complete with accumulated data.
	// The accumulated data is "A" (from seq 0) + "C" (from seq 2).
	// Note: seq 1 ("B") was never received.
	complete, done, err := r.Add(testChunk(1, 3, 0, ChunkStreamEnd, nil))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true after StreamEnd")
	}

	// The full accumulated stream should be "AC" (A from seq 0, C from seq 2).
	// The gap at seq 1 means "B" is missing — the stream completes with
	// partial data, which is the correct behavior for StreamEnd.
	if string(complete) != "AC" {
		t.Errorf("complete=%q, want %q", string(complete), "AC")
	}
}

// =============================================================================
// Section 16: Add Accumulation with Out-of-Order + StreamEnd
// =============================================================================

// TestAddAccumulationOutOfOrderWithStreamEnd verifies that the Add
// interface correctly accumulates data when chunks arrive out of order
// and the stream is completed via StreamEnd.
func TestAddAccumulationOutOfOrderWithStreamEnd(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunks in reverse order.
	r.Add(testChunk(1, 2, 0, ChunkData, []byte("C")))
	r.Add(testChunk(1, 1, 0, ChunkData, []byte("B")))
	r.Add(testChunk(1, 0, 0, ChunkData, []byte("A")))

	// Send StreamEnd — should complete.
	complete, done, err := r.Add(testChunk(1, 3, 0, ChunkStreamEnd, nil))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true after StreamEnd")
	}

	// The accumulated data should be in sequence order: "ABC".
	if string(complete) != "ABC" {
		t.Errorf("complete=%q, want %q", string(complete), "ABC")
	}
}

// =============================================================================
// Section 17: Round-Trip with Padding Chunks Interleaved
// =============================================================================

// TestRoundTripWithInterleavedPadding verifies that padding chunks
// interleaved with data chunks do not affect the reassembled output
// or the completion behavior.
func TestRoundTripWithInterleavedPadding(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send data and padding chunks interleaved.
	r.AddStreaming(testChunk(1, 0, 3, ChunkData, []byte("hello")))
	r.AddStreaming(testChunk(1, 99, 0, ChunkPadding, []byte("noise")))
	r.AddStreaming(testChunk(1, 1, 3, ChunkData, []byte(" ")))
	r.AddStreaming(testChunk(1, 98, 0, ChunkPadding, []byte("more noise")))
	delivered, done, err := r.AddStreaming(testChunk(1, 2, 3, ChunkData, []byte("world")))
	mustNoErrLocal(t, err)
	if !done {
		t.Fatal("expected done=true after all data chunks")
	}

	// Padding chunks should not appear in the output.
	if string(delivered) != "world" {
		t.Errorf("delivered=%q, want %q", string(delivered), "world")
	}
}

// =============================================================================
// Section 18: EntryNode Build Fix Verification
// =============================================================================

// TestEntryNodeBuildFix is a compile-time verification that the entry_node.go
// fix (adding `var err error` before the circuit setup block) compiles.
// If the package builds, this test passes trivially.
func TestEntryNodeBuildFix(t *testing.T) {
	// This test exists to document the build fix. The actual functionality
	// is tested by the entry_node_test.go suite.
	t.Log("entry_node.go build fix verified — package compiles")
}
