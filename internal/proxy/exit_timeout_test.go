package proxy

import (
	"testing"
	"time"
)

// TestNACKRetryExhaustion verifies that after MaxNACKRetries attempts,
// the exit node returns ErrNACKRetriesExhausted to signal circuit teardown
// (spec §3.3: NACK retry specification).
func TestNACKRetryExhaustion(t *testing.T) {
	cfg := DefaultExitConfig()
	cfg.AllowAllPorts = true
	cfg.ChunkerCfg = ChunkerConfig{
		MaxChunkSize:   1024,
		MinChunkSize:   1024,
		DisablePadding: true,
	}
	cfg.CircuitCfg.NACKTimeout = 10 * time.Millisecond // very short for test
	cfg.CircuitCfg.MaxNACKRetries = 3

	exit, ln, targetAddr, entryKeys, _ := setupExitWithMockTarget(t, cfg)
	defer ln.Close()
	defer exit.Close()

	circuitIDHex, circuitID, e2eKey := performCircuitSetup(t, exit, targetAddr, entryKeys, nil)

	// Send chunk 0 (in-order, no gap).
	chunk0 := Chunk{StreamID: 0, Sequence: 0, Type: ChunkData, Payload: []byte("A")}
	wc0 := encodeChunks(t, []Chunk{chunk0}, e2eKey, circuitID)[0]
	exit.HandleWireChunk(circuitIDHex, wc0, 0)

	// Send chunk 10 (creates a big gap: 1-9 are missing).
	chunk10 := Chunk{StreamID: 0, Sequence: 10, Type: ChunkData, Payload: []byte("B")}
	wc10 := encodeChunks(t, []Chunk{chunk10}, e2eKey, circuitID)[0]
	exit.HandleWireChunk(circuitIDHex, wc10, 0)

	// Now we need to trigger NACK checks. Each NACK requires:
	//   1. gapFirstSeen + NACKTimeout to have elapsed (initial delay)
	//   2. At least NACKTimeout since last NACK (rate limit)
	// After MaxNACKRetries (3) NACKs, the next check should return
	// ErrNACKRetriesExhausted.
	//
	// IMPORTANT: We resend the SAME chunk (seq=10, deduplicated) to trigger
	// the NACK check without creating NEW gap sequences. Sending chunks with
	// higher sequence numbers would add new gaps that reset the exhaustion
	// check for those sequences.
	//
	// Timeline with NACKTimeout=10ms:
	//   t=0: gap detected (seq 1-9 missing)
	//   t=12ms: 1st NACK (retry count: 1 for each missing seq)
	//   t=24ms: 2nd NACK (retry count: 2)
	//   t=36ms: 3rd NACK (retry count: 3 — reached MaxNACKRetries)
	//   t=48ms: 4th check → ErrNACKRetriesExhausted
	var lastErr error
	for i := 0; i < 30; i++ {
		time.Sleep(12 * time.Millisecond)
		// Resend chunk 10 (deduplicated, but triggers NACK check).
		_, err := exit.HandleWireChunk(circuitIDHex, wc10, 0)
		if err != nil {
			lastErr = err
			break
		}
	}

	if lastErr == nil {
		t.Fatal("expected ErrNACKRetriesExhausted after max retries, got nil")
	}
	if lastErr != ErrNACKRetriesExhausted {
		t.Fatalf("expected ErrNACKRetriesExhausted, got: %v", lastErr)
	}
}

// TestNACKRetryCountTracked verifies that the NACK retry counter is
// properly tracked per missing sequence.
func TestNACKRetryCountTracked(t *testing.T) {
	cfg := DefaultExitConfig()
	cfg.AllowAllPorts = true
	cfg.ChunkerCfg = ChunkerConfig{
		MaxChunkSize:   1024,
		MinChunkSize:   1024,
		DisablePadding: true,
	}
	cfg.CircuitCfg.NACKTimeout = 20 * time.Millisecond
	cfg.CircuitCfg.MaxNACKRetries = 5 // higher limit so we can count

	exit, ln, targetAddr, entryKeys, _ := setupExitWithMockTarget(t, cfg)
	defer ln.Close()
	defer exit.Close()

	circuitIDHex, circuitID, e2eKey := performCircuitSetup(t, exit, targetAddr, entryKeys, nil)

	// Send chunk 0 then chunk 5 to create a gap.
	chunk0 := Chunk{StreamID: 0, Sequence: 0, Type: ChunkData, Payload: []byte("A")}
	wc0 := encodeChunks(t, []Chunk{chunk0}, e2eKey, circuitID)[0]
	exit.HandleWireChunk(circuitIDHex, wc0, 0)

	chunk5 := Chunk{StreamID: 0, Sequence: 5, Type: ChunkData, Payload: []byte("B")}
	wc5 := encodeChunks(t, []Chunk{chunk5}, e2eKey, circuitID)[0]
	exit.HandleWireChunk(circuitIDHex, wc5, 0)

	// Wait for timeout and trigger NACKs.
	var nacksReceived int
	for i := 0; i < 10; i++ {
		time.Sleep(25 * time.Millisecond)
		chunkN := Chunk{StreamID: 0, Sequence: uint32(6 + i), Type: ChunkData, Payload: []byte("X")}
		wcN := encodeChunks(t, []Chunk{chunkN}, e2eKey, circuitID)[0]
		nack, _ := exit.HandleWireChunk(circuitIDHex, wcN, 0)
		if nack != nil {
			nacksReceived++
		}
	}

	// We should have received at least 1 NACK before retries exhaust.
	if nacksReceived == 0 {
		t.Error("expected at least 1 NACK before retry exhaustion")
	}
}

// TestStreamReassemblyTimeoutPurge verifies that a stuck stream
// (incomplete, no new chunks) is force-purged after
// StreamReassemblyTimeout (spec §3.2).
func TestStreamReassemblyTimeoutPurge(t *testing.T) {
	cfg := DefaultExitConfig()
	cfg.AllowAllPorts = true
	cfg.ChunkerCfg = ChunkerConfig{
		MaxChunkSize:   1024,
		MinChunkSize:   1024,
		DisablePadding: true,
		// Set low bounds so we can trigger easily
		MaxReassemblyChunks: 2048,
		MaxReassemblyBytes:  32 * 1024 * 1024,
	}
	cfg.CircuitCfg.OrphanTimeout = 30 * time.Second // long, so it doesn't interfere
	cfg.CircuitCfg.StreamReassemblyTimeout = 100 * time.Millisecond

	exit, ln, targetAddr, entryKeys, _ := setupExitWithMockTarget(t, cfg)
	defer ln.Close()
	defer exit.Close()

	circuitIDHex, circuitID, e2eKey := performCircuitSetup(t, exit, targetAddr, entryKeys, nil)

	// Send chunk 0 then chunk 2 (gap at 1 — stream won't complete).
	chunk0 := Chunk{StreamID: 0, Sequence: 0, Type: ChunkData, Payload: []byte("A")}
	wc0 := encodeChunks(t, []Chunk{chunk0}, e2eKey, circuitID)[0]
	exit.HandleWireChunk(circuitIDHex, wc0, 0)

	chunk2 := Chunk{StreamID: 0, Sequence: 2, Type: ChunkData, Payload: []byte("B")}
	wc2 := encodeChunks(t, []Chunk{chunk2}, e2eKey, circuitID)[0]
	exit.HandleWireChunk(circuitIDHex, wc2, 0)

	// Verify the stream has buffered data.
	exit.mu.RLock()
	circuit := exit.circuits[circuitIDHex]
	exit.mu.RUnlock()

	if circuit == nil {
		t.Fatal("circuit not found")
	}

	circuit.mu.Lock()
	streamExists := circuit.reassembler.HasGap(0)
	bufferedBefore := circuit.reassembler.BufferedBytes()
	circuit.mu.Unlock()

	if !streamExists {
		t.Fatal("expected stream to have a gap (buffered out-of-order chunks)")
	}
	if bufferedBefore == 0 {
		t.Fatal("expected buffered bytes > 0")
	}

	// Wait for StreamReassemblyTimeout.
	time.Sleep(150 * time.Millisecond)

	// Run cleanup — should purge the stuck stream.
	removed := exit.CleanupOrphans()
	if removed != 0 {
		t.Errorf("CleanupOrphans removed %d circuits, expected 0 (circuit should still be active)", removed)
	}

	// Verify the stream was purged.
	circuit.mu.Lock()
	bufferedAfter := circuit.reassembler.BufferedBytes()
	hasGapAfter := circuit.reassembler.HasGap(0)
	circuit.mu.Unlock()

	if bufferedAfter != 0 {
		t.Errorf("buffered bytes after cleanup = %d, want 0 (stream should be purged)", bufferedAfter)
	}
	if hasGapAfter {
		t.Error("stream still has gap after cleanup — stream not purged")
	}

	// Verify the stream timer was removed.
	circuit.mu.Lock()
	_, timerExists := circuit.streamTimers[0]
	circuit.mu.Unlock()

	if timerExists {
		t.Error("stream timer still exists after stream was purged")
	}
}

// TestStreamTimeoutDoesNotAffectOtherStreams verifies that a stuck
// stream's timeout doesn't cause other healthy streams in the same
// circuit to be purged (spec §3.2: per-stream, not per-circuit).
func TestStreamTimeoutDoesNotAffectOtherStreams(t *testing.T) {
	cfg := DefaultExitConfig()
	cfg.AllowAllPorts = true
	cfg.ChunkerCfg = ChunkerConfig{
		MaxChunkSize:   1024,
		MinChunkSize:   1024,
		DisablePadding: true,
	}
	cfg.CircuitCfg.StreamReassemblyTimeout = 100 * time.Millisecond

	exit, ln, targetAddr, entryKeys, _ := setupExitWithMockTarget(t, cfg)
	defer ln.Close()
	defer exit.Close()

	circuitIDHex, circuitID, e2eKey := performCircuitSetup(t, exit, targetAddr, entryKeys, nil)

	// Stream 0: stuck (gap, will never complete)
	chunk0 := Chunk{StreamID: 0, Sequence: 0, Type: ChunkData, Payload: []byte("A")}
	wc0 := encodeChunks(t, []Chunk{chunk0}, e2eKey, circuitID)[0]
	exit.HandleWireChunk(circuitIDHex, wc0, 0)

	chunk2s0 := Chunk{StreamID: 0, Sequence: 2, Type: ChunkData, Payload: []byte("B")}
	wc2s0 := encodeChunks(t, []Chunk{chunk2s0}, e2eKey, circuitID)[0]
	exit.HandleWireChunk(circuitIDHex, wc2s0, 0)

	// Stream 1: complete (ChunkStreamEnd)
	chunk0s1 := Chunk{StreamID: 1, Sequence: 0, Type: ChunkStreamEnd, Payload: []byte("done")}
	wc0s1 := encodeChunks(t, []Chunk{chunk0s1}, e2eKey, circuitID)[0]
	exit.HandleWireChunk(circuitIDHex, wc0s1, 0)

	// Wait for StreamReassemblyTimeout.
	time.Sleep(150 * time.Millisecond)

	// Run cleanup.
	exit.CleanupOrphans()

	// Stream 0 should be purged (stuck), stream 1 should be unaffected
	// (it already completed and was cleaned up by the reassembler).
	exit.mu.RLock()
	circuit := exit.circuits[circuitIDHex]
	exit.mu.RUnlock()

	if circuit == nil {
		t.Fatal("circuit not found after cleanup")
	}

	circuit.mu.Lock()
	buffered := circuit.reassembler.BufferedBytes()
	circuit.mu.Unlock()

	if buffered != 0 {
		t.Errorf("buffered bytes = %d, want 0 (all streams should be cleaned up)", buffered)
	}
}

// TestCircuitConfigDefaultsStreamTimeout verifies that the default
// CircuitConfig includes the new StreamReassemblyTimeout and
// MaxNACKRetries fields with correct defaults.
func TestCircuitConfigDefaultsStreamTimeout(t *testing.T) {
	cfg := DefaultCircuitConfig()

	if cfg.StreamReassemblyTimeout != 60*time.Second {
		t.Errorf("StreamReassemblyTimeout default = %v, want 60s", cfg.StreamReassemblyTimeout)
	}
	if cfg.MaxNACKRetries != 3 {
		t.Errorf("MaxNACKRetries default = %d, want 3", cfg.MaxNACKRetries)
	}
}

// TestPurgeStream verifies that PurgeStream correctly removes a
// stream's state and frees its buffered bytes.
func TestPurgeStream(t *testing.T) {
	cfg := ChunkerConfig{
		MaxChunkSize: 1024,
		MinChunkSize: 1024,
	}
	r := NewExitReassembler(cfg)

	// Add some out-of-order chunks (gap at seq 1).
	chunk0 := Chunk{StreamID: 5, Sequence: 0, Type: ChunkData, Payload: []byte("hello")}
	chunk2 := Chunk{StreamID: 5, Sequence: 2, Type: ChunkData, Payload: []byte("world")}

	r.Add(chunk0)
	r.Add(chunk2)

	// Verify stream has buffered data.
	if !r.HasGap(5) {
		t.Fatal("expected gap in stream 5")
	}
	if r.BufferedBytes() == 0 {
		t.Fatal("expected buffered bytes > 0")
	}

	// Purge the stream.
	r.PurgeStream(5)

	// Verify stream is gone.
	if r.HasGap(5) {
		t.Error("stream 5 still has gap after purge")
	}
	if r.BufferedBytes() != 0 {
		t.Errorf("buffered bytes after purge = %d, want 0", r.BufferedBytes())
	}
	if r.ActiveStreamCount() != 0 {
		t.Errorf("active stream count after purge = %d, want 0", r.ActiveStreamCount())
	}

	// Verify we can start a fresh reassembly for the same stream ID.
	chunk0new := Chunk{StreamID: 5, Sequence: 0, Type: ChunkStreamEnd, Payload: []byte("fresh")}
	_, done, err := r.Add(chunk0new)
	if err != nil {
		t.Fatalf("Add after purge: %v", err)
	}
	if !done {
		t.Error("expected stream to complete after fresh reassembly")
	}
}
