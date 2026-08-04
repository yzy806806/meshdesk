// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file contains comprehensive table-driven tests for:
//  1. Chunker TotalChunks ceil computation (fixed + bounded)
//     — covers empty, exact boundary, single-byte-over, and large-data cases
//  2. Reassembler timeout path (ErrStreamTimeout via ExpireStreams)
//  3. Duplicate chunk detection (silent ignore)
//  4. Backpressure (max reorder buffer enforcement)
//
// These tests resolve the relay deadlock gap identified in the
// MeshDesk Stop Condition v3 assessment (motion-ab7dcffe52e8).
package proxy

import (
	"bytes"
	"testing"
	"time"
)

// =============================================================================
// Section 1: TotalChunks Ceil Computation — Table-Driven
// =============================================================================

// ceilTestCases defines the table for ceil computation tests.
// Each case verifies that the chunker produces the correct number of
// chunks (and sets Total correctly) for a given data length.
//
// The four canonical boundary conditions:
//   - empty:            0 bytes → 0 chunks
//   - exact boundary:   N * MaxChunkSize → N chunks (no partial)
//   - single-byte-over: N * MaxChunkSize + 1 → N+1 chunks (1-byte tail)
//   - large-data:       many chunks, verify Total matches count
var ceilTestCases = []struct {
	name      string
	dataLen   int
	chunkSize int // MaxChunkSize for fixed, Max=Min for deterministic bounded
	wantTotal uint32
	wantEmpty bool
}{
	// ── Empty ──────────────────────────────────────────────────────
	{"empty input", 0, 16 * 1024, 0, true},

	// ── Exact boundary ─────────────────────────────────────────────
	{"exact 1 chunk", 16 * 1024, 16 * 1024, 1, false},
	{"exact 2 chunks", 32 * 1024, 16 * 1024, 2, false},
	{"exact 3 chunks", 48 * 1024, 16 * 1024, 3, false},
	{"exact 4 chunks", 64 * 1024, 16 * 1024, 4, false},

	// ── Single-byte-over ──────────────────────────────────────────
	{"1 byte over (1+1)", 16*1024 + 1, 16 * 1024, 2, false},
	{"1 byte over (2+1)", 32*1024 + 1, 16 * 1024, 3, false},
	{"1 byte over (3+1)", 48*1024 + 1, 16 * 1024, 4, false},

	// ── Partial last chunk (various sizes) ────────────────────────
	{"100 bytes (sub-chunk)", 100, 16 * 1024, 1, false},
	{"1 byte", 1, 16 * 1024, 1, false},
	{"17KB (1 full + 1KB tail)", 17 * 1024, 16 * 1024, 2, false},
	{"40KB (2 full + 8KB tail)", 40 * 1024, 16 * 1024, 3, false},
	{"31KB (1 full + 15KB tail)", 31 * 1024, 16 * 1024, 2, false},

	// ── Large data ────────────────────────────────────────────────
	{"1MB (64 chunks)", 1024 * 1024, 16 * 1024, 64, false},
	{"4MB (256 chunks)", 4 * 1024 * 1024, 16 * 1024, 256, false},
}

// TestFixedChunkerTotalCeilTableDriven runs the ceil test table
// against the fixed-16k chunker.
func TestFixedChunkerTotalCeilTableDriven(t *testing.T) {
	for _, tt := range ceilTestCases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ChunkerConfig{
				MaxChunkSize:   tt.chunkSize,
				MinChunkSize:   tt.chunkSize,
				DisablePadding: true,
			}
			c := newFixedChunker(cfg)
			data := make([]byte, tt.dataLen)
			chunks := c.Split(data)

			if tt.wantEmpty {
				if len(chunks) != 0 {
					t.Fatalf("expected 0 chunks for empty input, got %d", len(chunks))
				}
				return
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

// TestBoundedChunkerTotalCeilTableDriven runs the ceil test table
// against the bounded chunker with DebugFixedSizes for deterministic
// chunk counts (otherwise Pareto randomization makes counts unpredictable).
func TestBoundedChunkerTotalCeilTableDriven(t *testing.T) {
	for _, tt := range ceilTestCases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ChunkerConfig{
				MinChunkSize:    tt.chunkSize,
				MaxChunkSize:    tt.chunkSize,
				DisablePadding:  true,
				DebugFixedSizes: true,
			}
			c := newBoundedChunker(cfg)
			data := make([]byte, tt.dataLen)
			chunks := c.Split(data)

			if tt.wantEmpty {
				if len(chunks) != 0 {
					t.Fatalf("expected 0 chunks for empty input, got %d", len(chunks))
				}
				return
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

// TestChunkerCeilRoundTripReassembly verifies that for each ceil test
// case, the chunker→reassembler round trip produces the original data
// with correct completion (no deadlock, no waiting for StreamEnd).
func TestChunkerCeilRoundTripReassembly(t *testing.T) {
	for _, tt := range ceilTestCases {
		if tt.wantEmpty {
			continue // skip empty (nothing to reassemble)
		}
		t.Run(tt.name, func(t *testing.T) {
			cfg := ChunkerConfig{
				MaxChunkSize:        tt.chunkSize,
				MinChunkSize:        tt.chunkSize,
				DisablePadding:      true,
				MaxReassemblyChunks: 10000,
				MaxReassemblyBytes:  100 * 1024 * 1024,
			}
			c := newFixedChunker(cfg)
			r := NewExitReassembler(cfg)

			original := make([]byte, tt.dataLen)
			for i := range original {
				original[i] = byte(i % 256)
			}

			chunks := c.Split(original)
			if uint32(len(chunks)) != tt.wantTotal {
				t.Fatalf("got %d chunks, want %d", len(chunks), tt.wantTotal)
			}

			var reassembled []byte
			var done bool
			for i, ch := range chunks {
				var err error
				reassembled, done, err = r.Add(ch)
				if err != nil {
					t.Fatalf("chunk %d: %v", i, err)
				}
			}

			if !done {
				t.Fatal("reassembler did not signal completion from Total alone")
			}

			if len(reassembled) != len(original) {
				t.Fatalf("reassembled len %d != original %d", len(reassembled), len(original))
			}

			for i := range original {
				if reassembled[i] != original[i] {
					t.Fatalf("byte %d mismatch: got %d, want %d", i, reassembled[i], original[i])
				}
			}
		})
	}
}

// =============================================================================
// Section 2: Reassembler Timeout Path (ErrStreamTimeout)
// =============================================================================

// TestExpireStreamsBasic verifies that a stream that has been
// in-progress longer than StreamReassemblyTimeout is purged by
// ExpireStreams, and that the stream ID is returned.
func TestExpireStreamsBasic(t *testing.T) {
	cfg := ChunkerConfig{
		MaxReassemblyChunks:     100,
		MaxReassemblyBytes:      1024 * 1024,
		StreamReassemblyTimeout: 100 * time.Millisecond,
	}
	r := NewExitReassembler(cfg)

	// Send one chunk of a stream that will never complete (Total=10).
	r.AddStreaming(testChunk(1, 0, 10, ChunkData, []byte("partial")))

	// Immediately — should NOT be expired.
	expired := r.ExpireStreams(time.Now())
	if len(expired) != 0 {
		t.Fatalf("immediate: expected 0 expired, got %d: %v", len(expired), expired)
	}
	if r.ActiveStreamCount() != 1 {
		t.Errorf("ActiveStreamCount=%d, want 1", r.ActiveStreamCount())
	}

	// After timeout — should be expired.
	expired = r.ExpireStreams(time.Now().Add(200 * time.Millisecond))
	if len(expired) != 1 || expired[0] != 1 {
		t.Fatalf("after timeout: expected [1], got %v", expired)
	}
	if r.ActiveStreamCount() != 0 {
		t.Errorf("ActiveStreamCount=%d after expire, want 0", r.ActiveStreamCount())
	}
	if r.BufferedBytes() != 0 {
		t.Errorf("BufferedBytes=%d after expire, want 0", r.BufferedBytes())
	}
}

// TestExpireStreamsZeroTimeoutNoExpiry verifies that when
// StreamReassemblyTimeout is zero, ExpireStreams is a no-op.
func TestExpireStreamsZeroTimeoutNoExpiry(t *testing.T) {
	cfg := ChunkerConfig{
		MaxReassemblyChunks:     100,
		MaxReassemblyBytes:      1024 * 1024,
		StreamReassemblyTimeout: 0, // disabled
	}
	r := NewExitReassembler(cfg)

	r.AddStreaming(testChunk(1, 0, 10, ChunkData, []byte("stuck")))

	// Even far in the future, nothing should expire.
	expired := r.ExpireStreams(time.Now().Add(24 * time.Hour))
	if len(expired) != 0 {
		t.Fatalf("zero timeout: expected 0 expired, got %v", expired)
	}
	if r.ActiveStreamCount() != 1 {
		t.Errorf("ActiveStreamCount=%d, want 1 (no expiry)", r.ActiveStreamCount())
	}
}

// TestExpireStreamsMultiple verifies that ExpireStreams correctly
// handles multiple streams with different ages — only the old ones
// are purged, young ones survive.
func TestExpireStreamsMultiple(t *testing.T) {
	cfg := ChunkerConfig{
		MaxReassemblyChunks:     100,
		MaxReassemblyBytes:      1024 * 1024,
		StreamReassemblyTimeout: 100 * time.Millisecond,
	}
	r := NewExitReassembler(cfg)

	// Stream 1: old (will expire).
	r.AddStreaming(testChunk(1, 0, 10, ChunkData, []byte("old")))

	// Wait so stream 2 gets a later timestamp.
	time.Sleep(60 * time.Millisecond)

	// Stream 2: young (should survive for now).
	r.AddStreaming(testChunk(2, 0, 10, ChunkData, []byte("young")))

	// Stream 1 is ~60ms old — not yet expired (< 100ms).
	// Wait more so stream 1 exceeds 100ms.
	time.Sleep(60 * time.Millisecond)

	// Now stream 1 is ~120ms old (expired), stream 2 is ~60ms old (not expired).
	expired := r.ExpireStreams(time.Now())
	if len(expired) != 1 || expired[0] != 1 {
		t.Fatalf("expected [1] expired, got %v", expired)
	}
	if r.ActiveStreamCount() != 1 {
		t.Errorf("ActiveStreamCount=%d, want 1 (stream 2 survives)", r.ActiveStreamCount())
	}

	// Wait for stream 2 to also expire.
	time.Sleep(60 * time.Millisecond)
	expired = r.ExpireStreams(time.Now())
	if len(expired) != 1 || expired[0] != 2 {
		t.Fatalf("expected [2] expired, got %v", expired)
	}
	if r.ActiveStreamCount() != 0 {
		t.Errorf("ActiveStreamCount=%d, want 0", r.ActiveStreamCount())
	}
}

// TestExpireStreamsCompletedNotExpired verifies that completed streams
// are not reported as expired (they are already cleaned up).
func TestExpireStreamsCompletedNotExpired(t *testing.T) {
	cfg := ChunkerConfig{
		MaxReassemblyChunks:     100,
		MaxReassemblyBytes:      1024 * 1024,
		StreamReassemblyTimeout: 100 * time.Millisecond,
	}
	r := NewExitReassembler(cfg)

	// Complete a stream immediately.
	r.AddStreaming(testChunk(1, 0, 1, ChunkData, []byte("done")))

	// After timeout — completed stream should not appear in expired list.
	expired := r.ExpireStreams(time.Now().Add(200 * time.Millisecond))
	if len(expired) != 0 {
		t.Fatalf("expected 0 expired (stream already completed), got %v", expired)
	}
}

// TestExpireStreamSingle verifies the single-stream ExpireStream method.
func TestExpireStreamSingle(t *testing.T) {
	cfg := ChunkerConfig{
		MaxReassemblyChunks:     100,
		MaxReassemblyBytes:      1024 * 1024,
		StreamReassemblyTimeout: 100 * time.Millisecond,
	}
	r := NewExitReassembler(cfg)

	r.AddStreaming(testChunk(1, 0, 10, ChunkData, []byte("stuck")))

	// Not yet expired.
	if r.ExpireStream(1, time.Now()) {
		t.Error("expected ExpireStream=false before timeout")
	}

	// After timeout.
	if !r.ExpireStream(1, time.Now().Add(200*time.Millisecond)) {
		t.Error("expected ExpireStream=true after timeout")
	}

	// Already purged — should return false.
	if r.ExpireStream(1, time.Now().Add(300*time.Millisecond)) {
		t.Error("expected ExpireStream=false for non-existent stream")
	}
}

// TestStreamAge verifies the StreamAge diagnostic method.
func TestStreamAge(t *testing.T) {
	cfg := ChunkerConfig{
		MaxReassemblyChunks:     100,
		MaxReassemblyBytes:      1024 * 1024,
		StreamReassemblyTimeout: 1 * time.Second,
	}
	r := NewExitReassembler(cfg)

	// Non-existent stream.
	_, ok := r.StreamAge(1, time.Now())
	if ok {
		t.Error("StreamAge should return false for non-existent stream")
	}

	r.AddStreaming(testChunk(1, 0, 10, ChunkData, []byte("data")))

	age, ok := r.StreamAge(1, time.Now())
	if !ok {
		t.Fatal("StreamAge should return true for active stream")
	}
	if age < 0 {
		t.Errorf("StreamAge=%v, want >= 0", age)
	}
}

// TestErrStreamTimeoutError verifies that ErrStreamTimeout is a
// distinct sentinel error that callers can compare against.
func TestErrStreamTimeoutError(t *testing.T) {
	if ErrStreamTimeout == nil {
		t.Fatal("ErrStreamTimeout is nil")
	}
	if ErrStreamTimeout == ErrReassemblyChunksExceeded {
		t.Error("ErrStreamTimeout should not equal ErrReassemblyChunksExceeded")
	}
	if ErrStreamTimeout == ErrReassemblyBytesExceeded {
		t.Error("ErrStreamTimeout should not equal ErrReassemblyBytesExceeded")
	}
	if ErrStreamTimeout.Error() != "proxy: stream reassembly timeout" {
		t.Errorf("ErrStreamTimeout.Error() = %q, want %q",
			ErrStreamTimeout.Error(), "proxy: stream reassembly timeout")
	}
}

// =============================================================================
// Section 3: Duplicate Chunk Detection (Silent Ignore)
// =============================================================================

// dedupTestCase defines the table for duplicate detection tests.
var dedupTestCases = []struct {
	name     string
	chunks   []Chunk // chunks to feed in order
	wantData string  // expected reassembled data
	wantDone bool    // expected completion
}{
	{
		name: "exact duplicate seq 0",
		chunks: []Chunk{
			{StreamID: 1, Sequence: 0, Total: 2, Type: ChunkData, Payload: []byte("hello")},
			{StreamID: 1, Sequence: 0, Total: 2, Type: ChunkData, Payload: []byte("DUPLICATE")},
			{StreamID: 1, Sequence: 1, Total: 2, Type: ChunkData, Payload: []byte(" world")},
		},
		wantData: "hello world",
		wantDone: true,
	},
	{
		name: "duplicate seq 1 (middle)",
		chunks: []Chunk{
			{StreamID: 1, Sequence: 0, Total: 3, Type: ChunkData, Payload: []byte("A")},
			{StreamID: 1, Sequence: 1, Total: 3, Type: ChunkData, Payload: []byte("B")},
			{StreamID: 1, Sequence: 1, Total: 3, Type: ChunkData, Payload: []byte("DUP")},
			{StreamID: 1, Sequence: 2, Total: 3, Type: ChunkData, Payload: []byte("C")},
		},
		wantData: "ABC",
		wantDone: true,
	},
	{
		name: "duplicate last chunk",
		chunks: []Chunk{
			{StreamID: 1, Sequence: 0, Total: 2, Type: ChunkData, Payload: []byte("first")},
			{StreamID: 1, Sequence: 1, Total: 2, Type: ChunkData, Payload: []byte("last")},
			{StreamID: 1, Sequence: 1, Total: 2, Type: ChunkData, Payload: []byte("DUP")},
		},
		wantData: "firstlast",
		wantDone: true,
	},
	{
		name: "triple duplicate seq 0",
		chunks: []Chunk{
			{StreamID: 1, Sequence: 0, Total: 2, Type: ChunkData, Payload: []byte("orig")},
			{StreamID: 1, Sequence: 0, Total: 2, Type: ChunkData, Payload: []byte("dup1")},
			{StreamID: 1, Sequence: 0, Total: 2, Type: ChunkData, Payload: []byte("dup2")},
			{StreamID: 1, Sequence: 1, Total: 2, Type: ChunkData, Payload: []byte("-ok")},
		},
		wantData: "orig-ok",
		wantDone: true,
	},
	{
		name: "duplicate with different payload (first wins)",
		chunks: []Chunk{
			{StreamID: 1, Sequence: 0, Total: 2, Type: ChunkData, Payload: []byte("correct")},
			{StreamID: 1, Sequence: 0, Total: 2, Type: ChunkData, Payload: []byte("wrong")},
			{StreamID: 1, Sequence: 1, Total: 2, Type: ChunkData, Payload: []byte("!")},
		},
		wantData: "correct!",
		wantDone: true,
	},
}

// TestReassemblerDeduplicationTableDriven runs the dedup test table
// through both Add (interface) and AddStreaming paths.
func TestReassemblerDeduplicationTableDriven(t *testing.T) {
	for _, tt := range dedupTestCases {
		t.Run(tt.name+"/Add", func(t *testing.T) {
			r := NewExitReassembler(ChunkerConfig{
				MaxReassemblyChunks: 100,
				MaxReassemblyBytes:  1024 * 1024,
			})

			var complete []byte
			done := false
			for i, ch := range tt.chunks {
				var err error
				var d bool
				var c []byte
				c, d, err = r.Add(ch)
				if err != nil {
					t.Fatalf("chunk %d: unexpected error: %v", i, err)
				}
				if d {
					done = true
					complete = c
				}
			}

			if done != tt.wantDone {
				t.Fatalf("done=%v, want %v", done, tt.wantDone)
			}
			if tt.wantDone && string(complete) != tt.wantData {
				t.Errorf("reassembled=%q, want %q", string(complete), tt.wantData)
			}
		})

		t.Run(tt.name+"/AddStreaming", func(t *testing.T) {
			r := NewExitReassembler(ChunkerConfig{
				MaxReassemblyChunks: 100,
				MaxReassemblyBytes:  1024 * 1024,
			})

			var accumulated []byte
			done := false
			for i, ch := range tt.chunks {
				var err error
				var delivered []byte
				var d bool
				delivered, d, err = r.AddStreaming(ch)
				if err != nil {
					t.Fatalf("chunk %d: unexpected error: %v", i, err)
				}
				accumulated = append(accumulated, delivered...)
				if d {
					done = true
				}
			}

			if done != tt.wantDone {
				t.Fatalf("done=%v, want %v", done, tt.wantDone)
			}
			if tt.wantDone && string(accumulated) != tt.wantData {
				t.Errorf("reassembled=%q, want %q", string(accumulated), tt.wantData)
			}
		})
	}
}

// TestReassemblerDuplicateNoError verifies that duplicates never
// cause an error — they are silently ignored.
func TestReassemblerDuplicateNoError(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 2,
		MaxReassemblyBytes:  100,
	})

	// Fill to capacity.
	_, _, err := r.AddStreaming(testChunk(1, 1, 10, ChunkData, make([]byte, 10)))
	if err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	_, _, err = r.AddStreaming(testChunk(1, 2, 10, ChunkData, make([]byte, 10)))
	if err != nil {
		t.Fatalf("second chunk: %v", err)
	}

	// Duplicate of seq 1 — should be silently ignored, NOT counted
	// against MaxReassemblyChunks.
	_, _, err = r.AddStreaming(testChunk(1, 1, 10, ChunkData, make([]byte, 10)))
	if err != nil {
		t.Errorf("duplicate chunk should not error, got: %v", err)
	}
}

// =============================================================================
// Section 4: Backpressure (Max Reorder Buffer)
// =============================================================================

// backpressureTestCase defines the table for backpressure tests.
var backpressureTestCases = []struct {
	name           string
	maxChunks      int
	maxBytes       int
	chunks         []Chunk
	wantErrOnLast  error // expected error on the last chunk (nil if no error expected)
	wantErrOnIndex int   // 0-based index of the chunk that should trigger the error
}{
	{
		name:      "chunk limit exact (no overflow)",
		maxChunks: 3,
		maxBytes:  1024 * 1024,
		chunks: []Chunk{
			testChunk(1, 1, 10, ChunkData, []byte("a")),
			testChunk(1, 2, 10, ChunkData, []byte("b")),
			testChunk(1, 3, 10, ChunkData, []byte("c")),
		},
		wantErrOnLast:  nil,
		wantErrOnIndex: -1,
	},
	{
		name:      "chunk limit overflow by 1",
		maxChunks: 3,
		maxBytes:  1024 * 1024,
		chunks: []Chunk{
			testChunk(1, 1, 10, ChunkData, []byte("a")),
			testChunk(1, 2, 10, ChunkData, []byte("b")),
			testChunk(1, 3, 10, ChunkData, []byte("c")),
			testChunk(1, 4, 10, ChunkData, []byte("overflow")),
		},
		wantErrOnLast:  ErrReassemblyChunksExceeded,
		wantErrOnIndex: 3,
	},
	{
		name:      "byte limit exact (no overflow)",
		maxChunks: 100,
		maxBytes:  30,
		chunks: []Chunk{
			testChunk(1, 1, 10, ChunkData, make([]byte, 15)),
			testChunk(1, 2, 10, ChunkData, make([]byte, 15)),
		},
		wantErrOnLast:  nil,
		wantErrOnIndex: -1,
	},
	{
		name:      "byte limit overflow by 1 byte",
		maxChunks: 100,
		maxBytes:  30,
		chunks: []Chunk{
			testChunk(1, 1, 10, ChunkData, make([]byte, 15)),
			testChunk(1, 2, 10, ChunkData, make([]byte, 16)), // 15+16=31 > 30
		},
		wantErrOnLast:  ErrReassemblyBytesExceeded,
		wantErrOnIndex: 1,
	},
	{
		name:      "single chunk exceeds byte limit",
		maxChunks: 100,
		maxBytes:  5,
		chunks: []Chunk{
			testChunk(1, 1, 10, ChunkData, make([]byte, 10)),
		},
		wantErrOnLast:  ErrReassemblyBytesExceeded,
		wantErrOnIndex: 0,
	},
	{
		name:      "empty payload does not trigger byte limit",
		maxChunks: 1,
		maxBytes:  1,
		chunks: []Chunk{
			testChunk(1, 1, 10, ChunkData, []byte{}),
		},
		wantErrOnLast:  nil,
		wantErrOnIndex: -1,
	},
}

// TestReassemblerBackpressureTableDriven runs the backpressure test table.
func TestReassemblerBackpressureTableDriven(t *testing.T) {
	for _, tt := range backpressureTestCases {
		t.Run(tt.name, func(t *testing.T) {
			r := NewExitReassembler(ChunkerConfig{
				MaxReassemblyChunks: tt.maxChunks,
				MaxReassemblyBytes:  tt.maxBytes,
			})

			for i, ch := range tt.chunks {
				_, _, err := r.AddStreaming(ch)
				if i == tt.wantErrOnIndex {
					if err != tt.wantErrOnLast {
						t.Fatalf("chunk %d: expected error %v, got %v", i, tt.wantErrOnLast, err)
					}
					return // test passed
				}
				if err != nil {
					t.Fatalf("chunk %d: unexpected error: %v", i, err)
				}
			}

			// If we get here, no error was expected.
			if tt.wantErrOnLast != nil {
				t.Fatalf("expected error %v on chunk %d, but all chunks succeeded",
					tt.wantErrOnLast, tt.wantErrOnIndex)
			}
		})
	}
}

// TestReassemblerBackpressureFreesAfterDelivery verifies that
// backpressure limits are relaxed as chunks are delivered — i.e.
// delivered chunks no longer count toward MaxReassemblyChunks.
//
// checkBounds runs BEFORE the chunk is stored, using >= comparison.
// So with maxChunks=N, we can store at most N chunks before the next
// is rejected. To test "frees after delivery" we:
//  1. Buffer 3 out-of-order chunks (2,3,4) with maxChunks=5
//  2. Verify we can still add more (3 < 5)
//  3. Send chunk 1 (4th, within limit) → triggers delivery of 1,2,3,4
//  4. After delivery, 0 chunks buffered → can add 5+ more
func TestReassemblerBackpressureFreesAfterDelivery(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 5,
		MaxReassemblyBytes:  1024 * 1024,
	})

	// Send chunk 0 (delivered immediately — 0 buffered after).
	_, _, err := r.AddStreaming(testChunk(1, 0, 100, ChunkData, []byte("a")))
	if err != nil {
		t.Fatalf("chunk 0: %v", err)
	}

	// Buffer 3 out-of-order chunks (gap at seq 1).
	for _, seq := range []uint32{2, 3, 4} {
		_, _, err = r.AddStreaming(testChunk(1, seq, 100, ChunkData, []byte("x")))
		if err != nil {
			t.Fatalf("chunk %d: %v", seq, err)
		}
	}

	// 3 buffered, max=5 → room for 2 more.
	if r.BufferedBytes() == 0 {
		t.Error("expected buffered bytes > 0 before gap-fill")
	}

	// Send chunk 1 (4th buffered, within limit) → triggers delivery.
	_, _, err = r.AddStreaming(testChunk(1, 1, 100, ChunkData, []byte("b")))
	if err != nil {
		t.Fatalf("chunk 1: %v", err)
	}

	// After delivery, all buffered chunks (1,2,3,4) are delivered.
	// Buffer should be empty.
	if r.BufferedBytes() != 0 {
		t.Errorf("BufferedBytes=%d after delivery, want 0", r.BufferedBytes())
	}

	// Can now add many new out-of-order chunks (fresh buffer).
	for i := uint32(5); i < 10; i++ {
		_, _, err = r.AddStreaming(testChunk(1, i, 100, ChunkData, []byte("y")))
		if err != nil {
			t.Errorf("chunk %d after delivery: %v", i, err)
		}
	}
}

// TestReassemblerBackpressureCrossStream verifies that the byte limit
// is enforced across multiple streams, not per-stream.
func TestReassemblerBackpressureCrossStream(t *testing.T) {
	r := NewExitReassembler(ChunkerConfig{
		MaxReassemblyChunks: 100,
		MaxReassemblyBytes:  20,
	})

	// Stream 1: 10 bytes buffered (out of order).
	_, _, err := r.AddStreaming(testChunk(1, 1, 10, ChunkData, make([]byte, 10)))
	if err != nil {
		t.Fatalf("stream 1: %v", err)
	}

	// Stream 2: 10 bytes buffered (out of order). Total = 20 (at limit).
	_, _, err = r.AddStreaming(testChunk(2, 1, 10, ChunkData, make([]byte, 10)))
	if err != nil {
		t.Fatalf("stream 2: %v", err)
	}

	// Stream 3: 1 byte — total would be 21 > 20.
	_, _, err = r.AddStreaming(testChunk(3, 1, 10, ChunkData, make([]byte, 1)))
	if err != ErrReassemblyBytesExceeded {
		t.Errorf("expected ErrReassemblyBytesExceeded cross-stream, got %v", err)
	}
}

// =============================================================================
// Section 5: Large-Data Round Trip (Integration)
// =============================================================================

// TestLargeDataRoundTripFixed verifies end-to-end reassembly of a
// large data buffer (1MB) split by the fixed chunker, fed in random
// order to the reassembler. This validates that the ceil computation,
// Total-based completion, dedup, and backpressure all work together.
func TestLargeDataRoundTripFixed(t *testing.T) {
	cfg := ChunkerConfig{
		MaxChunkSize:        16 * 1024,
		MinChunkSize:        16 * 1024,
		DisablePadding:      true,
		MaxReassemblyChunks: 10000,
		MaxReassemblyBytes:  10 * 1024 * 1024,
	}
	c := newFixedChunker(cfg)
	r := NewExitReassembler(cfg)

	// 1MB of recognizable data.
	original := make([]byte, 1024*1024)
	for i := range original {
		original[i] = byte(i % 256)
	}

	chunks := c.Split(original)

	// Feed in reverse order to stress out-of-order handling.
	var accumulated []byte
	var done bool
	for i := len(chunks) - 1; i >= 0; i-- {
		delivered, _, err := r.AddStreaming(chunks[i])
		if err != nil {
			t.Fatalf("chunk %d (reverse): %v", i, err)
		}
		_ = append(accumulated, delivered...)
	}

	// The last chunk fed (seq 0) should trigger delivery of all
	// remaining chunks and completion.
	// However, since we fed in reverse, the final AddStreaming may
	// not return done=true if there are gaps. Let's check.
	// Actually, with Total set, completion happens when nextExpected >= total.
	// Feeding in reverse: seq N-1, N-2, ..., 1, 0. When seq 0 arrives,
	// all chunks become contiguous and are delivered, and nextExpected
	// reaches Total → done=true.

	// Re-check: we need to capture done from the last iteration.
	// The loop above doesn't capture done correctly for the last chunk.
	// Let's redo properly:
	r2 := NewExitReassembler(cfg)
	accumulated = nil
	for i := len(chunks) - 1; i >= 0; i-- {
		var err error
		var delivered []byte
		delivered, done, err = r2.AddStreaming(chunks[i])
		if err != nil {
			t.Fatalf("chunk %d (reverse): %v", i, err)
		}
		accumulated = append(accumulated, delivered...)
	}

	if !done {
		t.Fatal("reassembler did not signal completion after all chunks in reverse order")
	}

	if !bytes.Equal(accumulated, original) {
		t.Fatalf("reassembled data mismatch: got %d bytes, want %d", len(accumulated), len(original))
	}
}

// TestLargeDataRoundTripWithDuplicates verifies that injecting
// duplicate chunks into a large-data stream does not corrupt
// the reassembly.
func TestLargeDataRoundTripWithDuplicates(t *testing.T) {
	cfg := ChunkerConfig{
		MaxChunkSize:        16 * 1024,
		MinChunkSize:        16 * 1024,
		DisablePadding:      true,
		MaxReassemblyChunks: 10000,
		MaxReassemblyBytes:  10 * 1024 * 1024,
	}
	c := newFixedChunker(cfg)
	r := NewExitReassembler(cfg)

	original := make([]byte, 256*1024) // 256KB → 16 chunks
	for i := range original {
		original[i] = byte(i % 256)
	}

	chunks := c.Split(original)

	// Feed in order, but inject duplicates for chunks 5, 10, 0.
	dupIndices := map[int]bool{5: true, 10: true, 0: true}
	var accumulated []byte
	var done bool
	for i, ch := range chunks {
		var err error
		var delivered []byte
		delivered, done, err = r.AddStreaming(ch)
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		accumulated = append(accumulated, delivered...)

		// Inject duplicate.
		if dupIndices[i] {
			dupPayload := make([]byte, len(ch.Payload))
			for j := range dupPayload {
				dupPayload[j] = 0xFF // wrong data — should be ignored
			}
			dupCh := ch
			dupCh.Payload = dupPayload
			_, _, err = r.AddStreaming(dupCh)
			if err != nil {
				t.Fatalf("duplicate of chunk %d: %v", i, err)
			}
		}
	}

	if !done {
		t.Fatal("reassembler did not complete with duplicates injected")
	}

	if !bytes.Equal(accumulated, original) {
		t.Fatalf("reassembled data mismatch after duplicates: got %d bytes, want %d",
			len(accumulated), len(original))
	}
}

// TestLargeDataRoundTripWithTimeout verifies that a timeout does
// NOT fire during legitimate large-data reassembly that completes
// within the timeout window.
func TestLargeDataRoundTripWithTimeout(t *testing.T) {
	cfg := ChunkerConfig{
		MaxChunkSize:            16 * 1024,
		MinChunkSize:            16 * 1024,
		DisablePadding:          true,
		MaxReassemblyChunks:     10000,
		MaxReassemblyBytes:      10 * 1024 * 1024,
		StreamReassemblyTimeout: 30 * time.Second,
	}
	c := newFixedChunker(cfg)
	r := NewExitReassembler(cfg)

	original := make([]byte, 1024*1024)
	for i := range original {
		original[i] = byte(i % 256)
	}

	chunks := c.Split(original)

	var accumulated []byte
	var done bool
	for i, ch := range chunks {
		var err error
		var delivered []byte
		delivered, done, err = r.AddStreaming(ch)
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		accumulated = append(accumulated, delivered...)

		// Periodically check for expired streams — should be none.
		if i%100 == 0 {
			expired := r.ExpireStreams(time.Now())
			if len(expired) != 0 {
				t.Fatalf("unexpected stream expiration during reassembly: %v", expired)
			}
		}
	}

	if !done {
		t.Fatal("reassembler did not complete")
	}

	if !bytes.Equal(accumulated, original) {
		t.Fatalf("data mismatch: got %d bytes, want %d", len(accumulated), len(original))
	}
}
