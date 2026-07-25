// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the exit-side Reassembler — a streaming-capable
// reassembler that keys on chunk sequence/total for correct reassembly
// and handles arbitrary chunk sizes for future-proofing.
//
// Key differences from the basic fixedReassembler/boundedReassembler:
//
//   1. STREAMING DELIVERY: Instead of buffering the entire stream and
//      delivering only on completion, ExitReassembler delivers contiguous
//      data incrementally as chunks arrive. This reduces latency for
//      interactive protocols (SSH, HTTP) where the first bytes must reach
//      the target before the entire stream is complete.
//
//   2. SEQUENCE/TOTAL KEYING: Completion is determined by two independent
//      signals, both keyed on the chunk's Sequence and Total fields:
//        a) ChunkStreamEnd marker — universal completion signal.
//        b) Total field — when all chunks 0..Total-1 have arrived.
//      The reassembler tracks nextExpected (the next contiguous sequence
//      we haven't delivered yet) and uses it for gap detection and
//      ackBase advancement.
//
//   3. ARBITRARY CHUNK SIZES: The reassembler makes NO assumption about
//      payload size. It operates on []byte slices of variable length.
//      This means the same reassembler works for fixed-16k, bounded-4k-64k,
//      or any future variable-size chunking strategy — the entry-side
//      Chunker can be swapped without touching the exit-side reassembler.
//
//   4. DEDUPLICATION + BOUNDS ENFORCEMENT: Duplicate (StreamID, Sequence)
//      pairs are silently ignored. MaxReassemblyChunks and MaxReassemblyBytes
//      are enforced to prevent memory exhaustion attacks.
//
//   5. MULTI-STREAM SUPPORT: Multiple streams (identified by StreamID)
//      can be reassembled concurrently within a single reassembler instance,
//      each with independent completion state.
//
// The ExitReassembler implements the standard Reassembler interface so it
// is fully backward-compatible with existing callers (exit.go uses
// Reassembler.Add). It also exposes a NextContiguous method for callers
// that want streaming delivery.
package proxy

import "sort"

// ExitReassembler is the exit-side streaming reassembler. It reconstructs
// the original data stream from received chunks, delivering contiguous data
// incrementally rather than buffering everything until completion.
//
// ExitReassembler is safe for concurrent use by a single goroutine.
// If shared across goroutines, the caller is responsible for synchronization.
type ExitReassembler struct {
	cfg        ChunkerConfig
	streams    map[uint32]*exitStreamState
	totalBytes int // running total of buffered payload bytes across all streams
}

// exitStreamState holds per-stream reassembly state.
type exitStreamState struct {
	// chunks stores out-of-order chunks keyed by sequence number.
	chunks map[uint32][]byte

	// nextExpected is the next contiguous sequence number we expect to
	// deliver. All sequences 0..nextExpected-1 have been delivered.
	// When a chunk with Sequence == nextExpected arrives, it and any
	// subsequent contiguous chunks are immediately deliverable.
	nextExpected uint32

	// total is the known total chunk count (0 = unknown/streaming mode).
	total    uint32
	totalSet bool

	// completed is true when the stream has been fully reassembled
	// (either ChunkStreamEnd received or all 0..Total-1 arrived).
	completed bool

	// bytes is the total payload bytes currently buffered for this stream.
	// Decremented as chunks are delivered.
	bytes int

	// accumulated stores all data delivered via AddStreaming for this
	// stream. This is used by the Add method (Reassembler interface compat)
	// to return the full reassembled data on completion. Callers using
	// AddStreaming directly consume the incremental data and don't need
	// this field — but it's maintained unconditionally so Add works
	// correctly regardless of which method was previously called.
	accumulated []byte
}

// NewExitReassembler creates a new ExitReassembler with the given config.
func NewExitReassembler(cfg ChunkerConfig) *ExitReassembler {
	return &ExitReassembler{
		cfg:     cfg,
		streams: make(map[uint32]*exitStreamState),
	}
}

// exitReassemblerFactory is the factory function for the ReassemblerRegistry.
// It creates an ExitReassembler, which is backward-compatible with the
// Reassembler interface.
func exitReassemblerFactory(cfg ChunkerConfig) Reassembler {
	return NewExitReassembler(cfg)
}

// Add receives a Chunk and incorporates it into the reassembly state.
// It implements the Reassembler interface for backward compatibility.
//
// Unlike AddStreaming, Add does NOT return data incrementally. It
// accumulates all delivered data internally and returns the full
// reassembled stream only when done=true.
//
// For streaming (incremental) delivery, use AddStreaming instead.
func (r *ExitReassembler) Add(chunk Chunk) (complete []byte, done bool, err error) {
	// Track per-stream accumulation for Add callers.
	// We use a separate map from the streaming state because Add callers
	// expect the full stream on completion, not incremental delivery.
	st := r.getOrCreateStream(chunk.StreamID)

	if st.completed {
		return nil, false, nil
	}

	// Process the chunk using the core logic.
	delivered, done, err := r.processChunk(st, chunk)
	if err != nil {
		return nil, false, err
	}

	// Accumulate delivered data for this stream.
	if len(delivered) > 0 {
		st.accumulated = append(st.accumulated, delivered...)
	}

	if done {
		// Return the full accumulated stream.
		full := st.accumulated
		r.cleanupStream(chunk.StreamID)
		return full, true, nil
	}

	return nil, false, nil
}

// AddStreaming receives a Chunk and returns any newly-deliverable contiguous
// data. Unlike Add, this method returns data as soon as contiguous chunks
// are available — it does NOT wait for stream completion.
//
// Returns:
//   - delivered: contiguous bytes that can be written to the target now
//     (may be nil if no new contiguous data is available)
//   - done: true when the stream is fully reassembled
//   - err: non-nil when a resource limit is exceeded
//
// When done=true, the delivered data contains ONLY the final incremental
// portion (not the full stream). Callers should write it to the target
// immediately, as with all prior incremental deliveries.
func (r *ExitReassembler) AddStreaming(chunk Chunk) (delivered []byte, done bool, err error) {
	st := r.getOrCreateStream(chunk.StreamID)

	if st.completed {
		return nil, false, nil
	}

	delivered, done, err = r.processChunk(st, chunk)
	if err != nil {
		return nil, false, err
	}

	if done {
		// Stream complete — cleanup. The caller has already received
		// prior incremental deliveries via previous AddStreaming calls.
		// This final call returns only the remaining incremental data.
		r.cleanupStream(chunk.StreamID)
	}

	return delivered, done, nil
}

// processChunk is the core reassembly logic shared by Add and AddStreaming.
// It processes a single chunk and returns any newly-deliverable contiguous
// data. The caller is responsible for accumulating (Add) or returning
// (AddStreaming) the delivered data, and for cleanup on completion.
//
// Parameters:
//   - st: the stream state (must already be retrieved via getOrCreateStream)
//   - chunk: the chunk to process
//
// Returns:
//   - delivered: incremental contiguous data ready for delivery
//   - done: true when the stream is fully reassembled
//   - err: non-nil when a resource limit is exceeded
func (r *ExitReassembler) processChunk(st *exitStreamState, chunk Chunk) (delivered []byte, done bool, err error) {
	if st.completed {
		return nil, false, nil
	}

	// Padding chunks are consumed without affecting data state.
	if chunk.Type == ChunkPadding {
		return nil, false, nil
	}

	// Handle ChunkStreamEnd: store any payload, then flush remaining
	// buffered data as the final delivery.
	if chunk.Type == ChunkStreamEnd {
		if len(chunk.Payload) > 0 {
			if _, exists := st.chunks[chunk.Sequence]; !exists {
				if err := r.checkBounds(st, chunk.Payload); err != nil {
					return nil, false, err
				}
				st.chunks[chunk.Sequence] = chunk.Payload
				st.bytes += len(chunk.Payload)
				r.totalBytes += len(chunk.Payload)
			}
		}
		st.completed = true
		// Deliver all remaining buffered data in sequence order.
		delivered = r.flushRemaining(st)
		return delivered, true, nil
	}

	// ── Data chunk processing ───────────────────────────────────────

	// Reject chunks outside the valid [0, Total-1] range when Total is known.
	if chunk.Total > 0 && chunk.Sequence >= chunk.Total {
		return nil, false, nil
	}
	if st.totalSet && chunk.Sequence >= st.total {
		return nil, false, nil
	}

	// Deduplicate: same (StreamID, Sequence) already received → ignore.
	if _, exists := st.chunks[chunk.Sequence]; exists {
		return nil, false, nil
	}

	// Enforce bounds before storing.
	if err := r.checkBounds(st, chunk.Payload); err != nil {
		return nil, false, err
	}

	// Store the chunk payload (copy to avoid aliasing).
	payload := make([]byte, len(chunk.Payload))
	copy(payload, chunk.Payload)
	st.chunks[chunk.Sequence] = payload
	st.bytes += len(payload)
	r.totalBytes += len(payload)

	// Update Total if this chunk provides new information.
	if chunk.Total > 0 && !st.totalSet {
		st.total = chunk.Total
		st.totalSet = true
	}

	// Deliver any newly-contiguous chunks.
	delivered = r.deliverContiguous(st)

	// Check Total-based completion: if Total is known and we've delivered
	// all chunks 0..Total-1, the stream is complete.
	if st.totalSet && st.nextExpected >= st.total {
		st.completed = true
		return delivered, true, nil
	}

	return delivered, false, nil
}

// deliverContiguous delivers all contiguous chunks starting from nextExpected.
// It advances nextExpected past delivered chunks and removes them from the
// buffer, freeing memory incrementally.
func (r *ExitReassembler) deliverContiguous(st *exitStreamState) []byte {
	var result []byte

	for {
		payload, exists := st.chunks[st.nextExpected]
		if !exists {
			break
		}
		result = append(result, payload...)
		st.bytes -= len(payload)
		r.totalBytes -= len(payload)
		delete(st.chunks, st.nextExpected)
		st.nextExpected++
	}

	return result
}

// flushRemaining delivers all buffered chunks in sequence order, regardless
// of contiguity. Used when ChunkStreamEnd is received — any gaps at this
// point represent lost chunks that will not arrive.
func (r *ExitReassembler) flushRemaining(st *exitStreamState) []byte {
	if len(st.chunks) == 0 {
		return nil
	}

	// Sort sequence numbers for ordered delivery.
	seqs := make([]uint32, 0, len(st.chunks))
	for seq := range st.chunks {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	var result []byte
	for _, seq := range seqs {
		result = append(result, st.chunks[seq]...)
	}

	// Subtract this stream's buffered bytes from the global counter.
	// Gap fix: previously this zeroed r.totalBytes, which corrupted
	// the byte count when multiple streams were active concurrently.
	r.totalBytes -= st.bytes
	if r.totalBytes < 0 {
		r.totalBytes = 0
	}
	st.bytes = 0
	st.chunks = make(map[uint32][]byte)
	return result
}

// checkBounds enforces MaxReassemblyChunks and MaxReassemblyBytes before
// storing a new chunk. Returns an error if the chunk would exceed a limit.
func (r *ExitReassembler) checkBounds(st *exitStreamState, payload []byte) error {
	maxChunks := r.cfg.MaxReassemblyChunks
	if maxChunks > 0 && len(st.chunks) >= maxChunks {
		return ErrReassemblyChunksExceeded
	}

	pLen := len(payload)
	maxBytes := r.cfg.MaxReassemblyBytes
	if maxBytes > 0 && r.totalBytes+pLen > maxBytes {
		return ErrReassemblyBytesExceeded
	}
	return nil
}

// getOrCreateStream returns the stream state for the given StreamID,
// creating it if this is the first chunk for that stream.
func (r *ExitReassembler) getOrCreateStream(streamID uint32) *exitStreamState {
	st, ok := r.streams[streamID]
	if !ok {
		st = &exitStreamState{
			chunks: make(map[uint32][]byte),
		}
		r.streams[streamID] = st
	}
	return st
}

// cleanupStream removes the stream's state and subtracts its bytes from
// the global total. Called after successful completion.
func (r *ExitReassembler) cleanupStream(streamID uint32) {
	if st, ok := r.streams[streamID]; ok {
		r.totalBytes -= st.bytes
		if r.totalBytes < 0 {
			r.totalBytes = 0
		}
		delete(r.streams, streamID)
	}
}

// NextExpected returns the next expected sequence number for the given
// stream — i.e., the next contiguous chunk that hasn't been delivered yet.
// This is used by the exit node for ackBase tracking and gap detection.
//
// Returns (0, false) if the stream doesn't exist (not started or already
// completed and cleaned up).
func (r *ExitReassembler) NextExpected(streamID uint32) (uint32, bool) {
	st, ok := r.streams[streamID]
	if !ok {
		return 0, false
	}
	return st.nextExpected, true
}

// HasGap returns true if the stream has buffered chunks beyond nextExpected,
// indicating a gap in the contiguous sequence. Used for NACK generation.
func (r *ExitReassembler) HasGap(streamID uint32) bool {
	st, ok := r.streams[streamID]
	if !ok {
		return false
	}
	return len(st.chunks) > 0
}

// MissingSequences returns the sequence numbers of buffered chunks that
// are ahead of nextExpected (i.e., the gaps). The returned slice is sorted
// in ascending order. Returns nil if the stream doesn't exist or has no gaps.
func (r *ExitReassembler) MissingSequences(streamID uint32) []uint32 {
	st, ok := r.streams[streamID]
	if !ok {
		return nil
	}

	var missing []uint32
	for seq := range st.chunks {
		if seq >= st.nextExpected {
			// Find the gap: sequences between nextExpected and seq
			// that are NOT in st.chunks.
			for s := st.nextExpected; s < seq; s++ {
				if _, exists := st.chunks[s]; !exists {
					missing = append(missing, s)
				}
			}
		}
	}

	// Deduplicate and sort.
	if len(missing) == 0 {
		return nil
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })

	// Remove duplicates (the nested loop above can add the same gap
	// multiple times if multiple out-of-order chunks exist).
	unique := missing[:1]
	for i := 1; i < len(missing); i++ {
		if missing[i] != missing[i-1] {
			unique = append(unique, missing[i])
		}
	}
	return unique
}

// IsCompleted returns true if the stream has been fully reassembled.
func (r *ExitReassembler) IsCompleted(streamID uint32) bool {
	st, ok := r.streams[streamID]
	if !ok {
		return false
	}
	return st.completed
}

// ActiveStreamCount returns the number of streams currently being
// reassembled (not yet completed).
func (r *ExitReassembler) ActiveStreamCount() int {
	return len(r.streams)
}

// BufferedBytes returns the total payload bytes currently buffered across
// all in-progress streams.
func (r *ExitReassembler) BufferedBytes() int {
	return r.totalBytes
}

// init registers the ExitReassembler under the "exit-streaming" strategy
// name. Exit nodes that want streaming delivery should use this strategy.
// The existing "fixed-16k" and "bounded-4k-64k" strategies remain available
// for backward compatibility.
func init() {
	RegisterReassembler("exit-streaming", exitReassemblerFactory)
}
