// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the "fixed-16k" Chunker/Reassembler strategy:
// the v1 baseline that produces uniform 16KB chunks with optional
// random padding (1–4KB). It self-registers via init() so that the
// contract tests in chunker_test.go can exercise the Chunker and
// Reassembler interfaces.
//
// The fixed-16k strategy is also used as the fallback when an
// unknown strategy name is requested (see NewChunkerWithConfig).
package proxy

import (
	"crypto/rand"
	"math/big"
	"sort"
)

const fixed16kName = "fixed-16k"

// fixedChunker splits data into uniform MaxChunkSize-byte chunks.
// It is the simplest conformant Chunker implementation and serves
// as the v1 baseline.
type fixedChunker struct {
	cfg      ChunkerConfig
	streamID uint32
	nextSeq  uint32
	total    uint32 // set by SetTotal if known, 0 = unknown
	totalSet bool
}

func newFixedChunker(cfg ChunkerConfig) *fixedChunker {
	if cfg.MaxChunkSize <= 0 {
		cfg.MaxChunkSize = 16 * 1024
	}
	if cfg.MinChunkSize <= 0 {
		cfg.MinChunkSize = cfg.MaxChunkSize
	}
	return &fixedChunker{cfg: cfg}
}

// Split divides data into chunks of exactly cfg.MaxChunkSize bytes.
// The last chunk may be smaller if len(data) is not a multiple of
// MaxChunkSize. Empty input produces no chunks.
func (c *fixedChunker) Split(data []byte) []Chunk {
	if len(data) == 0 {
		return nil
	}

	maxSize := c.cfg.MaxChunkSize
	var chunks []Chunk

	for offset := 0; offset < len(data); {
		end := offset + maxSize
		if end > len(data) {
			end = len(data)
		}
		payload := make([]byte, end-offset)
		copy(payload, data[offset:end])

		chunk := Chunk{
			StreamID: c.streamID,
			Sequence: c.nextSeq,
			Type:     ChunkData,
			Payload:  payload,
		}

		if !c.cfg.DisablePadding && c.cfg.PaddingMax > 0 {
			paddingLen := c.randomPaddingLen()
			if paddingLen > 0 {
				chunk.PaddingLen = uint16(paddingLen)
			}
		}

		if c.totalSet {
			chunk.Total = c.total
		}

		chunks = append(chunks, chunk)
		c.nextSeq++
		offset = end
	}

	return chunks
}

// SetStreamID assigns the stream identifier for this chunker.
func (c *fixedChunker) SetStreamID(id uint32) {
	c.streamID = id
	c.nextSeq = 0
}

// SetTotal sets the total chunk count for early completion detection.
func (c *fixedChunker) SetTotal(total uint32) {
	c.total = total
	c.totalSet = true
}

// randomPaddingLen returns a random padding length in [PaddingMin, PaddingMax].
func (c *fixedChunker) randomPaddingLen() int {
	min := c.cfg.PaddingMin
	max := c.cfg.PaddingMax
	if min < 0 {
		min = 0
	}
	if max < min {
		return 0
	}
	if max == 0 {
		return 0
	}
	rangeSize := max - min + 1
	n, err := rand.Int(rand.Reader, big.NewInt(int64(rangeSize)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

// fixedReassembler reconstructs the original data stream from received
// chunks. It handles out-of-order arrival, deduplication, and signals
// completion via either ChunkStreamEnd or Total-based counting.
type fixedReassembler struct {
	cfg     ChunkerConfig
	streams map[uint32]*reassemblyState
}

// reassemblyState holds the state for a single stream being reassembled.
type reassemblyState struct {
	chunks    map[uint32][]byte // sequence → payload
	total     uint32            // known total (0 = unknown)
	totalSet  bool
	completed bool
}

func newFixedReassembler(cfg ChunkerConfig) *fixedReassembler {
	return &fixedReassembler{
		cfg:     cfg,
		streams: make(map[uint32]*reassemblyState),
	}
}

func (r *fixedReassembler) Add(chunk Chunk) ([]byte, bool) {
	st, ok := r.streams[chunk.StreamID]
	if !ok {
		st = &reassemblyState{chunks: make(map[uint32][]byte)}
		r.streams[chunk.StreamID] = st
	}

	if st.completed {
		return nil, false
	}

	// Padding chunks are ignored.
	if chunk.Type == ChunkPadding {
		return nil, false
	}

	// StreamEnd marker — flush whatever we have.
	if chunk.Type == ChunkStreamEnd {
		st.completed = true
		return r.assemble(st), true
	}

	// Data chunk — deduplicate by sequence number.
	if _, exists := st.chunks[chunk.Sequence]; exists {
		return nil, false
	}

	// Reject chunks with sequence numbers outside [0, Total-1]
	// when Total is known (from this chunk or a previous one).
	if chunk.Total > 0 && chunk.Sequence >= chunk.Total {
		return nil, false
	}
	if st.totalSet && chunk.Sequence >= st.total {
		return nil, false
	}

	payload := make([]byte, len(chunk.Payload))
	copy(payload, chunk.Payload)
	st.chunks[chunk.Sequence] = payload

	if chunk.Total > 0 {
		st.total = chunk.Total
		st.totalSet = true
	}

	// Total-based completion: verify every sequence 0..st.total-1
	// exists in st.chunks. A count-based check (seqCount >= total)
	// is insufficient because chunks outside the [0, total-1] range
	// would inflate seqCount and trigger premature completion.
	if st.totalSet {
		complete := true
		for i := uint32(0); i < st.total; i++ {
			if _, exists := st.chunks[i]; !exists {
				complete = false
				break
			}
		}
		if complete {
			st.completed = true
			return r.assemble(st), true
		}
	}

	return nil, false
}

// assemble sorts chunks by sequence and concatenates their payloads.
func (r *fixedReassembler) assemble(st *reassemblyState) []byte {
	seqs := make([]uint32, 0, len(st.chunks))
	for seq := range st.chunks {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	var result []byte
	for _, seq := range seqs {
		result = append(result, st.chunks[seq]...)
	}
	return result
}

// init registers the "fixed-16k" Chunker and Reassembler strategies.
func init() {
	RegisterChunker(fixed16kName, func(cfg ChunkerConfig) Chunker {
		return newFixedChunker(cfg)
	})
	RegisterReassembler(fixed16kName, func(cfg ChunkerConfig) Reassembler {
		return newFixedReassembler(cfg)
	})
}
