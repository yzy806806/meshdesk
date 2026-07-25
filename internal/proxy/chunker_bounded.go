// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the "bounded-4k-64k" Chunker/Reassembler strategy:
// the production chunking strategy specified in PROXY_DESIGN.md §1.2.
//
// Each chunk payload is 4KB–64KB, sampled from a Pareto distribution
// (α≈1.5) that mirrors real HTTP/2 frame sizes. External wire format
// uses TLS 1.3 record padding for protocol mimicry (handled by the
// transport layer, not here). The chunker passes PaddingLen through
// so the transport layer can pad to TLS record boundaries.
//
// Key properties per CHUNKER_CONTRACT.md §6 Condition 2:
//   - Distribution shape: Pareto (heavy-tailed), NOT uniform random
//   - Per-chunk sampling: each chunk independently sized
//   - Padding: crypto/rand-filled, not math/rand
//   - No size-0 data chunks: min payload is 1 byte (min chunk is 4KB)
//   - Debug mode: --debug-fixed-chunks forces uniform 16KB
package proxy

import (
	"crypto/rand"
	"math"
	"math/big"
	"sort"
)

// cryptoRandFloat64 returns a random float64 in [0, 1) using crypto/rand.
// This replaces math/rand.Float64 with a cryptographically secure version
// per CHUNKER_CONTRACT.md §6 Condition 2.3 (padding must use crypto/rand).
func cryptoRandFloat64() (float64, error) {
	// Read 8 bytes and interpret as a 64-bit unsigned integer.
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	// Convert to uint64 (big-endian) then to float64 in [0, 1).
	// We use the top 53 bits to stay within float64 precision.
	n := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 |
		uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 |
		uint64(b[6])<<8 | uint64(b[7])
	// Shift right by 11 to get 53 significant bits, then divide by 2^53.
	return float64(n>>11) / float64(1<<53), nil
}

const (
	boundedName = "bounded-4k-64k"

	// Pareto distribution shape parameter. α≈1.5 produces a
	// heavy-tailed distribution matching real HTTP/2 frame sizes:
	// most chunks are small (4–8KB), with a long tail of larger
	// chunks (up to 64KB). This is the distribution shape required
	// by CHUNKER_CONTRACT.md §6 Condition 2.1.
	paretoAlpha = 1.5

	// Default bounds for the bounded random chunker.
	defaultBoundedMin = 4 * 1024   // 4KB
	defaultBoundedMax = 64 * 1024  // 64KB
)

// boundedChunker splits data into variable-size chunks sampled from
// a Pareto distribution. Each chunk's size is independently sampled.
type boundedChunker struct {
	cfg       ChunkerConfig
	streamID  uint32
	nextSeq   uint32
	total     uint32
	totalSet  bool
	minSize   int
	maxSize   int
	alpha     float64 // Pareto shape parameter
}

func newBoundedChunker(cfg ChunkerConfig) *boundedChunker {
	minSize := cfg.MinChunkSize
	if minSize <= 0 {
		minSize = defaultBoundedMin
	}
	maxSize := cfg.MaxChunkSize
	if maxSize <= 0 {
		maxSize = defaultBoundedMax
	}
	if maxSize < minSize {
		maxSize = minSize
	}
	return &boundedChunker{
		cfg:     cfg,
		minSize: minSize,
		maxSize: maxSize,
		alpha:   paretoAlpha,
	}
}

// Split divides data into variable-size chunks. Each chunk's size is
// independently sampled from a truncated Pareto distribution in
// [minSize, maxSize]. The final chunk may be smaller than the sampled
// size if insufficient data remains.
func (c *boundedChunker) Split(data []byte) []Chunk {
	if len(data) == 0 {
		return nil
	}

	var chunks []Chunk
	offset := 0

	for offset < len(data) {
		chunkSize := c.sampleParetoSize()
		// Clamp to remaining data.
		remaining := len(data) - offset
		if chunkSize > remaining {
			chunkSize = remaining
		}
		// Ensure minimum chunk size unless this is the last chunk
		// and remaining data is less than minSize.
		if chunkSize < 1 {
			chunkSize = 1
		}

		payload := make([]byte, chunkSize)
		copy(payload, data[offset:offset+chunkSize])

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
		offset += chunkSize
	}

	return chunks
}

// SetStreamID assigns the stream identifier for this chunker.
func (c *boundedChunker) SetStreamID(id uint32) {
	c.streamID = id
	c.nextSeq = 0
}

// SetTotal sets the total chunk count for early completion detection.
func (c *boundedChunker) SetTotal(total uint32) {
	c.total = total
	c.totalSet = true
}

// sampleParetoSize samples a chunk size from a truncated Pareto
// distribution in [minSize, maxSize].
//
// The Pareto distribution CDF: F(x) = 1 - (xm / x)^α  for x >= xm
// Inverse CDF: x = xm / (1 - U)^(1/α)  for U ~ Uniform(0,1)
//
// We use the inverse CDF method: sample U from crypto/rand, compute
// the Pareto quantile, then truncate to [minSize, maxSize].
func (c *boundedChunker) sampleParetoSize() int {
	u, err := cryptoRandFloat64()
	if err != nil {
		return c.minSize // fallback on error
	}

	// Avoid division by zero when U is exactly 0.
	if u <= 0 {
		u = 1e-10
	}

	// Pareto inverse CDF: x = xm / (1 - U)^(1/α)
	// Here xm = minSize (the scale/location parameter).
	scaleFactor := math.Pow(1-u, -1.0/c.alpha)
	size := float64(c.minSize) * scaleFactor

	// Truncate to [minSize, maxSize].
	result := int(math.Round(size))
	if result < c.minSize {
		result = c.minSize
	}
	if result > c.maxSize {
		result = c.maxSize
	}
	return result
}

// randomPaddingLen returns a random padding length in [PaddingMin, PaddingMax]
// using crypto/rand. Same implementation as fixedChunker.
func (c *boundedChunker) randomPaddingLen() int {
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

// boundedReassembler is functionally identical to fixedReassembler —
// the Reassembler interface is chunk-size-agnostic. It operates on
// Chunk.Payload []byte which is variable-length. We reuse the same
// reassembly logic but register under a different name so exit nodes
// configured for "bounded-4k-64k" find their factory.
type boundedReassembler struct {
	streams map[uint32]*reassemblyState
}

func newBoundedReassembler(_ ChunkerConfig) *boundedReassembler {
	return &boundedReassembler{
		streams: make(map[uint32]*reassemblyState),
	}
}

func (r *boundedReassembler) Add(chunk Chunk) ([]byte, bool) {
	st, ok := r.streams[chunk.StreamID]
	if !ok {
		st = &reassemblyState{chunks: make(map[uint32][]byte)}
		r.streams[chunk.StreamID] = st
	}

	if st.completed {
		return nil, false
	}

	if chunk.Type == ChunkPadding {
		return nil, false
	}

	if chunk.Type == ChunkStreamEnd {
		st.completed = true
		return r.assemble(st), true
	}

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
	// exists in st.chunks.
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

func (r *boundedReassembler) assemble(st *reassemblyState) []byte {
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

// init registers the "bounded-4k-64k" Chunker and Reassembler strategies.
func init() {
	RegisterChunker(boundedName, func(cfg ChunkerConfig) Chunker {
		return newBoundedChunker(cfg)
	})
	RegisterReassembler(boundedName, func(cfg ChunkerConfig) Reassembler {
		return newBoundedReassembler(cfg)
	})
}
