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
	"encoding/binary"
	"io"
	"math"
)

const (
	boundedName = "bounded-4k-64k"

	// Pareto distribution shape parameter. α≈1.5 produces a
	// heavy-tailed distribution matching real HTTP/2 frame sizes:
	// most chunks are small (4–8KB), with a long tail of larger
	// chunks (up to 64KB). This is the distribution shape required
	// by CHUNKER_CONTRACT.md §6 Condition 2.1.
	paretoAlpha = 1.5

	// Default bounds for the bounded random chunker.
	defaultBoundedMin = 4 * 1024  // 4KB
	defaultBoundedMax = 64 * 1024 // 64KB
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
	alpha     float64  // Pareto shape parameter
	padSource io.Reader // per-circuit padding CSPRNG or crypto/rand
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
		cfg:       cfg,
		minSize:   minSize,
		maxSize:   maxSize,
		alpha:     paretoAlpha,
		padSource: NewPaddingSource(cfg),
	}
}

// Split divides data into variable-size chunks. Each chunk's size is
// independently sampled from a truncated Pareto distribution in
// [minSize, maxSize]. The final chunk may be smaller than the sampled
// size if insufficient data remains.
//
// When cfg.DebugFixedSizes is true, all chunks are produced at exactly
// maxSize (uniform sizing), bypassing the Pareto sampler. This is the
// debug/testing mode required by CHUNKER_CONTRACT.md §6.5 — it must NOT
// be enabled in production.
func (c *boundedChunker) Split(data []byte) []Chunk {
	if len(data) == 0 {
		return nil
	}

	var chunks []Chunk
	offset := 0

	for offset < len(data) {
		var chunkSize int
		if c.cfg.DebugFixedSizes {
			// Debug mode: force uniform chunk sizing at maxSize.
			chunkSize = c.maxSize
		} else {
			chunkSize = c.sampleParetoSize()
		}
		// Clamp to remaining data.
		remaining := len(data) - offset
		if chunkSize > remaining {
			chunkSize = remaining
		}
		// Ensure minimum chunk size of 1 byte (never produce size-0 chunks).
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
			paddingLen := randomPaddingLen(c.padSource, c.cfg.PaddingMin, c.cfg.PaddingMax)
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
// distribution in [minSize, maxSize] using the per-circuit padSource.
//
// The Pareto distribution CDF: F(x) = 1 - (xm / x)^α  for x >= xm
// Inverse CDF: x = xm / (1 - U)^(1/α)  for U ~ Uniform(0,1)
//
// We use the inverse CDF method: read 8 bytes from padSource as a
// uniform uint64, convert to float64 in [0,1), compute the Pareto
// quantile, then truncate to [minSize, maxSize].
func (c *boundedChunker) sampleParetoSize() int {
	// Read 8 bytes from padSource, interpret as uniform [0,1).
	var buf [8]byte
	if _, err := io.ReadFull(c.padSource, buf[:]); err != nil {
		return c.minSize // fallback on error
	}
	n := binary.BigEndian.Uint64(buf[:])
	// Shift right by 11 to get 53 significant bits, then normalize.
	u := float64(n>>11) / float64(1<<53)

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

// ──────────────────────────────────────────────────────────────────────
// boundedReassembler — delegates to ExitReassembler
// ──────────────────────────────────────────────────────────────────────

// boundedReassembler is a thin wrapper around ExitReassembler. The
// Reassembler interface is chunk-size-agnostic — it operates on
// Chunk.Payload []byte which is variable-length — so the reassembly
// logic is identical regardless of how the Chunker chose payload sizes.
// This wrapper exists only for the registry pattern so exit nodes
// configured for "bounded-4k-64k" find their factory.
type boundedReassembler struct {
	inner *ExitReassembler
}

func newBoundedReassembler(cfg ChunkerConfig) *boundedReassembler {
	return &boundedReassembler{inner: NewExitReassembler(cfg)}
}

func (r *boundedReassembler) Add(chunk Chunk) ([]byte, bool, error) {
	return r.inner.Add(chunk)
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