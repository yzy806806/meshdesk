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
	"encoding/binary"
	"io"
)

const fixed16kName = "fixed-16k"

// fixedChunker splits data into uniform MaxChunkSize-byte chunks.
// It is the simplest conformant Chunker implementation and serves
// as the v1 baseline.
type fixedChunker struct {
	cfg       ChunkerConfig
	streamID  uint32
	nextSeq   uint32
	total     uint32 // set by SetTotal if known, 0 = unknown
	totalSet  bool
	padSource io.Reader // per-circuit padding CSPRNG or crypto/rand
}

func newFixedChunker(cfg ChunkerConfig) *fixedChunker {
	if cfg.MaxChunkSize <= 0 {
		cfg.MaxChunkSize = 16 * 1024
	}
	if cfg.MinChunkSize <= 0 {
		cfg.MinChunkSize = cfg.MaxChunkSize
	}
	return &fixedChunker{
		cfg:       cfg,
		padSource: NewPaddingSource(cfg),
	}
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

// randomPaddingLen returns a random padding length in [min, max] using
// the supplied io.Reader (either a per-circuit CSPRNG or crypto/rand).
// This is a package-level helper shared by all Chunker implementations.
func randomPaddingLen(src io.Reader, min, max int) int {
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

	// Read 8 bytes, interpret as uint64, mod into range.
	var buf [8]byte
	if _, err := io.ReadFull(src, buf[:]); err != nil {
		return min // fallback on error
	}
	n := binary.BigEndian.Uint64(buf[:])
	return min + int(n%uint64(rangeSize))
}

// ──────────────────────────────────────────────────────────────────────
// fixedReassembler — delegates to ExitReassembler
// ──────────────────────────────────────────────────────────────────────

// fixedReassembler is a thin wrapper around ExitReassembler that implements
// the Reassembler interface for the "fixed-16k" strategy. The reassembly
// logic is chunk-size-agnostic, so there is no need for a separate
// implementation — all strategies share the same ExitReassembler core.
//
// The wrapper exists to maintain backward compatibility with the registry
// pattern: callers that request "fixed-16k" get a Reassembler that works
// identically to the ExitReassembler.
type fixedReassembler struct {
	inner *ExitReassembler
}

func newFixedReassembler(cfg ChunkerConfig) *fixedReassembler {
	return &fixedReassembler{inner: NewExitReassembler(cfg)}
}

func (r *fixedReassembler) Add(chunk Chunk) ([]byte, bool, error) {
	return r.inner.Add(chunk)
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
