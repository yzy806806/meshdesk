// Package proxy implements the MeshDesk anonymous proxy system — multi-path
// dispersed transport, circuit management, relay forwarding, and exit-side
// reassembly. See docs/PROXY_DESIGN.md for the architecture.
//
// This file defines the Chunker/Reassembler abstraction: the pluggable
// interface contract for splitting data streams into chunks on the entry
// side and reconstructing them on the exit side. Concrete implementations
// (fixed 16KB, bounded random 4KB–64KB, etc.) self-register via init().
package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Sentinal errors returned by Reassembler.Add when resource limits are hit.
// ──────────────────────────────────────────────────────────────────────────────

var (
	// ErrReassemblyChunksExceeded is returned when a stream accumulates
	// more chunks than MaxReassemblyChunks allows.
	ErrReassemblyChunksExceeded = errors.New("proxy: reassembly chunk limit exceeded")

	// ErrReassemblyBytesExceeded is returned when total buffered bytes
	// across all in-progress streams exceeds MaxReassemblyBytes.
	ErrReassemblyBytesExceeded = errors.New("proxy: reassembly byte limit exceeded")

	// ErrStreamTimeout is returned when a stream's reassembly has not
	// completed within StreamReassemblyTimeout. The caller should
	// discard the stream and signal upstream that the circuit is dead.
	// This prevents the relay/exit from deadlocking when chunks are
	// lost or the entry node never sends a ChunkStreamEnd marker.
	ErrStreamTimeout = errors.New("proxy: stream reassembly timeout")
)

// ──────────────────────────────────────────────────────────────────────────────
// ChunkType constants
// ──────────────────────────────────────────────────────────────────────────────

// ChunkType classifies a chunk's role in the stream lifecycle.
type ChunkType byte

const (
	// ChunkData carries a segment of the application data stream.
	ChunkData ChunkType = 0x01

	// ChunkStreamEnd marks the last chunk of a stream. After receiving
	// this chunk, the reassembler delivers the completed stream and
	// discards the reassembly buffer.
	ChunkStreamEnd ChunkType = 0x02

	// ChunkPadding is a padding-only chunk that carries no application
	// data. Used for anti-fingerprinting: injecting dummy chunks into
	// the stream to obscure true data volume.
	ChunkPadding ChunkType = 0x03

	// ChunkStreamStart is reserved for future use (e.g. stream metadata).
	ChunkStreamStart ChunkType = 0x04
)

// ──────────────────────────────────────────────────────────────────────
// Chunk struct
// ──────────────────────────────────────────────────────────────────────────────
//
// TRUST BOUNDARY: Chunk is the IN-MEMORY represention of a chunk fragment.
// It exists ONLY inside the trust boundry of the entry or exit node:
//   - Entry side: produced by Chunker.Split BEFORE encryption
//   - Exit side:  consumed by Reassembler.Add AFTER decryption
//
// On the wire, ALL metadata fields (StreamID, Sequence, Total, Type,
// PaddingLen) are serialized into the AEAD plaintext and encrypted
// end-to-end with ChaCha20-Poly1305. Intermediate relays NEVER see
// this metadata — they only see the onion-encrypted forwarding header
// and the opaque ciphertext.
//
// Wire encoding/decoding is handled by EncodeChunk / DecodeChunk in
// protocol.go. The Chunk struct MUST NOT be serialized directly for
// inter-node transfer.
type Chunk struct {
	// StreamID identifies which stream this chunk belongs to. A circuit
	// may carry multiple concurent streams (e.g. concurent TCP
	// connections through the same entry↔exit pair).
	StreamID uint32

	// Sequence is the monotonic, 0-based position of this chunk within
	// its stream. Gaps in the sequence indicate lost or delayed chunks.
	Sequence uint32

	// Total is the total number of chunks in this stream. A value of 0
	// means "unknown" — the stream is still being produced (streaming
	// mode). The exit-side Reassembler uses Total to know when all chunks
	// have arrived without waiting for a ChunkStreamEnd marker.
	Total uint32

	// Type classifies the chunk for the reassembly state machine.
	Type ChunkType

	// Payload is the application data carried by this chunk. Its length
	// is determined by the Chunker implementation and may vary between
	// chunks (e.g. 4KB–64KB in bounded-random mode). The Reassembler
	// MUST NOT assume a fixed payload size.
	Payload []byte

	// PaddingLen records how many bytes of random padding were appened
	// to the wire represention of this chunk. This is informational —// the padding is already stripped before the Reassembler sees the
	// Payload. Implementations use this for wire-size accounting.
	PaddingLen uint16
}

// ──────────────────────────────────────────────────────────────────────────────
// Chunker interface
// ──────────────────────────────────────────────────────────────────────────────

// Chunker splits an application data stream into Chunks for multi-path
// transport. Implementations control chunk sizing, padding, and
// stream-lifecycle markers (ChunkStreamEnd, etc.).
//
// Split may be called multiple times for the same stream as data arrives
// from the application. Each call produces zero or more Chunks. A call
// that produces zero Chunks is valid — for example, a Chunker that buffers
// data until a minimum chunk size is reached.
//
// Implementations must be safe for concurent use by a single goroutine.
// If shared across goroutines, the caller is responsible for
// synchronization.
type Chunker interface {
	// Split splits a contigous segment of the application data stream
	// into Chunks. The data argument represents newly arrived bytes for
	// the current stream. Implementations may buffer internally and
	// produce multiple Chunks, a single Chunk, or no Chunks at all.
	//
	// The caller owns the returned slice. Implementations should not
	// retain references to the data argument after Split returns.
	//
	// NOTE: Chunks produced by Split are plaintext — the caller MUST
	// encrypt them via EncodeChunk (protocol.go) before sending them
	// over the wire.
	Split(data []byte) []Chunk
}

// ──────────────────────────────────────────────────────────────────────────────
// Reassembler interface
// ──────────────────────────────────────────────────────────────────────────────

// Reassembler reconstructs the original application data stream from
// received Chunks. It handles out-of-order arrival (sorting by Sequence),
// deduplication (same Sequence + StreamID), and signals completion when
// all chunks have arrived.
//
// Add returns (complete, done, err) where:
//   - complete is the reassembled stream bytes, only non-nil when done
//     is true
//   - done is true when the stream is fully reassembled (all chunks
//     received and sorted)
//   - err is non-nil when a resource limit is exceeded or the chunk
//     is malformed
//
// If a Chunk with ChunkStreamEnd is received, the stream is complete
// regarless of Total. If Total is set and all chunks from 0..Total-1
// have been received, the stream is also complete.
//
// Implementations must be safe for concurent use by a single goroutine.
// If shared across goroutines, the caller is responsible for
// synchronization.
//
// BOUNDS ENFORCEMENT: Implementations MUST enforce MaxReassemblyChunks
// and MaxReassemblyBytes from ChunkerConfig. When a limit is exceeded,
// Add returns an error and the offending chunk is discarded. The
// reassembly buffer for the affected stream is NOT automatically purged —
// the caller should discard the stream on error.
type Reassembler interface {
	// Add receives a Chunk and incorporates it into the reassembly state.
	// Returns the complete reassembled stream when all chunks have arrived,
	// or (nil, false, nil) if more chunks are expected. Returns a non-nil
	// error when resource limits are breached.
	Add(chunk Chunk) (complete []byte, done bool, err error)
}

// ──────────────────────────────────────────────────────────────────────────────
// Factory types and registries
// ──────────────────────────────────────────────────────────────────────────────

// ChunkerFactory constructs a Chunker from configuration.
// The factory pattern allows new chunking strategies to be registered
// and selected by name, mirroring the obfuscation registry in mesh.
type ChunkerFactory func(cfg ChunkerConfig) Chunker

// ReassemblerFactory constructs a Reassembler from configuration.
// The factory pattern exists alongside ChunkerFactory so that entry
// and exit nodes can independently construct their half of the pair.
type ReassemblerFactory func(cfg ChunkerConfig) Reassembler

// ──────────────────────────────────────────────────────────────────────
// ChunkerConfig
// ──────────────────────────────────────────────────────────────────────────────

// DefaultMaxReassemblyChunks is the maximum number of chunks per stream
// when no explicit limit is configured in ChunkerConfig.
const DefaultMaxReassemblyChunks = 2048

// DefaultMaxReassemblyBytes is the maximum total buffered payload bytes
// across all streams when no explicit limit is configured.
const DefaultMaxReassemblyBytes = 32 * 1024 * 1024 // 32 MB

// ChunkerConfig holds the parameters that control chunking behavior.
// All Chunker/Reassembler implementations receive this configuration;
// individual implementations interpret the fields relevant to their
// strategy and ignore the rest.
type ChunkerConfig struct {
	// MaxChunkSize is the maximum payload size in bytes. The Chunker
	// must not produce chunks with payloads larger than this value.
	// For fixed-size chunkers, this is the exact payload size. For
	// variable-size chunkers, this is the upper bound of the range.
	MaxChunkSize int

	// MinChunkSize is the minimum payload size in bytes. Only relevant
	// for variable-size (bounded random) chunkers; fixed-size
	// implementations ignore this field.
	MinChunkSize int

	// PaddingMin is the minimum number of random padding bytes added to
	// each chunk's wire represention. Zero means no padding minimum.
	PaddingMin int

	// PaddingMax is the maximum number of random padding bytes added to
	// each chunk's wire represention. Must be >= PaddingMin. Zero
	// means no padding.
	PaddingMax int

	// DisablePadding, when true, suppresses all padding. Useful for
	// deterministic testing and debugging. Overides PaddingMin/PaddingMax.
	DisablePadding bool

	// DebugFixedSizes, when true, forces uniform chunk sizing equal to
	// MaxChunkSize. Off by default in production. Used for deterministic
	// testing where variable chunk sizes would make assertions flaky.
	DebugFixedSizes bool

	// PaddingSeed is an optional 32-byte seed for per-circuit deterministic
	// padding. When set (len > 0), the Chunker derives a CSPRNG from this
	// seed instead of calling crypto/and on every chunk. This provides:
	//
	//   1. Per-circuit padding isolation: different circuits with different
	//      seeds produce uncorrelated padding streams. A passive adversary
	//      cannot corrolate padding patterns across circuits.
	//   2. Deterministic replay for debugging: capturing the seed allows
	//      exact reproduction of the padding sequence for a circuit.
	//   3. Reduced kernel entropy consumption: a single syscall at circuit
	//      setup replaces per-chunk crypto/and reads.
	//
	// When nil (default), crypto/and.Reader is used directly.
	// See NewPaddingSource for the CSPRNG constructon helper.
	PaddingSeed []byte

	// MaxReassemblyChunks is the maximum number of chunks that can be
	// buffered for a single stream during reassembly. When a chunk would
	// push the chunk count for a stream above this limit, Add returns
	// ErrReassemblyChunksExceeded. Zero means no limit (testing only;
	// production must set this).
	MaxReassemblyChunks int

	// MaxReassemblyBytes is the maximum total payload bytes that can be
	// buffered across all in-progress streams being reassembled. When
	// a chunk would push the total above this limit, Add returns
	// ErrReassemblyBytesExceeded. Zero means no limit.
	MaxReassemblyBytes int

	// StreamReassemblyTimeout is the maximum duration a stream may
	// remain in-progress (not yet complete) before it is considered
	// timed out. When ExpireStreams is called, any stream whose
	// first-chunk timestamp is older than now - StreamReassemblyTimeout
	// is purged and the caller receives ErrStreamTimeout for each.
	//
	// Zero means no timeout (streams persist indefinitely). This is
	// appropriate for testing but MUST NOT be used in production —
	// without a timeout, a stream that never receives its
	// ChunkStreamEnd or all Total chunks will buffer forever,
	// potentially causing a relay/exit deadlock.
	StreamReassemblyTimeout time.Duration
}

// DefaultStreamReassemblyTimeout is the default maximum duration a
// stream may remain in-progress before being considered timed out.
// This is conservative: most legitimate streams complete in well
// under 30 seconds. The value must be long enough to accommodate
// legitimate retransmission delays but short enough to prevent
// unbounded resource consumption from abandoned streams.
const DefaultStreamReassemblyTimeout = 30 * time.Second

// DefaultChunkerConfig returns a ChunkerConfig suitable for the v1
// fixed-16KB chunking strategy with per-chunk random padding (1–4KB)
// and production-grade reassembly bounds.
func DefaultChunkerConfig() ChunkerConfig {
	return ChunkerConfig{
		MaxChunkSize:            16 * 1024,
		MinChunkSize:            16 * 1024,
		PaddingMin:              1024,
		PaddingMax:              4 * 1024,
		MaxReassemblyChunks:     DefaultMaxReassemblyChunks,
		MaxReassemblyBytes:      DefaultMaxReassemblyBytes,
		StreamReassemblyTimeout: DefaultStreamReassemblyTimeout,
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// NewPaddingSource — per-circuit deterministic CSPRNG for padding
// ──────────────────────────────────────────────────────────────────────────────

// padSource implements io.Reader as a determinisitc CSPRNG backed by
// AES-256-CTR. The key is derived from PaddingSeed via SHA-256.
type padSource struct {
	stream cipher.Stream
}

func (s *padSource) Read(p []byte) (int, error) {
	// XOR with zeros to generate the key stream.
	for i := range p {
		p[i] = 0
	}
	s.stream.XORKeyStream(p, p)
	return len(p), nil
}

// NewPaddingSource returns an io.Reader suitable for generating per-chunk
// padding bytes. When cfg.PaddingSeed is set, returns a determinisitc
// CSPRNG seeded from that value — different seeds produce independent,
// uncorrelated streams. When PaddingSeed is nil, returns crypto/and.Reader.
//
// Usage in Chunker implementations:
//
//	pad := NewPaddingSource(cfg)
//	buf := make([]byte, paddingLen)
//	io.ReadFull(pad, buf)
//
// The returned io.Reader is safe for concurent use (AES-CTR via
// cipher.Stream is not goroutine-safe; callers must serialize access
// or create one padSource per goroutine).
func NewPaddingSource(cfg ChunkerConfig) io.Reader {
	if len(cfg.PaddingSeed) == 0 {
		return rand.Reader
	}
	// Derive a 32-byte AES-256 key from the seed via SHA-256.
	key := sha256.Sum256(cfg.PaddingSeed)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		// This should never happen with a 32-byte key.
		return rand.Reader
	}
	// Zero IV is safe here because the key is unique per circuit
	// (PaddingSeed is different for each circuit).
	iv := make([]byte, aes.BlockSize)
	return &padSource{stream: cipher.NewCTR(block, iv)}
}

// ──────────────────────────────────────────────────────────────────────
// ChunkerRegistry
// ──────────────────────────────────────────────────────────────────────

// ChunkerRegistry is the global registry of chunking strategy factories.
// Strategies self-register via init() calling RegisterChunker. The
// registry indrection allows adding new chunking strategies without
// modifying core dispatch code, mirroring the ObfuscatorRegistry in
// the mesh package.
var ChunkerRegistry = &chunkerRegistry{
	factories: &sync.Map{},
}

// chunkerRegistry wraps a sync.Map of strategy-name → ChunkerFactory.
type chunkerRegistry struct {
	factories *sync.Map
}

// RegisterChunker registers a Chunker factory under the given name.
// Registering the same name twice panics, catching duplicate
// registrations at program start. Names should be stable identifiers
// suitable for configurtion files (e.g. "fixed-16k", "bounded-4k-64k").
func RegisterChunker(name string, factory ChunkerFactory) {
	if _, loaded := ChunkerRegistry.factories.LoadOrStore(name, factory); loaded {
		panic(fmt.Sprintf("proxy: duplicate chunker registration for %q", name))
	}
}

// Get looks up the Chunker factory for the named strategy.
// Returns the factory and true if found, or nil and false otherwise.
func (r *chunkerRegistry) Get(name string) (ChunkerFactory, bool) {
	v, ok := r.factories.Load(name)
	if !ok {
		return nil, false
	}
	return v.(ChunkerFactory), true
}

// MustGet is like Get but panics if the strategy is not registered.
// Useful in init-time paths where a missing registration indicates a
// programming error.
func (r *chunkerRegistry) MustGet(name string) ChunkerFactory {
	f, ok := r.Get(name)
	if !ok {
		panic(fmt.Sprintf("proxy: chunker strategy %q not registered", name))
	}
	return f
}

// Names returns all registered chunking strategy names.
// The order is non-deterministic (sync.Map iteration).
func (r *chunkerRegistry) Names() []string {
	var names []string
	r.factories.Range(func(key, _ any) bool {
		names = append(names, key.(string))
		return true
	})
	return names
}

// NewChunker creates a Chunker for the named strategy with default config.
func NewChunker(name string) Chunker {
	return NewChunkerWithConfig(name, DefaultChunkerConfig())
}

// NewChunkerWithConfig creates a Chunker with a specific configuration.
// If the named strategy is not registered, it falls back to "fixed-16k"
// (the v1 default). If even that is not registered, it panics.
func NewChunkerWithConfig(name string, cfg ChunkerConfig) Chunker {
	factory, ok := ChunkerRegistry.Get(name)
	if !ok {
		factory = ChunkerRegistry.MustGet("fixed-16k")
	}
	return factory(cfg)
}

// ──────────────────────────────────────────────────────────────────────
// ReassemblerRegistry
// ──────────────────────────────────────────────────────────────────────

// ReassemblerRegistry is the global registry of reassembler factories.
// Strategies self-register via init() calling RegisterReassembler.
// Paired with ChunkerRegistry so entry and exit nodes can independently
// construct their half of the chunking contract.
var ReassemblerRegistry = &reassemblerRegistry{
	factories: &sync.Map{},
}

// reassemblerRegistry wraps a sync.Map of strategy-name → ReassemblerFactory.
type reassemblerRegistry struct {
	factories *sync.Map
}

// RegisterReassembler registers a Reassembler factory under the given name.
// The name must match a corresponsing Chunker registration. Registering
// the same name twice panics.
func RegisterReassembler(name string, factory ReassemblerFactory) {
	if _, loaded := ReassemblerRegistry.factories.LoadOrStore(name, factory); loaded {
		panic(fmt.Sprintf("proxy: duplicate reassembler registration for %q", name))
	}
}

// Get looks up the Reassembler factory for the named strategy.
func (r *reassemblerRegistry) Get(name string) (ReassemblerFactory, bool) {
	v, ok := r.factories.Load(name)
	if !ok {
		return nil, false
	}
	return v.(ReassemblerFactory), true
}

// MustGet is like Get but panics if the strategy is not registered.
func (r *reassemblerRegistry) MustGet(name string) ReassemblerFactory {
	f, ok := r.Get(name)
	if !ok {
		panic(fmt.Sprintf("proxy: reassembler strategy %q not registered", name))
	}
	return f
}

// Names returns all registered reassembler strategy names.
func (r *reassemblerRegistry) Names() []string {
	var names []string
	r.factories.Range(func(key, _ any) bool {
		names = append(names, key.(string))
		return true
	})
	return names
}

// NewReassembler creates a Reassembler for the named strategy with default config.
func NewReassembler(name string) Reassembler {
	return NewReassemblerWithConfig(name, DefaultChunkerConfig())
}

// NewReassemblerWithConfig creates a Reassembler with a specific configuration.
func NewReassemblerWithConfig(name string, cfg ChunkerConfig) Reassembler {
	factory, ok := ReassemblerRegistry.Get(name)
	if !ok {
		factory = ReassemblerRegistry.MustGet("fixed-16k")
	}
	return factory(cfg)
}
