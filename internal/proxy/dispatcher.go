// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the entry-side dispatcher: the component that
// receives TCP data from the SS listener, chunks it, and dispatches
// chunks across multiple mesh paths to the exit node.
//
// Responsibilities (PROXY_DESIGN.md §1.1, §1.5, §1.8):
//   - Split incoming TCP stream into chunks (via Chunker)
//   - Select two disjoint paths through relay nodes to the exit
//   - Dispatch chunks across both paths (round-robin or weighted)
//   - Handle path overlap detection (hard requirement: reject circuits
//     where two candidate paths share a relay node)
//   - Encrypt each chunk with E2E AEAD (ChaCha20-Poly1305)
//   - Add onion-encrypted forwarding headers per hop
//   - Handle NACK retransmission requests from the exit
//   - Send keepalive pings every 30s
package proxy

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Path represents a single mesh path from entry to exit through relays.
type Path struct {
	// Relays is the ordered list of relay node IDs (hex public keys)
	// that the chunk passes through, from entry to exit.
	// The entry and exit nodes are NOT included in this list.
	Relays []string

	// RelayKeys is the per-relay symmetric key for onion header encryption.
	// Key at index i is for Relays[i].
	RelayKeys [][]byte
}

// Nodes returns the set of all node IDs on this path (relays only,
// excluding entry and exit — they are implicitly trusted).
func (p *Path) Nodes() map[string]bool {
	set := make(map[string]bool, len(p.Relays))
	for _, r := range p.Relays {
		set[r] = true
	}
	return set
}

// HasOverlap returns true if two paths share any relay node.
// This is the path overlap detection required by PROXY_DESIGN.md §1.5.
func HasOverlap(a, b *Path) bool {
	aNodes := a.Nodes()
	for _, r := range b.Relays {
		if aNodes[r] {
			return true
		}
	}
	return false
}

// DispatcherConfig holds parameters for the entry-side dispatcher.
type DispatcherConfig struct {
	// ChunkerStrategy is the name of the registered chunker strategy.
	// Default: "bounded-4k-64k".
	ChunkerStrategy string

	// ChunkerCfg is the configuration for the chunker.
	ChunkerCfg ChunkerConfig

	// CircuitCfg is the circuit lifecycle configuration.
	CircuitCfg CircuitConfig

	// Path1 and Path2 are the two disjoint paths through relay nodes.
	Path1 *Path
	Path2 *Path

	// E2EKey is the shared ChaCha20-Poly1305 key for E2E encryption.
	E2EKey []byte

	// CircuitID is the 16-byte circuit identifier, bound into each
	// chunk's AEAD plaintext to prevent cross-circuit replay.
	CircuitID []byte

	// ExitAddr is the mesh address of the exit node.
	ExitAddr string

	// DebugFixedChunks forces uniform chunk sizes when true (testing).
	DebugFixedChunks bool

	// AssignmentStrategy controls how chunks are distributed across
	// the two paths. If nil, round-robin is used (v1 default).
	// This implements the ChunkAssignmentStrategy interface from
	// circuit_manager.go (AC-IN-02).
	AssignmentStrategy ChunkAssignmentStrategy
}

// Dispatcher manages a single proxy session: it reads from the SS
// connection, chunks the data, and dispatches chunks across two paths.
type Dispatcher struct {
	cfg        DispatcherConfig
	chunker    Chunker
	chunkerCfg ChunkerConfig // resolved config including padding seed
	streamID   uint32
	nextSeq    uint32
	conn       net.Conn // the SS session connection
	closed     bool
	mu         sync.Mutex
	pathStats  pathStats
	strategy   ChunkAssignmentStrategy // resolved strategy (never nil)
	callCount  int                     // total chunks assigned (for round-robin)
}

type pathStats struct {
	p1Chunks int
	p2Chunks int
	p1Bytes  int64
	p2Bytes  int64
}

// NewDispatcher creates a dispatcher for a single proxy session.
func NewDispatcher(cfg DispatcherConfig, conn net.Conn) (*Dispatcher, error) {
	if cfg.E2EKey == nil || len(cfg.E2EKey) != KeySize {
		return nil, fmt.Errorf("E2E key must be %d bytes", KeySize)
	}
	if cfg.CircuitID == nil || len(cfg.CircuitID) != CircuitIDSize {
		return nil, fmt.Errorf("circuit ID must be %d bytes", CircuitIDSize)
	}
	if cfg.Path1 == nil || cfg.Path2 == nil {
		return nil, fmt.Errorf("two paths are required")
	}
	if HasOverlap(cfg.Path1, cfg.Path2) {
		return nil, fmt.Errorf("path overlap detected: Path1 and Path2 share relay nodes (PROXY_DESIGN.md §1.5 hard requirement)")
	}

	strategy := cfg.ChunkerStrategy
	if strategy == "" {
		strategy = "bounded-4k-64k"
	}
	if cfg.DebugFixedChunks {
		strategy = "fixed-16k"
	}

	chunkerCfg := cfg.ChunkerCfg
	if chunkerCfg.MaxChunkSize == 0 {
		chunkerCfg = DefaultChunkerConfig()
	}

	// Per-circuit padding seed lifecycle (spec §4.2):
	// The entry node generates 32 random bytes as the per-circuit
	// padding seed. This seed is NOT transmitted to the exit — it
	// drives the per-circuit CSPRNG for padding length generation
	// and (for bounded chunker) chunk size sampling. The seed is
	// zeroed on Dispatcher.Close() to prevent key material leakage.
	if len(chunkerCfg.PaddingSeed) == 0 {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("generate padding seed: %w", err)
		}
		chunkerCfg.PaddingSeed = seed
	}

	chunker := NewChunkerWithConfig(strategy, chunkerCfg)

	// Resolve the chunk assignment strategy. If none is provided,
	// default to round-robin (v1 default, AC-CA-01).
	assignmentStrategy := cfg.AssignmentStrategy
	if assignmentStrategy == nil {
		assignmentStrategy = &RoundRobinStrategy{}
	}

	return &Dispatcher{
		cfg:        cfg,
		chunkerCfg: chunkerCfg,
		chunker:    chunker,
		conn:       conn,
		strategy:   assignmentStrategy,
	}, nil
}

// Run reads data from the SS connection, chunks it, encrypts each chunk
// with E2E AEAD, adds onion forwarding headers, and dispatches across
// the two paths. It blocks until the connection is closed or an error
// occurs.
//
// The chunk-to-path assignment is delegated to the configured
// ChunkAssignmentStrategy (round-robin, weighted, or fastest-only).
// This replaces the inline pathToggle from Phase 1 (AC-IN-02).
func (d *Dispatcher) Run(ctx context.Context, sendChunk func(path int, wc *WireChunk) error) error {
	buf := make([]byte, 32*1024) // 32KB read buffer

	// Build CircuitPath snapshots for the assignment strategy.
	// The strategy reads path health and RTT from these objects.
	circuitPaths := d.buildCircuitPaths()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := d.conn.Read(buf)
		if n > 0 {
			// Copy the data (the chunker may retain references).
			data := make([]byte, n)
			copy(data, buf[:n])

			// Chunk the data.
			chunks := d.chunker.Split(data)
			for _, chunk := range chunks {
				// Assign sequence and stream ID.
				d.mu.Lock()
				chunk.StreamID = d.streamID
				chunk.Sequence = d.nextSeq
				d.nextSeq++
				callCount := d.callCount
				d.callCount++
				d.mu.Unlock()

				// Streaming mode: each Split() call produces a partial
				// batch of chunks, not the full stream. Reset Total to 0
				// so the reassembler does not prematurely signal completion.
				chunk.Total = 0

				// Select path via the assignment strategy (AC-IN-02).
				// The strategy considers path health and RTT for weighted
				// decisions. Falls back to round-robin when no RTT data.
				pathIdx := d.strategy.AssignPath(&Circuit{
					Paths:              circuitPaths,
					AssignmentStrategy: d.strategy,
				}, callCount)

				// Get the path and first relay.
				var path *Path
				if pathIdx == 0 {
					path = d.cfg.Path1
				} else {
					path = d.cfg.Path2
				}

				// Determine next hop (first relay, or exit if no relays).
				nextHop := d.cfg.ExitAddr
				var relayKey []byte
				if len(path.Relays) > 0 {
					nextHop = path.Relays[0]
					relayKey = path.RelayKeys[0]
				} else {
					relayKey = d.cfg.E2EKey // direct to exit
				}

				// Encrypt the chunk.
				wc, encErr := EncodeChunk(chunk, d.cfg.E2EKey, relayKey, nextHop, d.cfg.CircuitID)
				if encErr != nil {
					return fmt.Errorf("encode chunk: %w", encErr)
				}

				// Dispatch via callback.
				if sendErr := sendChunk(pathIdx, wc); sendErr != nil {
					return fmt.Errorf("send chunk: %w", sendErr)
				}

				// Update stats.
				d.mu.Lock()
				if pathIdx == 0 {
					d.pathStats.p1Chunks++
					d.pathStats.p1Bytes += int64(len(chunk.Payload))
				} else {
					d.pathStats.p2Chunks++
					d.pathStats.p2Bytes += int64(len(chunk.Payload))
				}
				d.mu.Unlock()

				// Update circuit path stats for the strategy.
				circuitPaths[pathIdx].RecordChunk(len(chunk.Payload))
			}
		}

		if err != nil {
			if err == io.EOF {
				// Send stream-end marker.
				d.sendStreamEnd(sendChunk)
				return nil
			}
			return fmt.Errorf("read from SS connection: %w", err)
		}
	}
}

// buildCircuitPaths creates CircuitPath snapshots from the dispatcher's
// Path1 and Path2 for the assignment strategy to read.
func (d *Dispatcher) buildCircuitPaths() [2]*CircuitPath {
	now := time.Now()
	var result [2]*CircuitPath
	for i, p := range []*Path{d.cfg.Path1, d.cfg.Path2} {
		if p == nil {
			continue
		}
		result[i] = &CircuitPath{
			Index:         i,
			Hops:          append([]string{}, p.Relays...),
			RelayKeys:     p.RelayKeys,
			Health:        PathHealthHealthy,
			EstablishedAt: now,
		}
	}
	return result
}

// sendStreamEnd sends a ChunkStreamEnd marker on both paths to signal
// the exit node that the stream is complete.
func (d *Dispatcher) sendStreamEnd(sendChunk func(path int, wc *WireChunk) error) {
	d.mu.Lock()
	endChunk := Chunk{
		StreamID: d.streamID,
		Sequence: d.nextSeq,
		Type:     ChunkStreamEnd,
	}
	d.nextSeq++
	d.mu.Unlock()

	for _, pathIdx := range []int{0, 1} {
		var path *Path
		if pathIdx == 0 {
			path = d.cfg.Path1
		} else {
			path = d.cfg.Path2
		}

		nextHop := d.cfg.ExitAddr
		var relayKey []byte
		if len(path.Relays) > 0 {
			nextHop = path.Relays[0]
			relayKey = path.RelayKeys[0]
		} else {
			relayKey = d.cfg.E2EKey
		}

		wc, err := EncodeChunk(endChunk, d.cfg.E2EKey, relayKey, nextHop, d.cfg.CircuitID)
		if err != nil {
			continue
		}
		sendChunk(pathIdx, wc)
	}
}

// HandleNACK processes a retransmission request from the exit node.
// The exit sends a NACK when it detects a gap in the sequence window
// beyond NACKTimeout.
//
// In a full implementation, the dispatcher would need to buffer sent
// chunks for retransmission. For Phase 1, this is a placeholder that
// logs the NACK — full retransmission is Phase 2.
func (d *Dispatcher) HandleNACK(nack *NACKMsg) error {
	// Phase 1: log NACK, do not retransmit.
	// Phase 2: retransmit missing chunks from a send buffer.
	return nil
}

// Close shuts down the dispatcher and closes the SS connection.
// It also zeros the per-circuit padding seed to prevent key material
// leakage after the circuit is torn down (spec §4.2 lifecycle).
func (d *Dispatcher) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true

	// Zero the padding seed (spec §4.2: destruction step).
	// This overwrites the 32-byte seed in the resolved chunker config
	// so it cannot be recovered from memory after circuit teardown.
	if len(d.chunkerCfg.PaddingSeed) > 0 {
		for i := range d.chunkerCfg.PaddingSeed {
			d.chunkerCfg.PaddingSeed[i] = 0
		}
	}

	return d.conn.Close()
}

// Stats returns the current dispatch statistics.
func (d *Dispatcher) Stats() (p1Chunks, p2Chunks int, p1Bytes, p2Bytes int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pathStats.p1Chunks, d.pathStats.p2Chunks, d.pathStats.p1Bytes, d.pathStats.p2Bytes
}

// PaddingSeed returns a copy of the per-circuit padding seed.
// Used for verification and testing (spec §4.2 contract tests).
func (d *Dispatcher) PaddingSeed() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.chunkerCfg.PaddingSeed) == 0 {
		return nil
	}
	cp := make([]byte, len(d.chunkerCfg.PaddingSeed))
	copy(cp, d.chunkerCfg.PaddingSeed)
	return cp
}

// SelectPaths selects two disjoint paths from a set of candidate relays.
// This implements the path selection algorithm from PROXY_DESIGN.md §1.5:
//   - Phase 1 (Manual config): paths are specified in config file.
//   - Path overlap detection is a hard requirement.
//
// For Phase 1, this function validates that the provided paths are
// disjoint. For Phase 2, it will implement automatic selection based
// on latency probing.
func SelectPaths(candidates []string, exitAddr string, maxRelaysPerPath int) (*Path, *Path, error) {
	if len(candidates) < 2 {
		return nil, nil, fmt.Errorf("need at least 2 relay candidates, got %d", len(candidates))
	}

	// Phase 1: pick the first two candidates as single-hop paths.
	// Each path goes: entry → relay → exit.
	// For multi-hop paths, the caller provides the full relay list.

	// Simple selection: assign candidates round-robin to two paths.
	var path1Relays, path2Relays []string
	for i, relay := range candidates {
		if i%2 == 0 && len(path1Relays) < maxRelaysPerPath {
			path1Relays = append(path1Relays, relay)
		} else if len(path2Relays) < maxRelaysPerPath {
			path2Relays = append(path2Relays, relay)
		}
	}

	if len(path1Relays) == 0 || len(path2Relays) == 0 {
		return nil, nil, fmt.Errorf("insufficient relays for two paths")
	}

	// Generate relay keys (random for Phase 1 — in production these
	// are derived from per-relay ECDH key exchange).
	path1Keys := make([][]byte, len(path1Relays))
	path2Keys := make([][]byte, len(path2Relays))
	for i := range path1Keys {
		path1Keys[i] = make([]byte, KeySize)
		rand.Read(path1Keys[i])
	}
	for i := range path2Keys {
		path2Keys[i] = make([]byte, KeySize)
		rand.Read(path2Keys[i])
	}

	path1 := &Path{Relays: path1Relays, RelayKeys: path1Keys}
	path2 := &Path{Relays: path2Relays, RelayKeys: path2Keys}

	if HasOverlap(path1, path2) {
		return nil, nil, fmt.Errorf("selected paths overlap (should not happen with round-robin assignment)")
	}

	return path1, path2, nil
}

// KeepaliveLoop sends periodic keepalive pings to prevent idle timeout
// and measure RTT. Should be run in a goroutine alongside Run().
func (d *Dispatcher) KeepaliveLoop(ctx context.Context, sendKeepalive func(path int, msg *KeepaliveMsg) error) {
	ticker := time.NewTicker(d.cfg.CircuitCfg.KeepaliveInterval)
	defer ticker.Stop()

	circuitID := make([]byte, CircuitIDSize)
	rand.Read(circuitID)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			msg := &KeepaliveMsg{
				CircuitID: circuitID,
				Timestamp: time.Now().UnixNano(),
			}
			// Send on both paths.
			sendKeepalive(0, msg)
			sendKeepalive(1, msg)
		}
	}
}
