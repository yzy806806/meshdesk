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
	"fmt"
	"io"
	"math/rand"
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

	// ExitAddr is the mesh address of the exit node.
	ExitAddr string

	// DebugFixedChunks forces uniform chunk sizes when true (testing).
	DebugFixedChunks bool
}

// Dispatcher manages a single proxy session: it reads from the SS
// connection, chunks the data, and dispatches chunks across two paths.
type Dispatcher struct {
	cfg         DispatcherConfig
	chunker     Chunker
	streamID    uint32
	nextSeq     uint32
	conn        net.Conn // the SS session connection
	closed      bool
	mu          sync.Mutex
	pathStats   pathStats
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

	chunker := NewChunkerWithConfig(strategy, chunkerCfg)

	return &Dispatcher{
		cfg:     cfg,
		chunker: chunker,
		conn:    conn,
	}, nil
}

// Run reads data from the SS connection, chunks it, encrypts each chunk
// with E2E AEAD, adds onion forwarding headers, and dispatches across
// the two paths. It blocks until the connection is closed or an error
// occurs.
//
// In a full implementation, each chunk would be sent over the mesh
// transport (via MeshNode.Dial to the first relay on each path).
// For Phase 1, this function produces the encrypted WireChunks and
// dispatches them via a callback, allowing the caller to wire the
// transport layer.
func (d *Dispatcher) Run(ctx context.Context, sendChunk func(path int, wc *WireChunk) error) error {
	buf := make([]byte, 32*1024) // 32KB read buffer
	pathToggle := 0               // alternate between path 0 and path 1

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
				d.mu.Unlock()

				// Select path (round-robin for v1).
				pathIdx := pathToggle % 2
				pathToggle++

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
				wc, encErr := EncodeChunk(chunk, d.cfg.E2EKey, relayKey, nextHop)
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
			}
		}

		if err != nil {
			if err == io.EOF {
				// Send stream-end marker.
				d.sendStreamEnd(sendChunk, &pathToggle)
				return nil
			}
			return fmt.Errorf("read from SS connection: %w", err)
		}
	}
}

// sendStreamEnd sends a ChunkStreamEnd marker on both paths to signal
// the exit node that the stream is complete.
func (d *Dispatcher) sendStreamEnd(sendChunk func(path int, wc *WireChunk) error, pathToggle *int) {
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

		wc, err := EncodeChunk(endChunk, d.cfg.E2EKey, relayKey, nextHop)
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
func (d *Dispatcher) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.conn.Close()
}

// Stats returns the current dispatch statistics.
func (d *Dispatcher) Stats() (p1Chunks, p2Chunks int, p1Bytes, p2Bytes int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pathStats.p1Chunks, d.pathStats.p2Chunks, d.pathStats.p1Bytes, d.pathStats.p2Bytes
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
				CircuitID:  circuitID,
				Timestamp:  time.Now().UnixNano(),
			}
			// Send on both paths.
			sendKeepalive(0, msg)
			sendKeepalive(1, msg)
		}
	}
}
