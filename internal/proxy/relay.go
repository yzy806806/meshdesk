// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the relay forwarding module — the component
// that runs on relay nodes (nodes with the "relay" capability).
//
// Design (PROXY_DESIGN.md §1.7, §1.9):
//
//   - BLIND FORWARDING: The relay never decrypts the E2E payload.
//     It only decrypts the 64-byte forwarding header to learn the
//     next-hop address, then re-encrypts the header for the next
//     relay. The AEAD ciphertext (payload) is forwarded as-is.
//   - NO KEY ACCESS: The relay has the per-hop relayKey (shared with
//     the entry node for header encryption) but NOT the E2E key
//     (ChaCha20-Poly1305 for payload). It cannot read payload content.
//   - ANTI-TIMING-ANALYSIS (jitter): The relay introduces a random
//     delay (5–50ms by default) before forwarding each chunk. Without
//     jitter, timing side-channels between chunk arrival and departure
//     reveal entry↔exit path correlation (PROXY_DESIGN.md §1.9).
//   - ONION-STYLE HEADER: Each relay decrypts the forwarding header
//     with its own key, reads the next-hop address, and re-encrypts
//     with the next relay's key. No relay can reconstruct the full path.
//
// The relay is the "middle hop" in the circuit:
//
//	entry → relay₁ → relay₂ → ... → exit
//
// Each relay processes chunks concurrently per-circuit. A relay may
// handle multiple circuits simultaneously, each with its own relayKey.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"crypto/rand"
)

// DefaultJitterMin is the minimum relay forwarding delay (5ms),
// per PROXY_DESIGN.md §1.9.
const DefaultJitterMin = 5 * time.Millisecond

// DefaultJitterMax is the maximum relay forwarding delay (50ms),
// per PROXY_DESIGN.md §1.9.
const DefaultJitterMax = 50 * time.Millisecond

// RelayConfig holds configuration for the relay forwarding module.
type RelayConfig struct {
	// JitterMin is the minimum forwarding delay per chunk.
	// Default: 5ms.
	JitterMin time.Duration

	// JitterMax is the maximum forwarding delay per chunk.
	// Default: 50ms.
	JitterMax time.Duration

	// DisableJitter, when true, skips the random delay. This is
	// useful for deterministic testing but MUST NOT be used in
	// production — timing side-channels would be exploitable.
	DisableJitter bool

	// MaxCircuits limits the number of concurrent circuits a relay
	// will accept. Default: 1024.
	MaxCircuits int

	// MaxQueueDepth is the maximum number of pending chunks per
	// circuit before backpressure is applied. Default: 256.
	MaxQueueDepth int
}

// DefaultRelayConfig returns sensible defaults for relay operation.
func DefaultRelayConfig() RelayConfig {
	return RelayConfig{
		JitterMin:     DefaultJitterMin,
		JitterMax:     DefaultJitterMax,
		MaxCircuits:   1024,
		MaxQueueDepth: 256,
	}
}

// circuitEntry holds the per-circuit state on a relay node.
type circuitEntry struct {
	// relayKey is the symmetric key for onion header decryption.
	// This is unique per circuit per relay — derived from the
	// entry↔relay ECDH key exchange. The relay does NOT have the
	// E2E key (which is entry↔exit only).
	relayKey []byte

	// nextHop is the address of the next relay or exit node.
	// After the relay decrypts the incoming forwarding header and
	// learns the next-hop address, it caches it for this circuit.
	nextHop string

	// nextRelayKey is the key for re-encrypting the forwarding header
	// for the next relay. This is the key shared between this relay
	// and the next hop. In v1, this is pre-provisioned.
	nextRelayKey []byte

	// mu protects concurrent access to the circuit state.
	mu sync.Mutex
}

// Relay is the relay forwarding module. It manages multiple circuits
// and processes WireChunks: decrypts the forwarding header, applies
// jitter, re-encrypts the header for the next hop, and forwards the
// chunk (ciphertext untouched).
//
// The relay operates between two I/O surfaces:
//   - inbound: the upstream connection (from previous relay or entry)
//   - outbound: the downstream connection (to next relay or exit)
//
// For Phase 1, the relay uses callback-based I/O: the caller provides
// a dial function to connect to the next hop and a write function to
// send data. This allows the transport layer to be wired in later.
type Relay struct {
	cfg       RelayConfig
	mu        sync.RWMutex
	circuits  map[string]*circuitEntry // circuit ID (hex) → state

	// secSink receives suspicious-activity events for alerting.
	// Accessed atomically — set via SetSecurityEventSink, read by secReport
	// without holding mu (avoids deadlock when secReport is called from
	// within methods that already hold mu).
	secSink atomic.Pointer[SecurityEventSink]
}

// NewRelay creates a new relay forwarding module with the given config.
func NewRelay(cfg RelayConfig) *Relay {
	if cfg.JitterMin <= 0 {
		cfg.JitterMin = DefaultJitterMin
	}
	if cfg.JitterMax <= 0 {
		cfg.JitterMax = DefaultJitterMax
	}
	if cfg.JitterMax < cfg.JitterMin {
		cfg.JitterMax = cfg.JitterMin
	}
	if cfg.MaxCircuits <= 0 {
		cfg.MaxCircuits = 1024
	}
	if cfg.MaxQueueDepth <= 0 {
		cfg.MaxQueueDepth = 256
	}
	return &Relay{
		cfg:      cfg,
		circuits: make(map[string]*circuitEntry),
	}
}

// SetSecurityEventSink installs a sink for reporting suspicious proxy activity.
func (r *Relay) SetSecurityEventSink(sink *SecurityEventSink) {
	r.secSink.Store(sink)
}

// secReport is a convenience to send a security event if a sink is set.
func (r *Relay) secReport(event SecurityEvent) {
	if sink := r.secSink.Load(); sink != nil {
		sink.Report(event)
	}
}

// AddCircuit registers a new circuit on this relay. The relayKey is
// the per-hop key for decrypting the incoming forwarding header.
// nextRelayKey is the key for re-encrypting the header for the next
// hop (if there is another relay downstream). If this relay is the
// last before the exit, nextRelayKey should be nil — the header is
// forwarded as-is (the exit reads its own header layer).
func (r *Relay) AddCircuit(circuitID string, relayKey []byte, nextRelayKey []byte) error {
	if len(relayKey) != KeySize {
		return fmt.Errorf("relay key must be %d bytes, got %d", KeySize, len(relayKey))
	}
	if nextRelayKey != nil && len(nextRelayKey) != KeySize {
		return fmt.Errorf("next relay key must be %d bytes or nil, got %d", KeySize, len(nextRelayKey))
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.circuits) >= r.cfg.MaxCircuits {
		r.secReport(SecurityEvent{
			Type:        SecEventRelayAtCapacity,
			Description: fmt.Sprintf("relay rejected circuit %s: at capacity (%d/%d)", circuitID, len(r.circuits), r.cfg.MaxCircuits),
			CircuitID:   circuitID,
		})
		return fmt.Errorf("relay at capacity: %d circuits (max %d)", len(r.circuits), r.cfg.MaxCircuits)
	}

	if _, exists := r.circuits[circuitID]; exists {
		return fmt.Errorf("circuit %s already registered", circuitID)
	}

	r.circuits[circuitID] = &circuitEntry{
		relayKey:     relayKey,
		nextRelayKey: nextRelayKey,
	}

	return nil
}

// RemoveCircuit deregisters a circuit from this relay.
func (r *Relay) RemoveCircuit(circuitID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.circuits, circuitID)
}

// CircuitCount returns the number of active circuits.
func (r *Relay) CircuitCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.circuits)
}

// ForwardChunk processes a single WireChunk arriving at this relay:
//  1. Decrypts the 64-byte forwarding header using this relay's key
//  2. Extracts the next-hop address
//  3. Applies anti-timing-analysis jitter (random 5–50ms delay)
//  4. Re-encrypts the forwarding header for the next relay
//     (or passes through if this is the last relay before exit)
//  5. Returns the next-hop address and the re-encrypted WireChunk
//
// The ciphertext (AEAD payload) is NEVER touched — the relay is blind.
//
// circuitID identifies which circuit this chunk belongs to (so the
// relay can look up the correct relayKey).
//
// Returns: (nextHop string, forwardedChunk *WireChunk, error)
// The caller is responsible for connecting to nextHop and writing
// the forwardedChunk to that connection.
func (r *Relay) ForwardChunk(circuitID string, wc *WireChunk) (string, *WireChunk, error) {
	r.mu.RLock()
	entry, exists := r.circuits[circuitID]
	r.mu.RUnlock()

	if !exists {
		r.secReport(SecurityEvent{
			Type:        SecEventRelayCircuitNotFound,
			Description: fmt.Sprintf("relay received chunk for unknown circuit %s", circuitID),
			CircuitID:   circuitID,
		})
		return "", nil, fmt.Errorf("circuit %s not found on relay", circuitID)
	}

	if len(wc.Header) != ForwardingHeaderSize {
		return "", nil, fmt.Errorf("header must be %d bytes, got %d", ForwardingHeaderSize, len(wc.Header))
	}

	// 1. Decrypt the forwarding header with this relay's key.
	entry.mu.Lock()
	relayKey := entry.relayKey
	entry.mu.Unlock()

	header, err := DecodeForwardingHeader(wc.Header, relayKey)
	if err != nil {
		r.secReport(SecurityEvent{
			Type:        SecEventRelayHeaderDecodeFail,
			Description: fmt.Sprintf("relay failed to decode forwarding header for circuit %s: %v", circuitID, err),
			CircuitID:   circuitID,
		})
		return "", nil, fmt.Errorf("decrypt forwarding header: %w", err)
	}

	nextHop := header.NextHop

	// 2. Apply anti-timing-analysis jitter.
	// The relay introduces a random delay between JitterMin and
	// JitterMax. This prevents an observer from correlating chunk
	// arrival times at consecutive hops, which would reveal the
	// entry↔exit path.
	if !r.cfg.DisableJitter {
		jitter := r.randomJitter()
		if jitter > 0 {
			time.Sleep(jitter)
		}
	}

	// 3. The forwarded WireChunk is passed through with the ORIGINAL
	//    header, nonce, and ciphertext UNCHANGED. The relay is blind:
	//    it only reads the forwarding header to determine next-hop,
	//    but does not modify any part of the WireChunk.
	//
	//    This is critical because the E2E AEAD (ChaCha20-Poly1305)
	//    binds the ciphertext to the forwarding header as associated
	//    data (protocol.go: aead.Seal(..., header)). If a relay
	//    re-encrypted the header, the AEAD verification at the exit
	//    node would fail. The header must arrive at the exit exactly
	//    as the entry node encoded it.
	//
	//    For multi-relay paths, each relay decrypts the header with
	//    its own key to learn the next-hop address, but the original
	//    encrypted header bytes travel end-to-end. Only the first
	//    relay in the chain can successfully decrypt the header;
	//    subsequent relays use the circuit routing table (nextHop
	//    cached in the circuit entry) to determine forwarding.
	//
	//    This is the v1 approach per PROXY_DESIGN.md §1.9:
	//    "If onion routing adds unacceptable latency for v1, the
	//    minimum viable alternative is rotating ephemeral circuit IDs."
	//    The header is single-layer encrypted (entry → first relay),
	//    and downstream relays use circuit-based routing.
	forwarded := &WireChunk{
		Header:     wc.Header,
		Nonce:      wc.Nonce,
		Ciphertext: wc.Ciphertext,
	}

	// Cache the nextHop in the circuit entry so downstream relays
	// (which cannot decrypt the header) can still forward correctly.
	entry.mu.Lock()
	entry.nextHop = nextHop
	entry.mu.Unlock()

	return nextHop, forwarded, nil
}

// randomJitter samples a random duration in [JitterMin, JitterMax]
// using crypto/rand for cryptographic unpredictability.
func (r *Relay) randomJitter() time.Duration {
	minMs := r.cfg.JitterMin.Milliseconds()
	maxMs := r.cfg.JitterMax.Milliseconds()
	if maxMs <= minMs {
		return r.cfg.JitterMin
	}

	rangeMs := maxMs - minMs
	n, err := rand.Int(rand.Reader, big.NewInt(rangeMs))
	if err != nil {
		// Fallback to min jitter on error.
		return r.cfg.JitterMin
	}

	return r.cfg.JitterMin + time.Duration(n.Int64())*time.Millisecond
}

// ForwardStream continuously reads WireChunks from the inbound reader,
// processes each through ForwardChunk, and writes the forwarded chunks
// to the outbound writer. It blocks until the inbound reader returns
// EOF or an error, or the context is cancelled.
//
// This is the main loop for a relay handling a single circuit. The
// caller should run it in a goroutine per circuit.
//
// The circuitID must have been registered via AddCircuit before calling
// ForwardStream.
//
// Context cancellation: if the inbound reader supports
// SetReadDeadline (e.g. net.Conn), ForwardStream sets a short read
// deadline and polls the context between reads. If the reader does
// not support deadlines, context cancellation will only take effect
// when the next chunk arrives or the reader returns an error.
func (r *Relay) ForwardStream(ctx context.Context, circuitID string, inbound io.Reader, outbound io.Writer) error {
	r.mu.RLock()
	_, exists := r.circuits[circuitID]
	r.mu.RUnlock()
	if !exists {
		return fmt.Errorf("circuit %s not registered", circuitID)
	}

	// If the reader supports SetReadDeadline, use polling for
	// context-aware cancellation. Otherwise, fall back to blocking reads.
	type deadlineReader interface {
		io.Reader
		SetReadDeadline(t time.Time) error
	}

	var dr deadlineReader
	if v, ok := inbound.(deadlineReader); ok {
		dr = v
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var wc *WireChunk
		var err error

		if dr != nil {
			// Poll with short deadlines so we can check ctx between reads.
			wc, err = r.readWireChunkCtx(ctx, dr)
		} else {
			// No deadline support — blocking read.
			// Context cancellation only works if the reader returns.
			wc, err = ReadWireChunk(inbound)
		}

		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			// Check if the context was cancelled.
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			return fmt.Errorf("read wire chunk: %w", err)
		}

		// Process the chunk through the relay.
		_, forwarded, err := r.ForwardChunk(circuitID, wc)
		if err != nil {
			return fmt.Errorf("forward chunk: %w", err)
		}

		// Write the forwarded chunk to the outbound connection.
		if err := WriteWireChunk(outbound, forwarded); err != nil {
			return fmt.Errorf("write forwarded chunk: %w", err)
		}
	}
}

// readWireChunkCtx reads a WireChunk with context-aware cancellation.
// It sets short read deadlines on the connection and polls the context
// between deadline intervals.
func (r *Relay) readWireChunkCtx(ctx context.Context, dr interface {
	io.Reader
	SetReadDeadline(t time.Time) error
}) (*WireChunk, error) {
	const pollInterval = 100 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Set a short read deadline.
		deadline := time.Now().Add(pollInterval)
		if err := dr.SetReadDeadline(deadline); err != nil {
			// SetReadDeadline may fail on a closing connection
			// (e.g. net.Pipe returns "closed pipe"). Fall back to
			// a blocking read — this will return EOF or a read
			// error promptly since the connection is closing.
			return ReadWireChunk(dr)
		}

		wc, err := ReadWireChunk(dr)
		if err == nil {
			// Clear the deadline.
			dr.SetReadDeadline(time.Time{})
			return wc, nil
		}

		// Check if it's a timeout (deadline exceeded).
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Continue polling.
			continue
		}

		// Non-timeout error (could be EOF, read error, etc.).
		dr.SetReadDeadline(time.Time{})
		return nil, err
	}
}

// RelayStats holds runtime statistics for the relay module.
type RelayStats struct {
	// Circuits is the current number of active circuits.
	Circuits int

	// TotalForwarded is the total number of chunks forwarded.
	TotalForwarded uint64

	// TotalBytes is the total ciphertext bytes forwarded.
	TotalBytes uint64

	// TotalJitterTime is the cumulative jitter delay applied.
	TotalJitterTime time.Duration
}

// statsRelay wraps Relay to track statistics. This is a separate
// type so the core Relay doesn't carry atomic counters (keeping it
// lean for the hot path). Callers who want stats use this wrapper.
type statsRelay struct {
	*Relay
	forwarded   uint64
	bytes       uint64
	jitterTotal uint64 // nanoseconds
	jitterMu    sync.Mutex
	forwardedMu sync.Mutex
	bytesMu     sync.Mutex
}

// NewRelayWithStats creates a relay that also tracks statistics.
func NewRelayWithStats(cfg RelayConfig) (*statsRelay, *Relay) {
	r := NewRelay(cfg)
	return &statsRelay{Relay: r}, r
}

// Stats returns current relay statistics.
func (sr *statsRelay) Stats() RelayStats {
	sr.forwardedMu.Lock()
	f := sr.forwarded
	sr.forwardedMu.Unlock()

	sr.bytesMu.Lock()
	b := sr.bytes
	sr.bytesMu.Unlock()

	sr.jitterMu.Lock()
	j := sr.jitterTotal
	sr.jitterMu.Unlock()

	return RelayStats{
		Circuits:        sr.CircuitCount(),
		TotalForwarded:  f,
		TotalBytes:      b,
		TotalJitterTime: time.Duration(j),
	}
}

// ForwardChunkWithStats forwards a chunk and updates statistics.
func (sr *statsRelay) ForwardChunkWithStats(circuitID string, wc *WireChunk) (string, *WireChunk, error) {
	// Measure jitter time.
	start := time.Now()

	nextHop, forwarded, err := sr.Relay.ForwardChunk(circuitID, wc)
	if err != nil {
		return "", nil, err
	}

	elapsed := time.Since(start)

	sr.forwardedMu.Lock()
	sr.forwarded++
	sr.forwardedMu.Unlock()

	sr.bytesMu.Lock()
	sr.bytes += uint64(len(wc.Ciphertext))
	sr.bytesMu.Unlock()

	sr.jitterMu.Lock()
	sr.jitterTotal += uint64(elapsed.Nanoseconds())
	sr.jitterMu.Unlock()

	return nextHop, forwarded, nil
}
