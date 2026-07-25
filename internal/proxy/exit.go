// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the exit node module — the component that runs on
// nodes with the "exit" capability. The exit node is the termination point
// of the multi-path circuit: it receives AEAD-encrypted WireChunks from
// relay nodes, decrypts them with the E2E key, reassembles the original
// data stream (handling out-of-order arrival, deduplication, packet loss,
// and timeout), and forwards the reconstructed data to the target TCP
// connection.
//
// Design (PROXY_DESIGN.md §1.1, §1.3, §1.7, §1.8):
//
//   - CIRCUIT SETUP: The entry node sends a CircuitSetup message (ECDH
//     pubkey + target address). The exit performs ECDH, derives the shared
//     ChaCha20-Poly1305 key, validates the target port, and establishes a
//     TCP connection to the target. It sends back a CircuitAck.
//   - REASSEMBLY BUFFER: The exit maintains a per-circuit, per-stream
//     reassembly buffer with a sliding window. Chunks may arrive out of
//     order (different paths have different latencies), duplicated
//     (retransmission), or not at all (packet loss).
//   - DoS PROTECTION: A hard limit (MaxReassemblyWindow, default 256)
//     prevents an attacker from exhausting exit memory with sparse sequence
//     numbers. Chunks whose sequence is more than MaxReassemblyWindow ahead
//     of the highest contiguous sequence are rejected.
//   - NACK GENERATION: When a gap is detected in the sequence window and
//     the gap persists beyond NACKTimeout (default 5s), the exit sends a
//     NACK listing the missing sequence numbers back to the entry.
//   - ON-DEMAND PATH TRACKER: The exit records which path each chunk
//     arrived on, but only tracks paths that are actually in use. This
//     avoids O(N²) expansion when many circuits share the same relay
//     infrastructure — each circuit's path set is bounded by the number
//     of disjoint paths (typically 2), not the total relay count.
//   - ORPHAN CLEANUP: If a circuit's reassembly buffer is incomplete and
//     no new chunks arrive for OrphanTimeout (default 30s), the buffer is
//     discarded to prevent memory leaks from abandoned circuits.
//   - TARGET TCP: The exit dials the target address after circuit setup.
//     Reassembled data is written to the target connection. Responses from
//     the target are chunked and sent back through the circuit.
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ExitConfig holds configuration for the exit node module.
// This mirrors the proxy.CircuitConfig but is exposed at the exit level
// for operator configuration.
type ExitConfig struct {
	// CircuitCfg holds circuit lifecycle parameters (timeouts, window size).
	CircuitCfg CircuitConfig

	// AllowedPorts restricts which destination ports the exit will connect
	// to. If empty, all ports are allowed (subject to AllowAllPorts).
	// Typically [80, 443] for safety.
	AllowedPorts []int

	// AllowAllPorts removes the port restriction entirely.
	// WARNING: full legal exposure. Not recommended.
	AllowAllPorts bool

	// ChunkerStrategy selects the reassembler strategy name.
	// Must match a registered ReassemblerFactory. Default: "bounded-4k-64k".
	ChunkerStrategy string

	// ChunkerCfg is the configuration passed to the reassembler.
	ChunkerCfg ChunkerConfig

	// DebugFixedChunks forces uniform chunk sizing for deterministic testing.
	// Maps to the "fixed-16k" strategy. Must be off in production.
	DebugFixedChunks bool

	// Dialer is the function used to dial target TCP connections.
	// If nil, net.Dial is used. This allows tests to inject mock connections
	// and production to use custom dialers (e.g. with TPROXY or binding
	// to specific source IPs).
	Dialer func(network, addr string) (net.Conn, error)
}

// DefaultExitConfig returns sensible defaults for exit node operation.
func DefaultExitConfig() ExitConfig {
	return ExitConfig{
		CircuitCfg:      DefaultCircuitConfig(),
		AllowedPorts:    []int{80, 443},
		ChunkerStrategy: "bounded-4k-64k",
		ChunkerCfg:      DefaultChunkerConfig(),
	}
}

// exitCircuit holds the per-circuit state on an exit node.
type exitCircuit struct {
	// circuitID is the hex-encoded circuit identifier.
	circuitID string

	// circuitIDBytes is the raw 16-byte circuit identifier, used for
	// AEAD plaintext verification in DecodeChunk.
	circuitIDBytes []byte

	// e2eKey is the shared ChaCha20-Poly1305 key derived from ECDH.
	e2eKey []byte

	// targetConn is the TCP connection to the destination.
	// Established during circuit setup.
	targetConn net.Conn

	// targetAddr is the destination host:port.
	targetAddr string

	// reassembler reconstructs the original data stream from chunks.
	// Typed as ExitReassembler (not the Reassembler interface) so we can
	// use AddStreaming for incremental delivery and NextExpected for
	// correct ackBase advancement.
	reassembler *ExitReassembler

	// mu protects concurrent access to circuit state.
	mu sync.Mutex

	// pathTracker tracks which paths have delivered chunks to this circuit.
	// This is on-demand: only paths that have actually delivered at least
	// one chunk appear here. Bounded by the number of disjoint paths (2),
	// not the total relay count — avoids O(N²) expansion.
	pathTracker *pathTracker

	// ackBase is the highest contiguous sequence number received
	// (all sequences 0..ackBase-1 have been received). Used for
	// window-based ACK and NACK gap detection.
	ackBase uint32

	// gapDetected tracks whether a gap has been detected and when.
	// If a gap persists beyond NACKTimeout, a NACK is sent.
	gapDetected   bool
	gapFirstSeen  time.Time
	// gapSeqs records which sequence numbers in the window are missing.
	gapSeqs map[uint32]bool

	// lastActivity is the timestamp of the last received chunk.
	// Used for orphan timeout cleanup.
	lastActivity time.Time

	// state is the current circuit lifecycle state.
	state CircuitState

	// lastNACKSent tracks when the last NACK was sent to avoid
	// spamming the entry with duplicate NACKs.
	lastNACKSent time.Time

	// createdAt is when the circuit was established.
	createdAt time.Time
}

// pathTracker tracks which paths have delivered chunks to a circuit.
// It is on-demand: only paths that have actually delivered at least one
// chunk are recorded. This avoids O(N²) expansion because the path set
// is bounded by the number of disjoint paths (typically 2), not the
// total relay count.
type pathTracker struct {
	mu     sync.Mutex
	paths  map[int]bool      // path index → active
	delays map[int]time.Duration // path index → last measured RTT (from keepalive)
}

func newPathTracker() *pathTracker {
	return &pathTracker{
		paths:  make(map[int]bool),
		delays: make(map[int]time.Duration),
	}
}

// RecordPath marks a path as active (has delivered at least one chunk).
func (pt *pathTracker) RecordPath(pathIdx int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.paths[pathIdx] = true
}

// RecordRTT records a measured RTT for a path (from keepalive response).
func (pt *pathTracker) RecordRTT(pathIdx int, rtt time.Duration) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.delays[pathIdx] = rtt
}

// FastestPath returns the path index with the lowest RTT.
// Falls back to any active path if no RTTs are recorded.
func (pt *pathTracker) FastestPath() int {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	var bestPath = -1
	var bestRTT time.Duration = -1

	for pathIdx, rtt := range pt.delays {
		if bestRTT < 0 || rtt < bestRTT {
			bestPath = pathIdx
			bestRTT = rtt
		}
	}

	if bestPath >= 0 {
		return bestPath
	}

	// No RTT data — return any active path.
	for pathIdx := range pt.paths {
		return pathIdx
	}

	return 0 // fallback
}

// ActivePaths returns the number of paths that have delivered chunks.
func (pt *pathTracker) ActivePaths() int {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	return len(pt.paths)
}

// ExitNode is the exit node module. It manages multiple circuits,
// each with its own E2E key, reassembly buffer, and target TCP connection.
//
// The exit node receives WireChunks from relay nodes, decrypts them with
// the per-circuit E2E key, feeds them to the per-stream reassembler, and
// writes reassembled data to the target TCP connection.
type ExitNode struct {
	cfg      ExitConfig
	mu       sync.RWMutex
	circuits map[string]*exitCircuit // circuit ID (hex) → state

	// dialer is the function for dialing target TCP connections.
	dialer func(network, addr string) (net.Conn, error)

	// secSink receives suspicious-activity events for alerting.
	// Accessed atomically — set via SetSecurityEventSink, read by secReport
	// without holding mu (avoids deadlock when secReport is called from
	// within methods that already hold mu or circuit.mu).
	secSink atomic.Pointer[SecurityEventSink]

	// closed signals shutdown.
	closed bool
}

// NewExitNode creates a new exit node module with the given config.
func NewExitNode(cfg ExitConfig) *ExitNode {
	// Apply defaults.
	if cfg.CircuitCfg.IdleTimeout <= 0 {
		cfg.CircuitCfg = DefaultCircuitConfig()
	}
	if cfg.ChunkerStrategy == "" {
		cfg.ChunkerStrategy = "bounded-4k-64k"
	}
	if cfg.ChunkerCfg.MaxChunkSize == 0 {
		cfg.ChunkerCfg = DefaultChunkerConfig()
	}
	if cfg.DebugFixedChunks {
		cfg.ChunkerStrategy = "fixed-16k"
	}

	dialer := cfg.Dialer
	if dialer == nil {
		dialer = func(network, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}

	return &ExitNode{
		cfg:      cfg,
		circuits: make(map[string]*exitCircuit),
		dialer:   dialer,
	}
}

// HandleCircuitSetup processes a CircuitSetup message from the entry node.
// It performs ECDH key agreement, validates the target port, establishes
// a TCP connection to the target, and returns a CircuitAck.
//
// This is the entry point for a new circuit on the exit node.
func (e *ExitNode) HandleCircuitSetup(setup *CircuitSetup) (*CircuitAck, error) {
	if e.isClosed() {
		return nil, ErrCircuitClosed
	}

	if len(setup.CircuitID) != CircuitIDSize {
		return nil, fmt.Errorf("circuit ID must be %d bytes", CircuitIDSize)
	}
	if len(setup.ECDHPubKey) != 32 {
		return nil, fmt.Errorf("ECDH public key must be 32 bytes")
	}
	if setup.TargetAddr == "" {
		return nil, fmt.Errorf("target address is required")
	}

	circuitIDHex := fmt.Sprintf("%x", setup.CircuitID)

	// Check for duplicate circuit.
	e.mu.RLock()
	if _, exists := e.circuits[circuitIDHex]; exists {
		e.mu.RUnlock()
		return nil, fmt.Errorf("circuit %s already exists", circuitIDHex)
	}
	e.mu.RUnlock()

	// Validate target port.
	if err := e.validatePort(setup.TargetAddr); err != nil {
		e.secReport(SecurityEvent{
			Type:        SecEventExitPortDenied,
			Description: fmt.Sprintf("exit rejected circuit %s: %v", circuitIDHex, err),
			CircuitID:   circuitIDHex,
			TargetAddr:  setup.TargetAddr,
		})
		return &CircuitAck{
			CircuitID: setup.CircuitID,
			Accepted:  false,
			Reason:    err.Error(),
		}, nil
	}

	// Generate exit ECDH key pair.
	exitKeys, err := GenerateECDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ECDH key pair: %w", err)
	}

	// Derive shared E2E key.
	e2eKey, err := DeriveSharedKey(exitKeys.Private, setup.ECDHPubKey)
	if err != nil {
		return nil, fmt.Errorf("derive shared key: %w", err)
	}

	// Dial the target TCP connection.
	targetConn, err := e.dialer("tcp", setup.TargetAddr)
	if err != nil {
		e.secReport(SecurityEvent{
			Type:        SecEventExitCircuitSetupFail,
			Description: fmt.Sprintf("exit failed to dial target %s for circuit %s: %v", setup.TargetAddr, circuitIDHex, err),
			CircuitID:   circuitIDHex,
			TargetAddr:  setup.TargetAddr,
		})
		return &CircuitAck{
			CircuitID: setup.CircuitID,
			Accepted:  false,
			Reason:     fmt.Sprintf("dial target: %v", err),
		}, nil
	}

	// Create the reassembler.
	strategy := e.cfg.ChunkerStrategy
	// The exit node always uses ExitReassembler for streaming delivery,
	// regardless of the configured chunker strategy name. ExitReassembler
	// is chunk-size-agnostic and works with any Chunker implementation.
	reassembler := NewExitReassembler(e.cfg.ChunkerCfg)
	_ = strategy // strategy name is retained for future per-strategy config

	// Create the circuit entry.
	circuit := &exitCircuit{
		circuitID:      circuitIDHex,
		circuitIDBytes: setup.CircuitID,
		e2eKey:         e2eKey,
		targetConn:     targetConn,
		targetAddr:     setup.TargetAddr,
		reassembler:    reassembler,
		pathTracker:    newPathTracker(),
		gapSeqs:        make(map[uint32]bool),
		lastActivity:   time.Now(),
		state:          CircuitActive,
		createdAt:      time.Now(),
	}

	// Register the circuit.
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		targetConn.Close()
		return nil, ErrCircuitClosed
	}
	e.circuits[circuitIDHex] = circuit
	e.mu.Unlock()

	// Send back the circuit ack.
	return &CircuitAck{
		CircuitID:  setup.CircuitID,
		ECDHPubKey: exitKeys.Public,
		Accepted:   true,
	}, nil
}

// HandleWireChunk processes an incoming WireChunk on the exit node.
// It decrypts the chunk with the circuit's E2E key, feeds it to the
// reassembler, and writes any reassembled data to the target TCP connection.
//
// pathIdx indicates which path this chunk arrived on (0 or 1 for the
// two disjoint paths). The exit uses this for on-demand path tracking.
//
// If a gap is detected in the sequence window, this function returns a
// non-nil NACKMsg that the caller should send back to the entry node.
func (e *ExitNode) HandleWireChunk(circuitID string, wc *WireChunk, pathIdx int) (*NACKMsg, error) {
	if e.isClosed() {
		return nil, ErrCircuitClosed
	}

	e.mu.RLock()
	circuit, exists := e.circuits[circuitID]
	e.mu.RUnlock()

	if !exists {
		e.secReport(SecurityEvent{
			Type:        SecEventExitCircuitNotFound,
			Description: fmt.Sprintf("exit received chunk for unknown circuit %s", circuitID),
			CircuitID:   circuitID,
		})
		return nil, ErrCircuitNotFound
	}

	// Decrypt the chunk with the E2E key.
	// The circuit ID is verified inside DecodeChunk against the expected
	// value, preventing cross-circuit replay.
	chunk, err := DecodeChunk(wc, circuit.e2eKey, circuit.circuitIDBytes)
	if err != nil {
		e.secReport(SecurityEvent{
			Type:        SecEventExitDecodeFail,
			Description: fmt.Sprintf("exit failed to decode chunk for circuit %s: %v", circuitID, err),
			CircuitID:   circuitID,
		})
		return nil, fmt.Errorf("decode chunk: %w", err)
	}

	circuit.mu.Lock()
	defer circuit.mu.Unlock()

	if circuit.state != CircuitActive {
		return nil, fmt.Errorf("circuit %s is not active (state=%d)", circuitID, circuit.state)
	}

	// Record the path for on-demand tracking.
	circuit.pathTracker.RecordPath(pathIdx)

	// Update last activity.
	circuit.lastActivity = time.Now()

	// DoS protection: reject chunks beyond the reassembly window.
	// The window is [ackBase, ackBase + MaxReassemblyWindow).
	// Chunks with sequence >= ackBase + MaxReassemblyWindow are rejected.
	maxWindow := e.cfg.CircuitCfg.MaxReassemblyWindow
	if maxWindow <= 0 {
		maxWindow = 256
	}

	if chunk.Sequence >= circuit.ackBase+uint32(maxWindow) {
		// Chunk is too far ahead — reject to prevent memory exhaustion.
		e.secReport(SecurityEvent{
			Type:        SecEventExitWindowExceeded,
			Description: fmt.Sprintf("exit rejected chunk seq %d beyond reassembly window (base=%d, max=%d) for circuit %s",
				chunk.Sequence, circuit.ackBase, maxWindow, circuitID),
			CircuitID: circuitID,
		})
		return nil, fmt.Errorf("chunk sequence %d beyond reassembly window (base=%d, max=%d)",
			chunk.Sequence, circuit.ackBase, maxWindow)
	}

	// Detect gaps for NACK generation.
	if chunk.Sequence > circuit.ackBase {
		// Mark all sequences between ackBase and this chunk's sequence as
		// potentially missing (if not already received).
		for seq := circuit.ackBase; seq < chunk.Sequence; seq++ {
			if !circuit.gapSeqs[seq] {
				circuit.gapSeqs[seq] = true
				if !circuit.gapDetected {
					circuit.gapDetected = true
					circuit.gapFirstSeen = time.Now()
				}
			}
		}
	}

	// Feed the chunk to the reassembler via the streaming API.
	// AddStreaming returns contiguous data as soon as it's available,
	// rather than buffering everything until stream completion.
	delivered, done, err := circuit.reassembler.AddStreaming(chunk)
	if err != nil {
		return nil, fmt.Errorf("reassemble chunk: %w", err)
	}

	// Write any newly-delivered contiguous data to the target connection.
	// This delivers data incrementally as chunks arrive in order,
	// reducing latency for interactive protocols.
	if len(delivered) > 0 {
		if _, werr := circuit.targetConn.Write(delivered); werr != nil {
			return nil, fmt.Errorf("write to target: %w", werr)
		}
	}

	// Update ackBase using the reassembler's authoritative nextExpected
	// value. This correctly advances past all contiguous received chunks,
	// fixing the previous bug where ackBase only advanced by 1.
	if nextExp, ok := circuit.reassembler.NextExpected(chunk.StreamID); ok {
		if nextExp > circuit.ackBase {
			circuit.ackBase = nextExp
		}
	} else if done {
		// Stream completed and cleaned up — advance ackBase past it.
		circuit.ackBase = chunk.Sequence + 1
	}

	// Clear any gap sequences that have been filled (acked past).
	// Since ackBase advanced, any gaps below ackBase are no longer relevant.
	for seq := range circuit.gapSeqs {
		if seq < circuit.ackBase {
			delete(circuit.gapSeqs, seq)
		}
	}
	if len(circuit.gapSeqs) == 0 {
		circuit.gapDetected = false
	}

	// Check if we need to send a NACK for detected gaps.
	nack := e.maybeGenerateNACK(circuit, chunk.StreamID)

	return nack, nil
}

// maybeGenerateNACK checks if a detected gap has persisted beyond
// NACKTimeout and generates a NACK message if so. It also rate-limits
// NACKs to avoid spamming the entry node.
func (e *ExitNode) maybeGenerateNACK(circuit *exitCircuit, streamID uint32) *NACKMsg {
	if !circuit.gapDetected || len(circuit.gapSeqs) == 0 {
		return nil
	}

	nackTimeout := e.cfg.CircuitCfg.NACKTimeout
	if nackTimeout <= 0 {
		nackTimeout = 5 * time.Second
	}

	// Check if the gap has persisted long enough.
	elapsed := time.Since(circuit.gapFirstSeen)
	if elapsed < nackTimeout {
		return nil
	}

	// Rate-limit: don't send NACKs more than once per NACKTimeout period.
	if !circuit.lastNACKSent.IsZero() && time.Since(circuit.lastNACKSent) < nackTimeout {
		return nil
	}

	// Build the list of missing sequences.
	missing := make([]uint32, 0, len(circuit.gapSeqs))
	for seq := range circuit.gapSeqs {
		missing = append(missing, seq)
	}

	// Sort missing sequences for deterministic output.
	// Simple insertion sort — the list is typically small (< 256).
	for i := 1; i < len(missing); i++ {
		for j := i; j > 0 && missing[j-1] > missing[j]; j-- {
			missing[j-1], missing[j] = missing[j], missing[j-1]
		}
	}

	// Parse the circuit ID bytes.
	circuitIDBytes, err := parseCircuitIDHex(circuit.circuitID)
	if err != nil {
		return nil
	}

	circuit.lastNACKSent = time.Now()

	return &NACKMsg{
		CircuitID:    circuitIDBytes,
		StreamID:     streamID,
		MissingSeqs: missing,
	}
}

// HandleTeardown processes a circuit teardown message, cleaning up
// the circuit's resources: flushing remaining reassembly data, closing
// the target TCP connection, and removing the circuit from the registry.
func (e *ExitNode) HandleTeardown(td *TeardownMsg) error {
	circuitIDHex := fmt.Sprintf("%x", td.CircuitID)

	e.mu.Lock()
	circuit, exists := e.circuits[circuitIDHex]
	if !exists {
		e.mu.Unlock()
		return ErrCircuitNotFound
	}
	delete(e.circuits, circuitIDHex)
	e.mu.Unlock()

	circuit.mu.Lock()
	defer circuit.mu.Unlock()

	circuit.state = CircuitTeardown

	// Close the target TCP connection.
	if circuit.targetConn != nil {
		circuit.targetConn.Close()
	}
	circuit.state = CircuitClosed

	return nil
}

// HandleKeepalive processes a keepalive message from the entry node.
// It records the RTT for the path and returns nil (no response needed —
// the keepalive is acknowledged implicitly by the next data chunk or
// ACK from the exit).
func (e *ExitNode) HandleKeepalive(circuitID string, msg *KeepaliveMsg, pathIdx int) error {
	e.mu.RLock()
	circuit, exists := e.circuits[circuitID]
	e.mu.RUnlock()

	if !exists {
		return ErrCircuitNotFound
	}

	// Calculate RTT from the timestamp in the keepalive.
	rtt := time.Since(time.Unix(0, msg.Timestamp))
	circuit.pathTracker.RecordRTT(pathIdx, rtt)

	circuit.mu.Lock()
	circuit.lastActivity = time.Now()
	circuit.mu.Unlock()

	return nil
}

// CircuitCount returns the number of active circuits on this exit node.
func (e *ExitNode) CircuitCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.circuits)
}

// GetCircuitInfo returns information about a specific circuit.
// This is primarily for diagnostics and testing.
func (e *ExitNode) GetCircuitInfo(circuitID string) (targetAddr string, state CircuitState, activePaths int, err error) {
	e.mu.RLock()
	circuit, exists := e.circuits[circuitID]
	e.mu.RUnlock()

	if !exists {
		return "", 0, 0, ErrCircuitNotFound
	}

	circuit.mu.Lock()
	defer circuit.mu.Unlock()

	return circuit.targetAddr, circuit.state, circuit.pathTracker.ActivePaths(), nil
}

// SetSecurityEventSink installs a sink for reporting suspicious proxy
// activity (port denials, decode failures, window exceeded, etc.).
// Pass nil to disable alerting on this exit node.
func (e *ExitNode) SetSecurityEventSink(sink *SecurityEventSink) {
	e.secSink.Store(sink)
}

// secReport is a convenience to send a security event if a sink is set.
func (e *ExitNode) secReport(event SecurityEvent) {
	if sink := e.secSink.Load(); sink != nil {
		sink.Report(event)
	}
}

// Close shuts down the exit node: tears down all circuits, closes all
// target TCP connections, and prevents new circuits from being created.
func (e *ExitNode) Close() error {
	e.mu.Lock()
	e.closed = true
	circuits := make([]*exitCircuit, 0, len(e.circuits))
	for _, c := range e.circuits {
		circuits = append(circuits, c)
	}
	e.circuits = make(map[string]*exitCircuit)
	e.mu.Unlock()

	for _, circuit := range circuits {
		circuit.mu.Lock()
		circuit.state = CircuitClosed
		if circuit.targetConn != nil {
			circuit.targetConn.Close()
		}
		circuit.mu.Unlock()
	}

	return nil
}

// CleanupOrphans removes circuits that have been inactive (no chunks received)
// for longer than OrphanTimeout. This prevents memory leaks from circuits
// that were abandoned by the entry node without a proper teardown.
//
// This function should be called periodically (e.g. every 30s) by a
// background goroutine.
func (e *ExitNode) CleanupOrphans() int {
	orphanTimeout := e.cfg.CircuitCfg.OrphanTimeout
	if orphanTimeout <= 0 {
		orphanTimeout = 30 * time.Second
	}

	now := time.Now()
	var removed int

	e.mu.Lock()
	for id, circuit := range e.circuits {
		circuit.mu.Lock()
		inactive := now.Sub(circuit.lastActivity)
		if inactive > orphanTimeout {
			circuit.state = CircuitClosed
			if circuit.targetConn != nil {
				circuit.targetConn.Close()
			}
			delete(e.circuits, id)
			removed++
		}
		circuit.mu.Unlock()
	}
	e.mu.Unlock()

	return removed
}

// StartOrphanCleanup runs a background goroutine that periodically calls
// CleanupOrphans. It runs until the context is cancelled.
func (e *ExitNode) StartOrphanCleanup(ctx context.Context) {
	orphanTimeout := e.cfg.CircuitCfg.OrphanTimeout
	if orphanTimeout <= 0 {
		orphanTimeout = 30 * time.Second
	}

	// Run cleanup at half the orphan timeout interval.
	interval := orphanTimeout / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.CleanupOrphans()
		}
	}
}

// validatePort checks that the target port is in the allowed list.
// If AllowAllPorts is true, any port is accepted.
func (e *ExitNode) validatePort(addr string) error {
	if e.cfg.AllowAllPorts {
		return nil
	}

	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid target address %q: %w", addr, err)
	}

	port := 0
	for _, c := range portStr {
		if c >= '0' && c <= '9' {
			port = port*10 + int(c-'0')
		} else {
			return fmt.Errorf("invalid port %q in address %q", portStr, addr)
		}
	}

	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port number %d", port)
	}

	if len(e.cfg.AllowedPorts) == 0 {
		return nil // no restriction configured
	}

	for _, allowed := range e.cfg.AllowedPorts {
		if port == allowed {
			return nil
		}
	}

	return fmt.Errorf("port %d is not in the allowed list %v", port, e.cfg.AllowedPorts)
}

// isClosed returns true if the exit node has been shut down.
func (e *ExitNode) isClosed() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.closed
}

// parseCircuitIDHex converts a hex circuit ID string back to bytes.
func parseCircuitIDHex(hexID string) ([]byte, error) {
	if len(hexID) != CircuitIDSize*2 {
		return nil, fmt.Errorf("circuit ID hex must be %d chars, got %d", CircuitIDSize*2, len(hexID))
	}

	result := make([]byte, CircuitIDSize)
	for i := 0; i < CircuitIDSize; i++ {
		high := hexCharToByte(hexID[i*2])
		low := hexCharToByte(hexID[i*2+1])
		if high < 0 || low < 0 {
			return nil, fmt.Errorf("invalid hex character in circuit ID")
		}
		result[i] = byte(high<<4 | low)
	}
	return result, nil
}

func hexCharToByte(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// ClosestFastestPath returns the fastest path for sending NACKs or
// control messages back to the entry. Uses the on-demand path tracker
// to select the path with the lowest measured RTT.
func (e *ExitNode) ClosestFastestPath(circuitID string) int {
	e.mu.RLock()
	circuit, exists := e.circuits[circuitID]
	e.mu.RUnlock()

	if !exists {
		return 0
	}
	return circuit.pathTracker.FastestPath()
}

// ForwardTargetToEntry reads data from the target TCP connection (responses
// from the destination server), chunks them, and sends them back to the
// entry node through the circuit. This function runs in a goroutine
// alongside the chunk receiving loop.
//
// For Phase 1, this uses a callback-based I/O model: the caller provides
// a sendChunk function that writes the encrypted chunk back through the
// mesh transport to the entry node.
func (e *ExitNode) ForwardTargetToEntry(ctx context.Context, circuitID string, e2eKey []byte, relayKey []byte, nextHop string, sendChunk func(path int, wc *WireChunk) error) error {
	e.mu.RLock()
	circuit, exists := e.circuits[circuitID]
	e.mu.RUnlock()

	if !exists {
		return ErrCircuitNotFound
	}

	// Create a chunker for the return path.
	strategy := e.cfg.ChunkerStrategy
	if e.cfg.DebugFixedChunks {
		strategy = "fixed-16k"
	}
	chunker := NewChunkerWithConfig(strategy, e.cfg.ChunkerCfg)

	buf := make([]byte, 32*1024)
	var seq uint32

	// We use StreamID=1 for the return path (response from target).
	const returnStreamID = 1

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := circuit.targetConn.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			chunks := chunker.Split(data)
			for _, chunk := range chunks {
				chunk.StreamID = returnStreamID
				chunk.Sequence = seq
				seq++

				// Determine the path to send on.
				pathIdx := circuit.pathTracker.FastestPath()

				// Encrypt and send the chunk back to the entry.
				wc, encErr := EncodeChunk(chunk, e2eKey, relayKey, nextHop, circuit.circuitIDBytes)
				if encErr != nil {
					return fmt.Errorf("encode return chunk: %w", encErr)
				}

				if sendErr := sendChunk(pathIdx, wc); sendErr != nil {
					return fmt.Errorf("send return chunk: %w", sendErr)
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				// Send stream end marker.
				endChunk := Chunk{
					StreamID: returnStreamID,
					Sequence: seq,
					Type:     ChunkStreamEnd,
				}
				wc, _ := EncodeChunk(endChunk, e2eKey, relayKey, nextHop, circuit.circuitIDBytes)
				pathIdx := circuit.pathTracker.FastestPath()
				sendChunk(pathIdx, wc)
				return nil
			}
			return fmt.Errorf("read from target: %w", err)
		}
	}
}
