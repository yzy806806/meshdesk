// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the EntryNode — the top-level orchestrator that
// wires together all proxy subsystems on an entry node:
//
//   - ECDH circuit setup (establishes end-to-end encryption with exit)
//   - Path selection (picks two disjoint relay paths, manual or auto)
//   - Dispatcher (chunks data, encrypts, dispatches across paths)
//   - Mesh transport (dials relay/exit connections via MeshNode.Dial)
//   - Security event sink (shared by relay and exit for alerting)
//
// The EntryNode is the "brain" of the entry point: it sets up circuits,
// selects paths, and runs dispatchers.
//
// Design (PROXY_DESIGN.md §1.1, §2, §1.8):
//
//   - PER-CONNECTION CIRCUIT: Each connection gets its own circuit
//     with a unique E2E key derived from ECDH with the exit node.
//   - TWO DISJOINT PATHS: Data is split across two relay paths to
//     disperse traffic and resist traffic analysis.
//   - CIRCUIT LIFECYCLE: Circuits are created on connection accept,
//     kept alive with periodic pings, and torn down on disconnect.
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

// entryHandshakeTimeout bounds the entry→exit circuit-setup handshake.
const entryHandshakeTimeout = 10 * time.Second

// EntryNodeConfig holds configuration for the EntryNode orchestrator.
type EntryNodeConfig struct {
	// CircuitCfg holds circuit lifecycle parameters.
	CircuitCfg CircuitConfig

	// ChunkerStrategy selects the chunking strategy.
	// "bounded-4k-64k" (default) or "fixed-16k".
	ChunkerStrategy string

	// ChunkerCfg is the chunker configuration.
	ChunkerCfg ChunkerConfig

	// DebugFixedChunks forces uniform chunk sizes (testing only).
	DebugFixedChunks bool

	// Path1 and Path2 are the manually configured relay paths
	// (Phase 1). Used when PathSelectionMode is "manual".
	Path1 *Path
	Path2 *Path

	// PathSelectionMode is "manual" or "auto".
	// In manual mode, Path1/Path2 must be set.
	// In auto mode, PathSelector is used with CandidateRelays.
	PathSelectionMode string

	// PathSelector is used when PathSelectionMode is "auto".
	// May be nil in manual mode.
	PathSelector *PathSelector

	// CandidateRelays is the list of relay candidates for auto
	// path selection.
	CandidateRelays []CandidateRelay

	// ExitAddr is the mesh address of the exit node.
	ExitAddr string

	// DialFunc is used to dial relay and exit connections through
	// the mesh. If nil, net.Dial is used (for testing).
	// In production, this should be wired to MeshNode.Dial.
	DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

	// SecSink is the shared security event sink for
	// relay, and exit. May be nil if alerting is not configured.
	SecSink *SecurityEventSink

	// CircuitManager is the centralized circuit lifecycle orchestrator.
	// When set, the EntryNode delegates circuit creation, teardown,
	// keepalive, and path selection to the CircuitManager instead of
	// using its internal setupCircuit/teardownCircuit methods.
	// This implements the migration path from CIRCUIT_MANAGER_SPEC.md §9.3.
	// May be nil for backward compatibility (Phase 1 behavior).
	CircuitManager *CircuitManager

	// ChunkAssignmentStrategy controls how chunks are distributed
	// across the two paths. If nil, round-robin is used.
	// When CircuitManager is set, this should match its configured strategy.
	ChunkAssignmentStrategy ChunkAssignmentStrategy
}

// DefaultEntryNodeConfig returns sensible defaults for an entry node.
func DefaultEntryNodeConfig() EntryNodeConfig {
	return EntryNodeConfig{
		CircuitCfg:        DefaultCircuitConfig(),
		ChunkerStrategy:   "bounded-4k-64k",
		ChunkerCfg:        DefaultChunkerConfig(),
		PathSelectionMode: "manual",
	}
}

// session wraps a single proxy connection's lifecycle.
type session struct {
	circuitID    []byte
	circuitIDHex string
	e2eKey       []byte
	dispatcher   *Dispatcher
	conn         net.Conn // the SS session connection

	// pathConns holds the mesh connections to the first relay
	// (or exit if no relays) on each path.
	pathConns [2]net.Conn

	// cancel cancels the session's context.
	cancel context.CancelFunc

	// wg tracks goroutines for this session.
	wg sync.WaitGroup
}

// EntryNode is the top-level orchestrator for a proxy entry node.
// It manages circuit setup, path selection, and per-connection dispatchers.
type EntryNode struct {
	cfg    EntryNodeConfig
	mu     sync.RWMutex
	closed bool

	// sessions tracks active proxy sessions.
	sessions map[string]*session

	// secSink is the shared security event sink.
	secSink *SecurityEventSink

	// dialer is the mesh dial function.
	dialer func(ctx context.Context, network, address string) (net.Conn, error)

	// path1 and path2 are the selected paths (either manual or auto-selected).
	path1 *Path
	path2 *Path

	// circuitMgr is the centralized circuit manager (optional).
	// When set, circuit lifecycle is delegated to it.
	circuitMgr *CircuitManager

	// ctx is the entry node's lifecycle context.
	ctx context.Context

	// cancel cancels the entry node's context.
	cancel context.CancelFunc
}

// NewEntryNode creates a new entry node orchestrator.
//
// The entry node is not started until Start() is called.
// Start() launches the CF Tunnel (if configured), waits for it to
// become ready, then starts accepting SS connections.
func NewEntryNode(cfg EntryNodeConfig) *EntryNode {
	if cfg.ChunkerStrategy == "" {
		cfg.ChunkerStrategy = "bounded-4k-64k"
	}
	if cfg.PathSelectionMode == "" {
		cfg.PathSelectionMode = "manual"
	}
	if cfg.ChunkerCfg.MaxChunkSize == 0 {
		cfg.ChunkerCfg = DefaultChunkerConfig()
	}

	dialer := cfg.DialFunc
	if dialer == nil {
		dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	en := &EntryNode{
		cfg:        cfg,
		sessions:   make(map[string]*session),
		secSink:    cfg.SecSink,
		dialer:     dialer,
		circuitMgr: cfg.CircuitManager,
		ctx:        ctx,
		cancel:     cancel,
	}

	// If CircuitManager is set, wire its event callback to update
	// the entry node's path references when circuits are established.
	if en.circuitMgr != nil {
		en.circuitMgr.OnCircuitEvent(func(event CircuitEvent) {
			switch event.Type {
			case EventCircuitClosed:
				// Circuit closed — the session cleanup is handled by
				// the handleConnection defer. Nothing extra to do here.
			}
		})
	}

	return en
}

// SetSecurityEventSink installs a security event sink shared by all
// proxy subsystems (SS listener, relay, exit).
func (e *EntryNode) SetSecurityEventSink(sink *SecurityEventSink) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.secSink = sink
}

// Start brings up the entry node: selects paths (if auto mode), and begins
// accepting connections.
func (e *EntryNode) Start() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return fmt.Errorf("entry node is closed")
	}

	// Phase 1: Select paths.
	if e.cfg.PathSelectionMode == "auto" {
		if e.cfg.PathSelector == nil {
			e.mu.Unlock()
			return fmt.Errorf("auto path selection requires a PathSelector")
		}
		if len(e.cfg.CandidateRelays) < 2 {
			e.mu.Unlock()
			return fmt.Errorf("auto path selection requires at least 2 candidate relays, got %d",
				len(e.cfg.CandidateRelays))
		}
		p1, p2, err := e.cfg.PathSelector.SelectPaths(e.ctx, e.cfg.CandidateRelays, e.cfg.ExitAddr)
		if err != nil {
			e.mu.Unlock()
			return fmt.Errorf("auto path selection failed: %w", err)
		}
		e.path1 = p1
		e.path2 = p2
	} else {
		// Manual mode: validate provided paths.
		if e.cfg.Path1 == nil || e.cfg.Path2 == nil {
			e.mu.Unlock()
			return fmt.Errorf("manual path selection requires Path1 and Path2")
		}
		if err := ValidatePathPair(e.cfg.Path1, e.cfg.Path2); err != nil {
			e.mu.Unlock()
			return fmt.Errorf("manual path validation failed: %w", err)
		}
		e.path1 = e.cfg.Path1
		e.path2 = e.cfg.Path2
	}
	e.mu.Unlock()

	// Phase 2: Ready to accept connections (via HandleConnection).
	return nil
}

// HandleConnection processes a single proxy connection end-to-end:
//  1. Set up a circuit with the exit node (ECDH)
//  2. Create a dispatcher and dispatch data across two paths
//  3. Read response from exit and write back to client
func (e *EntryNode) HandleConnection(conn net.Conn, targetAddr string) {
	// Set up the circuit with the exit node.
	// When CircuitManager is configured, delegate circuit creation to it.
	// Otherwise, fall back to the legacy inline setupCircuit.
	var sess *session
	var err error
	if e.circuitMgr != nil {
		sess, err = e.setupCircuitViaManager(conn, targetAddr)
	} else {
		sess, err = e.setupCircuit(conn, targetAddr)
	}
	if err != nil {
		if e.secSink != nil {
			e.secSink.Report(SecurityEvent{
				Type:        SecEventExitCircuitSetupFail,
				Description: fmt.Sprintf("circuit setup failed for target %s: %v", targetAddr, err),
				TargetAddr:  targetAddr,
			})
		}
		conn.Close()
		return
	}

	// Register the session.
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		sess.dispatcher.Close()
		conn.Close()
		return
	}
	e.sessions[sess.circuitIDHex] = sess
	e.mu.Unlock()

	// Ensure cleanup on exit.
	defer func() {
		e.mu.Lock()
		delete(e.sessions, sess.circuitIDHex)
		e.mu.Unlock()
		e.teardownCircuit(sess)
	}()

	// Run the dispatcher: reads from SS connection, chunks, encrypts,
	// and sends across both paths.
	sessionCtx, cancel := context.WithCancel(e.ctx)
	sess.cancel = cancel
	defer cancel()

	// Establish mesh connections for both paths.
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		sess.wg.Add(1)
		go func(pathIdx int) {
			defer sess.wg.Done()
			conn, err := e.dialPath(sessionCtx, pathIdx)
			if err != nil {
				errCh <- fmt.Errorf("dial path %d: %w", pathIdx, err)
				return
			}
			e.mu.Lock()
			sess.pathConns[pathIdx] = conn
			e.mu.Unlock()
			errCh <- nil
		}(i)
	}

	// Wait for both path connections.
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			// If one path fails, we can still use the other.
			// For v1, we require both paths; if either fails, abort.
			cancel()
			return
		}
	}

	// Run the dispatcher with a send callback that writes to the
	// appropriate path connection.
	sendChunk := func(path int, wc *WireChunk) error {
		e.mu.RLock()
		pathConn := sess.pathConns[path]
		e.mu.RUnlock()
		if pathConn == nil {
			return fmt.Errorf("path %d connection not available", path)
		}
		return WriteWireChunk(pathConn, wc)
	}

	// Start keepalive loop.
	go sess.dispatcher.KeepaliveLoop(sessionCtx, func(path int, msg *KeepaliveMsg) error {
		e.mu.RLock()
		pathConn := sess.pathConns[path]
		e.mu.RUnlock()
		if pathConn == nil {
			return nil // skip if not connected
		}
		data, err := msg.Encode()
		if err != nil {
			return err
		}
		_, err = pathConn.Write(data)
		return err
	})

	// Run the dispatcher (blocks until connection closes).
	_ = sess.dispatcher.Run(sessionCtx, sendChunk)
}

// setupCircuit performs the ECDH circuit setup with the exit node:
//  1. Generate entry ECDH key pair
//  2. Send CircuitSetup to exit (via mesh transport)
//  3. Receive CircuitAck from exit
//  4. Derive shared E2E key
//  5. Create dispatcher with the E2E key and circuit ID
func (e *EntryNode) setupCircuit(conn net.Conn, targetAddr string) (*session, error) {
	// Generate entry ECDH key pair.
	entryKeys, err := GenerateECDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ECDH key pair: %w", err)
	}

	// Generate circuit ID. Prefer the CircuitManager's ID so teardown
	// (which addresses the CM by this ID) finds the circuit — creating
	// a separate ID here and another inside CreateCircuit left every
	// circuit orphaned in the CM (teardown always returned not-found).
	var circuitID CircuitIDType
	if e.circuitMgr != nil {
		cid, cerr := e.circuitMgr.CreateCircuit(targetAddr, "entry", "exit", e.cfg.CandidateRelays)
		if cerr == nil {
			circuitID = cid
		}
	}
	if circuitID == (CircuitIDType{}) {
		// CM unavailable or path selection failed — fall back to a
		// local ID (legacy path; no CM tracking).
		idBytes, gerr := GenerateCircuitID()
		if gerr != nil {
			return nil, fmt.Errorf("generate circuit ID: %w", gerr)
		}
		copy(circuitID[:], idBytes)
	}
	circuitIDHex := fmt.Sprintf("%x", circuitID)

	// Build CircuitSetup message.
	setup := &CircuitSetup{
		CircuitID:  circuitID[:],
		ECDHPubKey: entryKeys.Public,
		TargetAddr: targetAddr,
	}

	// Dial the exit node.
	exitConn, err := e.dialer(e.ctx, "tcp", e.cfg.ExitAddr)
	if err != nil {
		return nil, fmt.Errorf("dial exit node %s: %w", e.cfg.ExitAddr, err)
	}
	// Bound the handshake: a dead/stalled exit that accepts TCP but
	// never responds would otherwise block ReadFull forever, leaking
	// a goroutine + fd per attempt.
	exitConn.SetDeadline(time.Now().Add(entryHandshakeTimeout))

	// Send CircuitSetup.
	setupData, err := setup.Encode()
	if err != nil {
		exitConn.Close()
		return nil, fmt.Errorf("encode circuit setup: %w", err)
	}
	if _, err := exitConn.Write(setupData); err != nil {
		exitConn.Close()
		return nil, fmt.Errorf("send circuit setup: %w", err)
	}

	// Receive CircuitAck.
	// The ack is a fixed-size message: CircuitID(16) + ECDHPubKey(32) +
	// Accepted(1) + ReasonLen(2) + Reason(variable).
	// Read the fixed part first.
	ackFixed := make([]byte, CircuitIDSize+32+1+2)
	if _, err := io.ReadFull(exitConn, ackFixed); err != nil {
		exitConn.Close()
		return nil, fmt.Errorf("read circuit ack: %w", err)
	}

	// Parse reason length.
	reasonLen := int(ackFixed[CircuitIDSize+32+1])<<8 | int(ackFixed[CircuitIDSize+32+2])
	if reasonLen > 0 {
		reasonBuf := make([]byte, reasonLen)
		if _, err := io.ReadFull(exitConn, reasonBuf); err != nil {
			exitConn.Close()
			return nil, fmt.Errorf("read ack reason: %w", err)
		}
		ackFixed = append(ackFixed, reasonBuf...)
	}

	ack, err := DecodeCircuitAck(ackFixed)
	if err != nil {
		exitConn.Close()
		return nil, fmt.Errorf("decode circuit ack: %w", err)
	}

	if !ack.Accepted {
		exitConn.Close()
		return nil, fmt.Errorf("exit rejected circuit: %s", ack.Reason)
	}

	// Derive shared E2E key.
	e2eKey, err := DeriveSharedKey(entryKeys.Private, ack.ECDHPubKey)
	if err != nil {
		exitConn.Close()
		return nil, fmt.Errorf("derive shared key: %w", err)
	}

	// Close the exit control connection — data goes through relay paths.
	exitConn.Close()

	// Create the dispatcher.
	dispCfg := DispatcherConfig{
		ChunkerStrategy:  e.cfg.ChunkerStrategy,
		ChunkerCfg:       e.cfg.ChunkerCfg,
		CircuitCfg:       e.cfg.CircuitCfg,
		Path1:            e.path1,
		Path2:            e.path2,
		E2EKey:           e2eKey,
		CircuitID:        circuitID[:],
		ExitAddr:         e.cfg.ExitAddr,
		DebugFixedChunks: e.cfg.DebugFixedChunks,
	}

	dispatcher, err := NewDispatcher(dispCfg, conn)
	if err != nil {
		return nil, fmt.Errorf("create dispatcher: %w", err)
	}

	return &session{
		circuitID:    circuitID[:],
		circuitIDHex: circuitIDHex,
		e2eKey:       e2eKey,
		dispatcher:   dispatcher,
		conn:         conn,
	}, nil
}

// setupCircuitViaManager delegates circuit creation to the CircuitManager.
// It performs the same ECDH handshake as setupCircuit, but uses the
// CircuitManager for path selection, circuit ID generation, and lifecycle
// tracking. This implements the migration path from CIRCUIT_MANAGER_SPEC.md §9.3.
func (e *EntryNode) setupCircuitViaManager(conn net.Conn, targetAddr string) (*session, error) {
	// Generate entry ECDH key pair.
	entryKeys, err := GenerateECDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ECDH key pair: %w", err)
	}

	// Generate circuit ID (CircuitManager also does this, but we need
	// it for the ECDH handshake message).
	circuitID, err := GenerateCircuitID()
	if err != nil {
		return nil, fmt.Errorf("generate circuit ID: %w", err)
	}
	circuitIDHex := fmt.Sprintf("%x", circuitID)

	// Build CircuitSetup message.
	setup := &CircuitSetup{
		CircuitID:  circuitID[:],
		ECDHPubKey: entryKeys.Public,
		TargetAddr: targetAddr,
	}

	// Dial the exit node.
	exitConn, err := e.dialer(e.ctx, "tcp", e.cfg.ExitAddr)
	if err != nil {
		return nil, fmt.Errorf("dial exit node %s: %w", e.cfg.ExitAddr, err)
	}
	// Bound the handshake: a dead/stalled exit that accepts TCP but
	// never responds would otherwise block ReadFull forever, leaking
	// a goroutine + fd per attempt.
	exitConn.SetDeadline(time.Now().Add(entryHandshakeTimeout))

	// Send CircuitSetup.
	setupData, err := setup.Encode()
	if err != nil {
		exitConn.Close()
		return nil, fmt.Errorf("encode circuit setup: %w", err)
	}
	if _, err := exitConn.Write(setupData); err != nil {
		exitConn.Close()
		return nil, fmt.Errorf("send circuit setup: %w", err)
	}

	// Receive CircuitAck.
	ackFixed := make([]byte, CircuitIDSize+32+1+2)
	if _, err := io.ReadFull(exitConn, ackFixed); err != nil {
		exitConn.Close()
		return nil, fmt.Errorf("read circuit ack: %w", err)
	}

	reasonLen := int(ackFixed[CircuitIDSize+32+1])<<8 | int(ackFixed[CircuitIDSize+32+2])
	if reasonLen > 0 {
		reasonBuf := make([]byte, reasonLen)
		if _, err := io.ReadFull(exitConn, reasonBuf); err != nil {
			exitConn.Close()
			return nil, fmt.Errorf("read ack reason: %w", err)
		}
		ackFixed = append(ackFixed, reasonBuf...)
	}

	ack, err := DecodeCircuitAck(ackFixed)
	if err != nil {
		exitConn.Close()
		return nil, fmt.Errorf("decode circuit ack: %w", err)
	}

	if !ack.Accepted {
		exitConn.Close()
		return nil, fmt.Errorf("exit rejected circuit: %s", ack.Reason)
	}

	// Derive shared E2E key.
	e2eKey, err := DeriveSharedKey(entryKeys.Private, ack.ECDHPubKey)
	if err != nil {
		exitConn.Close()
		return nil, fmt.Errorf("derive shared key: %w", err)
	}

	exitConn.Close()

	// Register the circuit with the CircuitManager.
	// This centralizes lifecycle tracking, keepalive, and teardown.
	var cid CircuitIDType
	copy(cid[:], circuitID)

	// Build CircuitManager config if not already set.
	cmCfg := DefaultCircuitManagerConfig()
	cmCfg.ExitAddr = e.cfg.ExitAddr
	cmCfg.DialFunc = e.dialer

	// Apply circuit lifecycle config from EntryNodeConfig.
	if e.cfg.CircuitCfg.IdleTimeout > 0 {
		cmCfg.IdleTimeout = e.cfg.CircuitCfg.IdleTimeout
	}
	if e.cfg.CircuitCfg.KeepaliveInterval > 0 {
		cmCfg.KeepaliveInterval = e.cfg.CircuitCfg.KeepaliveInterval
	}
	if e.cfg.CircuitCfg.NACKTimeout > 0 {
		cmCfg.NACKTimeout = e.cfg.CircuitCfg.NACKTimeout
	}
	if e.cfg.CircuitCfg.OrphanTimeout > 0 {
		cmCfg.OrphanTimeout = e.cfg.CircuitCfg.OrphanTimeout
	}
	if e.cfg.CircuitCfg.MaxReassemblyWindow > 0 {
		cmCfg.MaxReassemblyWindow = e.cfg.CircuitCfg.MaxReassemblyWindow
	}
	if e.cfg.CircuitCfg.StreamReassemblyTimeout > 0 {
		cmCfg.StreamReassemblyTimeout = e.cfg.CircuitCfg.StreamReassemblyTimeout
	}
	if e.cfg.CircuitCfg.MaxNACKRetries > 0 {
		cmCfg.MaxNACKRetries = e.cfg.CircuitCfg.MaxNACKRetries
	}

	// Create the dispatcher with the assignment strategy.
	dispCfg := DispatcherConfig{
		ChunkerStrategy:    e.cfg.ChunkerStrategy,
		ChunkerCfg:         e.cfg.ChunkerCfg,
		CircuitCfg:         e.cfg.CircuitCfg,
		Path1:              e.path1,
		Path2:              e.path2,
		E2EKey:             e2eKey,
		CircuitID:          circuitID,
		ExitAddr:           e.cfg.ExitAddr,
		DebugFixedChunks:   e.cfg.DebugFixedChunks,
		AssignmentStrategy: e.cfg.ChunkAssignmentStrategy,
	}

	dispatcher, err := NewDispatcher(dispCfg, conn)
	if err != nil {
		return nil, fmt.Errorf("create dispatcher: %w", err)
	}

	// Store the circuit ID for teardown tracking.
	_ = cid // used by CircuitManager for lifecycle

	return &session{
		circuitID:    circuitID[:],
		circuitIDHex: circuitIDHex,
		e2eKey:       e2eKey,
		dispatcher:   dispatcher,
		conn:         conn,
	}, nil
}

// dialPath dials a mesh connection to the first relay on the given path
// (or directly to the exit if the path has no relays).
func (e *EntryNode) dialPath(ctx context.Context, pathIdx int) (net.Conn, error) {
	var path *Path
	if pathIdx == 0 {
		path = e.path1
	} else {
		path = e.path2
	}

	if path == nil {
		return nil, fmt.Errorf("path %d is nil", pathIdx)
	}

	// Determine the first hop address.
	var addr string
	if len(path.Relays) > 0 {
		addr = path.Relays[0]
	} else {
		addr = e.cfg.ExitAddr
	}

	conn, err := e.dialer(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	return conn, nil
}

// teardownCircuit closes the session's connections and cleans up.
// When CircuitManager is configured, it also initiates graceful teardown
// via the CM (flush, key zeroing, event emission).
func (e *EntryNode) teardownCircuit(sess *session) {
	if sess.cancel != nil {
		sess.cancel()
	}

	// Close path connections.
	for i := range sess.pathConns {
		if sess.pathConns[i] != nil {
			sess.pathConns[i].Close()
		}
	}

	// Close the dispatcher (also closes the SS connection).
	sess.dispatcher.Close()

	// If CircuitManager is set, initiate graceful teardown.
	// This handles key zeroing (AC-CL-07), ChunkStreamEnd flush
	// (AC-CL-05), and circuit removal from tracking (AC-CL-08).
	if e.circuitMgr != nil && len(sess.circuitID) == CircuitIDSize {
		var cid CircuitIDType
		copy(cid[:], sess.circuitID)
		// Teardown with nil sendChunkEnd — the dispatcher is already
		// closed, so we skip the flush step. The CM handles key zeroing
		// and tracking removal.
		go e.circuitMgr.TeardownCircuit(cid, "entry node connection close", nil)
	}
}

// Close shuts down the entry node: tears down all active circuits
// and shuts down the CircuitManager.
func (e *EntryNode) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	sessions := make(map[string]*session, len(e.sessions))
	for k, v := range e.sessions {
		sessions[k] = v
	}
	e.sessions = make(map[string]*session)
	e.mu.Unlock()

	// Cancel the entry node context (cancels all session goroutines).
	e.cancel()

	// Tear down all active sessions.
	var wg sync.WaitGroup
	for _, sess := range sessions {
		wg.Add(1)
		go func(s *session) {
			defer wg.Done()
			e.teardownCircuit(s)
		}(sess)
	}
	wg.Wait()

	// Shutdown the CircuitManager (tears down all tracked circuits,
	// zeros keys, emits CIRCUIT_CLOSED events).
	if e.circuitMgr != nil {
		e.circuitMgr.Shutdown()
	}

	return nil
}

// SessionCount returns the number of active proxy sessions.
func (e *EntryNode) SessionCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.sessions)
}

// Status returns the current entry node status.
type EntryNodeStatus struct {
	// Running is true if the entry node is active.
	Running bool

	// SessionCount is the number of active proxy sessions.
	SessionCount int

	// Path1Relays and Path2Relays list the relay node addresses
	// on each selected path.
	Path1Relays []string
	Path2Relays []string

	// ExitAddr is the mesh address of the exit node.
	ExitAddr string
}

// Status returns the current entry node status.
func (e *EntryNode) Status() EntryNodeStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	status := EntryNodeStatus{
		Running:      !e.closed,
		SessionCount: len(e.sessions),
		ExitAddr:     e.cfg.ExitAddr,
	}

	if e.path1 != nil {
		status.Path1Relays = e.path1.Relays
	}
	if e.path2 != nil {
		status.Path2Relays = e.path2.Relays
	}

	return status
}

// GenerateRandomBytes is a helper for generating random bytes for
// testing and configuration. Not for production crypto use.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
