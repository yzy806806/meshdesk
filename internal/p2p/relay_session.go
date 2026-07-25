package p2p

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// RelaySessionState tracks the lifecycle of a single relay circuit
// on the relay node.
type RelaySessionState int

const (
	RelaySessionPending RelaySessionState = iota // SETUP received, not yet accepted
	RelaySessionActive                           // ACCEPT sent, forwarding traffic
	RelaySessionClosing                          // TEARDOWN received, draining
)

// String returns a human-readable state name.
func (s RelaySessionState) String() string {
	switch s {
	case RelaySessionPending:
		return "PENDING"
	case RelaySessionActive:
		return "ACTIVE"
	case RelaySessionClosing:
		return "CLOSING"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// relaySession holds the per-circuit state on the relay node.
// One relay can manage many concurrent sessions up to MaxCircuits.
type relaySession struct {
	// CircuitID is the unique identifier for this circuit.
	CircuitID string

	// EntryKey is the public key of the entry node that requested
	// this circuit.
	EntryKey string

	// TargetKey is the public key of the peer whose traffic is
	// being relayed.
	TargetKey string

	// TargetMeshIP is the mesh IP of the target peer.
	TargetMeshIP string

	// State is the current session state.
	State RelaySessionState

	// CreatedAt is when the session was created (SETUP received).
	CreatedAt time.Time

	// ActivatedAt is when the session became ACTIVE.
	ActivatedAt time.Time

	// LastActivity is the last time data flowed through this circuit
	// (ping/pong or data forwarding).
	LastActivity time.Time

	// LastPing is the last time a ping was received from the entry.
	LastPing time.Time

	// mu protects all fields.
	mu sync.Mutex
}

// RelaySessionManager manages relay circuits on a relay-capable node.
// It handles:
//   - Accepting circuit_setup requests (capacity check, duplicate check)
//   - Tracking active circuits (for load metric reporting)
//   - Health monitoring (ping/pong, idle timeout)
//   - Teardown (circuit_teardown, idle sweep)
//
// This implements the relay session lifecycle from
// P2P_NETWORKING_SPEC.md §5.3.
type RelaySessionManager struct {
	// localKey is this node's WireGuard public key.
	localKey string

	// maxCircuits is the hard limit on concurrent circuits.
	maxCircuits int

	// idleTimeout is how long a circuit can be idle before automatic teardown.
	idleTimeout time.Duration

	// healthCheckInterval is how often to check for idle circuits.
	healthCheckInterval time.Duration

	// mu protects the sessions map and pendingCount.
	mu sync.RWMutex

	// sessions maps circuit ID → session state.
	sessions map[string]*relaySession

	// pendingCount is the number of sessions in PENDING state.
	// Used to reserve capacity for in-flight setup requests.
	pendingCount int

	// msgSender sends relay messages via gossip to a specific peer.
	// Set via SetMessageSender. If nil, messages are logged but not sent
	// (useful for testing).
	msgSender func(peerKey string, msg *RelayMessage)

	// eventDelegate provides access to the peer metadata cache
	// (for looking up relay candidates, updating load metrics).
	events *meshEventDelegate

	// delegate provides access to update local NodeMeta (load metrics).
	delegate *meshDelegate

	// stopCh closes on Stop().
	stopCh chan struct{}

	// started tracks whether the manager is running.
	started bool
}

// RelaySessionManagerConfig holds configuration for the relay session manager.
type RelaySessionManagerConfig struct {
	// MaxCircuits is the hard limit on concurrent circuits. Default: 1024.
	MaxCircuits int

	// IdleTimeout is how long a circuit can be idle before teardown.
	// Default: 5 minutes (300s).
	IdleTimeout time.Duration

	// HealthCheckInterval is how often to sweep for idle circuits.
	// Default: 30 seconds.
	HealthCheckInterval time.Duration
}

// DefaultRelaySessionManagerConfig returns sensible defaults.
func DefaultRelaySessionManagerConfig() RelaySessionManagerConfig {
	return RelaySessionManagerConfig{
		MaxCircuits:         1024,
		IdleTimeout:         5 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
	}
}

// NewRelaySessionManager creates a new relay session manager.
//
// Parameters:
//   - localKey: this node's WireGuard public key (hex)
//   - events: the mesh event delegate (for peer metadata lookups)
//   - delegate: the mesh delegate (for updating local load metrics)
//   - cfg: configuration
func NewRelaySessionManager(localKey string, events *meshEventDelegate, delegate *meshDelegate, cfg RelaySessionManagerConfig) *RelaySessionManager {
	if cfg.MaxCircuits <= 0 {
		cfg.MaxCircuits = 1024
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.HealthCheckInterval <= 0 {
		cfg.HealthCheckInterval = 30 * time.Second
	}

	return &RelaySessionManager{
		localKey:            localKey,
		maxCircuits:         cfg.MaxCircuits,
		idleTimeout:         cfg.IdleTimeout,
		healthCheckInterval: cfg.HealthCheckInterval,
		sessions:            make(map[string]*relaySession),
		events:              events,
		delegate:            delegate,
		stopCh:              make(chan struct{}),
	}
}

// SetMessageSender installs a function that sends relay messages
// to a specific peer via gossip. The GossipLayer calls this during
// initialization to wire the message transport.
func (rsm *RelaySessionManager) SetMessageSender(sender func(peerKey string, msg *RelayMessage)) {
	rsm.mu.Lock()
	defer rsm.mu.Unlock()
	rsm.msgSender = sender
}

// sendMessage sends a relay message to the specified peer.
// No-op if no sender is installed.
func (rsm *RelaySessionManager) sendMessage(peerKey string, msg *RelayMessage) {
	rsm.mu.RLock()
	sender := rsm.msgSender
	rsm.mu.RUnlock()

	if sender != nil {
		sender(peerKey, msg)
	} else {
		log.Printf("[p2p/relay] (no sender) would send %s to %s for circuit %s",
			msg.Type, shortKey(peerKey), msg.CircuitID)
	}
}

// HandleMessage processes an incoming relay control message.
// This is called by the delegate's NotifyMsg when a relay message
// is received via gossip.
//
// The message must have already been decoded by the caller.
// Returns an error if the message is invalid or cannot be processed.
func (rsm *RelaySessionManager) HandleMessage(msg *RelayMessage) error {
	// Only process messages addressed to us (or broadcast).
	if msg.ToKey != "" && msg.ToKey != rsm.localKey {
		return nil // not for us
	}

	switch msg.Type {
	case MsgRelaySetup:
		return rsm.handleSetup(msg)
	case MsgRelayAccept:
		return rsm.handleAccept(msg)
	case MsgRelayReject:
		return rsm.handleReject(msg)
	case MsgRelayTeardown:
		return rsm.handleTeardown(msg)
	case MsgRelayPing:
		return rsm.handlePing(msg)
	case MsgRelayPong:
		return rsm.handlePong(msg)
	default:
		return fmt.Errorf("unknown relay message type: %d", msg.Type)
	}
}

// handleSetup processes a circuit_setup request from an entry node.
// It checks capacity and duplicate circuits, creates a session, and
// sends an ACCEPT or REJECT response.
func (rsm *RelaySessionManager) handleSetup(msg *RelayMessage) error {
	if msg.CircuitID == "" {
		return fmt.Errorf("setup message missing circuit ID")
	}
	if msg.FromKey == "" {
		return fmt.Errorf("setup message missing entry key")
	}
	if msg.TargetKey == "" || msg.TargetMeshIP == "" {
		return fmt.Errorf("setup message missing target info")
	}

	rsm.mu.Lock()

	// Check for duplicate circuit.
	if _, exists := rsm.sessions[msg.CircuitID]; exists {
		rsm.mu.Unlock()
		rsm.sendMessage(msg.FromKey, RelayRejectResponse(
			rsm.localKey, msg.FromKey, msg.CircuitID, RejectDuplicate,
		))
		log.Printf("[p2p/relay] rejected duplicate circuit %s from %s",
			msg.CircuitID, shortKey(msg.FromKey))
		return nil
	}

	// Check capacity (including pending sessions).
	totalCircuits := len(rsm.sessions) + rsm.pendingCount
	if totalCircuits >= rsm.maxCircuits {
		rsm.mu.Unlock()
		rsm.sendMessage(msg.FromKey, RelayRejectResponse(
			rsm.localKey, msg.FromKey, msg.CircuitID, RejectAtCapacity,
		))
		log.Printf("[p2p/relay] rejected circuit %s: at capacity (%d/%d)",
			msg.CircuitID, totalCircuits, rsm.maxCircuits)
		return nil
	}

	// Create the session in PENDING state.
	rsm.sessions[msg.CircuitID] = &relaySession{
		CircuitID:    msg.CircuitID,
		EntryKey:     msg.FromKey,
		TargetKey:    msg.TargetKey,
		TargetMeshIP: msg.TargetMeshIP,
		State:        RelaySessionPending,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	rsm.pendingCount++
	rsm.mu.Unlock()

	// In a real relay, we would configure the WireGuard forwarding
	// rules here (add AllowedIPs for the target peer, set up the
	// packet forwarder). For the P2P layer, the relay simply tracks
	// the session — actual data forwarding happens via WireGuard's
	// native packet routing (the relay's WG peer has the target's
	// AllowedIPs, so packets are forwarded automatically).

	// Accept the circuit.
	rsm.mu.Lock()
	if session, ok := rsm.sessions[msg.CircuitID]; ok {
		session.State = RelaySessionActive
		session.ActivatedAt = time.Now()
	}
	rsm.pendingCount--
	rsm.mu.Unlock()

	// Send ACCEPT response.
	rsm.sendMessage(msg.FromKey, RelayAcceptResponse(
		rsm.localKey, msg.FromKey, msg.CircuitID,
	))

	// Update local load metrics (increment circuit count).
	rsm.updateLoadMetrics()

	log.Printf("[p2p/relay] accepted circuit %s from %s (target %s)",
		msg.CircuitID, shortKey(msg.FromKey), shortKey(msg.TargetKey))
	return nil
}

// handleAccept processes a circuit_accept response from a relay.
// This is called on the entry node when the relay confirms the circuit.
func (rsm *RelaySessionManager) handleAccept(msg *RelayMessage) error {
	// On the entry side, we don't track sessions in the manager —
	// the NAT traversal layer handles the entry-side circuit state.
	// This callback exists for future extension (e.g., entry-side
	// circuit tracking). For now, just log.
	log.Printf("[p2p/relay] circuit %s accepted by relay %s",
		msg.CircuitID, shortKey(msg.FromKey))
	return nil
}

// handleReject processes a circuit_reject response from a relay.
// This is called on the entry node when the relay refuses the circuit.
func (rsm *RelaySessionManager) handleReject(msg *RelayMessage) error {
	log.Printf("[p2p/relay] circuit %s rejected by relay %s: %s",
		msg.CircuitID, shortKey(msg.FromKey), msg.RejectReason)
	return nil
}

// handleTeardown processes a circuit_teardown request from an entry node.
// It removes the circuit and decrements the load.
func (rsm *RelaySessionManager) handleTeardown(msg *RelayMessage) error {
	rsm.mu.Lock()
	session, ok := rsm.sessions[msg.CircuitID]
	if !ok {
		rsm.mu.Unlock()
		return nil // idempotent — already removed
	}

	// Verify the teardown came from the entry that created the circuit.
	if msg.FromKey != session.EntryKey {
		rsm.mu.Unlock()
		log.Printf("[p2p/relay] teardown for circuit %s from unauthorized key %s (expected %s)",
			msg.CircuitID, shortKey(msg.FromKey), shortKey(session.EntryKey))
		return fmt.Errorf("unauthorized teardown")
	}

	delete(rsm.sessions, msg.CircuitID)
	rsm.mu.Unlock()

	// Update local load metrics (decrement circuit count).
	rsm.updateLoadMetrics()

	log.Printf("[p2p/relay] torn down circuit %s (was active for %v)",
		msg.CircuitID, time.Since(session.CreatedAt).Round(time.Second))
	return nil
}

// handlePing processes a relay_ping from the entry node.
// It updates the last-activity timestamp and responds with a PONG.
func (rsm *RelaySessionManager) handlePing(msg *RelayMessage) error {
	rsm.mu.Lock()
	session, ok := rsm.sessions[msg.CircuitID]
	if !ok {
		rsm.mu.Unlock()
		// Ping for unknown circuit — ignore (may have been torn down).
		return nil
	}
	session.mu.Lock()
	session.LastPing = time.Now()
	session.LastActivity = time.Now()
	entryKey := session.EntryKey
	session.mu.Unlock()
	rsm.mu.Unlock()

	// Respond with PONG.
	rsm.sendMessage(entryKey, RelayPongResponse(
		rsm.localKey, entryKey, msg.CircuitID,
	))
	return nil
}

// handlePong processes a relay_pong from the relay node.
// This is called on the entry node to confirm circuit health.
func (rsm *RelaySessionManager) handlePong(msg *RelayMessage) error {
	log.Printf("[p2p/relay] pong received for circuit %s from relay %s",
		msg.CircuitID, shortKey(msg.FromKey))
	return nil
}

// ActiveCircuitCount returns the number of active relay circuits.
func (rsm *RelaySessionManager) ActiveCircuitCount() int {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()
	count := 0
	for _, s := range rsm.sessions {
		if s.State == RelaySessionActive {
			count++
		}
	}
	return count
}

// TotalCircuitCount returns the total number of tracked circuits
// (active + pending).
func (rsm *RelaySessionManager) TotalCircuitCount() int {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()
	return len(rsm.sessions)
}

// MaxCircuits returns the configured maximum.
func (rsm *RelaySessionManager) MaxCircuits() int {
	return rsm.maxCircuits
}

// IsAtCapacity returns true if the relay cannot accept more circuits.
func (rsm *RelaySessionManager) IsAtCapacity() bool {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()
	return len(rsm.sessions)+rsm.pendingCount >= rsm.maxCircuits
}

// CircuitIDs returns the IDs of all tracked circuits.
func (rsm *RelaySessionManager) CircuitIDs() []string {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()
	ids := make([]string, 0, len(rsm.sessions))
	for id := range rsm.sessions {
		ids = append(ids, id)
	}
	return ids
}

// GetSessionInfo returns a snapshot of a circuit's state.
type RelaySessionInfo struct {
	CircuitID    string
	EntryKey     string
	TargetKey    string
	TargetMeshIP string
	State        RelaySessionState
	CreatedAt    time.Time
	ActivatedAt  time.Time
	LastActivity time.Time
}

// GetSessionInfo returns a snapshot of a circuit's state, or nil if not found.
func (rsm *RelaySessionManager) GetSessionInfo(circuitID string) *RelaySessionInfo {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()
	s, ok := rsm.sessions[circuitID]
	if !ok {
		return nil
	}
	s.mu.Lock()
	info := &RelaySessionInfo{
		CircuitID:    s.CircuitID,
		EntryKey:     s.EntryKey,
		TargetKey:    s.TargetKey,
		TargetMeshIP: s.TargetMeshIP,
		State:        s.State,
		CreatedAt:    s.CreatedAt,
		ActivatedAt:  s.ActivatedAt,
		LastActivity: s.LastActivity,
	}
	s.mu.Unlock()
	return info
}

// AllSessions returns snapshots of all tracked circuits.
func (rsm *RelaySessionManager) AllSessions() []*RelaySessionInfo {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()
	result := make([]*RelaySessionInfo, 0, len(rsm.sessions))
	for _, s := range rsm.sessions {
		s.mu.Lock()
		result = append(result, &RelaySessionInfo{
			CircuitID:    s.CircuitID,
			EntryKey:     s.EntryKey,
			TargetKey:    s.TargetKey,
			TargetMeshIP: s.TargetMeshIP,
			State:        s.State,
			CreatedAt:    s.CreatedAt,
			ActivatedAt:  s.ActivatedAt,
			LastActivity: s.LastActivity,
		})
		s.mu.Unlock()
	}
	return result
}

// updateLoadMetrics updates the local node's LoadCircuits in NodeMeta
// and triggers a gossip broadcast of the updated metadata.
func (rsm *RelaySessionManager) updateLoadMetrics() {
	if rsm.delegate == nil {
		return
	}
	count := rsm.ActiveCircuitCount()
	rsm.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.LoadCircuits = count
		m.Seq++
	})
}

// Start begins the idle-circuit sweep goroutine.
func (rsm *RelaySessionManager) Start() error {
	rsm.mu.Lock()
	if rsm.started {
		rsm.mu.Unlock()
		return fmt.Errorf("relay session manager already started")
	}
	rsm.started = true
	rsm.mu.Unlock()

	go rsm.idleSweepLoop()
	log.Printf("[p2p/relay] session manager started (maxCircuits=%d, idleTimeout=%v)",
		rsm.maxCircuits, rsm.idleTimeout)
	return nil
}

// Stop shuts down the relay session manager.
func (rsm *RelaySessionManager) Stop() error {
	rsm.mu.Lock()
	if !rsm.started {
		rsm.mu.Unlock()
		return nil
	}
	rsm.started = false
	rsm.mu.Unlock()

	close(rsm.stopCh)
	log.Printf("[p2p/relay] session manager stopped (%d circuits cleared)", rsm.TotalCircuitCount())
	return nil
}

// idleSweepLoop periodically checks for idle circuits and tears them down.
// A circuit is considered idle if no data or ping has been received for
// IdleTimeout (default: 5 minutes).
func (rsm *RelaySessionManager) idleSweepLoop() {
	ticker := time.NewTicker(rsm.healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rsm.stopCh:
			return
		case <-ticker.C:
		}

		rsm.sweepIdleCircuits()
	}
}

// sweepIdleCircuits finds and removes circuits that have been idle
// for longer than IdleTimeout.
func (rsm *RelaySessionManager) sweepIdleCircuits() {
	rsm.mu.Lock()
	var toRemove []string
	for id, s := range rsm.sessions {
		s.mu.Lock()
		idle := time.Since(s.LastActivity) > rsm.idleTimeout
		s.mu.Unlock()
		if idle {
			toRemove = append(toRemove, id)
		}
	}

	for _, id := range toRemove {
		delete(rsm.sessions, id)
	}
	rsm.mu.Unlock()

	if len(toRemove) > 0 {
		rsm.updateLoadMetrics()
		log.Printf("[p2p/relay] swept %d idle circuits (idle > %v)", len(toRemove), rsm.idleTimeout)
	}
}

// shortKey returns the first 8 characters of a public key for logging.
func shortKey(key string) string {
	if len(key) < 8 {
		return key
	}
	return key[:8]
}
