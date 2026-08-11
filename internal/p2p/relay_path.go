package p2p

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// relayCircuitState tracks the state of a relay circuit on the entry node (A).
type relayCircuitState int

const (
	circuitSelecting   relayCircuitState = iota // selecting relays
	circuitSetupSent                            // circuit_setup sent to relay
	circuitActive                               // relay accepted, traffic flowing
	circuitFailingOver                          // primary failed, trying secondary
	circuitClosed                               // torn down
)

func (s relayCircuitState) String() string {
	switch s {
	case circuitSelecting:
		return "SELECTING"
	case circuitSetupSent:
		return "SETUP_SENT"
	case circuitActive:
		return "ACTIVE"
	case circuitFailingOver:
		return "FAILING_OVER"
	case circuitClosed:
		return "CLOSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// relayCircuit holds the per-target-peer circuit state on the entry node (A).
type relayCircuit struct {
	circuitID       string
	relayKey        string   // current relay's public key
	targetKey       string   // target peer (B) public key
	targetEndpoints []string // target peer (B) endpoints
	state           relayCircuitState
	pingFailures    int       // consecutive missed PONGs
	lastPong        time.Time // last successful PONG
	createdAt       time.Time

	// fallbackRelayKey is the secondary relay for failover.
	fallbackRelayKey string

	// quarantine tracks relays that have failed and are quarantined.
	quarantine map[string]time.Time // relayKey → quarantine until

	mu sync.Mutex
}

// RelayPathBuilderImpl implements RelayPathBuilder. It manages the lifecycle
// of relay circuits for NAT peers on the entry node (A).
//
// When a NAT peer (B) with no public endpoints is discovered via gossip:
//  1. Select top-K=2 relay candidates via RelaySelector
//  2. Send circuit_setup to the primary relay (R1)
//  3. On accept, extend R1's AllowedIPs to include B's mesh IP
//  4. Health-check R1 every 30s via PING/PONG
//  5. If R1 fails (3 missed PONGs), fail over to R2
type RelayPathBuilderImpl struct {
	// gossip provides access to relay message sending and relay selection.
	gossip *GossipLayer

	// wg is the peer manager (for AddRelayTarget/RemoveRelayTarget).
	wg PeerManager

	// selector scores and selects relay candidates.
	selector *RelaySelector

	// events provides access to the peer metadata cache.
	events *meshEventDelegate

	// circuits maps target peer key → circuit state.
	circuits map[string]*relayCircuit

	// rttFunc estimates RTT to a peer. If nil, a default 100ms is used.
	rttFunc func(peerKey string) time.Duration

	// localKey is this node's own public key (for circuit IDs).
	localKey string

	mu     sync.Mutex
	stopCh chan struct{}
}

// NewRelayPathBuilder creates a new RelayPathBuilder.
//
// Parameters:
//   - gossip: the gossip layer (for sending relay messages and selecting relays)
//   - wg: the peer manager (for AddRelayTarget on the entry node)
//   - selector: the relay selector (for scoring relay candidates)
//   - events: the event delegate (for accessing peer metadata)
//   - localKey: this node's public key
func NewRelayPathBuilder(gossip *GossipLayer, wg PeerManager, selector *RelaySelector, events *meshEventDelegate, localKey string) RelayPathBuilder {
	rpb := &RelayPathBuilderImpl{
		gossip:   gossip,
		wg:       wg,
		selector: selector,
		events:   events,
		circuits: make(map[string]*relayCircuit),
		localKey: localKey,
		stopCh:   make(chan struct{}),
	}

	// Default RTT estimator: 100ms for all peers.
	// The gossip layer can override this with a real estimator.
	rpb.rttFunc = func(peerKey string) time.Duration {
		return 100 * time.Millisecond
	}

	return rpb
}

// SetRTTEstimator installs a custom RTT estimator function.
func (rpb *RelayPathBuilderImpl) SetRTTEstimator(fn func(peerKey string) time.Duration) {
	rpb.mu.Lock()
	defer rpb.mu.Unlock()
	rpb.rttFunc = fn
}

// OnNATPeerDiscovered is called by NotifyJoin when a NAT peer with no
// endpoints is discovered. It selects relays and sets up the circuit.
func (rpb *RelayPathBuilderImpl) OnNATPeerDiscovered(meta *NodeMeta) {
	if meta == nil || meta.PublicKey == "" {
		return
	}

	rpb.mu.Lock()
	// Check if we already have a circuit for this peer.
	if existing, ok := rpb.circuits[meta.PublicKey]; ok && existing.state != circuitClosed {
		rpb.mu.Unlock()
		return // already handling this peer
	}
	rpb.mu.Unlock()

	log.Printf("[p2p/relay] NAT peer %s discovered (no endpoints), selecting relay...",
		safeShortKey(meta.PublicKey))

	// Select top-K=2 relay candidates.
	rpb.mu.Lock()
	rttFunc := rpb.rttFunc
	rpb.mu.Unlock()

	candidates := rpb.selector.SelectRelays(2, 3, rttFunc)
	if len(candidates) == 0 {
		log.Printf("[p2p/relay] no relay candidates available for NAT peer %s — will retry on next reconciliation",
			safeShortKey(meta.PublicKey))
		return
	}

	primary := candidates[0]
	var fallbackKey string
	if len(candidates) > 1 {
		fallbackKey = candidates[1].Meta.PublicKey
	}

	circuitID := generateCircuitID()
	circuit := &relayCircuit{
		circuitID:        circuitID,
		relayKey:         primary.Meta.PublicKey,
		targetKey:        meta.PublicKey,
		targetEndpoints:  meta.Endpoints,
		state:            circuitSelecting,
		createdAt:        time.Now(),
		fallbackRelayKey: fallbackKey,
		quarantine:       make(map[string]time.Time),
	}

	rpb.mu.Lock()
	rpb.circuits[meta.PublicKey] = circuit
	rpb.mu.Unlock()

	// Send circuit_setup to the primary relay.
	rpb.sendCircuitSetup(circuit)

	// Start health monitoring for this circuit.
	go rpb.healthCheckLoop(circuit)
}

// OnPeerLeft cleans up relay circuits when a peer leaves.
func (rpb *RelayPathBuilderImpl) OnPeerLeft(peerKey string) {
	rpb.mu.Lock()
	circuit, ok := rpb.circuits[peerKey]
	if !ok {
		rpb.mu.Unlock()
		return
	}
	delete(rpb.circuits, peerKey)
	rpb.mu.Unlock()

	// Tear down the circuit on the relay.
	rpb.sendCircuitTeardown(circuit)

	// Remove the relay target from our PeerManager.
	if rpb.wg != nil {
		if err := rpb.wg.RemoveRelayTarget(circuit.targetKey); err != nil {
			log.Printf("[p2p/relay] failed to remove relay target for %s: %v",
				safeShortKey(peerKey), err)
		}
	}

	log.Printf("[p2p/relay] cleaned up circuit for peer %s (left mesh)",
		safeShortKey(peerKey))
}

// sendCircuitSetup sends a circuit_setup message to the relay.
func (rpb *RelayPathBuilderImpl) sendCircuitSetup(circuit *relayCircuit) {
	if rpb.gossip == nil {
		log.Printf("[p2p/relay] cannot send circuit_setup: no gossip layer")
		return
	}

	circuit.mu.Lock()
	circuit.state = circuitSetupSent
	circuit.mu.Unlock()

	msg := RelaySetupRequest(
		rpb.localKey,            // from (A)
		circuit.relayKey,        // to (R)
		circuit.circuitID,       // circuit ID
		circuit.targetKey,       // target (B)
		circuit.targetEndpoints, // target endpoints
	)

	rpb.gossip.SendRelayMessage(circuit.relayKey, msg)

	log.Printf("[p2p/relay] sent circuit_setup to relay %s for target %s (circuit %s)",
		safeShortKey(circuit.relayKey), safeShortKey(circuit.targetKey), safeShortKey(circuit.circuitID))
}

// sendCircuitTeardown sends a circuit_teardown message to the relay.
func (rpb *RelayPathBuilderImpl) sendCircuitTeardown(circuit *relayCircuit) {
	if rpb.gossip == nil {
		return
	}

	msg := RelayTeardownRequest(
		rpb.localKey,     // from (A)
		circuit.relayKey, // to (R)
		circuit.circuitID,
	)

	rpb.gossip.SendRelayMessage(circuit.relayKey, msg)
}

// HandleAccept processes a circuit_accept from the relay.
// This is called on the entry node (A) when the relay (R) confirms the circuit.
func (rpb *RelayPathBuilderImpl) HandleAccept(msg *RelayMessage) {
	rpb.mu.Lock()
	// Find the circuit by circuit ID.
	var circuit *relayCircuit
	for _, c := range rpb.circuits {
		if c.circuitID == msg.CircuitID {
			circuit = c
			break
		}
	}
	rpb.mu.Unlock()

	if circuit == nil {
		log.Printf("[p2p/relay] received accept for unknown circuit %s", safeShortKey(msg.CircuitID))
		return
	}

	circuit.mu.Lock()
	previousState := circuit.state
	circuit.state = circuitActive
	circuit.lastPong = time.Now()
	circuit.pingFailures = 0
	circuit.mu.Unlock()

	// On the entry node (A), add the relay target so that traffic
	// destined for B is forwarded through R.
	if rpb.wg != nil && previousState != circuitActive {
		if err := rpb.wg.AddRelayTarget(circuit.targetKey, circuit.targetEndpoints); err != nil {
			log.Printf("[p2p/relay] failed to add relay target for %s via relay %s: %v",
				safeShortKey(circuit.targetKey), safeShortKey(circuit.relayKey), err)
		} else {
			log.Printf("[p2p/relay] circuit %s active: target %s routed via relay %s",
				safeShortKey(circuit.circuitID), safeShortKey(circuit.targetKey), safeShortKey(circuit.relayKey))
		}
	}
}

// HandleReject processes a circuit_reject from the relay.
func (rpb *RelayPathBuilderImpl) HandleReject(msg *RelayMessage) {
	rpb.mu.Lock()
	var circuit *relayCircuit
	for _, c := range rpb.circuits {
		if c.circuitID == msg.CircuitID {
			circuit = c
			break
		}
	}
	rpb.mu.Unlock()

	if circuit == nil {
		return
	}

	log.Printf("[p2p/relay] circuit %s rejected by relay %s: %s",
		safeShortKey(circuit.circuitID), safeShortKey(msg.FromKey), msg.RejectReason)

	// Try fallback relay.
	rpb.tryFallback(circuit)
}

// HandlePong processes a relay_pong from the relay node.
func (rpb *RelayPathBuilderImpl) HandlePong(msg *RelayMessage) {
	rpb.mu.Lock()
	var circuit *relayCircuit
	for _, c := range rpb.circuits {
		if c.circuitID == msg.CircuitID {
			circuit = c
			break
		}
	}
	rpb.mu.Unlock()

	if circuit == nil {
		return
	}

	circuit.mu.Lock()
	circuit.lastPong = time.Now()
	circuit.pingFailures = 0
	circuit.mu.Unlock()
}

// tryFallback attempts to use the secondary relay.
func (rpb *RelayPathBuilderImpl) tryFallback(circuit *relayCircuit) {
	circuit.mu.Lock()
	fallbackKey := circuit.fallbackRelayKey
	if fallbackKey == "" || circuit.state == circuitFailingOver {
		circuit.mu.Unlock()
		log.Printf("[p2p/relay] no fallback relay available for target %s",
			safeShortKey(circuit.targetKey))
		return
	}

	// Quarantine the failed relay.
	circuit.quarantine[circuit.relayKey] = time.Now().Add(60 * time.Second)
	circuit.relayKey = fallbackKey
	circuit.fallbackRelayKey = "" // used up the fallback
	circuit.state = circuitFailingOver
	circuit.circuitID = generateCircuitID() // new circuit ID for the new relay
	circuit.mu.Unlock()

	log.Printf("[p2p/relay] failing over to secondary relay %s for target %s",
		safeShortKey(fallbackKey), safeShortKey(circuit.targetKey))

	// Send circuit_setup to the fallback relay.
	rpb.sendCircuitSetup(circuit)
}

// healthCheckLoop sends periodic PING messages to the relay and
// monitors for PONG responses. If 3 consecutive PONGs are missed,
// it triggers failover to the secondary relay.
func (rpb *RelayPathBuilderImpl) healthCheckLoop(circuit *relayCircuit) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rpb.stopCh:
			return
		case <-ticker.C:
		}

		rpb.mu.Lock()
		c, ok := rpb.circuits[circuit.targetKey]
		rpb.mu.Unlock()
		if !ok {
			return
		}

		c.mu.Lock()
		// state is written under c.mu elsewhere — reading it here without
		// the lock is a data race. Read it inside the lock.
		if c.state == circuitClosed {
			c.mu.Unlock()
			return
		}
		if c.state != circuitActive && c.state != circuitSetupSent {
			c.mu.Unlock()
			continue
		}

		// Check for missed PONGs.
		if !c.lastPong.IsZero() && time.Since(c.lastPong) > 90*time.Second {
			c.pingFailures++
		}

		if c.pingFailures >= 3 {
			log.Printf("[p2p/relay] relay %s unresponsive (3 missed PONGs), failing over",
				safeShortKey(c.relayKey))
			c.mu.Unlock()
			rpb.tryFallback(c)
			continue
		}

		// Send PING.
		circuitID := c.circuitID
		relayKey := c.relayKey
		c.mu.Unlock()

		if rpb.gossip != nil {
			ping := RelayPingMessage(rpb.localKey, relayKey, circuitID)
			rpb.gossip.SendRelayMessage(relayKey, ping)
		}
	}
}

// ReconcileNATPeers scans for NAT peers without circuits and establishes them.
// This handles the case where a relay joins after NAT peers are discovered.
func (rpb *RelayPathBuilderImpl) ReconcileNATPeers() {
	if rpb.events == nil {
		return
	}

	peers := rpb.events.AllKnownPeers()
	for _, meta := range peers {
		if firstNonEmpty(meta.Endpoints) == "" && meta.PublicKey != rpb.localKey {
			rpb.mu.Lock()
			circuit, hasCircuit := rpb.circuits[meta.PublicKey]
			rpb.mu.Unlock()

			if !hasCircuit || (circuit != nil && circuit.state == circuitClosed) {
				log.Printf("[p2p/relay] reconciliation: establishing circuit for NAT peer %s",
					safeShortKey(meta.PublicKey))
				rpb.OnNATPeerDiscovered(meta)
			}
		}
	}
}

// StartReconciliationLoop starts a periodic goroutine that reconciles
// NAT peers without relay circuits. Call after the gossip layer is started.
func (rpb *RelayPathBuilderImpl) StartReconciliationLoop() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-rpb.stopCh:
				return
			case <-ticker.C:
				rpb.ReconcileNATPeers()
			}
		}
	}()
}

// Stop shuts down the relay path builder.
func (rpb *RelayPathBuilderImpl) Stop() {
	close(rpb.stopCh)
}
