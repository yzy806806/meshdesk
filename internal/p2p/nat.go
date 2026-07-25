package p2p

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// NatState is the state of the NAT traversal state machine for a single peer.
// States follow §3.3 of P2P_NETWORKING_SPEC.md.
type NatState int

const (
	// NatInit is the initial state — no peer connections yet.
	NatInit NatState = iota

	// NatStunDiscovery — querying STUN servers for public endpoint + NAT type.
	NatStunDiscovery

	// NatDirectProbe — attempting direct WireGuard handshake to peer's
	// STUN-discovered endpoint via hole-punching.
	NatDirectProbe

	// NatDirect — direct WireGuard connection established.
	NatDirect

	// NatRelayFallback — relaying WireGuard traffic through a relay peer.
	NatRelayFallback

	// NatDirectReprobe — re-attempting direct connection while in relay mode.
	NatDirectReprobe

	// NatActive — a valid connection exists (either DIRECT or RELAY).
	NatActive

	// NatRetry — connection lost, retrying with exponential backoff.
	NatRetry

	// NatFailed — all retry attempts exhausted. Peer is unreachable.
	NatFailed
)

// String returns a human-readable state name.
func (s NatState) String() string {
	switch s {
	case NatInit:
		return "INIT"
	case NatStunDiscovery:
		return "STUN_DISCOVERY"
	case NatDirectProbe:
		return "DIRECT_PROBE"
	case NatDirect:
		return "DIRECT"
	case NatRelayFallback:
		return "RELAY_FALLBACK"
	case NatDirectReprobe:
		return "DIRECT_REPROBE"
	case NatActive:
		return "ACTIVE"
	case NatRetry:
		return "RETRY"
	case NatFailed:
		return "FAILED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// NatSession tracks the NAT traversal state for a single peer connection.
// It implements the NatSession struct from §3.4 of the spec.
type NatSession struct {
	// PeerKey is the WireGuard public key of the remote peer.
	PeerKey string

	// State is the current state machine state.
	State NatState

	// Endpoints are the peer's STUN-discovered public endpoints.
	Endpoints []string

	// NatType is the local node's NAT classification.
	NatType NatType

	// RemoteNatType is the peer's NAT type (from gossip NodeMeta).
	RemoteNatType NatType

	// Retries is the current retry count.
	Retries int

	// MaxRetries is the maximum number of retries before FAILED.
	MaxRetries int

	// LastProbe is when the last probe was attempted.
	LastProbe time.Time

	// RelayVia is the peer key of the relay being used (if in relay mode).
	RelayVia string

	// Established is when the connection became Active.
	Established time.Time

	// localEndpoint is our STUN-discovered public endpoint.
	localEndpoint string

	// mu protects all fields above.
	mu sync.Mutex
}

// NatTraversalConfig holds configuration for the NAT traversal module.
type NatTraversalConfig struct {
	// StunServers is the list of STUN server addresses.
	StunServers []string

	// DirectReprobeInterval is seconds between direct reprobes when in
	// relay fallback mode. Default: 120.
	DirectReprobeInterval time.Duration

	// MaxRetries is the max retry attempts before FAILED. Default: 10.
	MaxRetries int

	// ProbeTimeout is the timeout for a single direct probe attempt.
	ProbeTimeout time.Duration

	// RelayMode controls relay fallback behavior:
	// "auto" (default), "manual", "disabled".
	RelayMode string

	// MaxRelayHops is the max relay hops. Default: 2.
	MaxRelayHops int
}

// DefaultNatTraversalConfig returns sensible defaults.
func DefaultNatTraversalConfig() NatTraversalConfig {
	return NatTraversalConfig{
		StunServers:           []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"},
		DirectReprobeInterval: 120 * time.Second,
		MaxRetries:            10,
		ProbeTimeout:          5 * time.Second,
		RelayMode:             "auto",
		MaxRelayHops:          2,
	}
}

// NatTraversalFromP2pConfig converts a P2pConfig to a NatTraversalConfig.
func NatTraversalFromP2pConfig(cfg P2pConfig) NatTraversalConfig {
	nc := DefaultNatTraversalConfig()
	if len(cfg.StunServers) > 0 {
		nc.StunServers = cfg.StunServers
	}
	if cfg.DirectReprobeInterval > 0 {
		nc.DirectReprobeInterval = time.Duration(cfg.DirectReprobeInterval) * time.Second
	}
	if cfg.RelayMode != "" {
		nc.RelayMode = cfg.RelayMode
	}
	if cfg.MaxRelayHops > 0 {
		nc.MaxRelayHops = cfg.MaxRelayHops
	}
	return nc
}

// NatTraversal is the top-level coordinator for NAT traversal. It manages
// per-peer NatSessions, runs STUN discovery, performs hole-punching,
// and falls back to relay when direct connection fails.
//
// The state machine flow (§3.3):
//
//	INIT → STUN_DISCOVERY → DIRECT_PROBE → DIRECT (success) or RELAY_FALLBACK
//	RELAY_FALLBACK → DIRECT_REPROBE (every 120s) → DIRECT (success) or back to RELAY
//	DIRECT/RELAY → ACTIVE → RETRY (on connection loss) → back to STUN_DISCOVERY or FAILED
type NatTraversal struct {
	cfg         NatTraversalConfig
	wgDelegate  PeerManager
	relay       *RelaySelector
	events      *meshEventDelegate
	stun        *StunClient
	puncher     *HolePunchCoordinator
	meshPort    int

	mu        sync.RWMutex
	sessions  map[string]*NatSession // peerKey → session
	localEP   string
	localNat  NatType
	started   bool
	stopCh    chan struct{}
	reprobeTC *time.Ticker
}

// NewNatTraversal creates a new NAT traversal coordinator.
func NewNatTraversal(cfg NatTraversalConfig, wgDelegate PeerManager, relay *RelaySelector, events *meshEventDelegate, meshPort int) *NatTraversal {
	return &NatTraversal{
		cfg:        cfg,
		wgDelegate: wgDelegate,
		relay:      relay,
		events:     events,
		stun:       NewStunClient(cfg.StunServers, 5*time.Second),
		puncher:    NewHolePunchCoordinator(),
		meshPort:   meshPort,
		sessions:   make(map[string]*NatSession),
		stopCh:     make(chan struct{}),
	}
}

// Start initializes the NAT traversal layer. It performs initial STUN
// discovery for the local node and starts the re-probe timer.
func (nt *NatTraversal) Start() error {
	nt.mu.Lock()
	if nt.started {
		nt.mu.Unlock()
		return fmt.Errorf("NAT traversal already started")
	}
	nt.started = true
	nt.mu.Unlock()

	// Perform initial STUN discovery.
	go nt.initialDiscovery()

	// Start the re-probe ticker.
	if nt.cfg.DirectReprobeInterval > 0 {
		nt.reprobeTC = time.NewTicker(nt.cfg.DirectReprobeInterval)
		go nt.reprobeLoop()
	}

	log.Printf("[p2p/nat] NAT traversal started (STUN servers: %d, reprobe interval: %v)",
		len(nt.cfg.StunServers), nt.cfg.DirectReprobeInterval)

	return nil
}

// Stop shuts down the NAT traversal layer.
func (nt *NatTraversal) Stop() error {
	nt.mu.Lock()
	if !nt.started {
		nt.mu.Unlock()
		return nil
	}
	nt.started = false
	nt.mu.Unlock()

	close(nt.stopCh)

	if nt.reprobeTC != nil {
		nt.reprobeTC.Stop()
	}

	log.Printf("[p2p/nat] NAT traversal stopped")
	return nil
}

// initialDiscovery performs STUN discovery for the local node.
// The discovered endpoint and NAT type are stored and used for
// all subsequent hole-punching attempts.
func (nt *NatTraversal) initialDiscovery() {
	discovery, err := nt.stun.Discover()
	if err != nil {
		log.Printf("[p2p/nat] initial STUN discovery failed: %v (will retry)", err)

		// Retry with backoff.
		backoff := 10 * time.Second
		for {
			select {
			case <-nt.stopCh:
				return
			case <-time.After(backoff):
			}

			discovery, err = nt.stun.Discover()
			if err == nil {
				break
			}
			log.Printf("[p2p/nat] STUN discovery retry failed: %v (next in %v)", err, backoff*2)
			backoff *= 2
			if backoff > 5*time.Minute {
				backoff = 5 * time.Minute
			}
		}
	}

	nt.mu.Lock()
	nt.localEP = discovery.MappedAddress
	nt.localNat = discovery.NatType
	nt.mu.Unlock()

	log.Printf("[p2p/nat] STUN discovery complete: endpoint=%s, NAT type=%s",
		discovery.MappedAddress, discovery.NatType)
}

// LocalEndpoint returns the locally-discovered public endpoint.
func (nt *NatTraversal) LocalEndpoint() string {
	nt.mu.RLock()
	defer nt.mu.RUnlock()
	return nt.localEP
}

// LocalNatType returns the locally-classified NAT type.
func (nt *NatTraversal) LocalNatType() NatType {
	nt.mu.RLock()
	defer nt.mu.RUnlock()
	return nt.localNat
}

// GetSession returns the NAT session for a peer, or nil if none exists.
func (nt *NatTraversal) GetSession(peerKey string) *NatSession {
	nt.mu.RLock()
	defer nt.mu.RUnlock()
	s, ok := nt.sessions[peerKey]
	if !ok {
		return nil
	}
	return s
}

// SessionState returns the current state for a peer's NAT session.
// Returns NatInit if no session exists.
func (nt *NatTraversal) SessionState(peerKey string) NatState {
	nt.mu.RLock()
	defer nt.mu.RUnlock()
	s, ok := nt.sessions[peerKey]
	if !ok {
		return NatInit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.State
}

// AllSessions returns a snapshot of all NAT sessions.
func (nt *NatTraversal) AllSessions() []*NatSessionSnapshot {
	nt.mu.RLock()
	defer nt.mu.RUnlock()
	result := make([]*NatSessionSnapshot, 0, len(nt.sessions))
	for _, s := range nt.sessions {
		s.mu.Lock()
		result = append(result, &NatSessionSnapshot{
			PeerKey:       s.PeerKey,
			State:         s.State,
			Endpoints:     append([]string{}, s.Endpoints...),
			NatType:       s.NatType,
			RemoteNatType: s.RemoteNatType,
			Retries:       s.Retries,
			MaxRetries:    s.MaxRetries,
			LastProbe:     s.LastProbe,
			RelayVia:      s.RelayVia,
			Established:   s.Established,
		})
		s.mu.Unlock()
	}
	return result
}

// NatSessionSnapshot is an immutable snapshot of a NatSession for
// external observation without lock concerns.
type NatSessionSnapshot struct {
	PeerKey       string
	State         NatState
	Endpoints     []string
	NatType       NatType
	RemoteNatType NatType
	Retries       int
	MaxRetries    int
	LastProbe     time.Time
	RelayVia      string
	Established   time.Time
}

// InitiateConnection begins NAT traversal for a peer discovered via gossip.
// This is called by the event delegate's NotifyJoin handler (§1.5 step 3)
// when a new peer is discovered.
//
// The peer's endpoints and NAT type must be available from gossip NodeMeta.
func (nt *NatTraversal) InitiateConnection(peerKey string, peerEndpoints []string, peerNatType NatType) {
	nt.mu.Lock()
	if _, exists := nt.sessions[peerKey]; exists {
		nt.mu.Unlock()
		return // session already exists
	}

	session := &NatSession{
		PeerKey:        peerKey,
		State:          NatStunDiscovery,
		Endpoints:      peerEndpoints,
		RemoteNatType:  peerNatType,
		MaxRetries:     nt.cfg.MaxRetries,
	}
	nt.sessions[peerKey] = session
	nt.mu.Unlock()

	// Register for hole-punching.
	nt.puncher.RegisterPeer(peerKey, nt.localEP, nt.meshPort)

	// Run the state machine in a goroutine.
	go nt.runStateMachine(session)
}

// RemoveConnection cleans up the NAT session for a peer (gossip leave).
func (nt *NatTraversal) RemoveConnection(peerKey string) {
	nt.mu.Lock()
	delete(nt.sessions, peerKey)
	nt.mu.Unlock()

	nt.puncher.UnregisterPeer(peerKey)
}

// runStateMachine drives the per-peer NAT traversal state machine.
// It runs in a goroutine and handles all state transitions.
func (nt *NatTraversal) runStateMachine(session *NatSession) {
	for {
		select {
		case <-nt.stopCh:
			return
		default:
		}

		session.mu.Lock()
		state := session.State
		session.mu.Unlock()

		switch state {
		case NatStunDiscovery:
			nt.handleStunDiscovery(session)
		case NatDirectProbe:
			nt.handleDirectProbe(session)
		case NatRelayFallback:
			// Relay fallback is set up and we wait for re-probe.
			// The reprobeLoop handles periodic re-probes.
			return // exit goroutine — reprobeLoop will re-enter
		case NatDirect:
			// Direct connection established. Update to ACTIVE.
			session.mu.Lock()
			session.State = NatActive
			session.Established = time.Now()
			session.mu.Unlock()
			log.Printf("[p2p/nat] peer %s: DIRECT → ACTIVE", safeShortKey(session.PeerKey))
			return
		case NatActive:
			return
		case NatRetry:
			nt.handleRetry(session)
		case NatFailed:
			log.Printf("[p2p/nat] peer %s: FAILED (max retries exceeded)", safeShortKey(session.PeerKey))
			return
		}
	}
}

// handleStunDiscovery processes the STUN_DISCOVERY state.
// If the local node hasn't done STUN yet, it waits. Then it transitions
// to DIRECT_PROBE (if hole-punching is viable) or RELAY_FALLBACK (if
// both sides are symmetric NAT).
func (nt *NatTraversal) handleStunDiscovery(session *NatSession) {
	// Wait for local STUN discovery if not yet available.
	nt.mu.RLock()
	localEP := nt.localEP
	localNat := nt.localNat
	nt.mu.RUnlock()

	if localEP == "" {
		// STUN discovery hasn't completed yet. Wait and retry.
		select {
		case <-nt.stopCh:
			return
		case <-time.After(5 * time.Second):
		}

		nt.mu.RLock()
		localEP = nt.localEP
		localNat = nt.localNat
		nt.mu.RUnlock()

		if localEP == "" {
			// Still no endpoint. Skip direct probe, go to relay.
			nt.transitionToRelay(session)
			return
		}
	}

	session.mu.Lock()
	session.localEndpoint = localEP
	session.NatType = localNat
	session.mu.Unlock()

	// Check if hole-punching is viable (§3.9).
	if !CanHolePunch(localNat, session.RemoteNatType) {
		// Both sides symmetric → forced relay (§3.9).
		log.Printf("[p2p/nat] peer %s: both symmetric NAT, skipping direct probe",
			safeShortKey(session.PeerKey))
		nt.transitionToRelay(session)
		return
	}

	// Transition to DIRECT_PROBE.
	session.mu.Lock()
	session.State = NatDirectProbe
	session.LastProbe = time.Now()
	session.mu.Unlock()
	log.Printf("[p2p/nat] peer %s: STUN_DISCOVERY → DIRECT_PROBE", safeShortKey(session.PeerKey))
}

// handleDirectProbe processes the DIRECT_PROBE state.
// It performs hole-punching and checks if the WireGuard handshake completes.
func (nt *NatTraversal) handleDirectProbe(session *NatSession) {
	session.mu.Lock()
	endpoints := session.Endpoints
	peerKey := session.PeerKey
	session.mu.Unlock()

	if len(endpoints) == 0 {
		// No peer endpoints known — go to relay.
		log.Printf("[p2p/nat] peer %s: no endpoints, falling back to relay", safeShortKey(peerKey))
		nt.transitionToRelay(session)
		return
	}

	// Attempt hole-punching to each known endpoint.
	ctx, cancel := context.WithTimeout(context.Background(), nt.cfg.ProbeTimeout)
	defer cancel()

	var lastResult *HolePunchResult
	for _, ep := range endpoints {
		result := nt.puncher.AttemptPunch(ctx, peerKey, ep)
		lastResult = result
		if result.Success {
			break
		}
	}

	// Check if WireGuard handshake completes within timeout.
	// The hole-punch sent probe packets; now the WG device needs to
	// complete its handshake. We poll IsHealthy with a short delay.
	time.Sleep(nt.cfg.ProbeTimeout)

	if nt.wgDelegate.IsHealthy(peerKey) {
		// Direct connection established!
		session.mu.Lock()
		session.State = NatDirect
		session.Retries = 0
		session.mu.Unlock()
		log.Printf("[p2p/nat] peer %s: DIRECT_PROBE → DIRECT (handshake succeeded)",
			safeShortKey(peerKey))
		nt.wgDelegate.UpdateHandshakeTime(peerKey)
		return
	}

	// Direct probe failed.
	log.Printf("[p2p/nat] peer %s: direct probe failed (punch success=%v, last err=%v)",
		safeShortKey(peerKey), lastResult != nil && lastResult.Success, func() error {
			if lastResult != nil && lastResult.Error != nil {
				return lastResult.Error
			}
			return nil
		}())

	// Check relay mode.
	if nt.cfg.RelayMode == "disabled" {
		// No relay — go to retry.
		session.mu.Lock()
		session.State = NatRetry
		session.Retries++
		session.mu.Unlock()
		return
	}

	// Fall back to relay.
	nt.transitionToRelay(session)
}

// transitionToRelay sets up relay fallback for the session.
// It selects a relay peer and updates the WireGuard endpoint.
func (nt *NatTraversal) transitionToRelay(session *NatSession) {
	if nt.relay == nil {
		session.mu.Lock()
		session.State = NatFailed
		session.mu.Unlock()
		log.Printf("[p2p/nat] peer %s: no relay selector available → FAILED", safeShortKey(session.PeerKey))
		return
	}

	// Select a relay.
	candidate := nt.relay.SelectBestRelay(nil)
	if candidate == nil {
		// No relay candidates available.
		session.mu.Lock()
		session.State = NatRetry
		session.Retries++
		session.mu.Unlock()
		log.Printf("[p2p/nat] peer %s: no relay candidates → RETRY (%d/%d)",
			safeShortKey(session.PeerKey), session.Retries, session.MaxRetries)
		return
	}

	relayKey := candidate.Meta.PublicKey
	relayMeshIP := candidate.Meta.MeshIP

	session.mu.Lock()
	session.State = NatRelayFallback
	session.RelayVia = relayKey
	session.mu.Unlock()

	// Update the peer's WireGuard endpoint to the relay's mesh IP.
	// This routes WireGuard traffic through the relay peer.
	relayEndpoint := relayMeshIP + ":51820"
	if err := nt.wgDelegate.UpdateEndpoint(session.PeerKey, relayEndpoint); err != nil {
		log.Printf("[p2p/nat] peer %s: failed to update endpoint to relay %s: %v",
			safeShortKey(session.PeerKey), relayMeshIP, err)
	} else {
		log.Printf("[p2p/nat] peer %s: → RELAY_FALLBACK (via %s, score=%.3f, rtt=%v)",
			safeShortKey(session.PeerKey), relayMeshIP, candidate.Score, candidate.RTT)
	}
}

// handleRetry processes the RETRY state with exponential backoff.
func (nt *NatTraversal) handleRetry(session *NatSession) {
	session.mu.Lock()
	retries := session.Retries
	maxRetries := session.MaxRetries
	session.mu.Unlock()

	if retries >= maxRetries {
		session.mu.Lock()
		session.State = NatFailed
		session.mu.Unlock()
		return
	}

	// Exponential backoff: 2^retries * base, capped at 5 minutes.
	backoff := time.Duration(1<<uint(retries)) * 5 * time.Second
	if backoff > 5*time.Minute {
		backoff = 5 * time.Minute
	}

	select {
	case <-nt.stopCh:
		return
	case <-time.After(backoff):
	}

	// Retry from STUN discovery.
	session.mu.Lock()
	session.State = NatStunDiscovery
	session.mu.Unlock()
	log.Printf("[p2p/nat] peer %s: RETRY → STUN_DISCOVERY (attempt %d/%d, backoff %v)",
		safeShortKey(session.PeerKey), retries+1, maxRetries, backoff)
}

// reprobeLoop periodically re-attempts direct connections for sessions
// in RELAY_FALLBACK state (§3.8).
func (nt *NatTraversal) reprobeLoop() {
	for {
		select {
		case <-nt.stopCh:
			return
		case <-nt.reprobeTC.C:
		}

		nt.mu.RLock()
		var toReprobe []*NatSession
		for _, s := range nt.sessions {
			s.mu.Lock()
			if s.State == NatRelayFallback {
				toReprobe = append(toReprobe, s)
			}
			s.mu.Unlock()
		}
		nt.mu.RUnlock()

		for _, session := range toReprobe {
			go nt.handleDirectReprobe(session)
		}
	}
}

// handleDirectReprobe processes the DIRECT_REPROBE state (§3.8).
// Every DirectReprobeInterval seconds, while in RELAY_FALLBACK, we
// re-attempt direct connection. If successful, we switch to DIRECT.
func (nt *NatTraversal) handleDirectReprobe(session *NatSession) {
	session.mu.Lock()
	endpoints := session.Endpoints
	peerKey := session.PeerKey
	session.State = NatDirectReprobe
	session.LastProbe = time.Now()
	session.mu.Unlock()

	log.Printf("[p2p/nat] peer %s: RELAY_FALLBACK → DIRECT_REPROBE", safeShortKey(peerKey))

	if len(endpoints) == 0 {
		// No endpoints to probe — go back to relay.
		nt.backToRelay(session)
		return
	}

	// Attempt hole-punching.
	ctx, cancel := context.WithTimeout(context.Background(), nt.cfg.ProbeTimeout)
	defer cancel()

	var lastResult *HolePunchResult
	for _, ep := range endpoints {
		result := nt.puncher.AttemptPunch(ctx, peerKey, ep)
		lastResult = result
		if result.Success {
			break
		}
	}

	// Wait for handshake.
	time.Sleep(nt.cfg.ProbeTimeout)

	if nt.wgDelegate.IsHealthy(peerKey) {
		// Direct connection succeeded! Switch from relay to direct.
		// Per §3.8: keep the relay path for 30s before tearing down
		// (prevents flapping). We update the endpoint to the direct
		// endpoint immediately but don't remove the relay peer.
		session.mu.Lock()
		session.State = NatDirect
		session.Retries = 0
		session.RelayVia = ""
		session.mu.Unlock()

		// Update WireGuard endpoint to the peer's direct endpoint.
		directEndpoint := endpoints[0]
		if err := nt.wgDelegate.UpdateEndpoint(peerKey, directEndpoint); err != nil {
			log.Printf("[p2p/nat] peer %s: failed to update to direct endpoint: %v",
				safeShortKey(peerKey), err)
		} else {
			log.Printf("[p2p/nat] peer %s: DIRECT_REPROBE → DIRECT (switched from relay)",
				safeShortKey(peerKey))
		}
		nt.wgDelegate.UpdateHandshakeTime(peerKey)
		return
	}

	// Direct re-probe failed — go back to relay.
	log.Printf("[p2p/nat] peer %s: direct re-probe failed (punch=%v, err=%v), staying on relay",
		safeShortKey(peerKey), lastResult != nil && lastResult.Success, func() error {
			if lastResult != nil && lastResult.Error != nil {
				return lastResult.Error
			}
			return nil
		}())
	nt.backToRelay(session)
}

// backToRelay transitions a session from DIRECT_REPROBE back to RELAY_FALLBACK.
func (nt *NatTraversal) backToRelay(session *NatSession) {
	session.mu.Lock()
	if session.RelayVia == "" {
		// No relay was set up — try to select one.
		session.mu.Unlock()
		nt.transitionToRelay(session)
		return
	}

	// Restore the relay endpoint.
	relayKey := session.RelayVia
	session.State = NatRelayFallback
	session.mu.Unlock()

	// Get the relay peer's mesh IP from the events delegate.
	if nt.events != nil {
		relayMeta := nt.events.GetPeerMeta(relayKey)
		if relayMeta != nil {
			relayEndpoint := relayMeta.MeshIP + ":51820"
			_ = nt.wgDelegate.UpdateEndpoint(session.PeerKey, relayEndpoint)
		}
	}

	log.Printf("[p2p/nat] peer %s: DIRECT_REPROBE → RELAY_FALLBACK (re-probe failed)",
		safeShortKey(session.PeerKey))
}

// SetLocalDiscovery allows external code to set the local endpoint
// and NAT type (e.g., from a previous STUN query or manual config).
func (nt *NatTraversal) SetLocalDiscovery(endpoint string, natType NatType) {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	nt.localEP = endpoint
	nt.localNat = natType
}
