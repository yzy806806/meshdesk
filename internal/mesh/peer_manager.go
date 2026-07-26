// Package mesh provides the PeerManager — a per-peer connection lifecycle
// manager that sits above the Transport layer and below WireGuard.
//
// PeerManager implements:
//   - Three-state peer-level state machine (disconnected → connecting → connected)
//     with per-transport sub-states (active, connecting, probing, quarantined, failed)
//   - Per-transport quarantine with exponential backoff (30s→60s→120s→300s cap)
//   - Happy Eyeballs hedging (RFC 8305): race fallback after configurable delay
//   - Hybrid latency probing: active probe on idle transports, passive on active
//   - Score-based path selection: score = ewma_latency × (1 + failure_penalty)
//   - Per-peer goroutine with channel-driven select loop
//
// Design: motion motion-3911ff2db1df (adopted).
// See docs/PEERMANAGER_DESIGN.md for the full specification.
package mesh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// States
// ──────────────────────────────────────────────────────────────────────────────

// PeerState represents the peer-level connection state.
type PeerState int

const (
	// PeerDisconnected means no connection attempt is in progress.
	PeerDisconnected PeerState = iota
	// PeerConnecting means the peer is actively trying transports.
	PeerConnecting
	// PeerConnected means at least one transport has an active PeerConn.
	PeerConnected
)

func (s PeerState) String() string {
	switch s {
	case PeerDisconnected:
		return "disconnected"
	case PeerConnecting:
		return "connecting"
	case PeerConnected:
		return "connected"
	default:
		return fmt.Sprintf("PeerState(%d)", int(s))
	}
}

// TransportSubState represents per-transport sub-states within a peer.
type TransportSubState int

const (
	// TransportSubActive means this transport is actively connected.
	TransportSubActive TransportSubState = iota
	// TransportSubConnecting means a dial is in progress on this transport.
	TransportSubConnecting
	// TransportSubProbing means a latency probe is in progress.
	TransportSubProbing
	// TransportSubQuarantined means the transport hit its failure threshold
	// and is in exponential cooldown.
	TransportSubQuarantined
	// TransportSubFailed means the transport has permanently failed (blackout).
	TransportSubFailed
)

func (s TransportSubState) String() string {
	switch s {
	case TransportSubActive:
		return "active"
	case TransportSubConnecting:
		return "connecting"
	case TransportSubProbing:
		return "probing"
	case TransportSubQuarantined:
		return "quarantined"
	case TransportSubFailed:
		return "failed"
	default:
		return fmt.Sprintf("TransportSubState(%d)", int(s))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Config
// ──────────────────────────────────────────────────────────────────────────────

// Default failure thresholds per transport type.
const (
	DefaultUDPFailureThreshold     = 3
	DefaultWSFailureThreshold      = 2
	DefaultRealityFailureThreshold = 2
	DefaultRelayFailureThreshold   = 3
)

// Default blackout threshold.
const defaultBlackoutThreshold = 5

// PeerManagerConfig configures the PeerManager's behavior. All durations
// are configurable for testability — tests should use short values.
type PeerManagerConfig struct {
	// PeerID identifies this peer (e.g., public key).
	PeerID string

	// Addr is the remote address for this peer (host:port).
	Addr string

	// TransportNames is the ordered list of transport names to try,
	// in priority order (e.g., ["udp", "reality", "websocket", "relay"]).
	TransportNames []string

	// QuarantineThreshold is the number of consecutive failures before
	// a transport enters quarantine, keyed by transport name.
	QuarantineThreshold map[string]int

	// QuarantineBaseCooldown is the initial quarantine duration.
	// Exponential backoff: 30→60→120→300s cap.
	QuarantineBaseCooldown time.Duration

	// QuarantineMaxCooldown caps the exponential backoff.
	QuarantineMaxCooldown time.Duration

	// HedgeDelay is how long to wait before starting a parallel
	// fallback dial for slow transports (Happy Eyeballs).
	HedgeDelay time.Duration

	// SlowTransports is the set of transport names classified as "slow"
	// (trigger hedging via Happy Eyeballs). E.g., {"reality", "websocket"}.
	SlowTransports map[string]bool

	// ProbeInterval is how often to probe latency when idle.
	ProbeInterval time.Duration

	// ProbeIntervalQuarantinedReality is the probe interval for
	// quarantined Reality transports (to avoid GFW detection).
	ProbeIntervalQuarantinedReality time.Duration

	// BaselineWindow is the number of samples for the moving median.
	// Deprecated: replaced by EWMA smoothing (AlphaRise/AlphaFall).
	// Kept for backward compatibility — no longer used by latencyEWMA.
	BaselineWindow int

	// AlphaRise is the EWMA smoothing factor for increasing latency
	// (degradation detection). Higher = faster reaction to degradation.
	// Spec §5.1 default: 0.7.
	AlphaRise float64

	// AlphaFall is the EWMA smoothing factor for decreasing latency
	// (recovery). Lower = slower recovery, prevents flapping.
	// Spec §5.1 default: 0.3.
	AlphaFall float64

	// TriggerThreshold is the latency multiplier that triggers a
	// degraded-transport decision (2.0 = 2x baseline).
	TriggerThreshold float64

	// TriggerConsecutive is the number of consecutive probes above
	// the threshold before a transport is considered degraded.
	TriggerConsecutive int

	// FailureLookback is the time window for counting recent failures
	// in the path-selection scoring formula.
	FailureLookback time.Duration

	// BlackoutThreshold is the number of consecutive quarantine cycles
	// before a transport enters blackout (permanently failed).
	BlackoutThreshold int

	// ScoreSwitchThreshold is the fraction improvement needed to switch
	// active transports (0.25 = 25%).
	ScoreSwitchThreshold float64

	// ScoreStableProbes is the number of consecutive probe cycles a
	// better alternative must remain better before switching.
	ScoreStableProbes int

	// MinSamplesForScoring is the minimum latency samples needed before
	// a transport is eligible for path selection scoring.
	MinSamplesForScoring int

	// HysteresisBonus is subtracted from the active transport's score
	// during path comparison to prevent flapping between two near-identical
	// transports (e.g. UDP 8ms vs Reality 9ms). The spec (§6.1) calls for
	// 10% hysteresis; a 0 value means use 10% of the active score at
	// evaluation time. A positive fixed-ms value (e.g. 5ms) is also valid.
	// Set to a negative value to disable hysteresis entirely.
	HysteresisBonus float64
}

// DefaultPeerManagerConfig returns a PeerManagerConfig with sensible defaults.
func DefaultPeerManagerConfig() PeerManagerConfig {
	return PeerManagerConfig{
		QuarantineThreshold: map[string]int{
			"udp":       DefaultUDPFailureThreshold,
			"reality":   DefaultRealityFailureThreshold,
			"websocket": DefaultWSFailureThreshold,
			"relay":     DefaultRelayFailureThreshold,
		},
		QuarantineBaseCooldown:          30 * time.Second,
		QuarantineMaxCooldown:           300 * time.Second,
		HedgeDelay:                      5 * time.Second,
		SlowTransports:                  map[string]bool{"reality": true, "websocket": true},
		ProbeInterval:                   30 * time.Second,
		ProbeIntervalQuarantinedReality: 5 * time.Minute,
		BaselineWindow:                  10, // deprecated, kept for compat
		AlphaRise:                       defaultAlphaRise,
		AlphaFall:                       defaultAlphaFall,
		TriggerThreshold:                2.0,
		TriggerConsecutive:              3,
		FailureLookback:                 60 * time.Second,
		BlackoutThreshold:               defaultBlackoutThreshold,
		ScoreSwitchThreshold:            0.25,
		ScoreStableProbes:               3,
		MinSamplesForScoring:            3,
		HysteresisBonus:                 0, // 0 = use 10% of active score dynamically
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// latencyEWMA — exponentially weighted moving average with split-alpha smoothing
// ──────────────────────────────────────────────────────────────────────────────

// Default EWMA smoothing constants per spec §5.1.
// alpha_rise=0.7 makes the EWMA react quickly to latency increases (degradation),
// so degradation is detected within 30-60s instead of ~2min with a median window.
// alpha_fall=0.3 makes the EWMA recover slowly from latency drops, preventing
// oscillation when latency briefly dips after a degradation event.
const (
	defaultAlphaRise = 0.7
	defaultAlphaFall = 0.3
)

// latencyEWMA is a split-alpha exponentially weighted moving average of latency.
//
// On each sample:
//   - If sample > current EWMA (latency rising): ewma = ewma + alpha_rise × (sample - ewma)
//   - If sample ≤ current EWMA (latency falling): ewma = ewma + alpha_fall × (sample - ewma)
//
// This gives fast detection of degradation (alpha_rise=0.7) while preventing
// flapping on recovery (alpha_fall=0.3). The first sample initializes the EWMA.
type latencyEWMA struct {
	value   float64       // current EWMA value in nanoseconds
	hasValue bool         // whether we have received at least one sample
	count   int           // total samples received
	alphaRise float64     // smoothing factor for increasing latency
	alphaFall float64     // smoothing factor for decreasing latency
}

// newLatencyEWMA creates a latencyEWMA with the given alpha values.
// Zero values default to defaultAlphaRise / defaultAlphaFall.
func newLatencyEWMA(alphaRise, alphaFall float64) *latencyEWMA {
	if alphaRise <= 0 {
		alphaRise = defaultAlphaRise
	}
	if alphaFall <= 0 {
		alphaFall = defaultAlphaFall
	}
	return &latencyEWMA{
		alphaRise: alphaRise,
		alphaFall: alphaFall,
	}
}

// push applies a new latency sample to the EWMA.
func (e *latencyEWMA) push(d time.Duration) {
	sample := float64(d)
	if !e.hasValue {
		e.value = sample
		e.hasValue = true
		e.count = 1
		return
	}
	e.count++
	if sample > e.value {
		// Latency rising — use alpha_rise for fast detection.
		e.value += e.alphaRise * (sample - e.value)
	} else {
		// Latency falling — use alpha_fall for stable recovery.
		e.value += e.alphaFall * (sample - e.value)
	}
}

// value returns the current EWMA as a time.Duration, or 0 if no samples.
func (e *latencyEWMA) current() time.Duration {
	if !e.hasValue {
		return 0
	}
	return time.Duration(e.value)
}

// reset clears the EWMA state.
func (e *latencyEWMA) reset() {
	e.value = 0
	e.hasValue = false
	e.count = 0
}

// ──────────────────────────────────────────────────────────────────────────────
// transportState — per-transport state within a peer connection
// ──────────────────────────────────────────────────────────────────────────────

// transportState tracks the state of a single transport for a peer.
// All fields are accessed only from within the peer's goroutine,
// except for snapshots taken under the PeerManager's read lock.
type transportState struct {
	name          string
	subState      TransportSubState
	conn          PeerConn
	latency       *latencyEWMA
	failures      int         // consecutive failures (reset on success)
	quarantineN   int         // total quarantine cycles (reset on success)
	cooldownUntil time.Time   // when quarantine expires
	stableBetter  int         // consecutive probes where alternative was better
	lastProbeAt   time.Time   // last active probe time
	failureTimes  []time.Time // timestamps of recent failures (for lookback scoring)
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal message types
// ──────────────────────────────────────────────────────────────────────────────

// dialResult is sent from dial goroutines to the peer's main loop.
type dialResult struct {
	gen           int // connect cycle generation
	transportName string
	conn          PeerConn
	err           error
}

// peerCommand identifies a command sent to the peer's goroutine.
type peerCommand int

const (
	cmdReconnect peerCommand = iota
	cmdShutdown
)

// peerCommandMsg carries a command and a response channel.
type peerCommandMsg struct {
	cmd    peerCommand
	respCh chan error
}

// ──────────────────────────────────────────────────────────────────────────────
// PeerManager — single-peer connection lifecycle manager
// ──────────────────────────────────────────────────────────────────────────────

// PeerManager manages a single peer's connection lifecycle with
// auto-reconnect, multi-transport failover, latency probing, and
// optimal path selection. It sits above the Transport layer and
// below WireGuard.
//
// One goroutine is spawned per PeerManager instance on Start(). The
// goroutine runs a select-loop that manages transport dials, probes,
// quarantine timers, and Happy Eyeballs hedging.
type PeerManager struct {
	cfg      PeerManagerConfig
	registry *TransportRegistry

	// state is stored atomically for lock-free reads.
	stateAtomic atomic.Int32

	// mu protects transportStates, currentTransport, lastLatency, and
	// related fields for concurrent reads.
	mu               sync.RWMutex
	transportStates  map[string]*transportState
	currentTransport string
	lastLatency      time.Duration

	// goroutine communication
	cmdCh        chan peerCommandMsg
	dialResultCh chan dialResult
	done         chan struct{}
	cancel       context.CancelFunc

	// connect cycle management (owned by goroutine)
	connectGen         int
	dialCtx            context.Context
	dialCancel         context.CancelFunc
	inFlight           map[string]bool
	happyEyeballsTimer *time.Timer
	retryTimer         *time.Timer
	started            bool
	startMu            sync.Mutex
}

// NewPeerManager creates a new PeerManager for the given peer.
// Zero-value config fields are filled with DefaultPeerManagerConfig defaults.
func NewPeerManager(cfg PeerManagerConfig, registry *TransportRegistry) *PeerManager {
	def := DefaultPeerManagerConfig()
	if cfg.QuarantineThreshold == nil {
		cfg.QuarantineThreshold = def.QuarantineThreshold
	}
	if cfg.QuarantineBaseCooldown == 0 {
		cfg.QuarantineBaseCooldown = def.QuarantineBaseCooldown
	}
	if cfg.QuarantineMaxCooldown == 0 {
		cfg.QuarantineMaxCooldown = def.QuarantineMaxCooldown
	}
	if cfg.HedgeDelay == 0 {
		cfg.HedgeDelay = def.HedgeDelay
	}
	if cfg.SlowTransports == nil {
		cfg.SlowTransports = def.SlowTransports
	}
	if cfg.ProbeInterval == 0 {
		cfg.ProbeInterval = def.ProbeInterval
	}
	if cfg.ProbeIntervalQuarantinedReality == 0 {
		cfg.ProbeIntervalQuarantinedReality = def.ProbeIntervalQuarantinedReality
	}
	if cfg.BaselineWindow == 0 {
		cfg.BaselineWindow = def.BaselineWindow
	}
	if cfg.AlphaRise == 0 {
		cfg.AlphaRise = def.AlphaRise
	}
	if cfg.AlphaFall == 0 {
		cfg.AlphaFall = def.AlphaFall
	}
	if cfg.TriggerThreshold == 0 {
		cfg.TriggerThreshold = def.TriggerThreshold
	}
	if cfg.TriggerConsecutive == 0 {
		cfg.TriggerConsecutive = def.TriggerConsecutive
	}
	if cfg.FailureLookback == 0 {
		cfg.FailureLookback = def.FailureLookback
	}
	if cfg.BlackoutThreshold == 0 {
		cfg.BlackoutThreshold = def.BlackoutThreshold
	}
	if cfg.ScoreSwitchThreshold == 0 {
		cfg.ScoreSwitchThreshold = def.ScoreSwitchThreshold
	}
	if cfg.ScoreStableProbes == 0 {
		cfg.ScoreStableProbes = def.ScoreStableProbes
	}
	if cfg.MinSamplesForScoring == 0 {
		cfg.MinSamplesForScoring = def.MinSamplesForScoring
	}

	transportStates := make(map[string]*transportState)
	for _, name := range cfg.TransportNames {
		transportStates[name] = &transportState{
			name:     name,
			subState: TransportSubActive,
			latency:  newLatencyEWMA(cfg.AlphaRise, cfg.AlphaFall),
		}
	}

	return &PeerManager{
		cfg:             cfg,
		registry:        registry,
		transportStates: transportStates,
		cmdCh:           make(chan peerCommandMsg, 1),
		dialResultCh:    make(chan dialResult, 4),
		done:            make(chan struct{}),
		inFlight:        make(map[string]bool),
	}
}

// Start begins the connection management loop for this peer.
// It transitions from PeerDisconnected to PeerConnecting and begins
// dialing transports in priority order. Returns an error if already
// started or if no transports are configured.
func (pm *PeerManager) Start(ctx context.Context) error {
	pm.startMu.Lock()
	defer pm.startMu.Unlock()
	if pm.started {
		return errors.New("peermanager: already started")
	}
	if len(pm.cfg.TransportNames) == 0 {
		return errors.New("peermanager: no transports configured")
	}

	pm.started = true
	pm.stateAtomic.Store(int32(PeerConnecting))

	runCtx, cancel := context.WithCancel(ctx)
	pm.cancel = cancel

	go pm.run(runCtx)
	return nil
}

// Stop terminates the management loop and closes any active connections.
// Safe to call multiple times (idempotent).
func (pm *PeerManager) Stop() error {
	pm.startMu.Lock()
	if !pm.started {
		pm.startMu.Unlock()
		return nil
	}
	pm.started = false
	pm.startMu.Unlock()

	if pm.cancel != nil {
		pm.cancel()
	}
	select {
	case <-pm.done:
	case <-time.After(5 * time.Second):
		// Timeout — goroutine may be stuck.
	}
	return nil
}

// State returns the current peer-level state.
func (pm *PeerManager) State() PeerState {
	return PeerState(pm.stateAtomic.Load())
}

// TransportState returns the sub-state for the given transport name.
// Returns TransportSubFailed for unknown transports.
func (pm *PeerManager) TransportState(transportName string) TransportSubState {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	ts, ok := pm.transportStates[transportName]
	if !ok {
		return TransportSubFailed
	}
	return ts.subState
}

// CurrentTransport returns the name of the transport currently in use,
// or empty string if not connected.
func (pm *PeerManager) CurrentTransport() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.currentTransport
}

// Latency returns the current latency measurement for the active connection,
// or zero if not yet measured.
func (pm *PeerManager) Latency() time.Duration {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.lastLatency
}

// IsHealthy returns whether the peer is connected and the active transport
// is healthy.
func (pm *PeerManager) IsHealthy() bool {
	return PeerState(pm.stateAtomic.Load()) == PeerConnected
}

// Reconnect forces a reconnect, resetting all quarantine state and
// blackout flags. This is the escape hatch for blacked-out transports.
func (pm *PeerManager) Reconnect() error {
	pm.startMu.Lock()
	started := pm.started
	pm.startMu.Unlock()
	if !started {
		return errors.New("peermanager: not started")
	}

	respCh := make(chan error, 1)
	select {
	case pm.cmdCh <- peerCommandMsg{cmd: cmdReconnect, respCh: respCh}:
		select {
		case err := <-respCh:
			return err
		case <-pm.done:
			return errors.New("peermanager: goroutine exited during reconnect")
		}
	case <-pm.done:
		return errors.New("peermanager: goroutine already exited")
	}
}

// TransportStates returns per-transport sub-states and latency data
// for all configured transports. Used for dashboard/monitoring.
func (pm *PeerManager) TransportStates() map[string]TransportPeerState {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make(map[string]TransportPeerState, len(pm.transportStates))
	now := time.Now()
	for name, ts := range pm.transportStates {
		var cooldownRemaining time.Duration
		if ts.subState == TransportSubQuarantined && now.Before(ts.cooldownUntil) {
			cooldownRemaining = ts.cooldownUntil.Sub(now)
		}
		result[name] = TransportPeerState{
			Name:                name,
			SubState:            ts.subState,
			LatencyMedian:       ts.latency.current(),
			LatencySamples:      ts.latency.count,
			ConsecutiveFailures: ts.failures,
			QuarantineCycles:    ts.quarantineN,
			BlackedOut:          ts.subState == TransportSubFailed,
			CooldownRemaining:   cooldownRemaining,
		}
	}
	return result
}

// TransportPeerState describes a transport's status for dashboard/monitoring.
type TransportPeerState struct {
	Name                string
	SubState            TransportSubState
	LatencyMedian       time.Duration
	LatencySamples      int
	ConsecutiveFailures int
	QuarantineCycles    int
	BlackedOut          bool
	CooldownRemaining   time.Duration
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-peer goroutine — the connection management loop
// ──────────────────────────────────────────────────────────────────────────────

// run is the per-peer goroutine main loop. It manages transport dials,
// probes, quarantine timers, and Happy Eyeballs hedging via a select-loop.
func (pm *PeerManager) run(ctx context.Context) {
	defer close(pm.done)

	probeTicker := time.NewTicker(pm.cfg.ProbeInterval)
	defer probeTicker.Stop()

	// Start the first connect cycle immediately.
	pm.startConnectCycle(ctx)

	for {
		// Build dynamic channel references (nil channel = disabled).
		var happyEyeballsCh <-chan time.Time
		if pm.happyEyeballsTimer != nil {
			happyEyeballsCh = pm.happyEyeballsTimer.C
		}
		var retryCh <-chan time.Time
		if pm.retryTimer != nil {
			retryCh = pm.retryTimer.C
		}

		select {
		case <-ctx.Done():
			pm.cleanup()
			return

		case cmd := <-pm.cmdCh:
			switch cmd.cmd {
			case cmdReconnect:
				pm.handleReconnect(ctx)
				cmd.respCh <- nil
			case cmdShutdown:
				cmd.respCh <- nil
				pm.cleanup()
				return
			}

		case result := <-pm.dialResultCh:
			pm.handleDialResult(ctx, result)

		case <-probeTicker.C:
			pm.onProbeTick(ctx)

		case <-happyEyeballsCh:
			pm.happyEyeballsTimer = nil
			pm.startFallbackDial(ctx)

		case <-retryCh:
			pm.retryTimer = nil
			pm.startConnectCycle(ctx)
		}
	}
}

// ── Connect cycle ──────────────────────────────────────────────────────────

// startConnectCycle begins a new dial attempt cycle. It picks non-quarantined
// transports in fallback order, starts the primary dial, and sets the Happy
// Eyeballs timer if fallbacks are available.
func (pm *PeerManager) startConnectCycle(ctx context.Context) {
	// Cancel any previous in-flight dials.
	pm.cancelInFlight()

	// Transition to connecting if not already connected.
	if PeerState(pm.stateAtomic.Load()) != PeerConnected {
		pm.stateAtomic.Store(int32(PeerConnecting))
	}

	candidates := pm.candidateTransports()
	if len(candidates) == 0 {
		// All transports quarantined — check for blackout escape.
		candidates = pm.blackoutEscapeCandidates()
		if len(candidates) == 0 {
			// All blacked out. Wait for probe tick or manual reconnect.
			return
		}
	}

	// Start primary dial.
	primary := candidates[0]
	pm.connectGen++
	pm.dialCtx, pm.dialCancel = context.WithCancel(ctx)
	pm.startDial(pm.dialCtx, pm.connectGen, primary)

	// Set Happy Eyeballs timer if fallbacks are available and primary is slow.
	if len(candidates) > 1 && pm.cfg.SlowTransports[primary] {
		if pm.happyEyeballsTimer != nil {
			pm.happyEyeballsTimer.Stop()
		}
		pm.happyEyeballsTimer = time.NewTimer(pm.cfg.HedgeDelay)
	} else if len(candidates) > 1 {
		// For fast transports, still set a short timer — sequential fallback
		// is OK but we want to progress if the primary hangs.
		if pm.happyEyeballsTimer != nil {
			pm.happyEyeballsTimer.Stop()
		}
		pm.happyEyeballsTimer = time.NewTimer(pm.cfg.HedgeDelay)
	}
}

// startFallbackDial starts the next available fallback transport.
func (pm *PeerManager) startFallbackDial(ctx context.Context) {
	candidates := pm.candidateTransports()
	for _, name := range candidates {
		if !pm.inFlight[name] {
			pm.startDial(pm.dialCtx, pm.connectGen, name)
			return
		}
	}
}

// startDial launches a goroutine to dial the named transport.
func (pm *PeerManager) startDial(ctx context.Context, gen int, transportName string) {
	pm.inFlight[transportName] = true

	pm.mu.Lock()
	ts := pm.getOrCreateTransportState(transportName)
	ts.subState = TransportSubConnecting
	pm.mu.Unlock()

	go func() {
		cfg := pm.buildTransportConfig(transportName)
		conn, err := pm.registry.Dial(ctx, transportName, pm.cfg.Addr, cfg)
		result := dialResult{
			gen:           gen,
			transportName: transportName,
			conn:          conn,
			err:           err,
		}
		select {
		case pm.dialResultCh <- result:
		case <-ctx.Done():
			if conn != nil {
				conn.ForceClose()
			}
		}
	}()
}

// handleDialResult processes a dial result from a dial goroutine.
func (pm *PeerManager) handleDialResult(ctx context.Context, result dialResult) {
	// Ignore results from old connect cycles.
	if result.gen != pm.connectGen {
		if result.conn != nil {
			result.conn.ForceClose()
		}
		return
	}

	delete(pm.inFlight, result.transportName)

	pm.mu.Lock()
	ts := pm.getOrCreateTransportState(result.transportName)

	if result.err == nil {
		// Success: promote to active.
		ts.subState = TransportSubActive
		ts.failures = 0
		ts.quarantineN = 0
		ts.conn = result.conn
		ts.latency.push(result.conn.Latency())
		pm.lastLatency = result.conn.Latency()

		// Close previous active connection if different.
		if pm.currentTransport != "" && pm.currentTransport != result.transportName {
			if oldTS, ok := pm.transportStates[pm.currentTransport]; ok && oldTS.conn != nil {
				oldTS.conn.ForceClose()
				oldTS.conn = nil
				oldTS.subState = TransportSubActive // idle-ready
			}
		}
		pm.currentTransport = result.transportName
		pm.mu.Unlock()

		// Cancel other in-flight dials.
		pm.cancelInFlight()
		pm.stopHappyEyeballs()
		pm.stopRetry()

		// Transition to connected.
		pm.stateAtomic.Store(int32(PeerConnected))
		return
	}

	// Failure: record and check quarantine.
	ts.failures++
	ts.failureTimes = append(ts.failureTimes, time.Now())
	// Trim old failure times beyond lookback window.
	pm.trimFailures(ts, time.Now())

	threshold := pm.failureThreshold(result.transportName)
	if ts.failures >= threshold {
		ts.quarantineN++
		ts.subState = TransportSubQuarantined
		cooldown := pm.cooldownDuration(ts.quarantineN)
		ts.cooldownUntil = time.Now().Add(cooldown)

		if ts.quarantineN >= pm.cfg.BlackoutThreshold {
			ts.subState = TransportSubFailed
		}
	} else {
		// Stay available for retry — reset to active (idle-ready).
		ts.subState = TransportSubActive
	}
	pm.mu.Unlock()

	// If all in-flight dials have completed, decide what to do next.
	if len(pm.inFlight) == 0 {
		pm.stopHappyEyeballs()
		pm.onAllDialsFailed(ctx)
	}
}

// onAllDialsFailed handles the case where all dial attempts in a cycle failed.
func (pm *PeerManager) onAllDialsFailed(ctx context.Context) {
	candidates := pm.candidateTransports()
	if len(candidates) > 0 {
		// Still have non-quarantined transports — retry after a short delay.
		if pm.retryTimer != nil {
			pm.retryTimer.Stop()
		}
		pm.retryTimer = time.NewTimer(pm.cfg.RetryInterval())
		return
	}

	// All transports quarantined — wait for cooldown expiry on probe tick.
	// Check if any cooldowns have already expired (for very short cooldowns).
	pm.checkQuarantineExpiry(ctx)
}

// ── Probe tick ──────────────────────────────────────────────────────────────

// onProbeTick is called on each probe interval. It handles quarantine expiry,
// active probing, and path selection evaluation.
func (pm *PeerManager) onProbeTick(ctx context.Context) {
	state := PeerState(pm.stateAtomic.Load())

	switch state {
	case PeerConnecting:
		pm.checkQuarantineExpiry(ctx)
		// If retry timer hasn't started but we have candidates, start a cycle.
		if pm.retryTimer == nil && len(pm.inFlight) == 0 {
			candidates := pm.candidateTransports()
			if len(candidates) > 0 {
				pm.startConnectCycle(ctx)
			}
		}

	case PeerConnected:
		pm.probeAndEvaluate(ctx)
	}
}

// checkQuarantineExpiry transitions quarantined transports back to active
// if their cooldown has expired, and starts a new connect cycle if
// the peer is in connecting state.
func (pm *PeerManager) checkQuarantineExpiry(ctx context.Context) {
	now := time.Now()
	anyExpired := false

	pm.mu.Lock()
	for _, ts := range pm.transportStates {
		if ts.subState == TransportSubQuarantined && now.After(ts.cooldownUntil) {
			ts.subState = TransportSubActive
			ts.failures = 0 // reset for fresh attempt
			anyExpired = true
		}
	}
	pm.mu.Unlock()

	if anyExpired && PeerState(pm.stateAtomic.Load()) == PeerConnecting && len(pm.inFlight) == 0 {
		pm.startConnectCycle(ctx)
	}
}

// probeAndEvaluate probes idle transports for latency and evaluates
// whether the active transport should be switched.
func (pm *PeerManager) probeAndEvaluate(ctx context.Context) {
	pm.mu.Lock()
	activeName := pm.currentTransport
	states := make(map[string]*transportState, len(pm.transportStates))
	for k, v := range pm.transportStates {
		states[k] = v
	}
	pm.mu.Unlock()

	// Probe transports for latency.
	for name, ts := range states {
		if ts.subState == TransportSubQuarantined || ts.subState == TransportSubFailed {
			// For quarantined Reality, use extended probe interval.
			if name == "reality" && ts.subState == TransportSubQuarantined {
				if !time.Now().After(ts.lastProbeAt.Add(pm.cfg.ProbeIntervalQuarantinedReality)) {
					continue
				}
			} else {
				continue
			}
		}

		// Get the transport instance.
		transport, err := pm.getOrCreateTransport(name)
		if err != nil || !transport.IsHealthy() {
			continue
		}

		// Determine probe interval.
		probeInterval := pm.cfg.ProbeInterval
		if !time.Now().After(ts.lastProbeAt.Add(probeInterval)) {
			continue
		}

		// Transition to probing state so active probes are observable
		// in telemetry and state dumps (spec §2.3).
		prevState := ts.subState
		pm.mu.Lock()
		ts.subState = TransportSubProbing
		pm.mu.Unlock()

		// Run active probe.
		rtt, err := transport.LatencyProbe(ctx, pm.cfg.Addr)

		pm.mu.Lock()
		if err != nil {
			// Permanent error → mark transport as failed.
			var tErr *TransportError
			if errors.As(err, &tErr) && !tErr.IsRetryable() {
				ts.subState = TransportSubFailed
			} else {
				// Transient probe failure → restore previous state.
				ts.subState = prevState
			}
			ts.lastProbeAt = time.Now()
			pm.mu.Unlock()
			continue
		}
		// Probe succeeded → transition back to active.
		ts.subState = TransportSubActive
		ts.latency.push(rtt)
		ts.lastProbeAt = time.Now()
		if name == activeName {
			pm.lastLatency = rtt
		}
		pm.mu.Unlock()
	}

	// Evaluate path switching.
	pm.evaluatePathSwitching(ctx, activeName, states)
}

// evaluatePathSwitching computes scores and switches the active transport
// if a better alternative has been stable for ScoreStableProbes cycles.
func (pm *PeerManager) evaluatePathSwitching(ctx context.Context, activeName string, states map[string]*transportState) {
	if activeName == "" {
		return
	}

	activeTS, ok := states[activeName]
	if !ok || activeTS.latency.count < pm.cfg.MinSamplesForScoring {
		return
	}

	activeScore := pm.computeScore(activeTS)
	if activeScore == 0 {
		return
	}

	// Apply hysteresis bonus to the active transport's score.
	// This makes the active transport "stickier" — an alternative must
	// beat it by more than the bonus to trigger a switch, preventing
	// flapping between near-identical-latency transports.
	hBonus := pm.hysteresisBonus(activeScore)
	effectiveActive := activeScore - hBonus

	// Find best alternative.
	var bestName string
	var bestScore float64
	for name, ts := range states {
		if name == activeName {
			continue
		}
		if ts.subState == TransportSubQuarantined || ts.subState == TransportSubFailed {
			continue
		}
		if ts.latency.count < pm.cfg.MinSamplesForScoring {
			continue
		}
		score := pm.computeScore(ts)
		if score == 0 {
			continue
		}
		if bestName == "" || score < bestScore {
			bestName = name
			bestScore = score
		}
	}

	if bestName == "" {
		pm.mu.Lock()
		if activeTS != nil {
			activeTS.stableBetter = 0
		}
		pm.mu.Unlock()
		return
	}

	// Check if alternative is significantly better.
	// Switch when bestScore < effectiveActive × (1 - threshold)
	threshold := pm.cfg.ScoreSwitchThreshold
	if bestScore < effectiveActive*(1-threshold) {
		pm.mu.Lock()
		activeTS.stableBetter++
		stable := activeTS.stableBetter
		pm.mu.Unlock()

		if stable >= pm.cfg.ScoreStableProbes {
			// Switch! Close current connection, start connect cycle with alternative.
			pm.triggerSwitch(ctx, bestName)
		}
	} else {
		pm.mu.Lock()
		activeTS.stableBetter = 0
		pm.mu.Unlock()
	}
}

// hysteresisBonus returns the amount to subtract from the active
// transport's score to prevent flapping. If HysteresisBonus is 0,
// it defaults to 10% of the active score (spec §6.1). A positive
// value is used as a fixed latency in ms. A negative value disables
// hysteresis (returns 0).
func (pm *PeerManager) hysteresisBonus(activeScore float64) float64 {
	if pm.cfg.HysteresisBonus < 0 {
		return 0
	}
	if pm.cfg.HysteresisBonus == 0 {
		return activeScore * 0.1 // 10% default
	}
	return pm.cfg.HysteresisBonus
}

// computeScore calculates the path selection score for a transport.
// score = ewma_latency_ms × (1 + failure_penalty)
// where failure_penalty = recent_failures / max(attempts, 10)
// Recent failures are those within the FailureLookback window.
func (pm *PeerManager) computeScore(ts *transportState) float64 {
	ewma := ts.latency.current()
	if ewma == 0 {
		return 0
	}
	// Count recent failures within lookback window.
	now := time.Now()
	recentFailures := 0
	for _, ft := range ts.failureTimes {
		if now.Sub(ft) <= pm.cfg.FailureLookback {
			recentFailures++
		}
	}
	// Also count current consecutive failures.
	if ts.failures > recentFailures {
		recentFailures = ts.failures
	}
	attempts := 10 // floor per spec: max(attempts, 10)
	if ts.latency.count+recentFailures > attempts {
		attempts = ts.latency.count + recentFailures
	}
	failurePenalty := float64(recentFailures) / float64(attempts)
	return float64(ewma.Milliseconds()) * (1 + failurePenalty)
}

// triggerSwitch closes the current active connection and starts a new
// connect cycle with the target transport first in the fallback order.
func (pm *PeerManager) triggerSwitch(ctx context.Context, toTransport string) {
	// Close current active connection.
	pm.mu.Lock()
	if old, ok := pm.transportStates[pm.currentTransport]; ok && old.conn != nil {
		old.conn.ForceClose()
		old.conn = nil
		old.subState = TransportSubActive
	}
	// Reorder transport names to put target first.
	pm.cfg.TransportNames = pm.reorderTransports(toTransport)
	pm.currentTransport = ""
	pm.mu.Unlock()

	// Transition to connecting and start a new cycle.
	pm.stateAtomic.Store(int32(PeerConnecting))
	pm.startConnectCycle(ctx)
}

// ── Reconnect ───────────────────────────────────────────────────────────────

// handleReconnect resets all quarantine state and starts a fresh connect cycle.
func (pm *PeerManager) handleReconnect(ctx context.Context) {
	pm.mu.Lock()
	for _, ts := range pm.transportStates {
		ts.subState = TransportSubActive
		ts.quarantineN = 0
		ts.failures = 0
		ts.cooldownUntil = time.Time{}
		ts.failureTimes = nil
		ts.latency.reset()
		ts.stableBetter = 0
		if ts.conn != nil {
			ts.conn.ForceClose()
			ts.conn = nil
		}
	}
	pm.currentTransport = ""
	pm.mu.Unlock()

	pm.cancelInFlight()
	pm.stopHappyEyeballs()
	pm.stopRetry()

	pm.stateAtomic.Store(int32(PeerConnecting))
	pm.startConnectCycle(ctx)
}

// ── Cleanup ─────────────────────────────────────────────────────────────────

// cleanup closes all connections and timers. Called when the goroutine exits.
func (pm *PeerManager) cleanup() {
	pm.cancelInFlight()
	pm.stopHappyEyeballs()
	pm.stopRetry()

	pm.mu.Lock()
	for _, ts := range pm.transportStates {
		if ts.conn != nil {
			ts.conn.ForceClose()
			ts.conn = nil
		}
	}
	pm.currentTransport = ""
	pm.mu.Unlock()

	pm.stateAtomic.Store(int32(PeerDisconnected))
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// candidateTransports returns non-quarantined, non-failed transports
// in fallback order.
func (pm *PeerManager) candidateTransports() []string {
	var result []string
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, name := range pm.cfg.TransportNames {
		ts := pm.transportStates[name]
		if ts == nil {
			// New transport — eligible.
			result = append(result, name)
			continue
		}
		if ts.subState != TransportSubQuarantined && ts.subState != TransportSubFailed {
			result = append(result, name)
		}
	}
	return result
}

// blackoutEscapeCandidates returns transports for blackout escape:
// the least-recently-quarantined transport(s), tried immediately.
// Per spec §2.3, TransportSubFailed transports are excluded — they
// require an explicit Reconnect() call and must not be auto-escaped.
func (pm *PeerManager) blackoutEscapeCandidates() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var best string
	var bestTime time.Time
	for _, name := range pm.cfg.TransportNames {
		ts := pm.transportStates[name]
		if ts == nil {
			return []string{name} // never-tried transport
		}
		if ts.subState == TransportSubQuarantined {
			if best == "" || ts.cooldownUntil.Before(bestTime) {
				best = name
				bestTime = ts.cooldownUntil
			}
		}
	}
	if best != "" {
		return []string{best}
	}
	return nil
}

// reorderTransports returns a new transport name list with target first.
func (pm *PeerManager) reorderTransports(target string) []string {
	result := make([]string, 0, len(pm.cfg.TransportNames))
	result = append(result, target)
	for _, name := range pm.cfg.TransportNames {
		if name != target {
			result = append(result, name)
		}
	}
	return result
}

// getOrCreateTransportState returns the existing transportState or creates one.
// Caller must hold pm.mu (write lock).
func (pm *PeerManager) getOrCreateTransportState(name string) *transportState {
	ts, ok := pm.transportStates[name]
	if !ok {
		ts = &transportState{
			name:     name,
			subState: TransportSubActive,
			latency:  newLatencyEWMA(pm.cfg.AlphaRise, pm.cfg.AlphaFall),
		}
		pm.transportStates[name] = ts
	}
	return ts
}

// failureThreshold returns the failure threshold for a transport.
func (pm *PeerManager) failureThreshold(name string) int {
	if t, ok := pm.cfg.QuarantineThreshold[name]; ok && t > 0 {
		return t
	}
	switch name {
	case "udp":
		return DefaultUDPFailureThreshold
	case "websocket":
		return DefaultWSFailureThreshold
	case "reality":
		return DefaultRealityFailureThreshold
	default:
		return DefaultUDPFailureThreshold
	}
}

// cooldownDuration computes the exponential backoff for quarantine cycle n.
// cooldown = min(BaseCooldown × 2^n, MaxCooldown)
// n=0 → BaseCooldown (30s), n=1 → 60s, n=2 → 120s, n=3 → 240s, ...
func (pm *PeerManager) cooldownDuration(n int) time.Duration {
	d := pm.cfg.QuarantineBaseCooldown
	for i := 0; i < n; i++ {
		d *= 2
		if d > pm.cfg.QuarantineMaxCooldown {
			return pm.cfg.QuarantineMaxCooldown
		}
	}
	if d > pm.cfg.QuarantineMaxCooldown {
		return pm.cfg.QuarantineMaxCooldown
	}
	return d
}

// trimFailures removes failure timestamps older than the lookback window.
func (pm *PeerManager) trimFailures(ts *transportState, now time.Time) {
	cutoff := now.Add(-pm.cfg.FailureLookback)
	kept := ts.failureTimes[:0]
	for _, ft := range ts.failureTimes {
		if ft.After(cutoff) {
			kept = append(kept, ft)
		}
	}
	ts.failureTimes = kept
}

// getOrCreateTransport returns a cached Transport instance or creates one
// from the registry factory.
func (pm *PeerManager) getOrCreateTransport(name string) (Transport, error) {
	f, err := pm.registry.Get(name)
	if err != nil {
		return nil, err
	}
	cfg := pm.buildTransportConfig(name)
	return f.NewTransport(cfg)
}

// buildTransportConfig creates a TransportConfig for the given transport.
func (pm *PeerManager) buildTransportConfig(name string) TransportConfig {
	cfg := DefaultTransportConfig()
	cfg.Name = name
	return cfg
}

// cancelInFlight cancels all in-flight dials and clears the tracking map.
func (pm *PeerManager) cancelInFlight() {
	if pm.dialCancel != nil {
		pm.dialCancel()
	}
	pm.inFlight = make(map[string]bool)
}

// stopHappyEyeballs stops the Happy Eyeballs timer.
func (pm *PeerManager) stopHappyEyeballs() {
	if pm.happyEyeballsTimer != nil {
		pm.happyEyeballsTimer.Stop()
		pm.happyEyeballsTimer = nil
	}
}

// stopRetry stops the retry timer.
func (pm *PeerManager) stopRetry() {
	if pm.retryTimer != nil {
		pm.retryTimer.Stop()
		pm.retryTimer = nil
	}
}

// RetryInterval returns the delay between connect cycle retries.
// Defaults to 1s, or 10% of base cooldown if not explicitly set.
func (c PeerManagerConfig) RetryInterval() time.Duration {
	if c.QuarantineBaseCooldown > 0 {
		d := c.QuarantineBaseCooldown / 10
		if d < 100*time.Millisecond {
			d = 100 * time.Millisecond
		}
		return d
	}
	return 1 * time.Second
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportRegistry.Dial — convenience method for PeerManager
// ──────────────────────────────────────────────────────────────────────────────

// getFactoryExact returns the factory with the given name, ignoring fallback
// order. Used by Dial when a specific transport is requested.
func (r *TransportRegistry) getFactoryExact(name string) (TransportFactory, error) {
	if r.factories == nil {
		return nil, ErrTransportNotFound
	}
	f, ok := r.factories[name]
	if !ok {
		return nil, ErrTransportNotFound
	}
	return f, nil
}

// Dial creates a Transport from the named factory and connects to addr.
// The Transport instance is created fresh on each call; callers that need
// to reuse a Transport instance should cache it separately.
//
// This is the primary method PeerManager calls to establish a connection
// on a specific transport. It bypasses the fallback order — use Get() for
// fallback-aware factory selection.
func (r *TransportRegistry) Dial(ctx context.Context, transportName, addr string, cfg TransportConfig) (PeerConn, error) {
	f, err := r.getFactoryExact(transportName)
	if err != nil {
		return nil, err
	}
	cfg.Name = transportName
	t, err := f.NewTransport(cfg)
	if err != nil {
		return nil, err
	}
	return t.Connect(ctx, addr)
}
