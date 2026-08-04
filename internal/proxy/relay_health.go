package proxy

import (
	"sync"
	"time"
)

// RelayHealthState tracks the health of a single relay node.
type RelayHealthState int

const (
	// RelayHealthy means the relay is responding to probes and
	// available for path selection.
	RelayHealthy RelayHealthState = iota
	// RelayDegraded means the relay has missed 1-2 consecutive probes.
	// It is still eligible for selection but with a penalty.
	RelayDegraded
	// RelayUnhealthy means the relay has missed 3+ consecutive probes.
	// It is excluded from path selection until it recovers.
	RelayUnhealthy
)

// relayHealthEntry tracks per-relay health state.
type relayHealthEntry struct {
	state           RelayHealthState
	consecutiveFail int       // consecutive probe failures
	lastSuccess     time.Time // last successful probe
	lastFailure     time.Time // last failed probe
	lastRTT         time.Duration
}

// RelayHealthTracker tracks the health of relay nodes and provides
// failover decisions for the path selector.
//
// A relay transitions through three states:
//   - Healthy: 0 consecutive failures. Eligible for selection.
//   - Degraded: 1-2 consecutive failures. Eligible but penalized.
//   - Unhealthy: 3+ consecutive failures. Excluded from selection.
//
// A relay recovers to Healthy on the first successful probe after
// being Unhealthy. The recovery is subject to a cooldown period
// (healthRecoveryDelay) to avoid flapping.
type RelayHealthTracker struct {
	mu sync.RWMutex

	// health maps relay NodeID → health state.
	health map[string]*relayHealthEntry

	// healthRecoveryDelay is the minimum time a relay must stay
	// unhealthy before it can be re-tested for recovery. This
	// prevents rapid flapping between healthy and unhealthy.
	healthRecoveryDelay time.Duration

	// unhealthyThreshold is the number of consecutive failures
	// before a relay is marked unhealthy.
	unhealthyThreshold int

	// degradedThreshold is the number of consecutive failures
	// before a relay is marked degraded.
	degradedThreshold int
}

// DefaultHealthRecoveryDelay is the default cooldown before re-testing
// an unhealthy relay.
const DefaultHealthRecoveryDelay = 30 * time.Second

// NewRelayHealthTracker creates a new health tracker with default settings.
func NewRelayHealthTracker() *RelayHealthTracker {
	return &RelayHealthTracker{
		health:              make(map[string]*relayHealthEntry),
		healthRecoveryDelay: DefaultHealthRecoveryDelay,
		degradedThreshold:   1,
		unhealthyThreshold:  3,
	}
}

// RecordSuccess records a successful probe for a relay.
// This resets the failure count and transitions the relay to Healthy.
func (h *RelayHealthTracker) RecordSuccess(nodeID string, rtt time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	entry := h.getOrCreate(nodeID)
	entry.consecutiveFail = 0
	entry.state = RelayHealthy
	entry.lastSuccess = time.Now()
	entry.lastRTT = rtt
}

// RecordFailure records a failed probe for a relay.
// After degradedThreshold failures, the relay is marked Degraded.
// After unhealthyThreshold failures, the relay is marked Unhealthy.
func (h *RelayHealthTracker) RecordFailure(nodeID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	entry := h.getOrCreate(nodeID)
	entry.consecutiveFail++
	entry.lastFailure = time.Now()

	if entry.consecutiveFail >= h.unhealthyThreshold {
		entry.state = RelayUnhealthy
	} else if entry.consecutiveFail >= h.degradedThreshold {
		entry.state = RelayDegraded
	}
}

// IsHealthy returns true if the relay is Healthy or Degraded (i.e.,
// eligible for selection, possibly with a penalty).
func (h *RelayHealthTracker) IsHealthy(nodeID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	entry, ok := h.health[nodeID]
	if !ok {
		return true // unknown relays are assumed healthy
	}
	return entry.state != RelayUnhealthy
}

// IsUnhealthy returns true if the relay is Unhealthy and should be
// excluded from path selection.
func (h *RelayHealthTracker) IsUnhealthy(nodeID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	entry, ok := h.health[nodeID]
	if !ok {
		return false
	}
	return entry.state == RelayUnhealthy
}

// IsDegraded returns true if the relay is Degraded (missed probes but
// still eligible for selection with a penalty).
func (h *RelayHealthTracker) IsDegraded(nodeID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	entry, ok := h.health[nodeID]
	if !ok {
		return false
	}
	return entry.state == RelayDegraded
}

// HealthPenalty returns a quality penalty multiplier for a relay.
// Healthy relays return 1.0 (no penalty).
// Degraded relays return 1.5 (50% penalty).
// Unhealthy relays return math.Inf (excluded).
func (h *RelayHealthTracker) HealthPenalty(nodeID string) float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	entry, ok := h.health[nodeID]
	if !ok {
		return 1.0
	}
	switch entry.state {
	case RelayHealthy:
		return 1.0
	case RelayDegraded:
		return 1.5
	case RelayUnhealthy:
		return float64(1 << 30) // very large, effectively excludes
	default:
		return 1.0
	}
}

// CanRetry returns true if an unhealthy relay has waited long enough
// to be re-tested for recovery.
func (h *RelayHealthTracker) CanRetry(nodeID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	entry, ok := h.health[nodeID]
	if !ok {
		return true
	}
	if entry.state != RelayUnhealthy {
		return true
	}
	return time.Since(entry.lastFailure) >= h.healthRecoveryDelay
}

// UnhealthyRelays returns the list of currently unhealthy relay IDs.
func (h *RelayHealthTracker) UnhealthyRelays() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var result []string
	for id, entry := range h.health {
		if entry.state == RelayUnhealthy {
			result = append(result, id)
		}
	}
	return result
}

// Reset clears all health state for a relay.
func (h *RelayHealthTracker) Reset(nodeID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.health, nodeID)
}

// ResetAll clears all health state.
func (h *RelayHealthTracker) ResetAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.health = make(map[string]*relayHealthEntry)
}

// getOrCreate returns an existing entry or creates a new one.
// Caller must hold the write lock.
func (h *RelayHealthTracker) getOrCreate(nodeID string) *relayHealthEntry {
	entry, ok := h.health[nodeID]
	if !ok {
		entry = &relayHealthEntry{
			state: RelayHealthy,
		}
		h.health[nodeID] = entry
	}
	return entry
}
