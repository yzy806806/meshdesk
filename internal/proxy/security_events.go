package proxy

import "sync/atomic"

// SecurityEventType categorizes suspicious proxy activity for alerting.
type SecurityEventType string

const (
	// SecEventExitPortDenied: exit node rejected a circuit setup because
	// the target port is not in the allowed list.
	SecEventExitPortDenied SecurityEventType = "exit_port_denied"

	// SecEventExitCircuitSetupFail: exit node failed to process a circuit
	// setup (e.g. dial target failed, ECDH error, duplicate circuit).
	SecEventExitCircuitSetupFail SecurityEventType = "exit_circuit_setup_fail"

	// SecEventExitDecodeFail: exit node failed to decode/decrypt a wire chunk.
	SecEventExitDecodeFail SecurityEventType = "exit_decode_fail"

	// SecEventExitWindowExceeded: exit node rejected a chunk whose sequence
	// is beyond the reassembly window (potential DoS / protocol abuse).
	SecEventExitWindowExceeded SecurityEventType = "exit_window_exceeded"

	// SecEventExitCircuitNotFound: exit node received a chunk for an
	// unknown circuit (orphan or attack probe).
	SecEventExitCircuitNotFound SecurityEventType = "exit_circuit_not_found"

	// SecEventExitNACKRetriesExhausted: exit node has exhausted all NACK
	// retries for a gap and is requesting circuit teardown (spec §3.3).
	SecEventExitNACKRetriesExhausted SecurityEventType = "exit_nack_retries_exhausted"

	// SecEventSSConnError: SS listener encountered a connection error
	// (e.g. salt read failure, AEAD decryption failure, invalid address).
	SecEventSSConnError SecurityEventType = "ss_conn_error"

	// SecEventRelayCircuitNotFound: relay received a chunk for an
	// unregistered circuit.
	SecEventRelayCircuitNotFound SecurityEventType = "relay_circuit_not_found"

	// SecEventRelayHeaderDecodeFail: relay failed to decrypt the
	// forwarding header (wrong key or corrupt data).
	SecEventRelayHeaderDecodeFail SecurityEventType = "relay_header_decode_fail"

	// SecEventRelayAtCapacity: relay rejected a new circuit because it
	// is at max capacity (potential resource exhaustion attack).
	SecEventRelayAtCapacity SecurityEventType = "relay_at_capacity"
)

// SecurityEvent describes a suspicious proxy activity for alerting.
type SecurityEvent struct {
	Type        SecurityEventType
	Description string
	SourceIP    string // remote address of the connecting peer, if known
	CircuitID   string // hex circuit ID, if relevant
	TargetAddr  string // target address (for exit port denials), if relevant
}

// SecurityEventCallback is invoked when the proxy subsystem detects
// suspicious activity. It receives a SecurityEvent describing what happened.
// The callback is invoked synchronously within the handler, so it must be
// fast (e.g. enqueue to a buffer) and must not block.
type SecurityEventCallback func(event SecurityEvent)

// SecurityEventSink is an atomically-settable callback for proxy security
// events. It is shared by the exit node, relay, and SS listener so that
// all three can report to the same dashboard alert store.
type SecurityEventSink struct {
	cb atomic.Pointer[SecurityEventCallback]
}

// NewSecurityEventSink creates a new sink with no callback set.
func NewSecurityEventSink() *SecurityEventSink {
	return &SecurityEventSink{}
}

// SetCallback installs the callback. Pass nil to clear.
func (s *SecurityEventSink) SetCallback(cb SecurityEventCallback) {
	s.cb.Store(&cb)
}

// Report invokes the callback if one is set. Safe to call from any goroutine.
func (s *SecurityEventSink) Report(event SecurityEvent) {
	if s == nil {
		return
	}
	if cbPtr := s.cb.Load(); cbPtr != nil && *cbPtr != nil {
		(*cbPtr)(event)
	}
}
