package web

import (
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/proxy"
)

// Alert severity levels.
type AlertSeverity string

const (
	AlertInfo     AlertSeverity = "info"
	AlertWarning  AlertSeverity = "warning"
	AlertCritical AlertSeverity = "critical"
)

// SecurityAlert represents a security-relevant event for dashboard display.
type SecurityAlert struct {
	Timestamp   time.Time     `json:"timestamp"`
	Severity    AlertSeverity `json:"severity"`
	Type        string        `json:"type"`
	Username    string        `json:"username,omitempty"`
	SourceIP    string        `json:"source_ip,omitempty"`
	Description string        `json:"description"`
	Dismissed   bool          `json:"dismissed"`
}

// AlertStore is an in-memory ring buffer for security alerts.
// It caps at maxAlerts entries and deduplicates identical alerts
// (same type+username+description) within a 60-second window.
type AlertStore struct {
	mu        sync.Mutex
	alerts    []SecurityAlert
	maxAlerts int
	lastAlert map[string]time.Time // dedup key → last timestamp
}

// NewAlertStore creates a new alert store with a 1000-entry ring buffer.
func NewAlertStore() *AlertStore {
	return &AlertStore{
		alerts:    make([]SecurityAlert, 0, 256),
		maxAlerts: 1000,
		lastAlert: make(map[string]time.Time),
	}
}

// Add appends an alert to the store. Returns false if the alert was
// suppressed by deduplication (same type+username+description within 60s).
func (s *AlertStore) Add(alert SecurityAlert) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := alert.Type + ":" + alert.Username + ":" + alert.Description
	if last, ok := s.lastAlert[key]; ok && time.Since(last) < 60*time.Second {
		return false
	}

	alert.Timestamp = time.Now()
	s.lastAlert[key] = alert.Timestamp

	// Ring buffer: evict oldest when at capacity.
	if len(s.alerts) >= s.maxAlerts {
		s.alerts = s.alerts[1:]
	}
	s.alerts = append(s.alerts, alert)
	return true
}

// List returns a copy of all alerts (newest last).
func (s *AlertStore) List() []SecurityAlert {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]SecurityAlert, len(s.alerts))
	copy(result, s.alerts)
	return result
}

// Count returns the number of alerts in the store.
func (s *AlertStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.alerts)
}

// CountUndismissed returns the number of alerts that have not been dismissed.
func (s *AlertStore) CountUndismissed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, a := range s.alerts {
		if !a.Dismissed {
			count++
		}
	}
	return count
}

// DismissAll marks all alerts as dismissed (bulk acknowledge).
func (s *AlertStore) DismissAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.alerts {
		s.alerts[i].Dismissed = true
	}
}

// =============================================================================
// External event adapter methods
//
// These methods convert events from other subsystems (auth, mesh, proxy)
// into SecurityAlert entries and add them to the store. They are the bridge
// between subsystem-specific callback types and the dashboard alert model.
// =============================================================================

// HandleAuthDenial converts an auth.CapabilityEngine denial into a security
// alert and adds it to the store. This is designed to be installed as the
// engine's deny callback via auth.CapabilityEngine.SetDenyCallback.
//
// Denials are classified as "critical" for revoked peers (someone with a
// revoked key is trying to access services) and "warning" for all other
// denial reasons (no_capability, path_denied, service_not_scoped, etc.).
func (s *AlertStore) HandleAuthDenial(result auth.AuthResult) {
	severity := AlertWarning
	if result.Reason == "revoked" {
		severity = AlertCritical
	}

	s.Add(SecurityAlert{
		Type:        "capability_denied",
		Username:    result.SourcePeer,
		SourceIP:    result.SourceIP,
		Description: "capability " + result.Capability + " denied (" + result.Reason + ") for resource: " + result.Resource,
		Severity:    severity,
	})
}

// HandlePeerJoin converts a mesh peer join into a security alert and adds
// it to the store. This is designed to be installed as the routing table's
// join callback via mesh.RoutingTable.SetJoinCallback.
//
// New node joins are "info" severity by default. The admin can review the
// alert to verify the new peer is expected.
func (s *AlertStore) HandlePeerJoin(peer *mesh.PeerEntry) {
	s.Add(SecurityAlert{
		Type:        "node_join",
		Username:    peer.ID,
		Description:  "new node joined mesh: " + peer.ID[:min(8, len(peer.ID))] + " endpoint=" + peer.Endpoint,
		Severity:    AlertInfo,
	})
}

// HandlePeerLeave converts a mesh peer leave into a security alert.
// This is designed to be installed via mesh.RoutingTable.SetLeaveCallback.
func (s *AlertStore) HandlePeerLeave(peerID string) {
	s.Add(SecurityAlert{
		Type:        "node_leave",
		Username:    peerID,
		Description:  "node left mesh: " + peerID,
		Severity:    AlertInfo,
	})
}

// HandleProxySecurityEvent converts a proxy.SecurityEvent into a security
// alert and adds it to the store. This is designed to be installed as the
// proxy.SecurityEventSink callback.
//
// The severity is determined by the event type:
//   - port_denied, window_exceeded, relay_at_capacity: warning
//   - decode failures, circuit_not_found, ss_conn_error: warning
//   - circuit_setup_fail: warning
func (s *AlertStore) HandleProxySecurityEvent(event proxy.SecurityEvent) {
	s.Add(SecurityAlert{
		Type:        string(event.Type),
		Username:    event.CircuitID,
		SourceIP:    event.SourceIP,
		Description:  event.Description,
		Severity:    AlertWarning,
	})
}

// min returns the smaller of two ints (local to avoid import conflicts).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
