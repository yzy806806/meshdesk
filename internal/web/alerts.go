package web

import (
	"sync"
	"time"
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

// Dismiss marks all alerts as dismissed (bulk acknowledge).
func (s *AlertStore) DismissAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.alerts {
		s.alerts[i].Dismissed = true
	}
}
