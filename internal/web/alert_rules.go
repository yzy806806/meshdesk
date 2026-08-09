package web

import (
	"log"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/monitor"
)

// ──────────────────────────────────────────────────────────────────────────
// Threshold alert rules (T4.1): periodically evaluate node metrics and
// raise alerts when a rule fires (CPU > 90%, node offline, etc.).
// Rules live in memory; fired alerts go into the AlertStore (which can
// forward to a webhook).
// ──────────────────────────────────────────────────────────────────────────

// AlertRule is a threshold rule over node metrics.
type AlertRule struct {
	// Metric: "cpu" | "mem" | "offline" | "disk"
	Metric string `json:"metric"`
	// Threshold for numeric metrics (percent for cpu/mem/disk).
	Threshold float64 `json:"threshold"`
	// DurationSec: how long the condition must persist before firing.
	DurationSec int `json:"duration_sec,omitempty"`
	// Severity of the fired alert.
	Severity AlertSeverity `json:"severity"`
	// Description template (may reference {node}).
	Description string `json:"description"`
}

// RuleEvaluator periodically checks node metrics against rules.
type RuleEvaluator struct {
	store   *monitor.Store
	alerts  *AlertStore
	mu      sync.Mutex
	rules   []AlertRule
	started bool
	// conditionStart tracks when a rule+node condition first became true.
	conditionStart map[string]time.Time
}

// NewRuleEvaluator creates a rule evaluator over the monitor store.
func NewRuleEvaluator(store *monitor.Store, alerts *AlertStore) *RuleEvaluator {
	return &RuleEvaluator{
		store:          store,
		alerts:         alerts,
		conditionStart: make(map[string]time.Time),
	}
}

// SetRules installs the active rules.
func (e *RuleEvaluator) SetRules(rules []AlertRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// Start begins periodic evaluation (30s interval).
func (e *RuleEvaluator) Start() {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started = true
	e.mu.Unlock()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			e.evaluate()
		}
	}()
	log.Printf("[alerts] threshold rule evaluator started (30s interval)")
}

func (e *RuleEvaluator) evaluate() {
	e.mu.Lock()
	rules := append([]AlertRule(nil), e.rules...)
	e.mu.Unlock()
	if len(rules) == 0 {
		return
	}

	// Snapshot node IDs from the monitor store.
	now := time.Now()
	for _, rule := range rules {
		for _, nodeID := range e.nodeIDs() {
			fired := e.checkRule(nodeID, rule)
			key := rule.Metric + "|" + nodeID
			if fired {
				if _, ok := e.conditionStart[key]; !ok {
					e.conditionStart[key] = now
				}
				if time.Since(e.conditionStart[key]) >= time.Duration(rule.DurationSec)*time.Second {
					desc := rule.Description
					if desc == "" {
						desc = rule.Metric + " threshold exceeded on {node}"
					}
					e.alerts.Add(SecurityAlert{
						Timestamp:   now,
						Severity:    rule.Severity,
						Type:        "rule:" + rule.Metric,
						Description: desc + " (" + nodeID[:min(len(nodeID), 16)] + ")",
					})
					delete(e.conditionStart, key) // avoid repeat spam; next firing re-arms
				}
			} else {
				delete(e.conditionStart, key)
			}
		}
	}
}

func (e *RuleEvaluator) nodeIDs() []string {
	if e.store == nil {
		return []string{"local"}
	}
	ids := e.store.NodeIDs()
	if len(ids) == 0 {
		return []string{"local"}
	}
	return ids
}

func (e *RuleEvaluator) checkRule(nodeID string, rule AlertRule) bool {
	if e.store == nil {
		return false
	}
	m := e.store.Latest(nodeID)
	if m == nil {
		// No data: treat as offline for the "offline" rule.
		return rule.Metric == "offline"
	}
	age := time.Since(m.Timestamp)
	switch rule.Metric {
	case "cpu":
		if age > 90*time.Second {
			return false
		}
		return m.CPU.UsagePercent >= rule.Threshold
	case "mem":
		if age > 90*time.Second {
			return false
		}
		if m.Memory.Total == 0 {
			return false
		}
		return float64(m.Memory.Used)*100/float64(m.Memory.Total) >= rule.Threshold
	case "offline":
		// Fires when the node's latest sample is stale (>90s).
		return age > 90*time.Second
	}
	return false
}
