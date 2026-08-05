package web

import (
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/logging"
	"github.com/yzy806806/meshdesk/internal/mesh"
)

func TestACLReloader_RuleUpdate(t *testing.T) {
	// Create an ACL engine with initial rules.
	engine, err := mesh.NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{Action: config.ACLActionDeny, SourceCIDR: "10.0.0.0/8", DestCIDR: "*"},
		},
	})
	if err != nil {
		t.Fatalf("NewACLEngine: %v", err)
	}

	// Track broadcast calls.
	var broadcastCalled bool
	var broadcastedRules []string
	broadcast := func(rules []string) {
		broadcastCalled = true
		broadcastedRules = rules
	}

	reloader := NewACLReloader(engine, broadcast)

	// New config with updated rules.
	cfg := config.Default()
	cfg.ACL = config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionDeny,
		Rules: []config.ACLRule{
			{Action: config.ACLActionAllow, SourceCIDR: "192.168.0.0/16", DestCIDR: "*"},
			{Action: config.ACLActionDeny, SourceCIDR: "*", DestCIDR: "10.10.0.0/24"},
		},
	}

	applied, rejected, errs := reloader.ReloadConfig(cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rejected) != 0 {
		t.Fatalf("unexpected rejections: %v", rejected)
	}
	if len(applied) != 3 {
		t.Fatalf("expected 3 applied fields, got %d: %v", len(applied), applied)
	}

	// Verify the engine picked up the new values.
	if !engine.IsEnabled() {
		t.Error("engine should be enabled")
	}
	if engine.DefaultPolicy() != config.ACLActionDeny {
		t.Errorf("expected default_policy=deny, got %s", engine.DefaultPolicy())
	}
	rules := engine.CurrentRules()
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	// Verify broadcast was called.
	if !broadcastCalled {
		t.Error("broadcast should have been called")
	}
	if len(broadcastedRules) != 2 {
		t.Errorf("expected 2 broadcasted rules, got %d", len(broadcastedRules))
	}
}

func TestACLReloader_NilEngine(t *testing.T) {
	reloader := NewACLReloader(nil, nil)
	cfg := config.Default()
	applied, rejected, errs := reloader.ReloadConfig(cfg)
	if len(applied) != 0 || len(rejected) != 0 || len(errs) != 0 {
		t.Fatalf("expected no-ops for nil engine, got applied=%v rejected=%v errs=%v", applied, rejected, errs)
	}
}

func TestACLReloader_InvalidRule(t *testing.T) {
	engine, err := mesh.NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
	})
	if err != nil {
		t.Fatalf("NewACLEngine: %v", err)
	}

	reloader := NewACLReloader(engine, nil)

	// Config with an invalid rule (bad CIDR).
	cfg := config.Default()
	cfg.ACL = config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{Action: config.ACLActionDeny, SourceCIDR: "not-a-cidr", DestCIDR: "*"},
		},
	}

	applied, rejected, errs := reloader.ReloadConfig(cfg)
	if len(errs) == 0 {
		t.Fatal("expected error for invalid rule, got none")
	}
	if len(applied) != 0 {
		t.Errorf("expected 0 applied fields on error, got %d: %v", len(applied), applied)
	}
	_ = rejected // rejected is empty for this case
}

func TestACLReloader_FromProvider(t *testing.T) {
	// Test nil provider.
	reloader := NewACLReloaderFromProvider(nil)
	if reloader.engine != nil {
		t.Error("expected nil engine for nil provider")
	}

	// Test with a mock provider.
	engine, err := mesh.NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
	})
	if err != nil {
		t.Fatalf("NewACLEngine: %v", err)
	}

	provider := &mockACLProvider{engine: engine}
	reloader = NewACLReloaderFromProvider(provider)
	if reloader.engine != engine {
		t.Error("expected engine from provider")
	}
	if reloader.broadcast == nil {
		t.Error("expected broadcast function from provider")
	}
}

// mockACLProvider implements ACLProvider for testing.
type mockACLProvider struct {
	engine    *mesh.ACLEngine
	broadcast func(rules []string)
}

func (m *mockACLProvider) ACL() *mesh.ACLEngine { return m.engine }
func (m *mockACLProvider) BroadcastACLRules(rules []string) {
	if m.broadcast != nil {
		m.broadcast(rules)
	}
}

func TestProxyReloader(t *testing.T) {
	reloader := NewProxyReloader()
	cfg := config.Default()
	cfg.Proxy.ChunkerStrategy = "fixed-16k"
	cfg.Proxy.Circuit.IdleTimeout = 600
	cfg.Proxy.Relay.MaxCircuits = 2048
	cfg.Proxy.PathSelection.Mode = "auto"
	cfg.Proxy.SOCKS5.DialTimeoutSec = 60

	applied, rejected, errs := reloader.ReloadConfig(cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rejected) != 0 {
		t.Fatalf("unexpected rejections: %v", rejected)
	}

	// Verify that all expected fields are in the applied list.
	expectedFields := []string{
		"proxy.circuit.idle_timeout",
		"proxy.circuit.keepalive_interval",
		"proxy.circuit.nack_timeout",
		"proxy.circuit.orphan_timeout",
		"proxy.circuit.max_reassembly_window",
		"proxy.relay.jitter_min_ms",
		"proxy.relay.jitter_max_ms",
		"proxy.relay.disable_jitter",
		"proxy.relay.max_circuits",
		"proxy.relay.max_queue_depth",
		"proxy.path_selection.mode",
		"proxy.path_selection.strategy",
		"proxy.path_selection.max_relays_per_path",
		"proxy.path_selection.probe_timeout_sec",
		"proxy.path_selection.probe_concurrency",
		"proxy.path_selection.max_candidates",
		"proxy.path_selection.probe_cache_ttl_sec",
		"proxy.chunker_strategy",
		"proxy.debug_fixed_chunks",
		"proxy.exit.audit_log_dir",
		"proxy.exit.audit_retention_days",
		"proxy.socks5.dial_timeout_sec",
		"proxy.socks5.idle_timeout_sec",
		"proxy.socks5.max_connections",
	}

	appliedSet := make(map[string]bool, len(applied))
	for _, f := range applied {
		appliedSet[f] = true
	}

	for _, expected := range expectedFields {
		if !appliedSet[expected] {
			t.Errorf("expected field %q in applied list", expected)
		}
	}
}

func TestLoggingReloader_LogLevelChange(t *testing.T) {
	reloader := NewLoggingReloader()
	cfg := config.Default()
	cfg.Logging.LogLevel = "debug"

	applied, rejected, errs := reloader.ReloadConfig(cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rejected) != 0 {
		t.Fatalf("unexpected rejections: %v", rejected)
	}

	foundLogLevel := false
	for _, f := range applied {
		if f == "logging.log_level" {
			foundLogLevel = true
			break
		}
	}
	if !foundLogLevel {
		t.Error("logging.log_level should be in applied list")
	}
}

func TestLoggingReloader_WithWriter(t *testing.T) {
	// Create a temporary rotating writer.
	tmpDir := t.TempDir()
	w, err := logging.NewRotatingWriter(tmpDir+"/test.log", 1024, 3, false)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	reloader := NewLoggingReloaderWithWriter(w)
	cfg := config.Default()
	cfg.Logging.LogLevel = "warn"
	cfg.Logging.LogMaxAge = 7
	cfg.Logging.LogMaxSize = 2048
	cfg.Logging.LogMaxBackups = 10

	applied, _, errs := reloader.ReloadConfig(cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	// Verify all expected fields are in applied.
	expectedFields := []string{
		"logging.log_level",
		"logging.log_max_age",
		"logging.log_max_size",
		"logging.log_max_backups",
	}
	appliedSet := make(map[string]bool, len(applied))
	for _, f := range applied {
		appliedSet[f] = true
	}
	for _, expected := range expectedFields {
		if !appliedSet[expected] {
			t.Errorf("expected field %q in applied list", expected)
		}
	}
}
