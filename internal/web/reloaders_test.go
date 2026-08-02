package web

import (
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/webssh"
)

func TestMonitorReloader(t *testing.T) {
	// Create a reporter with initial config.
	reporter := monitor.NewReporter(monitor.ReporterConfig{
		NodeID:     "test-node",
		Hostname:   "test",
		Interval:   15,
		Port:       4191,
		Collectors: []string{"collector-1"},
	})

	reloader := NewMonitorReloader(reporter)

	// New config with updated values.
	cfg := config.Default()
	cfg.Monitoring.Interval = 30
	cfg.Monitoring.Port = 4192
	cfg.Monitoring.Collectors = []string{"collector-2", "collector-3"}

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

	// Verify the reporter picked up the new values.
	if reporter.Interval() != 30 {
		t.Errorf("expected interval 30, got %d", reporter.Interval())
	}
	if reporter.Port() != 4192 {
		t.Errorf("expected port 4192, got %d", reporter.Port())
	}
	cols := reporter.Collectors()
	if len(cols) != 2 || cols[0] != "collector-2" || cols[1] != "collector-3" {
		t.Errorf("expected [collector-2, collector-3], got %v", cols)
	}
}

func TestMonitorReloader_NilReporter(t *testing.T) {
	reloader := NewMonitorReloader(nil)
	cfg := config.Default()
	applied, rejected, errs := reloader.ReloadConfig(cfg)
	if len(applied) != 0 || len(rejected) != 0 || len(errs) != 0 {
		t.Fatalf("expected no-ops for nil reporter, got applied=%v rejected=%v errs=%v", applied, rejected, errs)
	}
}

func TestWebSSHReloader(t *testing.T) {
	hub := webssh.NewHub(nil, nil, 2222, 256, 300*time.Second, 10*time.Second)

	reloader := NewWebSSHReloader(hub)

	cfg := config.Default()
	cfg.WebSSH.Port = 2223
	cfg.WebSSH.MaxSessions = 512
	cfg.WebSSH.ReadDeadline = 600
	cfg.WebSSH.WriteDeadline = 15

	applied, rejected, errs := reloader.ReloadConfig(cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rejected) != 0 {
		t.Fatalf("unexpected rejections: %v", rejected)
	}
	if len(applied) != 4 {
		t.Fatalf("expected 4 applied fields, got %d: %v", len(applied), applied)
	}

	// The Hub doesn't expose getters, but we can verify no panic occurred
	// and the reloader reported success.
}

func TestWebSSHReloader_NilHub(t *testing.T) {
	reloader := NewWebSSHReloader(nil)
	cfg := config.Default()
	applied, rejected, errs := reloader.ReloadConfig(cfg)
	if len(applied) != 0 || len(rejected) != 0 || len(errs) != 0 {
		t.Fatalf("expected no-ops for nil hub, got applied=%v rejected=%v errs=%v", applied, rejected, errs)
	}
}

func TestLoggingReloader(t *testing.T) {
	reloader := NewLoggingReloader()
	cfg := config.Default()
	applied, rejected, errs := reloader.ReloadConfig(cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rejected) != 0 {
		t.Fatalf("unexpected rejections: %v", rejected)
	}
	// LoggingReloader returns nil applied (it's a no-op ack).
	if len(applied) != 0 {
		t.Fatalf("expected 0 applied fields, got %d: %v", len(applied), applied)
	}
}

func TestJoinSectionInTierMap(t *testing.T) {
	joinFields := []string{
		"join.enabled",
		"join.listen_addr",
		"join.secret",
		"join.tls_cert_file",
		"join.tls_key_file",
		"join.token_lifetime",
		"join.server_url",
		"join.token",
		"join.insecure_skip_tls_verify",
	}
	for _, f := range joinFields {
		if _, ok := tierMap[f]; !ok {
			t.Errorf("join field %q not in tierMap", f)
		}
	}
}

func TestSOCKS5SectionInTierMap(t *testing.T) {
	socks5Fields := []string{
		"proxy.socks5.enabled",
		"proxy.socks5.allowed_ports",
		"proxy.socks5.allow_all_ports",
		"proxy.socks5.destination_filter",
		"proxy.socks5.dial_timeout_sec",
		"proxy.socks5.idle_timeout_sec",
		"proxy.socks5.max_connections",
	}
	for _, f := range socks5Fields {
		if _, ok := tierMap[f]; !ok {
			t.Errorf("socks5 field %q not in tierMap", f)
		}
	}
}

func TestP2PAdvertiseEndpointsInTierMap(t *testing.T) {
	fields := []string{
		"p2p.advertise_endpoints",
		"p2p.peer_cache_path",
	}
	for _, f := range fields {
		if _, ok := tierMap[f]; !ok {
			t.Errorf("p2p field %q not in tierMap", f)
		}
	}
}

func TestJoinInValidSections(t *testing.T) {
	if !validSections["join"] {
		t.Error("'join' not in validSections")
	}
}

func TestJoinFieldsKnown(t *testing.T) {
	joinFields := []string{
		"join.enabled",
		"join.listen_addr",
		"join.secret",
		"join.token_lifetime",
		"join.server_url",
		"join.token",
	}
	for _, f := range joinFields {
		if !isKnownField(f) {
			t.Errorf("join field %q not recognized as known field", f)
		}
	}
}

func TestSOCKS5FieldsKnown(t *testing.T) {
	socks5Fields := []string{
		"proxy.socks5.enabled",
		"proxy.socks5.dial_timeout_sec",
		"proxy.socks5.idle_timeout_sec",
		"proxy.socks5.max_connections",
	}
	for _, f := range socks5Fields {
		if !isKnownField(f) {
			t.Errorf("socks5 field %q not recognized as known field", f)
		}
	}
}

func TestJoinMaskedFields(t *testing.T) {
	maskedJoinFields := []string{
		"join.secret",
		"join.tls_key_file",
		"join.token",
	}
	for _, f := range maskedJoinFields {
		if !isMasked(f) {
			t.Errorf("join field %q should be masked", f)
		}
	}
}

func TestSOCKS5StepUpFields(t *testing.T) {
	stepUpSocks5Fields := []string{
		"proxy.socks5.allowed_ports",
		"proxy.socks5.allow_all_ports",
		"proxy.socks5.destination_filter",
	}
	for _, f := range stepUpSocks5Fields {
		if !isStepUp(f) {
			t.Errorf("socks5 field %q should require step-up", f)
		}
	}
}

func TestPeerCachePathReadOnly(t *testing.T) {
	if !isReadOnly("p2p.peer_cache_path") {
		t.Error("p2p.peer_cache_path should be read-only")
	}
}
