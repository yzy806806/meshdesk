package proxy

import (
	"strings"
	"testing"
)

// TestCFTunnelConfigYAMLGeneration verifies that the generated config
// YAML contains all required fields and is well-formed.
func TestCFTunnelConfigYAMLGeneration(t *testing.T) {
	cfg := CFTunnelConfig{
		TunnelID:        "test-tunnel-uuid",
		CredentialsFile: "/etc/meshdesk/tunnel-creds.json",
		OriginServer:    "127.0.0.1:8388",
		Region:          "us",
		ReconnectRetries: 5,
		GracePeriodSec:  30,
		LogLevel:        "warn",
		MetricsAddr:     "127.0.0.1:36500",
		IngressRules: []CFIngressRule{
			{
				Hostname: "proxy.example.com",
				Service:  "ws://127.0.0.1:8388",
				OriginRequest: &CFOriginRequest{
					ConnectTimeoutSec:   30,
					TLSTimeoutSec:       10,
					KeepAliveTimeoutSec: 15,
				},
			},
		},
	}

	mgr := NewCFTunnelManager(cfg)
	yaml := mgr.GenerateConfigYAML()

	// Verify required fields are present.
	checks := map[string]bool{
		"tunnel: test-tunnel-uuid":                true,
		"credentials-file: /etc/meshdesk/tunnel-creds.json": true,
		"region: us":                               true,
		"retries: 5":                               true,
		"grace-period: 30s":                        true,
		"loglevel: warn":                           true,
		"metrics: 127.0.0.1:36500":                 true,
		"hostname: proxy.example.com":              true,
		"service: ws://127.0.0.1:8388":             true,
		"connectTimeout: 30s":                      true,
		"tlsTimeout: 10s":                          true,
		"keepAliveTimeout: 15s":                    true,
		"http_status:404":                          true, // catch-all rule
	}

	for check, _ := range checks {
		if !strings.Contains(yaml, check) {
			t.Errorf("config YAML missing: %q\nFull config:\n%s", check, yaml)
		}
	}
}

// TestCFTunnelConfigDefaults verifies that default values are applied.
func TestCFTunnelConfigDefaults(t *testing.T) {
	cfg := CFTunnelConfig{
		TunnelID:        "test-tunnel",
		CredentialsFile: "/tmp/creds.json",
		IngressRules: []CFIngressRule{
			{Hostname: "test.example.com", Service: "ws://127.0.0.1:8388"},
		},
	}

	mgr := NewCFTunnelManager(cfg)

	if mgr.cfg.OriginServer == "" {
		t.Error("expected default OriginServer")
	}
	if mgr.cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want %q", mgr.cfg.LogLevel, "warn")
	}
	if mgr.cfg.MetricsAddr != "127.0.0.1:36500" {
		t.Errorf("MetricsAddr = %q, want %q", mgr.cfg.MetricsAddr, "127.0.0.1:36500")
	}
	if mgr.cfg.ReconnectRetries != 5 {
		t.Errorf("ReconnectRetries = %d, want 5", mgr.cfg.ReconnectRetries)
	}
	if mgr.cfg.GracePeriodSec != 30 {
		t.Errorf("GracePeriodSec = %d, want 30", mgr.cfg.GracePeriodSec)
	}
}

// TestCFTunnelValidate verifies config validation.
func TestCFTunnelValidate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cfg := CFTunnelConfig{
			TunnelID:        "test-tunnel",
			CredentialsFile: "/tmp/creds.json",
			IngressRules: []CFIngressRule{
				{Hostname: "test.example.com", Service: "ws://127.0.0.1:8388"},
			},
		}
		mgr := NewCFTunnelManager(cfg)
		if err := mgr.Validate(); err != nil {
			t.Errorf("valid config should not error: %v", err)
		}
	})

	t.Run("missing_tunnel_id", func(t *testing.T) {
		cfg := CFTunnelConfig{
			CredentialsFile: "/tmp/creds.json",
			IngressRules:    []CFIngressRule{{Service: "ws://127.0.0.1:8388"}},
		}
		mgr := NewCFTunnelManager(cfg)
		if err := mgr.Validate(); err == nil {
			t.Error("expected error for missing tunnel_id")
		}
	})

	t.Run("missing_credentials", func(t *testing.T) {
		cfg := CFTunnelConfig{
			TunnelID:     "test-tunnel",
			IngressRules: []CFIngressRule{{Service: "ws://127.0.0.1:8388"}},
		}
		mgr := NewCFTunnelManager(cfg)
		if err := mgr.Validate(); err == nil {
			t.Error("expected error for missing credentials_file")
		}
	})

	t.Run("no_ingress_rules", func(t *testing.T) {
		cfg := CFTunnelConfig{
			TunnelID:        "test-tunnel",
			CredentialsFile: "/tmp/creds.json",
		}
		mgr := NewCFTunnelManager(cfg)
		if err := mgr.Validate(); err == nil {
			t.Error("expected error for no ingress rules")
		}
	})
}

// TestNewSSTunnelConfig verifies the SS tunnel config convenience function.
func TestNewSSTunnelConfig(t *testing.T) {
	cfg := NewSSTunnelConfig(
		"tunnel-uuid",
		"/etc/meshdesk/creds.json",
		"proxy.example.com",
		"127.0.0.1:8388",
	)

	if cfg.TunnelID != "tunnel-uuid" {
		t.Errorf("TunnelID = %q, want %q", cfg.TunnelID, "tunnel-uuid")
	}
	if cfg.CredentialsFile != "/etc/meshdesk/creds.json" {
		t.Errorf("CredentialsFile = %q", cfg.CredentialsFile)
	}
	if len(cfg.IngressRules) < 2 {
		t.Errorf("expected at least 2 ingress rules (SS + catch-all), got %d", len(cfg.IngressRules))
	}

	// First rule should be the SS WebSocket rule.
	rule := cfg.IngressRules[0]
	if rule.Hostname != "proxy.example.com" {
		t.Errorf("hostname = %q, want %q", rule.Hostname, "proxy.example.com")
	}
	if !strings.HasPrefix(rule.Service, "ws://") {
		t.Errorf("service should use ws:// scheme, got %q", rule.Service)
	}
	if rule.OriginRequest == nil {
		t.Error("OriginRequest should not be nil for SS tunnel")
	}
	if rule.OriginRequest.ConnectTimeoutSec != 30 {
		t.Errorf("ConnectTimeoutSec = %d, want 30", rule.OriginRequest.ConnectTimeoutSec)
	}

	// Last rule should be the catch-all (no hostname).
	last := cfg.IngressRules[len(cfg.IngressRules)-1]
	if last.Hostname != "" {
		t.Error("last ingress rule should be catch-all (no hostname)")
	}
}

// TestNewWebUITunnelConfig verifies the Web UI tunnel config.
func TestNewWebUITunnelConfig(t *testing.T) {
	cfg := NewWebUITunnelConfig(
		"tunnel-uuid",
		"/etc/meshdesk/creds.json",
		"dashboard.example.com",
		"127.0.0.1:8080",
	)

	if len(cfg.IngressRules) < 2 {
		t.Errorf("expected at least 2 ingress rules, got %d", len(cfg.IngressRules))
	}

	rule := cfg.IngressRules[0]
	if rule.Hostname != "dashboard.example.com" {
		t.Errorf("hostname = %q, want %q", rule.Hostname, "dashboard.example.com")
	}
	// Web UI uses HTTP, not WebSocket.
	if !strings.HasPrefix(rule.Service, "http://") {
		t.Errorf("service should use http:// scheme for Web UI, got %q", rule.Service)
	}
}

// TestCFTunnelSystemdUnit verifies the systemd unit file generation.
func TestCFTunnelSystemdUnit(t *testing.T) {
	cfg := CFTunnelConfig{
		TunnelID: "test-tunnel-uuid",
	}
	mgr := NewCFTunnelManager(cfg)

	unit := mgr.GenerateSystemdUnit()

	checks := []string{
		"[Unit]",
		"Description=MeshDesk Cloudflare Tunnel",
		"[Service]",
		"Type=simple",
		"cloudflared",
		"tunnel",
		"test-tunnel-uuid",
		"Restart=on-failure",
		"[Install]",
		"WantedBy=multi-user.target",
	}

	for _, check := range checks {
		if !strings.Contains(unit, check) {
			t.Errorf("systemd unit missing: %q\nFull unit:\n%s", check, unit)
		}
	}
}

// TestCFTunnelStatus verifies the initial status.
func TestCFTunnelStatus(t *testing.T) {
	cfg := CFTunnelConfig{
		TunnelID:        "test-tunnel",
		CredentialsFile: "/tmp/creds.json",
		IngressRules: []CFIngressRule{
			{Service: "ws://127.0.0.1:8388"},
		},
	}
	mgr := NewCFTunnelManager(cfg)

	status := mgr.Status()
	if status.Running {
		t.Error("tunnel should not be running initially")
	}
	if status.Healthy {
		t.Error("tunnel should not be healthy initially")
	}
	if status.PID != 0 {
		t.Errorf("PID should be 0 initially, got %d", status.PID)
	}
}

// TestEnsureLocalListener verifies the local listener check.
func TestEnsureLocalListener(t *testing.T) {
	// Test with a non-existent address.
	err := EnsureLocalListener("127.0.0.1:59999")
	if err == nil {
		t.Error("expected error for unreachable listener")
	}
}

// TestParseMetricsJSON verifies JSON metrics parsing.
func TestParseMetricsJSON(t *testing.T) {
	jsonData := `{"connected": true, "connectionCount": 3, "totalRequests": 42, "requestErrors": 1}`

	metrics, err := ParseMetricsJSON([]byte(jsonData))
	if err != nil {
		t.Fatal(err)
	}

	if !metrics.Connected {
		t.Error("Connected should be true")
	}
	if metrics.ConnectionCount != 3 {
		t.Errorf("ConnectionCount = %d, want 3", metrics.ConnectionCount)
	}
	if metrics.TotalRequests != 42 {
		t.Errorf("TotalRequests = %d, want 42", metrics.TotalRequests)
	}
	if metrics.RequestErrors != 1 {
		t.Errorf("RequestErrors = %d, want 1", metrics.RequestErrors)
	}
}

// TestParseMetricsJSONInvalid verifies error on invalid JSON.
func TestParseMetricsJSONInvalid(t *testing.T) {
	_, err := ParseMetricsJSON([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// TestCFTunnelConfigYAMLWithMultipleIngress verifies config generation
// with multiple ingress rules.
func TestCFTunnelConfigYAMLWithMultipleIngress(t *testing.T) {
	cfg := CFTunnelConfig{
		TunnelID:        "multi-tunnel",
		CredentialsFile: "/tmp/creds.json",
		IngressRules: []CFIngressRule{
			{
				Hostname: "proxy.example.com",
				Service:  "ws://127.0.0.1:8388",
			},
			{
				Hostname: "dashboard.example.com",
				Service:  "http://127.0.0.1:8080",
				OriginRequest: &CFOriginRequest{
					NoTLSVerify: true,
				},
			},
			{
				// Catch-all
				Service: "http_status:404",
			},
		},
	}

	mgr := NewCFTunnelManager(cfg)
	yaml := mgr.GenerateConfigYAML()

	// Both hostnames should be present.
	if !strings.Contains(yaml, "proxy.example.com") {
		t.Error("missing proxy.example.com hostname")
	}
	if !strings.Contains(yaml, "dashboard.example.com") {
		t.Error("missing dashboard.example.com hostname")
	}
	// noTLSVerify should be present.
	if !strings.Contains(yaml, "noTLSVerify: true") {
		t.Error("missing noTLSVerify setting")
	}
}
