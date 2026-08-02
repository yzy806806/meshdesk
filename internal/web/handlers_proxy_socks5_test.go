package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/monitor"
)

// mockSOCKS5StatusProvider is a test double for SOCKS5StatusProvider.
type mockSOCKS5StatusProvider struct {
	handlerActive   bool
	exitHandlerActive bool
	activeConns      int64
}

func (m *mockSOCKS5StatusProvider) SOCKS5HandlerActive() bool {
	return m.handlerActive
}

func (m *mockSOCKS5StatusProvider) SOCKS5ExitHandlerActive() bool {
	return m.exitHandlerActive
}

func (m *mockSOCKS5StatusProvider) SOCKS5ActiveConnections() int64 {
	return m.activeConns
}

// newSOCKS5TestServer creates a web server suitable for testing the
// /api/proxy/socks5/status handler. It uses no web users (first-run
// mode) so requests don't need session cookies.
func newSOCKS5TestServer(t *testing.T, provider SOCKS5StatusProvider) *Server {
	t.Helper()
	cfg := config.Default()
	srv, err := New(Deps{
		Config:              cfg,
		MonitorStore:        monitor.NewStore(),
		SOCKS5StatusProvider: provider,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return srv
}

// --- Test: basic status response structure ---

func TestProxySocks5Status_BasicResponse(t *testing.T) {
	srv := newSOCKS5TestServer(t, &mockSOCKS5StatusProvider{
		handlerActive:    true,
		exitHandlerActive: false,
		activeConns:       3,
	})

	req := httptest.NewRequest("GET", "/api/proxy/socks5/status", nil)
	rr := httptest.NewRecorder()

	srv.handleProxySocks5Status(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp SOCKS5ProxyStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal failed: %v\nBody: %s", err, rr.Body.String())
	}

	if !resp.SOCKS5Enabled {
		t.Error("Expected socks5_enabled=true")
	}
	if resp.SOCKS5ExitEnabled {
		t.Error("Expected socks5_exit_enabled=false")
	}
	if resp.ActiveConnections != 3 {
		t.Errorf("Expected active_connections=3, got %d", resp.ActiveConnections)
	}
}

// --- Test: default proxy port is 52888 ---

func TestProxySocks5Status_DefaultPort(t *testing.T) {
	srv := newSOCKS5TestServer(t, &mockSOCKS5StatusProvider{})

	req := httptest.NewRequest("GET", "/api/proxy/socks5/status", nil)
	rr := httptest.NewRecorder()

	srv.handleProxySocks5Status(rr, req)

	var resp SOCKS5ProxyStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if resp.ProxyPort != 52888 {
		t.Errorf("Expected default proxy_port=52888, got %d", resp.ProxyPort)
	}
}

// --- Test: custom reality listen port is reflected ---

func TestProxySocks5Status_CustomPort(t *testing.T) {
	cfg := config.Default()
	cfg.Reality.Enabled = true
	cfg.Reality.ListenPort = 12345

	srv, err := New(Deps{
		Config:               cfg,
		MonitorStore:         monitor.NewStore(),
		SOCKS5StatusProvider: &mockSOCKS5StatusProvider{},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/proxy/socks5/status", nil)
	rr := httptest.NewRecorder()

	srv.handleProxySocks5Status(rr, req)

	var resp SOCKS5ProxyStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if resp.ProxyPort != 12345 {
		t.Errorf("Expected proxy_port=12345, got %d", resp.ProxyPort)
	}
	if !resp.RealityEnabled {
		t.Error("Expected reality_enabled=true")
	}
}

// --- Test: SOCKS5 config fields are populated from config ---

func TestProxySocks5Status_ConfigFields(t *testing.T) {
	cfg := config.Default()
	cfg.Proxy.SOCKS5.Enabled = true
	cfg.Proxy.SOCKS5.MaxConnections = 128
	cfg.Proxy.SOCKS5.DialTimeoutSec = 15
	cfg.Proxy.SOCKS5.IdleTimeoutSec = 120
	cfg.Proxy.SOCKS5.AllowAllPorts = true
	cfg.Proxy.SOCKS5.RequireMeshPeer = true
	cfg.Proxy.SOCKS5.AllowedPorts = []int{80, 443, 8080}
	cfg.Proxy.SOCKS5.DestinationFilter = []string{"10.0.0.0/8"}

	srv, err := New(Deps{
		Config:               cfg,
		MonitorStore:         monitor.NewStore(),
		SOCKS5StatusProvider: &mockSOCKS5StatusProvider{},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/proxy/socks5/status", nil)
	rr := httptest.NewRecorder()

	srv.handleProxySocks5Status(rr, req)

	var resp SOCKS5ProxyStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !resp.SOCKS5Config.Enabled {
		t.Error("Expected socks5_config.enabled=true")
	}
	if resp.SOCKS5Config.MaxConnections != 128 {
		t.Errorf("Expected max_connections=128, got %d", resp.SOCKS5Config.MaxConnections)
	}
	if resp.SOCKS5Config.DialTimeoutSec != 15 {
		t.Errorf("Expected dial_timeout_sec=15, got %d", resp.SOCKS5Config.DialTimeoutSec)
	}
	if resp.SOCKS5Config.IdleTimeoutSec != 120 {
		t.Errorf("Expected idle_timeout_sec=120, got %d", resp.SOCKS5Config.IdleTimeoutSec)
	}
	if !resp.SOCKS5Config.AllowAllPorts {
		t.Error("Expected allow_all_ports=true")
	}
	if !resp.SOCKS5Config.RequireMeshPeer {
		t.Error("Expected require_mesh_peer=true")
	}
	if len(resp.SOCKS5Config.AllowedPorts) != 3 {
		t.Errorf("Expected 3 allowed ports, got %d", len(resp.SOCKS5Config.AllowedPorts))
	}
	if len(resp.SOCKS5Config.DestinationFilter) != 1 {
		t.Errorf("Expected 1 destination filter, got %d", len(resp.SOCKS5Config.DestinationFilter))
	}
}

// --- Test: exit config fields are populated ---

func TestProxySocks5Status_ExitConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Proxy.Exit.AllowAllPorts = true
	cfg.Proxy.Exit.AllowedPorts = []int{80, 443}
	cfg.Proxy.Exit.AuditRetentionDays = 30
	cfg.Proxy.Exit.DestinationFilter = []string{"0.0.0.0/0"}

	srv, err := New(Deps{
		Config:               cfg,
		MonitorStore:         monitor.NewStore(),
		SOCKS5StatusProvider: &mockSOCKS5StatusProvider{},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/proxy/socks5/status", nil)
	rr := httptest.NewRecorder()

	srv.handleProxySocks5Status(rr, req)

	var resp SOCKS5ProxyStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !resp.ExitConfig.AllowAllPorts {
		t.Error("Expected exit_config.allow_all_ports=true")
	}
	if resp.ExitConfig.AuditRetentionDays != 30 {
		t.Errorf("Expected audit_retention_days=30, got %d", resp.ExitConfig.AuditRetentionDays)
	}
	if len(resp.ExitConfig.AllowedPorts) != 2 {
		t.Errorf("Expected 2 exit allowed ports, got %d", len(resp.ExitConfig.AllowedPorts))
	}
}

// --- Test: method not allowed for POST ---

func TestProxySocks5Status_MethodNotAllowed(t *testing.T) {
	srv := newSOCKS5TestServer(t, &mockSOCKS5StatusProvider{})

	req := httptest.NewRequest("POST", "/api/proxy/socks5/status", nil)
	rr := httptest.NewRecorder()

	srv.handleProxySocks5Status(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Expected 405, got %d", rr.Code)
	}
}

// --- Test: nil provider returns zero values ---

func TestProxySocks5Status_NilProvider(t *testing.T) {
	cfg := config.Default()
	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: monitor.NewStore(),
		// SOCKS5StatusProvider intentionally nil
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/proxy/socks5/status", nil)
	rr := httptest.NewRecorder()

	srv.handleProxySocks5Status(rr, req)

	var resp SOCKS5ProxyStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if resp.SOCKS5Enabled {
		t.Error("Expected socks5_enabled=false with nil provider")
	}
	if resp.SOCKS5ExitEnabled {
		t.Error("Expected socks5_exit_enabled=false with nil provider")
	}
	if resp.ActiveConnections != 0 {
		t.Errorf("Expected active_connections=0, got %d", resp.ActiveConnections)
	}
}

// --- Test: path selection mode is reflected ---

func TestProxySocks5Status_PathMode(t *testing.T) {
	cfg := config.Default()
	cfg.Proxy.PathSelection.Mode = "auto"
	cfg.Proxy.ExitAddr = "10.10.0.5:8388"

	srv, err := New(Deps{
		Config:               cfg,
		MonitorStore:         monitor.NewStore(),
		SOCKS5StatusProvider: &mockSOCKS5StatusProvider{},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/proxy/socks5/status", nil)
	rr := httptest.NewRecorder()

	srv.handleProxySocks5Status(rr, req)

	var resp SOCKS5ProxyStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if resp.PathMode != "auto" {
		t.Errorf("Expected path_mode=auto, got %q", resp.PathMode)
	}
	if resp.ExitAddr != "10.10.0.5:8388" {
		t.Errorf("Expected exit_addr=10.10.0.5:8388, got %q", resp.ExitAddr)
	}
}
