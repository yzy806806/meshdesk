package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yzy806806/meshdesk/internal/xray"
)

// mockXrayManager is a test double for the XrayManager interface.
type mockXrayManager struct {
	inbounds []*xray.InboundConfig
}

func (m *mockXrayManager) AddInbound(cfg *xray.InboundConfig) error {
	m.inbounds = append(m.inbounds, cfg)
	return nil
}

func (m *mockXrayManager) RemoveInbound(tag string) error {
	for i, ib := range m.inbounds {
		if ib.Tag == tag {
			m.inbounds = append(m.inbounds[:i], m.inbounds[i+1:]...)
			return nil
		}
	}
	return xray.ErrNotFound
}

func (m *mockXrayManager) GetInbound(tag string) (*xray.InboundConfig, bool) {
	for _, ib := range m.inbounds {
		if ib.Tag == tag {
			return ib, true
		}
	}
	return nil, false
}

func (m *mockXrayManager) ListInbounds() []*xray.InboundConfig {
	return m.inbounds
}

func (m *mockXrayManager) GenerateConfig() (*xray.XrayConfig, error) {
	return &xray.XrayConfig{}, nil
}

func (m *mockXrayManager) WriteConfig() error             { return nil }
func (m *mockXrayManager) Reload() error                  { return nil }
func (m *mockXrayManager) Start() error                   { return nil }
func (m *mockXrayManager) Stop() error                    { return nil }
func (m *mockXrayManager) Status() xray.ProcessStatus     { return xray.ProcessStatus{} }
func (m *mockXrayManager) Logs() []xray.LogEntry          { return nil }
func (m *mockXrayManager) TailLogs(n int) []xray.LogEntry { return nil }
func (m *mockXrayManager) ConfigPath() string             { return "/tmp/test-config.json" }
func (m *mockXrayManager) BinaryPath() string             { return "/usr/bin/xray" }

// TestProxyNodesPageNotConfigured verifies that the proxy nodes page
// renders correctly when the xray manager is not configured (nil).
// The page should show the "not configured" panel instead of the
// inbound management UI.
func TestProxyNodesPageNotConfigured(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/proxy-nodes", nil)
	rr := httptest.NewRecorder()
	srv.handleProxyNodesPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if want := "xray-core Not Configured"; !contains(body, want) {
		t.Errorf("expected %q in body when xray is nil", want)
	}
	if want := "proxy-unavailable"; !contains(body, want) {
		t.Errorf("expected %q CSS class in body", want)
	}
}

// TestProxyNodesPageConfigured verifies that the proxy nodes page
// renders the inbound management UI when the xray manager is available.
func TestProxyNodesPageConfigured(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{}

	req := httptest.NewRequest(http.MethodGet, "/proxy-nodes", nil)
	rr := httptest.NewRecorder()
	srv.handleProxyNodesPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	// Should show the status bar and inbound table
	if want := "xray-status-bar"; !contains(body, want) {
		t.Errorf("expected %q in body when xray is configured", want)
	}
	if want := "inbound-table"; !contains(body, want) {
		t.Errorf("expected %q in body", want)
	}
	if want := "Create New Inbound"; !contains(body, want) {
		t.Errorf("expected %q in body", want)
	}
	// Should NOT show the unavailable panel
	if notWant := "proxy-unavailable"; contains(body, notWant) {
		t.Errorf("should not show %q when xray is configured", notWant)
	}
}

// TestProxyNodesNavActive verifies the navigation bar includes the
// Proxy link and marks it active on the proxy_nodes page.
func TestProxyNodesNavActive(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{}

	req := httptest.NewRequest(http.MethodGet, "/proxy-nodes", nil)
	rr := httptest.NewRecorder()
	srv.handleProxyNodesPage(rr, req)

	body := rr.Body.String()
	if want := `/proxy-nodes`; !contains(body, want) {
		t.Errorf("expected nav link %q in body", want)
	}
	if want := `class="active"`; !contains(body, want) {
		t.Errorf("expected active nav class in body")
	}
}

// contains is a simple substring check.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
