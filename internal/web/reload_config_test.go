package web

import (
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

// TestReloadConfig_NilConfigAPI verifies that ReloadConfig is safe to call
// on a server that has no configAPI (e.g. a minimal server without config
// management). It should return nil without panicking.
func TestReloadConfig_NilConfigAPI(t *testing.T) {
	s := &Server{}
	// s.configAPI is nil — ReloadConfig should be a no-op.
	err := s.ReloadConfig(config.Default())
	if err != nil {
		t.Errorf("expected nil error for nil configAPI, got: %v", err)
	}
}

// TestReloadConfig_WithConfigAPI verifies that ReloadConfig updates the
// in-memory config pointer when a configAPI is present.
func TestReloadConfig_WithConfigAPI(t *testing.T) {
	s := &Server{
		configAPI: NewConfigAPIManager(""),
	}

	// Set initial config.
	initialCfg := &config.Config{}
	initialCfg.Node.Hostname = "initial"
	configMu.Lock()
	s.cfg = initialCfg
	configMu.Unlock()

	// Reload with new config.
	newCfg := &config.Config{}
	newCfg.Node.Hostname = "reloaded"

	err := s.ReloadConfig(newCfg)
	if err != nil {
		t.Fatalf("ReloadConfig returned error: %v", err)
	}

	// Verify the in-memory config was updated.
	configMu.RLock()
	currentCfg := s.cfg
	configMu.RUnlock()

	if currentCfg.Node.Hostname != "reloaded" {
		t.Errorf("expected hostname 'reloaded' after reload, got '%s'",
			currentCfg.Node.Hostname)
	}
}

// TestReloadConfig_WithReloaders verifies that ReloadConfig triggers
// registered reloaders with the new config.
func TestReloadConfig_WithReloaders(t *testing.T) {
	s := &Server{
		configAPI: NewConfigAPIManager(""),
	}

	// Track if the reloader was called.
	reloaded := false
	mockReloader := &mockConfigReloader{
		reloadFn: func(cfg *config.Config) ([]string, []string, []error) {
			reloaded = true
			return []string{"monitoring.interval"}, nil, nil
		},
	}
	s.RegisterReloader(mockReloader)

	// Reload — but the reloader only runs if there are dirty fields.
	// We need to mark a field as dirty first.
	s.configAPI.reloaderRegistry.MarkDirty("monitoring.interval")

	newCfg := config.Default()
	newCfg.Monitoring.Interval = 42

	err := s.ReloadConfig(newCfg)
	if err != nil {
		t.Fatalf("ReloadConfig returned error: %v", err)
	}

	if !reloaded {
		t.Error("expected reloader to be called after reload")
	}
}

// mockConfigReloader implements ConfigReloader for testing.
type mockConfigReloader struct {
	reloadFn func(cfg *config.Config) ([]string, []string, []error)
}

func (m *mockConfigReloader) ReloadConfig(cfg *config.Config) ([]string, []string, []error) {
	if m.reloadFn != nil {
		return m.reloadFn(cfg)
	}
	return nil, nil, nil
}
