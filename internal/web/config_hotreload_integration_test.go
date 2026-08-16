package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
)

// ============================================================================
// Integration Test: Config Hot-Reload Validation
// ============================================================================
//
// This test suite validates the config hot-reload lifecycle:
//
// 1. Edit a hot-reload field via the API (PUT /api/config)
// 2. Verify the live in-memory config is updated WITHOUT a restart
// 3. Verify the config file on disk is updated atomically
// 4. Verify POST /api/config/reload triggers the reloader and clears dirty state
// 5. Edit a restart-required field and verify it's correctly flagged
// 6. Verify restart-required fields are NOT hot-reloaded (pending_restart = true)
// 7. Verify the full cycle: edit → reload → verify applied → verify clean

// --- Test: Hot-Reload Field Lifecycle ---

func TestIntegration_ConfigHotReload_Lifecycle(t *testing.T) {
	srv, configPath, sessionToken := newConfigTestServerWithStepUp(t)

	// Register a mock reloader to track reload invocations.
	mock := &mockReloader{
		appliedFields: []string{"monitoring.interval"},
	}
	srv.configAPI.reloaderRegistry.Register(mock)

	t.Run("Step1_EditHotReloadField_LiveConfigUpdatedNoRestart", func(t *testing.T) {
		// Record original value.
		configMu.RLock()
		originalInterval := srv.cfg.Monitoring.Interval
		configMu.RUnlock()

		// Edit a hot-reload field via PUT. Use a value DIFFERENT from the default (15).
		body := `{"monitoring":{"interval":42}}`
		req := configRequestWithAuth("PUT", "/api/config", body, sessionToken)
		rr := httptest.NewRecorder()
		srv.handleConfigPut(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("PUT status = %d, want %d, body: %s",
				rr.Code, http.StatusOK, rr.Body.String())
		}

		var result ConfigPutResult
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}

		// Verify the result indicates the field was applied (not restart-required).
		if !result.OK {
			t.Error("result.ok = false, want true")
		}
		foundApplied := false
		for _, f := range result.Applied {
			if f == "monitoring.interval" {
				foundApplied = true
				break
			}
		}
		if !foundApplied {
			t.Error("monitoring.interval should be in 'applied' list (hot-reload)")
		}

		// Verify the live in-memory config was updated WITHOUT restart.
		configMu.RLock()
		currentInterval := srv.cfg.Monitoring.Interval
		configMu.RUnlock()

		if currentInterval != 42 {
			t.Errorf("live config monitoring.interval = %d, want 42 (updated without restart)",
				currentInterval)
		}
		if currentInterval == originalInterval {
			t.Error("live config was not updated — value is still the original")
		}

		// Verify pending_restart is NOT set for hot-reload fields.
		if result.PendingRestart {
			t.Error("pending_restart should be false for hot-reload fields")
		}

		// Verify the dirty tracking knows about the change.
		if !srv.configAPI.reloaderRegistry.HasPendingReload() {
			t.Error("registry should have pending reload after hot-reload field edit")
		}
	})

	t.Run("Step2_ConfigFileWrittenToDisk", func(t *testing.T) {
		// Re-read the config from disk to verify atomic write.
		diskCfg, err := config.Load(configPath)
		if err != nil {
			t.Fatalf("Load from disk: %v", err)
		}
		if diskCfg.Monitoring.Interval != 42 {
			t.Errorf("disk config monitoring.interval = %d, want 42 (atomic write)",
				diskCfg.Monitoring.Interval)
		}
	})

	t.Run("Step3_ReloadTriggersReloaderAndClearsDirty", func(t *testing.T) {
		// POST /api/config/reload should trigger all registered reloaders.
		req := configRequestWithAuth("POST", "/api/config/reload", "", sessionToken)
		rr := httptest.NewRecorder()
		srv.handleConfigReload(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("reload status = %d, want %d", rr.Code, http.StatusOK)
		}

		var result ReloadResult
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}

		if !result.OK {
			t.Error("reload result.ok = false, want true")
		}
		if len(result.Applied) == 0 {
			t.Error("reload result.applied should not be empty")
		}

		// Verify the mock reloader was called.
		if !mock.called {
			t.Error("mock reloader was not called during reload")
		}

		// Verify dirty state is cleared after reload.
		if srv.configAPI.reloaderRegistry.HasPendingReload() {
			t.Error("registry should not have pending reload after successful reload")
		}
	})

	t.Run("Step4_ReloadWithNoChangesPending_IsNoOp", func(t *testing.T) {
		// Wait for rate-limit to expire.
		time.Sleep(6 * time.Second)

		req := configRequestWithAuth("POST", "/api/config/reload", "", sessionToken)
		rr := httptest.NewRecorder()
		srv.handleConfigReload(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("reload status = %d, want %d", rr.Code, http.StatusOK)
		}

		var result ReloadResult
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}

		// Should indicate no changes pending.
		if len(result.Applied) > 0 {
			t.Error("applied should be empty when no changes pending")
		}
		if result.Message == "" {
			t.Error("message should indicate no changes pending")
		}
	})
}

// --- Test: Restart-Required Field Validation ---

func TestIntegration_ConfigRestartRequired_Fields(t *testing.T) {
	srv, _, sessionToken := newConfigTestServerWithStepUp(t)

	t.Run("Step1_EditRestartRequiredField_FlaggedCorrectly", func(t *testing.T) {
		// mesh.port is a restart-required field.
		body := `{"mesh":{"port":51821,"gossip_port":7946}}`
		req := configRequestWithAuth("PUT", "/api/config", body, sessionToken)
		rr := httptest.NewRecorder()
		srv.handleConfigPut(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("PUT status = %d, want %d, body: %s",
				rr.Code, http.StatusOK, rr.Body.String())
		}

		var result ConfigPutResult
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}

		// The restart-required field should be in 'requires_restart', not 'applied'.
		if len(result.RequiresRestart) == 0 {
			t.Fatal("requires_restart list should not be empty for mesh.port")
		}
		foundRestartField := false
		for _, f := range result.RequiresRestart {
			if f == "mesh.port" {
				foundRestartField = true
				break
			}
		}
		if !foundRestartField {
			t.Error("mesh.port should be in requires_restart list")
		}

		// pending_restart should be true.
		if !result.PendingRestart {
			t.Error("pending_restart should be true after editing restart-required field")
		}

		// Verify via the registry.
		if !srv.configAPI.reloaderRegistry.HasPendingRestart() {
			t.Error("registry should have pending restart")
		}
	})

	t.Run("Step2_ReloadDoesNotClearRestartDirty", func(t *testing.T) {
		// Wait for rate limit.
		time.Sleep(6 * time.Second)

		// POST /api/config/reload — should NOT clear restart dirty entries.
		req := configRequestWithAuth("POST", "/api/config/reload", "", sessionToken)
		rr := httptest.NewRecorder()
		srv.handleConfigReload(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("reload status = %d, want %d", rr.Code, http.StatusOK)
		}

		var result ReloadResult
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}

		// pending_restart should still be true after reload (restart fields persist).
		if !result.PendingRestart {
			t.Error("pending_restart should still be true after reload " +
				"(restart-required fields are not hot-reloaded)")
		}

		// Verify via registry.
		if !srv.configAPI.reloaderRegistry.HasPendingRestart() {
			t.Error("registry should still have pending restart after reload")
		}
	})

	t.Run("Step3_ClearRestartDirty_SimulatesProcessRestart", func(t *testing.T) {
		// After a process restart, restart dirty entries are cleared.
		srv.configAPI.reloaderRegistry.ClearRestartDirty()

		if srv.configAPI.reloaderRegistry.HasPendingRestart() {
			t.Error("registry should not have pending restart after ClearRestartDirty()")
		}
	})
}

// --- Test: Mixed Hot-Reload + Restart-Required Fields ---

func TestIntegration_ConfigMixedFields_HotReloadAndRestart(t *testing.T) {
	srv, _, sessionToken := newConfigTestServerWithStepUp(t)

	// Register a mock reloader.
	mock := &mockReloader{
		appliedFields: []string{"monitoring.interval"},
	}
	srv.configAPI.reloaderRegistry.Register(mock)

	// Edit BOTH a hot-reload field AND a restart-required field in one PUT.
	body := `{"monitoring":{"interval":30},"mesh":{"port":51822}}`
	req := configRequestWithAuth("PUT", "/api/config", body, sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want %d, body: %s",
			rr.Code, http.StatusOK, rr.Body.String())
	}

	var result ConfigPutResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Both hot-reload and restart-required fields should be present.
	t.Run("HotReloadFieldInAppliedList", func(t *testing.T) {
		found := false
		for _, f := range result.Applied {
			if f == "monitoring.interval" {
				found = true
				break
			}
		}
		if !found {
			t.Error("monitoring.interval should be in 'applied' list")
		}
	})

	t.Run("RestartFieldInRequiresRestartList", func(t *testing.T) {
		found := false
		for _, f := range result.RequiresRestart {
			if f == "mesh.port" {
				found = true
				break
			}
		}
		if !found {
			t.Error("mesh.port should be in 'requires_restart' list")
		}
	})

	t.Run("BothDirtySetsPopulated", func(t *testing.T) {
		if !srv.configAPI.reloaderRegistry.HasPendingReload() {
			t.Error("should have pending reload (monitoring.interval is hot-reload)")
		}
		if !srv.configAPI.reloaderRegistry.HasPendingRestart() {
			t.Error("should have pending restart (mesh.port is restart-required)")
		}
	})

	t.Run("ReloadClearsHotReloadButNotRestart", func(t *testing.T) {
		// Wait for rate limit.
		time.Sleep(6 * time.Second)

		req := configRequestWithAuth("POST", "/api/config/reload", "", sessionToken)
		rr := httptest.NewRecorder()
		srv.handleConfigReload(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("reload status = %d, want %d", rr.Code, http.StatusOK)
		}

		// Hot-reload dirty should be cleared.
		if srv.configAPI.reloaderRegistry.HasPendingReload() {
			t.Error("pending reload should be cleared after successful reload")
		}
		// Restart dirty should persist.
		if !srv.configAPI.reloaderRegistry.HasPendingRestart() {
			t.Error("pending restart should persist after reload")
		}
	})

	t.Run("LiveConfigUpdatedForBothFields", func(t *testing.T) {
		// Even restart-required fields are written to the in-memory config
		// and to disk — they just don't take effect until process restart.
		configMu.RLock()
		cfg := srv.cfg
		configMu.RUnlock()

		if cfg.Monitoring.Interval != 30 {
			t.Errorf("live monitoring.interval = %d, want 30", cfg.Monitoring.Interval)
		}
		if cfg.Mesh.Port != 51822 {
			t.Errorf("live mesh.port = %d, want 51822", cfg.Mesh.Port)
		}
	})
}

// --- Test: PATCH Hot-Reload ---

func TestIntegration_ConfigPatch_HotReloadField(t *testing.T) {
	srv, _, sessionToken := newConfigTestServerWithStepUp(t)

	// Register a mock reloader.
	mock := &mockReloader{
		appliedFields: []string{"monitoring.interval"},
	}
	srv.configAPI.reloaderRegistry.Register(mock)

	// Record original value.
	configMu.RLock()
	originalInterval := srv.cfg.Monitoring.Interval
	configMu.RUnlock()

	// PATCH only the hot-reload field. Use a value DIFFERENT from the default (30).
	body := `{"monitoring":{"interval":60}}`
	req := configRequestWithAuth("PATCH", "/api/config", body, sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigPatch(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, want %d, body: %s",
			rr.Code, http.StatusOK, rr.Body.String())
	}

	var result ConfigPutResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Verify the field was applied.
	if !result.OK {
		t.Error("result.ok = false")
	}
	foundApplied := false
	for _, f := range result.Applied {
		if f == "monitoring.interval" {
			foundApplied = true
			break
		}
	}
	if !foundApplied {
		t.Error("monitoring.interval should be in 'applied' list")
	}

	// Verify live config is updated.
	configMu.RLock()
	currentInterval := srv.cfg.Monitoring.Interval
	configMu.RUnlock()

	if currentInterval != 60 {
		t.Errorf("live monitoring.interval = %d, want 60", currentInterval)
	}
	if currentInterval == originalInterval {
		t.Error("live config was not updated by PATCH")
	}

	// Verify pending reload is set.
	if !srv.configAPI.reloaderRegistry.HasPendingReload() {
		t.Error("should have pending reload after PATCH")
	}
}

// --- Test: GET /api/config/diff After Hot-Reload Edit ---

func TestIntegration_ConfigDiff_AfterHotReloadEdit(t *testing.T) {
	srv, configPath, sessionToken := newConfigTestServerWithStepUp(t)

	// Edit a hot-reload field.
	body := `{"monitoring":{"interval":25}}`
	req := configRequestWithAuth("PUT", "/api/config", body, sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Now the in-memory config has monitoring.interval=20 and the disk
	// config also has it (because applyConfigChanges writes to disk).
	// To create a diff, we need to modify the disk config independently.
	// (In the real system, the diff endpoint compares running vs saved.)

	// Since applyConfigChanges writes to BOTH memory and disk atomically,
	// the diff should be empty right after a PUT (they match).
	// But if we modify the disk config externally, we can see a diff.

	// Modify the disk config to differ from running.
	configMu.RLock()
	diskCfg := *srv.cfg
	configMu.RUnlock()
	diskCfg.Monitoring.Interval = 999 // different from running (25)
	if err := config.Save(configPath, &diskCfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// GET /api/config/diff should show the difference.
	req = configRequestWithAuth("GET", "/api/config/diff", "", sessionToken)
	rr = httptest.NewRecorder()
	srv.handleConfigDiff(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("diff status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	diff, ok := result["running_vs_saved"].(map[string]any)
	if !ok {
		t.Fatal("running_vs_saved missing")
	}

	// Should have a diff entry for monitoring.interval.
	foundDiff := false
	for k := range diff {
		if k == "monitoring.interval" || k == "monitoring" {
			foundDiff = true
			break
		}
	}
	if !foundDiff {
		t.Error("diff should contain monitoring.interval or monitoring section")
	}

	// pending_restart should be reflected.
	if _, ok := result["pending_restart"]; !ok {
		t.Error("diff response should include pending_restart")
	}
}

// --- Test: Full Cycle: Edit → Reload → Verify Clean → Edit Again ---

func TestIntegration_ConfigHotReload_FullCycle(t *testing.T) {
	srv, _, sessionToken := newConfigTestServerWithStepUp(t)

	mock := &mockReloader{
		appliedFields: []string{"monitoring.interval"},
	}
	srv.configAPI.reloaderRegistry.Register(mock)

	// Step 1: Edit hot-reload field.
	body1 := `{"monitoring":{"interval":10}}`
	req := configRequestWithAuth("PUT", "/api/config", body1, sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT #1: status = %d", rr.Code)
	}

	// Verify dirty.
	if !srv.configAPI.reloaderRegistry.HasPendingReload() {
		t.Fatal("should have pending reload after edit #1")
	}

	// Step 2: Reload.
	time.Sleep(1 * time.Second) // avoid rate-limit
	req = configRequestWithAuth("POST", "/api/config/reload", "", sessionToken)
	rr = httptest.NewRecorder()
	srv.handleConfigReload(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Reload #1: status = %d", rr.Code)
	}

	// Verify dirty cleared.
	if srv.configAPI.reloaderRegistry.HasPendingReload() {
		t.Fatal("should not have pending reload after reload #1")
	}

	// Step 3: Edit again (same field, different value).
	time.Sleep(5 * time.Second) // wait for rate-limit

	body2 := `{"monitoring":{"interval":25}}`
	req = configRequestWithAuth("PUT", "/api/config", body2, sessionToken)
	rr = httptest.NewRecorder()
	srv.handleConfigPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT #2: status = %d", rr.Code)
	}

	// Verify dirty is set again.
	if !srv.configAPI.reloaderRegistry.HasPendingReload() {
		t.Fatal("should have pending reload after edit #2")
	}

	// Verify live config has the new value.
	configMu.RLock()
	interval := srv.cfg.Monitoring.Interval
	configMu.RUnlock()
	if interval != 25 {
		t.Errorf("live config monitoring.interval = %d, want 25", interval)
	}

	// Step 4: Reload again.
	time.Sleep(1 * time.Second)
	req = configRequestWithAuth("POST", "/api/config/reload", "", sessionToken)
	rr = httptest.NewRecorder()
	srv.handleConfigReload(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Reload #2: status = %d", rr.Code)
	}

	// Verify clean state.
	if srv.configAPI.reloaderRegistry.HasPendingReload() {
		t.Fatal("should not have pending reload after reload #2")
	}
}
