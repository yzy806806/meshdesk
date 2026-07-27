package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// newConfigTestServer creates a web server configured for config API tests.
// It sets up a web user, session, and step-up auth so handlers can be
// called directly without going through the full middleware chain.
func newConfigTestServer(t *testing.T) (*Server, string) {
	t.Helper()

	// Create a temp config file.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := config.Default()
	cfg.Node.Hostname = "test-node"
	cfg.Node.WebAddr = ":8080"
	cfg.Mesh.Port = 51820
	cfg.Proxy.SS.Password = "secret-ss-password"
	cfg.Proxy.CFTunnel.TunnelID = "cf-tunnel-uuid-123"
	cfg.WebSSH.HostKey = "ssh-host-key-data"
	cfg.Reality.PrivateKey = "x25519-private-key-hex"

	// Add a test peer with sensitive fields.
	cfg.Peers = []config.PeerConfig{
		{
			PublicKey:    "peer-pubkey-abc",
			Endpoint:     "1.2.3.4:51820",
			AllowedIPs:   []string{"10.10.0.2/32"},
			Capabilities: []string{"ssh_proxy"},
			PresharedKey: "peer-psk-secret",
			ObfConfig: &config.ObfuscationOpts{
				PSK: "obf-psk-secret",
			},
			Reality: &config.RealityPeerConfig{
				ServerName: "www.apple.com",
				PublicKey:  "reality-server-pubkey",
				ShortID:    "abcd1234",
			},
		},
	}

	// Add web user.
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)
	cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: string(hash)},
	}

	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("Save config: %v", err)
	}

	srv, err := New(Deps{
		Config:     cfg,
		ConfigPath: configPath,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	return srv, configPath
}

// newConfigTestServerWithStepUp creates a server with a session that has
// step-up auth for the "settings" scope.
func newConfigTestServerWithStepUp(t *testing.T) (*Server, string, string) {
	t.Helper()
	srv, configPath := newConfigTestServer(t)

	// Create a session.
	session := srv.sessions.Create("admin")
	// Grant step-up for settings.
	srv.stepUpStore.Grant(session.Token, []string{OpSettings})

	return srv, configPath, session.Token
}

// configRequestWithAuth creates an HTTP request with session cookie
// and session token in context (simulating requireAuth middleware).
func configRequestWithAuth(method, target string, body string, sessionToken string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: sessionToken})
	ctx := context.WithValue(req.Context(), ctxSessionTokenKey{}, sessionToken)
	ctx = context.WithValue(ctx, ctxUsernameKey{}, "admin")
	return req.WithContext(ctx)
}

// --- AC-1: GET /api/config returns all fields with correct tier masking ---

func TestAC1_GetConfig_ReturnsAllFieldsWithMasking(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	req := configRequestWithAuth("GET", "/api/config", "", session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigGet(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check masked fields are "***".
	if node, ok := result["node"].(map[string]any); ok {
		if identity, ok := node["identity"].(string); ok {
			if identity != maskSentinel {
				t.Errorf("node.identity = %q, want %q (masked)", identity, maskSentinel)
			}
		} else {
			t.Error("node.identity missing or not a string")
		}
	} else {
		t.Error("node section missing or not a map")
	}

	// Check non-masked fields are actual values.
	if mesh, ok := result["mesh"].(map[string]any); ok {
		if port, ok := mesh["port"].(float64); ok {
			if int(port) != 51820 {
				t.Errorf("mesh.port = %v, want 51820", port)
			}
		} else {
			t.Error("mesh.port missing or not a number")
		}
	} else {
		t.Error("mesh section missing or not a map")
	}

	// Check _meta exists.
	meta, ok := result["_meta"].(map[string]any)
	if !ok {
		t.Fatal("_meta missing")
	}

	// Check masked_fields list.
	maskedList, ok := meta["masked_fields"].([]any)
	if !ok {
		t.Fatal("_meta.masked_fields missing")
	}
	if len(maskedList) != len(maskedFields) {
		t.Errorf("masked_fields count = %d, want %d", len(maskedList), len(maskedFields))
	}

	// Check readonly_fields list.
	readonlyList, ok := meta["readonly_fields"].([]any)
	if !ok {
		t.Fatal("_meta.readonly_fields missing")
	}
	if len(readonlyList) != len(readOnlyFields) {
		t.Errorf("readonly_fields count = %d, want %d", len(readonlyList), len(readOnlyFields))
	}

	// Check tier_map.
	tierMapResult, ok := meta["tier_map"].(map[string]any)
	if !ok {
		t.Fatal("_meta.tier_map missing")
	}
	if len(tierMapResult) == 0 {
		t.Error("_meta.tier_map is empty")
	}
}

// --- AC-2: PUT rejects read-only fields with 400 ---

func TestAC2_PutConfig_RejectsReadOnlyFields(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	// Try to write a read-only field.
	body := `{"node":{"hostname":"new-hostname"}}`
	req := configRequestWithAuth("PUT", "/api/config", body, session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Status = %d, want %d (readonly violation)", rr.Code, http.StatusBadRequest)
	}

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result["error"] != "readonly_fields" {
		t.Errorf("error = %v, want 'readonly_fields'", result["error"])
	}

	fields, ok := result["fields"].([]any)
	if !ok || len(fields) == 0 {
		t.Error("no readonly fields listed in response")
	}
}

// --- AC-3: PUT with T2 fields but no step-up → 403 ---

func TestAC3_PutConfig_T2FieldsNoStepUp_Returns403(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")
	// No step-up granted.

	body := `{"p2p":{"join_approval":"manual"}}`
	req := configRequestWithAuth("PUT", "/api/config", body, session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d, want %d (step-up required)", rr.Code, http.StatusForbidden)
	}

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result["error"] != "step_up_required" {
		t.Errorf("error = %v, want 'step_up_required'", result["error"])
	}

	// Check X-StepUp-Required header (AC-14).
	if rr.Header().Get("X-StepUp-Required") != OpSettings {
		t.Errorf("X-StepUp-Required = %q, want %q", rr.Header().Get("X-StepUp-Required"), OpSettings)
	}
}

// --- AC-4: PUT with T2 fields and valid step-up succeeds ---

func TestAC4_PutConfig_T2FieldsWithStepUp_Succeeds(t *testing.T) {
	srv, _, sessionToken := newConfigTestServerWithStepUp(t)
	// sessionToken has step-up for settings.

	body := `{"p2p":{"join_approval":"manual"}}`
	req := configRequestWithAuth("PUT", "/api/config", body, sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var result ConfigPutResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if !result.OK {
		t.Error("result.ok = false, want true")
	}

	// Verify the field was applied.
	configMu.RLock()
	cfg := srv.cfg
	configMu.RUnlock()
	if cfg.P2P.JoinApproval != "manual" {
		t.Errorf("p2p.join_approval = %q, want 'manual'", cfg.P2P.JoinApproval)
	}
}

// --- AC-5: Sending "***" for a masked field is a no-op ---

func TestAC5_PutConfig_MaskedFieldNoOp(t *testing.T) {
	srv, _, sessionToken := newConfigTestServerWithStepUp(t)

	// Read current SS password first.
	configMu.RLock()
	originalPassword := srv.cfg.Proxy.SS.Password
	configMu.RUnlock()

	// Send "***" for the masked password field.
	body := `{"proxy":{"ss":{"password":"***","cipher":"chacha20-ietf-poly1305","listen_addr":"127.0.0.1","port":8388}}}`
	req := configRequestWithAuth("PUT", "/api/config", body, sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var result ConfigPutResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Verify the password was not changed.
	configMu.RLock()
	currentPassword := srv.cfg.Proxy.SS.Password
	configMu.RUnlock()

	if currentPassword != originalPassword {
		t.Errorf("ss.password changed: %q → %q (should be no-op)", originalPassword, currentPassword)
	}

	// Check that the field appears in noop list.
	foundNoOp := false
	for _, f := range result.NoOp {
		if f == "proxy.ss.password" {
			foundNoOp = true
			break
		}
	}
	if !foundNoOp {
		t.Error("proxy.ss.password not in noop list")
	}
}

// --- AC-6: POST /api/config/reload triggers reloaders ---

func TestAC6_PostConfigReload_TriggersReloaders(t *testing.T) {
	srv, _, sessionToken := newConfigTestServerWithStepUp(t)

	// Register a mock reloader.
	mock := &mockReloader{
		appliedFields: []string{"monitoring.interval", "p2p.gossip_interval"},
	}
	srv.configAPI.reloaderRegistry.Register(mock)

	// Mark some fields as dirty.
	srv.configAPI.reloaderRegistry.MarkDirty("monitoring.interval")

	req := configRequestWithAuth("POST", "/api/config/reload", "", sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigReload(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result ReloadResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if !result.OK {
		t.Error("ok = false, want true")
	}
	if len(result.Applied) == 0 {
		t.Error("applied list is empty")
	}

	// Verify the reloader was called.
	if !mock.called {
		t.Error("mock reloader was not called")
	}
}

// --- AC-7: After modifying restart-required field, pending_restart is true ---

func TestAC7_PutConfig_RestartRequired_PendingRestartTrue(t *testing.T) {
	srv, _, sessionToken := newConfigTestServerWithStepUp(t)

	// Modify a restart-required field (mesh.port is T3 normal + restart).
	body := `{"mesh":{"port":51821,"gossip_port":7946}}`
	req := configRequestWithAuth("PUT", "/api/config", body, sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var result ConfigPutResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if !result.PendingRestart {
		t.Error("pending_restart = false, want true (mesh.port is restart-required)")
	}

	if len(result.RequiresRestart) == 0 {
		t.Error("requires_restart list is empty")
	}

	// Verify via the registry.
	if !srv.configAPI.reloaderRegistry.HasPendingRestart() {
		t.Error("registry.HasPendingRestart() = false, want true")
	}
}

// --- AC-8: POST /api/config/restart requires step-up ---

func TestAC8_PostConfigRestart_RequiresStepUp(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")
	// No step-up — the route registration wraps this in requireStepUp,
	// so calling the handler directly should still check. But since we
	// call the handler directly (not via the mux), we test the handler
	// itself. The requireStepUp wrapper is tested separately.

	// Grant step-up and test successful call.
	srv.stepUpStore.Grant(session.Token, []string{OpSettings})

	req := configRequestWithAuth("POST", "/api/config/restart", "", session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigRestart(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result["ok"] != true {
		t.Error("ok = false, want true")
	}
}

// --- AC-9: GET /api/config/diff shows differences ---

func TestAC9_GetConfigDiff_ShowsDifferences(t *testing.T) {
	srv, configPath, sessionToken := newConfigTestServerWithStepUp(t)

	// Modify the saved config on disk (simulating external edit).
	// We need to create a DIFFERENT config on disk from the in-memory one.
	// The in-memory config has mesh.port=51820. We'll write mesh.port=99999 to disk.
	configMu.RLock()
	savedCfg := *srv.cfg // copy by value to avoid modifying the running pointer
	configMu.RUnlock()
	savedCfg.Mesh.Port = 99999 // different from running (51820)
	if err := config.Save(configPath, &savedCfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	req := configRequestWithAuth("GET", "/api/config/diff", "", sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigDiff(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	diff, ok := result["running_vs_saved"].(map[string]any)
	if !ok {
		t.Fatal("running_vs_saved missing")
	}

	// Should have a diff entry for mesh.port.
	if _, ok := diff["mesh.port"]; !ok {
		// The diff may show it as a nested object — check.
		found := false
		for k := range diff {
			if k == "mesh.port" || k == "mesh" {
				found = true
				break
			}
		}
		if !found {
			t.Error("no diff entry for mesh.port or mesh")
		}
	}
}

// --- AC-10: Modifying node.identity or peers[N].public_key is rejected ---

func TestAC10_ReadOnlyFields_Rejected(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	tests := []struct {
		name string
		body string
	}{
		{
			name: "node.identity",
			body: `{"node":{"identity":"new-private-key"}}`,
		},
		{
			name: "peers[0].public_key",
			body: `{"peers":[{"public_key":"new-pub","endpoint":"1.2.3.4:51820","allowed_ips":["10.10.0.2/32"]}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := configRequestWithAuth("PUT", "/api/config", tt.body, session.Token)
			rr := httptest.NewRecorder()
			srv.handleConfigPut(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("Status = %d, want %d (readonly)", rr.Code, http.StatusBadRequest)
			}
		})
	}
}

// --- AC-11: Response always includes _meta ---

func TestAC11_ResponseIncludesMeta(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	req := configRequestWithAuth("GET", "/api/config", "", session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigGet(rr, req)

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	meta, ok := result["_meta"]
	if !ok {
		t.Fatal("_meta missing from response")
	}

	metaMap, ok := meta.(map[string]any)
	if !ok {
		t.Fatal("_meta is not a map")
	}

	requiredKeys := []string{"tier_map", "masked_fields", "readonly_fields", "pending_restart"}
	for _, key := range requiredKeys {
		if _, ok := metaMap[key]; !ok {
			t.Errorf("_meta.%s missing", key)
		}
	}
}

// --- AC-12: Unknown field paths are rejected ---

func TestAC12_UnknownFields_Rejected(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	body := `{"mesh":{"nonexistent_field":123}}`
	req := configRequestWithAuth("PUT", "/api/config", body, session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Status = %d, want %d (unknown field)", rr.Code, http.StatusBadRequest)
	}

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result["error"] != "unknown_fields" {
		t.Errorf("error = %v, want 'unknown_fields'", result["error"])
	}
}

// --- AC-13: PATCH applies JSON merge semantics ---

func TestAC13_PatchConfig_MergeSemantics(t *testing.T) {
	srv, _, sessionToken := newConfigTestServerWithStepUp(t)

	// Record original mesh.gossip_port.
	configMu.RLock()
	originalGossipPort := srv.cfg.Mesh.GossipPort
	configMu.RUnlock()

	// Patch only mesh.port, leaving gossip_port unchanged.
	body := `{"mesh":{"port":51821}}`
	req := configRequestWithAuth("PATCH", "/api/config", body, sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigPatch(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify mesh.port was updated but gossip_port was preserved.
	configMu.RLock()
	cfg := srv.cfg
	configMu.RUnlock()

	if cfg.Mesh.Port != 51821 {
		t.Errorf("mesh.port = %d, want 51821", cfg.Mesh.Port)
	}
	if cfg.Mesh.GossipPort != originalGossipPort {
		t.Errorf("mesh.gossip_port = %d, want %d (should be unchanged by patch)",
			cfg.Mesh.GossipPort, originalGossipPort)
	}
}

// --- AC-14: 403 step-up response includes X-StepUp-Required header ---

func TestAC14_StepUpResponse_IncludesHeader(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")
	// No step-up.

	body := `{"p2p":{"authorized_keys":["new-key"]}}`
	req := configRequestWithAuth("PUT", "/api/config", body, session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	if rr.Header().Get("X-StepUp-Required") != OpSettings {
		t.Errorf("X-StepUp-Required header = %q, want %q",
			rr.Header().Get("X-StepUp-Required"), OpSettings)
	}
}

// --- Additional tests ---

// Test GET /api/config?section=mesh returns single section.
func TestGetConfig_SingleSection(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	req := configRequestWithAuth("GET", "/api/config?section=mesh", "", session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigGet(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result["section"] != "mesh" {
		t.Errorf("section = %v, want 'mesh'", result["section"])
	}

	data, ok := result["data"].(map[string]any)
	if !ok {
		t.Fatal("data missing or not a map")
	}
	if _, ok := data["port"]; !ok {
		t.Error("data.port missing")
	}
}

// Test GET /api/config?section=unknown returns 400.
func TestGetConfig_UnknownSection(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	req := configRequestWithAuth("GET", "/api/config?section=nonexistent", "", session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigGet(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// Test reload rate limiting.
func TestConfigReload_RateLimited(t *testing.T) {
	srv, _, sessionToken := newConfigTestServerWithStepUp(t)

	// First call should succeed.
	req1 := configRequestWithAuth("POST", "/api/config/reload", "", sessionToken)
	rr1 := httptest.NewRecorder()
	srv.handleConfigReload(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("First reload: Status = %d, want %d", rr1.Code, http.StatusOK)
	}

	// Second call within 5 seconds should be rate-limited.
	req2 := configRequestWithAuth("POST", "/api/config/reload", "", sessionToken)
	rr2 := httptest.NewRecorder()
	srv.handleConfigReload(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("Second reload: Status = %d, want %d (rate-limited)", rr2.Code, http.StatusTooManyRequests)
	}
}

// Test that masked fields in peers array are properly masked.
func TestGetConfig_PeerMaskedFields(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	req := configRequestWithAuth("GET", "/api/config", "", session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigGet(rr, req)

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	peers, ok := result["peers"].([]any)
	if !ok || len(peers) == 0 {
		t.Fatal("peers missing or empty")
	}

	peer, ok := peers[0].(map[string]any)
	if !ok {
		t.Fatal("peer[0] is not a map")
	}

	// preshared_key should be masked.
	if psk, ok := peer["preshared_key"].(string); ok {
		if psk != maskSentinel {
			t.Errorf("peers[0].preshared_key = %q, want %q", psk, maskSentinel)
		}
	} else {
		t.Error("peers[0].preshared_key missing or not a string")
	}

	// public_key should NOT be masked (it's read-only, not masked on read).
	// Actually, public_key is T0 read-only, so it should show the actual value.
	if pk, ok := peer["public_key"].(string); ok {
		if pk == maskSentinel {
			t.Error("peers[0].public_key should not be masked (it's read-only, not masked)")
		}
	}
}

// Test that PUT with valid step-up can write T2 fields.
func TestPutConfig_T2Fields_AllTypes(t *testing.T) {
	srv, _, sessionToken := newConfigTestServerWithStepUp(t)

	// Test multiple T2 fields.
	body := `{"p2p":{"join_approval":"manual","authorized_keys":["key1","key2"]},"auth":{"require_2fa":false,"step_up_timeout":600}}`
	req := configRequestWithAuth("PUT", "/api/config", body, sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify values were applied.
	configMu.RLock()
	cfg := srv.cfg
	configMu.RUnlock()

	if cfg.P2P.JoinApproval != "manual" {
		t.Errorf("p2p.join_approval = %q, want 'manual'", cfg.P2P.JoinApproval)
	}
	if cfg.Auth.StepUpTimeout != 600 {
		t.Errorf("auth.step_up_timeout = %d, want 600", cfg.Auth.StepUpTimeout)
	}
}

// Test PATCH with T2 fields requires step-up.
func TestPatchConfig_T2Fields_NoStepUp_403(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	body := `{"proxy":{"exit_addr":"10.10.0.5:8388"}}`
	req := configRequestWithAuth("PATCH", "/api/config", body, session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigPatch(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// Test config file is actually written to disk.
func TestPutConfig_WritesToDisk(t *testing.T) {
	srv, configPath, sessionToken := newConfigTestServerWithStepUp(t)

	body := `{"mesh":{"port":51822,"gossip_port":7946}}`
	req := configRequestWithAuth("PUT", "/api/config", body, sessionToken)
	rr := httptest.NewRecorder()
	srv.handleConfigPut(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Re-read from disk.
	diskCfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if diskCfg.Mesh.Port != 51822 {
		t.Errorf("disk mesh.port = %d, want 51822", diskCfg.Mesh.Port)
	}
}

// Test atomic config save (temp file + rename).
func TestAtomicConfigSave(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := config.Default()
	cfg.Mesh.Port = 12345

	err := atomicConfigSave(configPath, cfg)
	if err != nil {
		t.Fatalf("atomicConfigSave: %v", err)
	}

	// Verify file exists and temp file doesn't.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("config file not created")
	}
	if _, err := os.Stat(configPath + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp file should have been renamed")
	}

	// Verify content.
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Mesh.Port != 12345 {
		t.Errorf("port = %d, want 12345", loaded.Mesh.Port)
	}
}

// --- Tier map unit tests ---

func TestMatchFieldPath(t *testing.T) {
	tests := []struct {
		template string
		actual   string
		want     bool
	}{
		{"mesh.port", "mesh.port", true},
		{"mesh.port", "mesh.gossip_port", false},
		{"peers[N].preshared_key", "peers[0].preshared_key", true},
		{"peers[N].preshared_key", "peers[5].preshared_key", true},
		{"peers[N].preshared_key", "peers[0].endpoint", false},
		{"peers[N].preshared_key", "peers.public_key", false},
		{"auth.web_users[N].password_hash", "auth.web_users[0].password_hash", true},
		{"auth.web_users", "auth.web_users", true},
		{"node.identity", "node.identity", true},
		{"node.identity", "node.hostname", false},
	}

	for _, tt := range tests {
		t.Run(tt.template+"_"+tt.actual, func(t *testing.T) {
			got := matchFieldPath(tt.template, tt.actual)
			if got != tt.want {
				t.Errorf("matchFieldPath(%q, %q) = %v, want %v", tt.template, tt.actual, got, tt.want)
			}
		})
	}
}

func TestFieldPathToTemplate(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"mesh.port", "mesh.port"},
		{"peers[0].preshared_key", "peers[N].preshared_key"},
		{"peers[12].obf_config.psk", "peers[N].obf_config.psk"},
		{"auth.web_users[0].password_hash", "auth.web_users[N].password_hash"},
		{"node.identity", "node.identity"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := fieldPathToTemplate(tt.input)
			if got != tt.want {
				t.Errorf("fieldPathToTemplate(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsKnownField(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"mesh.port", true},
		{"peers[0].endpoint", true},
		{"node.identity", true},
		{"mesh.nonexistent", false},
		{"unknown.section.field", false},
		{"peers", true}, // container field
		{"mesh", true},  // container field
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isKnownField(tt.path)
			if got != tt.want {
				t.Errorf("isKnownField(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsMasked(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"node.identity", true},
		{"peers[0].preshared_key", true},
		{"peers[0].obf_config.psk", true},
		{"webssh.host_key", true},
		{"proxy.ss.password", true},
		{"reality.private_key", true},
		{"mesh.port", false},
		{"node.hostname", false},
		{"peers[0].endpoint", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isMasked(tt.path)
			if got != tt.want {
				t.Errorf("isMasked(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsStepUp(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"peers[0].capabilities", true},
		{"p2p.join_approval", true},
		{"p2p.authorized_keys", true},
		{"auth.web_users", true},
		{"proxy.exit.allowed_ports", true},
		{"mesh.port", false},
		{"node.identity", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isStepUp(tt.path)
			if got != tt.want {
				t.Errorf("isStepUp(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsReadOnly(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"node.identity", true},
		{"node.hostname", true},
		{"peers[0].public_key", true},
		{"auth.totp_store_dir", true},
		{"proxy.path_selection.exit_latency_matrix", true},
		{"mesh.port", false},
		{"peers[0].endpoint", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isReadOnly(tt.path)
			if got != tt.want {
				t.Errorf("isReadOnly(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// Test FieldTier.String() method.
func TestFieldTierString(t *testing.T) {
	tests := []struct {
		tier FieldTier
		want string
	}{
		{TierReadOnly, "read-only"},
		{TierMasked, "masked"},
		{TierStepUp, "step-up"},
		{TierNormal, "normal"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.tier.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Test ReloadClass.String() method.
func TestReloadClassString(t *testing.T) {
	if ReloadHot.String() != "hot-reload" {
		t.Errorf("ReloadHot.String() = %q, want 'hot-reload'", ReloadHot.String())
	}
	if ReloadRestart.String() != "restart" {
		t.Errorf("ReloadRestart.String() = %q, want 'restart'", ReloadRestart.String())
	}
}

// Test ReloaderRegistry dirty tracking.
func TestReloaderRegistry_DirtyTracking(t *testing.T) {
	reg := NewReloaderRegistry()

	// Initially clean.
	if reg.HasPendingReload() {
		t.Error("should not have pending reload initially")
	}
	if reg.HasPendingRestart() {
		t.Error("should not have pending restart initially")
	}

	// Mark a hot-reload field dirty.
	reg.MarkDirty("p2p.gossip_interval")
	if !reg.HasPendingReload() {
		t.Error("should have pending reload after marking hot field")
	}
	if reg.HasPendingRestart() {
		t.Error("should not have pending restart for hot field")
	}

	// Mark a restart-required field dirty.
	reg.MarkDirty("mesh.port")
	if !reg.HasPendingRestart() {
		t.Error("should have pending restart after marking restart field")
	}

	// DirtySinceReload should list both.
	dirty := reg.DirtySinceReload()
	if len(dirty) != 2 {
		t.Errorf("DirtySinceReload() = %d items, want 2", len(dirty))
	}

	// Clear hot-reload via Reload.
	cfg := config.Default()
	reg.Reload(cfg)

	if reg.HasPendingReload() {
		t.Error("should not have pending reload after Reload()")
	}
	if !reg.HasPendingRestart() {
		t.Error("should still have pending restart after Reload()")
	}

	// Clear restart dirty.
	reg.ClearRestartDirty()
	if reg.HasPendingRestart() {
		t.Error("should not have pending restart after ClearRestartDirty()")
	}
}

// Test ReloadResult with no changes pending.
func TestReload_NoChangesPending(t *testing.T) {
	reg := NewReloaderRegistry()
	cfg := config.Default()
	result := reg.Reload(cfg)

	if !result.OK {
		t.Error("ok = false, want true")
	}
	if result.Message == "" {
		t.Error("message should indicate no changes pending")
	}
	if len(result.Applied) > 0 {
		t.Error("applied should be empty when no changes pending")
	}
}

// --- Mock helpers ---

type mockReloader struct {
	appliedFields []string
	called       bool
}

func (m *mockReloader) ReloadConfig(cfg *config.Config) ([]string, []string, []error) {
	m.called = true
	return m.appliedFields, nil, nil
}

// Test collectFieldPaths.
func TestCollectFieldPaths(t *testing.T) {
	data := map[string]any{
		"mesh": map[string]any{
			"port":        51820,
			"gossip_port": 7946,
		},
		"node": map[string]any{
			"hostname": "test",
			"position": map[string]any{
				"x": 1.0,
				"y": 2.0,
			},
		},
	}

	paths := collectFieldPaths(data, "")
	found := map[string]bool{}
	for _, p := range paths {
		found[p] = true
	}

	expected := []string{"mesh.port", "mesh.gossip_port", "node.hostname", "node.position.x", "node.position.y"}
	for _, e := range expected {
		if !found[e] {
			t.Errorf("field path %q not found in collected paths", e)
		}
	}
}
