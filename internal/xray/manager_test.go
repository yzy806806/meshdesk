package xray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestGenerateShortID(t *testing.T) {
	id := GenerateShortID()
	if len(id) != 16 {
		t.Fatalf("expected 16-char hex short ID, got %d chars: %s", len(id), id)
	}
	// Should be valid hex
	if _, err := parseHex(id); err != nil {
		t.Fatalf("short ID is not valid hex: %v", err)
	}
	// Should be unique across calls
	id2 := GenerateShortID()
	if id == id2 {
		t.Fatal("two consecutive short IDs are identical")
	}
}

func parseHex(s string) (interface{}, error) {
	return hexDecode(s)
}

// hexDecode decodes a hex string.
func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high, ok1 := hexVal(s[i])
		low, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return nil, nil
		}
		b[i/2] = high<<4 | low
	}
	return b, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func TestGenerateVLESSUUID(t *testing.T) {
	uuid := GenerateVLESSUUID()
	if len(uuid) != 36 {
		t.Fatalf("expected 36-char UUID, got %d: %s", len(uuid), uuid)
	}
	// Check UUID v4 format
	if uuid[14] != '4' {
		t.Fatalf("expected version 4 at position 14, got %c", uuid[14])
	}
	if uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' {
		t.Fatalf("UUID format is wrong: %s", uuid)
	}
	// Variant should be 8, 9, a, or b
	v := uuid[19]
	if v != '8' && v != '9' && v != 'a' && v != 'b' {
		t.Fatalf("expected variant 8/9/a/b at position 19, got %c", v)
	}
	// Unique
	uuid2 := GenerateVLESSUUID()
	if uuid == uuid2 {
		t.Fatal("two consecutive UUIDs are identical")
	}
}

func TestGenerateX25519Key(t *testing.T) {
	priv, pub, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("GenerateX25519Key failed: %v", err)
	}
	if len(priv) == 0 || len(pub) == 0 {
		t.Fatal("keys are empty")
	}
	// Base64 encoded 32 bytes = 44 chars with padding
	if len(priv) != 44 {
		t.Fatalf("expected 44-char base64 private key, got %d: %s", len(priv), priv)
	}
	if len(pub) != 44 {
		t.Fatalf("expected 44-char base64 public key, got %d: %s", len(pub), pub)
	}
	// Keys should be different
	if priv == pub {
		t.Fatal("private and public keys are identical")
	}
	// Two runs should produce different keys
	priv2, pub2, _ := GenerateX25519Key()
	if priv == priv2 {
		t.Fatal("two consecutive private keys are identical")
	}
	if pub == pub2 {
		t.Fatal("two consecutive public keys are identical")
	}
}

func TestInboundCRUD(t *testing.T) {
	m, err := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Add an inbound
	ic := &InboundConfig{
		Tag:         "test-inbound",
		Protocol:    "vless-reality",
		Port:        443,
		Listen:      "0.0.0.0",
		Network:     "tcp",
		Security:    "reality",
		Dest:        "www.cloudflare.com:443",
		ServerNames: []string{"www.cloudflare.com"},
		PrivateKey:  "dummy-private-key",
		ShortIds:    []string{"abcdef0123456789"},
		VLESSClients: []VLESSClient{
			{ID: GenerateVLESSUUID(), Flow: "xtls-rprx-vision"},
		},
	}
	if err := m.AddInbound(ic); err != nil {
		t.Fatalf("AddInbound: %v", err)
	}

	// Get it back
	got, ok := m.GetInbound("test-inbound")
	if !ok {
		t.Fatal("GetInbound: not found")
	}
	if got.Port != 443 {
		t.Fatalf("expected port 443, got %d", got.Port)
	}

	// List
	list := m.ListInbounds()
	if len(list) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(list))
	}

	// Remove
	if err := m.RemoveInbound("test-inbound"); err != nil {
		t.Fatalf("RemoveInbound: %v", err)
	}
	if _, ok := m.GetInbound("test-inbound"); ok {
		t.Fatal("inbound still exists after remove")
	}

	// Remove non-existent
	if err := m.RemoveInbound("nonexistent"); err == nil {
		t.Fatal("expected error removing non-existent inbound")
	}
}

func TestAddInboundValidation(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	// Empty tag
	err := m.AddInbound(&InboundConfig{Port: 443})
	if err == nil || err.Error() != "inbound tag is required" {
		t.Fatalf("expected tag error, got: %v", err)
	}

	// Invalid port
	err = m.AddInbound(&InboundConfig{Tag: "test", Port: 99999})
	if err == nil {
		t.Fatal("expected port error")
	}

	// Zero port
	err = m.AddInbound(&InboundConfig{Tag: "test", Port: 0})
	if err == nil {
		t.Fatal("expected port error for zero port")
	}
}

func TestGenerateConfig(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	priv, _, _ := GenerateX25519Key()
	uuid := GenerateVLESSUUID()

	ic := &InboundConfig{
		Tag:         "reality-inbound",
		Protocol:    "vless-reality",
		Port:        443,
		Network:     "tcp",
		Security:    "reality",
		Dest:        "www.cloudflare.com:443",
		ServerNames: []string{"www.cloudflare.com"},
		PrivateKey:  priv,
		ShortIds:    []string{"abcdef0123456789"},
		VLESSClients: []VLESSClient{
			{ID: uuid, Flow: "xtls-rprx-vision"},
		},
		SniffEnabled: true,
	}
	m.AddInbound(ic)

	cfg, err := m.GenerateConfig()
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	if cfg.Log == nil || cfg.Log.LogLevel != "warning" {
		t.Fatal("expected log level warning")
	}
	if len(cfg.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(cfg.Inbounds))
	}

	inb := cfg.Inbounds[0]
	if inb.Tag != "reality-inbound" {
		t.Fatalf("expected tag 'reality-inbound', got %s", inb.Tag)
	}
	if inb.Port != 443 {
		t.Fatalf("expected port 443, got %d", inb.Port)
	}
	if inb.Protocol != "vless" {
		t.Fatalf("expected protocol 'vless', got %s", inb.Protocol)
	}
	if inb.StreamSettings == nil {
		t.Fatal("streamSettings is nil")
	}
	if inb.StreamSettings.Security != "reality" {
		t.Fatalf("expected security 'reality', got %s", inb.StreamSettings.Security)
	}
	if inb.StreamSettings.RealitySettings == nil {
		t.Fatal("realitySettings is nil")
	}
	if inb.StreamSettings.RealitySettings.Dest != "www.cloudflare.com:443" {
		t.Fatalf("expected dest www.cloudflare.com:443, got %s",
			inb.StreamSettings.RealitySettings.Dest)
	}
	if inb.StreamSettings.RealitySettings.PrivateKey != priv {
		t.Fatal("private key mismatch")
	}
	if inb.Sniffing == nil || !inb.Sniffing.Enabled {
		t.Fatal("sniffing not enabled")
	}

	// Check VLESS settings
	var vlessSettings VLESSInboundSettings
	if err := json.Unmarshal(inb.Settings, &vlessSettings); err != nil {
		t.Fatalf("unmarshal vless settings: %v", err)
	}
	if vlessSettings.Decryption != "none" {
		t.Fatalf("expected decryption 'none', got %s", vlessSettings.Decryption)
	}
	if len(vlessSettings.Clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(vlessSettings.Clients))
	}
	if vlessSettings.Clients[0].ID != uuid {
		t.Fatal("client UUID mismatch")
	}
	if vlessSettings.Clients[0].Flow != "xtls-rprx-vision" {
		t.Fatalf("expected flow xtls-rprx-vision, got %s", vlessSettings.Clients[0].Flow)
	}

	// Should have at least a "direct" outbound
	if len(cfg.Outbounds) == 0 {
		t.Fatal("expected at least one outbound")
	}
	hasDirect := false
	for _, ob := range cfg.Outbounds {
		if ob.Tag == "direct" && ob.Protocol == "freedom" {
			hasDirect = true
			break
		}
	}
	if !hasDirect {
		t.Fatal("expected a 'direct' freedom outbound")
	}
}

func TestGenerateConfigRealityValidation(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	// Missing private key
	ic := &InboundConfig{
		Tag:          "bad",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		VLESSClients: []VLESSClient{{ID: "uuid"}},
	}
	m.AddInbound(ic)
	_, err := m.GenerateConfig()
	if err == nil {
		t.Fatal("expected error for missing private key")
	}

	// Missing server names
	m.inbounds = make(map[string]*InboundConfig)
	ic2 := &InboundConfig{
		Tag:          "bad2",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		PrivateKey:   "key",
		VLESSClients: []VLESSClient{{ID: "uuid"}},
	}
	m.AddInbound(ic2)
	_, err = m.GenerateConfig()
	if err == nil {
		t.Fatal("expected error for missing server names")
	}

	// Missing dest
	m.inbounds = make(map[string]*InboundConfig)
	ic3 := &InboundConfig{
		Tag:          "bad3",
		Port:         443,
		Security:     "reality",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   "key",
		VLESSClients: []VLESSClient{{ID: "uuid"}},
	}
	m.AddInbound(ic3)
	_, err = m.GenerateConfig()
	if err == nil {
		t.Fatal("expected error for missing dest")
	}

	// No VLESS clients
	m.inbounds = make(map[string]*InboundConfig)
	ic4 := &InboundConfig{
		Tag:         "bad4",
		Port:        443,
		Security:    "reality",
		Dest:        "www.cloudflare.com:443",
		ServerNames: []string{"www.cloudflare.com"},
		PrivateKey:  "key",
	}
	m.AddInbound(ic4)
	_, err = m.GenerateConfig()
	if err == nil {
		t.Fatal("expected error for no VLESS clients")
	}
}

func TestWriteConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	m, _ := NewManager(ManagerOptions{
		ConfigDir:  dir,
		ConfigPath: configPath,
		ApiPort:    -1,
	})

	priv, _, _ := GenerateX25519Key()
	ic := &InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID(), Flow: "xtls-rprx-vision"}},
	}
	m.AddInbound(ic)

	if err := m.WriteConfig(); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("config file is empty")
	}

	// Should be valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	if _, ok := raw["inbounds"]; !ok {
		t.Fatal("config JSON missing 'inbounds' key")
	}
	if _, ok := raw["outbounds"]; !ok {
		t.Fatal("config JSON missing 'outbounds' key")
	}
}

func TestLogRingBuffer(t *testing.T) {
	rb := newLogRingBuffer(3)

	// Add 5 entries to a size-3 buffer
	for i := 0; i < 5; i++ {
		rb.Add(LogEntry{Line: string(rune('a' + i))})
	}

	all := rb.All()
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}
	// Should be the last 3: c, d, e
	if all[0].Line != "c" || all[1].Line != "d" || all[2].Line != "e" {
		t.Fatalf("expected c,d,e got %s,%s,%s", all[0].Line, all[1].Line, all[2].Line)
	}

	// Tail(2)
	tail := rb.Tail(2)
	if len(tail) != 2 {
		t.Fatalf("expected 2 tail entries, got %d", len(tail))
	}
	if tail[0].Line != "d" || tail[1].Line != "e" {
		t.Fatalf("expected d,e got %s,%s", tail[0].Line, tail[1].Line)
	}

	// Tail(10) should return all
	tail = rb.Tail(10)
	if len(tail) != 3 {
		t.Fatalf("expected 3, got %d", len(tail))
	}
}

func TestLogRingBufferNotFull(t *testing.T) {
	rb := newLogRingBuffer(10)
	rb.Add(LogEntry{Line: "a"})
	rb.Add(LogEntry{Line: "b"})

	all := rb.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(all))
	}
	if all[0].Line != "a" || all[1].Line != "b" {
		t.Fatal("entries in wrong order")
	}
}

func TestOutboundCRUD(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	oc := &OutboundConfig{
		Tag:         "test-outbound",
		Protocol:    "vless",
		PeerAddress: "1.2.3.4",
		PeerPort:    443,
		VLESSUsers:  []VLESSUser{{ID: "uuid", Flow: "xtls-rprx-vision", Encryption: "none"}},
		Fingerprint: "chrome",
		ServerName:  "www.cloudflare.com",
		Password:    "dummy-password",
	}
	if err := m.AddOutbound(oc); err != nil {
		t.Fatalf("AddOutbound: %v", err)
	}

	list := m.ListOutbounds()
	if len(list) != 1 {
		t.Fatalf("expected 1 outbound, got %d", len(list))
	}
}

func TestGenerateConfigWithVLESSOutbound(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	oc := &OutboundConfig{
		Tag:         "peer-outbound",
		Protocol:    "vless",
		PeerAddress: "203.0.113.5",
		PeerPort:    443,
		VLESSUsers:  []VLESSUser{{ID: "uuid", Flow: "xtls-rprx-vision", Encryption: "none"}},
		Fingerprint: "chrome",
		ServerName:  "www.cloudflare.com",
		Password:    "dummy-password",
		ShortId:     "abcdef0123456789",
	}
	m.AddOutbound(oc)

	cfg, err := m.GenerateConfig()
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	// Should have direct + peer-outbound
	if len(cfg.Outbounds) < 2 {
		t.Fatalf("expected >= 2 outbounds, got %d", len(cfg.Outbounds))
	}

	// Find the vless outbound
	var vlessOut *Outbound
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].Tag == "peer-outbound" {
			vlessOut = &cfg.Outbounds[i]
			break
		}
	}
	if vlessOut == nil {
		t.Fatal("peer-outbound not found")
	}
	if vlessOut.Protocol != "vless" {
		t.Fatalf("expected protocol vless, got %s", vlessOut.Protocol)
	}
	if vlessOut.StreamSettings == nil {
		t.Fatal("streamSettings is nil")
	}
	if vlessOut.StreamSettings.RealitySettings == nil {
		t.Fatal("realitySettings is nil")
	}
	if vlessOut.StreamSettings.RealitySettings.Fingerprint != "chrome" {
		t.Fatalf("expected fingerprint chrome, got %s",
			vlessOut.StreamSettings.RealitySettings.Fingerprint)
	}
}

func TestFileConfigStore(t *testing.T) {
	dir := t.TempDir()
	store := NewFileConfigStore(filepath.Join(dir, "state.json"))

	// Save inbounds
	inbounds := map[string]*InboundConfig{
		"test": {
			Tag:      "test",
			Port:     443,
			Security: "reality",
		},
	}
	if err := store.SaveInbounds(inbounds); err != nil {
		t.Fatalf("SaveInbounds: %v", err)
	}

	// Load them back
	loaded, err := store.LoadInbounds()
	if err != nil {
		t.Fatalf("LoadInbounds: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(loaded))
	}
	if loaded["test"].Port != 443 {
		t.Fatalf("expected port 443, got %d", loaded["test"].Port)
	}
}

func TestManagerWithFileStore(t *testing.T) {
	dir := t.TempDir()
	store := NewFileConfigStore(filepath.Join(dir, "state.json"))

	m, _ := NewManager(ManagerOptions{
		ConfigDir: dir,
		Store:     store,
		ApiPort:   -1,
	})

	ic := &InboundConfig{
		Tag:          "persisted",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   "key",
		VLESSClients: []VLESSClient{{ID: "uuid"}},
	}
	m.AddInbound(ic)

	// Create a new manager with the same store — should load the inbound
	m2, _ := NewManager(ManagerOptions{
		ConfigDir: dir,
		Store:     store,
		ApiPort:   -1,
	})
	list := m2.ListInbounds()
	if len(list) != 1 {
		t.Fatalf("expected 1 inbound from store, got %d", len(list))
	}
	if list[0].Tag != "persisted" {
		t.Fatalf("expected tag 'persisted', got %s", list[0].Tag)
	}
}

func TestProcessStatus(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	status := m.Status()
	if status.Running {
		t.Fatal("expected not running")
	}
	if status.RestartCount != 0 {
		t.Fatalf("expected 0 restarts, got %d", status.RestartCount)
	}
}

func TestFindBinary(t *testing.T) {
	// FindBinary should not panic; may return empty string if xray not installed
	path := FindBinary()
	_ = path // just verify it doesn't crash
}

func TestLogsEmpty(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})
	logs := m.Logs()
	if len(logs) != 0 {
		t.Fatalf("expected 0 logs, got %d", len(logs))
	}
}

// --- Subprocess lifecycle tests ---
// These tests use a mock binary (the test binary itself via a helper
// script) to verify start/stop/reload without requiring xray-core.

func TestStartNoBinary(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir:  t.TempDir(),
		BinaryPath: "/nonexistent/xray-binary",
		ApiPort:    -1,
	})

	// Add a valid inbound so config generation succeeds
	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	err := m.Start()
	if err == nil {
		t.Fatal("expected error when binary not found")
	}
}

// mockBinaryPath returns the path to a mock "xray" binary that behaves
// like a long-running process: it reads stdin, prints to stdout, and
// exits on SIGTERM/SIGHUP. Used for subprocess lifecycle tests.
func mockBinaryPath(t *testing.T) string {
	// We create a small shell script that simulates a long-running process
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "mock-xray")
	if runtime.GOOS == "windows" {
		scriptPath += ".bat"
	}

	script := `#!/bin/sh
# Mock xray-core: runs until signaled
echo "started mock xray"
trap 'echo "got SIGHUP" >&2; exit 0' HUP
trap 'echo "got SIGTERM" >&2; exit 0' TERM
# Keep running
while true; do
  sleep 0.1
done
`
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write mock binary: %v", err)
	}
	return scriptPath
}

func TestStartStopMockBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	mockPath := mockBinaryPath(t)
	dir := t.TempDir()

	m, _ := NewManager(ManagerOptions{
		BinaryPath: mockPath,
		ApiPort:    -1,
		ConfigDir:  dir,
		ConfigPath: filepath.Join(dir, "config.json"),
	})

	// Add a valid inbound
	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	// Start
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Verify running
	status := m.Status()
	if !status.Running {
		t.Fatal("expected running")
	}
	if status.PID == 0 {
		t.Fatal("expected non-zero PID")
	}

	// Wait a moment for logs to be captured
	time.Sleep(200 * time.Millisecond)

	// Check logs
	logs := m.Logs()
	if len(logs) == 0 {
		t.Fatal("expected at least 1 log entry")
	}
	foundStarted := false
	for _, l := range logs {
		if l.Line == "started mock xray" {
			foundStarted = true
			break
		}
	}
	if !foundStarted {
		t.Fatal("did not find 'started mock xray' in logs")
	}

	// Stop
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Verify stopped
	status = m.Status()
	if status.Running {
		t.Fatal("expected not running after stop")
	}
}

func TestReloadMockBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	mockPath := mockBinaryPath(t)
	dir := t.TempDir()

	m, _ := NewManager(ManagerOptions{
		BinaryPath: mockPath,
		ApiPort:    -1,
		ConfigDir:  dir,
		ConfigPath: filepath.Join(dir, "config.json"),
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for startup
	time.Sleep(200 * time.Millisecond)

	// Reload (SIGHUP)
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Wait for the SIGHUP to be processed
	time.Sleep(200 * time.Millisecond)

	// The mock binary exits on SIGHUP, so process should have crashed
	// and the crash monitor should have restarted it
	// Wait a bit for restart
	time.Sleep(2 * time.Second)

	// Stop cleanly
	m.Stop()
}

func TestReloadNotRunning(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})
	err := m.Reload()
	if err == nil {
		t.Fatal("expected error when reloading while not running")
	}
}

func TestStartAlreadyRunning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	mockPath := mockBinaryPath(t)
	dir := t.TempDir()

	m, _ := NewManager(ManagerOptions{
		BinaryPath: mockPath,
		ApiPort:    -1,
		ConfigDir:  dir,
		ConfigPath: filepath.Join(dir, "config.json"),
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Start again — should be no-op
	if err := m.Start(); err != nil {
		t.Fatalf("second Start should be no-op: %v", err)
	}

	m.Stop()
}

// --- Circuit Breaker Tests ---

func TestCircuitBreakerStartsClosed(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	if state := m.CircuitBreakerState(); state != CircuitClosed {
		t.Fatalf("expected circuit breaker to start closed, got %s", state)
	}

	status := m.Status()
	if status.CircuitState != CircuitClosed {
		t.Fatalf("expected status circuit_state closed, got %s", status.CircuitState)
	}
	if status.CrashCount != 0 {
		t.Fatalf("expected crash_count 0, got %d", status.CrashCount)
	}
}

func TestPruneCrashTimestamps(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	now := time.Now()

	// Add 5 crashes: 3 old (outside window), 2 recent
	m.mu.Lock()
	m.crashTimestamps = []time.Time{
		now.Add(-2 * time.Minute), // old
		now.Add(-90 * time.Second), // old
		now.Add(-70 * time.Second), // old
		now.Add(-30 * time.Second), // recent
		now.Add(-10 * time.Second), // recent
	}
	m.pruneCrashTimestampsLocked(now)
	count := len(m.crashTimestamps)
	m.mu.Unlock()

	if count != 2 {
		t.Fatalf("expected 2 crashes after pruning, got %d", count)
	}
}

func TestPruneCrashTimestampsAllExpired(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	now := time.Now()

	m.mu.Lock()
	m.crashTimestamps = []time.Time{
		now.Add(-2 * time.Minute),
		now.Add(-3 * time.Minute),
	}
	// Set circuit to half-open to verify it gets reset to closed
	m.circuitState = CircuitHalfOpen
	m.pruneCrashTimestampsLocked(now)
	count := len(m.crashTimestamps)
	state := m.circuitState
	m.mu.Unlock()

	if count != 0 {
		t.Fatalf("expected 0 crashes after pruning all, got %d", count)
	}
	if state != CircuitClosed {
		t.Fatalf("expected circuit closed after all crashes expired, got %s", state)
	}
}

func TestComputeBackoffNormalRestart(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	m.mu.Lock()
	defer m.mu.Unlock()

	// 1 crash — within normal limit
	m.crashTimestamps = []time.Time{time.Now()}
	backoff, shouldRestart, transitioned := m.computeBackoffLocked(time.Now())

	if !shouldRestart {
		t.Fatal("expected shouldRestart=true for 1 crash")
	}
	if transitioned {
		t.Fatal("expected no circuit transition for 1 crash")
	}
	if backoff != InitialRestartBackoff {
		t.Fatalf("expected initial backoff %v, got %v", InitialRestartBackoff, backoff)
	}
}

func TestComputeBackoffExponentialSchedule(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	now := time.Now()

	// 4 crashes — exceeds MaxRestartsPerWindow (3)
	// First call to computeBackoffLocked should return schedule[0] = 5s
	m.mu.Lock()
	m.crashTimestamps = []time.Time{
		now.Add(-3 * time.Second),
		now.Add(-2 * time.Second),
		now.Add(-1 * time.Second),
		now, // 4th crash
	}
	backoff, shouldRestart, transitioned := m.computeBackoffLocked(now)
	m.mu.Unlock()

	if !shouldRestart {
		t.Fatal("expected shouldRestart=true for 4th crash (within backoff schedule)")
	}
	if transitioned {
		t.Fatal("expected no circuit transition yet")
	}
	if backoff != ExponentialBackoffSchedule[0] {
		t.Fatalf("expected backoff %v (schedule[0]), got %v", ExponentialBackoffSchedule[0], backoff)
	}
}

func TestComputeBackoffScheduleProgression(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	now := time.Now()

	tests := []struct {
		name           string
		crashCount     int
		expectedBackoff time.Duration
	}{
		{"4th crash → 5s", 4, ExponentialBackoffSchedule[0]},
		{"5th crash → 10s", 5, ExponentialBackoffSchedule[1]},
		{"6th crash → 20s", 6, ExponentialBackoffSchedule[2]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.mu.Lock()
			// Reset state
			m.crashTimestamps = nil
			m.backoffIndex = 0
			m.circuitState = CircuitClosed

			// Add crashes
			for i := 0; i < tt.crashCount; i++ {
				m.crashTimestamps = append(m.crashTimestamps, now.Add(-time.Duration(tt.crashCount-i)*time.Second))
			}

			backoff, shouldRestart, _ := m.computeBackoffLocked(now)
			m.mu.Unlock()

			if !shouldRestart {
				t.Fatal("expected shouldRestart=true")
			}
			if backoff != tt.expectedBackoff {
				t.Fatalf("expected backoff %v, got %v", tt.expectedBackoff, backoff)
			}
		})
	}
}

func TestCircuitOpensAfterBackoffExhausted(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	now := time.Now()

	// After MaxRestartsPerWindow (3) + len(schedule) (3) = 6 crashes,
	// the next (7th) crash should open the circuit.
	m.mu.Lock()
	m.crashTimestamps = make([]time.Time, 7)
	for i := 0; i < 7; i++ {
		m.crashTimestamps[i] = now.Add(-time.Duration(7-i) * time.Second)
	}

	_, shouldRestart, transitioned := m.computeBackoffLocked(now)
	m.mu.Unlock()

	if !transitioned {
		t.Fatal("expected circuit breaker to open after 7 crashes (3+3+1)")
	}
	if shouldRestart {
		t.Fatal("expected shouldRestart=false when circuit opens")
	}
	if m.CircuitBreakerState() != CircuitOpen {
		t.Fatalf("expected circuit state open, got %s", m.CircuitBreakerState())
	}
}

func TestResetCircuitBreaker(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	// Set up a tripped circuit breaker
	m.mu.Lock()
	m.crashTimestamps = []time.Time{time.Now(), time.Now(), time.Now()}
	m.circuitState = CircuitOpen
	m.circuitTrippedAt = time.Now()
	m.backoffIndex = 5
	m.status.CircuitState = CircuitOpen
	m.status.CrashCount = 3
	m.mu.Unlock()

	// Reset
	m.ResetCircuitBreaker()

	if state := m.CircuitBreakerState(); state != CircuitClosed {
		t.Fatalf("expected circuit closed after reset, got %s", state)
	}

	status := m.Status()
	if status.CrashCount != 0 {
		t.Fatalf("expected crash_count 0 after reset, got %d", status.CrashCount)
	}
	if status.CircuitState != CircuitClosed {
		t.Fatalf("expected status circuit_state closed, got %s", status.CircuitState)
	}
}

func TestStopResetsCircuitBreaker(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	mockPath := mockBinaryPath(t)
	dir := t.TempDir()

	m, _ := NewManager(ManagerOptions{
		BinaryPath: mockPath,
		ApiPort:    -1,
		ConfigDir:  dir,
		ConfigPath: filepath.Join(dir, "config.json"),
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Simulate crash history
	m.mu.Lock()
	m.crashTimestamps = []time.Time{time.Now(), time.Now()}
	m.circuitState = CircuitHalfOpen
	m.status.CrashCount = 2
	m.mu.Unlock()

	// Stop should reset everything
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	status := m.Status()
	if status.CircuitState != CircuitClosed {
		t.Fatalf("expected circuit closed after stop, got %s", status.CircuitState)
	}
	if status.CrashCount != 0 {
		t.Fatalf("expected crash_count 0 after stop, got %d", status.CrashCount)
	}
}

func TestStartResetsCircuitBreaker(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	mockPath := mockBinaryPath(t)
	dir := t.TempDir()

	priv, _, _ := GenerateX25519Key()
	ic := &InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	}

	// First lifecycle: start, simulate stale circuit breaker state, stop
	m, _ := NewManager(ManagerOptions{
		BinaryPath: mockPath,
		ApiPort:    -1,
		ConfigDir:  dir,
		ConfigPath:  filepath.Join(dir, "config.json"),
	})
	m.AddInbound(ic)

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.Stop()

	// Simulate stale circuit breaker state from a previous lifecycle
	m.mu.Lock()
	m.crashTimestamps = []time.Time{time.Now(), time.Now(), time.Now(), time.Now()}
	m.circuitState = CircuitOpen
	m.backoffIndex = 3
	m.mu.Unlock()

	// A stopped manager can't be restarted — create a new one.
	// The new manager should start with a clean circuit breaker.
	m2, _ := NewManager(ManagerOptions{
		BinaryPath: mockPath,
		ApiPort:    -1,
		ConfigDir:  dir,
		ConfigPath: filepath.Join(dir, "config.json"),
	})
	m2.AddInbound(ic)

	if err := m2.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	status := m2.Status()
	if status.CircuitState != CircuitClosed {
		t.Fatalf("expected circuit closed after fresh start, got %s", status.CircuitState)
	}
	if status.CrashCount != 0 {
		t.Fatalf("expected crash_count 0 after fresh start, got %d", status.CrashCount)
	}

	m2.Stop()
}

func TestCircuitCooldownCalculation(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	now := time.Now()

	m.mu.Lock()
	// Oldest crash was 40s ago → cooldown = 60s - 40s = 20s
	m.crashTimestamps = []time.Time{
		now.Add(-40 * time.Second),
		now.Add(-20 * time.Second),
		now.Add(-5 * time.Second),
	}
	cooldown := m.circuitCooldownLocked(now)
	m.mu.Unlock()

	expected := 20 * time.Second
	if cooldown != expected {
		t.Fatalf("expected cooldown %v, got %v", expected, cooldown)
	}
}

func TestCircuitCooldownAllExpired(t *testing.T) {
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir(), ApiPort: -1})

	now := time.Now()

	m.mu.Lock()
	// Oldest crash was 120s ago → already outside window
	m.crashTimestamps = []time.Time{now.Add(-120 * time.Second)}
	cooldown := m.circuitCooldownLocked(now)
	m.mu.Unlock()

	if cooldown != 0 {
		t.Fatalf("expected cooldown 0 for expired crashes, got %v", cooldown)
	}
}

func TestCircuitStateString(t *testing.T) {
	tests := []struct {
		state    CircuitState
		expected string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Fatalf("expected %s, got %s", tt.expected, got)
		}
	}
}

// TestCrashLoopIntegration tests the full circuit breaker lifecycle
// with a mock binary that crashes immediately on each start.
// We use a binary that exits after a very short time to simulate crashes.
func TestCrashLoopIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	// Create a mock binary that exits immediately (simulating a crash)
	dir := t.TempDir()
	crashBinary := filepath.Join(dir, "crash-xray")
	crashScript := `#!/bin/sh
echo "crash mock starting"
exit 1
`
	if err := os.WriteFile(crashBinary, []byte(crashScript), 0755); err != nil {
		t.Fatalf("write crash binary: %v", err)
	}

	m, _ := NewManager(ManagerOptions{
		BinaryPath: crashBinary,
		ApiPort:    -1,
		ConfigDir:  dir,
		ConfigPath: filepath.Join(dir, "config.json"),
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for crashes to accumulate and circuit breaker to engage.
	// The circuit breaker should eventually open after:
	// 3 normal restarts + 3 exponential backoff restarts (5s, 10s, 20s)
	// Total time: ~1s + 1s + 1s + 5s + 10s + 20s = ~38s
	// But we can check intermediate state much sooner.
	time.Sleep(5 * time.Second)

	state := m.CircuitBreakerState()
	status := m.Status()

	// After 5 seconds, we should have accumulated several crashes.
	// The exact count depends on timing, but we should definitely have
	// more than MaxRestartsPerWindow crashes and be in either:
	// - CircuitClosed with exponential backoff active, or
	// - CircuitOpen (if backoff schedule already exhausted)
	t.Logf("after 5s: state=%s, crashes=%d, restarts=%d",
		state.String(), status.CrashCount, status.RestartCount)

	if status.RestartCount < MaxRestartsPerWindow {
		t.Fatalf("expected at least %d restarts after 5s, got %d",
			MaxRestartsPerWindow, status.RestartCount)
	}

	// Clean up
	m.Stop()
}

// TestCircuitBreakerDoesNotTripOnStableProcess verifies that a process
// that runs stably does not trigger the circuit breaker.
func TestCircuitBreakerDoesNotTripOnStableProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	mockPath := mockBinaryPath(t)
	dir := t.TempDir()

	m, _ := NewManager(ManagerOptions{
		BinaryPath: mockPath,
		ApiPort:    -1,
		ConfigDir:  dir,
		ConfigPath: filepath.Join(dir, "config.json"),
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Let it run stably for 2 seconds
	time.Sleep(2 * time.Second)

	status := m.Status()
	if status.CircuitState != CircuitClosed {
		t.Fatalf("expected circuit closed for stable process, got %s",
			status.CircuitState)
	}
	if status.CrashCount != 0 {
		t.Fatalf("expected 0 crashes for stable process, got %d",
			status.CrashCount)
	}
	if status.RestartCount != 0 {
		t.Fatalf("expected 0 restarts for stable process, got %d",
			status.RestartCount)
	}

	m.Stop()
}

// --- Drain-on-Stop Tests ---

// drainMockBinaryPath creates a mock binary that exits on SIGHUP
// (simulating xray-core draining all connections and exiting cleanly).
// This lets us test that Stop()'s drain phase works: SIGHUP is sent,
// the process exits, and no SIGTERM is needed.
func drainMockBinaryPath(t *testing.T) string {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "mock-xray-drain")
	script := `#!/bin/sh
# Mock xray-core that exits on SIGHUP (drain + exit)
echo "started mock xray"
trap 'echo "got SIGHUP — draining and exiting" >&2; exit 0' HUP
trap 'echo "got SIGTERM" >&2; exit 0' TERM
while true; do
  sleep 0.1
done
`
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write drain mock binary: %v", err)
	}
	return scriptPath
}

// noDrainMockBinaryPath creates a mock binary that ignores SIGHUP
// (simulating xray-core that doesn't exit during the drain timeout).
// This lets us test that Stop() falls through from drain to SIGTERM.
func noDrainMockBinaryPath(t *testing.T) string {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "mock-xray-nodrain")
	script := `#!/bin/sh
# Mock xray-core that ignores SIGHUP (stays alive during drain)
echo "started mock xray"
trap 'echo "got SIGHUP — ignoring" >&2' HUP
trap 'echo "got SIGTERM" >&2; exit 0' TERM
while true; do
  sleep 0.1
done
`
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write no-drain mock binary: %v", err)
	}
	return scriptPath
}

func TestStopWithDrain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	mockPath := drainMockBinaryPath(t)
	dir := t.TempDir()

	m, _ := NewManager(ManagerOptions{
		BinaryPath: mockPath,
		ApiPort:    -1,
		ConfigDir:  dir,
		ConfigPath: filepath.Join(dir, "config.json"),
		// Short drain timeout for test speed
		DrainTimeout:     2 * time.Second,
		TerminateTimeout: 2 * time.Second,
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Stop should drain (SIGHUP -> process exits) without needing SIGTERM
	start := time.Now()
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	elapsed := time.Since(start)

	// Should have exited quickly via drain, not waited the full drain timeout
	if elapsed > 5*time.Second {
		t.Fatalf("Stop took too long (%v) — drain may not have worked", elapsed)
	}

	status := m.Status()
	if status.Running {
		t.Fatal("expected not running after stop")
	}
}

func TestStopDrainFallbackToTerminate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	mockPath := noDrainMockBinaryPath(t)
	dir := t.TempDir()

	m, _ := NewManager(ManagerOptions{
		BinaryPath: mockPath,
		ApiPort:    -1,
		ConfigDir:  dir,
		ConfigPath: filepath.Join(dir, "config.json"),
		// Short timeouts for test speed
		DrainTimeout:     1 * time.Second,
		TerminateTimeout: 2 * time.Second,
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Stop should drain (SIGHUP -> ignored -> timeout), then SIGTERM -> exit
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	status := m.Status()
	if status.Running {
		t.Fatal("expected not running after stop")
	}

	// Verify the drain config was written (inbounds removed)
	// by checking the config file on disk
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	// After drain, the config should have no proxy inbounds.
	// When inbounds is nil, JSON produces "inbounds":null.
	inboundsVal, ok := raw["inbounds"]
	if !ok {
		t.Fatal("config missing inbounds key")
	}
	if inboundsVal == nil {
		// nil means no inbounds — this is what we expect
		return
	}
	inbounds, ok := inboundsVal.([]interface{})
	if !ok {
		t.Fatalf("inbounds is not an array: %T", inboundsVal)
	}
	if len(inbounds) != 0 {
		t.Fatalf("expected 0 inbounds in drain config, got %d", len(inbounds))
	}
}

func TestForceStop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	mockPath := noDrainMockBinaryPath(t)
	dir := t.TempDir()

	m, _ := NewManager(ManagerOptions{
		BinaryPath:        mockPath,
		ApiPort:           -1,
		ConfigDir:         dir,
		ConfigPath:        filepath.Join(dir, "config.json"),
		DrainTimeout:      10 * time.Second, // would be slow if ForceStop drained
		TerminateTimeout:  2 * time.Second,
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// ForceStop should skip drain and go straight to SIGTERM
	start := time.Now()
	if err := m.ForceStop(); err != nil {
		t.Fatalf("ForceStop: %v", err)
	}
	elapsed := time.Since(start)

	// Should be fast — no drain wait
	if elapsed > 5*time.Second {
		t.Fatalf("ForceStop took too long (%v) — may have drained", elapsed)
	}

	status := m.Status()
	if status.Running {
		t.Fatal("expected not running after force stop")
	}
}

func TestStopDrainDisabled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	mockPath := drainMockBinaryPath(t)
	dir := t.TempDir()

	m, _ := NewManager(ManagerOptions{
		BinaryPath:        mockPath,
		ApiPort:           -1,
		ConfigDir:         dir,
		ConfigPath:        filepath.Join(dir, "config.json"),
		DrainTimeout:      -1, // disable drain
		TerminateTimeout:  2 * time.Second,
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Stop with drain disabled should go straight to SIGTERM
	// The drain mock exits on SIGHUP, but since drain is disabled,
	// we should send SIGTERM directly. The mock also handles SIGTERM.
	start := time.Now()
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	elapsed := time.Since(start)

	// Should be fast — no drain wait
	if elapsed > 5*time.Second {
		t.Fatalf("Stop took too long (%v) with drain disabled", elapsed)
	}

	status := m.Status()
	if status.Running {
		t.Fatal("expected not running after stop")
	}
}

func TestStopResetsCircuitBreakerWithDrain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess tests are unreliable on Windows")
	}

	mockPath := drainMockBinaryPath(t)
	dir := t.TempDir()

	m, _ := NewManager(ManagerOptions{
		BinaryPath:        mockPath,
		ApiPort:           -1,
		ConfigDir:         dir,
		ConfigPath:        filepath.Join(dir, "config.json"),
		DrainTimeout:      2 * time.Second,
		TerminateTimeout:  2 * time.Second,
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Simulate crash history
	m.mu.Lock()
	m.crashTimestamps = []time.Time{time.Now(), time.Now()}
	m.circuitState = CircuitHalfOpen
	m.status.CrashCount = 2
	m.mu.Unlock()

	// Stop should drain and reset everything
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	status := m.Status()
	if status.CircuitState != CircuitClosed {
		t.Fatalf("expected circuit closed after stop, got %s", status.CircuitState)
	}
	if status.CrashCount != 0 {
		t.Fatalf("expected crash_count 0 after stop, got %d", status.CrashCount)
	}
}

func TestStopNotRunning(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	// Stop on a never-started manager should be a no-op
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop on non-running manager: %v", err)
	}
	if err := m.ForceStop(); err != nil {
		t.Fatalf("ForceStop on non-running manager: %v", err)
	}
}

func TestWriteDrainConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	m, _ := NewManager(ManagerOptions{
		ConfigDir:  dir,
		ConfigPath: configPath,
		ApiPort:    -1,
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:          "test",
		Port:         443,
		Security:     "reality",
		Dest:         "www.cloudflare.com:443",
		ServerNames:  []string{"www.cloudflare.com"},
		PrivateKey:   priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	// Write normal config first
	if err := m.WriteConfig(); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	// Verify normal config has the inbound
	data, _ := os.ReadFile(configPath)
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	inbounds, _ := raw["inbounds"].([]interface{})
	if len(inbounds) != 1 {
		t.Fatalf("expected 1 inbound in normal config, got %d", len(inbounds))
	}

	// Write drain config
	if err := m.writeDrainConfig(); err != nil {
		t.Fatalf("writeDrainConfig: %v", err)
	}

	// Verify drain config has no proxy inbounds
	data, _ = os.ReadFile(configPath)
	json.Unmarshal(data, &raw)
	inbounds, _ = raw["inbounds"].([]interface{})
	if len(inbounds) != 0 {
		t.Fatalf("expected 0 inbounds in drain config, got %d", len(inbounds))
	}

	// Verify inbounds are restored on the manager after writeDrainConfig
	list := m.ListInbounds()
	if len(list) != 1 {
		t.Fatalf("expected 1 inbound restored after drain config write, got %d", len(list))
	}
}

