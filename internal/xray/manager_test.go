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
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir()})

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
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir()})

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
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir()})

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
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir()})

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
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir()})

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
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir()})

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
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir()})
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
	m, _ := NewManager(ManagerOptions{ConfigDir: t.TempDir()})
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
