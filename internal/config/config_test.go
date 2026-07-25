package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Mesh.Port != 51820 {
		t.Errorf("default port = %d, want 51820", cfg.Mesh.Port)
	}
	if cfg.Monitoring.Interval != 15 {
		t.Errorf("default interval = %d, want 15", cfg.Monitoring.Interval)
	}
}

func TestLoadAndSave(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	// Save a config.
	original := &Config{
		Node: NodeConfig{
			Identity: "abcdef0123456789",
			Hostname: "test-node",
			WebAddr:  ":8080",
		},
		Mesh: MeshConfig{
			Port: 51820,
		},
		Peers: []PeerConfig{
			{
				PublicKey:   "peerkey123",
				Endpoint:    "1.2.3.4:51820",
				AllowedIPs:  []string{"10.10.1.1/32"},
				Obfuscation: "padded",
			},
		},
		Monitoring: MonitoringConfig{
			Collectors: []string{"collector1"},
			Interval:   15,
		},
	}

	if err := Save(path, original); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	// Load it back.
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if loaded.Node.Identity != original.Node.Identity {
		t.Errorf("Identity = %q, want %q", loaded.Node.Identity, original.Node.Identity)
	}
	if loaded.Node.Hostname != original.Node.Hostname {
		t.Errorf("Hostname = %q, want %q", loaded.Node.Hostname, original.Node.Hostname)
	}
	if loaded.Mesh.Port != original.Mesh.Port {
		t.Errorf("Port = %d, want %d", loaded.Mesh.Port, original.Mesh.Port)
	}
	if len(loaded.Peers) != 1 {
		t.Fatalf("Peers length = %d, want 1", len(loaded.Peers))
	}
	if loaded.Peers[0].PublicKey != "peerkey123" {
		t.Errorf("Peer[0] PublicKey = %q, want %q", loaded.Peers[0].PublicKey, "peerkey123")
	}
	if loaded.Peers[0].Obfuscation != "padded" {
		t.Errorf("Peer[0] Obfuscation = %q, want %q", loaded.Peers[0].Obfuscation, "padded")
	}
	if loaded.Monitoring.Interval != 15 {
		t.Errorf("Monitoring interval = %d, want 15", loaded.Monitoring.Interval)
	}
}

func TestLoadNonexistent(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Load should fail for nonexistent file")
	}
}

func TestLoadDefaultsApplied(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	// Write a minimal config with missing fields.
	minimal := []byte("node:\n  hostname: minimal\n")
	if err := os.WriteFile(path, minimal, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	// Defaults should be applied.
	if cfg.Mesh.Port != 51820 {
		t.Errorf("Port = %d, want default 51820", cfg.Mesh.Port)
	}
	if cfg.Monitoring.Interval != 15 {
		t.Errorf("Interval = %d, want default 15", cfg.Monitoring.Interval)
	}
	if cfg.Node.Hostname != "minimal" {
		t.Errorf("Hostname = %q, want %q", cfg.Node.Hostname, "minimal")
	}
}

// TestTransferConfigDefaults verifies that TransferConfig defaults
// are applied when not explicitly set (Gap 4).
func TestTransferConfigDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Transfer.MaxFileSize != DefaultMaxFileSize {
		t.Errorf("default MaxFileSize = %d, want %d", cfg.Transfer.MaxFileSize, DefaultMaxFileSize)
	}
	if cfg.Transfer.UploadDir != DefaultUploadDir {
		t.Errorf("default UploadDir = %q, want %q", cfg.Transfer.UploadDir, DefaultUploadDir)
	}
}

// TestTransferConfigLoadDefaults verifies that loading a config without
// a transfer section applies the default MaxFileSize and UploadDir.
func TestTransferConfigLoadDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	minimal := []byte("node:\n  hostname: test\n")
	if err := os.WriteFile(path, minimal, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if cfg.Transfer.MaxFileSize != DefaultMaxFileSize {
		t.Errorf("MaxFileSize = %d, want %d", cfg.Transfer.MaxFileSize, DefaultMaxFileSize)
	}
	if cfg.Transfer.UploadDir != DefaultUploadDir {
		t.Errorf("UploadDir = %q, want %q", cfg.Transfer.UploadDir, DefaultUploadDir)
	}
}

// TestTransferConfigCustomValues verifies that custom transfer config
// values are preserved through save/load.
func TestTransferConfigCustomValues(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	original := &Config{
		Node: NodeConfig{Hostname: "test"},
		Mesh: MeshConfig{Port: 51820},
		Transfer: TransferConfig{
			MaxFileSize: 500 * 1024 * 1024, // 500 MB
			UploadDir:   "/custom/uploads",
		},
	}

	if err := Save(path, original); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if loaded.Transfer.MaxFileSize != 500*1024*1024 {
		t.Errorf("MaxFileSize = %d, want %d", loaded.Transfer.MaxFileSize, 500*1024*1024)
	}
	if loaded.Transfer.UploadDir != "/custom/uploads" {
		t.Errorf("UploadDir = %q, want %q", loaded.Transfer.UploadDir, "/custom/uploads")
	}
}

// TestProxyConfigDefaults verifies that the proxy config defaults
// are populated when loading a config without proxy settings.
func TestProxyConfigDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	// Save a minimal config — no proxy section.
	original := &Config{
		Node: NodeConfig{Hostname: "test"},
		Mesh: MeshConfig{Port: 51820},
	}

	if err := Save(path, original); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	// Verify proxy defaults.
	if loaded.Proxy.ChunkerStrategy != "bounded-4k-64k" {
		t.Errorf("ChunkerStrategy = %q, want %q", loaded.Proxy.ChunkerStrategy, "bounded-4k-64k")
	}
	if loaded.Proxy.Circuit.IdleTimeout != 300 {
		t.Errorf("IdleTimeout = %d, want 300", loaded.Proxy.Circuit.IdleTimeout)
	}
	if loaded.Proxy.Circuit.KeepaliveInterval != 30 {
		t.Errorf("KeepaliveInterval = %d, want 30", loaded.Proxy.Circuit.KeepaliveInterval)
	}
	if loaded.Proxy.Circuit.NACKTimeout != 5 {
		t.Errorf("NACKTimeout = %d, want 5", loaded.Proxy.Circuit.NACKTimeout)
	}
	if loaded.Proxy.Circuit.OrphanTimeout != 30 {
		t.Errorf("OrphanTimeout = %d, want 30", loaded.Proxy.Circuit.OrphanTimeout)
	}
	if loaded.Proxy.Circuit.MaxReassemblyWindow != 256 {
		t.Errorf("MaxReassemblyWindow = %d, want 256", loaded.Proxy.Circuit.MaxReassemblyWindow)
	}
	if len(loaded.Proxy.Exit.AllowedPorts) != 2 {
		t.Errorf("AllowedPorts length = %d, want 2", len(loaded.Proxy.Exit.AllowedPorts))
	}
	if loaded.Proxy.Exit.AllowedPorts[0] != 80 || loaded.Proxy.Exit.AllowedPorts[1] != 443 {
		t.Errorf("AllowedPorts = %v, want [80 443]", loaded.Proxy.Exit.AllowedPorts)
	}
	if loaded.Proxy.Exit.AuditRetentionDays != 7 {
		t.Errorf("AuditRetentionDays = %d, want 7", loaded.Proxy.Exit.AuditRetentionDays)
	}
}

// TestProxyConfigCustomValues verifies custom proxy config values
// are preserved through save/load.
func TestProxyConfigCustomValues(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	original := &Config{
		Node: NodeConfig{Hostname: "test"},
		Mesh: MeshConfig{Port: 51820},
		Proxy: ProxyConfig{
			ChunkerStrategy: "fixed-16k",
			Circuit: CircuitLifecycleConfig{
				IdleTimeout:         600,
				KeepaliveInterval:   60,
				NACKTimeout:         10,
				OrphanTimeout:       60,
				MaxReassemblyWindow: 512,
			},
			Exit: ExitConfig{
				AllowedPorts:       []int{80, 443, 22},
				AllowAllPorts:      false,
				AuditLogDir:        "/var/log/meshdesk/exit-audit",
				AuditRetentionDays: 14,
			},
		},
	}

	if err := Save(path, original); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if loaded.Proxy.ChunkerStrategy != "fixed-16k" {
		t.Errorf("ChunkerStrategy = %q, want %q", loaded.Proxy.ChunkerStrategy, "fixed-16k")
	}
	if loaded.Proxy.Circuit.IdleTimeout != 600 {
		t.Errorf("IdleTimeout = %d, want 600", loaded.Proxy.Circuit.IdleTimeout)
	}
	if len(loaded.Proxy.Exit.AllowedPorts) != 3 {
		t.Errorf("AllowedPorts length = %d, want 3", len(loaded.Proxy.Exit.AllowedPorts))
	}
	if loaded.Proxy.Exit.AuditLogDir != "/var/log/meshdesk/exit-audit" {
		t.Errorf("AuditLogDir = %q, want %q", loaded.Proxy.Exit.AuditLogDir, "/var/log/meshdesk/exit-audit")
	}
}
