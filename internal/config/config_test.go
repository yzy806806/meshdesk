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
