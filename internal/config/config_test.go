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
			IdentityFile: "/tmp/test-identity.pem",
			Fingerprint:  "abc123fingerprint",
			Hostname:     "test-node",
			WebAddr:      ":8080",
		},
		Mesh: MeshConfig{
			Port: 51820,
		},
		Peers: []PeerConfig{
			{
				PublicKey:  "peerkey123",
				Endpoint:   "1.2.3.4:51820",
				AllowedIPs: []string{"10.10.1.1/32"},
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

	if loaded.Node.IdentityFile != original.Node.IdentityFile {
		t.Errorf("IdentityFile = %q, want %q", loaded.Node.IdentityFile, original.Node.IdentityFile)
	}
	if loaded.Node.Fingerprint != original.Node.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q", loaded.Node.Fingerprint, original.Node.Fingerprint)
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

// TestRelayEnabledDefaultFalse verifies that Default() produces a
// RelayNodeConfig with Enabled=false. This is critical for topology
// role derivation: a node using Default() must NOT appear as a relay
// just because MaxCircuits > 0.
func TestRelayEnabledDefaultFalse(t *testing.T) {
	cfg := Default()
	if cfg.Proxy.Relay.Enabled {
		t.Error("Default() Relay.Enabled = true, want false")
	}
	// Relay tuning params should still be populated for relay-enabled nodes.
	if cfg.Proxy.Relay.MaxCircuits != 1024 {
		t.Errorf("MaxCircuits = %d, want 1024 (tuning defaults preserved)", cfg.Proxy.Relay.MaxCircuits)
	}
}

// TestRelayEnabledNotSetByDefault verifies that loading a minimal
// config (no relay section) does NOT enable the relay.
func TestRelayEnabledNotSetByDefault(t *testing.T) {
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

	if cfg.Proxy.Relay.Enabled {
		t.Error("Relay.Enabled = true after loading minimal config, want false")
	}
}

// TestRelayEnabledTrueViaYAML verifies that a config YAML with
// relay.enabled: true correctly sets the field.
func TestRelayEnabledTrueViaYAML(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	yamlContent := []byte("node:\n  hostname: relay-node\nproxy:\n  relay:\n    enabled: true\n    max_circuits: 2048\n")
	if err := os.WriteFile(path, yamlContent, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if !cfg.Proxy.Relay.Enabled {
		t.Error("Relay.Enabled = false, want true")
	}
	if cfg.Proxy.Relay.MaxCircuits != 2048 {
		t.Errorf("MaxCircuits = %d, want 2048", cfg.Proxy.Relay.MaxCircuits)
	}
}

// TestRelayEnabledRoundTripSaveLoad verifies that Enabled=true
// survives a save/load cycle.
func TestRelayEnabledRoundTripSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	original := &Config{
		Node: NodeConfig{Hostname: "relay-test"},
		Mesh: MeshConfig{Port: 51820},
		Proxy: ProxyConfig{
			Relay: RelayNodeConfig{
				Enabled:     true,
				MaxCircuits: 512,
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

	if !loaded.Proxy.Relay.Enabled {
		t.Error("Relay.Enabled = false after round-trip, want true")
	}
	if loaded.Proxy.Relay.MaxCircuits != 512 {
		t.Errorf("MaxCircuits = %d, want 512", loaded.Proxy.Relay.MaxCircuits)
	}
}

// TestLegacyTOTPSecretDetection verifies that a deprecated totp_secret
// in config.yaml is detected and exposed via LegacyTOTPSecret().
func TestLegacyTOTPSecretDetection(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	yamlContent := []byte("node:\n  hostname: test\nauth:\n  totp_secret: \"JBSWY3DPEHPK3PXP\"\n  totp_issuer: \"TestIssuer\"\n")
	if err := os.WriteFile(path, yamlContent, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	// The legacy secret should be captured for migration
	if cfg.Auth.LegacyTOTPSecret() != "JBSWY3DPEHPK3PXP" {
		t.Errorf("LegacyTOTPSecret = %q, want 'JBSWY3DPEHPK3PXP'", cfg.Auth.LegacyTOTPSecret())
	}

	// TOTPIssuer should still be loaded normally
	if cfg.Auth.TOTPIssuer != "TestIssuer" {
		t.Errorf("TOTPIssuer = %q, want 'TestIssuer'", cfg.Auth.TOTPIssuer)
	}
}

// TestNoLegacyTOTPSecret verifies LegacyTOTPSecret is empty when
// the config doesn't contain totp_secret.
func TestNoLegacyTOTPSecret(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	yamlContent := []byte("node:\n  hostname: test\nauth:\n  totp_issuer: \"TestIssuer\"\n")
	if err := os.WriteFile(path, yamlContent, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if cfg.Auth.LegacyTOTPSecret() != "" {
		t.Errorf("LegacyTOTPSecret should be empty, got %q", cfg.Auth.LegacyTOTPSecret())
	}
}

// TestAdvertiseEndpointsMultiEndpoint verifies that the advertise_endpoints
// YAML field is parsed correctly into a list of strings.
func TestAdvertiseEndpointsMultiEndpoint(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	yamlContent := []byte("node:\n  hostname: dualstack\nmesh:\n  port: 51820\np2p:\n  enabled: true\n  advertise_endpoints:\n    - 203.0.113.99:51820\n    - \"[2001:db8::1]:51820\"\n")
	if err := os.WriteFile(path, yamlContent, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if len(cfg.P2P.AdvertiseEndpoints) != 2 {
		t.Fatalf("AdvertiseEndpoints length = %d, want 2", len(cfg.P2P.AdvertiseEndpoints))
	}
	if cfg.P2P.AdvertiseEndpoints[0] != "203.0.113.99:51820" {
		t.Errorf("AdvertiseEndpoints[0] = %q, want %q", cfg.P2P.AdvertiseEndpoints[0], "203.0.113.99:51820")
	}
	if cfg.P2P.AdvertiseEndpoints[1] != "[2001:db8::1]:51820" {
		t.Errorf("AdvertiseEndpoints[1] = %q, want %q", cfg.P2P.AdvertiseEndpoints[1], "[2001:db8::1]:51820")
	}
}

// TestAdvertiseEndpointLegacyBackwardCompat verifies that the old
// advertise_endpoint (singular) YAML field is still accepted and migrated
// to AdvertiseEndpoints as a single-element list.
func TestAdvertiseEndpointLegacyBackwardCompat(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	yamlContent := []byte("node:\n  hostname: legacy\nmesh:\n  port: 51820\np2p:\n  enabled: true\n  advertise_endpoint: 203.0.113.99:51820\n")
	if err := os.WriteFile(path, yamlContent, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if len(cfg.P2P.AdvertiseEndpoints) != 1 {
		t.Fatalf("AdvertiseEndpoints length = %d, want 1 (from legacy field)", len(cfg.P2P.AdvertiseEndpoints))
	}
	if cfg.P2P.AdvertiseEndpoints[0] != "203.0.113.99:51820" {
		t.Errorf("AdvertiseEndpoints[0] = %q, want %q", cfg.P2P.AdvertiseEndpoints[0], "203.0.113.99:51820")
	}
}

// TestLoadWithUnknownXraySection verifies that a config file containing
// a leftover xray: section (from the pre-refactor era) loads without
// error. The YAML decoder must use KnownFields(false) (the yaml.v3
// default) so that unknown top-level sections are silently tolerated
// rather than causing a hard-fail.
func TestLoadWithUnknownXraySection(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	yamlContent := []byte("node:\n  hostname: test-node\nmesh:\n  port: 51820\nxray:\n  api:\n    address: \"127.0.0.1:10085\"\n  loglevel: warning\nmonitoring:\n  interval: 15\n")
	if err := os.WriteFile(path, yamlContent, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load should succeed with unknown xray: section, got error: %v", err)
	}

	if cfg.Node.Hostname != "test-node" {
		t.Errorf("Hostname = %q, want %q", cfg.Node.Hostname, "test-node")
	}
	if cfg.Mesh.Port != 51820 {
		t.Errorf("Port = %d, want 51820", cfg.Mesh.Port)
	}
	if cfg.Monitoring.Interval != 15 {
		t.Errorf("Interval = %d, want 15", cfg.Monitoring.Interval)
	}
}

// TestLoadWithMultipleUnknownSections verifies that multiple unknown
// top-level sections are all tolerated without error.
func TestLoadWithMultipleUnknownSections(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	yamlContent := []byte("node:\n  hostname: test\nmesh:\n  port: 51820\nxray:\n  foo: bar\nold_section:\n  key: value\nanother_unknown:\n  nested:\n    deep: true\n")
	if err := os.WriteFile(path, yamlContent, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load should succeed with multiple unknown sections, got error: %v", err)
	}

	if cfg.Node.Hostname != "test" {
		t.Errorf("Hostname = %q, want %q", cfg.Node.Hostname, "test")
	}
}

// TestSavePermissionDenied verifies that config.Save returns a non-nil error
// (equivalent to a non-zero exit / fatal condition) when the config cannot be
// written — for example, when a path component in the parent directory is a
// file rather than a directory (ENOTDIR), or when the filesystem is read-only.
//
// This is a safety contract: Save must not silently succeed when it cannot
// persist the config — a nil return would mean the caller believes the config
// was written when it wasn't.
func TestSavePermissionDenied(t *testing.T) {
	// Strategy: create a regular file where a directory component is expected.
	// os.WriteFile will fail because it cannot treat a file as a directory.
	tmpDir := t.TempDir()

	// Create a regular file named "blocker" in the temp directory.
	blocker := filepath.Join(tmpDir, "blocker")
	if err := os.WriteFile(blocker, []byte("block"), 0644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg := &Config{
		Node: NodeConfig{Hostname: "test"},
		Mesh: MeshConfig{Port: 51820},
	}

	// Attempt to save at a path where "blocker" is treated as a directory.
	// e.g., block/config.yaml → block is a file, not a directory → ENOTDIR.
	savePath := filepath.Join(blocker, "config.yaml")
	err := Save(savePath, cfg)

	// The contract: Save MUST return an error when it cannot write.
	if err == nil {
		t.Fatalf("Save should fail (path component is a file, not a directory), but returned nil")
	}

	// Also verify: write-protect the parent directory directly.
	// On non-root systems or inside containers without CAP_DAC_OVERRIDE,
	// this should also fail.
	protectedDir := filepath.Join(tmpDir, "readonly")
	if err := os.Mkdir(protectedDir, 0000); err != nil {
		t.Fatalf("Mkdir error: %v", err)
	}
	defer os.Chmod(protectedDir, 0700)

	err = Save(filepath.Join(protectedDir, "config.yaml"), cfg)
	// Root can bypass DAC permissions, so we don't strictly require failure here.
	// The ENOTDIR case above is the reliable cross-privilege-level check.
	if err != nil {
		t.Logf("Save correctly failed on write-protected dir: %v", err)
	} else {
		t.Logf("Save succeeded on write-protected dir (expected under root with CAP_DAC_OVERRIDE)")
	}
}
