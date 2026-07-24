package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for a MeshDesk node.
type Config struct {
	Node       NodeConfig       `yaml:"node"`
	Mesh       MeshConfig       `yaml:"mesh"`
	Peers      []PeerConfig     `yaml:"peers"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
	Auth       AuthConfig       `yaml:"auth"`
}

// NodeConfig holds local node identity settings.
type NodeConfig struct {
	Identity string `yaml:"identity"` // WireGuard private key (hex); auto-generated if empty
	Hostname string `yaml:"hostname"` // auto-detected if empty
	WebAddr  string `yaml:"web"`      // e.g. ":8080"; empty = agent-only mode
}

// MeshConfig holds mesh-level settings.
type MeshConfig struct {
	Port int `yaml:"port"` // WireGuard listen port (default 51820)
}

// PeerConfig describes a single mesh peer.
type PeerConfig struct {
	PublicKey    string   `yaml:"public_key"`
	Endpoint     string   `yaml:"endpoint"`     // host:port; empty for roaming
	AllowedIPs   []string `yaml:"allowed_ips"`   // mesh IPs routed to this peer
	Capabilities []string `yaml:"capabilities"`  // what this peer can do on us
	Obfuscation  string   `yaml:"obfuscation"`   // none | padded | websocket
	PresharedKey string   `yaml:"preshared_key"` // optional WireGuard PSK
}

// MonitoringConfig holds monitoring/push settings.
type MonitoringConfig struct {
	Collectors []string `yaml:"collectors"` // peer IDs of collector nodes
	Interval   int      `yaml:"interval"`   // push interval in seconds
}

// AuthConfig holds web UI auth settings.
type AuthConfig struct {
	WebUsers []WebUser `yaml:"web_users"`
}

// WebUser is a web UI login account.
type WebUser struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

// Default returns a config with sensible defaults.
func Default() *Config {
	return &Config{
		Node: NodeConfig{
			WebAddr: "",
		},
		Mesh: MeshConfig{
			Port: 51820,
		},
		Monitoring: MonitoringConfig{
			Interval: 15,
		},
	}
}

// Load reads and parses a YAML config from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Mesh.Port == 0 {
		cfg.Mesh.Port = 51820
	}
	if cfg.Monitoring.Interval == 0 {
		cfg.Monitoring.Interval = 15
	}
	return cfg, nil
}

// Save writes the config to path as YAML.
func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
