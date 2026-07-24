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
	WebSSH     WebSSHConfig     `yaml:"webssh"`
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
	PublicKey    string            `yaml:"public_key"`
	Endpoint     string            `yaml:"endpoint"`     // host:port; empty for roaming
	AllowedIPs   []string          `yaml:"allowed_ips"`   // mesh IPs routed to this peer
	Capabilities []string          `yaml:"capabilities"`  // what this peer can do on us
	Obfuscation  string            `yaml:"obfuscation"`   // none | padded | websocket
	PresharedKey string            `yaml:"preshared_key"` // optional WireGuard PSK
	ObfConfig    *ObfuscationOpts  `yaml:"obf_config,omitempty"` // per-peer obfuscation parameters

	// ServiceManage holds the list of service names this peer is allowed to
	// manage (start/stop/restart). Only meaningful when "service_manage"
	// appears in Capabilities. If empty with service_manage present, the
	// peer can manage all services (not recommended).
	ServiceManage []string `yaml:"service_manage,omitempty"`

	// FileTransferPaths restricts file_transfer capability to specific
	// directory prefixes. If empty with file_transfer present, no path
	// restriction is enforced (peer can access any path).
	FileTransferPaths []string `yaml:"file_transfer_paths,omitempty"`

	// MonitorScopes restricts monitor_read/monitor_write to specific
	// metric categories. If empty, all metrics are accessible.
	MonitorScopes []string `yaml:"monitor_scopes,omitempty"`
}

// ObfuscationOpts holds per-peer obfuscation parameters (AmneziaWG-style).
// These are only used when the peer's obfuscation mode is "padded".
type ObfuscationOpts struct {
	// H1-H4: non-overlapping ranges for WireGuard message type fields.
	// Format: [min, max]. Zero values mean "use defaults".
	H1 [2]uint32 `yaml:"h1"`
	H2 [2]uint32 `yaml:"h2"`
	H3 [2]uint32 `yaml:"h3"`
	H4 [2]uint32 `yaml:"h4"`

	// S1-S4: maximum random padding bytes for each message type.
	S1 int `yaml:"s1"`
	S2 int `yaml:"s2"`
	S3 int `yaml:"s3"`
	S4 int `yaml:"s4"`

	// Jc: junk train count (v2 feature, 0=disabled).
	Jc   int `yaml:"jc"`
	Jmin int `yaml:"jmin"`
	Jmax int `yaml:"jmax"`

	// PSK: hex-encoded pre-shared key for anti-probe challenge (32 bytes).
	// If set, handshake initiation packets must include a valid HMAC tag.
	PSK string `yaml:"psk"`

	// JitterMaxMs: maximum timing jitter in milliseconds (0=disabled).
	JitterMaxMs int `yaml:"jitter_max_ms"`

	// WSUseTLS: for websocket mode, whether to use wss:// (TLS).
	WSUseTLS bool `yaml:"ws_use_tls"`
}

// MonitoringConfig holds monitoring/push settings.
type MonitoringConfig struct {
	Collectors []string `yaml:"collectors"` // peer IDs of collector nodes
	Interval   int      `yaml:"interval"`   // push interval in seconds
	Port       int      `yaml:"port"`       // mesh-internal port for metric pushes (default 4191)
}

// AuthConfig holds web UI auth settings.
type AuthConfig struct {
	WebUsers []WebUser `yaml:"web_users"`
}

// WebSSHConfig holds settings for the WebSSH bridge.
type WebSSHConfig struct {
	// Port is the mesh-internal port for the SSH server on the target node.
	// Default: 2222.
	Port int `yaml:"port"`

	// HostKey is the SSH host private key (PEM-encoded). If empty, an
	// Ed25519 key is auto-generated on startup.
	HostKey string `yaml:"host_key"`

	// Shell is the default shell to launch. If empty, auto-detected via
	// /etc/passwd, falling back to /bin/bash then /bin/sh.
	Shell string `yaml:"shell"`

	// DialTimeout is how long the web server node waits when dialing
	// the target node's SSH server over the mesh VPN (seconds, default 10).
	DialTimeout int `yaml:"dial_timeout"`

	// ReadDeadline is the WebSocket read deadline for idle sessions
	// (seconds, default 300 = 5 minutes).
	ReadDeadline int `yaml:"read_deadline"`

	// WriteDeadline is the WebSocket write deadline (seconds, default 10).
	WriteDeadline int `yaml:"write_deadline"`

	// MaxSessions limits concurrent terminal sessions per node (default 256).
	MaxSessions int `yaml:"max_sessions"`
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
		WebSSH: WebSSHConfig{
			Port:         2222,
			DialTimeout:  10,
			ReadDeadline: 300,
			WriteDeadline: 10,
			MaxSessions:  256,
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
	if cfg.Monitoring.Port == 0 {
		cfg.Monitoring.Port = 4191
	}
	if cfg.WebSSH.Port == 0 {
		cfg.WebSSH.Port = 2222
	}
	if cfg.WebSSH.DialTimeout == 0 {
		cfg.WebSSH.DialTimeout = 10
	}
	if cfg.WebSSH.ReadDeadline == 0 {
		cfg.WebSSH.ReadDeadline = 300
	}
	if cfg.WebSSH.WriteDeadline == 0 {
		cfg.WebSSH.WriteDeadline = 10
	}
	if cfg.WebSSH.MaxSessions == 0 {
		cfg.WebSSH.MaxSessions = 256
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
