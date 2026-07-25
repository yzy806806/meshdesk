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
	Transfer   TransferConfig   `yaml:"transfer"`
	Proxy      ProxyConfig      `yaml:"proxy,omitempty"`
}

// ProxyConfig holds settings for the anonymous proxy subsystem
// (multi-path dispersed transport). See docs/PROXY_DESIGN.md.
type ProxyConfig struct {
	// SS holds the Shadowsocks entry-point listener configuration.
	// Only needed on nodes that serve as proxy entry points.
	SS SSListenerConfig `yaml:"ss,omitempty"`

	// Circuit holds circuit lifecycle parameters.
	Circuit CircuitLifecycleConfig `yaml:"circuit,omitempty"`

	// ChunkerStrategy selects the chunking strategy: "fixed-16k"
	// or "bounded-4k-64k". Default: "bounded-4k-64k".
	ChunkerStrategy string `yaml:"chunker_strategy,omitempty"`

	// DebugFixedChunks forces uniform 16KB chunks for deterministic
	// testing. MUST be false in production.
	DebugFixedChunks bool `yaml:"debug_fixed_chunks,omitempty"`

	// Paths holds manually configured relay paths (Phase 1).
	// Each path is a list of relay node IDs (hex public keys).
	// When PathSelection.Mode is "auto", this is ignored.
	Paths [][]string `yaml:"paths,omitempty"`

	// PathSelection holds dynamic path selection configuration (Phase 2).
	// When enabled, the entry node automatically probes and selects
	// two disjoint paths based on RTT measurements.
	PathSelection PathSelectionConfig `yaml:"path_selection,omitempty"`

	// CFTunnel holds Cloudflare Tunnel configuration for exposing
	// the SS listener via CF's edge network (PROXY_DESIGN.md §2).
	// Only needed on entry nodes.
	CFTunnel CFTunnelYAMLConfig `yaml:"cf_tunnel,omitempty"`

	// Relay holds relay-node-specific configuration.
	// Only needed on nodes that serve as relay nodes.
	Relay RelayNodeConfig `yaml:"relay,omitempty"`

	// Exit holds exit-node-specific configuration.
	// Only needed on nodes that serve as exit nodes.
	Exit ExitConfig `yaml:"exit,omitempty"`
}

// PathSelectionConfig holds settings for dynamic path selection
// (PROXY_DESIGN.md §1.5, Phase 2).
type PathSelectionConfig struct {
	// Mode selects the path selection mode:
	//   "manual"  — use paths from ProxyConfig.Paths (Phase 1)
	//   "auto"    — probe and select best paths (Phase 2)
	// Default: "manual".
	Mode string `yaml:"mode,omitempty"`

	// MaxRelaysPerPath is the maximum number of relay hops per path.
	// Default: 2. Higher = more anonymity, more latency.
	MaxRelaysPerPath int `yaml:"max_relays_per_path,omitempty"`

	// ProbeTimeoutSec is the timeout for each relay probe (seconds).
	// Default: 3.
	ProbeTimeoutSec int `yaml:"probe_timeout_sec,omitempty"`

	// ProbeConcurrency limits concurrent probes.
	// Default: 8.
	ProbeConcurrency int `yaml:"probe_concurrency,omitempty"`

	// MaxCandidates is the maximum number of relays to probe.
	// Implements O(K) scaling per PROXY_DESIGN.md §1.5.
	// Default: 10.
	MaxCandidates int `yaml:"max_candidates,omitempty"`

	// ProbeCacheTTLSec is how long cached probe results are valid.
	// Default: 30.
	ProbeCacheTTLSec int `yaml:"probe_cache_ttl_sec,omitempty"`

	// ExitLatencyMatrix holds exit→region RTT data for exit selection.
	// Map key: exit node ID → map[region]RTT in milliseconds.
	// Used by SelectExit to pick the optimal exit for a target.
	ExitLatencyMatrix map[string]map[string]int `yaml:"exit_latency_matrix,omitempty"`
}

// CFTunnelYAMLConfig holds CF Tunnel settings for the config file.
// This maps to the CFTunnelConfig struct used by the tunnel manager.
type CFTunnelYAMLConfig struct {
	// Enabled controls whether the CF Tunnel is started on this node.
	// When true, the entry node runs cloudflared to expose its SS
	// listener via CF's edge network.
	Enabled bool `yaml:"enabled,omitempty"`

	// TunnelID is the Cloudflare Tunnel UUID.
	TunnelID string `yaml:"tunnel_id,omitempty"`

	// CredentialsFile is the path to the tunnel credentials JSON.
	CredentialsFile string `yaml:"credentials_file,omitempty"`

	// Hostname is the CF hostname that routes to this tunnel.
	// E.g., "proxy.example.com".
	Hostname string `yaml:"hostname,omitempty"`

	// OriginServer is the local address the tunnel forwards to.
	// Default: "127.0.0.1:8388" (the SS listener address).
	OriginServer string `yaml:"origin_server,omitempty"`

	// Region is the CF edge region preference. Empty = auto.
	Region string `yaml:"region,omitempty"`

	// LogLevel controls cloudflared's logging verbosity.
	// Default: "warn".
	LogLevel string `yaml:"log_level,omitempty"`

	// MetricsAddr is the cloudflared metrics server address.
	// Default: "127.0.0.1:36500".
	MetricsAddr string `yaml:"metrics_addr,omitempty"`

	// BinaryPath is the path to the cloudflared binary.
	// Empty = use "cloudflared" from PATH.
	BinaryPath string `yaml:"binary_path,omitempty"`

	// ReconnectRetries is the number of reconnection attempts.
	// Default: 5.
	ReconnectRetries int `yaml:"reconnect_retries,omitempty"`

	// GracePeriodSec is the drain time on shutdown.
	// Default: 30.
	GracePeriodSec int `yaml:"grace_period_sec,omitempty"`
}

// RelayNodeConfig holds settings for a relay node in the anonymous
// proxy system. Relay nodes blindly forward AEAD-encrypted ciphertext
// chunks — they have no decryption key for the payload and only process
// the forwarding header to determine the next hop.
//
// See PROXY_DESIGN.md §1.7 (Identity Trust Boundary) and §1.9
// (Forwarding Header Obfuscation).
type RelayNodeConfig struct {
	// JitterMinMs is the minimum forwarding delay per chunk in
	// milliseconds. Default: 5 (per PROXY_DESIGN.md §1.9).
	JitterMinMs int `yaml:"jitter_min_ms,omitempty"`

	// JitterMaxMs is the maximum forwarding delay per chunk in
	// milliseconds. Default: 50 (per PROXY_DESIGN.md §1.9).
	JitterMaxMs int `yaml:"jitter_max_ms,omitempty"`

	// DisableJitter, when true, skips the random delay. MUST be
	// false in production — timing side-channels would be exploitable.
	DisableJitter bool `yaml:"disable_jitter,omitempty"`

	// MaxCircuits limits the number of concurrent circuits a relay
	// will accept. Default: 1024.
	MaxCircuits int `yaml:"max_circuits,omitempty"`

	// MaxQueueDepth is the maximum number of pending chunks per
	// circuit before backpressure is applied. Default: 256.
	MaxQueueDepth int `yaml:"max_queue_depth,omitempty"`
}

// SSListenerConfig configures the Shadowsocks entry listener.
type SSListenerConfig struct {
	// Password is the pre-shared password for SS AEAD key derivation.
	Password string `yaml:"password"`

	// Cipher is the AEAD cipher name. Currently only
	// "chacha20-ietf-poly1305" is supported.
	Cipher string `yaml:"cipher,omitempty"`

	// ListenAddr is the address to listen on. In production this
	// is behind a CF Tunnel — the tunnel provides TLS.
	ListenAddr string `yaml:"listen_addr"`
}

// CircuitLifecycleConfig holds circuit lifecycle parameters.
// These map to the CircuitConfig in internal/proxy/protocol.go.
type CircuitLifecycleConfig struct {
	// IdleTimeout is how long a circuit stays active without data
	// before automatic teardown (seconds). Default: 300 (5 min).
	IdleTimeout int `yaml:"idle_timeout,omitempty"`

	// KeepaliveInterval is how often the entry sends keepalive pings
	// (seconds). Default: 30.
	KeepaliveInterval int `yaml:"keepalive_interval,omitempty"`

	// NACKTimeout is how long the exit waits for a missing chunk
	// before sending a NACK (seconds). Default: 5.
	NACKTimeout int `yaml:"nack_timeout,omitempty"`

	// OrphanTimeout is how long the exit keeps an incomplete reassembly
	// buffer (seconds). Default: 30.
	OrphanTimeout int `yaml:"orphan_timeout,omitempty"`

	// MaxReassemblyWindow is the hard limit on reassembly window size.
	// Default: 256.
	MaxReassemblyWindow int `yaml:"max_reassembly_window,omitempty"`
}

// ExitConfig holds exit-node-specific configuration.
type ExitConfig struct {
	// AllowedPorts is the list of destination ports the exit will
	// connect to. Default: [80, 443]. Operators can expand this
	// at their own legal risk.
	AllowedPorts []int `yaml:"allowed_ports,omitempty"`

	// AllowAllPorts removes the port restriction entirely.
	// WARNING: full legal exposure. Not recommended.
	AllowAllPorts bool `yaml:"allow_all_ports,omitempty"`

	// AuditLogDir is the directory for exit audit logs.
	// Logs record circuit_id → dest_ip:port → timestamp (no payload).
	AuditLogDir string `yaml:"audit_log_dir,omitempty"`

	// AuditRetentionDays is how long to keep audit logs. Default: 7.
	AuditRetentionDays int `yaml:"audit_retention_days,omitempty"`
}

// TransferConfig holds file transfer settings.
type TransferConfig struct {
	// MaxFileSize is the maximum size in bytes for a single incoming file
	// transfer. A value of 0 means no limit (not recommended for production).
	// Defaults to 1 GB (1 << 30) when unset.
	MaxFileSize int64 `yaml:"max_file_size"`

	// UploadDir is the directory where incoming file transfers are written.
	// Defaults to /tmp/meshdesk-uploads/ when empty.
	UploadDir string `yaml:"upload_dir"`
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
	PublicKey    string           `yaml:"public_key"`
	Endpoint     string           `yaml:"endpoint"`             // host:port; empty for roaming
	AllowedIPs   []string         `yaml:"allowed_ips"`          // mesh IPs routed to this peer
	Capabilities []string         `yaml:"capabilities"`         // what this peer can do on us
	Obfuscation  string           `yaml:"obfuscation"`          // none | padded | websocket
	PresharedKey string           `yaml:"preshared_key"`        // optional WireGuard PSK
	ObfConfig    *ObfuscationOpts `yaml:"obf_config,omitempty"` // per-peer obfuscation parameters

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

	// TLSSni: Server Name Indication sent in the TLS ClientHello. When
	// non-empty, the TLS handshake includes this SNI, making the connection
	// look like normal HTTPS to the configured domain. Used only in
	// WebSocket+TLS mode (ws_use_tls: true).
	TLSSni string `yaml:"tls_sni,omitempty"`

	// TLSFingerprint: which browser ClientHello to mimic to evade JA4
	// fingerprinting by the GFW. Supported: "chrome", "firefox", "safari",
	// "edge", "ios", "android". Defaults to "chrome" when empty.
	// Used only in WebSocket+TLS mode.
	TLSFingerprint string `yaml:"tls_fingerprint,omitempty"`
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

// DefaultMaxFileSize is the default limit for incoming file transfers (1 GB).
const DefaultMaxFileSize int64 = 1 << 30

// DefaultUploadDir is the default directory for incoming file transfers.
const DefaultUploadDir = "/tmp/meshdesk-uploads/"

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
			Port:          2222,
			DialTimeout:   10,
			ReadDeadline:  300,
			WriteDeadline: 10,
			MaxSessions:   256,
		},
		Transfer: TransferConfig{
			MaxFileSize: DefaultMaxFileSize,
			UploadDir:   DefaultUploadDir,
		},
		Proxy: ProxyConfig{
			ChunkerStrategy: "bounded-4k-64k",
			Circuit: CircuitLifecycleConfig{
				IdleTimeout:         300,
				KeepaliveInterval:   30,
				NACKTimeout:         5,
				OrphanTimeout:       30,
				MaxReassemblyWindow: 256,
			},
			Exit: ExitConfig{
				AllowedPorts:       []int{80, 443},
				AllowAllPorts:      false,
				AuditRetentionDays: 7,
			},
			Relay: RelayNodeConfig{
				JitterMinMs:    5,
				JitterMaxMs:    50,
				MaxCircuits:    1024,
				MaxQueueDepth:  256,
			},
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
	if cfg.Transfer.MaxFileSize == 0 {
		cfg.Transfer.MaxFileSize = DefaultMaxFileSize
	}
	if cfg.Transfer.UploadDir == "" {
		cfg.Transfer.UploadDir = DefaultUploadDir
	}
	// Proxy config defaults.
	if cfg.Proxy.ChunkerStrategy == "" {
		cfg.Proxy.ChunkerStrategy = "bounded-4k-64k"
	}
	if cfg.Proxy.Circuit.IdleTimeout == 0 {
		cfg.Proxy.Circuit.IdleTimeout = 300
	}
	if cfg.Proxy.Circuit.KeepaliveInterval == 0 {
		cfg.Proxy.Circuit.KeepaliveInterval = 30
	}
	if cfg.Proxy.Circuit.NACKTimeout == 0 {
		cfg.Proxy.Circuit.NACKTimeout = 5
	}
	if cfg.Proxy.Circuit.OrphanTimeout == 0 {
		cfg.Proxy.Circuit.OrphanTimeout = 30
	}
	if cfg.Proxy.Circuit.MaxReassemblyWindow == 0 {
		cfg.Proxy.Circuit.MaxReassemblyWindow = 256
	}
	if len(cfg.Proxy.Exit.AllowedPorts) == 0 && !cfg.Proxy.Exit.AllowAllPorts {
		cfg.Proxy.Exit.AllowedPorts = []int{80, 443}
	}
	if cfg.Proxy.Exit.AuditRetentionDays == 0 {
		cfg.Proxy.Exit.AuditRetentionDays = 7
	}
	// Relay config defaults.
	if cfg.Proxy.Relay.JitterMinMs == 0 {
		cfg.Proxy.Relay.JitterMinMs = 5
	}
	if cfg.Proxy.Relay.JitterMaxMs == 0 {
		cfg.Proxy.Relay.JitterMaxMs = 50
	}
	if cfg.Proxy.Relay.MaxCircuits == 0 {
		cfg.Proxy.Relay.MaxCircuits = 1024
	}
	if cfg.Proxy.Relay.MaxQueueDepth == 0 {
		cfg.Proxy.Relay.MaxQueueDepth = 256
	}
	// Path selection defaults.
	if cfg.Proxy.PathSelection.Mode == "" {
		cfg.Proxy.PathSelection.Mode = "manual"
	}
	if cfg.Proxy.PathSelection.MaxRelaysPerPath == 0 {
		cfg.Proxy.PathSelection.MaxRelaysPerPath = 2
	}
	if cfg.Proxy.PathSelection.ProbeTimeoutSec == 0 {
		cfg.Proxy.PathSelection.ProbeTimeoutSec = 3
	}
	if cfg.Proxy.PathSelection.ProbeConcurrency == 0 {
		cfg.Proxy.PathSelection.ProbeConcurrency = 8
	}
	if cfg.Proxy.PathSelection.MaxCandidates == 0 {
		cfg.Proxy.PathSelection.MaxCandidates = 10
	}
	if cfg.Proxy.PathSelection.ProbeCacheTTLSec == 0 {
		cfg.Proxy.PathSelection.ProbeCacheTTLSec = 30
	}
	// CF Tunnel defaults.
	if cfg.Proxy.CFTunnel.OriginServer == "" {
		cfg.Proxy.CFTunnel.OriginServer = "127.0.0.1:8388"
	}
	if cfg.Proxy.CFTunnel.LogLevel == "" {
		cfg.Proxy.CFTunnel.LogLevel = "warn"
	}
	if cfg.Proxy.CFTunnel.MetricsAddr == "" {
		cfg.Proxy.CFTunnel.MetricsAddr = "127.0.0.1:36500"
	}
	if cfg.Proxy.CFTunnel.ReconnectRetries == 0 {
		cfg.Proxy.CFTunnel.ReconnectRetries = 5
	}
	if cfg.Proxy.CFTunnel.GracePeriodSec == 0 {
		cfg.Proxy.CFTunnel.GracePeriodSec = 30
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
