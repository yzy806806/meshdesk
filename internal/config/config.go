package config

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for a MeshDesk node.
type Config struct {
	Node       NodeConfig       `yaml:"node"`
	Mesh       MeshConfig       `yaml:"mesh"`
	Peers      []PeerConfig     `yaml:"peers"`
	P2P        P2pConfig        `yaml:"p2p,omitempty"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
	WebSSH     WebSSHConfig     `yaml:"webssh"`
	Auth       AuthConfig       `yaml:"auth"`
	Transfer   TransferConfig   `yaml:"transfer"`
	Proxy      ProxyConfig      `yaml:"proxy,omitempty"`
	Xray       XrayYAMLConfig   `yaml:"xray,omitempty"`
}

// XrayYAMLConfig holds settings for the xray-core managed subprocess layer.
// When Enabled is true, the node starts an xray-core subprocess for
// VLESS+REALITY transport (replacing padded/websocket obfuscation for
// public interconnects). See motion-dfa7426d3d4b action item 3.
type XrayYAMLConfig struct {
	// Enabled controls whether the xray-core subprocess is started.
	Enabled bool `yaml:"enabled,omitempty"`

	// BinaryPath is the path to the xray-core binary. When empty,
	// the manager auto-detects via PATH and common install locations.
	BinaryPath string `yaml:"binary_path,omitempty"`

	// ConfigDir is where the generated xray config JSON is stored.
	// Default: /var/lib/meshdesk/xray
	ConfigDir string `yaml:"config_dir,omitempty"`

	// LogLines is the max number of log lines kept in the ring buffer
	// for the Dashboard log viewer. Default: 1000.
	LogLines int `yaml:"log_lines,omitempty"`

	// ApiPort is the port for xray-core's gRPC API inbound, used
	// for the healthy-before-ready self-check. Default: 8421.
	// Set to -1 to disable health checking entirely.
	ApiPort int `yaml:"api_port,omitempty"`

	// ApiListen is the listen address for the API inbound.
	// Default: "127.0.0.1" (localhost only).
	ApiListen string `yaml:"api_listen,omitempty"`

	// HealthCheckInterval is how often the background monitor
	// polls xray-core's health. Default: 10s.
	HealthCheckInterval int `yaml:"health_check_interval,omitempty"`

	// ReadinessTimeout is how long Start() waits for the first
	// successful health check before returning an error (seconds).
	// Default: 15.
	ReadinessTimeout int `yaml:"readiness_timeout,omitempty"`
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

	// Strategy selects the path ranking algorithm used when Mode is
	// "auto". Supported values:
	//   "latency"     — pick the two lowest-RTT disjoint paths (default)
	//   "random"      — random selection from healthy candidates
	//   "round-robin" — cycle through available paths to distribute load
	// Default: "latency".
	Strategy string `yaml:"strategy,omitempty"`

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
	// Enabled indicates whether this node is intentionally configured
	// as a relay node. When false, the relay module should not be
	// instantiated and the node should NOT be treated as a relay in
	// topology role derivation.
	//
	// This field exists because Default() pre-populates relay tuning
	// parameters (MaxCircuits=1024, etc.) so that relay-enabled nodes
	// have sane defaults without requiring every field. Without an
	// explicit Enabled flag, checking MaxCircuits > 0 would incorrectly
	// classify every Default()-derived node as a relay.
	Enabled bool `yaml:"enabled,omitempty"`

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

	// Port is the Shadowsocks listener port. Default: 8388.
	// Mutually exclusive with ListenAddr when ListenAddr includes
	// an explicit port. When both are set, Port takes precedence.
	Port int `yaml:"port,omitempty"`
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

	// DestinationFilter is a list of CIDR prefixes or FQDN patterns
	// that the exit is allowed to connect to. When non-empty, the
	// exit refuses connections to destinations that don't match at
	// least one entry. Empty (default) allows all destinations
	// subject to AllowedPorts/AllowAllPorts.
	// Examples: "10.0.0.0/8", "*.example.com", "203.0.113.0/24".
	DestinationFilter []string `yaml:"destination_filter,omitempty"`

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

	// Position holds an optional manual 3D display position for topology
	// visualization. When nil, positions are auto-derived from the node's
	// public key (see topology.DerivePosition). This is display-only
	// metadata and does not affect routing or proxy behavior.
	Position *PositionConfig `yaml:"position,omitempty"`
}

// PositionConfig holds a manual 3D display position for the topology
// visualization. Coordinates are in arbitrary screen-space units.
type PositionConfig struct {
	X float64 `yaml:"x"`
	Y float64 `yaml:"y"`
	Z float64 `yaml:"z"`
}

// MeshConfig holds mesh-level settings.
type MeshConfig struct {
	Port int `yaml:"port"` // WireGuard listen port (default 51820)
	// GossipPort is the TCP port for memberlist gossip on the mesh IP.
	// Default: 7946. Only used when p2p.enabled is true.
	GossipPort int `yaml:"gossip_port,omitempty"`
}

// P2pConfig holds settings for the P2P dynamic networking layer
// (gossip discovery, NAT traversal, dynamic join).
// When Enabled is false, the node uses static peers only (backward compat).
type P2pConfig struct {
	// Enabled controls whether dynamic P2P networking is active.
	Enabled bool `yaml:"enabled,omitempty"`

	// Seeds is the list of known mesh IP:gossip_port addresses used to
	// bootstrap the gossip cluster.
	Seeds []string `yaml:"seeds,omitempty"`

	// NatTraversal enables STUN discovery and UDP hole-punching.
	NatTraversal bool `yaml:"nat_traversal,omitempty"`

	// StunServers is the list of STUN server addresses for NAT discovery.
	StunServers []string `yaml:"stun_servers,omitempty"`

	// RelayMode controls how relay fallback is handled:
	//   "auto"     — automatically select relay peers (default)
	//   "manual"   — use only manually configured relay peers
	//   "disabled" — no relay fallback (direct-only)
	RelayMode string `yaml:"relay_mode,omitempty"`

	// MaxRelayHops is the maximum number of relay hops for relayed connections.
	MaxRelayHops int `yaml:"max_relay_hops,omitempty"`

	// JoinApproval controls the authentication mode for new nodes:
	//   "auto"   — pre-authorized key list (authorized_keys)
	//   "manual" — admin approval via dashboard
	JoinApproval string `yaml:"join_approval,omitempty"`

	// AuthorizedKeys is the list of WireGuard public keys (hex) pre-authorized
	// to join the mesh. Used when JoinApproval is "auto".
	AuthorizedKeys []string `yaml:"authorized_keys,omitempty"`

	// GossipInterval is the PushPull interval in seconds (state sync). Default: 30.
	GossipInterval int `yaml:"gossip_interval,omitempty"`

	// GossipProbeInterval is the probe interval in seconds (health check). Default: 1.
	GossipProbeInterval int `yaml:"gossip_probe_interval,omitempty"`

	// DirectReprobeInterval is seconds between direct re-probes in relay mode. Default: 120.
	DirectReprobeInterval int `yaml:"direct_reprobe_interval,omitempty"`

	// MaxPeers is the hard limit on total peers. Default: 256.
	MaxPeers int `yaml:"max_peers,omitempty"`
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

	// TOTPIssuer is the issuer name embedded in otpauth:// URIs shown
	// in QR codes during 2FA enrollment. Default: "MeshDesk".
	TOTPIssuer string `yaml:"totp_issuer,omitempty"`

	// Require2FA, when true, mandates that all web dashboard users
	// complete TOTP enrollment before accessing any authenticated
	// endpoint. When false (default), 2FA enrollment is optional.
	Require2FA bool `yaml:"require_2fa,omitempty"`

	// TOTPWindow is the ±skew tolerance in time steps (default 1).
	// Each step is 30 seconds, so a value of 1 accepts codes from
	// the previous, current, and next 30-second windows.
	TOTPWindow int `yaml:"totp_window,omitempty"`

	// TOTPStoreDir is the directory for persistent TOTP encrypted state
	// storage. When set, TOTP enrollment state is encrypted and persisted
	// to <TOTPStoreDir>/users/<username>.enc, surviving process restarts.
	// When empty (default), TOTP state is in-memory only and lost on restart.
	// Production deployments should set this to /var/lib/meshdesk/totp.
	TOTPStoreDir string `yaml:"totp_store_dir,omitempty"`

	// StepUpTimeout is the lifetime of a step-up auth token in seconds
	// (default 300 = 5 minutes). After this period, sensitive operations
	// require re-authentication.
	StepUpTimeout int `yaml:"step_up_timeout,omitempty"`

	// AlertWebhookURL is an optional webhook endpoint for external
	// security alert notifications. When empty, alerts are only stored
	// in-memory and surfaced in the web UI.
	AlertWebhookURL string `yaml:"alert_webhook_url,omitempty"`

	// legacyTOTPSecret captures a deprecated totp_secret value found in
	// config.yaml during Load(). It is NOT serialized (no yaml tag) and
	// is used only for one-time migration to the node-local master secret.
	// Access via LegacyTOTPSecret() method.
	legacyTOTPSecret string `yaml:"-"`
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

// DefaultTOTPStoreDir is the default directory for persistent TOTP
// encrypted state storage.
const DefaultTOTPStoreDir = "/var/lib/meshdesk/totp"

// Default returns a config with sensible defaults.
func Default() *Config {
	return &Config{
		Node: NodeConfig{
			WebAddr: "",
		},
		Mesh: MeshConfig{
			Port:       51820,
			GossipPort: 7946,
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
		Auth: AuthConfig{
			TOTPIssuer:    "MeshDesk",
			TOTPWindow:    1,
			StepUpTimeout: 300,
			// Require2FA defaults to false (2FA is opt-in).
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
			SS: SSListenerConfig{
				Port: 8388,
			},
			Exit: ExitConfig{
				AllowedPorts:       []int{80, 443},
				AllowAllPorts:      false,
				AuditRetentionDays: 7,
			},
			Relay: RelayNodeConfig{
				Enabled:       false, // Nodes are relays only when explicitly enabled.
				JitterMinMs:   5,
				JitterMaxMs:   50,
				MaxCircuits:   1024,
				MaxQueueDepth: 256,
			},
			PathSelection: PathSelectionConfig{
				Mode:     "manual",
				Strategy: "latency",
			},
		},
		P2P: P2pConfig{
			Enabled:               false,
			NatTraversal:          true,
			StunServers:           []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"},
			RelayMode:             "auto",
			MaxRelayHops:          2,
			JoinApproval:          "auto",
			GossipInterval:        30,
			GossipProbeInterval:   1,
			DirectReprobeInterval: 120,
			MaxPeers:              256,
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
	// Detect deprecated totp_secret in config.yaml (removed field).
	// The TOTP encryption key is now node-local at /var/lib/meshdesk/totp/master.key.
	if legacySecret := extractLegacyTOTPSecret(data); legacySecret != "" {
		cfg.Auth.legacyTOTPSecret = legacySecret
		log.Printf("[WARNING] config.yaml contains deprecated field 'totp_secret' — " +
			"TOTP encryption now uses node-local /var/lib/meshdesk/totp/master.key. " +
			"The config field is ignored and should be removed.")
	}
	if cfg.Mesh.Port == 0 {
		cfg.Mesh.Port = 51820
	}
	if cfg.Mesh.GossipPort == 0 {
		cfg.Mesh.GossipPort = 7946
	}
	// P2P config defaults.
	if !cfg.P2P.NatTraversal && cfg.P2P.Enabled {
		// If P2P is enabled but NatTraversal is explicitly false, respect that.
	} else if cfg.P2P.Enabled {
		cfg.P2P.NatTraversal = true
	}
	if len(cfg.P2P.StunServers) == 0 && cfg.P2P.Enabled {
		cfg.P2P.StunServers = []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}
	}
	if cfg.P2P.RelayMode == "" && cfg.P2P.Enabled {
		cfg.P2P.RelayMode = "auto"
	}
	if cfg.P2P.MaxRelayHops == 0 && cfg.P2P.Enabled {
		cfg.P2P.MaxRelayHops = 2
	}
	if cfg.P2P.JoinApproval == "" && cfg.P2P.Enabled {
		cfg.P2P.JoinApproval = "auto"
	}
	if cfg.P2P.GossipInterval == 0 && cfg.P2P.Enabled {
		cfg.P2P.GossipInterval = 30
	}
	if cfg.P2P.GossipProbeInterval == 0 && cfg.P2P.Enabled {
		cfg.P2P.GossipProbeInterval = 1
	}
	if cfg.P2P.DirectReprobeInterval == 0 && cfg.P2P.Enabled {
		cfg.P2P.DirectReprobeInterval = 120
	}
	if cfg.P2P.MaxPeers == 0 && cfg.P2P.Enabled {
		cfg.P2P.MaxPeers = 256
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
	// Auth config defaults.
	if cfg.Auth.TOTPIssuer == "" {
		cfg.Auth.TOTPIssuer = "MeshDesk"
	}
	if cfg.Auth.TOTPWindow == 0 {
		cfg.Auth.TOTPWindow = 1
	}
	if cfg.Auth.StepUpTimeout == 0 {
		cfg.Auth.StepUpTimeout = 300
	}
	// Enable persistent TOTP storage by default in production (when
	// loaded from config file). Tests use config.Default() which
	// leaves this empty for in-memory mode.
	if cfg.Auth.TOTPStoreDir == "" {
		cfg.Auth.TOTPStoreDir = DefaultTOTPStoreDir
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
	// SS listener defaults.
	if cfg.Proxy.SS.Port == 0 {
		cfg.Proxy.SS.Port = 8388
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
	if cfg.Proxy.PathSelection.Strategy == "" {
		cfg.Proxy.PathSelection.Strategy = "latency"
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

// LegacyTOTPSecret returns the deprecated totp_secret value found in
// config.yaml during Load(), or empty string if none. Used for one-time
// migration to the node-local master secret at /var/lib/meshdesk/totp/master.key.
func (a *AuthConfig) LegacyTOTPSecret() string {
	return a.legacyTOTPSecret
}

// extractLegacyTOTPSecret scans raw YAML bytes for a top-level
// auth.totp_secret field and returns its string value if present.
// This is needed because the TOTPSecret struct field was removed;
// the value is captured for migration only.
func extractLegacyTOTPSecret(data []byte) string {
	var raw map[string]map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return ""
	}
	auth, ok := raw["auth"]
	if !ok {
		return ""
	}
	secret, ok := auth["totp_secret"]
	if !ok {
		return ""
	}
	s, ok := secret.(string)
	if !ok {
		return ""
	}
	return s
}
