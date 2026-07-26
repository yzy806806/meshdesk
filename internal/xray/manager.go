package xray

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"
)

// DefaultConfigDir is where xray config and state are stored.
const DefaultConfigDir = "/var/lib/meshdesk/xray"

// DefaultConfigPath is the path to the generated xray config JSON.
const DefaultConfigPath = "/var/lib/meshdesk/xray/config.json"

// DefaultLogLines is the maximum number of log lines kept in the ring buffer.
const DefaultLogLines = 1000

// DefaultBinaryPath is used when no binary path is configured.
const DefaultBinaryPath = "xray"

// DefaultDrainTimeout is how long Stop() waits for active connections
// to drain after signaling xray-core to stop accepting new inbound
// connections. During this period, existing TCP connections are allowed
// to finish naturally. Set to 0 to disable the drain phase entirely.
const DefaultDrainTimeout = 10 * time.Second

// DefaultTerminateTimeout is how long Stop() waits for the xray-core
// process to exit after sending SIGTERM before escalating to SIGKILL.
const DefaultTerminateTimeout = 5 * time.Second

// MaxRestartBackoff is the maximum delay between crash restart attempts
// once exponential backoff has escalated beyond this value.
const MaxRestartBackoff = 60 * time.Second

// InitialRestartBackoff is the initial delay before the first restart.
const InitialRestartBackoff = 1 * time.Second

// --- Circuit Breaker Configuration ---

// MaxRestartsPerWindow is the maximum number of crash-restarts allowed
// within CrashWindow before the circuit breaker trips (opens).
// Once tripped, no further restarts happen until the window elapses
// and the breaker is reset.
const MaxRestartsPerWindow = 3

// CrashWindow is the sliding time window for counting crash-restarts.
const CrashWindow = 60 * time.Second

// ExponentialBackoffSchedule defines the backoff delays applied after
// MaxRestartsPerWindow restarts have occurred within CrashWindow.
// Index 0 applies after the 3rd crash, index 1 after the 4th, etc.
// After the schedule is exhausted, MaxRestartBackoff is used.
var ExponentialBackoffSchedule = []time.Duration{
	5 * time.Second,
	10 * time.Second,
	20 * time.Second,
}

// CircuitState represents the state of the circuit breaker.
type CircuitState int

const (
	// CircuitClosed means the process is healthy and restarts are allowed.
	CircuitClosed CircuitState = iota
	// CircuitOpen means the breaker has tripped: too many crashes in the
	// window. No restarts will be attempted until the cooldown elapses.
	CircuitOpen
	// CircuitHalfOpen means the breaker is testing whether the process
	// can stay alive after a cooldown. A crash in this state re-opens
	// the circuit.
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// LogEntry is a single captured log line from xray-core's stdout/stderr.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Stream    string    `json:"stream"` // "stdout" or "stderr"
	Line      string    `json:"line"`
}

// ProcessStatus represents the state of the managed xray-core subprocess.
type ProcessStatus struct {
	Running      bool      `json:"running"`
	PID          int       `json:"pid,omitempty"`
	StartedAt    time.Time `json:"started_at,omitempty"`
	RestartCount int       `json:"restart_count"`
	LastRestart  time.Time `json:"last_restart,omitempty"`
	ConfigPath   string    `json:"config_path"`
	BinaryPath   string    `json:"binary_path"`

	// Circuit breaker state
	CircuitState    CircuitState `json:"circuit_state"`
	CircuitTrippedAt time.Time   `json:"circuit_tripped_at,omitempty"`
	CrashCount      int          `json:"crash_count"` // crashes in current window
}

// logRingBuffer is a fixed-size ring buffer for log entries.
type logRingBuffer struct {
	mu      sync.Mutex
	entries []LogEntry
	size    int
	next    int // next write position
	full    bool
}

func newLogRingBuffer(size int) *logRingBuffer {
	return &logRingBuffer{
		entries: make([]LogEntry, size),
		size:    size,
	}
}

func (rb *logRingBuffer) Add(entry LogEntry) {
	rb.mu.Lock()
	rb.entries[rb.next] = entry
	rb.next = (rb.next + 1) % rb.size
	if rb.next == 0 {
		rb.full = true
	}
	rb.mu.Unlock()
}

func (rb *logRingBuffer) All() []LogEntry {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if !rb.full {
		return append([]LogEntry{}, rb.entries[:rb.next]...)
	}
	result := make([]LogEntry, 0, rb.size)
	result = append(result, rb.entries[rb.next:]...)
	result = append(result, rb.entries[:rb.next]...)
	return result
}

func (rb *logRingBuffer) Tail(n int) []LogEntry {
	all := rb.All()
	if len(all) <= n {
		return all
	}
	return all[len(all)-n:]
}

// XrayConfigManager manages the xray-core subprocess and its configuration.
// It is safe for concurrent use.
type XrayConfigManager struct {
	mu sync.Mutex

	binaryPath string
	configPath string
	configDir  string

	// Managed inbound/outbound configs
	inbounds  map[string]*InboundConfig
	outbounds map[string]*OutboundConfig

	// Process state
	cmd     *exec.Cmd
	process *os.Process
	status  ProcessStatus
	stopCh  chan struct{}
	stopped bool

	// Log capture
	logBuffer *logRingBuffer

	// Restart backoff state
	currentBackoff time.Duration

	// Circuit breaker state
	crashTimestamps []time.Time // timestamps of recent crashes (sliding window)
	circuitState    CircuitState
	circuitTrippedAt time.Time
	backoffIndex    int // index into ExponentialBackoffSchedule

	// KeyValueStore is an optional interface for persisting inbound configs.
	// When nil, configs are in-memory only (lost on restart).
	store ConfigStore

	// --- Health / Readiness ---

	// apiPort is the port xray-core's gRPC API inbound listens on.
	// Used for the gRPC self-check (healthy-before-ready gate).
	apiPort int

	// apiListen is the listen address for the API inbound.
	apiListen string

	// healthChecker probes xray-core's gRPC API port.
	healthChecker *HealthChecker

	// healthStatus is the current health state.
	healthStatus HealthStatus

	// healthCancel cancels the background health monitor goroutine.
	healthCancel context.CancelFunc

	// healthInterval is how often the background monitor polls.
	healthInterval time.Duration

	// readinessTimeout is how long Start() waits for the first
	// successful health check before returning an error.
	readinessTimeout time.Duration

	// drainTimeout is how long Stop() waits for active connections
	// to drain after removing inbound listeners. 0 disables the
	// drain phase (jumps straight to SIGTERM).
	drainTimeout time.Duration

	// terminateTimeout is how long Stop() waits for the process to
	// exit after SIGTERM before sending SIGKILL.
	terminateTimeout time.Duration
}

// ConfigStore is an optional interface for persisting xray inbound/outbound
// configurations. Implementations can use a JSON file, SQLite, etc.
type ConfigStore interface {
	SaveInbounds(map[string]*InboundConfig) error
	LoadInbounds() (map[string]*InboundConfig, error)
	SaveOutbounds(map[string]*OutboundConfig) error
	LoadOutbounds() (map[string]*OutboundConfig, error)
}

// ManagerOptions configures a new XrayConfigManager.
type ManagerOptions struct {
	BinaryPath string
	ConfigDir  string
	ConfigPath string
	LogLines   int
	Store      ConfigStore

	// --- Health / Readiness ---

	// ApiPort is the port for xray-core's gRPC API inbound.
	// If 0, DefaultApiPort (8421) is used. Set to -1 to disable
	// the API inbound and health checking entirely.
	ApiPort int

	// ApiListen is the listen address for the API inbound.
	// Default: "127.0.0.1" (localhost only, for security).
	ApiListen string

	// HealthCheckInterval is how often the background monitor
	// polls xray-core's health. Default: 10s.
	HealthCheckInterval time.Duration

	// ReadinessTimeout is how long Start() waits for the first
	// successful health check before returning an error.
	// Default: 15s. Set to 0 to skip the readiness gate (not recommended).
	ReadinessTimeout time.Duration

	// DrainTimeout is how long Stop() waits for active connections
	// to drain after signaling xray-core to stop accepting new
	// inbound connections. During this period, existing TCP
	// connections finish naturally. Default: 10s. Set to 0 to
	// disable the drain phase entirely (jumps straight to SIGTERM).
	DrainTimeout time.Duration

	// TerminateTimeout is how long Stop() waits for the xray-core
	// process to exit after SIGTERM before escalating to SIGKILL.
	// Default: 5s.
	TerminateTimeout time.Duration
}

// NewManager creates a new XrayConfigManager with the given options.
// If BinaryPath is empty, it tries to locate "xray" in PATH and common
// install locations. If the binary is not found, Start() will return
// an error — but the manager can still generate configs and be used
// for config management without running the process.
func NewManager(opts ManagerOptions) (*XrayConfigManager, error) {
	if opts.ConfigDir == "" {
		opts.ConfigDir = DefaultConfigDir
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = filepath.Join(opts.ConfigDir, "config.json")
	}
	if opts.LogLines <= 0 {
		opts.LogLines = DefaultLogLines
	}

	binaryPath := opts.BinaryPath
	if binaryPath == "" {
		binaryPath = DefaultBinaryPath
	}

	m := &XrayConfigManager{
		binaryPath: binaryPath,
		configPath: opts.ConfigPath,
		configDir:  opts.ConfigDir,
		inbounds:   make(map[string]*InboundConfig),
		outbounds:  make(map[string]*OutboundConfig),
		logBuffer:  newLogRingBuffer(opts.LogLines),
		store:      opts.Store,
		status: ProcessStatus{
			ConfigPath:   opts.ConfigPath,
			BinaryPath:   binaryPath,
			CircuitState: CircuitClosed,
		},
		currentBackoff: InitialRestartBackoff,
	}

	// Initialize health / readiness configuration
	m.apiPort = opts.ApiPort
	if m.apiPort == 0 {
		m.apiPort = DefaultApiPort
	}
	m.apiListen = opts.ApiListen
	if m.apiListen == "" {
		m.apiListen = DefaultApiListen
	}
	m.healthInterval = opts.HealthCheckInterval
	if m.healthInterval == 0 {
		m.healthInterval = DefaultHealthCheckInterval
	}
	m.readinessTimeout = opts.ReadinessTimeout
	if m.readinessTimeout == 0 {
		m.readinessTimeout = DefaultReadinessTimeout
	}
	m.drainTimeout = opts.DrainTimeout
	if m.drainTimeout == 0 {
		m.drainTimeout = DefaultDrainTimeout
	}
	m.terminateTimeout = opts.TerminateTimeout
	if m.terminateTimeout == 0 {
		m.terminateTimeout = DefaultTerminateTimeout
	}

	// Create the health checker (unless explicitly disabled)
	if opts.ApiPort >= 0 {
		apiAddr := defaultAPIAddr(m.apiListen, m.apiPort)
		m.healthChecker = NewHealthChecker(apiAddr, DefaultHealthCheckTimeout)
	}

	m.healthStatus = HealthStatus{State: HealthUnknown}

	// Load persisted configs if a store is available.
	if m.store != nil {
		if inbounds, err := m.store.LoadInbounds(); err == nil && inbounds != nil {
			m.inbounds = inbounds
		}
		if outbounds, err := m.store.LoadOutbounds(); err == nil && outbounds != nil {
			m.outbounds = outbounds
		}
	}

	return m, nil
}

// FindBinary attempts to locate the xray-core binary.
// Returns the full path if found, or empty string if not found.
func FindBinary() string {
	// Check PATH
	if path, err := exec.LookPath("xray"); err == nil {
		return path
	}
	// Check common install locations
	commonPaths := []string{
		"/usr/local/bin/xray",
		"/usr/bin/xray",
		"/opt/xray/xray",
		"/snap/bin/xray",
	}
	for _, p := range commonPaths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// --- Inbound CRUD ---

// AddInbound adds or replaces an inbound configuration.
func (m *XrayConfigManager) AddInbound(cfg *InboundConfig) error {
	if cfg.Tag == "" {
		return fmt.Errorf("inbound tag is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("invalid port: %d", cfg.Port)
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "vless-reality"
	}
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0"
	}
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	if cfg.Security == "" {
		cfg.Security = "reality"
	}

	m.mu.Lock()
	m.inbounds[cfg.Tag] = cfg
	m.mu.Unlock()

	if m.store != nil {
		if err := m.store.SaveInbounds(m.inbounds); err != nil {
			log.Printf("[xray] warning: failed to persist inbounds: %v", err)
		}
	}

	return nil
}

// RemoveInbound removes an inbound by tag. Returns ErrNotFound if not present.
func (m *XrayConfigManager) RemoveInbound(tag string) error {
	m.mu.Lock()
	_, ok := m.inbounds[tag]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	delete(m.inbounds, tag)
	m.mu.Unlock()

	if m.store != nil {
		if err := m.store.SaveInbounds(m.inbounds); err != nil {
			log.Printf("[xray] warning: failed to persist inbounds: %v", err)
		}
	}

	return nil
}

// GetInbound returns the inbound config for the given tag.
func (m *XrayConfigManager) GetInbound(tag string) (*InboundConfig, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, ok := m.inbounds[tag]
	return cfg, ok
}

// ListInbounds returns all configured inbounds.
func (m *XrayConfigManager) ListInbounds() []*InboundConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*InboundConfig, 0, len(m.inbounds))
	for _, cfg := range m.inbounds {
		result = append(result, cfg)
	}
	return result
}

// AddClient adds a VLESS client to an existing inbound.
// If a client with the same UUID already exists, it's replaced.
func (m *XrayConfigManager) AddClient(inboundTag string, client VLESSClient) error {
	if client.ID == "" {
		return fmt.Errorf("client UUID is required")
	}
	m.mu.Lock()
	ic, ok := m.inbounds[inboundTag]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("inbound %q not found", inboundTag)
	}

	// Replace if exists, otherwise append
	found := false
	for i, c := range ic.VLESSClients {
		if c.ID == client.ID {
			ic.VLESSClients[i] = client
			found = true
			break
		}
	}
	if !found {
		ic.VLESSClients = append(ic.VLESSClients, client)
	}
	m.mu.Unlock()

	if m.store != nil {
		if err := m.store.SaveInbounds(m.inbounds); err != nil {
			log.Printf("[xray] warning: failed to persist inbounds: %v", err)
		}
	}
	return nil
}

// RemoveClient removes a VLESS client from an inbound by UUID.
func (m *XrayConfigManager) RemoveClient(inboundTag, clientUUID string) error {
	m.mu.Lock()
	ic, ok := m.inbounds[inboundTag]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("inbound %q not found", inboundTag)
	}

	found := false
	for i, c := range ic.VLESSClients {
		if c.ID == clientUUID {
			ic.VLESSClients = append(ic.VLESSClients[:i], ic.VLESSClients[i+1:]...)
			found = true
			break
		}
	}
	m.mu.Unlock()

	if !found {
		return fmt.Errorf("client %q not found in inbound %q", clientUUID, inboundTag)
	}

	if m.store != nil {
		if err := m.store.SaveInbounds(m.inbounds); err != nil {
			log.Printf("[xray] warning: failed to persist inbounds: %v", err)
		}
	}
	return nil
}

// GetClients returns the VLESS clients for an inbound.
func (m *XrayConfigManager) GetClients(inboundTag string) ([]VLESSClient, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ic, ok := m.inbounds[inboundTag]
	if !ok {
		return nil, false
	}
	return append([]VLESSClient{}, ic.VLESSClients...), true
}

// APIAddr returns the gRPC API address (host:port) for the xray-core
// API inbound, used for stats queries and health checks.
func (m *XrayConfigManager) APIAddr() string {
	return defaultAPIAddr(m.apiListen, m.apiPort)
}

// AddOutbound adds or replaces an outbound configuration.
func (m *XrayConfigManager) AddOutbound(cfg *OutboundConfig) error {
	if cfg.Tag == "" {
		return fmt.Errorf("outbound tag is required")
	}
	m.mu.Lock()
	m.outbounds[cfg.Tag] = cfg
	m.mu.Unlock()

	if m.store != nil {
		if err := m.store.SaveOutbounds(m.outbounds); err != nil {
			log.Printf("[xray] warning: failed to persist outbounds: %v", err)
		}
	}
	return nil
}

// ListOutbounds returns all configured outbounds.
func (m *XrayConfigManager) ListOutbounds() []*OutboundConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*OutboundConfig, 0, len(m.outbounds))
	for _, cfg := range m.outbounds {
		result = append(result, cfg)
	}
	return result
}

// --- Config Generation ---

// GenerateConfig builds an XrayConfig from the managed inbound/outbound configs.
// This is the JSON config that gets written to disk and passed to xray-core.
func (m *XrayConfigManager) GenerateConfig() (*XrayConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generateConfigUnlocked()
}

// generateConfigUnlocked is the lock-free internal version.
// Caller must hold m.mu.
func (m *XrayConfigManager) generateConfigUnlocked() (*XrayConfig, error) {

	xrayCfg := &XrayConfig{
		Log: &LogConfig{
			LogLevel: "warning",
		},
	}

	// Build inbounds
	for _, ic := range m.inbounds {
		inbound, err := m.buildInbound(ic)
		if err != nil {
			return nil, fmt.Errorf("inbound %s: %w", ic.Tag, err)
		}
		xrayCfg.Inbounds = append(xrayCfg.Inbounds, *inbound)
	}

	// Inject the gRPC API inbound (dokodemo-door) for health checking,
	// unless explicitly disabled (apiPort < 0).
	if m.apiPort > 0 {
		// Top-level API configuration
		xrayCfg.Api = &ApiConfig{
			Tag: "api",
			Services: []string{
				"HandlerService",
				"LoggerService",
				"StatsService",
			},
		}

		// API inbound (dokodemo-door that routes to the API handler)
		apiInbound := m.buildAPIInbound()
		xrayCfg.Inbounds = append(xrayCfg.Inbounds, apiInbound)

		// Add routing rule: traffic on "api" inbound → "api" outbound
		if xrayCfg.Routing == nil {
			xrayCfg.Routing = &RoutingConfig{
				DomainStrategy: "AsIs",
			}
		}
		xrayCfg.Routing.Rules = append(xrayCfg.Routing.Rules, RoutingRule{
			Type:        "field",
			InboundTag:  []string{"api"},
			OutboundTag: "api",
		})
	}

	// Always add a "freedom" outbound as the default direct route
	if _, hasDirect := m.outbounds["direct"]; !hasDirect {
		freedomSettings, _ := json.Marshal(FreedomOutboundSettings{
			DomainStrategy: "AsIs",
		})
		xrayCfg.Outbounds = append(xrayCfg.Outbounds, Outbound{
			Tag:      "direct",
			Protocol: "freedom",
			Settings: freedomSettings,
		})
	}

	// Build configured outbounds
	for _, oc := range m.outbounds {
		outbound, err := m.buildOutbound(oc)
		if err != nil {
			return nil, fmt.Errorf("outbound %s: %w", oc.Tag, err)
		}
		xrayCfg.Outbounds = append(xrayCfg.Outbounds, *outbound)
	}

	return xrayCfg, nil
}

// buildInbound converts a managed InboundConfig to an xray Inbound struct.
func (m *XrayConfigManager) buildInbound(ic *InboundConfig) (*Inbound, error) {
	inbound := &Inbound{
		Tag:      ic.Tag,
		Port:     ic.Port,
		Listen:   ic.Listen,
		Protocol: "vless",
	}

	// VLESS settings
	vlessSettings := VLESSInboundSettings{
		Clients:    ic.VLESSClients,
		Decryption: "none",
	}
	if len(vlessSettings.Clients) == 0 {
		return nil, fmt.Errorf("no VLESS clients configured")
	}
	settingsJSON, err := json.Marshal(vlessSettings)
	if err != nil {
		return nil, fmt.Errorf("marshal vless settings: %w", err)
	}
	inbound.Settings = settingsJSON

	// Stream settings
	ss := &StreamSettings{
		Network:  ic.Network,
		Security: ic.Security,
	}

	switch ic.Security {
	case "reality":
		if ic.PrivateKey == "" {
			return nil, fmt.Errorf("reality security requires private_key")
		}
		if len(ic.ServerNames) == 0 {
			return nil, fmt.Errorf("reality security requires server_names")
		}
		if ic.Dest == "" {
			return nil, fmt.Errorf("reality security requires dest (camouflage target)")
		}
		shortIds := ic.ShortIds
		if len(shortIds) == 0 {
			// Generate a default short ID
			shortIds = []string{GenerateShortID()}
		}
		ss.RealitySettings = &RealitySettings{
			Show:        false,
			Dest:        ic.Dest,
			Xver:        0,
			ServerNames: ic.ServerNames,
			PrivateKey:  ic.PrivateKey,
			ShortIds:    shortIds,
		}
	case "tls":
		if ic.CertFile == "" || ic.KeyFile == "" {
			return nil, fmt.Errorf("tls security requires cert_file and key_file")
		}
		ss.TLSSettings = &TLSSettings{
			Certificates: []Cert{
				{CertificateFile: ic.CertFile, KeyFile: ic.KeyFile},
			},
		}
	case "none", "":
		ss.Security = "none"
	default:
		return nil, fmt.Errorf("unsupported security: %s", ic.Security)
	}

	inbound.StreamSettings = ss

	// Sniffing
	if ic.SniffEnabled {
		destOverride := ic.SniffDestOverride
		if len(destOverride) == 0 {
			destOverride = []string{"http", "tls"}
		}
		inbound.Sniffing = &SniffingConfig{
			Enabled:      true,
			DestOverride: destOverride,
			RouteOnly:    true,
		}
	}

	return inbound, nil
}

// buildOutbound converts a managed OutboundConfig to an xray Outbound struct.
func (m *XrayConfigManager) buildOutbound(oc *OutboundConfig) (*Outbound, error) {
	outbound := &Outbound{
		Tag:      oc.Tag,
		Protocol: oc.Protocol,
	}

	switch oc.Protocol {
	case "freedom":
		settings, _ := json.Marshal(FreedomOutboundSettings{
			DomainStrategy: oc.DomainStrategy,
		})
		outbound.Settings = settings

	case "vless":
		if oc.PeerAddress == "" || oc.PeerPort == 0 {
			return nil, fmt.Errorf("vless outbound requires peer_address and peer_port")
		}
		vlessOut := VLESSOutboundSettings{
			VNext: []VLESSOutboundServer{
				{
					Address: oc.PeerAddress,
					Port:    oc.PeerPort,
					Users:   oc.VLESSUsers,
				},
			},
		}
		settings, err := json.Marshal(vlessOut)
		if err != nil {
			return nil, fmt.Errorf("marshal vless outbound: %w", err)
		}
		outbound.Settings = settings

		// If reality fields are set, add stream settings
		if oc.Password != "" || oc.Fingerprint != "" {
			ss := &StreamSettings{
				Network:  "tcp",
				Security: "reality",
			}
			ss.RealitySettings = &RealitySettings{
				Fingerprint: oc.Fingerprint,
				ServerName:  oc.ServerName,
				Password:    oc.Password,
				ShortId:     oc.ShortId,
			}
			outbound.StreamSettings = ss
		}

	case "blackhole":
		outbound.Settings = json.RawMessage(`{}`)

	default:
		return nil, fmt.Errorf("unsupported outbound protocol: %s", oc.Protocol)
	}

	return outbound, nil
}

// buildAPIInbound constructs the dokodemo-door inbound that xray-core
// uses to expose its gRPC API for health checking.
// The inbound listens on 127.0.0.1:<apiPort> and routes to the
// "api" outbound via a routing rule.
func (m *XrayConfigManager) buildAPIInbound() Inbound {
	settings, _ := json.Marshal(DokodemoDoorSettings{
		Address: "127.0.0.1",
		Network: "tcp",
	})
	return Inbound{
		Tag:      "api",
		Listen:   m.apiListen,
		Port:     m.apiPort,
		Protocol: "dokodemo-door",
		Settings: settings,
	}
}

// WriteConfig generates the xray config JSON and writes it to disk.
func (m *XrayConfigManager) WriteConfig() error {
	cfg, err := m.GenerateConfig()
	if err != nil {
		return fmt.Errorf("generate config: %w", err)
	}

	// Ensure config directory exists
	if err := os.MkdirAll(m.configDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := atomicWriteFile(m.configPath, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// --- Process Management ---

// Start launches the xray-core subprocess with the current config.
// If xray is already running, it returns nil (no-op).
// The config is written to disk before starting.
//
// Healthy-before-ready gate: after the process starts, Start() waits
// for a successful gRPC self-check before returning nil. If xray-core
// doesn't pass a health check within ReadinessTimeout, Start() returns
// an error (but the process keeps running — the background monitor
// continues probing).
func (m *XrayConfigManager) Start() error {
	m.mu.Lock()

	if m.status.Running {
		m.mu.Unlock()
		return nil // already running
	}

	if m.stopped {
		m.mu.Unlock()
		return fmt.Errorf("manager has been stopped, create a new one")
	}

	// Reset circuit breaker for a fresh start
	m.crashTimestamps = nil
	m.circuitState = CircuitClosed
	m.circuitTrippedAt = time.Time{}
	m.backoffIndex = 0
	m.currentBackoff = InitialRestartBackoff
	m.status.CircuitState = CircuitClosed
	m.status.CircuitTrippedAt = time.Time{}
	m.status.CrashCount = 0

	// Reset health state
	m.healthStatus = HealthStatus{State: HealthUnknown}

	// Write config to disk
	if err := m.writeConfigUnlocked(); err != nil {
		m.mu.Unlock()
		return err
	}

	// Check binary exists
	binaryPath := m.binaryPath
	if _, err := exec.LookPath(binaryPath); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("xray binary not found: %s — install xray-core and ensure it is in PATH", binaryPath)
	}

	if err := m.startProcessUnlocked(); err != nil {
		m.mu.Unlock()
		return err
	}

	// Start process monitor goroutine (handles crash auto-restart)
	// Started here (not in startProcessUnlocked) to prevent goroutine
	// pileup: monitorProcess calls startProcessUnlocked() in its own
	// restart loop.
	go m.monitorProcess()

	// Grab values we need for the readiness gate, then release the lock.
	healthChecker := m.healthChecker
	readinessTimeout := m.readinessTimeout
	m.mu.Unlock()

	// Start the background health monitor
	m.startHealthMonitor()

	// --- Healthy-before-ready gate ---
	// Wait for xray-core to pass a gRPC self-check before reporting
	// success. If health checking is disabled, skip the gate.
	if healthChecker == nil || readinessTimeout <= 0 {
		return nil
	}

	if err := m.waitForHealthy(readinessTimeout); err != nil {
		return fmt.Errorf("xray started but not healthy within %v: %w", readinessTimeout, err)
	}

	return nil
}

// startProcessUnlocked starts the xray subprocess (caller must hold m.mu).
func (m *XrayConfigManager) startProcessUnlocked() error {
	cmd := exec.Command(m.binaryPath, "run", "-config", m.configPath)

	// Capture stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("create stderr pipe: %w", err)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // put xray in its own process group for clean signal delivery
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start xray: %w", err)
	}

	m.cmd = cmd
	m.process = cmd.Process
	m.status.Running = true
	m.status.PID = cmd.Process.Pid
	m.status.StartedAt = time.Now()
	m.status.ConfigPath = m.configPath
	m.status.BinaryPath = m.binaryPath
	m.stopCh = make(chan struct{})

	// Start log capture goroutines
	go m.captureLogs(stdout, "stdout")
	go m.captureLogs(stderr, "stderr")

	// NOTE: monitorProcess is started by Start(), not here.
	// This prevents goroutine pileup on restart: monitorProcess calls
	// startProcessUnlocked() in its own loop, so starting a new
	// monitor goroutine here would create a new one every restart.

	log.Printf("[xray] started (pid=%d, config=%s)", m.status.PID, m.configPath)
	return nil
}

// captureLogs reads from a pipe and stores lines in the ring buffer.
func (m *XrayConfigManager) captureLogs(reader io.Reader, stream string) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := reader.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			// Process complete lines
			for {
				idx := -1
				for i, b := range buf {
					if b == '\n' {
						idx = i
						break
					}
				}
				if idx < 0 {
					break
				}
				line := string(buf[:idx])
				buf = buf[idx+1:]
				m.logBuffer.Add(LogEntry{
					Timestamp: time.Now(),
					Stream:    stream,
					Line:      line,
				})
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[xray] %s read error: %v", stream, err)
			}
			// Flush remaining buffer
			if len(buf) > 0 {
				m.logBuffer.Add(LogEntry{
					Timestamp: time.Now(),
					Stream:    stream,
					Line:      string(buf),
				})
				buf = buf[:0]
			}
			return
		}
	}
}

// monitorProcess waits for the xray process to exit and handles
// crash auto-restart with a circuit breaker:
//
//   - MaxRestartsPerWindow (3) restarts per CrashWindow (60s) are allowed.
//   - After that, exponential backoff (5s, 10s, 20s) kicks in.
//   - If the process keeps crashing despite backoff, the circuit breaker
//     opens and stops all restart attempts until the window elapses.
//   - After the cooldown, the breaker goes half-open: one restart is
//     attempted. If it survives, the breaker closes. If it crashes,
//     the breaker re-opens.
func (m *XrayConfigManager) monitorProcess() {
	for {
		process := func() *os.Process {
			m.mu.Lock()
			defer m.mu.Unlock()
			return m.process
		}()
		if process == nil {
			return
		}

		// Wait for the process to exit
		state, err := process.Wait()

		// Record crash and compute backoff under lock, then release
		var wasStopped bool
		var exitCode int = -1
		var backoff time.Duration
		var shouldRestart bool
		var cooldown time.Duration

		m.mu.Lock()
		wasStopped = m.stopped
		m.status.Running = false
		m.status.PID = 0

		if wasStopped {
			// Intentional stop — don't restart
			m.mu.Unlock()
			log.Printf("[xray] process exited (intentional stop): %v", err)
			return
		}

		// Process crashed or exited unexpectedly
		if state != nil {
			exitCode = state.ExitCode()
		}

		// Record this crash in the sliding window
		now := time.Now()
		m.crashTimestamps = append(m.crashTimestamps, now)
		m.pruneCrashTimestampsLocked(now)

		// Update status fields
		m.status.CrashCount = len(m.crashTimestamps)
		m.status.CircuitState = m.circuitState
		m.status.CircuitTrippedAt = m.circuitTrippedAt

		// Determine backoff and whether to restart
		var circuitTransitioned bool
		backoff, shouldRestart, circuitTransitioned = m.computeBackoffLocked(now)

		if circuitTransitioned {
			log.Printf("[xray] circuit breaker OPENED — too many crashes (%d in %v), halting restarts",
				len(m.crashTimestamps), CrashWindow)
		}

		log.Printf("[xray] process exited unexpectedly (code=%d, err=%v) — crashes=%d, circuit=%s, backoff=%v",
			exitCode, err, len(m.crashTimestamps), m.circuitState.String(), backoff)

		if !shouldRestart {
			// Circuit breaker is open — compute cooldown, then unlock
			cooldown = m.circuitCooldownLocked(now)
		}
		m.mu.Unlock()

		if !shouldRestart {
			// Circuit breaker is open — wait for the cooldown period
			// before transitioning to half-open and trying again.
			// Mutex is NOT held during this wait.
			log.Printf("[xray] circuit breaker open — waiting %v cooldown before half-open probe", cooldown)
			select {
			case <-time.After(cooldown):
				m.mu.Lock()
				// Transition to half-open: we'll attempt one restart
				m.circuitState = CircuitHalfOpen
				m.status.CircuitState = CircuitHalfOpen
				// Prune timestamps again in case the window has moved
				m.pruneCrashTimestampsLocked(time.Now())
				m.status.CrashCount = len(m.crashTimestamps)
				log.Printf("[xray] circuit breaker → half-open — attempting probe restart")
				m.mu.Unlock()
			case <-m.stopCh:
				return
			}
		}

		// Wait for backoff before restarting.
		// Mutex is NOT held during this wait — other operations can proceed.
		select {
		case <-time.After(backoff):
			m.mu.Lock()
			// Prune stale crashes before deciding to proceed
			m.pruneCrashTimestampsLocked(time.Now())
			m.status.CrashCount = len(m.crashTimestamps)

			m.status.RestartCount++
			m.status.LastRestart = time.Now()

			// Rewrite config (in case inbounds changed during the crash)
			if err := m.writeConfigUnlocked(); err != nil {
				log.Printf("[xray] failed to rewrite config before restart: %v", err)
				m.mu.Unlock()
				continue
			}

			// Restart
			if err := m.startProcessUnlocked(); err != nil {
				log.Printf("[xray] restart failed: %v", err)
				m.mu.Unlock()
				continue
			}

			log.Printf("[xray] restarted (attempt %d, pid=%d, circuit=%s)",
				m.status.RestartCount, m.status.PID, m.circuitState.String())
			m.mu.Unlock()

		case <-m.stopCh:
			return
		}
	}
}

// computeBackoffLocked determines the backoff duration and whether
// a restart should be attempted. It also manages circuit breaker
// state transitions (Closed → Open).
//
// The backoff schedule is indexed by the number of crashes beyond
// MaxRestartsPerWindow:
//   - Crashes 1..3: normal restart with InitialRestartBackoff
//   - Crash 4: ExponentialBackoffSchedule[0] (5s)
//   - Crash 5: ExponentialBackoffSchedule[1] (10s)
//   - Crash 6: ExponentialBackoffSchedule[2] (20s)
//   - Crash 7+: circuit breaker opens (no restart)
//
// Returns:
//   - backoff: duration to wait before next restart attempt
//   - shouldRestart: false if circuit breaker is open (skip restart)
//   - circuitTransitioned: true if breaker just opened this call
//
// Caller must hold m.mu.
func (m *XrayConfigManager) computeBackoffLocked(now time.Time) (backoff time.Duration, shouldRestart bool, circuitTransitioned bool) {
	crashCount := len(m.crashTimestamps)

	// If circuit is already open, don't restart
	if m.circuitState == CircuitOpen {
		return 0, false, false
	}

	// If we've exceeded the restart limit within the window,
	// apply exponential backoff
	if crashCount > MaxRestartsPerWindow {
		// Index into the schedule based on how many crashes beyond the limit
		scheduleIdx := crashCount - MaxRestartsPerWindow - 1 // 0-based

		if scheduleIdx < len(ExponentialBackoffSchedule) {
			// Still within the backoff schedule
			backoff = ExponentialBackoffSchedule[scheduleIdx]
			return backoff, true, false
		}

		// Schedule exhausted — open the circuit breaker
		m.circuitState = CircuitOpen
		m.circuitTrippedAt = now
		m.status.CircuitState = CircuitOpen
		m.status.CircuitTrippedAt = now
		circuitTransitioned = true
		return 0, false, true
	}

	// Normal restart with initial backoff
	// If we were in half-open, close the circuit since we're restarting
	// within the normal limit
	if m.circuitState == CircuitHalfOpen {
		m.circuitState = CircuitClosed
		m.status.CircuitState = CircuitClosed
		log.Printf("[xray] circuit breaker → closed (crashes within window: %d)", crashCount)
	}

	return m.currentBackoff, true, false
}

// circuitCooldownLocked returns how long to wait when the circuit is open
// before attempting a half-open probe. This is the remaining time until
// the oldest crash in the window falls outside CrashWindow.
//
// Caller must hold m.mu.
func (m *XrayConfigManager) circuitCooldownLocked(now time.Time) time.Duration {
	if len(m.crashTimestamps) == 0 {
		return CrashWindow
	}

	// Cooldown = time until the oldest crash exits the window,
	// at which point crashCount drops below the threshold
	oldest := m.crashTimestamps[0]
	cooldown := CrashWindow - now.Sub(oldest)
	if cooldown < 0 {
		cooldown = 0
	}
	return cooldown
}

// pruneCrashTimestampsLocked removes crash timestamps older than CrashWindow.
//
// Caller must hold m.mu.
func (m *XrayConfigManager) pruneCrashTimestampsLocked(now time.Time) {
	cutoff := now.Add(-CrashWindow)
	idx := 0
	for i, ts := range m.crashTimestamps {
		if ts.After(cutoff) {
			m.crashTimestamps[i] = ts
			m.crashTimestamps[idx] = ts
			idx++
		}
	}
	m.crashTimestamps = m.crashTimestamps[:idx]

	// If all crashes have expired, reset the circuit breaker
	if len(m.crashTimestamps) == 0 && m.circuitState != CircuitOpen {
		m.circuitState = CircuitClosed
		m.status.CircuitState = CircuitClosed
		m.backoffIndex = 0
	}
}

// ResetCircuitBreaker manually resets the circuit breaker to closed state
// and clears all crash history. This can be used by an operator to force
// a restart attempt after the breaker has tripped.
func (m *XrayConfigManager) ResetCircuitBreaker() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.crashTimestamps = nil
	m.circuitState = CircuitClosed
	m.circuitTrippedAt = time.Time{}
	m.backoffIndex = 0
	m.currentBackoff = InitialRestartBackoff
	m.status.CircuitState = CircuitClosed
	m.status.CircuitTrippedAt = time.Time{}
	m.status.CrashCount = 0

	log.Printf("[xray] circuit breaker manually reset")
}

// CircuitBreakerState returns the current circuit breaker state.
func (m *XrayConfigManager) CircuitBreakerState() CircuitState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.circuitState
}

// Reload sends SIGHUP to the xray-core process for hot-reload.
// The config is rewritten to disk first, then SIGHUP is sent.
// If xray is not running, this is a no-op (use Start instead).
func (m *XrayConfigManager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.status.Running || m.process == nil {
		return fmt.Errorf("xray is not running")
	}

	// Rewrite config to disk
	if err := m.writeConfigUnlocked(); err != nil {
		return fmt.Errorf("rewrite config: %w", err)
	}

	// Send SIGHUP for hot-reload
	if err := m.process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("send SIGHUP: %w", err)
	}

	// Reset backoff and circuit breaker on successful manual reload
	m.currentBackoff = InitialRestartBackoff
	m.backoffIndex = 0
	// Don't clear crash history — only a clean process restart does that.
	// But allow the next crash to start fresh if reload succeeded.

	log.Printf("[xray] SIGHUP sent for hot-reload (pid=%d)", m.status.PID)
	return nil
}

// --- Graceful Shutdown (Drain-on-Stop) ---

// drainConnectionsUnlocked signals xray-core to stop accepting new
// connections on all proxy inbounds, allowing active connections to
// drain naturally.
//
// It works by rewriting the config with all proxy inbounds removed
// (keeping only the API inbound if present), then sending SIGHUP for
// hot-reload. xray-core closes the listener sockets for the removed
// inbounds, which prevents new connections, while existing connections
// continue until they complete or the process is terminated.
//
// After signaling, it waits up to drainTimeout for the process to
// exit on its own (which happens if all connections drain quickly).
// If the process is still running after the timeout, the caller
// should proceed to the terminate phase (SIGTERM/SIGKILL).
//
// process and pid are passed in from the caller (Stop) because it
// already snapshotted them before clearing m.status.PID.
//
// Returns true if the process exited during the drain wait,
// false if it is still running (or drain was skipped).
//
// Caller must NOT hold m.mu (this method acquires it internally
// for config operations, then releases it during the wait).
func (m *XrayConfigManager) drainConnectionsUnlocked(process *os.Process, pid int) bool {
	if m.drainTimeout <= 0 {
		return false
	}

	if process == nil {
		return false
	}

	// Rewrite config with proxy inbounds removed (drain config).
	// We temporarily swap m.inbounds to an empty map, generate the
	// drain config, write it, then restore. This keeps the API
	// inbound (if present) but removes all proxy listeners.
	if err := m.writeDrainConfig(); err != nil {
		log.Printf("[xray] drain: failed to write drain config: %v — skipping drain phase", err)
		return false
	}

	// Send SIGHUP to trigger hot-reload of the drain config
	if err := process.Signal(syscall.SIGHUP); err != nil {
		log.Printf("[xray] drain: SIGHUP failed: %v — skipping drain phase", err)
		return false
	}

	log.Printf("[xray] drain: SIGHUP sent (pid=%d) — waiting up to %v for connections to drain",
		pid, m.drainTimeout)

	// Wait for the process to exit (all connections drained) or timeout.
	// We use process.Wait() in a goroutine with a timeout. If the process
	// exits, it means all connections have drained and xray shut down.
	// If it's still running after the timeout, we proceed to terminate.
	done := make(chan struct{})
	go func() {
		_, _ = process.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("[xray] drain: process exited after drain (pid=%d)", pid)
		return true
	case <-time.After(m.drainTimeout):
		log.Printf("[xray] drain: %v timeout — connections may still be active, proceeding to terminate",
			m.drainTimeout)
		return false
	}
}

// writeDrainConfig writes a config that has all proxy inbounds removed
// but retains the API inbound (if configured). This causes xray-core
// to close proxy listener sockets on hot-reload, preventing new
// connections while existing ones drain.
func (m *XrayConfigManager) writeDrainConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Save current inbounds, temporarily clear them
	savedInbounds := m.inbounds
	m.inbounds = make(map[string]*InboundConfig)
	defer func() { m.inbounds = savedInbounds }()

	// Write the drain config (only API inbound, if present)
	if err := m.writeConfigUnlocked(); err != nil {
		return fmt.Errorf("write drain config: %w", err)
	}

	return nil
}

// resetCircuitBreakerUnlocked resets all circuit breaker state.
// Used by Stop() and ForceStop() to clean up on intentional shutdown.
//
// Caller must hold m.mu.
func (m *XrayConfigManager) resetCircuitBreakerUnlocked() {
	m.crashTimestamps = nil
	m.circuitState = CircuitClosed
	m.circuitTrippedAt = time.Time{}
	m.backoffIndex = 0
	m.currentBackoff = InitialRestartBackoff
	m.status.CircuitState = CircuitClosed
	m.status.CircuitTrippedAt = time.Time{}
	m.status.CrashCount = 0
}

// waitForProcessExit waits up to timeout for the process to exit.
// If it doesn't exit, sends SIGKILL and waits for exit.
// Returns true if the process exited gracefully (within timeout),
// false if SIGKILL was needed.
//
// Caller must NOT hold m.mu.
func (m *XrayConfigManager) waitForProcessExit(process *os.Process, pid int, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_, _ = process.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("[xray] process stopped gracefully (pid=%d)", pid)
		return true
	case <-time.After(timeout):
		log.Printf("[xray] process did not exit in %v — sending SIGKILL (pid=%d)", timeout, pid)
		_ = process.Kill()
		<-done
		return false
	}
}

// Stop gracefully stops the xray-core subprocess with drain-on-stop.
//
// The shutdown proceeds in two phases:
//
//  1. Drain phase: Rewrites the xray config with all proxy inbounds
//     removed and sends SIGHUP for hot-reload. This causes xray-core
//     to close proxy listener sockets (no new connections accepted)
//     while existing connections continue to flow. Waits up to
//     drainTimeout (default 10s) for the process to exit naturally.
//
//  2. Terminate phase: Sends SIGTERM, waits up to terminateTimeout
//     (default 5s), then SIGKILL if still running.
//
// If drainTimeout is 0, the drain phase is skipped entirely.
func (m *XrayConfigManager) Stop() error {
	m.mu.Lock()

	if !m.status.Running {
		m.mu.Unlock()
		return nil
	}

	m.stopped = true
	if m.stopCh != nil {
		close(m.stopCh)
	}

	// Stop the background health monitor
	if m.healthCancel != nil {
		m.healthCancel()
		m.healthCancel = nil
	}

	// Reset health state
	m.healthStatus = HealthStatus{State: HealthUnknown}

	if m.process == nil {
		m.status.Running = false
		m.mu.Unlock()
		return nil
	}

	// Snapshot process info for the drain/terminate phases
	process := m.process
	pid := m.status.PID
	terminateTimeout := m.terminateTimeout

	// Mark as not running so monitorProcess won't restart
	m.status.Running = false
	m.status.PID = 0

	m.mu.Unlock()

	// --- Phase 1: Drain ---
	// Signal xray to stop accepting new connections, wait for active
	// connections to finish. If the process exits during drain, we're done.
	drained := m.drainConnectionsUnlocked(process, pid)
	if drained {
		// Process exited during drain — clean up state
		m.mu.Lock()
		m.process = nil
		m.cmd = nil
		m.resetCircuitBreakerUnlocked()
		m.mu.Unlock()
		return nil
	}

	// --- Phase 2: Terminate ---
	// Send SIGTERM, wait for exit, escalate to SIGKILL
	if err := process.Signal(syscall.SIGTERM); err != nil {
		log.Printf("[xray] SIGTERM failed: %v — trying SIGKILL (pid=%d)", err, pid)
		_ = process.Kill()
	}

	m.waitForProcessExit(process, pid, terminateTimeout)

	// Clean up state
	m.mu.Lock()
	m.process = nil
	m.cmd = nil
	m.resetCircuitBreakerUnlocked()
	m.mu.Unlock()

	return nil
}

// ForceStop immediately terminates the xray-core subprocess without
// the drain phase. Sends SIGTERM, waits up to terminateTimeout,
// then SIGKILL.
//
// Use this when you need to stop xray-core quickly (e.g., emergency
// shutdown, config corruption, debugging) and don't care about
// in-flight connections.
func (m *XrayConfigManager) ForceStop() error {
	m.mu.Lock()

	if !m.status.Running {
		m.mu.Unlock()
		return nil
	}

	m.stopped = true
	if m.stopCh != nil {
		close(m.stopCh)
	}

	// Stop the background health monitor
	if m.healthCancel != nil {
		m.healthCancel()
		m.healthCancel = nil
	}

	m.healthStatus = HealthStatus{State: HealthUnknown}

	if m.process == nil {
		m.status.Running = false
		m.mu.Unlock()
		return nil
	}

	process := m.process
	pid := m.status.PID
	terminateTimeout := m.terminateTimeout

	m.status.Running = false
	m.status.PID = 0
	m.mu.Unlock()

	// Send SIGTERM, wait, escalate to SIGKILL
	if err := process.Signal(syscall.SIGTERM); err != nil {
		log.Printf("[xray] ForceStop: SIGTERM failed: %v — trying SIGKILL (pid=%d)", err, pid)
		_ = process.Kill()
	}

	m.waitForProcessExit(process, pid, terminateTimeout)

	// Clean up state
	m.mu.Lock()
	m.process = nil
	m.cmd = nil
	m.resetCircuitBreakerUnlocked()
	m.mu.Unlock()

	return nil
}

// --- Health / Readiness ---

// waitForHealthy polls the gRPC API port until it succeeds or timeout.
// The mutex is NOT held during this wait — other operations can proceed.
// It uses a short initial delay (200ms) to give xray-core time to start
// listening, then polls every 500ms.
func (m *XrayConfigManager) waitForHealthy(timeout time.Duration) error {
	// Give xray-core a brief moment to start listening on the API port.
	initialDelay := 200 * time.Millisecond
	pollInterval := 500 * time.Millisecond

	// If the timeout is shorter than the initial delay, just do one check.
	if timeout <= initialDelay {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return m.healthChecker.CheckAndUpdate(ctx)
	}

	select {
	case <-time.After(initialDelay):
	case <-m.stopCh:
		return fmt.Errorf("manager stopped during readiness wait")
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Check if process is still running (might have crashed already)
		m.mu.Lock()
		running := m.status.Running
		m.mu.Unlock()
		if !running {
			return fmt.Errorf("xray process exited during readiness wait")
		}

		ctx, cancel := context.WithTimeout(context.Background(), pollInterval)
		err := m.healthChecker.CheckAndUpdate(ctx)
		cancel()

		if err == nil {
			// Update our health status
			m.mu.Lock()
			m.healthStatus = m.healthChecker.Status()
			m.mu.Unlock()
			log.Printf("[xray] health check passed — xray-core is ready (api=%s)", m.healthChecker.addr)
			return nil
		}

		// Wait before retrying
		select {
		case <-time.After(pollInterval):
		case <-m.stopCh:
			return fmt.Errorf("manager stopped during readiness wait")
		}
	}

	return fmt.Errorf("timeout after %v — last failure: %s", timeout, m.healthChecker.Status().LastFailure)
}

// startHealthMonitor launches a background goroutine that periodically
// probes xray-core's gRPC API. This runs independently of the readiness
// gate and keeps the health status fresh for /api/xray/status queries.
func (m *XrayConfigManager) startHealthMonitor() {
	// Cancel any previous monitor
	if m.healthCancel != nil {
		m.healthCancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.healthCancel = cancel
	interval := m.healthInterval
	checker := m.healthChecker
	m.mu.Unlock()

	if checker == nil {
		cancel()
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Don't check if process isn't running
				m.mu.Lock()
				running := m.status.Running
				m.mu.Unlock()
				if !running {
					continue
				}

				checkCtx, checkCancel := context.WithTimeout(ctx, DefaultHealthCheckTimeout)
				err := checker.CheckAndUpdate(checkCtx)
				checkCancel()

				// Update health status
				m.mu.Lock()
				oldState := m.healthStatus.State
				m.healthStatus = checker.Status()
				newState := m.healthStatus.State
				m.mu.Unlock()

				logHealthChange(oldState, newState)

				if err != nil {
					log.Printf("[xray] health check failed: %v", err)
				}

			case <-ctx.Done():
				return
			}
		}
	}()
}

// stopHealthMonitor stops the background health monitor goroutine.
func (m *XrayConfigManager) stopHealthMonitor() {
	m.mu.Lock()
	cancel := m.healthCancel
	m.healthCancel = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// IsReady returns true if xray-core is running AND healthy (passed
// the last gRPC self-check). This is the readiness gate: the node
// should not report "ready" until this returns true.
func (m *XrayConfigManager) IsReady() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status.Running && m.healthStatus.State == HealthHealthy
}

// HealthStatus returns the current health status snapshot.
func (m *XrayConfigManager) HealthStatus() HealthStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthStatus
}

// CheckHealthNow triggers an immediate health check (bypassing the
// background monitor's interval). Returns the result.
func (m *XrayConfigManager) CheckHealthNow() error {
	m.mu.Lock()
	checker := m.healthChecker
	running := m.status.Running
	m.mu.Unlock()

	if checker == nil {
		return fmt.Errorf("health checking is disabled")
	}
	if !running {
		return fmt.Errorf("xray is not running")
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultHealthCheckTimeout)
	defer cancel()

	err := checker.CheckAndUpdate(ctx)

	m.mu.Lock()
	m.healthStatus = checker.Status()
	m.mu.Unlock()

	return err
}

// Status returns the current process status.
func (m *XrayConfigManager) Status() ProcessStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// Logs returns all captured log entries.
func (m *XrayConfigManager) Logs() []LogEntry {
	return m.logBuffer.All()
}

// TailLogs returns the last n log entries.
func (m *XrayConfigManager) TailLogs(n int) []LogEntry {
	return m.logBuffer.Tail(n)
}

// ConfigPath returns the path to the generated config file.
func (m *XrayConfigManager) ConfigPath() string {
	return m.configPath
}

// BinaryPath returns the path to the xray binary.
func (m *XrayConfigManager) BinaryPath() string {
	return m.binaryPath
}

// writeConfigUnlocked generates and writes the config (caller must hold m.mu).
func (m *XrayConfigManager) writeConfigUnlocked() error {
	cfg, err := m.generateConfigUnlocked()
	if err != nil {
		return fmt.Errorf("generate config: %w", err)
	}

	if err := os.MkdirAll(m.configDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := atomicWriteFile(m.configPath, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// --- Key Generation Utilities ---

// GenerateShortID generates a random 8-byte hex short ID for REALITY.
// Returns a 16-character hex string.
func GenerateShortID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateX25519Key generates an X25519 keypair.
// Returns (privateKey, publicKey, error).
// The keys are base64-encoded (standard, with padding) as xray-core expects.
//
// The private key goes into the server config's privateKey field.
// The public key should be shared with clients for their password field
// (or publicKey in legacy mode).
func GenerateX25519Key() (privateKey, publicKey string, err error) {
	priv := make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}
	// Clamp the private key per RFC 7748
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	// Compute public key using curve25519 scalar multiplication
	// with the standard base point (9)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("compute public key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

// GenerateVLESSUUID generates a random UUIDv4 for VLESS user IDs.
func GenerateVLESSUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// Set version (4) and variant (10xx) bits
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// --- Errors ---

// ErrNotFound is returned when a requested inbound/outbound is not found.
var ErrNotFound = fmt.Errorf("not found")
