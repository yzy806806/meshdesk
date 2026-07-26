package xray

import (
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

// MaxRestartBackoff is the maximum delay between crash restart attempts.
const MaxRestartBackoff = 60 * time.Second

// InitialRestartBackoff is the initial delay before the first restart.
const InitialRestartBackoff = 1 * time.Second

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

	// KeyValueStore is an optional interface for persisting inbound configs.
	// When nil, configs are in-memory only (lost on restart).
	store ConfigStore
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
			ConfigPath: opts.ConfigPath,
			BinaryPath: binaryPath,
		},
		currentBackoff: InitialRestartBackoff,
	}

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

	if err := os.WriteFile(m.configPath, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// --- Process Management ---

// Start launches the xray-core subprocess with the current config.
// If xray is already running, it returns nil (no-op).
// The config is written to disk before starting.
func (m *XrayConfigManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.status.Running {
		return nil // already running
	}

	if m.stopped {
		return fmt.Errorf("manager has been stopped, create a new one")
	}

	// Write config to disk
	if err := m.writeConfigUnlocked(); err != nil {
		return err
	}

	// Check binary exists
	binaryPath := m.binaryPath
	if _, err := exec.LookPath(binaryPath); err != nil {
		return fmt.Errorf("xray binary not found: %s — install xray-core and ensure it is in PATH", binaryPath)
	}

	return m.startProcessUnlocked()
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

	// Start process monitor goroutine (handles crash auto-restart)
	go m.monitorProcess()

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
// crash auto-restart with exponential backoff.
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

		m.mu.Lock()
		wasStopped := m.stopped
		m.status.Running = false
		m.status.PID = 0
		m.mu.Unlock()

		if wasStopped {
			// Intentional stop — don't restart
			log.Printf("[xray] process exited (intentional stop): %v", err)
			return
		}

		// Process crashed or exited unexpectedly
		exitCode := -1
		if state != nil {
			exitCode = state.ExitCode()
		}
		log.Printf("[xray] process exited unexpectedly (code=%d, err=%v) — will restart in %v",
			exitCode, err, m.currentBackoff)

		// Wait for backoff or stop signal
		select {
		case <-time.After(m.currentBackoff):
			// Increase backoff for next time
			m.mu.Lock()
			m.status.RestartCount++
			m.status.LastRestart = time.Now()
			m.currentBackoff = m.currentBackoff * 2
			if m.currentBackoff > MaxRestartBackoff {
				m.currentBackoff = MaxRestartBackoff
			}

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
			log.Printf("[xray] restarted (attempt %d, pid=%d)", m.status.RestartCount, m.status.PID)
			m.mu.Unlock()

		case <-m.stopCh:
			return
		}
	}
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

	// Reset backoff on successful manual reload
	m.currentBackoff = InitialRestartBackoff

	log.Printf("[xray] SIGHUP sent for hot-reload (pid=%d)", m.status.PID)
	return nil
}

// Stop gracefully stops the xray-core subprocess.
// Sends SIGTERM, waits up to 5 seconds, then SIGKILL if still running.
func (m *XrayConfigManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.status.Running {
		return nil
	}

	m.stopped = true
	if m.stopCh != nil {
		close(m.stopCh)
	}

	if m.process == nil {
		m.status.Running = false
		return nil
	}

	// Send SIGTERM
	if err := m.process.Signal(syscall.SIGTERM); err != nil {
		log.Printf("[xray] SIGTERM failed: %v — trying SIGKILL", err)
		_ = m.process.Kill()
	}

	// Wait for exit (with timeout)
	done := make(chan struct{})
	go func() {
		m.process.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("[xray] process stopped gracefully (pid=%d)", m.status.PID)
	case <-time.After(5 * time.Second):
		log.Printf("[xray] process did not exit in 5s — sending SIGKILL")
		_ = m.process.Kill()
		<-done
	}

	m.status.Running = false
	m.status.PID = 0
	m.process = nil
	m.cmd = nil

	return nil
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

	if err := os.WriteFile(m.configPath, data, 0600); err != nil {
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
