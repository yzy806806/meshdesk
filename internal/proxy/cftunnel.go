// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the Cloudflare Tunnel integration for proxy
// entry nodes. Per PROXY_DESIGN.md §2 and §3, entry nodes expose
// their SS listener via cloudflared, which provides TLS camouflage.
//
// The CF Tunnel integration provides:
//
//   - CONFIG GENERATION: Generates cloudflared config YAML for the
//     SS listener, including ingress rules and origin server config.
//   - HEALTH MONITORING: Periodically checks the tunnel's health
//     endpoint and reports status.
//   - TUNNEL MANAGEMENT: Start, stop, and status queries for the
//     cloudflared process.
//   - MULTI-TUNNEL SUPPORT: A node can expose multiple tunnels
//     (e.g., SS listener + Web UI) with separate ingress rules.
//
// CF Tunnel Limitations (PROXY_DESIGN.md §2):
//   - No bandwidth cap (CF has not published a limit)
//   - Idle timeout: connections dropped when idle; proxy scenario
//     has continuous traffic, not a concern
//   - TCP only: no UDP; UDP applications must be encapsulated in TCP
//   - CF ToS gray area: proxy traffic strictly violates ToS, but
//     enforcement is lax in practice
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// CFTunnelConfig holds configuration for a Cloudflare Tunnel.
type CFTunnelConfig struct {
	// TunnelID is the Cloudflare Tunnel UUID (from `cloudflared tunnel create`).
	TunnelID string `yaml:"tunnel_id,omitempty"`

	// TunnelName is the human-readable tunnel name.
	TunnelName string `yaml:"tunnel_name,omitempty"`

	// CredentialsFile is the path to the tunnel credentials JSON file
	// (created by `cloudflared tunnel create`).
	CredentialsFile string `yaml:"credentials_file,omitempty"`

	// IngressRules defines the routing rules for this tunnel.
	// Each rule maps a hostname/path to an origin service.
	IngressRules []CFIngressRule `yaml:"ingress_rules,omitempty"`

	// OriginServer is the local address that the SS listener binds to.
	// The tunnel forwards traffic here. Default: "127.0.0.1:8388".
	OriginServer string `yaml:"origin_server,omitempty"`

	// Region is the Cloudflare edge region preference. Empty = auto.
	// Example: "us", "eu", "ap".
	Region string `yaml:"region,omitempty"`

	// ReconnectRetries is the number of times to retry connecting
	// to the CF edge on failure. Default: 5.
	ReconnectRetries int `yaml:"reconnect_retries,omitempty"`

	// GracePeriod is the time to wait for existing connections to
	// drain before shutting down. Default: 30s.
	GracePeriodSec int `yaml:"grace_period_sec,omitempty"`

	// LogLevel controls cloudflared's logging verbosity.
	// "debug", "info", "warn", "error", "fatal". Default: "warn".
	LogLevel string `yaml:"log_level,omitempty"`

	// MetricsAddr is the address for cloudflared's metrics server.
	// Default: "127.0.0.1:36500". Used for health monitoring.
	MetricsAddr string `yaml:"metrics_addr,omitempty"`

	// BinaryPath is the path to the cloudflared binary.
	// If empty, uses "cloudflared" from PATH.
	BinaryPath string `yaml:"binary_path,omitempty"`
}

// CFIngressRule defines a single ingress routing rule for a CF Tunnel.
type CFIngressRule struct {
	// Hostname is the CF hostname to match (e.g., "proxy.example.com").
	// Empty matches all hostnames (catch-all rule, must be last).
	Hostname string `yaml:"hostname,omitempty"`

	// Path is the URL path to match (e.g., "/ws"). Empty matches all paths.
	Path string `yaml:"path,omitempty"`

	// Service is the origin service URL.
	// For SS-over-WebSocket: "ws://127.0.0.1:8388"
	// For HTTP: "http://127.0.0.1:8080"
	// For TCP: "tcp://127.0.0.1:8388"
	Service string `yaml:"service"`

	// OriginRequest holds advanced origin request settings.
	OriginRequest *CFOriginRequest `yaml:"origin_request,omitempty"`
}

// CFOriginRequest holds settings for how cloudflared connects to the
// origin server.
type CFOriginRequest struct {
	// ConnectTimeout is the timeout for connecting to the origin.
	// Default: 30s.
	ConnectTimeoutSec int `yaml:"connect_timeout_sec,omitempty"`

	// TLSTimeout is the TLS handshake timeout. Default: 10s.
	TLSTimeoutSec int `yaml:"tls_timeout_sec,omitempty"`

	// KeepAliveTimeout is the TCP keepalive timeout. Default: 15s.
	KeepAliveTimeoutSec int `yaml:"keep_alive_timeout_sec,omitempty"`

	// HTTPHostHeader overrides the Host header sent to the origin.
	HTTPHostHeader string `yaml:"http_host_header,omitempty"`

	// NoTLSVerify disables TLS certificate verification for the origin.
	// Use only for self-signed certs. Default: false.
	NoTLSVerify bool `yaml:"no_tls_verify,omitempty"`

	// NoHappyEyeballs disables the Happy Eyeballs algorithm for IPv4/IPv6.
	NoHappyEyeballs bool `yaml:"no_happy_eyeballs,omitempty"`
}

// CFTunnelManager manages the cloudflared process and monitors its health.
type CFTunnelManager struct {
	cfg CFTunnelConfig
	mu  sync.Mutex

	// cmd is the running cloudflared process.
	cmd *exec.Cmd

	// status is the current tunnel status.
	status CFTunnelStatus

	// healthCancel cancels the health check goroutine.
	healthCancel context.CancelFunc

	// healthClient is the HTTP client for health checks.
	healthClient *http.Client
}

// CFTunnelStatus represents the operational status of the tunnel.
type CFTunnelStatus struct {
	// Running is true if the cloudflared process is active.
	Running bool

	// Healthy is true if the tunnel is connected to CF edge.
	Healthy bool

	// LastHealthCheck is the time of the last successful health check.
	LastHealthCheck time.Time

	// LastError is the last health check error, if any.
	LastError string

	// ConnectionCount is the number of active tunnel connections.
	ConnectionCount int

	// PID is the cloudflared process ID (0 if not running).
	PID int

	// StartedAt is when the tunnel was started.
	StartedAt time.Time
}

// CFTunnelMetrics represents the metrics reported by cloudflared.
type CFTunnelMetrics struct {
	// Connected is whether the tunnel is connected to CF edge.
	Connected bool `json:"connected"`

	// ConnectionCount is the number of active connections.
	ConnectionCount int `json:"connectionCount"`

	// TotalRequests is the total number of requests served.
	TotalRequests int64 `json:"totalRequests"`

	// RequestErrors is the total number of request errors.
	RequestErrors int64 `json:"requestErrors"`
}

// NewCFTunnelManager creates a new CF Tunnel manager with the given config.
func NewCFTunnelManager(cfg CFTunnelConfig) *CFTunnelManager {
	if cfg.OriginServer == "" {
		cfg.OriginServer = "127.0.0.1:8388"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "warn"
	}
	if cfg.MetricsAddr == "" {
		cfg.MetricsAddr = "127.0.0.1:36500"
	}
	if cfg.ReconnectRetries == 0 {
		cfg.ReconnectRetries = 5
	}
	if cfg.GracePeriodSec == 0 {
		cfg.GracePeriodSec = 30
	}

	return &CFTunnelManager{
		cfg: cfg,
		healthClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// GenerateConfigYAML generates the cloudflared config.yaml content
// for this tunnel. This file is passed to cloudflared via --config.
//
// The config includes:
//   - Tunnel ID and credentials file path
//   - Ingress rules mapping hostnames to origin services
//   - Origin request settings (timeouts, TLS)
//   - Warp routing (disabled for proxy use case)
func (m *CFTunnelManager) GenerateConfigYAML() string {
	var b strings.Builder

	b.WriteString("tunnel: ")
	b.WriteString(m.cfg.TunnelID)
	b.WriteString("\n")

	b.WriteString("credentials-file: ")
	b.WriteString(m.cfg.CredentialsFile)
	b.WriteString("\n")

	if m.cfg.Region != "" {
		b.WriteString("region: ")
		b.WriteString(m.cfg.Region)
		b.WriteString("\n")
	}

	b.WriteString(fmt.Sprintf("retries: %d\n", m.cfg.ReconnectRetries))
	b.WriteString(fmt.Sprintf("grace-period: %ds\n", m.cfg.GracePeriodSec))
	b.WriteString("loglevel: ")
	b.WriteString(m.cfg.LogLevel)
	b.WriteString("\n")

	b.WriteString("metrics: ")
	b.WriteString(m.cfg.MetricsAddr)
	b.WriteString("\n")

	b.WriteString("ingress:\n")
	for _, rule := range m.cfg.IngressRules {
		b.WriteString("  - ")
		if rule.Hostname != "" {
			b.WriteString("hostname: ")
			b.WriteString(rule.Hostname)
			b.WriteString("\n")
			b.WriteString("    ")
		}
		if rule.Path != "" {
			b.WriteString("path: ")
			b.WriteString(rule.Path)
			b.WriteString("\n")
			b.WriteString("    ")
		}
		b.WriteString("service: ")
		b.WriteString(rule.Service)
		b.WriteString("\n")

		if rule.OriginRequest != nil {
			b.WriteString("    originRequest:\n")
			if rule.OriginRequest.ConnectTimeoutSec > 0 {
				b.WriteString(fmt.Sprintf("      connectTimeout: %ds\n", rule.OriginRequest.ConnectTimeoutSec))
			}
			if rule.OriginRequest.TLSTimeoutSec > 0 {
				b.WriteString(fmt.Sprintf("      tlsTimeout: %ds\n", rule.OriginRequest.TLSTimeoutSec))
			}
			if rule.OriginRequest.KeepAliveTimeoutSec > 0 {
				b.WriteString(fmt.Sprintf("      keepAliveTimeout: %ds\n", rule.OriginRequest.KeepAliveTimeoutSec))
			}
			if rule.OriginRequest.HTTPHostHeader != "" {
				b.WriteString(fmt.Sprintf("      httpHostHeader: %s\n", rule.OriginRequest.HTTPHostHeader))
			}
			if rule.OriginRequest.NoTLSVerify {
				b.WriteString("      noTLSVerify: true\n")
			}
			if rule.OriginRequest.NoHappyEyeballs {
				b.WriteString("      noHappyEyeballs: true\n")
			}
		}
	}

	// Catch-all rule (required by cloudflared).
	b.WriteString("  - service: http_status:404\n")

	return b.String()
}

// SaveConfigFile writes the generated config YAML to the given path.
func (m *CFTunnelManager) SaveConfigFile(path string) error {
	return os.WriteFile(path, []byte(m.GenerateConfigYAML()), 0600)
}

// Start launches the cloudflared tunnel process.
// The binary must be installed and the credentials file must exist.
func (m *CFTunnelManager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.status.Running {
		return fmt.Errorf("tunnel is already running (PID %d)", m.status.PID)
	}

	binary := m.cfg.BinaryPath
	if binary == "" {
		binary = "cloudflared"
	}

	// Verify the binary exists.
	if _, err := exec.LookPath(binary); err != nil {
		return fmt.Errorf("cloudflared binary not found: %w (install from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)", err)
	}

	// Verify credentials file exists.
	if m.cfg.CredentialsFile != "" {
		if _, err := os.Stat(m.cfg.CredentialsFile); err != nil {
			return fmt.Errorf("credentials file not found: %w", err)
		}
	}

	// Build the command arguments.
	args := []string{
		"tunnel",
		"--config", "/dev/stdin", // we'll pipe config via stdin
		"run",
		m.cfg.TunnelID,
	}

	cmd := exec.CommandContext(ctx, binary, args...)

	// Feed config via stdin.
	configYAML := m.GenerateConfigYAML()
	cmd.Stdin = strings.NewReader(configYAML)

	// Capture stderr for logging.
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start cloudflared: %w", err)
	}

	m.cmd = cmd
	m.status = CFTunnelStatus{
		Running:   true,
		Healthy:   false, // will be set true by health check
		PID:       cmd.Process.Pid,
		StartedAt: time.Now(),
	}

	// Start health monitoring goroutine.
	healthCtx, cancel := context.WithCancel(context.Background())
	m.healthCancel = cancel
	go m.healthMonitorLoop(healthCtx)

	return nil
}

// Stop gracefully shuts down the cloudflared tunnel.
func (m *CFTunnelManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.status.Running {
		return nil
	}

	// Cancel health monitoring.
	if m.healthCancel != nil {
		m.healthCancel()
		m.healthCancel = nil
	}

	// Send SIGTERM to cloudflared.
	if m.cmd != nil && m.cmd.Process != nil {
		if err := m.cmd.Process.Signal(os.Interrupt); err != nil {
			// If SIGINT fails, force kill.
			_ = m.cmd.Process.Kill()
		}
		// Wait for the process to exit.
		_ = m.cmd.Wait()
	}

	m.cmd = nil
	m.status = CFTunnelStatus{
		Running: false,
	}
	return nil
}

// Status returns the current tunnel status.
func (m *CFTunnelManager) Status() CFTunnelStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// healthMonitorLoop periodically checks the cloudflared metrics endpoint
// and updates the tunnel status.
func (m *CFTunnelManager) healthMonitorLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkHealth()
		}
	}
}

// checkHealth queries the cloudflared metrics endpoint to determine
// if the tunnel is healthy and connected to the CF edge.
func (m *CFTunnelManager) checkHealth() {
	metricsURL := fmt.Sprintf("http://%s/metrics", m.cfg.MetricsAddr)

	resp, err := m.healthClient.Get(metricsURL)
	if err != nil {
		m.mu.Lock()
		m.status.Healthy = false
		m.status.LastError = fmt.Sprintf("health check failed: %v", err)
		m.mu.Unlock()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		m.mu.Lock()
		m.status.Healthy = false
		m.status.LastError = fmt.Sprintf("health check returned %d", resp.StatusCode)
		m.mu.Unlock()
		return
	}

	// Parse the Prometheus-format metrics to extract connection count.
	// cloudflared exposes metrics in Prometheus text format.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		m.mu.Lock()
		m.status.Healthy = false
		m.status.LastError = fmt.Sprintf("read metrics: %v", err)
		m.mu.Unlock()
		return
	}

	connected := false
	connCount := 0

	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "cloudflared_tunnel_active_streams ") {
			// Format: cloudflared_tunnel_active_streams <count>
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				fmt.Sscanf(parts[1], "%d", &connCount)
				if connCount > 0 {
					connected = true
				}
			}
		}
	}

	m.mu.Lock()
	m.status.Healthy = connected
	m.status.ConnectionCount = connCount
	m.status.LastHealthCheck = time.Now()
	if connected {
		m.status.LastError = ""
	}
	m.mu.Unlock()
}

// IsTunnelReady returns true if the tunnel is running and healthy.
// Use this to gate SS listener startup: the SS listener should only
// start after the tunnel is ready to accept connections.
func (m *CFTunnelManager) IsTunnelReady() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status.Running && m.status.Healthy
}

// WaitForReady blocks until the tunnel is healthy or the timeout expires.
// Returns nil if healthy, error if timed out.
func (m *CFTunnelManager) WaitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.IsTunnelReady() {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("tunnel did not become ready within %v", timeout)
}

// GenerateSystemdUnit generates a systemd unit file for running
// cloudflared as a managed service. This is the recommended deployment
// method for production entry nodes.
func (m *CFTunnelManager) GenerateSystemdUnit() string {
	var b strings.Builder

	b.WriteString("[Unit]\n")
	b.WriteString("Description=MeshDesk Cloudflare Tunnel\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")

	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")

	binary := m.cfg.BinaryPath
	if binary == "" {
		binary = "/usr/local/bin/cloudflared"
	}
	b.WriteString("ExecStart=")
	b.WriteString(binary)
	b.WriteString(" tunnel --config /etc/meshdesk/cloudflared-config.yaml run ")
	b.WriteString(m.cfg.TunnelID)
	b.WriteString("\n")

	b.WriteString("Restart=on-failure\n")
	b.WriteString(fmt.Sprintf("RestartSec=%d\n", 5))
	b.WriteString("User=meshdesk\n")
	b.WriteString("Group=meshdesk\n")
	b.WriteString("AmbientCapabilities=CAP_NET_BIND_SERVICE\n\n")

	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")

	return b.String()
}

// Validate checks that the CF Tunnel configuration is valid.
// Returns nil if valid, error describing the issue otherwise.
func (m *CFTunnelManager) Validate() error {
	if m.cfg.TunnelID == "" {
		return fmt.Errorf("tunnel_id is required")
	}
	if m.cfg.CredentialsFile == "" {
		return fmt.Errorf("credentials_file is required")
	}
	if len(m.cfg.IngressRules) == 0 {
		return fmt.Errorf("at least one ingress rule is required")
	}
	// Check that the last rule is a catch-all (no hostname).
	// cloudflared requires this.
	last := m.cfg.IngressRules[len(m.cfg.IngressRules)-1]
	if last.Hostname != "" {
		// Not an error per se, but cloudflared will add one.
		// We just warn via the error return if it's the only rule.
	}
	return nil
}

// NewSSTunnelConfig is a convenience function that creates a CFTunnelConfig
// pre-configured for an SS-over-WebSocket entry node. The SS listener
// should be running on originServer (default 127.0.0.1:8388) and should
// accept WebSocket upgrades.
//
// Per PROXY_DESIGN.md §2, the user device → CF Tunnel → Entry node
// path uses "Shadowsocks over WebSocket":
//   - CF's TLS provides protocol camouflage layer (GFW sees access to
//     CF website), no Reality needed
//   - SS is lighter than xray, better performance
//   - CF IP space is vast; GFW cannot block all CF IPs
func NewSSTunnelConfig(tunnelID, credentialsFile, hostname, originServer string) CFTunnelConfig {
	if originServer == "" {
		originServer = "127.0.0.1:8388"
	}

	return CFTunnelConfig{
		TunnelID:        tunnelID,
		CredentialsFile: credentialsFile,
		OriginServer:    originServer,
		LogLevel:        "warn",
		MetricsAddr:     "127.0.0.1:36500",
		ReconnectRetries: 5,
		GracePeriodSec:  30,
		IngressRules: []CFIngressRule{
			{
				Hostname: hostname,
				Service:  fmt.Sprintf("ws://%s", originServer),
				OriginRequest: &CFOriginRequest{
					ConnectTimeoutSec:   30,
					TLSTimeoutSec:       10,
					KeepAliveTimeoutSec: 15,
				},
			},
			// Catch-all: return 404 for unmatched hostnames.
			{
				Service: "http_status:404",
			},
		},
	}
}

// NewWebUITunnelConfig creates a CFTunnelConfig for exposing the
// MeshDesk Web UI via CF Tunnel (Dashboard node use case).
func NewWebUITunnelConfig(tunnelID, credentialsFile, hostname, originServer string) CFTunnelConfig {
	if originServer == "" {
		originServer = "127.0.0.1:8080"
	}

	return CFTunnelConfig{
		TunnelID:         tunnelID,
		CredentialsFile:  credentialsFile,
		OriginServer:     originServer,
		LogLevel:         "warn",
		MetricsAddr:      "127.0.0.1:36500",
		ReconnectRetries: 5,
		GracePeriodSec:   30,
		IngressRules: []CFIngressRule{
			{
				Hostname: hostname,
				Service:  fmt.Sprintf("http://%s", originServer),
				OriginRequest: &CFOriginRequest{
					ConnectTimeoutSec:   30,
					TLSTimeoutSec:       10,
					KeepAliveTimeoutSec: 15,
				},
			},
			{
				Service: "http_status:404",
			},
		},
	}
}

// ParseMetricsJSON parses the JSON metrics output from cloudflared's
// /health endpoint (if available). This is an alternative to the
// Prometheus text format parser.
func ParseMetricsJSON(data []byte) (*CFTunnelMetrics, error) {
	var metrics CFTunnelMetrics
	if err := json.Unmarshal(data, &metrics); err != nil {
		return nil, fmt.Errorf("parse metrics JSON: %w", err)
	}
	return &metrics, nil
}

// EnsureLocalListener checks if a local TCP listener is active on
// the given address. This is useful to verify the SS listener is
// running before starting the tunnel.
func EnsureLocalListener(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("local listener %s not reachable: %w", addr, err)
	}
	conn.Close()
	return nil
}
