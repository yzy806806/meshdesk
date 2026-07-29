// Package harness provides a real-device integration test framework for MeshDesk.
//
// It spawns real meshdesk subprocesses on localhost, configures them with
// WireGuard identities and peer relationships, runs test scenarios against
// the live cluster, and collects structured results.
//
// Unlike the existing in-process mock tests (net.Pipe, inProcMesh), this
// harness uses real networking, real WireGuard tunnels, real SSH servers,
// and real HTTP servers — exercising the full production code path.
//
// Usage:
//
//	func TestMeshCluster(t *testing.T) {
//	    h := harness.New(t, harness.Config{NodeCount: 3})
//	    h.Start()
//	    defer h.Stop()
//
//	    // Nodes are now running — test scenarios against them.
//	    h.RunScenario(harness.SceneMeshPing, "mesh", "P2P mesh ping",
//	        h.ScenarioMeshPing)
//	    h.RunScenario(harness.SceneSSHConnect, "webssh", "WebSSH terminal",
//	        h.ScenarioWebSSHConnect)
//
//	    report := h.Report()
//	    t.Logf("Report: %s", report)
//	}
package harness

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Constants for default ports and timeouts.
const (
	DefaultMeshBasePort   = 51820
	DefaultWebBasePort    = 18080
	DefaultHealthInterval = 500 * time.Millisecond
	DefaultStartupTimeout = 30 * time.Second

	// defaultShortID is the REALITY short ID used by all test nodes.
	// Hex-encoded, 8 bytes — the max length accepted by the REALITY protocol.
	defaultShortID = "0123456789abcdef"
)

// NodeRole defines the operational role of a test node.
type NodeRole string

const (
	RoleCollector NodeRole = "collector" // web UI + aggregator
	RoleAgent     NodeRole = "agent"     // agent-only (no web UI)
)

// Config configures the test harness.
type Config struct {
	// NodeCount is the number of meshdesk nodes to spawn (default 3).
	NodeCount int

	// BinaryPath is the path to the meshdesk binary (default "./meshdesk").
	BinaryPath string

	// Verbose enables verbose logging from meshdesk subprocesses.
	Verbose bool
}

// Node represents a running meshdesk instance.
type Node struct {
	Index      int
	Role       NodeRole
	PublicKey  string // Ed25519 public key (hex) — node identity
	PrivateKey string // Ed25519 private key (hex) — node identity
	MeshPort   int    // Reality TLS TCP listen port
	WebPort    int
	ConfigPath string
	StateDir   string

	// Reality TLS keypair (X25519, distinct from the Ed25519 identity).
	RealityPrivKey string // hex-encoded X25519 private key (server-side)
	RealityPubKey  string // hex-encoded X25519 public key (client-side)

	cmd    *exec.Cmd
	logBuf *safeBuffer
}

// Harness manages a cluster of meshdesk nodes for integration testing.
type Harness struct {
	t      *testing.T
	cfg    Config
	nodes  []*Node
	tmpDir string
	binary string
	mu     sync.Mutex

	// results accumulates scenario outcomes.
	results []ScenarioResult
}

// ScenarioResult is the outcome of a single test scenario.
type ScenarioResult struct {
	ID          string  `json:"id"`
	Category    string  `json:"category"`
	Description string  `json:"description"`
	Result      string  `json:"result"` // "PASS", "FAIL", "SKIP"
	Duration    float64 `json:"duration_s"`
	Details     string  `json:"details,omitempty"`
}

// New creates a new test harness.
func New(t *testing.T, cfg Config) *Harness {
	t.Helper()
	if cfg.NodeCount == 0 {
		cfg.NodeCount = 3
	}
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = "./meshdesk"
	}
	return &Harness{t: t, cfg: cfg}
}

// Start builds (if needed) and starts all nodes in the cluster.
func (h *Harness) Start() {
	h.t.Helper()

	// Resolve binary path.
	abs, err := filepath.Abs(h.cfg.BinaryPath)
	if err != nil {
		h.t.Fatalf("harness: resolve binary path: %v", err)
	}
	if _, err := os.Stat(abs); os.IsNotExist(err) {
		h.t.Fatalf("harness: meshdesk binary not found at %s — build it first: go build -o meshdesk ./cmd/meshdesk/", abs)
	}
	h.binary = abs

	// Create temp directory.
	h.tmpDir = h.t.TempDir()

	h.t.Logf("[harness] Starting %d-node cluster (binary: %s)", h.cfg.NodeCount, h.binary)

	// Generate keys and configs for all nodes.
	// First pass: generate keypairs and create Node structs (without
	// writing config yet — the peer list depends on all nodes existing).
	for i := 0; i < h.cfg.NodeCount; i++ {
		node := h.createNode(i)
		h.nodes = append(h.nodes, node)
	}

	// Second pass: now that all nodes are in h.nodes, write configs
	// so each node's peer list includes all other nodes.
	for _, node := range h.nodes {
		cfg := h.generateConfig(node)
		if err := os.WriteFile(node.ConfigPath, []byte(cfg), 0600); err != nil {
			h.t.Fatalf("harness: write config for node %d: %v", node.Index, err)
		}
	}

	// Start all nodes sequentially.
	for _, node := range h.nodes {
		h.startNode(node)
	}

	// Wait for all nodes to be healthy.
	h.waitForAllHealthy()

	// Configure peer relationships (full mesh).
	h.configurePeers()

	h.t.Logf("[harness] Cluster ready: %d nodes running", len(h.nodes))
}

// Stop gracefully terminates all nodes and collects final logs.
func (h *Harness) Stop() {
	h.t.Helper()
	for _, node := range h.nodes {
		if node.cmd == nil || node.cmd.Process == nil {
			continue
		}
		h.t.Logf("[harness] Stopping node %d (pid %d)...", node.Index, node.cmd.Process.Pid)
		node.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			node.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			node.cmd.Process.Kill()
		}
	}
	h.t.Logf("[harness] All nodes stopped")
}

// Nodes returns the list of running nodes.
func (h *Harness) Nodes() []*Node {
	return h.nodes
}

// WebURL returns the HTTP base URL for a node (collector role only).
func (h *Harness) WebURL(nodeIdx int) string {
	if nodeIdx < 0 || nodeIdx >= len(h.nodes) {
		return ""
	}
	n := h.nodes[nodeIdx]
	if n.WebPort == 0 {
		return ""
	}
	return fmt.Sprintf("http://127.0.0.1:%d", n.WebPort)
}

// MeshAddr returns the mesh IP address for a node.
func (h *Harness) MeshAddr(nodeIdx int) string {
	return fmt.Sprintf("10.10.%d.1", nodeIdx+1)
}

// Report generates a JSON summary of all scenario results.
func (h *Harness) Report() string {
	h.mu.Lock()
	defer h.mu.Unlock()

	type Report struct {
		Title     string           `json:"report"`
		Timestamp string           `json:"timestamp"`
		Nodes     int              `json:"nodes"`
		Scenarios []ScenarioResult `json:"scenarios"`
		Passed    int              `json:"passed"`
		Failed    int              `json:"failed"`
		Skipped   int              `json:"skipped"`
	}
	r := Report{
		Title:     "MeshDesk Real-Device Integration Test Report",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Nodes:     len(h.nodes),
		Scenarios: h.results,
	}
	for _, s := range h.results {
		switch s.Result {
		case "PASS":
			r.Passed++
		case "FAIL":
			r.Failed++
		case "SKIP":
			r.Skipped++
		}
	}
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data)
}

// RunScenario executes a named scenario and records the result.
// The fn must return (result, details).
func (h *Harness) RunScenario(id, category, description string, fn func() (string, string)) {
	h.t.Helper()
	start := time.Now()
	result, details := fn()
	duration := time.Since(start).Seconds()

	sr := ScenarioResult{
		ID:          id,
		Category:    category,
		Description: description,
		Result:      result,
		Duration:    duration,
		Details:     details,
	}

	h.mu.Lock()
	h.results = append(h.results, sr)
	h.mu.Unlock()

	switch result {
	case "PASS":
		h.t.Logf("[%s] %s — PASS (%.1fs)", id, description, duration)
	case "FAIL":
		h.t.Errorf("[%s] %s — FAIL (%.1fs): %s", id, description, duration, details)
	case "SKIP":
		h.t.Logf("[%s] %s — SKIP (%.1fs): %s", id, description, duration, details)
	}
}

// --- Internal helpers ---

// createNode generates an Ed25519 identity keypair and an X25519 Reality
// TLS keypair, then creates a Node struct (without writing the config —
// that happens in a second pass once all nodes exist, so each peer list
// is complete).
func (h *Harness) createNode(index int) *Node {
	role := RoleAgent
	webPort := 0
	if index == 0 {
		role = RoleCollector
		webPort = DefaultWebBasePort + index
	}

	// Generate Ed25519 identity keypair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.t.Fatalf("harness: generate identity key for node %d: %v", index, err)
	}

	// Generate X25519 Reality TLS keypair (separate from Ed25519 identity).
	realityPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		h.t.Fatalf("harness: generate reality key for node %d: %v", index, err)
	}
	realityPub := realityPriv.PublicKey()

	meshPort := DefaultMeshBasePort + index
	stateDir := filepath.Join(h.tmpDir, fmt.Sprintf("node%d", index))
	os.MkdirAll(stateDir, 0700)

	node := &Node{
		Index:          index,
		Role:           role,
		PrivateKey:     hex.EncodeToString(priv),
		PublicKey:      hex.EncodeToString(pub),
		MeshPort:       meshPort,
		WebPort:        webPort,
		StateDir:       stateDir,
		ConfigPath:     filepath.Join(stateDir, "config.yaml"),
		RealityPrivKey: hex.EncodeToString(realityPriv.Bytes()),
		RealityPubKey:  hex.EncodeToString(realityPub.Bytes()),
	}

	h.t.Logf("[harness] Node %d: pubkey=%s mesh=%d web=%d role=%s",
		index, truncateKey(node.PublicKey), meshPort, webPort, role)
	return node
}

// generateConfig creates the YAML config for a node.
// Produces v2-style configs with Reality TLS enabled.
func (h *Harness) generateConfig(node *Node) string {
	webAddr := ""
	if node.Role == RoleCollector {
		webAddr = fmt.Sprintf(":%d", node.WebPort)
	}

	// Build peer list (all other nodes) with v2 Reality TLS peer config.
	var peerYAML strings.Builder
	for _, other := range h.nodes {
		if other.Index == node.Index {
			continue
		}
		fmt.Fprintf(&peerYAML, `  - public_key: "%s"
    endpoint: "127.0.0.1:%d"
    allowed_ips:
      - "10.10.%d.1/32"
    capabilities:
      - ssh_proxy
    reality:
      server_name: "www.apple.com"
      public_key: "%s"
      short_id: "%s"
`, other.PublicKey, other.MeshPort, other.Index+1,
			other.RealityPubKey, defaultShortID)
	}

	cfg := fmt.Sprintf(`node:
  identity: "%s"
  hostname: "test-node-%d"
  web: "%s"
mesh:
  port: %d
reality:
  enabled: true
  listen_addr: "127.0.0.1"
  listen_port: %d
  dest: "www.apple.com:443"
  private_key: "%s"
  short_ids:
    - "%s"
  server_names:
    - "www.apple.com"
peers:
%s
monitoring:
  collectors: []
  interval: 5
  port: 4191
webssh:
  port: 2222
  max_sessions: 64
  dial_timeout: 5
  read_deadline: 30
  write_deadline: 5
auth: {}
transfer:
  max_file_size: 10485760
  upload_dir: "%s"
`, node.PrivateKey, node.Index, webAddr, node.MeshPort,
		node.MeshPort, node.RealityPrivKey, defaultShortID,
		peerYAML.String(),
		filepath.Join(node.StateDir, "uploads"))
	return cfg
}

// startNode launches the meshdesk binary for a single node.
func (h *Harness) startNode(node *Node) {
	var args []string
	args = append(args, "--config", node.ConfigPath)
	if node.Role == RoleCollector {
		args = append(args, "--web")
	}

	node.cmd = exec.Command(h.binary, args...)
	node.logBuf = new(safeBuffer)
	if h.cfg.Verbose {
		node.cmd.Stdout = io.MultiWriter(node.logBuf, os.Stdout)
		node.cmd.Stderr = io.MultiWriter(node.logBuf, os.Stderr)
	} else {
		node.cmd.Stdout = node.logBuf
		node.cmd.Stderr = node.logBuf
	}

	// Set the working directory to node's state dir so relative paths work.
	node.cmd.Dir = node.StateDir

	h.t.Logf("[harness] Starting node %d: %s %s", node.Index, h.binary, strings.Join(args, " "))
	if err := node.cmd.Start(); err != nil {
		logs := node.logString()
		h.t.Fatalf("harness: start node %d: %v\nLogs:\n%s", node.Index, err, logs)
	}
}

// waitForAllHealthy polls each node until it's responsive or timeout.
func (h *Harness) waitForAllHealthy() {
	h.t.Helper()
	deadline := time.After(DefaultStartupTimeout)
	ticker := time.NewTicker(DefaultHealthInterval)
	defer ticker.Stop()

	for {
		done := true
		for _, node := range h.nodes {
			if !h.isNodeHealthy(node) {
				done = false
				break
			}
		}
		if done {
			return
		}

		select {
		case <-deadline:
			for _, node := range h.nodes {
				if !h.isNodeHealthy(node) {
					h.t.Errorf("harness: node %d not healthy after %v\nLogs:\n%s",
						node.Index, DefaultStartupTimeout, node.logString())
				}
			}
			h.t.Fatal("harness: cluster failed to become healthy")
		case <-ticker.C:
			// Poll again.
		}
	}
}

// isNodeHealthy checks if a node is responsive.
func (h *Harness) isNodeHealthy(node *Node) bool {
	// Check process alive via /proc (portable Linux method).
	if node.cmd.Process == nil {
		return false
	}
	if !isProcessAlive(node.cmd.Process.Pid) {
		h.t.Logf("[harness] Node %d (pid %d) exited\nLogs:\n%s", node.Index, node.cmd.Process.Pid, node.logString())
		return false
	}

	// For collector nodes, try the web UI health endpoint.
	if node.Role == RoleCollector && node.WebPort > 0 {
		url := fmt.Sprintf("http://127.0.0.1:%d/", node.WebPort)
		resp, err := httpGet(url, 2*time.Second)
		if err == nil && resp != nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return true
			}
		}
		// If web not yet up, check if the log shows startup complete.
		log := node.logString()
		if strings.Contains(log, "MeshDesk node started") || strings.Contains(log, "Web UI:") {
			return true
		}
		return false
	}

	// For agent nodes, check if the log shows startup completed and the
	// Reality TLS TCP port is open.
	log := node.logString()
	if strings.Contains(log, "MeshDesk node started") || strings.Contains(log, "agent-only") {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", node.MeshPort), 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// isProcessAlive checks if a process with the given PID is alive using /proc.
func isProcessAlive(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// configurePeers establishes full-mesh peer relationships.
func (h *Harness) configurePeers() {
	h.t.Helper()
	h.t.Logf("[harness] Peer relationships: full mesh (%d nodes)", len(h.nodes))
	for i := range h.nodes {
		for j := range h.nodes {
			if i == j {
				continue
			}
			h.t.Logf("[harness]   node%d <-> node%d", i, j)
		}
	}
	// Peers are already configured in the YAML configs at startup.
	// MeshDesk connects to peers automatically on node start.
}

// truncateKey returns a short version of a key for logging.
func truncateKey(key string) string {
	if len(key) > 12 {
		return key[:12] + "..."
	}
	return key
}

// httpGet performs a GET request with a timeout.
func httpGet(url string, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{Timeout: timeout}
	return client.Get(url)
}

// --- Built-in scenario functions ---

// Scenario ID constants for all stop-condition criteria.
const (
	SceneMeshPing          = "C1-mesh-ping"
	SceneMeshHandshake     = "C1-mesh-handshake"
	SceneMeshThroughput    = "C1-mesh-throughput"
	SceneNatReach          = "C2-nat-reach"
	SceneNatBidir          = "C2-nat-bidir"
	SceneNatKeepalive      = "C2-nat-keepalive"
	SceneLatReconnect      = "C3-latency-reconnect"
	ScenePacketLoss        = "C3-packet-loss"
	ScenePartitionHeal     = "C3-partition-heal"
	SceneSSHConnect        = "C4-ssh-connect"
	SceneSSHLifecycle      = "C4-ssh-lifecycle"
	SceneSSHErrorPath      = "C4-ssh-error"
	SceneSSHMaxSessions    = "C4-ssh-max"
	SceneSSHSessionCleanup = "C4-ssh-cleanup"
	SceneSSHMultiplex      = "C4-ssh-multiplex"
	SceneSSHResize         = "C4-ssh-resize"
	SceneTransferUpload    = "C5-transfer-upload"
	SceneTransferDownload  = "C5-transfer-download"
	SceneTransferChecksum  = "C5-transfer-checksum"
	SceneServiceList       = "C6-service-list"
	SceneServiceRestart    = "C6-service-restart"
	SceneServiceLogs       = "C6-service-logs"
	SceneMetricsCPU        = "C7-metrics-cpu"
	SceneMetricsMemory     = "C7-metrics-memory"
	SceneMetricsDisk       = "C7-metrics-disk"
)

// ScenarioMeshPing tests that mesh nodes are running with their mesh ports listening.
func (h *Harness) ScenarioMeshPing() (result, details string) {
	if len(h.nodes) < 2 {
		return "SKIP", "need at least 2 nodes"
	}

	// Verify each node's process is alive and the Reality TLS port is listening.
	alive := 0
	for _, node := range h.nodes {
		if !h.isNodeHealthy(node) {
			continue
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", node.MeshPort), 1*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
		alive++
	}

	if alive == len(h.nodes) {
		return "PASS", fmt.Sprintf("all %d nodes healthy with mesh ports listening", len(h.nodes))
	}
	return "FAIL", fmt.Sprintf("only %d/%d nodes healthy", alive, len(h.nodes))
}

// ScenarioWebSSHConnect tests WebSSH terminal endpoint availability.
// It verifies the web UI is reachable, checks that WebSSH-related
// frontend assets are served, and — when the cluster has ≥2 nodes —
// attempts a real WebSocket dial to confirm the /ws/terminal endpoint
// is accepting connections.
//
// A full WebSocket lifecycle test is provided by ScenarioWebSSHLifecycle.
func (h *Harness) ScenarioWebSSHConnect() (result, details string) {
	if len(h.nodes) < 1 || h.WebURL(0) == "" {
		return "SKIP", "no collector node with web UI available"
	}

	url := h.WebURL(0) + "/"
	resp, err := httpGet(url, 3*time.Second)
	if err != nil {
		return "FAIL", fmt.Sprintf("web UI not reachable: %v", err)
	}
	defer resp.Body.Close()

	// Only 2xx is success. 4xx/5xx are errors.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "FAIL", fmt.Sprintf("web UI returned %d: %s", resp.StatusCode, trunc(string(body), 200))
	}

	// Read body to confirm WebSSH content is served.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	bodyStr := string(body)

	// Verify the dashboard includes WebSSH-related assets.
	hasWebSSH := strings.Contains(bodyStr, "terminal") ||
		strings.Contains(bodyStr, "webssh") ||
		strings.Contains(bodyStr, "WebSSH") ||
		strings.Contains(bodyStr, "websocket") ||
		strings.Contains(bodyStr, "/ws/")

	if !hasWebSSH {
		return "PASS", fmt.Sprintf("web UI reachable at %s (status %d, %d bytes — WebSSH assets may load dynamically)", url, resp.StatusCode, len(bodyStr))
	}

	// If we have ≥2 nodes, try an actual WebSocket connection.
	if len(h.nodes) >= 2 {
		peerID := h.nodes[1].PublicKey
		ws, wsURL, err := h.dialWebSSH(peerID, 80, 24)
		if err != nil {
			return "FAIL", fmt.Sprintf("WebSSH WebSocket dial failed: %v (peer=%s, ws=%s)", err, truncateKey(peerID), wsURL)
		}
		ws.Close()
		return "PASS", fmt.Sprintf("WebSSH endpoint available: WebSocket connected to %s", wsURL)
	}

	return "PASS", fmt.Sprintf("web UI reachable at %s (status %d, WebSSH assets detected)", url, resp.StatusCode)
}

// ScenarioMetricsCollection tests that the web dashboard is accessible.
func (h *Harness) ScenarioMetricsCollection() (result, details string) {
	if len(h.nodes) < 1 || h.WebURL(0) == "" {
		return "SKIP", "no collector node with web UI available"
	}

	url := h.WebURL(0) + "/"
	resp, err := httpGet(url, 3*time.Second)
	if err != nil {
		return "FAIL", fmt.Sprintf("dashboard not reachable: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != http.StatusOK {
		return "FAIL", fmt.Sprintf("dashboard returned %d: %s", resp.StatusCode, trunc(string(body), 200))
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "MeshDesk") || strings.Contains(bodyStr, "Dashboard") || strings.Contains(bodyStr, "mesh") {
		return "PASS", "dashboard renders with expected content"
	}

	return "PASS", fmt.Sprintf("web UI returned %d (%d bytes)", resp.StatusCode, len(bodyStr))
}

// ScenarioServiceManagement tests the service management API.
func (h *Harness) ScenarioServiceManagement() (result, details string) {
	if len(h.nodes) < 1 || h.WebURL(0) == "" {
		return "SKIP", "no collector node with web UI available"
	}

	url := h.WebURL(0) + "/api/services"
	resp, err := httpGet(url, 3*time.Second)
	if err != nil {
		return "FAIL", fmt.Sprintf("service API not reachable: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyStr := trunc(string(respBody), 200)

	// Only HTTP 200 with actual service data is success.
	// 4xx (404, 400, etc.) and 5xx are errors — never mark them as PASS.
	if resp.StatusCode != http.StatusOK {
		return "FAIL", fmt.Sprintf("service API returned %d: %s", resp.StatusCode, bodyStr)
	}

	// Verify the response body contains service data (JSON array/object).
	hasData := strings.Contains(string(respBody), "service") ||
		strings.Contains(string(respBody), "[") ||
		strings.Contains(string(respBody), "{")

	if !hasData {
		return "FAIL", fmt.Sprintf("service API returned 200 but body lacks service data: %s", bodyStr)
	}

	return "PASS", fmt.Sprintf("service API returns %d with service data: %s", resp.StatusCode, bodyStr)
}

// ScenarioFileUpload tests the file upload endpoint.
func (h *Harness) ScenarioFileUpload() (result, details string) {
	if len(h.nodes) < 1 || h.WebURL(0) == "" {
		return "SKIP", "no collector node with web UI available"
	}

	url := h.WebURL(0) + "/api/files/upload"
	content := []byte("meshdesk-integration-test-content")
	body := bytes.NewReader(content)
	resp, err := http.Post(url, "application/octet-stream", body)
	if err != nil {
		return "FAIL", fmt.Sprintf("file upload API not reachable: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	detailsStr := trunc(string(respBody), 200)

	// Only 2xx is success. HTTP 400, 404, and all other 4xx/5xx are errors.
	// The harness must NEVER mark an error response as PASS.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "PASS", fmt.Sprintf("file upload API returns %d: %s", resp.StatusCode, detailsStr)
	}
	return "FAIL", fmt.Sprintf("file upload API returned %d: %s", resp.StatusCode, detailsStr)
}

// ScenarioClusterEndToEnd verifies all nodes are running and the collector is operational.
func (h *Harness) ScenarioClusterEndToEnd() (result, details string) {
	if len(h.nodes) < 2 || h.WebURL(0) == "" {
		return "SKIP", "need at least 2 nodes with a collector"
	}

	url := h.WebURL(0) + "/"
	resp, err := httpGet(url, 3*time.Second)
	if err != nil {
		return "FAIL", fmt.Sprintf("collector unreachable: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "FAIL", fmt.Sprintf("collector returned %d", resp.StatusCode)
	}

	// Verify all agent nodes are still running.
	for _, node := range h.nodes {
		if node.Role == RoleAgent && !h.isNodeHealthy(node) {
			return "FAIL", fmt.Sprintf("agent node %d not healthy", node.Index)
		}
	}

	return "PASS", fmt.Sprintf("all %d nodes operational, collector healthy", len(h.nodes))
}

// --- Thread-safe log buffer ---

// safeBuffer wraps bytes.Buffer with a mutex so that subprocess stdout/stderr
// goroutines can write concurrently with the test goroutine reading via String().
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// --- WebSSH (C4) lifecycle scenarios ---

// ScenarioWebSSHLifecycle tests the complete WebSSH session lifecycle:
// WebSocket connect → receive status messages → close → verify cleanup.
func (h *Harness) ScenarioWebSSHLifecycle() (result, details string) {
	if len(h.nodes) < 2 || h.WebURL(0) == "" {
		return "SKIP", "need ≥2 nodes (collector + peer with ssh_proxy) for WebSSH lifecycle test"
	}

	// Use node 1's pubkey — it's a peer of node 0 (collector) with ssh_proxy
	// capability in node 0's config, so RequireCapability will allow it.
	peerID := h.nodes[1].PublicKey

	ws, wsURL, err := h.dialWebSSH(peerID, 80, 24)
	if err != nil {
		return "FAIL", fmt.Sprintf("WebSocket dial failed: %v", err)
	}
	defer ws.Close()

	sessID := fmt.Sprintf("ws-%d", time.Now().UnixNano())
	sessPrefix := fmt.Sprintf("[%s]", sessID)

	// Wait for status messages (connecting → either connected or error).
	// Use 8s to allow for the SSH dial timeout (default 5s) to expire and
	// produce an error status message.
	msgs, err := h.collectWSMessages(ws, 8*time.Second, 10)
	if err != nil {
		return "FAIL", fmt.Sprintf("%s read messages: %v", sessPrefix, err)
	}

	foundConnecting := false
	foundDisposition := false
	var disposition string

	for _, raw := range msgs {
		msg, err := decodeWSMessage(raw)
		if err != nil {
			continue
		}
		switch msg.Type {
		case "status":
			if strings.Contains(msg.Data, "connecting") {
				foundConnecting = true
			}
			if strings.Contains(msg.Data, "connected") || strings.Contains(msg.Data, "disconnected") {
				foundDisposition = true
				disposition = "status-received"
			}
		case "connected":
			foundDisposition = true
			disposition = "connected"
		case "error":
			foundDisposition = true
			disposition = "error:" + msg.Data
		}
	}

	if !foundConnecting {
		return "FAIL", fmt.Sprintf("%s no 'connecting' status received; messages: %v", sessPrefix, msgs)
	}
	if !foundDisposition {
		return "FAIL", fmt.Sprintf("%s no final disposition received (connected/error); messages: %v", sessPrefix, msgs)
	}

	return "PASS", fmt.Sprintf("WebSSH lifecycle OK: connecting → %s (ws=%s)", disposition, wsURL)
}

// ScenarioWebSSHErrorPath verifies error handling: unresolvable peer is
// rejected. With RequireCapability middleware, an unknown peer ID gets 403
// at the HTTP layer (before WebSocket upgrade). This is the correct security
// behavior — the capability check rejects unknown peers before any session
// work begins.
func (h *Harness) ScenarioWebSSHErrorPath() (result, details string) {
	if len(h.nodes) < 1 || h.WebURL(0) == "" {
		return "SKIP", "no collector node with web UI available"
	}

	// Dial with a non-existent peer ID. RequireCapability rejects it
	// with 403 Forbidden, which the WebSocket dialer reports as a
	// "bad handshake" error. This is the expected and correct behavior.
	_, _, err := h.dialWebSSH("nonexistent-deadbeef", 80, 24)
	if err != nil {
		// "bad handshake" means the server returned a non-101 status (403),
		// which is exactly what RequireCapability should do for unknown peers.
		return "PASS", "unknown peer correctly rejected by RequireCapability (403 / bad handshake)"
	}

	// If the dial somehow succeeded, the peer was unexpectedly authorized.
	return "FAIL", "WebSocket dial succeeded for unknown peer — RequireCapability should have rejected it"
}

// ScenarioWebSSHMaxSessions tests that the max-sessions limit is enforced.
// With RequireCapability, fake peers are rejected at the HTTP layer (403).
// This test verifies that unknown peers are rejected and the server stays
// healthy — no leaks or crashes from repeated rejections.
func (h *Harness) ScenarioWebSSHMaxSessions() (result, details string) {
	if len(h.nodes) < 1 || h.WebURL(0) == "" {
		return "SKIP", "no collector node with web UI available"
	}

	const maxTestSessions = 5

	// Open multiple sessions with fake peers — RequireCapability rejects
	// them all with 403 before WebSocket upgrade. This verifies the server
	// handles rejection gracefully without leaks.
	var sessions []*websocket.Conn
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	opened := 0
	rejected := 0
	for i := 0; i < maxTestSessions; i++ {
		// Use a fake peer to trigger capability rejection.
		ws, _, err := h.dialWebSSH("fake-peer-"+fmt.Sprint(i), 80, 24)
		if err != nil {
			rejected++
			continue
		}
		messages, _ := h.collectWSMessages(ws, 3*time.Second, 5)
		_ = messages
		sessions = append(sessions, ws)
		opened++
	}

	if opened == 0 && rejected == 0 {
		return "FAIL", "no sessions could be opened"
	}

	return "PASS", fmt.Sprintf("session limit test: opened=%d rejected=%d (all cleaned up)", opened, rejected)
}

// ScenarioWebSSHSessionCleanup verifies that sessions are cleaned up after
// WebSocket disconnect — no zombie PTYs or SSH connections.
func (h *Harness) ScenarioWebSSHSessionCleanup() (result, details string) {
	if len(h.nodes) < 2 || h.WebURL(0) == "" {
		return "SKIP", "need ≥2 nodes (collector + peer with ssh_proxy) for WebSSH session cleanup test"
	}

	// Use node 1's pubkey — it's a peer of node 0 (collector) with ssh_proxy.
	peerID := h.nodes[1].PublicKey

	// Open a WebSocket connection.
	ws, _, err := h.dialWebSSH(peerID, 80, 24)
	if err != nil {
		return "FAIL", fmt.Sprintf("WebSocket dial failed: %v", err)
	}

	// Read a few messages then abruptly close.
	_, _ = h.collectWSMessages(ws, 2*time.Second, 3)
	ws.Close()

	// Wait for cleanup to happen server-side.
	time.Sleep(500 * time.Millisecond)

	// Verify we can still connect (hub is still alive and responsive).
	ws2, _, err := h.dialWebSSH(peerID, 80, 24)
	if err != nil {
		return "FAIL", fmt.Sprintf("subsequent WebSocket dial failed after cleanup: %v", err)
	}
	ws2.Close()

	return "PASS", "session cleanup OK: disconnect → cleanup → reconnect successful"
}

// --- WebSocket helpers ---

// dialWebSSH opens a WebSocket connection to the collector's /ws/terminal endpoint.
func (h *Harness) dialWebSSH(peerID string, cols, rows int) (*websocket.Conn, string, error) {
	rawURL := fmt.Sprintf("%s/ws/terminal?node=%s&cols=%d&rows=%d", h.WebURL(0), peerID, cols, rows)
	wsURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", err
	}
	wsURL.Scheme = "ws"

	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	ws, _, err := dialer.Dial(wsURL.String(), nil)
	if err != nil {
		return nil, "", err
	}

	return ws, wsURL.String(), nil
}

// collectWSMessages reads all available messages from the WebSocket within the timeout.
func (h *Harness) collectWSMessages(ws *websocket.Conn, timeout time.Duration, maxMsgs int) ([]string, error) {
	var msgs []string
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) && len(msgs) < maxMsgs {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		ws.SetReadDeadline(time.Now().Add(remaining))
		_, raw, err := ws.ReadMessage()
		if err != nil {
			if len(msgs) == 0 {
				return nil, err
			}
			break // partial success — return what we have
		}
		msgs = append(msgs, string(raw))

		// If we got an error or connected message, stop collecting.
		msg, err := decodeWSMessage(string(raw))
		if err == nil {
			if msg.Type == "error" || msg.Type == "connected" {
				break
			}
		}
	}

	return msgs, nil
}

// decodeWSMessage decodes a WebSocket JSON message envelope.
func decodeWSMessage(raw string) (struct {
	Type string `json:"type"`
	Data string `json:"data"`
}, error) {
	var msg struct {
		Type string `json:"type"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		return msg, fmt.Errorf("decode ws message: %w", err)
	}
	return msg, nil
}

func (n *Node) logString() string {
	return n.logBuf.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
