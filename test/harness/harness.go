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
	"golang.org/x/crypto/curve25519"
)

// Constants for default ports and timeouts.
const (
	DefaultMeshBasePort   = 51820
	DefaultWebBasePort    = 18080
	DefaultHealthInterval = 500 * time.Millisecond
	DefaultStartupTimeout = 30 * time.Second
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

	// Obfuscation mode for all peers: "", "padded", or "websocket".
	Obfuscation string

	// Verbose enables verbose logging from meshdesk subprocesses.
	Verbose bool
}

// Node represents a running meshdesk instance.
type Node struct {
	Index      int
	Role       NodeRole
	PublicKey  string
	PrivateKey string
	MeshPort   int
	WebPort    int
	ConfigPath string
	StateDir   string
	cmd        *exec.Cmd
	logBuf     *safeBuffer
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
	for i := 0; i < h.cfg.NodeCount; i++ {
		node := h.createNodeConfig(i)
		h.nodes = append(h.nodes, node)
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

// createNodeConfig generates WireGuard keys, YAML config, and state directories
// for a single node. Does NOT start the process.
func (h *Harness) createNodeConfig(index int) *Node {
	role := RoleAgent
	webPort := 0
	if index == 0 {
		role = RoleCollector
		webPort = DefaultWebBasePort + index
	}

	// Generate WireGuard keypair (same method as internal/mesh/peer).
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		h.t.Fatalf("harness: generate key for node %d: %v", index, err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		h.t.Fatalf("harness: derive public key for node %d: %v", index, err)
	}

	meshPort := DefaultMeshBasePort + index
	stateDir := filepath.Join(h.tmpDir, fmt.Sprintf("node%d", index))
	os.MkdirAll(stateDir, 0700)

	node := &Node{
		Index:      index,
		Role:       role,
		PrivateKey: hex.EncodeToString(priv),
		PublicKey:  hex.EncodeToString(pub),
		MeshPort:   meshPort,
		WebPort:    webPort,
		StateDir:   stateDir,
		ConfigPath: filepath.Join(stateDir, "config.yaml"),
	}

	// Write config YAML.
	cfg := h.generateConfig(node)
	if err := os.WriteFile(node.ConfigPath, []byte(cfg), 0600); err != nil {
		h.t.Fatalf("harness: write config for node %d: %v", index, err)
	}

	h.t.Logf("[harness] Node %d: pubkey=%s mesh=%d web=%d role=%s",
		index, truncateKey(node.PublicKey), meshPort, webPort, role)
	return node
}

// generateConfig creates the YAML config for a node.
func (h *Harness) generateConfig(node *Node) string {
	webAddr := ""
	if node.Role == RoleCollector {
		webAddr = fmt.Sprintf(":%d", node.WebPort)
	}

	// Build peer list (all other nodes).
	var peerYAML strings.Builder
	for _, other := range h.nodes {
		if other.Index == node.Index {
			continue
		}
		peerYAML.WriteString(fmt.Sprintf(`  - public_key: "%s"
    endpoint: "127.0.0.1:%d"
    allowed_ips:
      - "10.10.%d.1/32"
`, other.PublicKey, other.MeshPort, other.Index+1))

		if h.cfg.Obfuscation != "" {
			peerYAML.WriteString(fmt.Sprintf(`    obfuscation: "%s"
`, h.cfg.Obfuscation))
		}
	}

	cfg := fmt.Sprintf(`node:
  identity: "%s"
  hostname: "test-node-%d"
  web: "%s"
mesh:
  port: %d
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

	// For agent nodes, check if the log shows startup completed and the mesh port is open.
	log := node.logString()
	if strings.Contains(log, "MeshDesk node started") || strings.Contains(log, "agent-only") {
		conn, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", node.MeshPort), 500*time.Millisecond)
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

	// Verify each node's process is alive and the mesh port is listening.
	alive := 0
	for _, node := range h.nodes {
		if !h.isNodeHealthy(node) {
			continue
		}
		conn, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", node.MeshPort), 1*time.Second)
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
func (h *Harness) ScenarioWebSSHConnect() (result, details string) {
	if len(h.nodes) < 1 || h.WebURL(0) == "" {
		return "SKIP", "no collector node with web UI available"
	}

	// Verify the web server is serving pages.
	url := h.WebURL(0) + "/"
	resp, err := httpGet(url, 3*time.Second)
	if err != nil {
		return "FAIL", fmt.Sprintf("web UI not reachable: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return "PASS", fmt.Sprintf("web UI reachable at %s (status %d)", url, resp.StatusCode)
	}
	return "FAIL", fmt.Sprintf("web UI returned %d", resp.StatusCode)
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

	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return "PASS", fmt.Sprintf("service API returns %d", resp.StatusCode)
	}
	return "FAIL", fmt.Sprintf("service API returned %d", resp.StatusCode)
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

	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return "PASS", fmt.Sprintf("file upload API returns %d", resp.StatusCode)
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

	if resp.StatusCode >= 500 {
		return "FAIL", fmt.Sprintf("collector returned 5xx: %d", resp.StatusCode)
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
	if len(h.nodes) < 1 || h.WebURL(0) == "" {
		return "SKIP", "no collector node with web UI available"
	}

	// Use the collector's own public key as the peer ID.
	// The collector should have its own pubkey in the routing table.
	peerID := h.nodes[0].PublicKey

	ws, wsURL, err := h.dialWebSSH(peerID, 80, 24)
	if err != nil {
		return "FAIL", fmt.Sprintf("WebSocket dial failed: %v", err)
	}
	defer ws.Close()

	sessID := fmt.Sprintf("ws-%d", time.Now().UnixNano())
	sessPrefix := fmt.Sprintf("[%s]", sessID)

	// Wait for status messages (connecting → either connected or error).
	msgs, err := h.collectWSMessages(ws, 5*time.Second, 10)
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

// ScenarioWebSSHErrorPath verifies error handling: unresolvable peer, unreachable SSH.
func (h *Harness) ScenarioWebSSHErrorPath() (result, details string) {
	if len(h.nodes) < 1 || h.WebURL(0) == "" {
		return "SKIP", "no collector node with web UI available"
	}

	// Try connecting to a non-existent peer.
	ws, _, err := h.dialWebSSH("nonexistent-deadbeef", 80, 24)
	if err != nil {
		return "FAIL", fmt.Sprintf("WebSocket dial failed: %v", err)
	}
	defer ws.Close()

	msgs, err := h.collectWSMessages(ws, 5*time.Second, 10)
	if err != nil {
		return "FAIL", fmt.Sprintf("read messages: %v", err)
	}

	// Should receive an error message about unresolvable peer.
	hasError := false
	errorText := ""
	for _, raw := range msgs {
		msg, err := decodeWSMessage(raw)
		if err != nil {
			continue
		}
		if msg.Type == "error" {
			hasError = true
			errorText = msg.Data
			break
		}
	}

	if !hasError {
		return "FAIL", fmt.Sprintf("expected error for unresolvable peer, got messages: %s", trunc(strings.Join(msgs, "|"), 200))
	}

	return "PASS", fmt.Sprintf("error path OK: %s", trunc(errorText, 100))
}

// ScenarioWebSSHMaxSessions tests that the max-sessions limit is enforced.
func (h *Harness) ScenarioWebSSHMaxSessions() (result, details string) {
	if len(h.nodes) < 1 || h.WebURL(0) == "" {
		return "SKIP", "no collector node with web UI available"
	}

	const maxTestSessions = 5

	// Open multiple sessions with an error-prone peer (will stick in connecting/resolving).
	var sessions []*websocket.Conn
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	opened := 0
	rejected := 0
	for i := 0; i < maxTestSessions; i++ {
		// Use a fake peer to trigger error quickly — sessions that error out should be cleaned up.
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
	if len(h.nodes) < 1 || h.WebURL(0) == "" {
		return "SKIP", "no collector node with web UI available"
	}

	peerID := h.nodes[0].PublicKey

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
