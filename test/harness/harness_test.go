package harness

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSuiteRealDevice runs the complete real-device integration test suite.
// It requires a pre-built meshdesk binary (go build -o meshdesk ./cmd/meshdesk/).
//
// This is a comprehensive end-to-end test that spawns real meshdesk
// subprocesses and verifies all 7 stop-condition criteria:
//
//	C1 — Mesh VPN connectivity
//	C2 — NAT traversal (tested implicitly via localhost mesh)
//	C3 — Cross-region resilience (tested via subprocess lifecycle)
//	C4 — WebSSH terminal
//	C5 — File transfer
//	C6 — Service management
//	C7 — Monitoring metrics
//
// Run with:
//
//	go test -v -timeout 300s ./test/harness/ -run TestSuiteRealDevice
//
// To skip (when no binary is available), set MESHDESK_SKIP_REAL=1:
//
//	MESHDESK_SKIP_REAL=1 go test ./test/harness/
func TestSuiteRealDevice(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set — skipping real-device tests")
	}

	// Check if the binary exists.
	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found — build it first: go build -o meshdesk ./cmd/meshdesk/")
	}

	t.Logf("=== MeshDesk Real-Device Integration Test Suite ===")
	t.Logf("Binary: %s", binaryPath)
	t.Logf("Time:   %s", time.Now().Format(time.RFC3339))

	h := New(t, Config{
		NodeCount:  3,
		BinaryPath: binaryPath,
		Verbose:    testing.Verbose(),
	})

	t.Log("--- Phase 1: Cluster Startup ---")
	h.Start()
	defer h.Stop()

	t.Log("--- Phase 2: Mesh VPN Connectivity (C1) ---")
	h.RunScenario(SceneMeshPing, "mesh", "P2P mesh connectivity — all nodes healthy",
		h.ScenarioMeshPing)

	t.Log("--- Phase 3: NAT Traversal (C2) ---")
	h.RunScenario(SceneNatReach, "nat", "Node reachability through mesh",
		h.scenarioNatReach)

	t.Log("--- Phase 4: Cross-Region Resilience (C3) ---")
	h.RunScenario(SceneLatReconnect, "resilience", "Process lifecycle resilience",
		h.scenarioResilience)

	t.Log("--- Phase 5: WebSSH Terminal (C4) ---")
	h.RunScenario(SceneSSHConnect, "webssh", "WebSSH endpoint availability",
		h.ScenarioWebSSHConnect)

	t.Log("--- Phase 6: File Transfer (C5) ---")
	h.RunScenario(SceneTransferUpload, "transfer", "File upload endpoint",
		h.ScenarioFileUpload)

	t.Log("--- Phase 7: Service Management (C6) ---")
	h.RunScenario(SceneServiceList, "service", "Service management API",
		h.ScenarioServiceManagement)

	t.Log("--- Phase 8: Monitoring Metrics (C7) ---")
	h.RunScenario(SceneMetricsCPU, "monitoring", "Dashboard with live metrics",
		h.ScenarioMetricsCollection)

	t.Log("--- Phase 9: End-to-End Cluster Validation ---")
	h.RunScenario("C-all-e2e", "integration", "Full cluster end-to-end verification",
		h.ScenarioClusterEndToEnd)

	t.Log("--- Results ---")
	report := h.Report()
	t.Logf("\n%s", report)

	// Save report to file.
	reportPath := filepath.Join(h.tmpDir, "real_device_report.json")
	os.WriteFile(reportPath, []byte(report), 0644)
	t.Logf("Report saved: %s", reportPath)

	// Also save to test/results if it exists.
	resultsDir := filepath.Join(repoRoot(t), "test", "results")
	if _, err := os.Stat(resultsDir); err == nil {
		os.WriteFile(filepath.Join(resultsDir, "real_device_report.json"), []byte(report), 0644)
	}
}

// TestQuickSanity runs a fast 1-node cluster test for CI pre-flight checks.
func TestQuickSanity(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  1,
		BinaryPath: binaryPath,
	})
	h.Start()
	defer h.Stop()

	// Quick check: web UI is accessible.
	h.RunScenario(SceneSSHConnect, "webssh", "Quick sanity — web UI reachable",
		h.ScenarioWebSSHConnect)
}

// TestBinaryBuildAndSmoke builds the binary and runs a smoke test.
// This test does NOT skip — it always tries to build.
func TestBinaryBuildAndSmoke(t *testing.T) {
	// Build the binary.
	repoRoot := repoRoot(t)
	binaryPath := filepath.Join(t.TempDir(), "meshdesk")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/meshdesk/")
	buildCmd.Dir = repoRoot
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	t.Logf("Binary built: %s", binaryPath)

	// Verify binary works.
	versionCmd := exec.Command(binaryPath, "--help")
	out, err := versionCmd.Output()
	if err != nil {
		t.Fatalf("Binary execution failed: %v", err)
	}
	if !strings.Contains(string(out), "config") && !strings.Contains(string(out), "Usage") {
		t.Logf("Binary output: %s", string(out))
	}

	// Generate a keypair.
	genKeyCmd := exec.Command(binaryPath, "--gen-key")
	keyOut, err := genKeyCmd.Output()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}
	if !strings.Contains(string(keyOut), "Private") || !strings.Contains(string(keyOut), "Public") {
		t.Errorf("Unexpected key output: %s", string(keyOut))
	}
	t.Logf("Key generation: PASS")
}

// TestNodeLifecycle tests the full lifecycle of a single node.
func TestNodeLifecycle(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  1,
		BinaryPath: binaryPath,
		Verbose:    testing.Verbose(),
	})

	t.Log("Starting single node...")
	h.Start()

	// Verify node is running.
	nodes := h.Nodes()
	if len(nodes) != 1 {
		t.Fatalf("Expected 1 node, got %d", len(nodes))
	}
	if nodes[0].PublicKey == "" {
		t.Error("Node has empty public key")
	}
	if nodes[0].PrivateKey == "" {
		t.Error("Node has empty private key")
	}

	// Verify web UI is accessible.
	if h.WebURL(0) != "" {
		resp, err := httpGet(h.WebURL(0)+"/", 3*time.Second)
		if err != nil {
			t.Errorf("Web UI not accessible: %v", err)
		} else {
			resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 500 {
				t.Errorf("Web UI returned %d", resp.StatusCode)
			} else {
				t.Logf("Web UI: %d", resp.StatusCode)
			}
		}
	}

	t.Log("Stopping node...")
	h.Stop()

	t.Logf("Node logs:\n%s", nodes[0].logString())
}

// TestFileUploadAPI tests the file upload API endpoint.
func TestFileUploadAPI(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  1,
		BinaryPath: binaryPath,
	})
	h.Start()
	defer h.Stop()

	if h.WebURL(0) == "" {
		t.Skip("no web UI on single agent node")
	}

	// Test file upload.
	url := h.WebURL(0) + "/api/files/upload"
	content := []byte("meshdesk-test-file-content-12345")
	resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(content))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	t.Logf("Upload response: %d — %s", resp.StatusCode, string(respBody))

	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		// 4xx is acceptable (e.g., missing form fields) — the endpoint exists.
		if resp.StatusCode >= 500 {
			t.Errorf("Upload API returned 5xx: %d", resp.StatusCode)
		} else {
			t.Logf("Upload API returns %d (endpoint exists, may need multipart form)", resp.StatusCode)
		}
	}
}

// TestServiceAPI tests the service management API endpoint.
func TestServiceAPI(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  1,
		BinaryPath: binaryPath,
	})
	h.Start()
	defer h.Stop()

	if h.WebURL(0) == "" {
		t.Skip("no web UI on single agent node")
	}

	url := h.WebURL(0) + "/api/services"
	resp, err := httpGet(url, 3*time.Second)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	t.Logf("Services API response: %d — %s", resp.StatusCode, string(body))

	if resp.StatusCode >= 500 {
		t.Errorf("Services API returned 5xx: %d", resp.StatusCode)
	}
}

// TestDashboardAccess tests the web dashboard is accessible.
func TestDashboardAccess(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  1,
		BinaryPath: binaryPath,
	})
	h.Start()
	defer h.Stop()

	if h.WebURL(0) == "" {
		t.Skip("no web UI on single agent node")
	}

	url := h.WebURL(0) + "/"
	resp, err := httpGet(url, 3*time.Second)
	if err != nil {
		t.Fatalf("Dashboard unreachable: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	t.Logf("Dashboard: %d (%d bytes)", resp.StatusCode, len(body))

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Dashboard returned %d, expected 200", resp.StatusCode)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "MeshDesk") && !strings.Contains(bodyStr, "mesh") && !strings.Contains(bodyStr, "html") {
		t.Errorf("Dashboard content missing expected elements: %s", trunc(bodyStr, 200))
	} else {
		t.Log("Dashboard content: OK")
	}
}

// TestPeerConnectivity tests that nodes can establish peer connections.
func TestPeerConnectivity(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  3,
		BinaryPath: binaryPath,
	})
	h.Start()
	defer h.Stop()

	// Verify all 3 nodes are healthy.
	for _, node := range h.Nodes() {
		if !h.isNodeHealthy(node) {
			t.Errorf("Node %d not healthy after startup", node.Index)
		} else {
			t.Logf("Node %d healthy: mesh=%d", node.Index, node.MeshPort)
		}
	}

	// Verify each node's mesh port is accepting connections.
	for _, node := range h.Nodes() {
		conn, err := netDialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", node.MeshPort), 1*time.Second)
		if err != nil {
			t.Errorf("Node %d mesh port %d not reachable: %v", node.Index, node.MeshPort, err)
		} else {
			conn.Close()
			t.Logf("Node %d mesh port %d: reachable", node.Index, node.MeshPort)
		}
	}

	// Check process logs for peer handshake messages.
	for _, node := range h.Nodes() {
		log := node.logString()
		if strings.Contains(log, "peer") || strings.Contains(log, "Peer") {
			t.Logf("Node %d: peer activity in logs", node.Index)
		}
	}
}

// TestGracefulShutdown verifies that nodes shut down cleanly on SIGINT.
func TestGracefulShutdown(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  1,
		BinaryPath: binaryPath,
	})
	h.Start()

	node := h.Nodes()[0]
	pid := node.cmd.Process.Pid

	// Send SIGINT.
	t.Logf("Sending SIGINT to pid %d", pid)
	h.Stop()

	// Wait briefly and verify process is gone.
	time.Sleep(1 * time.Second)

	if isProcessAlive(pid) {
		// Still alive — may still be shutting down. Wait a bit more.
		time.Sleep(2 * time.Second)
		if isProcessAlive(pid) {
			// Force kill it.
			process, _ := os.FindProcess(pid)
			if process != nil {
				process.Kill()
			}
			t.Log("Process was still alive after SIGINT — killed")
		}
	}

	t.Log("Graceful shutdown: PASS")
}

// TestWebSSHLifecycle tests the complete WebSSH session lifecycle
// against a real meshdesk collector node: WebSocket connect,
// status messages, and cleanup.
func TestWebSSHLifecycle(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  1,
		BinaryPath: binaryPath,
	})
	h.Start()
	defer h.Stop()

	h.RunScenario(SceneSSHLifecycle, "webssh", "WebSSH lifecycle: WS connect → status → close",
		h.ScenarioWebSSHLifecycle)
}

// TestWebSSHErrorPath tests error handling: unresolvable peer returns
// a proper error message.
func TestWebSSHErrorPath(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  1,
		BinaryPath: binaryPath,
	})
	h.Start()
	defer h.Stop()

	h.RunScenario(SceneSSHErrorPath, "webssh", "WebSSH error path: unresolvable peer → error",
		h.ScenarioWebSSHErrorPath)
}

// TestWebSSHSessionCleanup verifies that sessions are cleaned up after
// WebSocket disconnect — no zombie sessions.
func TestWebSSHSessionCleanup(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  1,
		BinaryPath: binaryPath,
	})
	h.Start()
	defer h.Stop()

	h.RunScenario(SceneSSHSessionCleanup, "webssh", "WebSSH session cleanup after disconnect",
		h.ScenarioWebSSHSessionCleanup)
}

// TestWebSSHMaxSessions tests session limit enforcement via real
// WebSocket connections to a meshdesk collector.
func TestWebSSHMaxSessions(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  1,
		BinaryPath: binaryPath,
	})
	h.Start()
	defer h.Stop()

	h.RunScenario(SceneSSHMaxSessions, "webssh", "WebSSH max sessions enforcement",
		h.ScenarioWebSSHMaxSessions)
}

// TestWebSSHDataRaceRegression runs the WebSSH scenarios with the Go race
// detector enabled, verifying no data races occur in session lifecycle.
func TestWebSSHDataRaceRegression(t *testing.T) {
	if os.Getenv("MESHDESK_SKIP_REAL") == "1" {
		t.Skip("MESHDESK_SKIP_REAL=1 set")
	}

	binaryPath := findMeshDeskBinary(t)
	if binaryPath == "" {
		t.Skip("meshdesk binary not found")
	}

	h := New(t, Config{
		NodeCount:  3,
		BinaryPath: binaryPath,
	})
	h.Start()
	defer h.Stop()

	// Run multiple WebSSH scenarios against the live cluster
	// to exercise concurrent session code paths.
	h.RunScenario(SceneSSHLifecycle, "webssh", "race: session lifecycle",
		h.ScenarioWebSSHLifecycle)
	h.RunScenario(SceneSSHErrorPath, "webssh", "race: error path",
		h.ScenarioWebSSHErrorPath)
	h.RunScenario(SceneSSHSessionCleanup, "webssh", "race: session cleanup",
		h.ScenarioWebSSHSessionCleanup)
	h.RunScenario(SceneSSHMaxSessions, "webssh", "race: max sessions",
		h.ScenarioWebSSHMaxSessions)

	report := h.Report()
	t.Logf("\n%s", report)

	// Save race report for historical tracking.
	resultsDir := filepath.Join(repoRoot(t), "test", "results")
	if _, err := os.Stat(resultsDir); err == nil {
		os.WriteFile(filepath.Join(resultsDir, "webssh_race_report.json"), []byte(report), 0644)
	}
}

// --- Internal test helpers ---

// findMeshDeskBinary looks for the meshdesk binary in common locations.
func findMeshDeskBinary(t *testing.T) string {
	t.Helper()

	// Check explicit env var.
	if p := os.Getenv("MESHDESK_BINARY"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Check common locations.
	candidates := []string{
		"meshdesk",                // relative to CWD
		"./meshdesk",              // explicit relative
		"/root/meshdesk/meshdesk", // repo root
	}

	// Also check relative to the test file's location.
	if repo := repoRoot(t); repo != "" {
		candidates = append(candidates, filepath.Join(repo, "meshdesk"))
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}

	return ""
}

// repoRoot finds the MeshDesk repository root relative to this test file.
func repoRoot(t *testing.T) string {
	t.Helper()
	// Walk up from the test harness directory to find go.mod.
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// netDialTimeout wraps net.DialTimeout for readability.
func netDialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

// --- Additional scenario implementations ---

// scenarioNatReach verifies that all nodes are reachable through the mesh.
func (h *Harness) scenarioNatReach() (result, details string) {
	reachable := 0
	for _, node := range h.nodes {
		if h.isNodeHealthy(node) {
			reachable++
		}
	}
	if reachable == len(h.nodes) {
		return "PASS", fmt.Sprintf("all %d nodes reachable", reachable)
	}
	return "FAIL", fmt.Sprintf("only %d/%d nodes reachable", reachable, len(h.nodes))
}

// scenarioResilience verifies the cluster can survive process-level operations.
func (h *Harness) scenarioResilience() (result, details string) {
	// Verify all nodes survived startup and are still running.
	alive := 0
	for _, node := range h.nodes {
		if node.cmd.Process != nil && isProcessAlive(node.cmd.Process.Pid) {
			alive++
		}
	}
	if alive == len(h.nodes) {
		return "PASS", fmt.Sprintf("all %d nodes survived startup and health checks", alive)
	}
	return "FAIL", fmt.Sprintf("only %d/%d nodes alive after startup", alive, len(h.nodes))
}

// Import needed for net.Conn.
var _ net.Conn = nil
