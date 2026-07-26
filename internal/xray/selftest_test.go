package xray

import (
	"encoding/json"
	"testing"
	"time"
)

// --- SelfTest() unit tests ---

func TestSelfTestNotRunning(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1, // disable health checker
	})

	result := m.SelfTest()

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Summary.Total == 0 {
		t.Fatal("expected at least 1 check")
	}

	// Binary check: configured path is "xray" by default; if not
	// installed, this will be a fail. Either way it should produce
	// a valid check entry.
	binaryCheck := findCheck(result, "binary_present")
	if binaryCheck == nil {
		t.Fatal("expected binary_present check")
	}
	if binaryCheck.Status != CheckPass && binaryCheck.Status != CheckWarn && binaryCheck.Status != CheckFail {
		t.Fatalf("unexpected binary check status: %s", binaryCheck.Status)
	}

	// Process running: should be fail since we never started
	procCheck := findCheck(result, "process_running")
	if procCheck == nil {
		t.Fatal("expected process_running check")
	}
	if procCheck.Status != CheckFail {
		t.Fatalf("expected process_running to fail (not running), got %s", procCheck.Status)
	}

	// gRPC health: should be skip since health checking is disabled
	grpcCheck := findCheck(result, "grpc_health")
	if grpcCheck == nil {
		t.Fatal("expected grpc_health check")
	}
	if grpcCheck.Status != CheckSkip {
		t.Fatalf("expected grpc_health skip (disabled), got %s", grpcCheck.Status)
	}

	// Overall should be unhealthy (process_running failed)
	if result.Overall != OverallUnhealthy {
		t.Fatalf("expected overall unhealthy, got %s", result.Overall)
	}

	// Verify summary counts match
	if result.Summary.Failed == 0 {
		t.Fatal("expected at least 1 failed check")
	}
}

func TestSelfTestWithMockGRPCHealthy(t *testing.T) {
	addr, cleanup := mockHTTP2Server(t)
	defer cleanup()

	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   8421,
		ApiListen: "127.0.0.1",
	})
	// Point the health checker at the mock gRPC server
	m.healthChecker = NewHealthChecker(addr, 3*time.Second)

	// Simulate running state
	m.mu.Lock()
	m.status.Running = true
	m.status.PID = 12345
	m.status.StartedAt = time.Now().Add(-30 * time.Second)
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	result := m.SelfTest()

	// gRPC health should pass
	grpcCheck := findCheck(result, "grpc_health")
	if grpcCheck == nil {
		t.Fatal("expected grpc_health check")
	}
	if grpcCheck.Status != CheckPass {
		t.Fatalf("expected grpc_health pass, got %s: %s", grpcCheck.Status, grpcCheck.Message)
	}

	// Process running should pass
	procCheck := findCheck(result, "process_running")
	if procCheck == nil {
		t.Fatal("expected process_running check")
	}
	if procCheck.Status != CheckPass {
		t.Fatalf("expected process_running pass, got %s", procCheck.Status)
	}

	// Circuit breaker should be closed (pass)
	cbCheck := findCheck(result, "circuit_breaker")
	if cbCheck == nil {
		t.Fatal("expected circuit_breaker check")
	}
	if cbCheck.Status != CheckPass {
		t.Fatalf("expected circuit_breaker pass (closed), got %s", cbCheck.Status)
	}
}

func TestSelfTestCircuitBreakerOpen(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	// Force the circuit breaker open
	m.mu.Lock()
	m.circuitState = CircuitOpen
	m.circuitTrippedAt = time.Now()
	m.status.CircuitState = CircuitOpen
	m.status.CrashCount = 5
	m.mu.Unlock()

	result := m.SelfTest()

	cbCheck := findCheck(result, "circuit_breaker")
	if cbCheck == nil {
		t.Fatal("expected circuit_breaker check")
	}
	if cbCheck.Status != CheckFail {
		t.Fatalf("expected circuit_breaker fail (open), got %s", cbCheck.Status)
	}
	if cbCheck.Details["state"] != "open" {
		t.Fatalf("expected state 'open', got %v", cbCheck.Details["state"])
	}

	// Overall should be unhealthy
	if result.Overall != OverallUnhealthy {
		t.Fatalf("expected overall unhealthy, got %s", result.Overall)
	}
}

func TestSelfTestInboundConfigsValid(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:         "proxy-in",
		Port:        443,
		Security:    "reality",
		Dest:        "www.cloudflare.com:443",
		ServerNames: []string{"www.cloudflare.com"},
		PrivateKey:  priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	result := m.SelfTest()

	ibCheck := findCheck(result, "inbound_configs")
	if ibCheck == nil {
		t.Fatal("expected inbound_configs check")
	}
	if ibCheck.Status != CheckPass {
		t.Fatalf("expected inbound_configs pass, got %s: %s", ibCheck.Status, ibCheck.Message)
	}
}

func TestSelfTestInboundConfigsWithIssues(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	// Add an inbound with missing required reality fields
	m.AddInbound(&InboundConfig{
		Tag:      "broken-in",
		Port:     443,
		Security: "reality",
		// Missing: PrivateKey, ServerNames, Dest
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	result := m.SelfTest()

	ibCheck := findCheck(result, "inbound_configs")
	if ibCheck == nil {
		t.Fatal("expected inbound_configs check")
	}
	if ibCheck.Status != CheckFail {
		t.Fatalf("expected inbound_configs fail, got %s: %s", ibCheck.Status, ibCheck.Message)
	}
}

func TestSelfTestNoInbounds(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	result := m.SelfTest()

	ibCheck := findCheck(result, "inbound_configs")
	if ibCheck == nil {
		t.Fatal("expected inbound_configs check")
	}
	if ibCheck.Status != CheckWarn {
		t.Fatalf("expected inbound_configs warn (no inbounds), got %s", ibCheck.Status)
	}
}

func TestSelfTestConfigValidity(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:         "test",
		Port:        443,
		Security:    "reality",
		Dest:        "www.cloudflare.com:443",
		ServerNames: []string{"www.cloudflare.com"},
		PrivateKey:  priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	result := m.SelfTest()

	cfgCheck := findCheck(result, "config_valid")
	if cfgCheck == nil {
		t.Fatal("expected config_valid check")
	}
	// Should be at least pass or warn (warn if xray binary not available for -test)
	if cfgCheck.Status == CheckFail {
		t.Fatalf("expected config_valid pass/warn, got fail: %s", cfgCheck.Message)
	}
}

func TestSelfTestRecentLogsNoErrors(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	// Add some non-error log lines
	m.logBuffer.Add(LogEntry{Timestamp: time.Now(), Stream: "stdout", Line: "starting xray-core"})
	m.logBuffer.Add(LogEntry{Timestamp: time.Now(), Stream: "stdout", Line: "xray started"})

	result := m.SelfTest()

	logCheck := findCheck(result, "recent_log_errors")
	if logCheck == nil {
		t.Fatal("expected recent_log_errors check")
	}
	if logCheck.Status != CheckPass {
		t.Fatalf("expected recent_log_errors pass, got %s", logCheck.Status)
	}
}

func TestSelfTestRecentLogsWithErrors(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	// Add some error log lines
	m.logBuffer.Add(LogEntry{Timestamp: time.Now(), Stream: "stderr", Line: "[Error] failed to listen on port 443"})
	m.logBuffer.Add(LogEntry{Timestamp: time.Now(), Stream: "stderr", Line: "ERROR: config parse failed"})
	m.logBuffer.Add(LogEntry{Timestamp: time.Now(), Stream: "stdout", Line: "starting xray-core"})

	result := m.SelfTest()

	logCheck := findCheck(result, "recent_log_errors")
	if logCheck == nil {
		t.Fatal("expected recent_log_errors check")
	}
	if logCheck.Status != CheckWarn {
		t.Fatalf("expected recent_log_errors warn, got %s", logCheck.Status)
	}

	errorCount, ok := logCheck.Details["error_count"].(int)
	if !ok {
		t.Fatal("expected error_count in details")
	}
	if errorCount < 2 {
		t.Fatalf("expected error_count >= 2, got %d", errorCount)
	}
}

func TestSelfTestJSONSerialization(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	result := m.SelfTest()

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}

	// Round-trip back
	var decoded SelfTestResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	if decoded.Summary.Total != result.Summary.Total {
		t.Fatalf("total mismatch: %d vs %d", decoded.Summary.Total, result.Summary.Total)
	}
	if decoded.Overall != result.Overall {
		t.Fatalf("overall mismatch: %s vs %s", decoded.Overall, result.Overall)
	}
	if len(decoded.Checks) != len(result.Checks) {
		t.Fatalf("checks count mismatch: %d vs %d", len(decoded.Checks), len(result.Checks))
	}
}

func TestSelfTestSummaryAggregation(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	checks := []SelfTestCheck{
		{Name: "a", Status: CheckPass},
		{Name: "b", Status: CheckPass},
		{Name: "c", Status: CheckWarn},
		{Name: "d", Status: CheckFail},
		{Name: "e", Status: CheckSkip},
	}

	summary := m.summarizeChecks(checks)

	if summary.Total != 5 {
		t.Fatalf("expected total 5, got %d", summary.Total)
	}
	if summary.Passed != 2 {
		t.Fatalf("expected passed 2, got %d", summary.Passed)
	}
	if summary.Warnings != 1 {
		t.Fatalf("expected warnings 1, got %d", summary.Warnings)
	}
	if summary.Failed != 1 {
		t.Fatalf("expected failed 1, got %d", summary.Failed)
	}
	if summary.Skipped != 1 {
		t.Fatalf("expected skipped 1, got %d", summary.Skipped)
	}

	overall := m.computeOverallStatus(summary)
	if overall != OverallUnhealthy {
		t.Fatalf("expected unhealthy (1 fail), got %s", overall)
	}

	// No fails, 1 warning → degraded
	summary2 := SelfTestSummary{Total: 3, Passed: 2, Warnings: 1}
	if overall2 := m.computeOverallStatus(summary2); overall2 != OverallDegraded {
		t.Fatalf("expected degraded, got %s", overall2)
	}

	// All pass → healthy
	summary3 := SelfTestSummary{Total: 3, Passed: 3}
	if overall3 := m.computeOverallStatus(summary3); overall3 != OverallHealthy {
		t.Fatalf("expected healthy, got %s", overall3)
	}
}

func TestSelfTestAllChecksPresent(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	result := m.SelfTest()

	expectedChecks := []string{
		"binary_present",
		"config_valid",
		"process_running",
		"grpc_health",
		"inbound_configs",
		"circuit_breaker",
		"recent_log_errors",
	}

	for _, name := range expectedChecks {
		if findCheck(result, name) == nil {
			t.Errorf("expected check %q in results, not found", name)
		}
	}

	if len(result.Checks) != len(expectedChecks) {
		t.Fatalf("expected %d checks, got %d", len(expectedChecks), len(result.Checks))
	}
}

func TestSelfTestDurationRecorded(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})

	result := m.SelfTest()

	if result.Duration <= 0 {
		t.Fatal("expected positive duration")
	}
}

func TestSelfTestGRPCHealthSkippedWhenNotRunning(t *testing.T) {
	addr, cleanup := mockHTTP2Server(t)
	defer cleanup()

	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   8421,
		ApiListen: "127.0.0.1",
	})
	m.healthChecker = NewHealthChecker(addr, 3*time.Second)

	// Not setting Running = true, so xray is not running

	result := m.SelfTest()

	grpcCheck := findCheck(result, "grpc_health")
	if grpcCheck == nil {
		t.Fatal("expected grpc_health check")
	}
	if grpcCheck.Status != CheckSkip {
		t.Fatalf("expected grpc_health skip (not running), got %s", grpcCheck.Status)
	}
}

// --- containsLower tests ---

func TestContainsLower(t *testing.T) {
	tests := []struct {
		s, substr string
		expected  bool
	}{
		{"hello world", "world", true},
		{"Hello World", "world", true},
		{"HELLO", "hello", true},
		{"hello", "HELLO", true},
		{"hello", "xyz", false},
		{"", "abc", false},
		{"abc", "", true},
		{"[Error] failed", "error", true},
		{"INFO: starting", "error", false},
	}

	for _, tt := range tests {
		got := containsLower(tt.s, tt.substr)
		if got != tt.expected {
			t.Errorf("containsLower(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.expected)
		}
	}
}

// --- Test helper ---

func findCheck(result *SelfTestResult, name string) *SelfTestCheck {
	for i := range result.Checks {
		if result.Checks[i].Name == name {
			return &result.Checks[i]
		}
	}
	return nil
}
