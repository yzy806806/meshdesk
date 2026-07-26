package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// --- Self-Test Types ---

// CheckStatus represents the outcome of a single self-test check.
type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckFail CheckStatus = "fail"
	CheckWarn CheckStatus = "warn"
	CheckSkip CheckStatus = "skip"
)

// SelfTestCheck represents the result of a single diagnostic check.
type SelfTestCheck struct {
	Name    string                 `json:"name"`
	Status  CheckStatus            `json:"status"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// OverallStatus is the aggregate self-test verdict.
type OverallStatus string

const (
	OverallHealthy   OverallStatus = "healthy"
	OverallDegraded  OverallStatus = "degraded"
	OverallUnhealthy OverallStatus = "unhealthy"
)

// SelfTestResult is the structured self-test response, suitable for
// monitoring and alerting systems. It aggregates multiple diagnostic
// checks into a single response with a clear overall status.
type SelfTestResult struct {
	Overall  OverallStatus   `json:"overall_status"`
	Time     time.Time       `json:"timestamp"`
	Checks   []SelfTestCheck `json:"checks"`
	Summary  SelfTestSummary `json:"summary"`
	Duration time.Duration   `json:"duration_ms"`
}

// SelfTestSummary is the aggregate count of check outcomes.
type SelfTestSummary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Warnings int `json:"warnings"`
	Skipped  int `json:"skipped"`
}

// --- Self-Test Implementation ---

// SelfTest runs a comprehensive diagnostic of the xray-core subsystem
// and returns a structured result. It checks:
//
//  1. Binary presence — is the xray binary findable in PATH?
//  2. Config validity — can the current config be generated and validated?
//  3. Process running — is the xray subprocess alive?
//  4. gRPC health — does xray-core's gRPC API respond?
//  5. Inbound configs — are all configured inbounds structurally valid?
//  6. Circuit breaker — is the crash-restart circuit breaker tripped?
//  7. Recent log errors — are there error-level lines in recent logs?
//
// The result is safe to serialize as JSON for monitoring/alerting.
// Individual check failures do not short-circuit the overall test;
// every check runs and its result is included.
func (m *XrayConfigManager) SelfTest() *SelfTestResult {
	start := time.Now()
	result := &SelfTestResult{
		Time:   start,
		Checks: make([]SelfTestCheck, 0, 7),
	}

	// 1. Binary presence
	result.Checks = append(result.Checks, m.checkBinary())

	// 2. Config validity
	result.Checks = append(result.Checks, m.checkConfigValidity())

	// 3. Process running
	result.Checks = append(result.Checks, m.checkProcessRunning())

	// 4. gRPC health
	result.Checks = append(result.Checks, m.checkGRPCHealth())

	// 5. Inbound configs
	result.Checks = append(result.Checks, m.checkInboundConfigs())

	// 6. Circuit breaker
	result.Checks = append(result.Checks, m.checkCircuitBreaker())

	// 7. Recent log errors
	result.Checks = append(result.Checks, m.checkRecentLogs())

	// Aggregate
	result.Summary = m.summarizeChecks(result.Checks)
	result.Overall = m.computeOverallStatus(result.Summary)
	result.Duration = time.Since(start)

	return result
}

// --- Individual Checks ---

// checkBinary verifies the xray-core binary is findable.
func (m *XrayConfigManager) checkBinary() SelfTestCheck {
	check := SelfTestCheck{
		Name:    "binary_present",
		Details: make(map[string]interface{}),
	}

	binaryPath := m.binaryPath
	check.Details["binary_path"] = binaryPath

	// Try exec.LookPath (searches PATH)
	foundPath, err := exec.LookPath(binaryPath)
	if err != nil {
		// Check if it's an absolute path that exists
		if info, statErr := os.Stat(binaryPath); statErr == nil && !info.IsDir() {
			check.Status = CheckPass
			check.Message = fmt.Sprintf("binary found at %s", binaryPath)
			check.Details["resolved_path"] = binaryPath
			return check
		}

		// Try FindBinary as a last resort
		if found := FindBinary(); found != "" {
			check.Status = CheckWarn
			check.Message = fmt.Sprintf("configured binary %q not in PATH, but found at %s", binaryPath, found)
			check.Details["resolved_path"] = found
			return check
		}

		check.Status = CheckFail
		check.Message = fmt.Sprintf("xray binary not found: %s — install xray-core and ensure it is in PATH", binaryPath)
		return check
	}

	check.Status = CheckPass
	check.Message = "binary found in PATH"
	check.Details["resolved_path"] = foundPath
	return check
}

// checkConfigValidity generates the xray config and validates it.
// If the xray binary is available, it runs `xray run -test -config <path>`
// for a full validation. Otherwise, it falls back to structural validation
// (JSON marshal + round-trip).
func (m *XrayConfigManager) checkConfigValidity() SelfTestCheck {
	check := SelfTestCheck{
		Name:    "config_valid",
		Details: make(map[string]interface{}),
	}

	// Generate the config
	cfg, err := m.GenerateConfig()
	if err != nil {
		check.Status = CheckFail
		check.Message = fmt.Sprintf("config generation failed: %v", err)
		return check
	}

	// Count inbounds/outbounds
	check.Details["inbound_count"] = len(cfg.Inbounds)
	check.Details["outbound_count"] = len(cfg.Outbounds)

	// Marshal to JSON to verify it's serializable
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		check.Status = CheckFail
		check.Message = fmt.Sprintf("config JSON marshal failed: %v", err)
		return check
	}

	check.Details["config_size_bytes"] = len(data)

	// Round-trip: unmarshal back to verify structural integrity
	var roundTrip XrayConfig
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		check.Status = CheckFail
		check.Message = fmt.Sprintf("config JSON round-trip failed: %v", err)
		return check
	}

	// Try xray run -test if binary is available
	binaryPath := m.binaryPath
	if _, err := exec.LookPath(binaryPath); err == nil {
		// Write config to a temp file for validation
		tmpDir := os.TempDir()
		tmpPath := filepath.Join(tmpDir, fmt.Sprintf("meshdesk-xray-selftest-%d.json", time.Now().UnixNano()))
		if err := os.WriteFile(tmpPath, data, 0600); err != nil {
			check.Status = CheckWarn
			check.Message = fmt.Sprintf("structural validation passed, but could not write temp config for xray -test: %v", err)
			return check
		}
		defer os.Remove(tmpPath)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, binaryPath, "run", "-test", "-config", tmpPath)
		output, err := cmd.CombinedOutput()
		check.Details["xray_test_output"] = string(output)

		if err != nil {
			check.Status = CheckFail
			check.Message = fmt.Sprintf("xray config validation failed: %v", err)
			return check
		}

		check.Status = CheckPass
		check.Message = "config validated by xray run -test"
		return check
	}

	// Binary not available — structural validation only
	check.Status = CheckWarn
	check.Message = "config structurally valid (xray binary not available for -test validation)"
	return check
}

// checkProcessRunning verifies the xray subprocess is alive.
func (m *XrayConfigManager) checkProcessRunning() SelfTestCheck {
	check := SelfTestCheck{
		Name:    "process_running",
		Details: make(map[string]interface{}),
	}

	status := m.Status()
	check.Details["running"] = status.Running
	check.Details["pid"] = status.PID
	check.Details["restart_count"] = status.RestartCount

	if !status.StartedAt.IsZero() {
		uptime := time.Since(status.StartedAt)
		check.Details["uptime_seconds"] = int(uptime.Seconds())
	}

	if status.Running {
		check.Status = CheckPass
		if status.PID > 0 {
			check.Message = fmt.Sprintf("xray process running (pid=%d, uptime=%v)", status.PID, time.Since(status.StartedAt).Round(time.Second))
		} else {
			check.Message = "xray process running"
		}
	} else {
		check.Status = CheckFail
		check.Message = "xray process is not running"
	}

	return check
}

// checkGRPCHealth probes xray-core's gRPC API port.
func (m *XrayConfigManager) checkGRPCHealth() SelfTestCheck {
	check := SelfTestCheck{
		Name:    "grpc_health",
		Details: make(map[string]interface{}),
	}

	// Check if health checking is enabled
	m.mu.Lock()
	checker := m.healthChecker
	running := m.status.Running
	m.mu.Unlock()

	if checker == nil {
		check.Status = CheckSkip
		check.Message = "health checking is disabled (apiPort < 0)"
		return check
	}

	if !running {
		check.Status = CheckSkip
		check.Message = "xray not running — gRPC health check skipped"
		return check
	}

	// Perform an immediate health check
	err := m.CheckHealthNow()
	health := m.HealthStatus()

	check.Details["check_count"] = health.CheckCount
	check.Details["failure_count"] = health.FailureCount

	if !health.LastChecked.IsZero() {
		check.Details["last_checked"] = health.LastChecked.Format(time.RFC3339)
	}
	if !health.LastHealthy.IsZero() {
		check.Details["last_healthy"] = health.LastHealthy.Format(time.RFC3339)
	}

	if err != nil {
		check.Status = CheckFail
		check.Message = fmt.Sprintf("gRPC health check failed: %v", err)
		if health.LastFailure != "" {
			check.Details["last_failure"] = health.LastFailure
		}
		return check
	}

	check.Status = CheckPass
	check.Message = "gRPC API responding"
	return check
}

// checkInboundConfigs validates all configured inbounds have required fields.
func (m *XrayConfigManager) checkInboundConfigs() SelfTestCheck {
	check := SelfTestCheck{
		Name:    "inbound_configs",
		Details: make(map[string]interface{}),
	}

	inbounds := m.ListInbounds()
	check.Details["count"] = len(inbounds)

	if len(inbounds) == 0 {
		check.Status = CheckWarn
		check.Message = "no inbounds configured"
		return check
	}

	var issues []string
	validCount := 0

	for _, ic := range inbounds {
		if ic.Tag == "" {
			issues = append(issues, "inbound missing tag")
			continue
		}
		if ic.Port <= 0 || ic.Port > 65535 {
			issues = append(issues, fmt.Sprintf("inbound %q: invalid port %d", ic.Tag, ic.Port))
			continue
		}
		if ic.Protocol == "" {
			issues = append(issues, fmt.Sprintf("inbound %q: missing protocol", ic.Tag))
			continue
		}
		if ic.Security == "reality" {
			if ic.PrivateKey == "" {
				issues = append(issues, fmt.Sprintf("inbound %q: reality security requires private_key", ic.Tag))
				continue
			}
			if len(ic.ServerNames) == 0 {
				issues = append(issues, fmt.Sprintf("inbound %q: reality security requires server_names", ic.Tag))
				continue
			}
			if ic.Dest == "" {
				issues = append(issues, fmt.Sprintf("inbound %q: reality security requires dest", ic.Tag))
				continue
			}
		}
		if ic.Security == "tls" {
			if ic.CertFile == "" || ic.KeyFile == "" {
				issues = append(issues, fmt.Sprintf("inbound %q: tls security requires cert_file and key_file", ic.Tag))
				continue
			}
		}
		if len(ic.VLESSClients) == 0 {
			issues = append(issues, fmt.Sprintf("inbound %q: no VLESS clients configured", ic.Tag))
			continue
		}
		validCount++
	}

	check.Details["valid"] = validCount
	check.Details["issues"] = issues

	if len(issues) == 0 {
		check.Status = CheckPass
		check.Message = fmt.Sprintf("all %d inbounds valid", validCount)
	} else if validCount > 0 {
		check.Status = CheckWarn
		check.Message = fmt.Sprintf("%d/%d inbounds valid, %d issues", validCount, len(inbounds), len(issues))
	} else {
		check.Status = CheckFail
		check.Message = fmt.Sprintf("all %d inbounds have issues", len(inbounds))
	}

	return check
}

// checkCircuitBreaker checks the crash-restart circuit breaker state.
func (m *XrayConfigManager) checkCircuitBreaker() SelfTestCheck {
	check := SelfTestCheck{
		Name:    "circuit_breaker",
		Details: make(map[string]interface{}),
	}

	state := m.CircuitBreakerState()
	status := m.Status()

	check.Details["state"] = state.String()
	check.Details["crash_count"] = status.CrashCount

	if !status.CircuitTrippedAt.IsZero() {
		check.Details["tripped_at"] = status.CircuitTrippedAt.Format(time.RFC3339)
	}

	switch state {
	case CircuitClosed:
		check.Status = CheckPass
		if status.CrashCount > 0 {
			check.Message = fmt.Sprintf("circuit closed (%d recent crashes)", status.CrashCount)
		} else {
			check.Message = "circuit closed (no recent crashes)"
		}
	case CircuitHalfOpen:
		check.Status = CheckWarn
		check.Message = "circuit half-open — probe restart in progress"
	case CircuitOpen:
		check.Status = CheckFail
		check.Message = fmt.Sprintf("circuit open — %d crashes in %v window, restarts halted", status.CrashCount, CrashWindow)
	default:
		check.Status = CheckWarn
		check.Message = fmt.Sprintf("unknown circuit state: %s", state.String())
	}

	return check
}

// checkRecentLogs scans the last 50 log lines for error-level messages.
func (m *XrayConfigManager) checkRecentLogs() SelfTestCheck {
	check := SelfTestCheck{
		Name:    "recent_log_errors",
		Details: make(map[string]interface{}),
	}

	logs := m.TailLogs(50)
	check.Details["lines_scanned"] = len(logs)

	errorCount := 0
	var errorSamples []string

	for _, entry := range logs {
		line := entry.Line
		// xray-core logs use "[Error]" or "error" or "ERRO" prefixes
		isError := false
		for _, prefix := range []string{"[Error]", "error", "ERRO", "ERROR", "panic", "fatal"} {
			if len(line) >= len(prefix) {
				if line[:len(prefix)] == prefix || containsLower(line, prefix) {
					isError = true
					break
				}
			}
		}
		if isError {
			errorCount++
			if len(errorSamples) < 3 {
				errorSamples = append(errorSamples, line)
			}
		}
	}

	check.Details["error_count"] = errorCount
	if len(errorSamples) > 0 {
		check.Details["samples"] = errorSamples
	}

	if errorCount == 0 {
		check.Status = CheckPass
		check.Message = fmt.Sprintf("no errors in last %d log lines", len(logs))
	} else {
		check.Status = CheckWarn
		check.Message = fmt.Sprintf("%d error lines in last %d log lines", errorCount, len(logs))
	}

	return check
}

// --- Aggregation ---

func (m *XrayConfigManager) summarizeChecks(checks []SelfTestCheck) SelfTestSummary {
	var s SelfTestSummary
	s.Total = len(checks)
	for _, c := range checks {
		switch c.Status {
		case CheckPass:
			s.Passed++
		case CheckFail:
			s.Failed++
		case CheckWarn:
			s.Warnings++
		case CheckSkip:
			s.Skipped++
		}
	}
	return s
}

func (m *XrayConfigManager) computeOverallStatus(s SelfTestSummary) OverallStatus {
	if s.Failed > 0 {
		return OverallUnhealthy
	}
	if s.Warnings > 0 {
		return OverallDegraded
	}
	return OverallHealthy
}

// containsLower is a case-insensitive substring check.
func containsLower(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			a := s[i+j]
			b := substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
