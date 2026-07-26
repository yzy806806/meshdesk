package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/xray"
)

// mockXrayManagerSelfTest returns an unhealthy self-test result.
type mockXrayManagerSelfTest struct {
	mockXrayManager // embed base mock
}

func (m *mockXrayManagerSelfTest) SelfTest() *xray.SelfTestResult {
	return &xray.SelfTestResult{
		Overall: xray.OverallUnhealthy,
		Time:    time.Now(),
		Checks: []xray.SelfTestCheck{
			{Name: "binary_present", Status: xray.CheckFail, Message: "binary not found"},
			{Name: "process_running", Status: xray.CheckFail, Message: "not running"},
		},
		Summary: xray.SelfTestSummary{Total: 2, Failed: 2},
	}
}

// mockXrayManagerSelfTestHealthy returns a healthy self-test result.
type mockXrayManagerSelfTestHealthy struct {
	mockXrayManager // embed base mock
}

func (m *mockXrayManagerSelfTestHealthy) SelfTest() *xray.SelfTestResult {
	return &xray.SelfTestResult{
		Overall: xray.OverallHealthy,
		Time:    time.Now(),
		Checks: []xray.SelfTestCheck{
			{Name: "binary_present", Status: xray.CheckPass, Message: "found"},
			{Name: "process_running", Status: xray.CheckPass, Message: "running"},
			{Name: "grpc_health", Status: xray.CheckPass, Message: "responding"},
		},
		Summary: xray.SelfTestSummary{Total: 3, Passed: 3},
	}
}

// mockXrayManagerSelfTestDegraded returns a degraded self-test result.
type mockXrayManagerSelfTestDegraded struct {
	mockXrayManager // embed base mock
}

func (m *mockXrayManagerSelfTestDegraded) SelfTest() *xray.SelfTestResult {
	return &xray.SelfTestResult{
		Overall: xray.OverallDegraded,
		Time:    time.Now(),
		Checks: []xray.SelfTestCheck{
			{Name: "binary_present", Status: xray.CheckPass, Message: "found"},
			{Name: "process_running", Status: xray.CheckPass, Message: "running"},
			{Name: "recent_log_errors", Status: xray.CheckWarn, Message: "2 errors in logs"},
		},
		Summary: xray.SelfTestSummary{Total: 3, Passed: 2, Warnings: 1},
	}
}

// TestSelfTestHandlerNotConfigured verifies the endpoint returns 503
// when the xray manager is nil.
func TestSelfTestHandlerNotConfigured(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/xray/selftest", nil)
	rr := httptest.NewRecorder()
	srv.handleXraySelfTest(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

// TestSelfTestHandlerUnhealthy verifies the endpoint returns 503 and
// structured JSON when the self-test result is unhealthy.
func TestSelfTestHandlerUnhealthy(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManagerSelfTest{}

	req := httptest.NewRequest(http.MethodGet, "/api/xray/selftest", nil)
	rr := httptest.NewRecorder()
	srv.handleXraySelfTest(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for unhealthy, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !contains(body, "overall_status") {
		t.Errorf("expected 'overall_status' in response body, got: %s", body)
	}
	if !contains(body, "unhealthy") {
		t.Errorf("expected 'unhealthy' in response body, got: %s", body)
	}
	if !contains(body, "checks") {
		t.Errorf("expected 'checks' array in response body")
	}
	if !contains(body, "binary_present") {
		t.Errorf("expected 'binary_present' check name in response body")
	}
	if !contains(body, "summary") {
		t.Errorf("expected 'summary' in response body")
	}
}

// TestSelfTestHandlerHealthy verifies the endpoint returns 200 when
// the self-test result is healthy.
func TestSelfTestHandlerHealthy(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManagerSelfTestHealthy{}

	req := httptest.NewRequest(http.MethodGet, "/api/xray/selftest", nil)
	rr := httptest.NewRecorder()
	srv.handleXraySelfTest(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for healthy, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !contains(body, "healthy") {
		t.Errorf("expected 'healthy' in response body, got: %s", body)
	}
}

// TestSelfTestHandlerDegraded verifies the endpoint returns 200 for
// degraded status (warnings but no failures).
func TestSelfTestHandlerDegraded(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManagerSelfTestDegraded{}

	req := httptest.NewRequest(http.MethodGet, "/api/xray/selftest", nil)
	rr := httptest.NewRecorder()
	srv.handleXraySelfTest(rr, req)

	// Degraded returns 200 (not 503 — only unhealthy gets 503)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for degraded, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !contains(body, "degraded") {
		t.Errorf("expected 'degraded' in response body, got: %s", body)
	}
}

// TestSelfTestHandlerContentType verifies the response has the
// correct Content-Type header.
func TestSelfTestHandlerContentType(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManagerSelfTestHealthy{}

	req := httptest.NewRequest(http.MethodGet, "/api/xray/selftest", nil)
	rr := httptest.NewRecorder()
	srv.handleXraySelfTest(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
}

// TestSelfTestHandlerJSONStructure verifies the response body can be
// unmarshaled into a SelfTestResult struct.
func TestSelfTestHandlerJSONStructure(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManagerSelfTestHealthy{}

	req := httptest.NewRequest(http.MethodGet, "/api/xray/selftest", nil)
	rr := httptest.NewRecorder()
	srv.handleXraySelfTest(rr, req)

	var result xray.SelfTestResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if result.Overall != xray.OverallHealthy {
		t.Errorf("expected overall healthy, got %s", result.Overall)
	}
	if len(result.Checks) != 3 {
		t.Fatalf("expected 3 checks, got %d", len(result.Checks))
	}
	if result.Summary.Total != 3 {
		t.Errorf("expected summary total 3, got %d", result.Summary.Total)
	}
	if result.Summary.Passed != 3 {
		t.Errorf("expected summary passed 3, got %d", result.Summary.Passed)
	}
}
