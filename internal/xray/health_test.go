package xray

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// mockHTTP2Server starts a minimal TCP server that responds to the
// HTTP/2 connection preface with a SETTINGS frame, simulating a
// gRPC (HTTP/2) server. Returns the listen address and a cleanup func.
func mockHTTP2Server(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read the client's HTTP/2 preface + SETTINGS frame
				buf := make([]byte, 4096)
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, err := c.Read(buf)
				if err != nil {
					return
				}
				// Respond with our own SETTINGS frame (empty, length=0)
				// type=0x04 (SETTINGS), flags=0x00, streamID=0
				settingsFrame := []byte{
					0x00, 0x00, 0x00, // length: 0
					0x04,       // type: SETTINGS
					0x00,       // flags: none
					0x00, 0x00, 0x00, 0x00, // stream ID: 0
				}
				c.SetWriteDeadline(time.Now().Add(2 * time.Second))
				c.Write(settingsFrame)

				// Also send a SETTINGS ACK frame
				settingsAck := []byte{
					0x00, 0x00, 0x00, // length: 0
					0x04,       // type: SETTINGS
					0x01,       // flags: ACK
					0x00, 0x00, 0x00, 0x00, // stream ID: 0
				}
				c.Write(settingsAck)

				// Keep the connection open briefly
				time.Sleep(100 * time.Millisecond)
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	return addr, func() { ln.Close() }
}

// (mockTCPListener removed — mockHTTP2Server with a dead port covers the
// connection-refused case, and the timeout test covers the hang case.)

func TestHealthCheckerHealthyServer(t *testing.T) {
	addr, cleanup := mockHTTP2Server(t)
	defer cleanup()

	checker := NewHealthChecker(addr, 3*time.Second)
	ctx := context.Background()
	err := checker.CheckAndUpdate(ctx)
	if err != nil {
		t.Fatalf("expected healthy, got error: %v", err)
	}

	status := checker.Status()
	if status.State != HealthHealthy {
		t.Fatalf("expected state %s, got %s", HealthHealthy, status.State)
	}
	if status.CheckCount != 1 {
		t.Fatalf("expected check_count=1, got %d", status.CheckCount)
	}
	if status.FailureCount != 0 {
		t.Fatalf("expected failure_count=0, got %d", status.FailureCount)
	}
	if status.LastHealthy.IsZero() {
		t.Fatal("expected non-zero last_healthy")
	}
	if status.LastFailure != "" {
		t.Fatalf("expected empty last_failure, got %s", status.LastFailure)
	}
}

func TestHealthCheckerConnectionRefused(t *testing.T) {
	// Use a port that's almost certainly not listening
	checker := NewHealthChecker("127.0.0.1:1", 1*time.Second)
	ctx := context.Background()
	err := checker.CheckAndUpdate(ctx)
	if err == nil {
		t.Fatal("expected error for connection refused, got nil")
	}

	status := checker.Status()
	if status.State != HealthUnhealthy {
		t.Fatalf("expected state %s, got %s", HealthUnhealthy, status.State)
	}
	if status.CheckCount != 1 {
		t.Fatalf("expected check_count=1, got %d", status.CheckCount)
	}
	if status.FailureCount != 1 {
		t.Fatalf("expected failure_count=1, got %d", status.FailureCount)
	}
	if status.LastFailure == "" {
		t.Fatal("expected non-empty last_failure")
	}
	if !status.LastChecked.IsZero() == false {
		// LastChecked should be set
	}
}

func TestHealthCheckerIsHealthy(t *testing.T) {
	addr, cleanup := mockHTTP2Server(t)
	defer cleanup()

	checker := NewHealthChecker(addr, 3*time.Second)
	if checker.IsHealthy() {
		t.Fatal("expected not healthy before any check")
	}

	ctx := context.Background()
	_ = checker.CheckAndUpdate(ctx)
	if !checker.IsHealthy() {
		t.Fatal("expected healthy after successful check")
	}
}

func TestHealthCheckerStateTransitions(t *testing.T) {
	addr, cleanup := mockHTTP2Server(t)
	defer cleanup()

	checker := NewHealthChecker(addr, 3*time.Second)
	ctx := context.Background()

	// Initial state: unknown
	if checker.Status().State != HealthUnknown {
		t.Fatalf("expected initial state unknown, got %s", checker.Status().State)
	}

	// First check: healthy
	_ = checker.CheckAndUpdate(ctx)
	if checker.Status().State != HealthHealthy {
		t.Fatalf("expected healthy, got %s", checker.Status().State)
	}

	// Now check a bad address
	checker2 := NewHealthChecker("127.0.0.1:1", 1*time.Second)
	_ = checker2.CheckAndUpdate(ctx)
	if checker2.Status().State != HealthUnhealthy {
		t.Fatalf("expected unhealthy, got %s", checker2.Status().State)
	}
}

func TestHealthCheckerTimeout(t *testing.T) {
	// Create a listener that accepts but never responds (simulates hang)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Just hold the connection open without responding
			go func(c net.Conn) {
				time.Sleep(10 * time.Second)
				c.Close()
			}(conn)
		}
	}()

	checker := NewHealthChecker(ln.Addr().String(), 500*time.Millisecond)
	ctx := context.Background()
	err = checker.CheckAndUpdate(ctx)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if checker.Status().State != HealthUnhealthy {
		t.Fatalf("expected unhealthy, got %s", checker.Status().State)
	}
}

func TestHealthStateString(t *testing.T) {
	tests := []struct {
		state    HealthState
		expected string
	}{
		{HealthUnknown, "unknown"},
		{HealthHealthy, "healthy"},
		{HealthUnhealthy, "unhealthy"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("HealthState(%d).String() = %s, want %s", tt.state, got, tt.expected)
		}
	}
}

func TestHealthStateMarshalJSON(t *testing.T) {
	states := []HealthState{HealthUnknown, HealthHealthy, HealthUnhealthy}
	expected := []string{`"unknown"`, `"healthy"`, `"unhealthy"`}
	for i, s := range states {
		data, err := s.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON error: %v", err)
		}
		if string(data) != expected[i] {
			t.Errorf("HealthState(%d).MarshalJSON() = %s, want %s", s, string(data), expected[i])
		}
	}
}

func TestFormatAPIAddr(t *testing.T) {
	tests := []struct {
		listen   string
		port     int
		expected string
	}{
		{"127.0.0.1", 8421, "127.0.0.1:8421"},
		{"0.0.0.0", 9000, "0.0.0.0:9000"},
		{"localhost", 80, "localhost:80"},
	}
	for _, tt := range tests {
		got := formatAPIAddr(tt.listen, tt.port)
		if got != tt.expected {
			t.Errorf("formatAPIAddr(%q, %d) = %s, want %s", tt.listen, tt.port, got, tt.expected)
		}
	}
}

func TestDefaultAPIAddr(t *testing.T) {
	// Default listen and port
	got := defaultAPIAddr("", 0)
	expected := "127.0.0.1:8421"
	if got != expected {
		t.Errorf("defaultAPIAddr(\"\", 0) = %s, want %s", got, expected)
	}

	// Custom listen
	got = defaultAPIAddr("0.0.0.0", 0)
	expected = "0.0.0.0:8421"
	if got != expected {
		t.Errorf("defaultAPIAddr(\"0.0.0.0\", 0) = %s, want %s", got, expected)
	}

	// Custom port
	got = defaultAPIAddr("", 9999)
	expected = "127.0.0.1:9999"
	if got != expected {
		t.Errorf("defaultAPIAddr(\"\", 9999) = %s, want %s", got, expected)
	}
}

func TestReadFull(t *testing.T) {
	// Create a TCP connection (not net.Pipe, which is synchronous)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(50 * time.Millisecond)
		conn.Write([]byte("hello world"))
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 5)
	n, err := readFull(client, buf)
	if err != nil {
		t.Fatalf("readFull error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes, got %d", n)
	}
	if string(buf) != "hello" {
		t.Fatalf("expected 'hello', got %s", string(buf))
	}
}

func TestReadFrameHeader(t *testing.T) {
	// Create a TCP connection for reliable read/write behavior
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(50 * time.Millisecond)
		// SETTINGS frame: length=0, type=0x04, flags=0x00, streamID=0
		conn.Write([]byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00})
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	length, frameType, flags, streamID, err := readFrameHeader(client)
	if err != nil {
		t.Fatalf("readFrameHeader error: %v", err)
	}
	if length != 0 {
		t.Fatalf("expected length=0, got %d", length)
	}
	if frameType != 0x04 {
		t.Fatalf("expected type=0x04 (SETTINGS), got 0x%02x", frameType)
	}
	if flags != 0x00 {
		t.Fatalf("expected flags=0x00, got 0x%02x", flags)
	}
	if streamID != 0 {
		t.Fatalf("expected streamID=0, got %d", streamID)
	}
}

func TestLogHealthChange(t *testing.T) {
	// Just verify it doesn't panic
	logHealthChange(HealthUnknown, HealthHealthy)
	logHealthChange(HealthHealthy, HealthHealthy)
	logHealthChange(HealthHealthy, HealthUnhealthy)
}

// --- Manager-level health tests ---

func TestManagerIsReadyFalseWhenNotRunning(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})
	if m.IsReady() {
		t.Fatal("expected IsReady=false when not running")
	}
}

func TestManagerHealthStatusInitial(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1,
	})
	hs := m.HealthStatus()
	if hs.State != HealthUnknown {
		t.Fatalf("expected initial state unknown, got %s", hs.State)
	}
}

func TestManagerCheckHealthNowDisabled(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1, // disabled
	})
	err := m.CheckHealthNow()
	if err == nil {
		t.Fatal("expected error when health checking is disabled")
	}
}

func TestManagerCheckHealthNowNotRunning(t *testing.T) {
	addr, cleanup := mockHTTP2Server(t)
	defer cleanup()

	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   8421,
		ApiListen: "127.0.0.1",
	})
	// Override the health checker to point to our mock server
	m.healthChecker = NewHealthChecker(addr, 3*time.Second)

	err := m.CheckHealthNow()
	if err == nil {
		t.Fatal("expected error when xray is not running")
	}
}

func TestManagerCheckHealthNowSuccess(t *testing.T) {
	addr, cleanup := mockHTTP2Server(t)
	defer cleanup()

	m, _ := NewManager(ManagerOptions{
		ConfigDir:  t.TempDir(),
		ApiPort:    8421,
		ApiListen:  "127.0.0.1",
	})
	// Override the health checker to point to our mock server
	m.healthChecker = NewHealthChecker(addr, 3*time.Second)

	// Simulate "running" state
	m.mu.Lock()
	m.status.Running = true
	m.mu.Unlock()

	err := m.CheckHealthNow()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	hs := m.HealthStatus()
	if hs.State != HealthHealthy {
		t.Fatalf("expected state healthy, got %s", hs.State)
	}
	if !m.IsReady() {
		t.Fatal("expected IsReady=true after successful health check")
	}
}

func TestGenerateConfigIncludesAPIInbound(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   8421,
		ApiListen: "127.0.0.1",
	})

	// Add a valid inbound so config generation doesn't fail on VLESS validation
	priv, _, _ := GenerateX25519Key()
	m.AddInbound(&InboundConfig{
		Tag:         "proxy",
		Port:        443,
		Security:    "reality",
		Dest:        "www.cloudflare.com:443",
		ServerNames: []string{"www.cloudflare.com"},
		PrivateKey:  priv,
		VLESSClients: []VLESSClient{{ID: GenerateVLESSUUID()}},
	})

	cfg, err := m.GenerateConfig()
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	// Verify API config is present
	if cfg.Api == nil {
		t.Fatal("expected top-level API config, got nil")
	}
	if cfg.Api.Tag != "api" {
		t.Fatalf("expected API tag 'api', got '%s'", cfg.Api.Tag)
	}
	if len(cfg.Api.Services) == 0 {
		t.Fatal("expected non-empty API services")
	}

	// Verify the API inbound (dokodemo-door) is present
	var apiInbound *Inbound
	for i := range cfg.Inbounds {
		if cfg.Inbounds[i].Tag == "api" {
			apiInbound = &cfg.Inbounds[i]
			break
		}
	}
	if apiInbound == nil {
		t.Fatal("expected 'api' tagged inbound in config")
	}
	if apiInbound.Protocol != "dokodemo-door" {
		t.Fatalf("expected protocol 'dokodemo-door', got '%s'", apiInbound.Protocol)
	}
	if apiInbound.Port != 8421 {
		t.Fatalf("expected port 8421, got %d", apiInbound.Port)
	}
	if apiInbound.Listen != "127.0.0.1" {
		t.Fatalf("expected listen '127.0.0.1', got '%s'", apiInbound.Listen)
	}

	// Verify routing rule exists
	if cfg.Routing == nil {
		t.Fatal("expected routing config, got nil")
	}
	var hasAPIRule bool
	for _, rule := range cfg.Routing.Rules {
		if rule.OutboundTag == "api" {
			hasAPIRule = true
			// Verify InboundTag contains "api"
			found := false
			for _, tag := range rule.InboundTag {
				if tag == "api" {
					found = true
					break
				}
			}
			if !found {
				t.Fatal("expected routing rule with inboundTag 'api'")
			}
			break
		}
	}
	if !hasAPIRule {
		t.Fatal("expected routing rule for API")
	}
}

func TestGenerateConfigNoAPIWhenDisabled(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir: t.TempDir(),
		ApiPort:   -1, // disabled
	})

	cfg, err := m.GenerateConfig()
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	if cfg.Api != nil {
		t.Fatal("expected no API config when disabled")
	}

	// Verify no 'api' tagged inbound
	for _, ib := range cfg.Inbounds {
		if ib.Tag == "api" {
			t.Fatal("expected no 'api' tagged inbound when disabled")
		}
	}

	// Verify no routing rules for 'api'
	if cfg.Routing != nil {
		for _, rule := range cfg.Routing.Rules {
			if rule.OutboundTag == "api" {
				t.Fatal("expected no routing rule for 'api' when disabled")
			}
		}
	}
}

func TestManagerStopResetsHealth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	mockPath := mockBinaryPath(t)
	dir := t.TempDir()

	m, _ := NewManager(ManagerOptions{
		BinaryPath: mockPath,
		ConfigDir:  dir,
		ConfigPath: filepath.Join(dir, "config.json"),
		ApiPort:    -1,
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

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Manually set health state to healthy
	m.mu.Lock()
	m.healthStatus = HealthStatus{State: HealthHealthy}
	m.mu.Unlock()

	if !m.IsReady() {
		t.Fatal("expected IsReady=true after setting health to healthy")
	}

	// Stop should reset health
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	hs := m.HealthStatus()
	if hs.State != HealthUnknown {
		t.Fatalf("expected health state reset to unknown after stop, got %s", hs.State)
	}
	if m.IsReady() {
		t.Fatal("expected IsReady=false after stop")
	}
}

func TestWaitForHealthySuccess(t *testing.T) {
	addr, cleanup := mockHTTP2Server(t)
	defer cleanup()

	m, _ := NewManager(ManagerOptions{
		ConfigDir:  t.TempDir(),
		ApiPort:    8421,
		ApiListen:  "127.0.0.1",
	})
	m.healthChecker = NewHealthChecker(addr, 3*time.Second)

	// Simulate running state
	m.mu.Lock()
	m.status.Running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	// Should succeed quickly since the mock server is ready
	err := m.waitForHealthy(5 * time.Second)
	if err != nil {
		t.Fatalf("waitForHealthy failed: %v", err)
	}

	if !m.IsReady() {
		t.Fatal("expected IsReady=true after waitForHealthy success")
	}
}

func TestWaitForHealthyTimeout(t *testing.T) {
	// Point to a non-listening port
	m, _ := NewManager(ManagerOptions{
		ConfigDir:  t.TempDir(),
		ApiPort:    8421,
		ApiListen:  "127.0.0.1",
	})
	m.healthChecker = NewHealthChecker("127.0.0.1:1", 500*time.Millisecond)

	// Simulate running state
	m.mu.Lock()
	m.status.Running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	// Use a short timeout
	err := m.waitForHealthy(2 * time.Second)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestWaitForHealthyProcessExits(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		ConfigDir:  t.TempDir(),
		ApiPort:    8421,
		ApiListen:  "127.0.0.1",
	})
	m.healthChecker = NewHealthChecker("127.0.0.1:1", 500*time.Millisecond)

	// Simulate NOT running state
	m.mu.Lock()
	m.status.Running = false
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	err := m.waitForHealthy(5 * time.Second)
	if err == nil {
		t.Fatal("expected error when process exits during wait")
	}
}

func TestStartHealthMonitorAndCheck(t *testing.T) {
	addr, cleanup := mockHTTP2Server(t)
	defer cleanup()

	m, _ := NewManager(ManagerOptions{
		ConfigDir:         t.TempDir(),
		ApiPort:           8421,
		ApiListen:         "127.0.0.1",
		HealthCheckInterval: 100 * time.Millisecond, // fast for testing
	})
	m.healthChecker = NewHealthChecker(addr, 3*time.Second)

	// Simulate running state
	m.mu.Lock()
	m.status.Running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	// Start the background monitor
	m.startHealthMonitor()

	// Wait a bit for the first tick
	time.Sleep(300 * time.Millisecond)

	// Check that health status was updated
	hs := m.HealthStatus()
	if hs.CheckCount == 0 {
		t.Fatal("expected check_count > 0 after background monitor ran")
	}
	if hs.State != HealthHealthy {
		t.Fatalf("expected state healthy, got %s", hs.State)
	}

	// Stop the monitor
	m.stopHealthMonitor()
}

func TestStopHealthMonitor(t *testing.T) {
	addr, cleanup := mockHTTP2Server(t)
	defer cleanup()

	m, _ := NewManager(ManagerOptions{
		ConfigDir:         t.TempDir(),
		ApiPort:           8421,
		ApiListen:         "127.0.0.1",
		HealthCheckInterval: 50 * time.Millisecond,
	})
	m.healthChecker = NewHealthChecker(addr, 3*time.Second)

	m.mu.Lock()
	m.status.Running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	// Start and then stop
	m.startHealthMonitor()
	m.stopHealthMonitor()

	// Should not panic or hang
	// Verify cancel was called
	m.mu.Lock()
	cancel := m.healthCancel
	m.mu.Unlock()
	if cancel != nil {
		t.Fatal("expected healthCancel to be nil after stopHealthMonitor")
	}
}
