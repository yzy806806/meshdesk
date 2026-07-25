package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"golang.org/x/crypto/bcrypt"
)

// newTestServer creates a web server with a populated monitor store for testing.
func newTestServer(t *testing.T) *Server {
	t.Helper()

	cfg := config.Default()
	store := monitor.NewStore()

	// Populate with test metrics
	now := time.Now().UTC()
	store.Append("node-a", &monitor.Metrics{
		Timestamp: now,
		NodeID:    "node-a",
		Hostname:  "web-server",
		CPU:       monitor.CPUMetrics{UsagePercent: 45.2, CoreCount: 4, PerCore: []float64{40, 50, 44, 47}},
		Memory: monitor.MemoryMetrics{
			Total:     8 * 1024 * 1024 * 1024,
			Used:      3 * 1024 * 1024 * 1024,
			Available: 5 * 1024 * 1024 * 1024,
		},
		LoadAvg: monitor.LoadAvgMetrics{Load1: 0.5, Load5: 0.4, Load15: 0.3},
		Uptime:  3600,
	})
	store.Append("node-b", &monitor.Metrics{
		Timestamp: now,
		NodeID:    "node-b",
		Hostname:  "db-server",
		CPU:       monitor.CPUMetrics{UsagePercent: 78.9, CoreCount: 2},
		Memory: monitor.MemoryMetrics{
			Total:     16 * 1024 * 1024 * 1024,
			Used:      12 * 1024 * 1024 * 1024,
			Available: 4 * 1024 * 1024 * 1024,
		},
		LoadAvg: monitor.LoadAvgMetrics{Load1: 2.1, Load5: 1.8, Load15: 1.5},
		Uptime:  86400,
	})

	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: store,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return srv
}

func TestNewServer(t *testing.T) {
	srv, err := New(Deps{
		Config:       config.Default(),
		MonitorStore: monitor.NewStore(),
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if srv == nil {
		t.Fatal("New() returned nil server")
	}
	if srv.tmpl == nil {
		t.Fatal("template is nil")
	}
	if srv.sessions == nil {
		t.Fatal("session store is nil")
	}
	if srv.sseHub == nil {
		t.Fatal("SSE hub is nil")
	}
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		input    uint64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
	}

	for _, tt := range tests {
		got := humanBytes(tt.input)
		if got != tt.expected {
			t.Errorf("humanBytes(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "—"},
		{60, "1m"},
		{3600, "1h 0m"},
		{86400, "1d 0h"},
		{90061, "1d 1h"},
		{7200, "2h 0m"},
	}

	for _, tt := range tests {
		got := humanDuration(tt.input)
		if got != tt.expected {
			t.Errorf("humanDuration(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestMetricBarClass(t *testing.T) {
	tests := []struct {
		input    float64
		expected string
	}{
		{0, ""},
		{50, ""},
		{74.9, ""},
		{75, "warn"},
		{89.9, "warn"},
		{90, "crit"},
		{100, "crit"},
	}

	for _, tt := range tests {
		got := metricBarClass(tt.input)
		if got != tt.expected {
			t.Errorf("metricBarClass(%.1f) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestShortIDDisplay(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"abc", "abc"},
		{"abcdef", "abcdef"},
		{"abcdefgh", "abcdefgh"},
		{"abcdefghij", "abcdefgh"},
	}

	for _, tt := range tests {
		got := shortIDDisplay(tt.input)
		if got != tt.expected {
			t.Errorf("shortIDDisplay(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSessionStore_CreateGetDelete(t *testing.T) {
	store := NewSessionStore()

	// Create
	session := store.Create("admin")
	if session == nil {
		t.Fatal("Create() returned nil")
	}
	if session.Username != "admin" {
		t.Errorf("Username = %q, want %q", session.Username, "admin")
	}
	if session.Token == "" {
		t.Error("Token is empty")
	}

	// Get
	got := store.Get(session.Token)
	if got == nil {
		t.Fatal("Get() returned nil for valid token")
	}
	if got.Username != "admin" {
		t.Errorf("Get() Username = %q, want %q", got.Username, "admin")
	}

	// Delete
	store.Delete(session.Token)
	if store.Get(session.Token) != nil {
		t.Error("Get() returned non-nil after Delete")
	}
}

func TestSessionStore_ExpiredSession(t *testing.T) {
	store := NewSessionStore()
	session := store.Create("admin")

	// Manually expire
	store.mu.Lock()
	session.ExpiresAt = time.Now().Add(-1 * time.Hour)
	store.mu.Unlock()

	if store.Get(session.Token) != nil {
		t.Error("Get() returned non-nil for expired session")
	}
}

func TestSSEHub_RegisterUnregister(t *testing.T) {
	hub := NewSSEHub()
	defer hub.Close()

	ch := hub.Register()
	if ch == nil {
		t.Fatal("Register() returned nil")
	}
	if hub.ClientCount() != 1 {
		t.Errorf("ClientCount = %d, want 1", hub.ClientCount())
	}

	hub.Unregister(ch)
	if hub.ClientCount() != 0 {
		t.Errorf("ClientCount = %d, want 0", hub.ClientCount())
	}
}

func TestSSEHub_Broadcast(t *testing.T) {
	hub := NewSSEHub()
	defer hub.Close()

	ch := hub.Register()
	defer hub.Unregister(ch)

	event := SSEEvent{Event: "metrics", Data: `{"node_count":1}`}
	hub.Broadcast(event)

	select {
	case got := <-ch:
		if got.Event != "metrics" {
			t.Errorf("Event = %q, want %q", got.Event, "metrics")
		}
		if got.Data != `{"node_count":1}` {
			t.Errorf("Data = %q, want %q", got.Data, `{"node_count":1}`)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for broadcast")
	}
}

func TestBuildNodeCards(t *testing.T) {
	srv := newTestServer(t)

	cards := srv.buildNodeCards()
	if len(cards) != 2 {
		t.Fatalf("buildNodeCards() returned %d cards, want 2", len(cards))
	}

	// Find node-a
	var nodeA *NodeCardData
	for i := range cards {
		if cards[i].NodeID == "node-a" {
			nodeA = &cards[i]
			break
		}
	}
	if nodeA == nil {
		t.Fatal("node-a not found in cards")
	}

	if nodeA.Hostname != "web-server" {
		t.Errorf("Hostname = %q, want %q", nodeA.Hostname, "web-server")
	}
	if nodeA.CPUUsage != 45.2 {
		t.Errorf("CPUUsage = %f, want 45.2", nodeA.CPUUsage)
	}
	if nodeA.MemTotal != 8*1024*1024*1024 {
		t.Errorf("MemTotal = %d, want %d", nodeA.MemTotal, 8*1024*1024*1024)
	}
	// MemUsage should be 3/8 * 100 = 37.5
	if nodeA.MemUsage < 37 || nodeA.MemUsage > 38 {
		t.Errorf("MemUsage = %.1f, want ~37.5", nodeA.MemUsage)
	}
}

func TestBuildDashboardJSON(t *testing.T) {
	srv := newTestServer(t)

	jsonStr := srv.buildDashboardJSON()
	if jsonStr == "" {
		t.Fatal("buildDashboardJSON() returned empty string")
	}

	var data struct {
		Nodes []struct {
			NodeID   string  `json:"node_id"`
			Hostname string  `json:"hostname"`
			CPUUsage float64 `json:"cpu_usage"`
		} `json:"nodes"`
		NodeCount int `json:"node_count"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if data.NodeCount != 2 {
		t.Errorf("NodeCount = %d, want 2", data.NodeCount)
	}
	if len(data.Nodes) != 2 {
		t.Fatalf("Nodes length = %d, want 2", len(data.Nodes))
	}
}

func TestHandleDashboard(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	srv.handleDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Mesh Overview") {
		t.Error("body doesn't contain 'Mesh Overview'")
	}
	if !strings.Contains(body, "web-server") {
		t.Error("body doesn't contain hostname 'web-server'")
	}
	if !strings.Contains(body, "db-server") {
		t.Error("body doesn't contain hostname 'db-server'")
	}
}

func TestHandleDashboardPartial(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/api/dashboard/partial", nil)
	rr := httptest.NewRecorder()

	srv.handleDashboardPartial(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "node-card") {
		t.Error("partial doesn't contain 'node-card' class")
	}
}

func TestHandleNodeDetail(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/nodes/node-a", nil)
	rr := httptest.NewRecorder()

	srv.handleNodeDetail(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "web-server") {
		t.Error("body doesn't contain hostname")
	}
	if !strings.Contains(body, "CPU") {
		t.Error("body doesn't contain 'CPU'")
	}
}

func TestHandleNodeDetail_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/nodes/nonexistent", nil)
	rr := httptest.NewRecorder()

	srv.handleNodeDetail(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleLogin_GET(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/login", nil)
	rr := httptest.NewRecorder()

	srv.handleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Sign In") {
		t.Error("body doesn't contain 'Sign In'")
	}
}

func TestHandleLogin_POST_Success(t *testing.T) {
	cfg := config.Default()
	hash, err := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash error: %v", err)
	}
	cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: string(hash)},
	}

	srv, err := New(Deps{Config: cfg, MonitorStore: monitor.NewStore()})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("POST", "/login", strings.NewReader("username=admin&password=testpass"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	srv.handleLogin(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Status = %d, want %d (redirect)", rr.Code, http.StatusSeeOther)
	}

	// Check that a session cookie was set
	cookies := rr.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "meshdesk_session" {
			found = true
			if c.Value == "" {
				t.Error("session cookie has empty value")
			}
		}
	}
	if !found {
		t.Error("no meshdesk_session cookie set")
	}
}

func TestHandleLogin_POST_Failure(t *testing.T) {
	cfg := config.Default()
	hash, err := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash error: %v", err)
	}
	cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: string(hash)},
	}

	srv, err := New(Deps{Config: cfg, MonitorStore: monitor.NewStore()})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("POST", "/login", strings.NewReader("username=admin&password=wrongpass"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	srv.handleLogin(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "Invalid") {
		t.Error("body doesn't contain error message")
	}
}

func TestAuthMiddleware_NoUsers(t *testing.T) {
	// When no web users configured, should allow access
	srv := newTestServer(t)

	handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d (no auth should allow)", rr.Code, http.StatusOK)
	}
}

func TestAuthMiddleware_WithUsers(t *testing.T) {
	cfg := config.Default()
	hash, err := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash error: %v", err)
	}
	cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: string(hash)},
	}

	srv, err := New(Deps{Config: cfg, MonitorStore: monitor.NewStore()})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Without session cookie → redirect to login
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Status = %d, want %d (redirect to login)", rr.Code, http.StatusSeeOther)
	}

	// With valid session → allowed
	session := srv.sessions.Create("admin")
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d (valid session)", rr.Code, http.StatusOK)
	}
}

// TestAuthenticate_RejectsPlaintext verifies that a plaintext password stored
// in config (instead of a bcrypt hash) is NOT accepted as a valid credential.
// This is the core security fix: the old plaintext fallback is gone.
func TestAuthenticate_RejectsPlaintext(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: "testpass"}, // plaintext, NOT a bcrypt hash
	}

	srv, err := New(Deps{Config: cfg, MonitorStore: monitor.NewStore()})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Even with the correct plaintext password, authentication must fail.
	if srv.authenticate("admin", "testpass") {
		t.Error("authenticate() returned true for plaintext stored password; expected false")
	}

	// A different password must also fail.
	if srv.authenticate("admin", "wrongpass") {
		t.Error("authenticate() returned true for wrong password; expected false")
	}

	// Unknown user must fail.
	if srv.authenticate("nobody", "testpass") {
		t.Error("authenticate() returned true for unknown user; expected false")
	}
}

// TestAuthenticate_AcceptsBcryptHashes verifies that all three bcrypt
// prefix variants ($2a$, $2b$, $2y$) are recognized as valid hash formats.
func TestAuthenticate_AcceptsBcryptPrefixes(t *testing.T) {
	hash2a, _ := bcrypt.GenerateFromPassword([]byte("pass1"), bcrypt.MinCost)
	// bcrypt.GenerateFromPassword always produces $2a$ hashes; we test that
	// $2a$ is accepted by the isBcryptHash check.
	cfg := config.Default()
	cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: string(hash2a)},
	}

	srv, err := New(Deps{Config: cfg, MonitorStore: monitor.NewStore()})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if !srv.authenticate("admin", "pass1") {
		t.Error("authenticate() returned false for $2a$ bcrypt hash with correct password")
	}
	if srv.authenticate("admin", "wrong") {
		t.Error("authenticate() returned true for bcrypt hash with wrong password")
	}
}

// TestIsBcryptHash covers the hash-format check directly.
func TestIsBcryptHash(t *testing.T) {
	// A bcrypt hash is exactly 60 chars: $2X$ + 2-digit cost + $ + 22-char salt + 31-char hash
	valid2a := "$2a$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
	valid2b := "$2b$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
	valid2y := "$2y$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZabcde"

	tests := []struct {
		input string
		want  bool
	}{
		{"testpass", false},        // plaintext
		{"password123", false},     // plaintext
		{"$2b$10$abc", false},      // too short
		{"$2b$notabcrypth", false}, // wrong length, bcrypt-like prefix
		{"", false},                // empty
		{valid2a, true},            // valid $2a$
		{valid2b, true},            // valid $2b$
		{valid2y, true},            // valid $2y$
		{"$1$abc$def", false},      // MD5 crypt, not bcrypt
		{"$5$abc$def", false},      // SHA-256 crypt, not bcrypt
	}

	for _, tt := range tests {
		got := isBcryptHash(tt.input)
		if got != tt.want {
			t.Errorf("isBcryptHash(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestAuthMiddleware_PublicRoutes(t *testing.T) {
	srv := newTestServer(t)

	handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// /login should be public
	req := httptest.NewRequest("GET", "/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/login Status = %d, want %d", rr.Code, http.StatusOK)
	}

	// /static/css/app.css should be public
	req = httptest.NewRequest("GET", "/static/css/app.css", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/static/ Status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandlePeersPage(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/peers", nil)
	rr := httptest.NewRecorder()

	srv.handlePeersPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Mesh Peers") {
		t.Error("body doesn't contain 'Mesh Peers'")
	}
}

func TestHandleTerminalPage(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/terminal?node=abcdef1234567890", nil)
	rr := httptest.NewRecorder()

	srv.handleTerminalPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "terminal-container") {
		t.Error("body doesn't contain terminal container")
	}
	if !strings.Contains(body, "terminal.js") {
		t.Error("body doesn't load terminal.js")
	}
}

func TestHandleTerminalPage_NoNode(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/terminal", nil)
	rr := httptest.NewRecorder()

	srv.handleTerminalPage(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleFilesPage(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/files", nil)
	rr := httptest.NewRecorder()

	srv.handleFilesPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "File Transfer") {
		t.Error("body doesn't contain 'File Transfer'")
	}
}

func TestHandleServicesPage(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/services", nil)
	rr := httptest.NewRecorder()

	srv.handleServicesPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Service Management") {
		t.Error("body doesn't contain 'Service Management'")
	}
}

func TestBuildNodeDetail(t *testing.T) {
	now := time.Now().UTC()
	m := &monitor.Metrics{
		Timestamp: now,
		NodeID:    "test-node",
		Hostname:  "test-host",
		CPU: monitor.CPUMetrics{
			UsagePercent: 55.5,
			CoreCount:    4,
			PerCore:      []float64{50, 60, 55, 57},
		},
		Memory: monitor.MemoryMetrics{
			Total:     16 * 1024 * 1024 * 1024,
			Used:      8 * 1024 * 1024 * 1024,
			Available: 8 * 1024 * 1024 * 1024,
			SwapTotal: 2 * 1024 * 1024 * 1024,
			SwapUsed:  1 * 1024 * 1024 * 1024,
		},
		LoadAvg: monitor.LoadAvgMetrics{Load1: 1.5, Load5: 1.2, Load15: 1.0},
		Uptime:  7200,
		Disk: []monitor.DiskMetrics{
			{
				Device:     "/dev/sda1",
				MountPoint: "/",
				FSType:     "ext4",
				Total:      100 * 1024 * 1024 * 1024,
				Used:       45 * 1024 * 1024 * 1024,
				Free:       55 * 1024 * 1024 * 1024,
			},
		},
		Network: []monitor.NetMetrics{
			{
				Name:    "eth0",
				RxBytes: 1024 * 1024,
				TxBytes: 2048 * 1024,
			},
		},
	}

	detail := buildNodeDetail(m)

	if detail.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want %q", detail.Hostname, "test-host")
	}
	if detail.CPUUsage != 55.5 {
		t.Errorf("CPUUsage = %f, want 55.5", detail.CPUUsage)
	}
	if detail.MemUsage < 49 || detail.MemUsage > 51 {
		t.Errorf("MemUsage = %.1f, want ~50", detail.MemUsage)
	}
	if len(detail.Disks) != 1 {
		t.Fatalf("Disks length = %d, want 1", len(detail.Disks))
	}
	if detail.Disks[0].UsagePercent < 44 || detail.Disks[0].UsagePercent > 46 {
		t.Errorf("Disk usage = %.1f, want ~45", detail.Disks[0].UsagePercent)
	}
	if len(detail.Networks) != 1 {
		t.Fatalf("Networks length = %d, want 1", len(detail.Networks))
	}
}

func TestIsHTMXRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if isHTMXRequest(req) {
		t.Error("isHTMXRequest = true for normal request")
	}

	req.Header.Set("HX-Request", "true")
	if !isHTMXRequest(req) {
		t.Error("isHTMXRequest = false for htmx request")
	}
}

func TestStaticAssetsEmbedded(t *testing.T) {
	// Verify that static assets are properly embedded by checking
	// the server can serve them.
	srv := newTestServer(t)

	// Register routes on a test mux
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	// Check that key static files are served
	files := []string{"/static/css/pico.min.css", "/static/css/app.css", "/static/js/htmx.min.js", "/static/js/xterm.js"}
	for _, f := range files {
		req := httptest.NewRequest("GET", f, nil)
		rr := httptest.NewRecorder()
		// Bypass auth middleware for static files
		h := srv.authMiddleware(mux)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("static file %s: Status = %d, want %d", f, rr.Code, http.StatusOK)
		}
	}
}
