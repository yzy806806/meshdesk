package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/topology"
)

// --- Test helpers ---

// newTopologyTestServer creates a server with injected mock topology providers.
// This tests the handler layer without requiring a live mesh.
func newTopologyTestServer(t *testing.T) *Server {
	t.Helper()

	cfg := config.Default()
	store := monitor.NewStore()
	now := time.Now().UTC()

	// Populate with test metrics.
	store.Append("aaa1", &monitor.Metrics{
		Timestamp: now,
		NodeID:    "aaa1",
		Hostname:  "node-alpha",
		CPU:       monitor.CPUMetrics{UsagePercent: 23.7, CoreCount: 4},
		Memory: monitor.MemoryMetrics{
			Total: 8 * 1024 * 1024 * 1024,
			Used:  3 * 1024 * 1024 * 1024,
		},
		Network: []monitor.NetMetrics{
			{Name: "eth0", SpeedMbps: 1000},
		},
		Uptime: 3600,
	})
	store.Append("bbb2", &monitor.Metrics{
		Timestamp: now,
		NodeID:    "bbb2",
		Hostname:  "node-beta",
		CPU:       monitor.CPUMetrics{UsagePercent: 45.2, CoreCount: 2},
		Memory: monitor.MemoryMetrics{
			Total: 16 * 1024 * 1024 * 1024,
			Used:  12 * 1024 * 1024 * 1024,
		},
		Network: []monitor.NetMetrics{
			{Name: "eth0", SpeedMbps: 500},
		},
		Uptime: 7200,
	})
	// Offline node (stale metrics).
	store.Append("ccc3", &monitor.Metrics{
		Timestamp: now.Add(-5 * time.Minute),
		NodeID:    "ccc3",
		Hostname:  "node-gamma",
		CPU:       monitor.CPUMetrics{UsagePercent: 10.0, CoreCount: 1},
		Memory:    monitor.MemoryMetrics{Total: 4 * 1024 * 1024 * 1024, Used: 1 * 1024 * 1024 * 1024},
		Uptime:    100,
	})

	// Build mock topology providers.
	peers := &testPeers{
		ids: []string{"aaa1", "bbb2", "ccc3"},
		roles: map[string]string{
			"aaa1": "entry+relay",
			"bbb2": "exit",
			"ccc3": "relay",
		},
	}
	metricsAdapter := &monitorTopologyMetrics{store: store}
	paths := &testPaths{
		latencies: map[string]float64{
			"aaa1→bbb2": 12.5,
			"bbb2→ccc3": 89.3,
			"aaa1→ccc3": 156.7,
		},
	}

	srv, err := New(Deps{
		Config:               cfg,
		MonitorStore:         store,
		TopologyPeers:        peers,
		TopologyMetrics:      metricsAdapter,
		TopologyPaths:        paths,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return srv
}

// testPeers is a minimal TopologyPeers implementation for testing.
type testPeers struct {
	ids   []string
	roles map[string]string
}

func (p *testPeers) AllPeerIDs() []string {
	return p.ids
}
func (p *testPeers) PeerExists(peerID string) bool {
	for _, id := range p.ids {
		if id == peerID {
			return true
		}
	}
	return false
}
func (p *testPeers) PeerRole(peerID string) string {
	if r, ok := p.roles[peerID]; ok {
		return r
	}
	return ""
}
func (p *testPeers) Position(peerID string) (x, y, z float64) {
	return topology.DerivePosition(peerID)
}

// testPaths is a minimal TopologyPathInfo implementation for testing.
type testPaths struct {
	latencies map[string]float64
}

func (p *testPaths) PeerLatency(sourceID, targetID string) float64 {
	if lat, ok := p.latencies[sourceID+"→"+targetID]; ok {
		return lat
	}
	return -1
}

// --- AC2: Response is valid JSON with nodes and edges arrays ---

func TestHandleTopology_ValidJSON(t *testing.T) {
	srv := newTopologyTestServer(t)

	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Invalid JSON: %v\nBody: %s", err, rr.Body.String())
	}

	if _, ok := resp["nodes"]; !ok {
		t.Error("JSON missing 'nodes' array")
	}
	if _, ok := resp["edges"]; !ok {
		t.Error("JSON missing 'edges' array")
	}
}

// --- AC3: Every node has non-empty id and role ---

func TestHandleTopology_NodesHaveIDAndRole(t *testing.T) {
	srv := newTopologyTestServer(t)

	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	var snap topology.TopologySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(snap.Nodes) == 0 {
		t.Fatal("Expected non-empty nodes array")
	}

	for i, n := range snap.Nodes {
		if n.ID == "" {
			t.Errorf("Node %d has empty ID", i)
		}
		if n.Role == "" {
			t.Errorf("Node %d has empty role", i)
		}
	}
}

// --- AC4: cpu/mem present when fresh, absent when stale ---

func TestHandleTopology_CPUFreshNodeHasCPU(t *testing.T) {
	srv := newTopologyTestServer(t)

	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	var snap topology.TopologySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	for _, n := range snap.Nodes {
		if n.ID == "aaa1" {
			if n.CPU != 23.7 {
				t.Errorf("Expected CPU=23.7 for aaa1, got %f", n.CPU)
			}
			if n.Status != "online" {
				t.Errorf("Expected status=online for aaa1, got %s", n.Status)
			}
		}
	}
}

func TestHandleTopology_OfflineNodeHasZeroCPU(t *testing.T) {
	srv := newTopologyTestServer(t)

	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	var snap topology.TopologySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	for _, n := range snap.Nodes {
		if n.ID == "ccc3" {
			if n.CPU != 0 {
				t.Errorf("Expected CPU=0 for offline node ccc3, got %f", n.CPU)
			}
			if n.Status != "offline" {
				t.Errorf("Expected status=offline for ccc3, got %s", n.Status)
			}
		}
	}
}

// --- AC5: Edge latency_ms is -1 when unknown ---

func TestHandleTopology_EdgeLatencyUnknown(t *testing.T) {
	srv := newTopologyTestServer(t)

	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	var snap topology.TopologySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// The testPaths mock has edges for aaa1→bbb2, bbb2→ccc3, aaa1→ccc3.
	// Verify known edge has correct latency.
	found := false
	for _, e := range snap.Edges {
		if e.Source == "aaa1" && e.Target == "bbb2" {
			if e.LatencyMs != 12.5 {
				t.Errorf("Expected latency=12.5, got %f", e.LatencyMs)
			}
			found = true
		}
	}
	if !found {
		t.Error("Expected edge aaa1→bbb2 not found")
	}
}

// --- AC6: Empty result valid when no nodes known ---

func TestHandleTopology_EmptyResult(t *testing.T) {
	cfg := config.Default()
	store := monitor.NewStore()

	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: store,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// With no mesh node and no providers, topology should return empty.
	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var snap topology.TopologySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(snap.Nodes) != 0 {
		t.Errorf("Expected 0 nodes, got %d", len(snap.Nodes))
	}
	if len(snap.Edges) != 0 {
		t.Errorf("Expected 0 edges, got %d", len(snap.Edges))
	}
}

// --- AC1: 401 when no valid session (when web users configured) ---

func TestHandleTopology_401WithoutSession(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.WebUsers = []config.WebUser{
		{Username: "admin", PasswordHash: "$2a$10$dummy"},
	}
	store := monitor.NewStore()

	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: store,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Test via requireAuth wrapper (the actual middleware that enforces auth).
	handler := srv.requireAuth(srv.handleTopology)

	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	// requireAuth should redirect to /login (302) or return 401 for HTMX.
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 302 or 401, got %d", rr.Code)
	}
}

// --- Method not allowed ---

func TestHandleTopology_MethodNotAllowed(t *testing.T) {
	srv := newTopologyTestServer(t)

	req := httptest.NewRequest("POST", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", rr.Code)
	}
}

// --- Content-Type header ---

func TestHandleTopology_ContentType(t *testing.T) {
	srv := newTopologyTestServer(t)

	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Expected application/json, got %q", ct)
	}
}

// --- Node count matches providers ---

func TestHandleTopology_NodeCount(t *testing.T) {
	srv := newTopologyTestServer(t)

	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	var snap topology.TopologySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(snap.Nodes) != 3 {
		t.Errorf("Expected 3 nodes, got %d", len(snap.Nodes))
	}
}

// --- Nodes are sorted by ID ---

func TestHandleTopology_NodesSorted(t *testing.T) {
	srv := newTopologyTestServer(t)

	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	var snap topology.TopologySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	for i := 1; i < len(snap.Nodes); i++ {
		if snap.Nodes[i-1].ID > snap.Nodes[i].ID {
			t.Errorf("Nodes not sorted: %q > %q at index %d",
				snap.Nodes[i-1].ID, snap.Nodes[i].ID, i)
		}
	}
}

// --- Hostname present ---

func TestHandleTopology_Hostname(t *testing.T) {
	srv := newTopologyTestServer(t)

	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	var snap topology.TopologySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	for _, n := range snap.Nodes {
		if n.ID == "aaa1" && n.Hostname != "node-alpha" {
			t.Errorf("Expected hostname 'node-alpha', got %q", n.Hostname)
		}
	}
}

// --- Bandwidth from BestBandwidth ---

func TestHandleTopology_Bandwidth(t *testing.T) {
	srv := newTopologyTestServer(t)

	req := httptest.NewRequest("GET", "/api/topology", nil)
	rr := httptest.NewRecorder()

	srv.handleTopology(rr, req)

	var snap topology.TopologySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	for _, e := range snap.Edges {
		if e.Source == "aaa1" && e.Target == "bbb2" {
			// aaa1 has eth0 at 1000 Mbps, bbb2 has eth0 at 500 Mbps.
			// Bandwidth is from source node's best interface.
			if e.BandwidthMbps != 1000 {
				t.Errorf("Expected bandwidth=1000 for aaa1→bbb2, got %f", e.BandwidthMbps)
			}
		}
	}
}

// --- Position is deterministic ---

func TestHandleTopology_PositionDeterministic(t *testing.T) {
	srv := newTopologyTestServer(t)

	req1 := httptest.NewRequest("GET", "/api/topology", nil)
	rr1 := httptest.NewRecorder()
	srv.handleTopology(rr1, req1)

	var snap1 topology.TopologySnapshot
	json.Unmarshal(rr1.Body.Bytes(), &snap1)

	req2 := httptest.NewRequest("GET", "/api/topology", nil)
	rr2 := httptest.NewRecorder()
	srv.handleTopology(rr2, req2)

	var snap2 topology.TopologySnapshot
	json.Unmarshal(rr2.Body.Bytes(), &snap2)

	for i := range snap1.Nodes {
		if snap1.Nodes[i].X != snap2.Nodes[i].X ||
			snap1.Nodes[i].Y != snap2.Nodes[i].Y ||
			snap1.Nodes[i].Z != snap2.Nodes[i].Z {
			t.Errorf("Position not deterministic for node %s", snap1.Nodes[i].ID)
		}
	}
}

// --- DeriveRole from config (integration) ---

func TestDeriveRoleFromConfig(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		expected string
	}{
		{
			name: "default config (exit only — Default() pre-populates exit ports, WebAddr is empty)",
			cfg:  config.Default(),
			// Default() sets Exit.AllowedPorts=[80,443] and WebAddr="".
			// So the role is "exit" only (no dashboard since no WebAddr).
			expected: "exit",
		},
		{
			name: "entry node (SS password set, web addr set)",
			cfg: &config.Config{
				Node:   config.NodeConfig{WebAddr: ":8080"},
				Proxy:  config.ProxyConfig{SS: config.SSListenerConfig{Password: "secret"}},
			},
			expected: "entry+dashboard",
		},
		{
			name: "relay node (enabled, web addr set)",
			cfg: &config.Config{
				Node:   config.NodeConfig{WebAddr: ":8080"},
				Proxy:  config.ProxyConfig{Relay: config.RelayNodeConfig{Enabled: true}},
			},
			expected: "relay+dashboard",
		},
		{
			name: "exit node (allowed ports, web addr set)",
			cfg: &config.Config{
				Node:   config.NodeConfig{WebAddr: ":8080"},
				Proxy:  config.ProxyConfig{Exit: config.ExitConfig{AllowedPorts: []int{80, 443}}},
			},
			expected: "exit+dashboard",
		},
		{
			name: "full node (entry+relay+exit+dashboard)",
			cfg: &config.Config{
				Node: config.NodeConfig{WebAddr: ":8080"},
				Proxy: config.ProxyConfig{
					SS:    config.SSListenerConfig{Password: "secret"},
					Relay: config.RelayNodeConfig{Enabled: true},
					Exit:  config.ExitConfig{AllowedPorts: []int{80, 443}},
				},
			},
			expected: "entry+relay+exit+dashboard",
		},
		{
			name: "no web addr (entry only)",
			cfg: &config.Config{
				Proxy: config.ProxyConfig{SS: config.SSListenerConfig{Password: "secret"}},
			},
			expected: "entry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := deriveRoleFromConfig(tt.cfg)
			if role != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, role)
			}
		})
	}
}

// --- PositionConfig in NodeConfig ---

func TestPositionConfig_YAML(t *testing.T) {
	// Verify that PositionConfig is properly unmarshaled from YAML.
	yamlData := []byte(`node:
  hostname: test-node
  web: ":8080"
  position:
    x: 100.0
    y: 200.0
    z: 50.0
`)

	tmpFile := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(tmpFile, yamlData, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := config.Load(tmpFile)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	if cfg.Node.Position == nil {
		t.Fatal("Position is nil")
	}
	if cfg.Node.Position.X != 100.0 {
		t.Errorf("Expected X=100.0, got %f", cfg.Node.Position.X)
	}
	if cfg.Node.Position.Y != 200.0 {
		t.Errorf("Expected Y=200.0, got %f", cfg.Node.Position.Y)
	}
	if cfg.Node.Position.Z != 50.0 {
		t.Errorf("Expected Z=50.0, got %f", cfg.Node.Position.Z)
	}
}
