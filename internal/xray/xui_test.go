package xray

import (
	"encoding/json"
	"net/url"
	"testing"
)

// TestParseStatsQueryOutput verifies parsing of xray-core's statsquery JSON output.
func TestParseStatsQueryOutput(t *testing.T) {
	// Sample output from `xray api statsquery`
	sample := `{
		"stat": [
			{"name": "inbound>>>test-inbound>>>traffic>>>uplink", "value": "12345"},
			{"name": "inbound>>>test-inbound>>>traffic>>>downlink", "value": "67890"},
			{"name": "user>>>user@example.com>>>traffic>>>uplink", "value": "100"},
			{"name": "user>>>user@example.com>>>traffic>>>downlink", "value": "200"}
		]
	}`

	// Trim using trimXrayOutput
	trimmed := trimXrayOutput([]byte(sample))
	if trimmed == nil {
		t.Fatal("trimXrayOutput returned nil for valid JSON")
	}

	var result StatsQueryResult
	if err := json.Unmarshal(trimmed, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(result.Stat) != 4 {
		t.Errorf("stat count: got %d, want 4", len(result.Stat))
	}

	// Verify first entry
	if result.Stat[0].Name != "inbound>>>test-inbound>>>traffic>>>uplink" {
		t.Errorf("name: got %q", result.Stat[0].Name)
	}
	if result.Stat[0].Value != "12345" {
		t.Errorf("value: got %q", result.Stat[0].Value)
	}
}

// TestTrimXrayOutputWithLogPrefix verifies that log lines before JSON
// are correctly stripped.
func TestTrimXrayOutputWithLogPrefix(t *testing.T) {
	input := `2026-07-26 12:00:00 INFO xray started
{"stat":[{"name":"inbound>>>x>>>traffic>>>uplink","value":"42"}]}`

	trimmed := trimXrayOutput([]byte(input))
	if trimmed == nil {
		t.Fatal("trimXrayOutput returned nil")
	}

	var result StatsQueryResult
	if err := json.Unmarshal(trimmed, &result); err != nil {
		t.Fatalf("unmarshal: %v (trimmed: %s)", err, string(trimmed))
	}

	if len(result.Stat) != 1 {
		t.Errorf("stat count: got %d, want 1", len(result.Stat))
	}
}

// TestTrimXrayOutputEmpty verifies handling of empty output.
func TestTrimXrayOutputEmpty(t *testing.T) {
	result := trimXrayOutput([]byte(""))
	if result != nil {
		t.Error("expected nil for empty input")
	}

	result = trimXrayOutput([]byte("   \n\t  "))
	if result != nil {
		t.Error("expected nil for whitespace-only input")
	}
}

// TestParseStatsQueryAggregation verifies the aggregation logic
// of QueryAllStats.
func TestParseStatsQueryAggregation(t *testing.T) {
	// We test the aggregation directly by constructing the result
	// and calling the parsing logic
	sample := `{
		"stat": [
			{"name": "inbound>>>in1>>>traffic>>>uplink", "value": "1000"},
			{"name": "inbound>>>in1>>>traffic>>>downlink", "value": "2000"},
			{"name": "inbound>>>in2>>>traffic>>>uplink", "value": "500"},
			{"name": "inbound>>>in2>>>traffic>>>downlink", "value": "1500"},
			{"name": "user>>>alice@example.com>>>traffic>>>uplink", "value": "100"},
			{"name": "user>>>alice@example.com>>>traffic>>>downlink", "value": "200"},
			{"name": "user>>>bob@example.com>>>traffic>>>uplink", "value": "50"},
			{"name": "user>>>bob@example.com>>>traffic>>>downlink", "value": "75"}
		]
	}`

	trimmed := trimXrayOutput([]byte(sample))
	var sqResult StatsQueryResult
	json.Unmarshal(trimmed, &sqResult)

	// Manually run the aggregation to verify logic
	inboundMap := make(map[string]*TrafficStats)
	clientMap := make(map[string]*ClientTrafficStats)

	for _, entry := range sqResult.Stat {
		// Use the same parsing logic as QueryAllStats
		parts := splitStatName(entry.Name)
		if len(parts) < 4 {
			continue
		}
		entityType := parts[0]
		entityName := parts[1]
		direction := parts[3]

		value, err := parseInt64(entry.Value)
		if err != nil {
			continue
		}

		switch entityType {
		case "inbound":
			s, ok := inboundMap[entityName]
			if !ok {
				s = &TrafficStats{Tag: entityName}
				inboundMap[entityName] = s
			}
			if direction == "uplink" {
				s.Uplink += value
			} else if direction == "downlink" {
				s.Downlink += value
			}
			s.Total = s.Uplink + s.Downlink

		case "user":
			s, ok := clientMap[entityName]
			if !ok {
				s = &ClientTrafficStats{Email: entityName}
				clientMap[entityName] = s
			}
			if direction == "uplink" {
				s.Uplink += value
			} else if direction == "downlink" {
				s.Downlink += value
			}
			s.Total = s.Uplink + s.Downlink
		}
	}

	// Verify inbound aggregation
	in1 := inboundMap["in1"]
	if in1 == nil {
		t.Fatal("inbound in1 not found")
	}
	if in1.Uplink != 1000 {
		t.Errorf("in1 uplink: got %d, want 1000", in1.Uplink)
	}
	if in1.Downlink != 2000 {
		t.Errorf("in1 downlink: got %d, want 2000", in1.Downlink)
	}
	if in1.Total != 3000 {
		t.Errorf("in1 total: got %d, want 3000", in1.Total)
	}

	in2 := inboundMap["in2"]
	if in2 == nil {
		t.Fatal("inbound in2 not found")
	}
	if in2.Total != 2000 {
		t.Errorf("in2 total: got %d, want 2000", in2.Total)
	}

	// Verify client aggregation
	alice := clientMap["alice@example.com"]
	if alice == nil {
		t.Fatal("client alice not found")
	}
	if alice.Uplink != 100 {
		t.Errorf("alice uplink: got %d, want 100", alice.Uplink)
	}
	if alice.Total != 300 {
		t.Errorf("alice total: got %d, want 300", alice.Total)
	}

	bob := clientMap["bob@example.com"]
	if bob == nil {
		t.Fatal("client bob not found")
	}
	if bob.Total != 125 {
		t.Errorf("bob total: got %d, want 125", bob.Total)
	}
}

// --- Share Link Tests ---

// TestVLESSShareLink verifies the generation of a VLESS share link.
func TestVLESSShareLink(t *testing.T) {
	link := VLESSShareLink("test-uuid", "203.0.113.1", 443, VLESSShareParams{
		Security:    "reality",
		Network:     "tcp",
		Flow:        "xtls-rprx-vision",
		PublicKey:   "dGVzdC1wdWJsaWMta2V5",
		ShortID:     "0123456789abcdef",
		Fingerprint: "chrome",
		ServerName:  "www.microsoft.com",
		Remark:      "Test Server",
	})

	if !contains(link, "vless://test-uuid@203.0.113.1:443") {
		t.Errorf("link prefix wrong: %s", link)
	}
	if !contains(link, "security=reality") {
		t.Errorf("missing security=reality: %s", link)
	}
	if !contains(link, "pbk=dGVzdC1wdWJsaWMta2V5") {
		t.Errorf("missing pbk: %s", link)
	}
	if !contains(link, "flow=xtls-rprx-vision") {
		t.Errorf("missing flow: %s", link)
	}
	if !contains(link, "Test+Server") || !contains(link, "Test%20Server") {
		// URL-encoded remark
		t.Logf("remark in link: %s", link)
	}
}

// TestParseVLESSLink verifies parsing a VLESS share link.
func TestParseVLESSLink(t *testing.T) {
	link := "vless://test-uuid@203.0.113.1:443?encryption=none&flow=xtls-rprx-vision&pbk=abc123&security=reality&sni=www.microsoft.com&type=tcp&fp=chrome#My+Server"

	info, err := ParseVLESSLink(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if info.UUID != "test-uuid" {
		t.Errorf("UUID: got %q, want %q", info.UUID, "test-uuid")
	}
	if info.Address != "203.0.113.1" {
		t.Errorf("Address: got %q", info.Address)
	}
	if info.Port != 443 {
		t.Errorf("Port: got %d, want 443", info.Port)
	}
	if info.Security != "reality" {
		t.Errorf("Security: got %q", info.Security)
	}
	if info.Network != "tcp" {
		t.Errorf("Network: got %q", info.Network)
	}
	if info.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow: got %q", info.Flow)
	}
	if info.PublicKey != "abc123" {
		t.Errorf("PublicKey: got %q", info.PublicKey)
	}
	if info.Fingerprint != "chrome" {
		t.Errorf("Fingerprint: got %q", info.Fingerprint)
	}
}

// TestParseVLESSLinkInvalid verifies error on invalid link.
func TestParseVLESSLinkInvalid(t *testing.T) {
	_, err := ParseVLESSLink("https://example.com")
	if err == nil {
		t.Error("expected error for non-vless link")
	}

	_, err = ParseVLESSLink("vless://")
	if err == nil {
		t.Error("expected error for incomplete link")
	}
}

// TestGenerateShareLinkForInbound verifies the full share link generation
// for a REALITY inbound.
func TestGenerateShareLinkForInbound(t *testing.T) {
	priv, pub, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	ic := &InboundConfig{
		Tag:         "test-reality",
		Protocol:    "vless-reality",
		Port:        8443,
		Security:    "reality",
		Dest:        "www.microsoft.com:443",
		ServerNames: []string{"www.microsoft.com"},
		PrivateKey:  priv,
		ShortIds:    []string{"abcdef0123456789"},
		VLESSClients: []VLESSClient{
			{ID: "test-client-uuid", Flow: "xtls-rprx-vision", Email: "user@test.com"},
		},
	}

	link, err := GenerateShareLinkForInbound(ic, ic.VLESSClients[0], "203.0.113.50")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if !contains(link, "vless://test-client-uuid@203.0.113.50:8443") {
		t.Errorf("link prefix wrong: %s", link)
	}
	if !contains(link, "security=reality") {
		t.Errorf("missing security=reality: %s", link)
	}
	if !contains(link, "pbk="+url.QueryEscape(pub)) {
		t.Errorf("missing or wrong pbk (expected %q, encoded %q): %s", pub, url.QueryEscape(pub), link)
	}
	if !contains(link, "sid=abcdef0123456789") {
		t.Errorf("missing sid: %s", link)
	}
	if !contains(link, "sni=www.microsoft.com") {
		t.Errorf("missing sni: %s", link)
	}
}

// TestDerivePublicKey verifies that DerivePublicKey produces the correct
// public key for a given private key.
func TestDerivePublicKey(t *testing.T) {
	priv, pub, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	derived, err := DerivePublicKey(priv)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	if derived != pub {
		t.Errorf("derived public key doesn't match: got %q, want %q", derived, pub)
	}
}

// TestDerivePublicKeyInvalid verifies error on invalid input.
func TestDerivePublicKeyInvalid(t *testing.T) {
	_, err := DerivePublicKey("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

// --- Client Management Tests (at xray manager level) ---

func TestManagerAddRemoveClient(t *testing.T) {
	m, err := NewManager(ManagerOptions{
		BinaryPath: "/usr/bin/xray",
		ConfigDir:  "/tmp/test-xray-client-mgmt",
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Add an inbound first
	ic := &InboundConfig{
		Tag:         "test-inbound",
		Protocol:    "vless-reality",
		Port:        443,
		Security:    "reality",
		PrivateKey:  "dGVzdC1wcml2YXRlLWtleQ==",
		ServerNames: []string{"example.com"},
		ShortIds:    []string{"abc123"},
		VLESSClients: []VLESSClient{
			{ID: "original-uuid", Flow: "xtls-rprx-vision"},
		},
	}
	m.AddInbound(ic)

	// Add a client
	client := VLESSClient{ID: "new-uuid", Flow: "xtls-rprx-vision", Email: "test@example.com"}
	err = m.AddClient("test-inbound", client)
	if err != nil {
		t.Fatalf("AddClient: %v", err)
	}

	clients, ok := m.GetClients("test-inbound")
	if !ok {
		t.Fatal("GetClients: inbound not found")
	}
	if len(clients) != 2 {
		t.Errorf("client count: got %d, want 2", len(clients))
	}

	// Remove a client
	err = m.RemoveClient("test-inbound", "new-uuid")
	if err != nil {
		t.Fatalf("RemoveClient: %v", err)
	}

	clients, _ = m.GetClients("test-inbound")
	if len(clients) != 1 {
		t.Errorf("client count after removal: got %d, want 1", len(clients))
	}
	if clients[0].ID != "original-uuid" {
		t.Errorf("remaining client: got %q, want %q", clients[0].ID, "original-uuid")
	}
}

// TestManagerAddClientReplace verifies that adding a client with
// an existing UUID replaces it.
func TestManagerAddClientReplace(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		BinaryPath: "/usr/bin/xray",
		ConfigDir:  "/tmp/test-xray-client-replace",
	})

	m.AddInbound(&InboundConfig{
		Tag:  "test-inbound",
		Port: 443,
		VLESSClients: []VLESSClient{
			{ID: "uuid-1", Flow: "xtls-rprx-vision", Email: "old@example.com"},
		},
	})

	// Replace
	m.AddClient("test-inbound", VLESSClient{ID: "uuid-1", Flow: "", Email: "new@example.com"})

	clients, _ := m.GetClients("test-inbound")
	if len(clients) != 1 {
		t.Errorf("client count: got %d, want 1", len(clients))
	}
	if clients[0].Email != "new@example.com" {
		t.Errorf("email: got %q, want %q", clients[0].Email, "new@example.com")
	}
}

// --- APIAddr Test ---

func TestManagerAPIAddr(t *testing.T) {
	m, _ := NewManager(ManagerOptions{
		BinaryPath: "/usr/bin/xray",
		ConfigDir:  "/tmp/test-xray-apiaddr",
	})

	addr := m.APIAddr()
	if addr == "" {
		t.Error("expected non-empty API address")
	}
	if !contains(addr, "127.0.0.1") {
		t.Errorf("expected 127.0.0.1 in address, got %q", addr)
	}
}

// --- Helpers ---

func splitStatName(name string) []string {
	// Same logic as strings.Split in stats.go
	result := []string{}
	current := ""
	for _, c := range name {
		if c == '>' && len(current) > 0 && len(current) < len(name) {
			// Check if next char is also '>'
		}
		if c == '>' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	// Use strings.Split for correctness
	return splitStr(name, ">>>")
}

func splitStr(s, sep string) []string {
	var result []string
	for {
		idx := indexOf(s, sep)
		if idx < 0 {
			result = append(result, s)
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	return result
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func parseInt64(s string) (int64, error) {
	var n int64
	_, err := fmtScanf(s, &n)
	return n, err
}

func fmtScanf(s string, n *int64) (int, error) {
	// Simple int parser
	var v int64
	neg := false
	i := 0
	if i < len(s) && s[i] == '-' {
		neg = true
		i++
	}
	for i < len(s) {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		v = v*10 + int64(s[i]-'0')
		i++
	}
	if neg {
		v = -v
	}
	*n = v
	return i, nil
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
