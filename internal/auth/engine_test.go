package auth

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
)

// --- Capability constant tests ---

func TestIsValidCapability(t *testing.T) {
	tests := []struct {
		cap   string
		valid bool
	}{
		{CapSSHProxy, true},
		{CapFileTransfer, true},
		{CapMonitorRead, true},
		{CapMonitorWrite, true},
		{CapServiceManage, true},
		{CapBinaryUpgrade, true},
		{"invalid_capability", false},
		{"", false},
		{"ssh", false},
	}
	for _, tt := range tests {
		t.Run(tt.cap, func(t *testing.T) {
			if got := IsValidCapability(tt.cap); got != tt.valid {
				t.Errorf("IsValidCapability(%q) = %v, want %v", tt.cap, got, tt.valid)
			}
		})
	}
}

func TestAllCapabilities(t *testing.T) {
	if len(AllCapabilities) != 6 {
		t.Errorf("expected 6 capabilities, got %d", len(AllCapabilities))
	}
}

// --- CapabilityEngine tests ---

func newTestEngine(t *testing.T) (*CapabilityEngine, *bytes.Buffer) {
	t.Helper()
	var auditBuf bytes.Buffer
	audit := NewAuditLogger(&auditBuf)
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:    "peer-a-key-1234567890abcdef",
				Capabilities: []string{CapSSHProxy, CapFileTransfer},
			},
			{
				PublicKey:    "peer-b-key-abcdefghij123456",
				Capabilities: []string{CapMonitorRead},
			},
			{
				PublicKey:     "peer-c-key-0987654321fedcba",
				Capabilities:  []string{CapServiceManage},
				ServiceManage: []string{"nginx", "meshdesk"},
			},
			{
				PublicKey:    "peer-d-key-no-caps",
				Capabilities: []string{},
			},
		},
	}
	engine := NewCapabilityEngine(cfg, audit)
	return engine, &auditBuf
}

func TestAuthorizeAllow(t *testing.T) {
	engine, _ := newTestEngine(t)

	result := engine.Authorize("peer-a-key-1234567890abcdef", CapSSHProxy, "")
	if !result.Allowed {
		t.Errorf("expected SSH proxy to be allowed for peer-a, got reason: %s", result.Reason)
	}
	if result.Reason != "explicit_allow" {
		t.Errorf("expected reason 'explicit_allow', got %s", result.Reason)
	}
}

func TestAuthorizeDenyNoCapability(t *testing.T) {
	engine, _ := newTestEngine(t)

	// peer-b has monitor_read but not ssh_proxy
	result := engine.Authorize("peer-b-key-abcdefghij123456", CapSSHProxy, "")
	if result.Allowed {
		t.Error("expected SSH proxy to be denied for peer-b (no capability)")
	}
	if result.Reason != "no_capability" {
		t.Errorf("expected reason 'no_capability', got %s", result.Reason)
	}
}

func TestAuthorizeDenyNoGrant(t *testing.T) {
	engine, _ := newTestEngine(t)

	// unknown peer
	result := engine.Authorize("unknown-peer-key", CapSSHProxy, "")
	if result.Allowed {
		t.Error("expected SSH proxy to be denied for unknown peer")
	}
	if result.Reason != "no_capability" {
		t.Errorf("expected reason 'no_capability', got %s", result.Reason)
	}
}

func TestAuthorizeDenyEmptyCapabilities(t *testing.T) {
	engine, _ := newTestEngine(t)

	// peer-d has empty capabilities — should not even have a grant
	result := engine.Authorize("peer-d-key-no-caps", CapSSHProxy, "")
	if result.Allowed {
		t.Error("expected denial for peer with empty capabilities")
	}
}

func TestAuthorizeServiceScopeAllow(t *testing.T) {
	engine, _ := newTestEngine(t)

	// peer-c has service_manage scoped to nginx and meshdesk
	result := engine.Authorize("peer-c-key-0987654321fedcba", CapServiceManage, "nginx")
	if !result.Allowed {
		t.Errorf("expected service_manage nginx to be allowed, got reason: %s", result.Reason)
	}
}

func TestAuthorizeServiceScopeDeny(t *testing.T) {
	engine, _ := newTestEngine(t)

	// peer-c is scoped to nginx and meshdesk — not ssh
	result := engine.Authorize("peer-c-key-0987654321fedcba", CapServiceManage, "ssh")
	if result.Allowed {
		t.Error("expected service_manage ssh to be denied (not in scope)")
	}
	if result.Reason != "service_not_scoped" {
		t.Errorf("expected reason 'service_not_scoped', got %s", result.Reason)
	}
}

func TestAuthorizeFileTransferPathScope(t *testing.T) {
	var auditBuf bytes.Buffer
	audit := NewAuditLogger(&auditBuf)
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:         "peer-ft",
				Capabilities:      []string{CapFileTransfer},
				FileTransferPaths: []string{"/var/log/", "/tmp/"},
			},
		},
	}
	engine := NewCapabilityEngine(cfg, audit)

	// Allowed path
	result := engine.Authorize("peer-ft", CapFileTransfer, "/var/log/nginx/access.log")
	if !result.Allowed {
		t.Errorf("expected file transfer to /var/log/ to be allowed, got: %s", result.Reason)
	}

	// Denied path
	result = engine.Authorize("peer-ft", CapFileTransfer, "/etc/passwd")
	if result.Allowed {
		t.Error("expected file transfer to /etc/ to be denied")
	}
	if result.Reason != "path_denied" {
		t.Errorf("expected reason 'path_denied', got %s", result.Reason)
	}
}

// TestAuthorizeFileTransferPrefixConfusion verifies that a grant for
// /tmp does NOT match /tmp_evil or /tmpsecret (prefix confusion attack).
func TestAuthorizeFileTransferPrefixConfusion(t *testing.T) {
	var auditBuf bytes.Buffer
	audit := NewAuditLogger(&auditBuf)
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:         "peer-ft-confusion",
				Capabilities:      []string{CapFileTransfer},
				FileTransferPaths: []string{"/tmp"},
			},
		},
	}
	engine := NewCapabilityEngine(cfg, audit)

	// /tmp_evil should NOT match a grant for /tmp
	result := engine.Authorize("peer-ft-confusion", CapFileTransfer, "/tmp_evil")
	if result.Allowed {
		t.Error("expected /tmp_evil to be denied (prefix confusion attack)")
	}
	if result.Reason != "path_denied" {
		t.Errorf("expected reason 'path_denied', got %s", result.Reason)
	}

	// /tmpsecret should NOT match a grant for /tmp
	result = engine.Authorize("peer-ft-confusion", CapFileTransfer, "/tmpsecret")
	if result.Allowed {
		t.Error("expected /tmpsecret to be denied (prefix confusion attack)")
	}
	if result.Reason != "path_denied" {
		t.Errorf("expected reason 'path_denied', got %s", result.Reason)
	}

	// /tmp_evil_file.txt should NOT match
	result = engine.Authorize("peer-ft-confusion", CapFileTransfer, "/tmp_evil_file.txt")
	if result.Allowed {
		t.Error("expected /tmp_evil_file.txt to be denied (prefix confusion attack)")
	}
	if result.Reason != "path_denied" {
		t.Errorf("expected reason 'path_denied', got %s", result.Reason)
	}
}

// TestAuthorizeFileTransferExactMatch verifies that a resource path
// exactly equal to the granted prefix is allowed.
func TestAuthorizeFileTransferExactMatch(t *testing.T) {
	var auditBuf bytes.Buffer
	audit := NewAuditLogger(&auditBuf)
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:         "peer-ft-exact",
				Capabilities:      []string{CapFileTransfer},
				FileTransferPaths: []string{"/tmp"},
			},
		},
	}
	engine := NewCapabilityEngine(cfg, audit)

	// Exact match: resource == prefix
	result := engine.Authorize("peer-ft-exact", CapFileTransfer, "/tmp")
	if !result.Allowed {
		t.Errorf("expected exact match /tmp to be allowed, got: %s", result.Reason)
	}

	// Also test with trailing slash variants — filepath.Clean normalizes them
	result = engine.Authorize("peer-ft-exact", CapFileTransfer, "/tmp/")
	if !result.Allowed {
		t.Errorf("expected /tmp/ (with trailing slash) to be allowed, got: %s", result.Reason)
	}
}

// TestAuthorizeFileTransferSubdirectory verifies that a resource path
// under the prefix directory (prefix/subpath) is allowed.
func TestAuthorizeFileTransferSubdirectory(t *testing.T) {
	var auditBuf bytes.Buffer
	audit := NewAuditLogger(&auditBuf)
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:         "peer-ft-subdir",
				Capabilities:      []string{CapFileTransfer},
				FileTransferPaths: []string{"/home/user"},
			},
		},
	}
	engine := NewCapabilityEngine(cfg, audit)

	// Subdirectory access should be allowed
	result := engine.Authorize("peer-ft-subdir", CapFileTransfer, "/home/user/documents/report.txt")
	if !result.Allowed {
		t.Errorf("expected /home/user/documents/report.txt to be allowed, got: %s", result.Reason)
	}

	// Nested subdirectory
	result = engine.Authorize("peer-ft-subdir", CapFileTransfer, "/home/user/deep/nested/path/file.txt")
	if !result.Allowed {
		t.Errorf("expected nested path to be allowed, got: %s", result.Reason)
	}

	// /home/useradmin should NOT match (prefix confusion)
	result = engine.Authorize("peer-ft-subdir", CapFileTransfer, "/home/useradmin")
	if result.Allowed {
		t.Error("expected /home/useradmin to be denied (prefix confusion attack)")
	}
	if result.Reason != "path_denied" {
		t.Errorf("expected reason 'path_denied', got %s", result.Reason)
	}
}

// TestAuthorizeFileTransferTraversal verifies that directory traversal
// via ".." in the resource path is rejected.
func TestAuthorizeFileTransferTraversal(t *testing.T) {
	var auditBuf bytes.Buffer
	audit := NewAuditLogger(&auditBuf)
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:         "peer-ft-traversal",
				Capabilities:      []string{CapFileTransfer},
				FileTransferPaths: []string{"/tmp"},
			},
		},
	}
	engine := NewCapabilityEngine(cfg, audit)

	// Traversal: /tmp/../etc/passwd should be rejected.
	// filepath.Clean("/tmp/../etc/passwd") = "/etc/passwd", which is NOT
	// under /tmp, so this is denied.
	result := engine.Authorize("peer-ft-traversal", CapFileTransfer, "/tmp/../etc/passwd")
	if result.Allowed {
		t.Error("expected /tmp/../etc/passwd to be denied (directory traversal)")
	}
	if result.Reason != "path_denied" {
		t.Errorf("expected reason 'path_denied', got %s", result.Reason)
	}

	// Deeper traversal: /tmp/logs/../../etc/shadow
	result = engine.Authorize("peer-ft-traversal", CapFileTransfer, "/tmp/logs/../../etc/shadow")
	if result.Allowed {
		t.Error("expected /tmp/logs/../../etc/shadow to be denied (directory traversal)")
	}

	// Traversal that resolves outside the prefix even with deeper nesting
	result = engine.Authorize("peer-ft-traversal", CapFileTransfer, "/tmp/subdir/../../../etc/passwd")
	if result.Allowed {
		t.Error("expected /tmp/subdir/../../../etc/passwd to be denied (directory traversal)")
	}
}

// TestAuthorizeFileTransferPathNormalization verifies that path
// normalization via filepath.Clean is applied to both the resource
// and the granted prefix before comparison.
func TestAuthorizeFileTransferPathNormalization(t *testing.T) {
	var auditBuf bytes.Buffer
	audit := NewAuditLogger(&auditBuf)
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:         "peer-ft-norm",
				Capabilities:      []string{CapFileTransfer},
				FileTransferPaths: []string{"/var/log"}, // no trailing slash
			},
		},
	}
	engine := NewCapabilityEngine(cfg, audit)

	// Resource with redundant slashes — should be cleaned and matched
	result := engine.Authorize("peer-ft-norm", CapFileTransfer, "/var/log//nginx/access.log")
	if !result.Allowed {
		t.Errorf("expected /var/log//nginx/access.log (redundant slash) to be allowed, got: %s", result.Reason)
	}

	// Resource with single-dot segments — should be cleaned and matched
	result = engine.Authorize("peer-ft-norm", CapFileTransfer, "/var/log/./nginx/access.log")
	if !result.Allowed {
		t.Errorf("expected /var/log/./nginx/access.log (dot segment) to be allowed, got: %s", result.Reason)
	}

	// Grant prefix with trailing slash — should still work (cleaned)
	cfg2 := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:         "peer-ft-norm2",
				Capabilities:      []string{CapFileTransfer},
				FileTransferPaths: []string{"/var/log/"},
			},
		},
	}
	engine2 := NewCapabilityEngine(cfg2, audit)

	result = engine2.Authorize("peer-ft-norm2", CapFileTransfer, "/var/log/nginx/access.log")
	if !result.Allowed {
		t.Errorf("expected /var/log/nginx/access.log to be allowed with trailing-slash grant, got: %s", result.Reason)
	}
}

// TestPathWithinPrefixDirect is a unit test for the pathWithinPrefix
// helper function itself, covering all edge cases directly.
func TestPathWithinPrefixDirect(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		prefix   string
		want     bool
	}{
		// Exact match
		{"exact match", "/tmp", "/tmp", true},
		{"exact match with trailing slash resource", "/tmp/", "/tmp", true},
		{"exact match with trailing slash prefix", "/tmp", "/tmp/", true},

		// Subdirectory access
		{"subdirectory", "/tmp/file.txt", "/tmp", true},
		{"nested subdirectory", "/tmp/sub/deep/file.txt", "/tmp", true},

		// Prefix confusion — must be denied
		{"prefix confusion sibling", "/tmp_evil", "/tmp", false},
		{"prefix confusion secret", "/tmpsecret", "/tmp", false},
		{"prefix confusion with file ext", "/tmp_evil.txt", "/tmp", false},
		{"prefix confusion home", "/home/useradmin", "/home/user", false},

		// Directory traversal — must be denied
		{"traversal basic", "/tmp/../etc/passwd", "/tmp", false},
		{"traversal deep", "/tmp/subdir/../../../etc/passwd", "/tmp", false},
		{"traversal logs", "/tmp/logs/../../etc/shadow", "/tmp", false},

		// Completely different paths
		{"different root", "/etc/passwd", "/tmp", false},
		{"different root2", "/home/user/file", "/tmp", false},

		// Path normalization
		{"redundant slash in resource", "/var/log//nginx", "/var/log", true},
		{"dot segment in resource", "/var/log/./nginx", "/var/log", true},
		{"redundant slash in prefix", "/var/log/nginx", "/var/log//", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathWithinPrefix(tt.resource, tt.prefix)
			if got != tt.want {
				t.Errorf("pathWithinPrefix(%q, %q) = %v, want %v", tt.resource, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestAuthorizeMonitorScope(t *testing.T) {
	var auditBuf bytes.Buffer
	audit := NewAuditLogger(&auditBuf)
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:     "peer-mon",
				Capabilities:  []string{CapMonitorRead},
				MonitorScopes: []string{"cpu", "memory"},
			},
		},
	}
	engine := NewCapabilityEngine(cfg, audit)

	result := engine.Authorize("peer-mon", CapMonitorRead, "cpu")
	if !result.Allowed {
		t.Errorf("expected monitor_read cpu to be allowed, got: %s", result.Reason)
	}

	result = engine.Authorize("peer-mon", CapMonitorRead, "disk")
	if result.Allowed {
		t.Error("expected monitor_read disk to be denied (not in scope)")
	}
	if result.Reason != "scope_denied" {
		t.Errorf("expected reason 'scope_denied', got %s", result.Reason)
	}
}

// --- Revocation tests ---

func TestRevokePeer(t *testing.T) {
	engine, _ := newTestEngine(t)

	// Before revocation — peer-a can ssh_proxy
	result := engine.Authorize("peer-a-key-1234567890abcdef", CapSSHProxy, "")
	if !result.Allowed {
		t.Fatal("expected peer-a to be allowed before revocation")
	}

	// Revoke
	err := engine.Revoke("peer-a-key-1234567890abcdef", "revoker-key", "signature", "compromised")
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	if !engine.IsRevoked("peer-a-key-1234567890abcdef") {
		t.Error("expected peer-a to be revoked")
	}

	// After revocation — denied
	result = engine.Authorize("peer-a-key-1234567890abcdef", CapSSHProxy, "")
	if result.Allowed {
		t.Error("expected peer-a to be denied after revocation")
	}
	if result.Reason != "revoked" {
		t.Errorf("expected reason 'revoked', got %s", result.Reason)
	}
}

func TestReinstatePeer(t *testing.T) {
	engine, _ := newTestEngine(t)

	engine.Revoke("peer-a-key-1234567890abcdef", "revoker", "sig", "test")
	engine.Reinstate("peer-a-key-1234567890abcdef")

	if engine.IsRevoked("peer-a-key-1234567890abcdef") {
		t.Error("expected peer-a to not be revoked after reinstate")
	}

	result := engine.Authorize("peer-a-key-1234567890abcdef", CapSSHProxy, "")
	if !result.Allowed {
		t.Error("expected peer-a to be allowed after reinstate")
	}
}

func TestRevokedCount(t *testing.T) {
	engine, _ := newTestEngine(t)
	if engine.RevokedCount() != 0 {
		t.Error("expected 0 revocations initially")
	}
	engine.Revoke("peer-a-key-1234567890abcdef", "r", "s", "reason")
	if engine.RevokedCount() != 1 {
		t.Error("expected 1 revocation")
	}
}

// --- Audit logging tests ---

func TestAuditLogWritten(t *testing.T) {
	engine, auditBuf := newTestEngine(t)

	engine.Authorize("peer-a-key-1234567890abcdef", CapSSHProxy, "")
	engine.Authorize("peer-b-key-abcdefghij123456", CapSSHProxy, "")

	auditOutput := auditBuf.String()
	lines := strings.Split(strings.TrimSpace(auditOutput), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(lines))
	}

	// First should be allow, second should be deny
	var entry1, entry2 AuditEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry1); err != nil {
		t.Fatalf("parse entry 1: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &entry2); err != nil {
		t.Fatalf("parse entry 2: %v", err)
	}

	if entry1.Result != "allow" {
		t.Errorf("expected first entry to be allow, got %s", entry1.Result)
	}
	if entry2.Result != "deny" {
		t.Errorf("expected second entry to be deny, got %s", entry2.Result)
	}
	if entry1.Reason != "explicit_allow" {
		t.Errorf("expected reason 'explicit_allow', got %s", entry1.Reason)
	}
	if entry2.Reason != "no_capability" {
		t.Errorf("expected reason 'no_capability', got %s", entry2.Reason)
	}
	if entry1.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
	if _, err := time.Parse(time.RFC3339, entry1.Timestamp); err != nil {
		t.Errorf("timestamp not valid RFC3339: %v", err)
	}
}

func TestAuditEntryContainsAllFields(t *testing.T) {
	engine, auditBuf := newTestEngine(t)

	engine.Authorize("peer-c-key-0987654321fedcba", CapServiceManage, "ssh")

	var entry AuditEntry
	lines := strings.Split(strings.TrimSpace(auditBuf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(lines))
	}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parse entry: %v", err)
	}

	if entry.SourcePeer != "peer-c-key-0987654321fedcba" {
		t.Errorf("expected source_peer, got %s", entry.SourcePeer)
	}
	if entry.RequestedCapability != CapServiceManage {
		t.Errorf("expected capability %s, got %s", CapServiceManage, entry.RequestedCapability)
	}
	if entry.TargetResource != "ssh" {
		t.Errorf("expected resource 'ssh', got %s", entry.TargetResource)
	}
	if entry.Result != "deny" {
		t.Errorf("expected deny, got %s", entry.Result)
	}
	if entry.Reason != "service_not_scoped" {
		t.Errorf("expected 'service_not_scoped', got %s", entry.Reason)
	}
}

// --- Grant management tests ---

func TestGetGrant(t *testing.T) {
	engine, _ := newTestEngine(t)

	grant := engine.GetGrant("peer-a-key-1234567890abcdef")
	if grant == nil {
		t.Fatal("expected grant for peer-a")
	}
	if !grant.Capabilities[CapSSHProxy] {
		t.Error("expected ssh_proxy capability")
	}
	if !grant.Capabilities[CapFileTransfer] {
		t.Error("expected file_transfer capability")
	}
}

func TestGetGrantNotFound(t *testing.T) {
	engine, _ := newTestEngine(t)
	if g := engine.GetGrant("nonexistent"); g != nil {
		t.Error("expected nil for nonexistent peer")
	}
}

func TestAllGrants(t *testing.T) {
	engine, _ := newTestEngine(t)
	grants := engine.AllGrants()
	// peer-d has empty capabilities, so it should not have a grant
	if len(grants) != 3 {
		t.Errorf("expected 3 grants (peer-a, peer-b, peer-c), got %d", len(grants))
	}
}

func TestGrantCount(t *testing.T) {
	engine, _ := newTestEngine(t)
	if engine.GrantCount() != 3 {
		t.Errorf("expected 3 grants, got %d", engine.GrantCount())
	}
}

// --- Default-deny (zero-trust) test ---

func TestZeroTrustDefaultDeny(t *testing.T) {
	// A fresh config with no peer capabilities
	var auditBuf bytes.Buffer
	audit := NewAuditLogger(&auditBuf)
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{PublicKey: "fresh-peer", Capabilities: []string{}},
		},
	}
	engine := NewCapabilityEngine(cfg, audit)

	// Every capability should be denied
	for _, cap := range AllCapabilities {
		result := engine.Authorize("fresh-peer", cap, "")
		if result.Allowed {
			t.Errorf("expected %s to be denied for fresh peer (zero-trust)", cap)
		}
	}
}

// --- LoadPeerConfig test ---

func TestLoadPeerConfig(t *testing.T) {
	var auditBuf bytes.Buffer
	audit := NewAuditLogger(&auditBuf)
	engine := NewCapabilityEngine(&config.Config{}, audit)

	// Initially no grants
	if engine.GrantCount() != 0 {
		t.Fatal("expected 0 grants initially")
	}

	engine.LoadPeerConfig(config.PeerConfig{
		PublicKey:     "new-peer",
		Capabilities:  []string{CapSSHProxy, CapServiceManage},
		ServiceManage: []string{"nginx"},
	})

	if engine.GrantCount() != 1 {
		t.Fatal("expected 1 grant after LoadPeerConfig")
	}

	// Verify ssh_proxy is allowed
	result := engine.Authorize("new-peer", CapSSHProxy, "")
	if !result.Allowed {
		t.Error("expected ssh_proxy to be allowed")
	}

	// Verify service_manage nginx is allowed but ssh is not
	result = engine.Authorize("new-peer", CapServiceManage, "nginx")
	if !result.Allowed {
		t.Error("expected service_manage nginx to be allowed")
	}
	result = engine.Authorize("new-peer", CapServiceManage, "ssh")
	if result.Allowed {
		t.Error("expected service_manage ssh to be denied")
	}
}

// --- PeerGrant Summary test ---

func TestGrantSummary(t *testing.T) {
	engine, _ := newTestEngine(t)
	grant := engine.GetGrant("peer-a-key-1234567890abcdef")
	if grant == nil {
		t.Fatal("expected grant")
	}
	summary := grant.Summary()
	if !strings.Contains(summary, "peer-a") {
		t.Errorf("summary should contain peer ID prefix: %s", summary)
	}
}
