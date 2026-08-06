package web

import (
	"strings"
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

// TestDefaultJoinTokenGenerator_JoinServerURL_SharedNode verifies that on a
// shared node (P2P + Reality enabled), the join URL uses the Reality listen
// port — not the standalone join listen addr (:8443). This is the core fix
// for the broken install-script URL on single-port deployments.
func TestDefaultJoinTokenGenerator_JoinServerURL_SharedNode(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "shared.example.com"
	cfg.Join.Enabled = true
	cfg.Join.Secret = "test-secret"
	cfg.Join.ListenAddr = ":8443" // should be ignored on shared nodes
	cfg.P2P.Enabled = true
	cfg.Reality.Enabled = true
	cfg.Reality.ListenPort = 52888

	gen := &defaultJoinTokenGenerator{cfg: cfg}
	url := gen.JoinServerURL()

	if url == "" {
		t.Fatal("JoinServerURL() returned empty on shared node with join enabled")
	}
	if !strings.Contains(url, "52888") {
		t.Errorf("JoinServerURL() = %q, want port 52888 (Reality listen port)", url)
	}
	if strings.Contains(url, "8443") {
		t.Errorf("JoinServerURL() = %q, should NOT contain :8443 on shared node", url)
	}
	if !strings.HasPrefix(url, "http://shared.example.com:") {
		t.Errorf("JoinServerURL() = %q, want http://shared.example.com:52888", url)
	}
}

// TestDefaultJoinTokenGenerator_JoinServerURL_SharedNodeDefaultPort verifies
// that when Reality.ListenPort is 0, the default port 443 is used.
func TestDefaultJoinTokenGenerator_JoinServerURL_SharedNodeDefaultPort(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "node.example.com"
	cfg.Join.Enabled = true
	cfg.Join.Secret = "test-secret"
	cfg.P2P.Enabled = true
	cfg.Reality.Enabled = true
	cfg.Reality.ListenPort = 0 // should default to 443

	gen := &defaultJoinTokenGenerator{cfg: cfg}
	url := gen.JoinServerURL()

	if !strings.Contains(url, ":443") {
		t.Errorf("JoinServerURL() = %q, want port 443 (default)", url)
	}
}

// TestDefaultJoinTokenGenerator_JoinServerURL_RegularNode verifies that on
// a non-shared node (P2P disabled), the join URL uses the standalone join
// listen addr.
func TestDefaultJoinTokenGenerator_JoinServerURL_RegularNode(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "regular.example.com"
	cfg.Join.Enabled = true
	cfg.Join.Secret = "test-secret"
	cfg.Join.ListenAddr = ":8443"
	cfg.P2P.Enabled = false
	cfg.Reality.Enabled = true

	gen := &defaultJoinTokenGenerator{cfg: cfg}
	url := gen.JoinServerURL()

	if !strings.Contains(url, ":8443") {
		t.Errorf("JoinServerURL() = %q, want port 8443 (join listen addr)", url)
	}
	if strings.Contains(url, "443") && strings.Contains(url, "8443") {
		// 8443 contains "443" as a substring — this check just makes sure
		// we don't accidentally get the bare :443.
		if strings.HasSuffix(url, ":443") {
			t.Errorf("JoinServerURL() = %q, should end with :8443 not :443", url)
		}
	}
}

// TestWebBaseURL_SharedNode verifies that webBaseURL() returns the Reality
// listen port on shared nodes (P2P + Reality enabled), not cfg.Node.WebAddr.
func TestWebBaseURL_SharedNode(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "shared.example.com"
	cfg.Node.WebAddr = ":8080" // should be ignored on shared nodes
	cfg.P2P.Enabled = true
	cfg.Reality.Enabled = true
	cfg.Reality.ListenPort = 52888

	srv, err := New(Deps{Config: cfg})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	url := srv.webBaseURL()
	if !strings.Contains(url, "52888") {
		t.Errorf("webBaseURL() = %q, want port 52888 (Reality listen port)", url)
	}
	if strings.Contains(url, ":8080") {
		t.Errorf("webBaseURL() = %q, should NOT contain :8080 on shared node", url)
	}
}

// TestWebBaseURL_RegularWebNode verifies that webBaseURL() returns
// cfg.Node.WebAddr on regular (non-shared) web nodes.
func TestWebBaseURL_RegularWebNode(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "regular.example.com"
	cfg.Node.WebAddr = ":8080"
	cfg.P2P.Enabled = false
	cfg.Reality.Enabled = false

	srv, err := New(Deps{Config: cfg})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	url := srv.webBaseURL()
	if !strings.Contains(url, ":8080") {
		t.Errorf("webBaseURL() = %q, want port 8080 (WebAddr)", url)
	}
}

// TestWebBaseURL_SharedNodeDefaultPort verifies that when Reality.ListenPort
// is 0 on a shared node, webBaseURL defaults to port 443.
func TestWebBaseURL_SharedNodeDefaultPort(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "node.example.com"
	cfg.Node.WebAddr = ":8080"
	cfg.P2P.Enabled = true
	cfg.Reality.Enabled = true
	cfg.Reality.ListenPort = 0

	srv, err := New(Deps{Config: cfg})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	url := srv.webBaseURL()
	if !strings.HasSuffix(url, ":443") {
		t.Errorf("webBaseURL() = %q, want port 443 (default)", url)
	}
}
