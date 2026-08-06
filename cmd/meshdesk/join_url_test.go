package main

import (
	"strings"
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

// TestNodeJoinTokenGenerator_JoinServerURL_SharedNode verifies that on a
// shared node (P2P + Reality enabled), the join URL uses the Reality listen
// port — not the standalone join listen addr (:8443). This is the core fix
// for the broken install-script URL on single-port deployments.
func TestNodeJoinTokenGenerator_JoinServerURL_SharedNode(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "shared.example.com"
	cfg.P2P.Enabled = true
	cfg.P2P.AdvertiseEndpoints = []string{"shared.example.com:52888"}
	cfg.Join.Enabled = true
	cfg.Join.Secret = "test-secret"
	cfg.Join.ListenAddr = ":8443" // should be ignored on shared nodes
	cfg.Reality.Enabled = true
	cfg.Reality.ListenPort = 52888

	gen := &nodeJoinTokenGenerator{cfg: cfg}
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
	expected := "http://shared.example.com:52888"
	if url != expected {
		t.Errorf("JoinServerURL() = %q, want %q", url, expected)
	}
}

// TestNodeJoinTokenGenerator_JoinServerURL_SharedNodeDefaultPort verifies
// that when Reality.ListenPort is 0, the default port 443 is used.
func TestNodeJoinTokenGenerator_JoinServerURL_SharedNodeDefaultPort(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "node.example.com"
	cfg.P2P.Enabled = true
	cfg.P2P.AdvertiseEndpoints = []string{"node.example.com:443"}
	cfg.Join.Enabled = true
	cfg.Join.Secret = "test-secret"
	cfg.Reality.Enabled = true
	cfg.Reality.ListenPort = 0

	gen := &nodeJoinTokenGenerator{cfg: cfg}
	url := gen.JoinServerURL()

	if !strings.HasSuffix(url, ":443") {
		t.Errorf("JoinServerURL() = %q, want port 443 (default)", url)
	}
}

// TestNodeJoinTokenGenerator_JoinServerURL_RegularNode verifies that on
// a non-shared node (P2P disabled), the join URL uses the standalone join
// listen addr.
func TestNodeJoinTokenGenerator_JoinServerURL_RegularNode(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "regular.example.com"
	cfg.P2P.Enabled = false
	cfg.Join.Enabled = true
	cfg.Join.Secret = "test-secret"
	cfg.Join.ListenAddr = ":8443"
	cfg.Reality.Enabled = true

	gen := &nodeJoinTokenGenerator{cfg: cfg}
	url := gen.JoinServerURL()

	if !strings.Contains(url, ":8443") {
		t.Errorf("JoinServerURL() = %q, want port 8443 (join listen addr)", url)
	}
}

// TestNodeJoinTokenGenerator_JoinServerURL_JoinDisabled verifies that
// JoinServerURL returns empty when join is not enabled.
func TestNodeJoinTokenGenerator_JoinServerURL_JoinDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Join.Enabled = false

	gen := &nodeJoinTokenGenerator{cfg: cfg}
	url := gen.JoinServerURL()

	if url != "" {
		t.Errorf("JoinServerURL() = %q, want empty when join disabled", url)
	}
}
