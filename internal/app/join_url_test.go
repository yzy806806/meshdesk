package app

import (
	"strings"
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

// TestNodeJoinTokenGenerator_JoinServerURL_WebPort verifies that the join
// URL always uses the Dashboard web port (cfg.Node.WebAddr). Since the
// reality-discipline refactor the join endpoint (/api/join) is served by
// the Dashboard web server ONLY — the mesh port carries no HTTP, so the
// old "derive from the Reality listen port" behavior is gone.
func TestNodeJoinTokenGenerator_JoinServerURL_WebPort(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "shared.example.com"
	cfg.Node.WebAddr = ":8080"
	cfg.P2P.Enabled = true
	cfg.P2P.AdvertiseEndpoints = []string{"shared.example.com:52888"}
	cfg.Join.Enabled = true
	cfg.Join.Secret = "test-secret"
	cfg.Reality.Enabled = true
	cfg.Reality.ListenPort = 52888

	gen := &nodeJoinTokenGenerator{cfg: cfg}
	url := gen.JoinServerURL()

	if url == "" {
		t.Fatal("JoinServerURL() returned empty with join enabled")
	}
	expected := "http://shared.example.com:8080"
	if url != expected {
		t.Errorf("JoinServerURL() = %q, want %q (web port, NOT the mesh port)", url, expected)
	}
	if strings.Contains(url, "52888") {
		t.Errorf("JoinServerURL() = %q must not reference the mesh port anymore", url)
	}
}

// TestNodeJoinTokenGenerator_JoinServerURL_CustomWebPort verifies that a
// custom web address is honored.
func TestNodeJoinTokenGenerator_JoinServerURL_CustomWebPort(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "node.example.com"
	cfg.Node.WebAddr = "10.0.0.5:9090"
	cfg.P2P.Enabled = true
	cfg.P2P.AdvertiseEndpoints = []string{"node.example.com:52888"}
	cfg.Join.Enabled = true
	cfg.Reality.Enabled = true

	gen := &nodeJoinTokenGenerator{cfg: cfg}
	url := gen.JoinServerURL()

	if !strings.HasSuffix(url, ":9090") {
		t.Errorf("JoinServerURL() = %q, want port 9090 (web addr)", url)
	}
	if !strings.HasPrefix(url, "http://node.example.com") {
		t.Errorf("JoinServerURL() = %q, want host from advertise endpoint", url)
	}
}

// TestNodeJoinTokenGenerator_JoinServerURL_DefaultWebPort verifies the
// fallback when no web address is configured.
func TestNodeJoinTokenGenerator_JoinServerURL_DefaultWebPort(t *testing.T) {
	cfg := config.Default()
	cfg.Node.Hostname = "node.example.com"
	cfg.Node.WebAddr = ""
	cfg.P2P.Enabled = true
	cfg.P2P.AdvertiseEndpoints = []string{"node.example.com:443"}
	cfg.Join.Enabled = true
	cfg.Reality.Enabled = true

	gen := &nodeJoinTokenGenerator{cfg: cfg}
	url := gen.JoinServerURL()

	if !strings.HasSuffix(url, ":8080") {
		t.Errorf("JoinServerURL() = %q, want default web port 8080", url)
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
