package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
)

// TestAppBuildStartStop is the smoke test for the three-phase assembly:
// minimal config → Build (construct+wire) → Start → Stop, with a clean
// exit. This pins the split's "testable" promise and the explicit
// reverse-order shutdown.
func TestAppBuildStartStop(t *testing.T) {
	dir := t.TempDir()

	cfg := config.Default()
	cfg.Node.Hostname = "smoke-test"
	cfg.Node.IdentityFile = filepath.Join(dir, "identity.key")
	cfg.Mesh.TunEnabled = false
	cfg.Mesh.Port = 0       // avoid privileged/default port collisions
	cfg.P2P.Enabled = true
	cfg.Monitoring.Interval = 60
	cfg.Proxy.SOCKS5.Enabled = false

	a, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !a.wired {
		t.Fatal("Build: wire() not called")
	}
	if a.node == nil {
		t.Fatal("Build: mesh node not constructed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Give it a beat to actually start (identity generation, listeners).
	time.Sleep(500 * time.Millisecond)

	// Stop must return cleanly and quickly (no hangs, no double-close).
	done := make(chan struct{})
	go func() {
		a.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop: hung")
	}
}

// TestBuildMinimal verifies Build works with the zero-ish config used
// by tests and CLI defaults (identity auto-generation). Identity file
// must point into a writable temp dir (CI runs as non-root).
func TestBuildMinimal(t *testing.T) {
	cfg := config.Default()
	cfg.Node.IdentityFile = filepath.Join(t.TempDir(), "identity.pem")
	a, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if a.node == nil {
		t.Fatal("node nil")
	}
	_ = os.Getpid
}
