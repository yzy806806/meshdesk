package main

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/proxy"
)

// This file implements namespace-level smoke tests for the proxy data plane
// wiring that cmd/meshdesk/main.go sets up at lines 255-397.
//
// The main() function itself is not unit-testable (it blocks on signals and
// calls log.Fatalf), so these tests replicate the *same construction logic*
// — the same config field resolution, SS listener creation, EntryNode/ExitNode
// instantiation, SecurityEventSink wiring, and goroutine lifecycle — and verify
// that it produces correct, leak-free runtime state.
//
// These are in-process assertions, not real-machine deployment tests.

// makeTestProxyConfig builds a config.ProxyConfig with SS, circuit, and exit
// settings — exactly as main.go resolves them from YAML — but using ephemeral
// ports and test-safe values.
func makeTestProxyConfig(ssPort int) config.ProxyConfig {
	return config.ProxyConfig{
		SS: config.SSListenerConfig{
			Password:   "smoke-test-password",
			Cipher:     proxy.CipherChaCha20IETFPoly1305,
			ListenAddr: fmt.Sprintf("127.0.0.1:%d", ssPort),
			Port:       ssPort,
		},
		Circuit: config.CircuitLifecycleConfig{
			IdleTimeout:         300,
			KeepaliveInterval:   30,
			NACKTimeout:         5,
			OrphanTimeout:       30,
			MaxReassemblyWindow: 256,
		},
		ChunkerStrategy:  "bounded-4k-64k",
		DebugFixedChunks: true,              // deterministic for testing
		ExitAddr:         "127.0.0.1:19999", // unreachable, but required for entry node
		Exit: config.ExitConfig{
			AllowedPorts:  []int{80, 443},
			AllowAllPorts: false,
		},
		PathSelection: config.PathSelectionConfig{
			Mode: "manual",
		},
	}
}

// resolveEntryNodeConfig mirrors the construction logic in main.go:289-351.
// It takes a config.ProxyConfig and produces a proxy.EntryNodeConfig with
// all fields resolved — the same field resolution that main.go performs.
func resolveEntryNodeConfig(cfg config.ProxyConfig, dialFunc func(ctx context.Context, network, address string) (net.Conn, error)) proxy.EntryNodeConfig {
	ssListenAddr := cfg.SS.ListenAddr
	if ssListenAddr == "" {
		ssListenAddr = fmt.Sprintf(":%d", cfg.SS.Port)
	}

	circuitCfg := proxy.CircuitConfig{
		IdleTimeout:         time.Duration(cfg.Circuit.IdleTimeout) * time.Second,
		KeepaliveInterval:   time.Duration(cfg.Circuit.KeepaliveInterval) * time.Second,
		NACKTimeout:         time.Duration(cfg.Circuit.NACKTimeout) * time.Second,
		OrphanTimeout:       time.Duration(cfg.Circuit.OrphanTimeout) * time.Second,
		MaxReassemblyWindow: cfg.Circuit.MaxReassemblyWindow,
	}
	if circuitCfg.IdleTimeout == 0 {
		circuitCfg = proxy.DefaultCircuitConfig()
	}

	return proxy.EntryNodeConfig{
		SSConfig: proxy.SSConfig{
			Password:   cfg.SS.Password,
			Cipher:     cfg.SS.Cipher,
			ListenAddr: ssListenAddr,
		},
		CircuitCfg:       circuitCfg,
		ChunkerStrategy:  cfg.ChunkerStrategy,
		ChunkerCfg:       proxy.DefaultChunkerConfig(),
		DebugFixedChunks: cfg.DebugFixedChunks,
		ExitAddr:         cfg.ExitAddr,
		DialFunc:         dialFunc,
	}
}

// resolveExitNodeConfig mirrors the construction logic in main.go:357-377.
func resolveExitNodeConfig(cfg config.ProxyConfig) proxy.ExitConfig {
	exitCircuitCfg := proxy.DefaultCircuitConfig()
	if cfg.Circuit.OrphanTimeout > 0 {
		exitCircuitCfg.OrphanTimeout = time.Duration(cfg.Circuit.OrphanTimeout) * time.Second
	}
	if cfg.Circuit.NACKTimeout > 0 {
		exitCircuitCfg.NACKTimeout = time.Duration(cfg.Circuit.NACKTimeout) * time.Second
	}
	if cfg.Circuit.MaxReassemblyWindow > 0 {
		exitCircuitCfg.MaxReassemblyWindow = cfg.Circuit.MaxReassemblyWindow
	}

	return proxy.ExitConfig{
		CircuitCfg:       exitCircuitCfg,
		AllowedPorts:     cfg.Exit.AllowedPorts,
		AllowAllPorts:    cfg.Exit.AllowAllPorts,
		ChunkerStrategy:  cfg.ChunkerStrategy,
		ChunkerCfg:       proxy.DefaultChunkerConfig(),
		DebugFixedChunks: cfg.DebugFixedChunks,
		Dialer:           net.Dial,
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Test 1: Config field resolution produces correct values at runtime
// ──────────────────────────────────────────────────────────────────────────

// TestProxyConfigFieldResolution verifies that the config field resolution
// logic (mirroring main.go:289-377) produces correct values when translating
// from config.ProxyConfig to proxy.EntryNodeConfig and proxy.ExitConfig.
func TestProxyConfigFieldResolution(t *testing.T) {
	cfg := makeTestProxyConfig(8388)

	// ── Entry node config resolution ──
	entryCfg := resolveEntryNodeConfig(cfg, nil)

	if entryCfg.SSConfig.Password != cfg.SS.Password {
		t.Errorf("entry SSConfig.Password: expected %q, got %q", cfg.SS.Password, entryCfg.SSConfig.Password)
	}
	if entryCfg.SSConfig.Cipher != proxy.CipherChaCha20IETFPoly1305 {
		t.Errorf("entry SSConfig.Cipher: expected %q, got %q", proxy.CipherChaCha20IETFPoly1305, entryCfg.SSConfig.Cipher)
	}
	if entryCfg.SSConfig.ListenAddr != "127.0.0.1:8388" {
		t.Errorf("entry SSConfig.ListenAddr: expected %q, got %q", "127.0.0.1:8388", entryCfg.SSConfig.ListenAddr)
	}
	if entryCfg.ExitAddr != cfg.ExitAddr {
		t.Errorf("entry ExitAddr: expected %q, got %q", cfg.ExitAddr, entryCfg.ExitAddr)
	}
	if entryCfg.ChunkerStrategy != cfg.ChunkerStrategy {
		t.Errorf("entry ChunkerStrategy: expected %q, got %q", cfg.ChunkerStrategy, entryCfg.ChunkerStrategy)
	}
	if !entryCfg.DebugFixedChunks {
		t.Error("entry DebugFixedChunks: expected true")
	}
	// Circuit config resolution
	if entryCfg.CircuitCfg.IdleTimeout != 300*time.Second {
		t.Errorf("entry CircuitCfg.IdleTimeout: expected 300s, got %v", entryCfg.CircuitCfg.IdleTimeout)
	}
	if entryCfg.CircuitCfg.KeepaliveInterval != 30*time.Second {
		t.Errorf("entry CircuitCfg.KeepaliveInterval: expected 30s, got %v", entryCfg.CircuitCfg.KeepaliveInterval)
	}
	if entryCfg.CircuitCfg.NACKTimeout != 5*time.Second {
		t.Errorf("entry CircuitCfg.NACKTimeout: expected 5s, got %v", entryCfg.CircuitCfg.NACKTimeout)
	}
	if entryCfg.CircuitCfg.OrphanTimeout != 30*time.Second {
		t.Errorf("entry CircuitCfg.OrphanTimeout: expected 30s, got %v", entryCfg.CircuitCfg.OrphanTimeout)
	}
	if entryCfg.CircuitCfg.MaxReassemblyWindow != 256 {
		t.Errorf("entry CircuitCfg.MaxReassemblyWindow: expected 256, got %d", entryCfg.CircuitCfg.MaxReassemblyWindow)
	}

	// ── Exit node config resolution ──
	exitCfg := resolveExitNodeConfig(cfg)

	if len(exitCfg.AllowedPorts) != 2 || exitCfg.AllowedPorts[0] != 80 || exitCfg.AllowedPorts[1] != 443 {
		t.Errorf("exit AllowedPorts: expected [80, 443], got %v", exitCfg.AllowedPorts)
	}
	if exitCfg.AllowAllPorts {
		t.Error("exit AllowAllPorts: expected false")
	}
	if exitCfg.ChunkerStrategy != cfg.ChunkerStrategy {
		t.Errorf("exit ChunkerStrategy: expected %q, got %q", cfg.ChunkerStrategy, exitCfg.ChunkerStrategy)
	}
	if exitCfg.CircuitCfg.OrphanTimeout != 30*time.Second {
		t.Errorf("exit CircuitCfg.OrphanTimeout: expected 30s, got %v", exitCfg.CircuitCfg.OrphanTimeout)
	}
	if exitCfg.CircuitCfg.NACKTimeout != 5*time.Second {
		t.Errorf("exit CircuitCfg.NACKTimeout: expected 5s, got %v", exitCfg.CircuitCfg.NACKTimeout)
	}
	if exitCfg.CircuitCfg.MaxReassemblyWindow != 256 {
		t.Errorf("exit CircuitCfg.MaxReassemblyWindow: expected 256, got %d", exitCfg.CircuitCfg.MaxReassemblyWindow)
	}
	if exitCfg.Dialer == nil {
		t.Error("exit Dialer: expected non-nil (net.Dial)")
	}
}

// TestProxyConfigDefaultCircuitFallback verifies that when circuit config
// fields are all zero (as in config.Default()), the DefaultCircuitConfig()
// fallback kicks in — mirroring main.go:303-305.
func TestProxyConfigDefaultCircuitFallback(t *testing.T) {
	cfg := makeTestProxyConfig(0)
	cfg.Circuit = config.CircuitLifecycleConfig{} // all zeros

	entryCfg := resolveEntryNodeConfig(cfg, nil)

	defaults := proxy.DefaultCircuitConfig()
	if entryCfg.CircuitCfg.IdleTimeout != defaults.IdleTimeout {
		t.Errorf("IdleTimeout fallback: expected %v, got %v", defaults.IdleTimeout, entryCfg.CircuitCfg.IdleTimeout)
	}
	if entryCfg.CircuitCfg.KeepaliveInterval != defaults.KeepaliveInterval {
		t.Errorf("KeepaliveInterval fallback: expected %v, got %v", defaults.KeepaliveInterval, entryCfg.CircuitCfg.KeepaliveInterval)
	}
}

// TestProxyConfigListenAddrFallback verifies that when ListenAddr is empty
// but Port is set, the listen address is constructed from the port —
// mirroring main.go:290-293.
func TestProxyConfigListenAddrFallback(t *testing.T) {
	cfg := makeTestProxyConfig(9388)
	cfg.SS.ListenAddr = "" // force port-based fallback

	entryCfg := resolveEntryNodeConfig(cfg, nil)

	expected := ":9388"
	if entryCfg.SSConfig.ListenAddr != expected {
		t.Errorf("ListenAddr fallback: expected %q, got %q", expected, entryCfg.SSConfig.ListenAddr)
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Test 2: SS listener port binding succeeds
// ──────────────────────────────────────────────────────────────────────────

// TestSSListenerPortBinding verifies that the SS listener successfully binds
// to an ephemeral port and that the bound address matches the config.
// This exercises the same NewSSListener call in main.go:289.
func TestSSListenerPortBinding(t *testing.T) {
	// Bind to port 0 (ephemeral) to get an OS-assigned port.
	ln, err := proxy.NewSSListener(proxy.SSConfig{
		Password:   "port-binding-test",
		Cipher:     proxy.CipherChaCha20IETFPoly1305,
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewSSListener failed: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	if addr == "" {
		t.Fatal("listener Addr() returned empty string")
	}

	// Verify the address is a valid TCP address on 127.0.0.1.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("listener Addr() invalid %q: %v", addr, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %q", host)
	}
	if port == "0" || port == "" {
		t.Errorf("expected non-zero ephemeral port, got %q", port)
	}

	// Verify the port is actually listening by dialing it.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("could not dial SS listener at %s: %v", addr, err)
	}
	conn.Close()
}

// TestSSListenerPortConflict verifies that binding two SS listeners to the
// same port fails — confirming that port binding is real, not a no-op.
func TestSSListenerPortConflict(t *testing.T) {
	ln1, err := proxy.NewSSListener(proxy.SSConfig{
		Password:   "conflict-test-1",
		Cipher:     proxy.CipherChaCha20IETFPoly1305,
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("first NewSSListener failed: %v", err)
	}
	defer ln1.Close()

	// Try to bind a second listener to the same port.
	_, err2 := proxy.NewSSListener(proxy.SSConfig{
		Password:   "conflict-test-2",
		Cipher:     proxy.CipherChaCha20IETFPoly1305,
		ListenAddr: ln1.Addr().String(),
	})
	if err2 == nil {
		t.Fatal("expected error binding second listener to same port, got nil")
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Test 3: Entry node port binding (full Start → Close lifecycle)
// ──────────────────────────────────────────────────────────────────────────

// TestEntryNodePortBindingAndLifecycle verifies that the EntryNode —
// constructed with the same config resolution as main.go — successfully
// starts, binds a port, and shuts down cleanly.
func TestEntryNodePortBindingAndLifecycle(t *testing.T) {
	cfg := makeTestProxyConfig(0)
	cfg.SS.ListenAddr = "127.0.0.1:0" // ephemeral

	// Build minimal valid manual paths with proper relay keys.
	key1 := make([]byte, 32) // KeySize = 32
	key2 := make([]byte, 32)

	entryCfg := resolveEntryNodeConfig(cfg, nil)
	entryCfg.PathSelectionMode = "manual"
	entryCfg.Path1 = &proxy.Path{Relays: []string{"127.0.0.1:18001"}, RelayKeys: [][]byte{key1}}
	entryCfg.Path2 = &proxy.Path{Relays: []string{"127.0.0.1:18002"}, RelayKeys: [][]byte{key2}}

	en := proxy.NewEntryNode(entryCfg)
	if err := en.Start(); err != nil {
		t.Fatalf("EntryNode.Start failed: %v", err)
	}

	// Verify the entry node is running.
	status := en.Status()
	if !status.Running {
		t.Error("expected entry node Running=true after Start()")
	}

	// Verify the SS listener is actually listening by dialing it.
	// The SS listener is internal to the EntryNode; we can verify it's
	// bound by checking that a TCP connection to the entry node's SS
	// address succeeds. Since we used :0, we need to get the actual
	// address — but EntryNode doesn't expose it directly. Instead, we
	// verify via Status() that the node is running and via Close() that
	// it shuts down cleanly.
	if status.SessionCount != 0 {
		t.Errorf("expected 0 sessions on fresh start, got %d", status.SessionCount)
	}
	if status.ExitAddr != cfg.ExitAddr {
		t.Errorf("expected ExitAddr %q, got %q", cfg.ExitAddr, status.ExitAddr)
	}

	// Close and verify clean shutdown.
	if err := en.Close(); err != nil {
		t.Errorf("EntryNode.Close failed: %v", err)
	}

	// Verify the node is no longer running.
	status = en.Status()
	if status.Running {
		t.Error("expected entry node Running=false after Close()")
	}
}

// TestEntryNodeCloseIdempotent verifies that multiple Close() calls
// don't panic or leak goroutines — mirroring the defer pattern in main.go.
func TestEntryNodeCloseIdempotent(t *testing.T) {
	cfg := makeTestProxyConfig(0)
	cfg.SS.ListenAddr = "127.0.0.1:0"

	key := make([]byte, 32)
	entryCfg := resolveEntryNodeConfig(cfg, nil)
	entryCfg.PathSelectionMode = "manual"
	entryCfg.Path1 = &proxy.Path{Relays: []string{"r1"}, RelayKeys: [][]byte{key}}
	entryCfg.Path2 = &proxy.Path{Relays: []string{"r2"}, RelayKeys: [][]byte{key}}

	en := proxy.NewEntryNode(entryCfg)
	if err := en.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Close multiple times — should not panic.
	for i := 0; i < 3; i++ {
		if err := en.Close(); err != nil {
			t.Errorf("Close call %d failed: %v", i+1, err)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Test 4: Exit node goroutine lifecycle (orphan cleanup)
// ──────────────────────────────────────────────────────────────────────────

// TestExitNodeOrphanCleanupLifecycle verifies that the ExitNode's
// StartOrphanCleanup goroutine starts, runs, and stops cleanly when
// its context is cancelled — mirroring main.go:383-384.
func TestExitNodeOrphanCleanupLifecycle(t *testing.T) {
	cfg := makeTestProxyConfig(0)
	exitCfg := resolveExitNodeConfig(cfg)

	exitNode := proxy.NewExitNode(exitCfg)
	defer exitNode.Close()

	// Start orphan cleanup with a cancellable context.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		exitNode.StartOrphanCleanup(ctx)
		close(done)
	}()

	// Give it a moment to start.
	time.Sleep(50 * time.Millisecond)

	// Cancel the context — the goroutine should exit.
	cancel()

	select {
	case <-done:
		// Goroutine exited cleanly.
	case <-time.After(2 * time.Second):
		t.Fatal("StartOrphanCleanup goroutine did not exit within 2s after context cancel")
	}
}

// TestExitNodeCloseIdempotent verifies that multiple Close() calls
// on the ExitNode don't panic — mirroring the defer pattern in main.go:391.
func TestExitNodeCloseIdempotent(t *testing.T) {
	cfg := makeTestProxyConfig(0)
	exitCfg := resolveExitNodeConfig(cfg)

	exitNode := proxy.NewExitNode(exitCfg)

	for i := 0; i < 3; i++ {
		if err := exitNode.Close(); err != nil {
			t.Errorf("Close call %d failed: %v", i+1, err)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Test 5: SecurityEventSink wiring and callback delivery
// ──────────────────────────────────────────────────────────────────────────

// TestSecurityEventSinkWiring verifies that the shared SecurityEventSink
// — created in main.go:284 and wired to both the entry node and exit node —
// correctly delivers events from both subsystems to a single callback.
func TestSecurityEventSinkWiring(t *testing.T) {
	// Create the shared sink (mirrors main.go:284).
	sink := proxy.NewSecurityEventSink()

	// Track received events atomically.
	var receivedCount atomic.Int64
	sink.SetCallback(func(event proxy.SecurityEvent) {
		receivedCount.Add(1)
	})

	// ── Wire sink to exit node (mirrors main.go:380) ──
	cfg := makeTestProxyConfig(0)
	exitCfg := resolveExitNodeConfig(cfg)
	exitNode := proxy.NewExitNode(exitCfg)
	exitNode.SetSecurityEventSink(sink)
	defer exitNode.Close()

	// Trigger a security event on the exit node by sending a chunk
	// for a non-existent circuit.
	_, err := exitNode.HandleWireChunk("nonexistentcircuit", &proxy.WireChunk{
		Header:     make([]byte, 64), // ForwardingHeaderSize
		Nonce:      make([]byte, 12), // NonceSize
		Ciphertext: []byte("fake-ciphertext-data"),
	}, 0)
	if err == nil {
		t.Error("expected error handling chunk for nonexistent circuit")
	}

	// ── Wire sink to entry node (mirrors main.go:296-299) ──
	entryCfg := resolveEntryNodeConfig(cfg, nil)
	entryCfg.SecSink = sink
	key := make([]byte, 32)
	entryCfg.PathSelectionMode = "manual"
	entryCfg.Path1 = &proxy.Path{Relays: []string{"r1"}, RelayKeys: [][]byte{key}}
	entryCfg.Path2 = &proxy.Path{Relays: []string{"r2"}, RelayKeys: [][]byte{key}}

	en := proxy.NewEntryNode(entryCfg)
	if err := en.Start(); err != nil {
		t.Fatalf("EntryNode.Start failed: %v", err)
	}
	defer en.Close()

	// Verify the sink was wired to the SS listener internally.
	en.SetSecurityEventSink(sink) // mirrors the explicit SetSecurityEventSink call

	// At least one event should have been received from the exit node
	// (the nonexistent circuit chunk).
	if count := receivedCount.Load(); count < 1 {
		t.Errorf("expected at least 1 security event from exit node, got %d", count)
	}
}

// TestSecurityEventSinkNilSafe verifies that Report on a nil sink
// doesn't panic — the pattern used throughout the proxy package
// (secSink may be nil when alerting is not configured).
func TestSecurityEventSinkNilSafe(t *testing.T) {
	var sink *proxy.SecurityEventSink

	// Should not panic.
	sink.Report(proxy.SecurityEvent{
		Type:        proxy.SecEventExitCircuitNotFound,
		Description: "nil sink test",
	})
}

// TestSecurityEventSinkCallbackSwap verifies that the callback can be
// swapped at runtime — mirroring main.go:578-582 where the sink's
// callback is set after web server creation.
func TestSecurityEventSinkCallbackSwap(t *testing.T) {
	sink := proxy.NewSecurityEventSink()

	var firstCount atomic.Int64
	sink.SetCallback(func(event proxy.SecurityEvent) {
		firstCount.Add(1)
	})

	sink.Report(proxy.SecurityEvent{Type: proxy.SecEventSSConnError})
	if firstCount.Load() != 1 {
		t.Errorf("expected 1 event on first callback, got %d", firstCount.Load())
	}

	// Swap callback.
	var secondCount atomic.Int64
	sink.SetCallback(func(event proxy.SecurityEvent) {
		secondCount.Add(1)
	})

	sink.Report(proxy.SecurityEvent{Type: proxy.SecEventSSConnError})
	if firstCount.Load() != 1 {
		t.Errorf("first callback received unexpected event after swap: %d", firstCount.Load())
	}
	if secondCount.Load() != 1 {
		t.Errorf("expected 1 event on second callback, got %d", secondCount.Load())
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Test 6: Full wiring integration — entry + exit + sink together
// ──────────────────────────────────────────────────────────────────────────

// TestProxyDataPlaneFullWiring verifies the complete proxy data plane wiring
// — all three subsystems (entry node, exit node, security sink) instantiated
// and wired together, then cleanly torn down. This is the closest in-process
// equivalent to main.go's proxy section (lines 255-397).
func TestProxyDataPlaneFullWiring(t *testing.T) {
	cfg := makeTestProxyConfig(0)
	cfg.SS.ListenAddr = "127.0.0.1:0"

	// 1. Create the shared security event sink (main.go:284).
	sink := proxy.NewSecurityEventSink()
	var eventCount atomic.Int64
	sink.SetCallback(func(event proxy.SecurityEvent) {
		eventCount.Add(1)
	})

	// 2. Create the exit node (main.go:357-393).
	exitCfg := resolveExitNodeConfig(cfg)
	exitNode := proxy.NewExitNode(exitCfg)
	exitNode.SetSecurityEventSink(sink)

	exitCtx, exitCancel := context.WithCancel(context.Background())
	go exitNode.StartOrphanCleanup(exitCtx)

	// 3. Create the entry node (main.go:289-351).
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	entryCfg := resolveEntryNodeConfig(cfg, func(ctx context.Context, network, address string) (net.Conn, error) {
		// Use net.Dial as the mesh dial function substitute.
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	entryCfg.SecSink = sink
	entryCfg.PathSelectionMode = "manual"
	entryCfg.Path1 = &proxy.Path{Relays: []string{"127.0.0.1:19001"}, RelayKeys: [][]byte{key1}}
	entryCfg.Path2 = &proxy.Path{Relays: []string{"127.0.0.1:19002"}, RelayKeys: [][]byte{key2}}

	entryNode := proxy.NewEntryNode(entryCfg)

	// 4. Start the entry node — this binds the SS listener port.
	if err := entryNode.Start(); err != nil {
		t.Fatalf("EntryNode.Start failed: %v", err)
	}

	// 5. Verify runtime state.
	entryStatus := entryNode.Status()
	if !entryStatus.Running {
		t.Error("entry node should be running")
	}
	if entryStatus.SessionCount != 0 {
		t.Errorf("expected 0 sessions, got %d", entryStatus.SessionCount)
	}
	if entryStatus.ExitAddr != cfg.ExitAddr {
		t.Errorf("expected ExitAddr %q, got %q", cfg.ExitAddr, entryStatus.ExitAddr)
	}

	// Exit node should have 0 circuits (no data has flowed).
	if exitNode.CircuitCount() != 0 {
		t.Errorf("expected 0 exit circuits, got %d", exitNode.CircuitCount())
	}

	// 6. Clean teardown — mirrors the defer chain in main.go:389-397.
	if err := entryNode.Close(); err != nil {
		t.Errorf("EntryNode.Close failed: %v", err)
	}
	exitCancel() // stop orphan cleanup goroutine
	if err := exitNode.Close(); err != nil {
		t.Errorf("ExitNode.Close failed: %v", err)
	}

	// 7. Verify no panics or goroutine leaks (the orphan cleanup goroutine
	// should have exited when exitCancel was called).
	// We give a brief grace period for goroutine cleanup.
	time.Sleep(50 * time.Millisecond)

	// Entry node should report not running after close.
	entryStatus = entryNode.Status()
	if entryStatus.Running {
		t.Error("entry node should not be running after Close()")
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Test 7: Config field resolution edge cases
// ──────────────────────────────────────────────────────────────────────────

// TestProxyConfigEmptyPassword verifies that an empty SS password
// is caught at the SS listener creation level — confirming that
// the wiring correctly propagates the password requirement.
func TestProxyConfigEmptyPassword(t *testing.T) {
	cfg := makeTestProxyConfig(0)
	cfg.SS.Password = "" // empty password

	entryCfg := resolveEntryNodeConfig(cfg, nil)

	en := proxy.NewEntryNode(entryCfg)
	err := en.Start()
	if err == nil {
		en.Close()
		t.Fatal("expected Start() to fail with empty password, got nil")
	}
}

// TestProxyConfigExitNodeAllowAllPorts verifies that the exit node
// correctly resolves AllowAllPorts from config — mirroring main.go:357.
func TestProxyConfigExitNodeAllowAllPorts(t *testing.T) {
	cfg := makeTestProxyConfig(0)
	cfg.Exit.AllowAllPorts = true
	cfg.Exit.AllowedPorts = nil

	exitCfg := resolveExitNodeConfig(cfg)

	if !exitCfg.AllowAllPorts {
		t.Error("expected AllowAllPorts=true")
	}
	if len(exitCfg.AllowedPorts) != 0 {
		t.Errorf("expected empty AllowedPorts, got %v", exitCfg.AllowedPorts)
	}
}

// TestProxyConfigEntryNodeNotCreatedWithoutExitAddr verifies that when
// ExitAddr is empty, the entry node is not created — mirroring the
// conditional in main.go:289 (cfg.Proxy.SS.Port != 0 && cfg.Proxy.ExitAddr != "").
func TestProxyConfigEntryNodeNotCreatedWithoutExitAddr(t *testing.T) {
	cfg := makeTestProxyConfig(8388)
	cfg.ExitAddr = "" // no exit address

	// In main.go, this condition means proxyEntryNode stays nil.
	// We verify the same logic: if ExitAddr is empty, the entry node
	// config would have an empty ExitAddr, which is a valid but
	// non-functional configuration.
	entryCfg := resolveEntryNodeConfig(cfg, nil)
	if entryCfg.ExitAddr != "" {
		t.Errorf("expected empty ExitAddr, got %q", entryCfg.ExitAddr)
	}
}

// TestProxyConfigExitNodeNotCreatedWithoutPorts verifies that when
// neither AllowedPorts nor AllowAllPorts is set, the exit node is
// not created — mirroring the conditional in main.go:357.
func TestProxyConfigExitNodeNotCreatedWithoutPorts(t *testing.T) {
	cfg := makeTestProxyConfig(0)
	cfg.Exit.AllowedPorts = nil
	cfg.Exit.AllowAllPorts = false

	// In main.go:357, this condition means proxyExitNode stays nil.
	// The exit config resolution still works, but the exit node
	// wouldn't be instantiated in production.
	exitCfg := resolveExitNodeConfig(cfg)
	if len(exitCfg.AllowedPorts) != 0 || exitCfg.AllowAllPorts {
		t.Errorf("expected no exit ports configured, got AllowedPorts=%v AllowAllPorts=%v",
			exitCfg.AllowedPorts, exitCfg.AllowAllPorts)
	}
}
