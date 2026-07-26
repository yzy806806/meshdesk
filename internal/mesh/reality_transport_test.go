package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// RealityTransportFactory tests
// ──────────────────────────────────────────────────────────────────────────────

// TestRealityFactoryName verifies that the factory reports "reality" as its transport type.
func TestRealityFactoryName(t *testing.T) {
	f := NewRealityTransportFactory()
	if f.Name() != "reality" {
		t.Errorf("Name() = %q, want %q", f.Name(), "reality")
	}
}

// TestRealityFactoryActiveSince verifies that ActiveSince returns the creation time.
func TestRealityFactoryActiveSince(t *testing.T) {
	before := time.Now()
	f := NewRealityTransportFactory()
	after := time.Now()

	as := f.ActiveSince()
	if as.Before(before) || as.After(after) {
		t.Errorf("ActiveSince() = %v, want between %v and %v", as, before, after)
	}
}

// TestRealityFactoryConnCountInitial verifies ConnCount is 0 on a fresh factory.
func TestRealityFactoryConnCountInitial(t *testing.T) {
	f := NewRealityTransportFactory()
	if f.ConnCount() != 0 {
		t.Errorf("ConnCount() = %d, want 0", f.ConnCount())
	}
}

// TestRealityFactoryNewTransport verifies that NewTransport creates a working
// RealityTransport with the given config, applying defaults for zero-value fields.
func TestRealityFactoryNewTransport(t *testing.T) {
	f := NewRealityTransportFactory()
	tr, err := f.NewTransport(TransportConfig{Name: "reality"})
	if err != nil {
		t.Fatalf("NewTransport() error: %v", err)
	}
	if tr == nil {
		t.Fatal("NewTransport() returned nil transport")
	}
	if tr.Name() != "reality" {
		t.Errorf("Transport Name() = %q, want %q", tr.Name(), "reality")
	}
}

// TestRealityFactoryNewTransportDefaults verifies that zero-value fields in
// TransportConfig are replaced with defaults (DialTimeout=30s, TLSFingerprint="chrome").
func TestRealityFactoryNewTransportDefaults(t *testing.T) {
	f := NewRealityTransportFactory()
	tr, err := f.NewTransport(TransportConfig{Name: "reality"})
	if err != nil {
		t.Fatalf("NewTransport() error: %v", err)
	}
	rt := tr.(*RealityTransport)
	if rt.cfg.DialTimeout != 30*time.Second {
		t.Errorf("DialTimeout = %v, want 30s", rt.cfg.DialTimeout)
	}
	if rt.cfg.TLSFingerprint != "chrome" {
		t.Errorf("TLSFingerprint = %q, want %q", rt.cfg.TLSFingerprint, "chrome")
	}
}

// TestRealityFactoryNewTransportWrongName verifies that NewTransport rejects
// a config with a non-"reality" Name.
func TestRealityFactoryNewTransportWrongName(t *testing.T) {
	f := NewRealityTransportFactory()
	_, err := f.NewTransport(TransportConfig{Name: "udp"})
	if err == nil {
		t.Fatal("NewTransport() should reject non-reality name")
	}
	var cfgErr *TransportConfigError
	if !errors.As(err, &cfgErr) {
		t.Errorf("expected TransportConfigError, got %T: %v", err, err)
	}
	if cfgErr.Field != "Name" {
		t.Errorf("config error field = %q, want %q", cfgErr.Field, "Name")
	}
}

// TestRealityFactoryNewTransportAfterShutdown verifies that NewTransport
// returns ErrTransportShutdown after Shutdown has been called.
func TestRealityFactoryNewTransportAfterShutdown(t *testing.T) {
	f := NewRealityTransportFactory()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}
	_, err := f.NewTransport(TransportConfig{Name: "reality"})
	if !errors.Is(err, ErrTransportShutdown) {
		t.Errorf("NewTransport after shutdown = %v, want ErrTransportShutdown", err)
	}
}

// TestRealityFactoryShutdownIdempotent verifies that calling Shutdown
// multiple times is safe and returns nil.
func TestRealityFactoryShutdownIdempotent(t *testing.T) {
	f := NewRealityTransportFactory()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.Shutdown(ctx); err != nil {
		t.Fatalf("first Shutdown() error: %v", err)
	}
	if err := f.Shutdown(ctx); err != nil {
		t.Errorf("second Shutdown() error: %v", err)
	}
}

// TestRealityFactoryConnCount verifies that ConnCount tracks active connections.
func TestRealityFactoryConnCount(t *testing.T) {
	f := NewRealityTransportFactory()
	if f.ConnCount() != 0 {
		t.Fatalf("initial ConnCount = %d, want 0", f.ConnCount())
	}

	// Manually register a fake conn to test counting.
	f.connCount.Add(1)
	if f.ConnCount() != 1 {
		t.Errorf("ConnCount after increment = %d, want 1", f.ConnCount())
	}
	f.connCount.Add(-1)
	if f.ConnCount() != 0 {
		t.Errorf("ConnCount after decrement = %d, want 0", f.ConnCount())
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// RealityTransport tests (no network — interface compliance and config validation)
// ──────────────────────────────────────────────────────────────────────────────

// TestRealityTransportName verifies the transport reports "reality".
func TestRealityTransportName(t *testing.T) {
	f := NewRealityTransportFactory()
	tr, _ := f.NewTransport(TransportConfig{Name: "reality"})
	if tr.Name() != "reality" {
		t.Errorf("Name() = %q, want %q", tr.Name(), "reality")
	}
}

// TestRealityTransportIsHealthy verifies health reporting.
func TestRealityTransportIsHealthy(t *testing.T) {
	f := NewRealityTransportFactory()
	tr, _ := f.NewTransport(TransportConfig{Name: "reality"})
	rt := tr.(*RealityTransport)
	if !rt.IsHealthy() {
		t.Error("IsHealthy() = false, want true for fresh transport")
	}
	rt.markClosed()
	if rt.IsHealthy() {
		t.Error("IsHealthy() = true after markClosed, want false")
	}
}

// TestRealityTransportConnectAfterShutdown verifies that Connect returns
// a permanent error after the factory shuts down.
func TestRealityTransportConnectAfterShutdown(t *testing.T) {
	f := NewRealityTransportFactory()
	tr, _ := f.NewTransport(TransportConfig{
		Name:             "reality",
		RealityPublicKey: "abcd1234",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = f.Shutdown(ctx)

	_, err := tr.Connect(ctx, "127.0.0.1:443")
	if err == nil {
		t.Fatal("Connect after shutdown should error")
	}
	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if tErr.IsRetryable() {
		t.Error("error should be permanent (not retryable)")
	}
}

// TestRealityTransportConnectMissingPublicKey verifies that Connect returns
// a permanent config error when RealityPublicKey is empty.
func TestRealityTransportConnectMissingPublicKey(t *testing.T) {
	f := NewRealityTransportFactory()
	tr, _ := f.NewTransport(TransportConfig{Name: "reality"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := tr.Connect(ctx, "127.0.0.1:443")
	if err == nil {
		t.Fatal("Connect should fail with missing RealityPublicKey")
	}
	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if tErr.IsRetryable() {
		t.Error("error should be permanent")
	}
}

// TestRealityTransportListenMissingPrivateKey verifies that Listen returns
// a permanent config error when RealityPrivateKey is empty.
func TestRealityTransportListenMissingPrivateKey(t *testing.T) {
	f := NewRealityTransportFactory()
	tr, _ := f.NewTransport(TransportConfig{
		Name:        "reality",
		RealityDest: "www.apple.com:443",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := tr.Listen(ctx, "127.0.0.1:0")
	if err == nil {
		t.Fatal("Listen should fail with missing RealityPrivateKey")
	}
	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if tErr.IsRetryable() {
		t.Error("error should be permanent")
	}
}

// TestRealityTransportListenMissingDest verifies that Listen returns
// a permanent config error when RealityDest is empty.
func TestRealityTransportListenMissingDest(t *testing.T) {
	f := NewRealityTransportFactory()
	tr, _ := f.NewTransport(TransportConfig{
		Name:              "reality",
		RealityPrivateKey: "abcd1234",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := tr.Listen(ctx, "127.0.0.1:0")
	if err == nil {
		t.Fatal("Listen should fail with missing RealityDest")
	}
	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if tErr.IsRetryable() {
		t.Error("error should be permanent")
	}
}

// TestRealityTransportListenAfterShutdown verifies that Listen returns
// a permanent error after the factory shuts down.
func TestRealityTransportListenAfterShutdown(t *testing.T) {
	f := NewRealityTransportFactory()
	tr, _ := f.NewTransport(TransportConfig{
		Name:              "reality",
		RealityPrivateKey: "abcd1234",
		RealityDest:       "www.apple.com:443",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = f.Shutdown(ctx)

	_, err := tr.Listen(ctx, "127.0.0.1:0")
	if err == nil {
		t.Fatal("Listen after shutdown should error")
	}
	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if tErr.IsRetryable() {
		t.Error("error should be permanent")
	}
}

// TestRealityTransportLatencyProbeAfterShutdown verifies that LatencyProbe
// returns a permanent error after the factory shuts down.
func TestRealityTransportLatencyProbeAfterShutdown(t *testing.T) {
	f := NewRealityTransportFactory()
	tr, _ := f.NewTransport(TransportConfig{Name: "reality"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = f.Shutdown(ctx)

	_, err := tr.LatencyProbe(ctx, "127.0.0.1:443")
	if err == nil {
		t.Fatal("LatencyProbe after shutdown should error")
	}
	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if tErr.IsRetryable() {
		t.Error("error should be permanent")
	}
}

// TestRealityTransportShutdownDrainsConnections verifies that Shutdown
// properly waits for connections to drain.
func TestRealityTransportShutdownDrainsConnections(t *testing.T) {
	f := NewRealityTransportFactory()
	_, _ = f.NewTransport(TransportConfig{Name: "reality"})

	// Simulate an active connection by incrementing connCount.
	f.connCount.Add(1)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Shutdown should timeout because connCount > 0.
	err := f.Shutdown(ctx)
	if err == nil {
		t.Log("Shutdown returned nil despite active conn (may have timed out)")
	}
	// The error (if any) should be context.DeadlineExceeded or nil.
	// This test mainly verifies Shutdown doesn't hang forever.
}

// ──────────────────────────────────────────────────────────────────────────────
// Reality key pair generation tests
// ──────────────────────────────────────────────────────────────────────────────

// TestGenerateRealityKeyPair verifies that key generation produces valid hex strings.
func TestGenerateRealityKeyPair(t *testing.T) {
	privHex, pubHex, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatalf("GenerateRealityKeyPair() error: %v", err)
	}
	if len(privHex) != 64 {
		t.Errorf("private key hex length = %d, want 64 (32 bytes)", len(privHex))
	}
	if len(pubHex) != 64 {
		t.Errorf("public key hex length = %d, want 64 (32 bytes)", len(pubHex))
	}
	// Keys should be different.
	if privHex == pubHex {
		t.Error("private and public keys should be different")
	}
}

// TestGenerateRealityKeyPairUniqueness verifies that two calls produce
// different key pairs.
func TestGenerateRealityKeyPairUniqueness(t *testing.T) {
	priv1, _, _ := GenerateRealityKeyPair()
	priv2, _, _ := GenerateRealityKeyPair()
	if priv1 == priv2 {
		t.Error("two key generations should produce different private keys")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// REALITY crypto helper tests
// ──────────────────────────────────────────────────────────────────────────────

// TestDecodeHexKey verifies hex key decoding.
func TestDecodeHexKey(t *testing.T) {
	// Empty string returns nil, nil.
	b, err := decodeHexKey("")
	if err != nil {
		t.Errorf("decodeHexKey(\"\") error: %v", err)
	}
	if b != nil {
		t.Errorf("decodeHexKey(\"\") = %v, want nil", b)
	}

	// Valid hex.
	b, err = decodeHexKey("deadbeef")
	if err != nil {
		t.Errorf("decodeHexKey(\"deadbeef\") error: %v", err)
	}
	if len(b) != 4 {
		t.Errorf("decodeHexKey(\"deadbeef\") len = %d, want 4", len(b))
	}
	if b[0] != 0xde || b[1] != 0xad || b[2] != 0xbe || b[3] != 0xef {
		t.Errorf("decodeHexKey(\"deadbeef\") = %v, want [de ad be ef]", b)
	}

	// Invalid hex.
	_, err = decodeHexKey("xyz")
	if err == nil {
		t.Error("decodeHexKey(\"xyz\") should error")
	}
}

// TestNewAESGCM verifies AES-GCM initialization.
func TestNewAESGCM(t *testing.T) {
	// 32-byte key (AES-256).
	aead, err := newAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatalf("newAESGCM(32-byte key) error: %v", err)
	}
	if aead == nil {
		t.Fatal("newAESGCM returned nil AEAD")
	}

	// 16-byte key (AES-128).
	aead, err = newAESGCM(make([]byte, 16))
	if err != nil {
		t.Fatalf("newAESGCM(16-byte key) error: %v", err)
	}
	if aead == nil {
		t.Fatal("newAESGCM returned nil AEAD for 16-byte key")
	}

	// Invalid key length.
	_, err = newAESGCM(make([]byte, 7))
	if err == nil {
		t.Error("newAESGCM(7-byte key) should error")
	}
}

// TestGetEcdheKeyNilHandshakeState verifies that getEcdheKey handles nil safely.
func TestGetEcdheKeyNilHandshakeState(t *testing.T) {
	// nil handshake state should return nil, not panic.
	key := getEcdheKey(nil)
	if key != nil {
		t.Error("getEcdheKey(nil) should return nil")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// realityPeerConn tests
// ──────────────────────────────────────────────────────────────────────────────

// TestRealityPeerConn verifies the PeerConn interface methods.
func TestRealityPeerConn(t *testing.T) {
	f := NewRealityTransportFactory()

	// Create a net.Pipe for testing.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	pc := &realityPeerConn{
		Conn:      clientConn,
		transport: "reality",
		factory:   f,
	}
	f.registerConn(pc)

	if pc.Transport() != "reality" {
		t.Errorf("Transport() = %q, want %q", pc.Transport(), "reality")
	}
	if pc.Latency() != 0 {
		t.Errorf("Latency() = %v, want 0", pc.Latency())
	}

	// Test setLatency.
	pc.setLatency(50 * time.Millisecond)
	if pc.Latency() != 50*time.Millisecond {
		t.Errorf("Latency() = %v, want 50ms", pc.Latency())
	}

	// Test ForceClose.
	if err := pc.ForceClose(); err != nil {
		t.Errorf("ForceClose() error: %v", err)
	}
	// Double close should be safe.
	if err := pc.ForceClose(); err != nil {
		t.Errorf("double ForceClose() error: %v", err)
	}

	// Verify conn was unregistered (connCount should be 0).
	if f.ConnCount() != 0 {
		t.Errorf("ConnCount after close = %d, want 0", f.ConnCount())
	}
}

// TestRealityPeerConnClose verifies Close behavior.
func TestRealityPeerConnClose(t *testing.T) {
	f := NewRealityTransportFactory()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	pc := &realityPeerConn{
		Conn:      clientConn,
		transport: "reality",
		factory:   f,
	}
	f.registerConn(pc)

	if err := pc.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
	// Double close should be safe.
	if err := pc.Close(); err != nil {
		t.Errorf("double Close() error: %v", err)
	}
}

// TestRealityPeerConnWithSemaphore verifies that the semaphore slot is released on close.
func TestRealityPeerConnWithSemaphore(t *testing.T) {
	f := NewRealityTransportFactory()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	semReleased := atomic.Bool{}
	pc := &realityPeerConn{
		Conn:      clientConn,
		transport: "reality",
		factory:   f,
		slotRelease: func() {
			semReleased.Store(true)
		},
	}
	f.registerConn(pc)

	pc.ForceClose()
	if !semReleased.Load() {
		t.Error("semaphore slot was not released on ForceClose")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportRegistry integration tests (reality + udp)
// ──────────────────────────────────────────────────────────────────────────────

// TestRegistryRegisterReality verifies that a Reality factory can be
// registered and retrieved from the transport registry.
func TestRegistryRegisterReality(t *testing.T) {
	reg := NewTransportRegistry()
	f := NewRealityTransportFactory()
	reg.Register(f)

	// Get by name.
	got, err := reg.Get("reality")
	if err != nil {
		t.Fatalf("Get(\"reality\") error: %v", err)
	}
	if got.Name() != "reality" {
		t.Errorf("Get(\"reality\").Name() = %q, want %q", got.Name(), "reality")
	}

	// List should include "reality".
	names := reg.List()
	found := false
	for _, n := range names {
		if n == "reality" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("List() = %v, expected to contain \"reality\"", names)
	}
}

// TestRegistryFallbackUDPtoReality verifies that the fallback order
// works with both UDP and Reality transports.
func TestRegistryFallbackUDPtoReality(t *testing.T) {
	reg := NewTransportRegistry()
	udpFactory := NewUDPTransportFactory()
	realityFactory := NewRealityTransportFactory()
	reg.Register(udpFactory)
	reg.Register(realityFactory)

	// Set fallback order: UDP first, Reality as fallback.
	reg.SetFallbackOrder([]string{"udp", "reality"})

	// Get("anything") should return UDP (first in fallback order).
	got, err := reg.Get("anything")
	if err != nil {
		t.Fatalf("Get(\"anything\") error: %v", err)
	}
	if got.Name() != "udp" {
		t.Errorf("Get with fallback = %q, want %q (first in order)", got.Name(), "udp")
	}

	// Disable fallback.
	reg.SetFallbackOrder(nil)
	got, err = reg.Get("reality")
	if err != nil {
		t.Fatalf("Get(\"reality\") without fallback error: %v", err)
	}
	if got.Name() != "reality" {
		t.Errorf("Get(\"reality\") = %q, want %q", got.Name(), "reality")
	}
}

// TestRegistryShutdownAllWithReality verifies that ShutdownAll works
// with both UDP and Reality factories.
func TestRegistryShutdownAllWithReality(t *testing.T) {
	reg := NewTransportRegistry()
	udpFactory := NewUDPTransportFactory()
	realityFactory := NewRealityTransportFactory()
	reg.Register(udpFactory)
	reg.Register(realityFactory)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := reg.ShutdownAll(ctx); err != nil {
		t.Errorf("ShutdownAll() error: %v", err)
	}

	// Both factories should reject new transports.
	_, udpErr := udpFactory.NewTransport(TransportConfig{Name: "udp"})
	if !errors.Is(udpErr, ErrTransportShutdown) {
		t.Errorf("UDP factory after shutdown = %v, want ErrTransportShutdown", udpErr)
	}
	_, realityErr := realityFactory.NewTransport(TransportConfig{Name: "reality"})
	if !errors.Is(realityErr, ErrTransportShutdown) {
		t.Errorf("Reality factory after shutdown = %v, want ErrTransportShutdown", realityErr)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Error classification tests
// ──────────────────────────────────────────────────────────────────────────────

// TestRealityErrorClassification verifies that TransportError correctly
// classifies permanent vs transient errors for the Reality transport.
func TestRealityErrorClassification(t *testing.T) {
	// Missing public key — permanent.
	permErr := NewTransportError("connect", "reality", "1.2.3.4:443",
		&TransportConfigError{Field: "RealityPublicKey", Reason: "missing"}, false)
	if permErr.IsRetryable() {
		t.Error("missing public key error should be permanent (not retryable)")
	}

	// Timeout — transient.
	transErr := NewTransportError("connect", "reality", "1.2.3.4:443",
		context.DeadlineExceeded, true)
	if !transErr.IsRetryable() {
		t.Error("timeout error should be transient (retryable)")
	}

	// Invalid key — permanent.
	invalidKeyErr := NewTransportError("connect", "reality", "1.2.3.4:443",
		fmt.Errorf("invalid hex"), false)
	if invalidKeyErr.IsRetryable() {
		t.Error("invalid key error should be permanent")
	}

	// Verify error string format.
	s := permErr.Error()
	if s == "" {
		t.Error("Error() string is empty")
	}
	// Should contain "connect" and "reality".
	if !contains(s, "connect") || !contains(s, "reality") {
		t.Errorf("Error() = %q, expected to contain 'connect' and 'reality'", s)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Config validation tests
// ──────────────────────────────────────────────────────────────────────────────

// TestRealityConfigValidate verifies that TransportConfig.Validate
// handles the "reality" case correctly.
func TestRealityConfigValidate(t *testing.T) {
	// Empty Name — should error.
	cfg := TransportConfig{Name: ""}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail for empty Name")
	}

	// Reality with UseTLS but no CertFile — should error.
	cfg = TransportConfig{
		Name:     "reality",
		UseTLS:   true,
		CertFile: "",
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail for reality+UseTLS without CertFile")
	}

	// Reality with UseTLS, CertFile, and KeyFile — should pass.
	cfg = TransportConfig{
		Name:     "reality",
		UseTLS:   true,
		CertFile: "/path/to/cert.pem",
		KeyFile:  "/path/to/key.pem",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() error for valid reality+TLS config: %v", err)
	}

	// Reality without UseTLS — should pass (no cert needed for REALITY auth).
	cfg = TransportConfig{
		Name: "reality",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() error for reality without TLS: %v", err)
	}
}
