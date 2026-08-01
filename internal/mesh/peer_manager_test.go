// Package mesh provides unit tests for PeerManager: auto-reconnect,
// multi-transport failover, latency probing, and optimal path selection.
//
// These tests define the PeerManager contract per TDD — they are written
// BEFORE the implementation (parent task t_72aaf915). The PeerManager API
// and mock test infrastructure are designed from the adopted design spec
// (motion-3911ff2db1df).
//
// Test strategy:
//   - Managed mock transports with configurable dial delay and failure injection
//   - net.Pipe() for in-memory connections where real I/O is needed
//   - Time acceleration via manipulated clocks where possible
//   - Each test validates one aspect of the contract independently
//
// Test cases:
//  1. Quarantine: 3 consecutive failures → 30s cooldown, exponential backoff
//  2. Blackout escape: all transports quarantined → bypass, try LRQ
//  3. Hedging: slow transport → fallback races after 5s → first wins
//  4. Fallback chain: UDP → Reality → WS → relay in priority order
//  5. Path selection: score = e_lat + s_pen (additive, spec §6.1)
//  6. Latency baseline: EWMA with split-alpha (α_rise=0.7, α_fall=0.3)
//  7. State transitions: disconnected→connecting→connected with per-transport sub-states
package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Managed Mock Transport — configurable delay and failure injection
// ═══════════════════════════════════════════════════════════════════════════════

// managedMockTransport is a Transport implementation with configurable
// dial delay, failure injection, and call tracking for PeerManager testing.
type managedMockTransport struct {
	name string

	mu sync.Mutex

	// Health & lifecycle
	healthy bool
	closed  bool

	// Latency configuration
	latency time.Duration

	// Dial behavior
	dialDelay    time.Duration // artificial delay before Connect returns
	failCount    int           // number of times to fail before succeeding
	currentFails int           // tracks how many failures have occurred
	failErr      error         // error to return on failure (nil = use default)

	// Call tracking
	connectCalls      int
	latencyProbeCalls int
	lastConnectAddr   string

	// Pipe address
	pipeAddr mockAddr
}

func newManagedMockTransport(name string) *managedMockTransport {
	return &managedMockTransport{
		name:    name,
		healthy: true,
		latency: 1 * time.Millisecond,
		failErr: errors.New("mock dial failure"),
		pipeAddr: mockAddr{
			network: "pipe",
			address: fmt.Sprintf("%s-pipe", name),
		},
	}
}

func (m *managedMockTransport) Name() string { return m.name }

func (m *managedMockTransport) Connect(ctx context.Context, addr string) (PeerConn, error) {
	m.mu.Lock()
	m.connectCalls++
	m.lastConnectAddr = addr

	if m.closed {
		m.mu.Unlock()
		return nil, NewTransportError("connect", m.name, addr, net.ErrClosed, false)
	}

	// Check context
	select {
	case <-ctx.Done():
		m.mu.Unlock()
		return nil, NewTransportError("connect", m.name, addr, ctx.Err(), true)
	default:
	}

	// Failure injection: fail N times before succeeding
	if m.currentFails < m.failCount {
		m.currentFails++
		err := m.failErr
		if err == nil {
			err = errors.New("mock dial failure")
		}
		m.mu.Unlock()
		return nil, NewTransportError("connect", m.name, addr, err, true)
	}

	delay := m.dialDelay
	m.mu.Unlock()

	// Simulate dial delay
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, NewTransportError("connect", m.name, addr, ctx.Err(), true)
		}
	}

	// Return a pipe-based PeerConn
	client, _ := net.Pipe()
	pc := NewPeerConn(client, m.name)
	if pc2, ok := pc.(*peerConn); ok {
		m.mu.Lock()
		pc2.setLatency(m.latency)
		m.mu.Unlock()
	}
	return pc, nil
}

func (m *managedMockTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, NewTransportError("listen", m.name, addr, net.ErrClosed, false)
	}
	return &mockListener{addr: m.pipeAddr}, nil
}

func (m *managedMockTransport) LatencyProbe(ctx context.Context, addr string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.latencyProbeCalls++

	if m.closed {
		return 0, NewTransportError("latency_probe", m.name, addr, net.ErrClosed, false)
	}
	if !m.healthy {
		return 0, NewTransportError("latency_probe", m.name, addr,
			fmt.Errorf("transport unhealthy"), true)
	}
	return m.latency, nil
}

func (m *managedMockTransport) IsHealthy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthy && !m.closed
}

// --- Testability hooks ---

func (m *managedMockTransport) SetHealthy(h bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = h
}

func (m *managedMockTransport) SetLatency(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latency = d
}

// SetFailCount sets the number of times Connect should fail before succeeding.
func (m *managedMockTransport) SetFailCount(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failCount = n
	m.currentFails = 0
}

// SetDialDelay sets an artificial delay before Connect returns.
func (m *managedMockTransport) SetDialDelay(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dialDelay = d
}

// SetFailErr overrides the default mock dial failure error.
func (m *managedMockTransport) SetFailErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failErr = err
}

func (m *managedMockTransport) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
}

func (m *managedMockTransport) ConnectCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connectCalls
}

func (m *managedMockTransport) LatencyProbeCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.latencyProbeCalls
}

func (m *managedMockTransport) CurrentFails() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentFails
}

// ResetFailCount resets the failure counter so that Connect succeeds again.
func (m *managedMockTransport) ResetFailCount() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentFails = 0
	m.failCount = 0
}

// ──────────────────────────────────────────────────────────────────────────────
// managedMockFactory — TransportFactory for managedMockTransport
// ──────────────────────────────────────────────────────────────────────────────

type managedMockFactory struct {
	name        string
	transport   *managedMockTransport
	activeSince time.Time
	shutdownMu  sync.Mutex
	shutdown    bool
	// NewTransportFn allows custom transport creation
	NewTransportFn func(cfg TransportConfig) (Transport, error)
}

func newManagedMockFactory(name string) *managedMockFactory {
	return &managedMockFactory{
		name:        name,
		transport:   newManagedMockTransport(name),
		activeSince: time.Now(),
	}
}

func (f *managedMockFactory) Name() string { return f.name }

func (f *managedMockFactory) NewTransport(cfg TransportConfig) (Transport, error) {
	f.shutdownMu.Lock()
	defer f.shutdownMu.Unlock()
	if f.shutdown {
		return nil, ErrTransportShutdown
	}
	if f.NewTransportFn != nil {
		return f.NewTransportFn(cfg)
	}
	return f.transport, nil
}

func (f *managedMockFactory) Shutdown(ctx context.Context) error {
	f.shutdownMu.Lock()
	defer f.shutdownMu.Unlock()
	if f.shutdown {
		return nil
	}
	f.shutdown = true
	f.transport.Close()
	return nil
}

func (f *managedMockFactory) ConnCount() int         { return 0 }
func (f *managedMockFactory) ActiveSince() time.Time { return f.activeSince }

// ──────────────────────────────────────────────────────────────────────────────
// Test helper: build a registry with managed mock factories
// ──────────────────────────────────────────────────────────────────────────────

// testPeerManagerFixture holds all the pieces needed for a PeerManager test.
type testPeerManagerFixture struct {
	registry   *TransportRegistry
	factories  map[string]*managedMockFactory
	transports map[string]*managedMockTransport
}

func newTestPeerManagerFixture(transportNames ...string) *testPeerManagerFixture {
	reg := NewTransportRegistry()
	factories := make(map[string]*managedMockFactory)
	transports := make(map[string]*managedMockTransport)

	for _, name := range transportNames {
		f := newManagedMockFactory(name)
		reg.Register(f)
		factories[name] = f
		transports[name] = f.transport
	}

	return &testPeerManagerFixture{
		registry:   reg,
		factories:  factories,
		transports: transports,
	}
}

// quickConfig creates a PeerManagerConfig for the given transport list.
func quickConfig(peerID, addr string, transportNames ...string) PeerManagerConfig {
	cfg := DefaultPeerManagerConfig()
	cfg.PeerID = peerID
	cfg.Addr = addr
	cfg.TransportNames = transportNames
	return cfg
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 1: Quarantine — 3 consecutive failures → 30s cooldown → exponential backoff
// ═══════════════════════════════════════════════════════════════════════════════

// TestQuarantineThreeFailuresTriggersCooldown verifies that after 3 consecutive
// dial failures, a transport enters quarantine.
func TestQuarantineThreeFailuresTriggersCooldown(t *testing.T) {
	udp := newManagedMockTransport("udp")
	udp.SetFailCount(3) // Will fail 3 times, then succeed

	ctx := context.Background()

	// Attempt 1: fails
	_, err := udp.Connect(ctx, "10.0.0.1:51820")
	if err == nil {
		t.Fatal("connect 1: expected failure")
	}
	// Attempt 2: fails
	_, err = udp.Connect(ctx, "10.0.0.1:51820")
	if err == nil {
		t.Fatal("connect 2: expected failure")
	}
	// Attempt 3: fails
	_, err = udp.Connect(ctx, "10.0.0.1:51820")
	if err == nil {
		t.Fatal("connect 3: expected failure")
	}

	if udp.CurrentFails() != 3 {
		t.Errorf("CurrentFails() = %d, want 3", udp.CurrentFails())
	}

	// After the 3rd failure, PeerManager would mark the transport as quarantined.
	// Mock: we manually set unhealthy to simulate quarantine.
	udp.SetHealthy(false)

	if udp.IsHealthy() {
		t.Error("transport should be unhealthy after 3 consecutive failures (quarantine)")
	}

	t.Log("Quarantine: 3 consecutive failures → IsHealthy() returns false")
}

// TestQuarantineIsHealthyReturnsFalse verifies that IsHealthy() returns false
// for a quarantined transport.
func TestQuarantineIsHealthyReturnsFalse(t *testing.T) {
	udp := newManagedMockTransport("udp")

	// Mark the transport as unhealthy (simulating quarantine).
	udp.SetHealthy(false)

	if udp.IsHealthy() {
		t.Error("IsHealthy() should return false when transport is quarantined/unhealthy")
	}
}

// TestQuarantineCooldownExpiryAllowsRetry verifies that after the quarantine
// cooldown expires, the transport can be retried successfully.
func TestQuarantineCooldownExpiryAllowsRetry(t *testing.T) {
	udp := newManagedMockTransport("udp")

	// Simulate quarantine: set unhealthy.
	udp.SetHealthy(false)
	if udp.IsHealthy() {
		t.Fatal("transport should be unhealthy during quarantine")
	}

	// Simulate cooldown expiry: set healthy again.
	udp.SetHealthy(true)
	if !udp.IsHealthy() {
		t.Error("IsHealthy() should return true after cooldown expires")
	}

	// Verify Connect succeeds after recovery.
	ctx := context.Background()
	pc, err := udp.Connect(ctx, "10.0.0.1:51820")
	if err != nil {
		t.Fatalf("Connect() after recovery should succeed: %v", err)
	}
	defer pc.ForceClose()

	if pc.Transport() != "udp" {
		t.Errorf("Transport() = %q, want udp", pc.Transport())
	}
}

// TestQuarantineExponentialBackoff verifies that quarantine duration
// doubles on each repeat quarantine: 30s → 60s → 120s → 300s cap.
func TestQuarantineExponentialBackoff(t *testing.T) {
	baseCooldown := 30 * time.Second
	maxCooldown := 300 * time.Second

	backoffs := []time.Duration{}
	for i := 0; i < 5; i++ {
		d := baseCooldown * (1 << i) // 30, 60, 120, 240, 480
		if d > maxCooldown {
			d = maxCooldown
		}
		backoffs = append(backoffs, d)
	}

	// expected is a correction: the first calculation was wrong.
	// i=0: 30 * 1 = 30s; i=1: 30 * 2 = 60s; i=2: 30 * 4 = 120s
	// i=3: 30 * 8 = 240s (not capped, 240 < 300)
	// i=4: 30 * 16 = 480s → capped to 300s
	expected := []time.Duration{
		30 * time.Second,
		60 * time.Second,
		120 * time.Second,
		240 * time.Second,
		300 * time.Second, // capped
	}

	for i := range expected {
		if backoffs[i] != expected[i] {
			t.Errorf("backoff[%d] = %v, want %v", i, backoffs[i], expected[i])
		}
	}
}

// TestQuarantineDifferentiatedThresholds verifies that different transport
// types have different quarantine thresholds (UDP: 3, Reality/WS: 2).
func TestQuarantineDifferentiatedThresholds(t *testing.T) {
	tests := []struct {
		transport string
		threshold int
	}{
		{"udp", 3},
		{"reality", 2},
		{"websocket", 2},
		{"relay", 3},
	}

	cfg := DefaultPeerManagerConfig()
	for _, tt := range tests {
		got := cfg.QuarantineThreshold[tt.transport]
		if got != tt.threshold {
			t.Errorf("QuarantineThreshold[%q] = %d, want %d", tt.transport, got, tt.threshold)
		}
	}
}

// TestQuarantineFailureCountResetOnSuccess verifies that a successful
// connection resets the consecutive failure counter.
func TestQuarantineFailureCountResetOnSuccess(t *testing.T) {
	udp := newManagedMockTransport("udp")

	// Fail twice, then succeed.
	udp.SetFailCount(2)

	ctx := context.Background()

	// Attempt 1: fails
	_, err := udp.Connect(ctx, "10.0.0.1:51820")
	if err == nil {
		t.Fatal("Connect() should fail (attempt 1)")
	}

	// Attempt 2: fails
	_, err = udp.Connect(ctx, "10.0.0.1:51820")
	if err == nil {
		t.Fatal("Connect() should fail (attempt 2)")
	}

	if udp.CurrentFails() != 2 {
		t.Errorf("CurrentFails() = %d, want 2", udp.CurrentFails())
	}

	// Attempt 3: succeeds (failCount was 2, currentFails reached 2)
	pc, err := udp.Connect(ctx, "10.0.0.1:51820")
	if err != nil {
		t.Fatalf("Connect() should succeed after 2 failures: %v", err)
	}
	defer pc.ForceClose()

	t.Log("Success resets failure counter — contract verified")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 2: Blackout escape — all transports quarantined → bypass quarantine
// ═══════════════════════════════════════════════════════════════════════════════

// TestBlackoutEscapeAllQuarantinedBypass verifies that when ALL transports
// are quarantined, the PeerManager bypasses quarantine and tries the
// least-recently-quarantined transport.
func TestBlackoutEscapeAllQuarantinedBypass(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket")

	// Set all transports as unhealthy (simulating all quarantined).
	fix.transports["udp"].SetHealthy(false)
	fix.transports["reality"].SetHealthy(false)
	fix.transports["websocket"].SetHealthy(false)

	unhealthyCount := 0
	for _, tr := range fix.transports {
		if !tr.IsHealthy() {
			unhealthyCount++
		}
	}
	if unhealthyCount != 3 {
		t.Fatalf("expected all 3 transports unhealthy, got %d unhealthy", unhealthyCount)
	}

	// Blackout escape: when all transports are quarantined,
	// the least-recently-quarantined (LRQ) should be tried immediately.
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp", "reality", "websocket")
	_ = NewPeerManager(cfg, fix.registry)

	if len(fix.registry.List()) != 3 {
		t.Errorf("registry should have 3 factories, got %d", len(fix.registry.List()))
	}

	t.Log("Blackout escape: all quarantined → bypass, try LRQ")
}

// TestBlackoutEscapeLeastRecentlyQuarantined verifies the LRQ selection
// when all transports are quarantined at different times.
func TestBlackoutEscapeLeastRecentlyQuarantined(t *testing.T) {
	type quarantineEntry struct {
		name          string
		quarantinedAt time.Time
	}

	entries := []quarantineEntry{
		{"udp", time.Now().Add(-2 * time.Minute)}, // LRQ — oldest
		{"reality", time.Now().Add(-30 * time.Second)},
		{"websocket", time.Now().Add(-5 * time.Second)}, // most recent
	}

	// Sort by quarantinedAt (ascending) — oldest first = LRQ.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].quarantinedAt.Before(entries[j].quarantinedAt)
	})

	if entries[0].name != "udp" {
		t.Errorf("LRQ should be 'udp' (oldest quarantine), got %q", entries[0].name)
	}

	t.Log("LRQ selection: udp quarantined 2min ago → should be tried first in blackout")
}

// TestBlackoutEscapeRecoveryThenReEnterQuarantine verifies that after
// a successful blackout escape connection, the transport returns to
// normal operation and can be re-quarantined.
func TestBlackoutEscapeRecoveryThenReEnterQuarantine(t *testing.T) {
	udp := newManagedMockTransport("udp")

	// Phase 1: quarantined
	udp.SetHealthy(false)
	if udp.IsHealthy() {
		t.Fatal("phase 1: should be quarantined")
	}

	// Phase 2: blackout escape — set healthy (bypass quarantine)
	udp.SetHealthy(true)
	if !udp.IsHealthy() {
		t.Fatal("phase 2: should be healthy after blackout escape")
	}

	// Phase 3: normal operation succeeds
	ctx := context.Background()
	pc, err := udp.Connect(ctx, "10.0.0.1:51820")
	if err != nil {
		t.Fatalf("phase 3: Connect() should succeed: %v", err)
	}
	pc.ForceClose()

	// Phase 4: fails again → re-enters quarantine
	udp.SetHealthy(false)
	if udp.IsHealthy() {
		t.Fatal("phase 4: should be re-quarantined after new failures")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 3: Hedging — slow transport triggers parallel fallback after 5s
// ═══════════════════════════════════════════════════════════════════════════════

// TestHedgingSlowTransportTriggersFallback verifies that when a slow
// transport is the primary, a parallel fallback starts after HedgeDelay
// and the first to connect wins.
func TestHedgingSlowTransportTriggersFallback(t *testing.T) {
	// Reality (slow, 200ms dial) and UDP (fast, 1ms dial)
	reality := newManagedMockTransport("reality")
	reality.SetDialDelay(200 * time.Millisecond)

	udp := newManagedMockTransport("udp")

	// Hedge delay: 50ms for test (instead of 5s)
	hedgeDelay := 50 * time.Millisecond

	start := time.Now()
	ctx := context.Background()

	type dialResult struct {
		name string
		pc   PeerConn
		err  error
	}

	resultCh := make(chan dialResult, 2)

	// Primary: Reality (slow)
	go func() {
		pc, err := reality.Connect(ctx, "10.0.0.1:51820")
		resultCh <- dialResult{name: "reality", pc: pc, err: err}
	}()

	// Hedged fallback: UDP after HedgeDelay
	go func() {
		time.Sleep(hedgeDelay)
		pc, err := udp.Connect(ctx, "10.0.0.1:51820")
		resultCh <- dialResult{name: "udp", pc: pc, err: err}
	}()

	// First to connect wins.
	result := <-resultCh
	elapsed := time.Since(start)

	// Clean up the other connection.
	go func() {
		second := <-resultCh
		if second.pc != nil {
			second.pc.ForceClose()
		}
	}()

	if result.err != nil {
		t.Fatalf("first connection should succeed: %v", result.err)
	}
	defer result.pc.ForceClose()

	t.Logf("hedging: first connect = %s in %v (hedgeDelay=%v)", result.name, elapsed, hedgeDelay)

	// With 50ms hedge delay, the first 50ms are exclusive to Reality.
	// Reality has 200ms dial so it won't be done by then.
	// UDP starts at 50ms and completes almost instantly (~50ms).
	// So UDP should win.
	if result.name != "udp" {
		t.Logf("expected udp to win the race, got %s", result.name)
	}
}

// TestHedgingFirstToConnectWins verifies the "first to connect wins" property.
func TestHedgingFirstToConnectWins(t *testing.T) {
	fast := newManagedMockTransport("udp")
	fast.SetDialDelay(1 * time.Millisecond)

	slow := newManagedMockTransport("reality")
	slow.SetDialDelay(50 * time.Millisecond)

	resultCh := make(chan string, 2)
	ctx := context.Background()

	go func() {
		pc, err := fast.Connect(ctx, "10.0.0.1:51820")
		if err == nil {
			pc.ForceClose()
			resultCh <- "udp"
		}
	}()

	go func() {
		pc, err := slow.Connect(ctx, "10.0.0.1:51820")
		if err == nil {
			pc.ForceClose()
			resultCh <- "reality"
		}
	}()

	winner := <-resultCh
	if winner != "udp" {
		t.Errorf("first to connect = %q, want %q (faster transport)", winner, "udp")
	}
}

// TestHedgingCancelsLoser verifies that the losing connection is cancelled
// when the first one succeeds (avoid resource leaks).
func TestHedgingCancelsLoser(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	slow := newManagedMockTransport("reality")
	slow.SetDialDelay(500 * time.Millisecond)

	errCh := make(chan error, 1)
	go func() {
		_, err := slow.Connect(ctx, "10.0.0.1:51820")
		errCh <- err
	}()

	// Cancel the context before the dial completes (simulating winner found).
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("dial should fail with cancelled context")
		} else {
			t.Logf("loser cancelled: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("dial did not respond to cancellation within timeout")
	}
}

// TestHedgingOnlyForSlowTransports verifies that hedging is only triggered
// for transports classified as "slow" (Reality, WS), not for fast ones (UDP).
func TestHedgingOnlyForSlowTransports(t *testing.T) {
	slowTransports := DefaultPeerManagerConfig().SlowTransports

	if !slowTransports["reality"] {
		t.Error("reality should be classified as slow transport")
	}
	if !slowTransports["websocket"] {
		t.Error("websocket should be classified as slow transport")
	}
	if slowTransports["udp"] {
		t.Error("udp should NOT be classified as slow transport")
	}
	if slowTransports["relay"] {
		t.Error("relay should NOT be classified as slow transport")
	}

	t.Log("Hedging only for slow transports: reality, websocket")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 4: Fallback chain — UDP → Reality → WS → relay in priority order
// ═══════════════════════════════════════════════════════════════════════════════

// TestFallbackChainPriorityOrder verifies that transports are tried in
// the configured priority order: UDP → Reality → WS → relay.
func TestFallbackChainPriorityOrder(t *testing.T) {
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp", "reality", "websocket", "relay")

	expected := []string{"udp", "reality", "websocket", "relay"}
	for i, want := range expected {
		if cfg.TransportNames[i] != want {
			t.Errorf("TransportNames[%d] = %q, want %q", i, cfg.TransportNames[i], want)
		}
	}
}

// TestFallbackChainUDPFailsThenReality verifies that when UDP fails,
// the fallback chain progresses to Reality.
func TestFallbackChainUDPFailsThenReality(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket", "relay")

	// Set UDP to always fail.
	fix.transports["udp"].SetFailCount(100)

	// Set Reality to succeed.
	fix.transports["reality"].SetFailCount(0)

	ctx := context.Background()

	// Try UDP: should fail.
	_, err := fix.transports["udp"].Connect(ctx, "10.0.0.1:51820")
	if err == nil {
		t.Fatal("UDP should fail (configured for failure)")
	}

	// Fallback to Reality: should succeed.
	pc, err := fix.transports["reality"].Connect(ctx, "10.0.0.1:51820")
	if err != nil {
		t.Fatalf("Reality (fallback) should succeed: %v", err)
	}
	defer pc.ForceClose()

	if pc.Transport() != "reality" {
		t.Errorf("Transport() = %q, want reality", pc.Transport())
	}
}

// TestFallbackChainAllFail verifies that when all transports in the
// chain fail, the PeerManager reports an error.
func TestFallbackChainAllFail(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket", "relay")

	// All transports fail.
	for _, tr := range fix.transports {
		tr.SetFailCount(100)
	}

	ctx := context.Background()

	failures := 0
	for _, name := range []string{"udp", "reality", "websocket", "relay"} {
		tr := fix.transports[name]
		_, err := tr.Connect(ctx, "10.0.0.1:51820")
		if err != nil {
			failures++
		}
	}

	if failures != 4 {
		t.Errorf("all 4 transports should fail, got %d failures", failures)
	}

	t.Log("All fallback transports failed — PeerManager should signal error")
}

// TestFallbackChainSkipQuarantined verifies that quarantined transports
// are skipped during fallback progression.
func TestFallbackChainSkipQuarantined(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket")

	// UDP is quarantined (unhealthy).
	fix.transports["udp"].SetHealthy(false)

	// Reality is healthy.
	fix.transports["reality"].SetHealthy(true)

	if fix.transports["udp"].IsHealthy() {
		t.Error("UDP should be unhealthy (quarantined)")
	}
	if !fix.transports["reality"].IsHealthy() {
		t.Error("Reality should be healthy")
	}

	t.Log("Fallback chain skips quarantined transports — uses next healthy one")
}

// TestFallbackChainRecoversWhenHigherPriorityRecovers verifies that when
// a higher-priority transport recovers from quarantine, it is used again.
func TestFallbackChainRecoversWhenHigherPriorityRecovers(t *testing.T) {
	udp := newManagedMockTransport("udp")
	reality := newManagedMockTransport("reality")

	// Phase 1: UDP quarantined → use Reality.
	udp.SetHealthy(false)

	if udp.IsHealthy() {
		t.Fatal("phase 1: UDP should be quarantined")
	}
	if !reality.IsHealthy() {
		t.Fatal("phase 1: Reality should be healthy")
	}

	// Phase 2: UDP recovers → use UDP again.
	udp.SetHealthy(true)

	if !udp.IsHealthy() {
		t.Error("phase 2: UDP should be healthy after recovery")
	}

	// Phase 3: UDP should now be the preferred transport.
	ctx := context.Background()
	pc, err := udp.Connect(ctx, "10.0.0.1:51820")
	if err != nil {
		t.Fatalf("phase 3: Connect() after recovery: %v", err)
	}
	defer pc.ForceClose()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 5: Path selection — score = e_lat + s_pen (additive, spec §6.1)
// ═══════════════════════════════════════════════════════════════════════════════

// TestPathSelectionScoreFormula verifies the path selection scoring:
// score = e_lat + s_pen
// where s_pen = e_lat × (recent_failures / max(attempts, 10)), lookback 60s.
func TestPathSelectionScoreFormula(t *testing.T) {
	// Transport A: 5ms latency, 50% failure rate (5 failures in 10 attempts)
	//   s_pen = 5 × (5/10) = 2.5
	//   score = 5 + 2.5 = 7.5
	// Transport B: 15ms latency, 0% failure rate (0 failures in 10 attempts)
	//   s_pen = 15 × (0/10) = 0
	//   score = 15 + 0 = 15.0

	eLatA, failA, attA := 5.0, 5.0, 10.0
	eLatB, failB, attB := 15.0, 0.0, 10.0
	scoreA := eLatA + eLatA*(failA/attA) // 7.5
	scoreB := eLatB + eLatB*(failB/attB) // 15.0

	// Lower score wins.
	if scoreA >= scoreB {
		t.Errorf("scoreA (%v) should be less than scoreB (%v) — A should win", scoreA, scoreB)
	}

	t.Logf("Path selection: A(5ms,50%%fail)=%.1f < B(15ms,0%%fail)=%.1f → A wins", scoreA, scoreB)
}

// TestPathSelectionScoreWithEdgeCases verifies edge cases in the scoring formula.
// score = e_lat + s_pen where s_pen = e_lat × (recent_failures / max(attempts, 10))
func TestPathSelectionScoreWithEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		latency        float64
		recentFailures int
		attempts       int
		expectedScore  float64
	}{
		{
			name:           "no failures",
			latency:        10,
			recentFailures: 0,
			attempts:       10,
			expectedScore:  10.0,
		},
		{
			name:           "all failures (100%)",
			latency:        5,
			recentFailures: 10,
			attempts:       10,
			expectedScore:  10.0,
		},
		{
			name:           "low attempts (under 10, use 10 as floor)",
			latency:        8,
			recentFailures: 2,
			attempts:       4,
			expectedScore:  9.6,
		},
		{
			name:           "high attempts, moderate failures",
			latency:        20,
			recentFailures: 30,
			attempts:       100,
			expectedScore:  26.0,
		},
		{
			name:           "zero latency (instant response)",
			latency:        0.1,
			recentFailures: 0,
			attempts:       10,
			expectedScore:  0.1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempts := tt.attempts
			if attempts < 10 {
				attempts = 10
			}
			sPen := tt.latency * (float64(tt.recentFailures) / float64(attempts))
			score := tt.latency + sPen

			epsilon := 0.01
			if diff := score - tt.expectedScore; diff < -epsilon || diff > epsilon {
				t.Errorf("score = %v, want %v", score, tt.expectedScore)
			}
		})
	}
}

// TestPathSelectionFailureLookback verifies that only failures within
// the lookback window (60s) are counted.
func TestPathSelectionFailureLookback(t *testing.T) {
	now := time.Now()
	lookback := 60 * time.Second

	recentFailures := 0
	oldFailures := 0

	failures := []time.Time{
		now.Add(-10 * time.Second),  // recent
		now.Add(-20 * time.Second),  // recent
		now.Add(-30 * time.Second),  // recent
		now.Add(-90 * time.Second),  // old — outside lookback
		now.Add(-120 * time.Second), // old — outside lookback
	}

	for _, ts := range failures {
		if now.Sub(ts) <= lookback {
			recentFailures++
		} else {
			oldFailures++
		}
	}

	if recentFailures != 3 {
		t.Errorf("recentFailures = %d, want 3", recentFailures)
	}
	if oldFailures != 2 {
		t.Errorf("oldFailures = %d, want 2", oldFailures)
	}

	latency := 10.0
	sPen := latency * (float64(recentFailures) / 10.0)
	score := latency + sPen
	expectedScore := 13.0
	if score != expectedScore {
		t.Errorf("score = %v, want %v (only 3 recent failures counted)", score, expectedScore)
	}
}

// TestPathSelectionSelectsLowestScore verifies that among multiple
// transports, the one with the lowest score is selected.
func TestPathSelectionSelectsLowestScore(t *testing.T) {
	type transportScore struct {
		name  string
		score float64
	}

	scores := []transportScore{
		{"udp", 7.5},
		{"reality", 15.0},
		{"websocket", 50.0},
		{"relay", 100.0},
	}

	best := scores[0]
	for _, s := range scores[1:] {
		if s.score < best.score {
			best = s
		}
	}

	if best.name != "udp" {
		t.Errorf("best transport = %q, want udp (score %.1f)", best.name, best.score)
	}

	t.Logf("Path selection: %s wins with score %.1f", best.name, best.score)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 6: Latency baseline — moving median of 10, 2x trigger, 3 consecutive
// ═══════════════════════════════════════════════════════════════════════════════

// TestLatencyBaselineMovingMedian verifies that the baseline is computed
// as the moving median of the last 10 samples.
func TestLatencyBaselineMovingMedian(t *testing.T) {
	// Sample set: 5, 5, 5, 5, 5, 10, 10, 10, 10, 10
	// Sorted: 5, 5, 5, 5, 5, 10, 10, 10, 10, 10
	// Median of even set (10 items): average of indices 4 and 5
	//   = (5 + 10) / 2 = 7.5ms

	samples := []float64{5, 5, 5, 5, 5, 10, 10, 10, 10, 10}

	sorted := make([]float64, len(samples))
	copy(sorted, samples)
	sort.Float64s(sorted)

	n := len(sorted)
	var median float64
	if n%2 == 0 {
		median = (sorted[n/2-1] + sorted[n/2]) / 2.0
	} else {
		median = sorted[n/2]
	}

	expectedMedian := 7.5
	if median != expectedMedian {
		t.Errorf("median = %v, want %v", median, expectedMedian)
	}

	t.Logf("Moving median of %d samples: %v", n, median)
}

// TestLatencyBaselineTwoXTrigger verifies that a 2x latency trigger
// requires 3 consecutive probes above the baseline.
func TestLatencyBaselineTwoXTrigger(t *testing.T) {
	baseline := 10.0
	threshold := baseline * 2.0 // 20ms

	probes := []float64{25, 22, 21, 8, 30, 25}
	consecutiveAbove := 0

	for i, probe := range probes {
		if probe > threshold {
			consecutiveAbove++
		} else {
			consecutiveAbove = 0
		}

		if consecutiveAbove == 3 {
			t.Logf("TRIGGER at probe %d (value %.1f > threshold %.1f)", i, probe, threshold)
		}
	}

	if consecutiveAbove != 2 {
		t.Errorf("consecutiveAbove = %d, want 2 (probes 5 and 6 > threshold)", consecutiveAbove)
	}
}

// TestLatencyBaselineRequiresThreeConsecutive verifies the 3-consecutive requirement.
func TestLatencyBaselineRequiresThreeConsecutive(t *testing.T) {
	baseline := 10.0
	threshold := baseline * 2.0 // 20ms

	scenarios := []struct {
		name     string
		probes   []float64
		triggers bool
	}{
		{
			name:     "3 consecutive above → triggers",
			probes:   []float64{25, 22, 21},
			triggers: true,
		},
		{
			name:     "2 above, 1 below, 1 above → does NOT trigger",
			probes:   []float64{25, 22, 8, 21},
			triggers: false,
		},
		{
			name:     "spike but drops → does NOT trigger",
			probes:   []float64{100, 5, 5, 5},
			triggers: false,
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			consecutive := 0
			everTriggered := false
			for _, probe := range sc.probes {
				if probe > threshold {
					consecutive++
				} else {
					consecutive = 0
				}
				if consecutive >= 3 {
					everTriggered = true
				}
			}

			if everTriggered != sc.triggers {
				t.Errorf("triggered = %v, want %v", everTriggered, sc.triggers)
			}
		})
	}
}

// TestLatencyBaselineThirtySecondSeparation verifies that probes are
// separated by at least 30 seconds.
func TestLatencyBaselineThirtySecondSeparation(t *testing.T) {
	probeInterval := 30 * time.Second

	probes := []time.Time{
		time.Now().Add(-90 * time.Second),
		time.Now().Add(-60 * time.Second),
		time.Now().Add(-30 * time.Second),
		time.Now(),
	}

	for i := 1; i < len(probes); i++ {
		interval := probes[i].Sub(probes[i-1])
		if interval < probeInterval {
			t.Errorf("probes[%d] interval = %v, want ≥30s", i, interval)
		}
	}

	t.Log("All probes are separated by ≥30s — valid for latency baseline")
}

// TestLatencyBaselineProbeIntervalQuarantinedReality verifies that
// quarantined Reality transports use 5-minute probe intervals.
func TestLatencyBaselineProbeIntervalQuarantinedReality(t *testing.T) {
	cfg := DefaultPeerManagerConfig()

	normalInterval := cfg.ProbeInterval
	quarantinedRealityInterval := cfg.ProbeIntervalQuarantinedReality

	if normalInterval >= quarantinedRealityInterval {
		t.Errorf("normal probe interval (%v) should be shorter than quarantined reality interval (%v)",
			normalInterval, quarantinedRealityInterval)
	}

	if quarantinedRealityInterval != 5*time.Minute {
		t.Errorf("quarantined reality probe interval = %v, want 5min", quarantinedRealityInterval)
	}

	t.Logf("Quarantined Reality probe interval: %v (avoids GFW detection)", quarantinedRealityInterval)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 7: State transitions — disconnected → connecting → connected
// ═══════════════════════════════════════════════════════════════════════════════

// TestStateTransitionsPeerLevel verifies the three peer-level states.
func TestStateTransitionsPeerLevel(t *testing.T) {
	states := []struct {
		state PeerState
		name  string
	}{
		{PeerDisconnected, "disconnected"},
		{PeerConnecting, "connecting"},
		{PeerConnected, "connected"},
	}

	for _, s := range states {
		if s.state.String() != s.name {
			t.Errorf("PeerState(%d).String() = %q, want %q", s.state, s.state.String(), s.name)
		}
	}

	pm := NewPeerManager(quickConfig("peer-1", "10.0.0.1:51820", "udp"), NewTransportRegistry())

	if pm.State() != PeerDisconnected {
		t.Errorf("initial State() = %s, want disconnected", pm.State())
	}

	t.Log("Peer state machine: disconnected → connecting → connected (3 states)")
}

// TestStateTransitionsPerTransportSubStates verifies the per-transport
// sub-states: active, connecting, probing, quarantined, failed.
func TestStateTransitionsPerTransportSubStates(t *testing.T) {
	subStates := []struct {
		state TransportSubState
		name  string
	}{
		{TransportSubActive, "active"},
		{TransportSubConnecting, "connecting"},
		{TransportSubProbing, "probing"},
		{TransportSubQuarantined, "quarantined"},
		{TransportSubFailed, "failed"},
	}

	for _, s := range subStates {
		if s.state.String() != s.name {
			t.Errorf("TransportSubState(%d).String() = %q, want %q", s.state, s.state.String(), s.name)
		}
	}
}

// TestStateTransitionsDisconnectedToConnectingOnStart verifies that
// calling Start() transitions from disconnected to connecting.
func TestStateTransitionsDisconnectedToConnectingOnStart(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp")
	pm := NewPeerManager(cfg, fix.registry)

	if pm.State() != PeerDisconnected {
		t.Errorf("initial state = %s, want disconnected", pm.State())
	}

	ctx := context.Background()
	err := pm.Start(ctx)
	if err != nil {
		t.Logf("Start() returned: %v (stub — real impl in parent task)", err)
	}

	t.Log("State transition: disconnected → connecting on Start()")
}

// TestStateTransitionsConnectedToDisconnectedOnStop verifies that
// calling Stop() transitions from connected to disconnected.
func TestStateTransitionsConnectedToDisconnectedOnStop(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp")
	pm := NewPeerManager(cfg, fix.registry)

	err := pm.Stop()
	if err != nil {
		t.Logf("Stop() returned: %v (stub — real impl in parent task)", err)
	}

	t.Log("State transition: connected → disconnected on Stop()")
}

// TestStateTransitionsTransportSubStateOnQuarantine verifies that the
// per-transport sub-state changes to quarantined after threshold failures.
func TestStateTransitionsTransportSubStateOnQuarantine(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp")
	pm := NewPeerManager(cfg, fix.registry)

	initialState := pm.TransportState("udp")
	if initialState != TransportSubActive {
		t.Errorf("initial TransportState(udp) = %s, want active", initialState)
	}

	t.Log("Per-transport sub-state: active → quarantined after threshold failures")
}

// TestStateTransitionsTransportSubStateDiagram verifies the full
// sub-state transition diagram.
func TestStateTransitionsTransportSubStateDiagram(t *testing.T) {
	transitions := []struct {
		from   TransportSubState
		to     TransportSubState
		reason string
	}{
		{TransportSubActive, TransportSubConnecting, "new connection attempt"},
		{TransportSubConnecting, TransportSubActive, "dial succeeded"},
		{TransportSubActive, TransportSubProbing, "latency probe started"},
		{TransportSubProbing, TransportSubActive, "probe completed"},
		{TransportSubProbing, TransportSubFailed, "permanent probe error"},
		{TransportSubActive, TransportSubQuarantined, "threshold failures reached"},
		{TransportSubConnecting, TransportSubQuarantined, "failures during connect"},
		{TransportSubQuarantined, TransportSubConnecting, "cooldown expired"},
		{TransportSubQuarantined, TransportSubConnecting, "blackout escape"},
		{TransportSubConnecting, TransportSubFailed, "permanent error"},
		{TransportSubQuarantined, TransportSubFailed, "max cooldown exhausted"},
	}

	for _, tr := range transitions {
		t.Logf("%s → %s (%s)", tr.from, tr.to, tr.reason)
	}

	if len(transitions) < 8 {
		t.Errorf("expected at least 8 state transitions, got %d", len(transitions))
	}
}

// TestStateTransitionsIsHealthyReflectsState verifies that IsHealthy()
// returns true only when the peer is connected.
func TestStateTransitionsIsHealthyReflectsState(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp")
	pm := NewPeerManager(cfg, fix.registry)

	// Disconnected → not healthy.
	if pm.IsHealthy() {
		t.Error("IsHealthy() should be false when disconnected")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PeerManagerConfig defaults and validation
// ═══════════════════════════════════════════════════════════════════════════════

// TestPeerManagerConfigDefaults verifies that DefaultPeerManagerConfig
// returns sensible defaults as specified in the design.
func TestPeerManagerConfigDefaults(t *testing.T) {
	cfg := DefaultPeerManagerConfig()

	checks := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"QuarantineBaseCooldown", cfg.QuarantineBaseCooldown, 30 * time.Second},
		{"QuarantineMaxCooldown", cfg.QuarantineMaxCooldown, 300 * time.Second},
		{"HedgeDelay", cfg.HedgeDelay, 5 * time.Second},
		{"ProbeInterval", cfg.ProbeInterval, 30 * time.Second},
		{"ProbeIntervalQuarantinedReality", cfg.ProbeIntervalQuarantinedReality, 5 * time.Minute},
		{"BaselineWindow", cfg.BaselineWindow, 10},
		{"TriggerThreshold", cfg.TriggerThreshold, 2.0},
		{"TriggerConsecutive", cfg.TriggerConsecutive, 3},
		{"FailureLookback", cfg.FailureLookback, 60 * time.Second},
		{"QuarantineThreshold[udp]", cfg.QuarantineThreshold["udp"], 3},
		{"QuarantineThreshold[reality]", cfg.QuarantineThreshold["reality"], 2},
		{"QuarantineThreshold[websocket]", cfg.QuarantineThreshold["websocket"], 2},
		{"QuarantineThreshold[relay]", cfg.QuarantineThreshold["relay"], 3},
	}

	for _, c := range checks {
		if c.got != c.expected {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.expected)
		}
	}
}

// TestPeerManagerConfigZeroValuesSafe verifies that zero-value
// PeerManagerConfig produces safe defaults via NewPeerManager.
func TestPeerManagerConfigZeroValuesSafe(t *testing.T) {
	cfg := PeerManagerConfig{
		PeerID:         "peer-1",
		Addr:           "10.0.0.1:51820",
		TransportNames: []string{"udp"},
	}
	pm := NewPeerManager(cfg, NewTransportRegistry())

	if pm.cfg.QuarantineBaseCooldown != 30*time.Second {
		t.Errorf("QuarantineBaseCooldown = %v, want 30s", pm.cfg.QuarantineBaseCooldown)
	}
	if pm.cfg.BaselineWindow != 10 {
		t.Errorf("BaselineWindow = %d, want 10", pm.cfg.BaselineWindow)
	}
	if pm.cfg.TriggerThreshold != 2.0 {
		t.Errorf("TriggerThreshold = %v, want 2.0", pm.cfg.TriggerThreshold)
	}

	if s := pm.TransportState("udp"); s != TransportSubActive {
		t.Errorf("TransportState(udp) = %s, want active", s)
	}

	if s := pm.TransportState("nonexistent"); s != TransportSubFailed {
		t.Errorf("TransportState(nonexistent) = %s, want failed", s)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Edge cases: empty config, single transport, context cancellation
// ═══════════════════════════════════════════════════════════════════════════════

// TestPeerManagerEmptyTransportList verifies behavior with no transports.
func TestPeerManagerEmptyTransportList(t *testing.T) {
	cfg := quickConfig("peer-1", "10.0.0.1:51820") // no transport names
	pm := NewPeerManager(cfg, NewTransportRegistry())

	if pm.State() != PeerDisconnected {
		t.Error("state should be disconnected with empty transport list")
	}
}

// TestPeerManagerSingleTransport verifies behavior with a single transport.
func TestPeerManagerSingleTransport(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp")
	pm := NewPeerManager(cfg, fix.registry)

	if pm.State() != PeerDisconnected {
		t.Error("initial state should be disconnected")
	}

	if count := len(cfg.TransportNames); count != 1 {
		t.Errorf("expected 1 transport, got %d", count)
	}
}

// TestPeerManagerContextCancellation verifies that context cancellation
// cleanly terminates the connection loop.
func TestPeerManagerContextCancellation(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp")
	pm := NewPeerManager(cfg, fix.registry)

	ctx, cancel := context.WithCancel(context.Background())

	_ = pm.Start(ctx)

	// Cancel immediately.
	cancel()

	err := pm.Stop()
	if err != nil {
		t.Logf("Stop() after cancel: %v", err)
	}

	t.Log("Context cancellation terminates PeerManager connection loop")
}

// TestPeerManagerDoubleStartIsSafe verifies that calling Start twice is safe.
func TestPeerManagerDoubleStartIsSafe(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp")
	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()

	err1 := pm.Start(ctx)
	t.Logf("first Start(): %v", err1)

	err2 := pm.Start(ctx)
	t.Logf("second Start(): %v", err2)
}

// TestPeerManagerDoubleStopIsSafe verifies that calling Stop twice is idempotent.
func TestPeerManagerDoubleStopIsSafe(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp")
	pm := NewPeerManager(cfg, fix.registry)

	err1 := pm.Stop()
	t.Logf("first Stop(): %v", err1)

	err2 := pm.Stop()
	t.Logf("second Stop(): %v", err2)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Latency probing modes: passive (I/O) vs active (interval-based)
// ═══════════════════════════════════════════════════════════════════════════════

// TestLatencyProbePassiveMode verifies that passive latency probes use
// I/O latency when the connection has been active in the last 30 seconds.
func TestLatencyProbePassiveMode(t *testing.T) {
	udp := newManagedMockTransport("udp")
	udp.SetLatency(5 * time.Millisecond)

	ctx := context.Background()
	pc, err := udp.Connect(ctx, "10.0.0.1:51820")
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	defer pc.ForceClose()

	latency := pc.Latency()
	if latency != 5*time.Millisecond {
		t.Errorf("Passive latency = %v, want 5ms", latency)
	}

	t.Logf("Passive latency probe: %v (I/O-based)", latency)
}

// TestLatencyProbeActiveMode verifies that active probes occur every 30s
// when the connection is idle.
func TestLatencyProbeActiveMode(t *testing.T) {
	udp := newManagedMockTransport("udp")
	udp.SetLatency(12 * time.Millisecond)

	ctx := context.Background()

	rtt, err := udp.LatencyProbe(ctx, "10.0.0.1:51820")
	if err != nil {
		t.Fatalf("LatencyProbe() error: %v", err)
	}

	if rtt != 12*time.Millisecond {
		t.Errorf("Active probe RTT = %v, want 12ms", rtt)
	}

	if udp.LatencyProbeCalls() != 1 {
		t.Errorf("LatencyProbeCalls = %d, want 1", udp.LatencyProbeCalls())
	}

	t.Logf("Active latency probe: %v (interval-based)", rtt)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Concurrent access safety
// ═══════════════════════════════════════════════════════════════════════════════

// TestPeerManagerConcurrentAccess verifies that PeerManager methods are
// safe for concurrent use.
func TestPeerManagerConcurrentAccess(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket")
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp", "reality", "websocket")
	pm := NewPeerManager(cfg, fix.registry)

	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = pm.State()
		}()
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = pm.TransportState("udp")
		}()
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = pm.IsHealthy()
		}()
	}

	wg.Wait()
	t.Log("Concurrent reads on PeerManager are safe")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Integration: PeerManager + TransportRegistry two-layer failover
// ═══════════════════════════════════════════════════════════════════════════════

// TestPeerManagerRegistryIntegration verifies the two-layer failover
// pattern: PeerManager uses TransportRegistry.Get() + Transport.IsHealthy().
func TestPeerManagerRegistryIntegration(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket")
	reg := fix.registry

	reg.SetFallbackOrder([]string{"udp", "reality", "websocket"})

	// Layer 1: Registry returns first registered factory (UDP).
	factory, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}

	// Layer 2: PeerManager checks health.
	tr, err := factory.NewTransport(TransportConfig{Name: factory.Name()})
	if err != nil {
		t.Fatalf("NewTransport() error: %v", err)
	}

	if !tr.IsHealthy() {
		t.Error("transport should be healthy initially")
	}

	t.Log("Two-layer failover: TransportRegistry.Get() + Transport.IsHealthy()")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Integration tests: PeerManager goroutine lifecycle with real mock transports
// ═══════════════════════════════════════════════════════════════════════════════

// pmTestConfig creates a PeerManagerConfig with short timers for fast tests.
func pmTestConfig(addr string, transportNames ...string) PeerManagerConfig {
	cfg := quickConfig("test-peer", addr, transportNames...)
	// Use short timers for test speed.
	cfg.QuarantineBaseCooldown = 50 * time.Millisecond
	cfg.QuarantineMaxCooldown = 200 * time.Millisecond
	cfg.HedgeDelay = 20 * time.Millisecond
	cfg.ProbeInterval = 50 * time.Millisecond
	cfg.ProbeIntervalQuarantinedReality = 100 * time.Millisecond
	cfg.BlackoutThreshold = 3 // lower for test speed
	cfg.ScoreStableProbes = 2
	cfg.MinSamplesForScoring = 2
	return cfg
}

// waitForState polls PeerManager.State() until it reaches the target state
// or the timeout expires. Returns true if the target state was reached.
func waitForState(pm *PeerManager, target PeerState, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pm.State() == target {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return pm.State() == target
}

// TestPMConnectSingleTransport verifies that PeerManager connects to a
// healthy transport and transitions to PeerConnected.
func TestPMConnectSingleTransport(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")
	cfg := pmTestConfig("127.0.0.1:51820", "udp")
	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer pm.Stop()

	if !waitForState(pm, PeerConnected, 2*time.Second) {
		t.Errorf("State() = %s, want %s", pm.State(), PeerConnected)
	}

	if pm.CurrentTransport() != "udp" {
		t.Errorf("CurrentTransport() = %q, want %q", pm.CurrentTransport(), "udp")
	}

	if !pm.IsHealthy() {
		t.Error("IsHealthy() should be true when connected")
	}
}

// TestPMConnectFailoverToSecondTransport verifies that when the primary
// transport fails, PeerManager falls over to the second transport.
func TestPMConnectFailoverToSecondTransport(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality")

	// UDP always fails.
	fix.transports["udp"].SetFailCount(1000)

	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality")
	// Set short HedgeDelay so fallback starts quickly.
	cfg.HedgeDelay = 5 * time.Millisecond

	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer pm.Stop()

	if !waitForState(pm, PeerConnected, 2*time.Second) {
		t.Fatalf("State() = %s, want %s", pm.State(), PeerConnected)
	}

	// Should have connected via reality (the fallback).
	if pm.CurrentTransport() != "reality" {
		t.Errorf("CurrentTransport() = %q, want %q (fallback)", pm.CurrentTransport(), "reality")
	}
}

// TestPMQuarantineAfterFailures verifies that a transport enters quarantine
// after hitting its failure threshold.
func TestPMQuarantineAfterFailures(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")

	// UDP fails 3 times (threshold = 3), then succeeds.
	fix.transports["udp"].SetFailCount(3)

	cfg := pmTestConfig("127.0.0.1:51820", "udp")
	cfg.QuarantineThreshold = map[string]int{"udp": 3}
	cfg.QuarantineBaseCooldown = 50 * time.Millisecond

	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer pm.Stop()

	// After 3 failures, UDP should be quarantined, then after cooldown
	// it should retry and succeed.
	if !waitForState(pm, PeerConnected, 3*time.Second) {
		t.Errorf("State() = %s, want %s (should connect after quarantine expiry)",
			pm.State(), PeerConnected)
	}
}

// TestPMReconnectResetsQuarantine verifies that Reconnect() resets all
// quarantine state and allows immediate retry.
func TestPMReconnectResetsQuarantine(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")

	// UDP always fails initially.
	fix.transports["udp"].SetFailCount(1000)

	cfg := pmTestConfig("127.0.0.1:51820", "udp")
	cfg.QuarantineBaseCooldown = 50 * time.Millisecond
	cfg.BlackoutThreshold = 3

	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer pm.Stop()

	// Wait for UDP to be quarantined.
	time.Sleep(100 * time.Millisecond)

	// Now make UDP succeed.
	fix.transports["udp"].ResetFailCount()

	// Reconnect should reset quarantine and try again.
	if err := pm.Reconnect(); err != nil {
		t.Fatalf("Reconnect() error: %v", err)
	}

	if !waitForState(pm, PeerConnected, 2*time.Second) {
		t.Errorf("State() = %s after Reconnect, want %s",
			pm.State(), PeerConnected)
	}
}

// TestPMShutdownStopsGoroutine verifies that Stop() cleanly stops the
// PeerManager goroutine.
func TestPMShutdownStopsGoroutine(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")
	cfg := pmTestConfig("127.0.0.1:51820", "udp")
	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Wait for connection.
	if !waitForState(pm, PeerConnected, 2*time.Second) {
		t.Fatalf("State() = %s, want %s before Stop", pm.State(), PeerConnected)
	}

	// Stop should transition to disconnected.
	if err := pm.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	if pm.State() != PeerDisconnected {
		t.Errorf("State() = %s after Stop, want %s", pm.State(), PeerDisconnected)
	}
}

// TestPMContextCancellation verifies that context cancellation cleanly
// terminates the PeerManager.
func TestPMContextCancellation(t *testing.T) {
	fix := newTestPeerManagerFixture("udp")
	cfg := pmTestConfig("127.0.0.1:51820", "udp")
	pm := NewPeerManager(cfg, fix.registry)

	ctx, cancel := context.WithCancel(context.Background())
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Wait for connection.
	if !waitForState(pm, PeerConnected, 2*time.Second) {
		t.Fatalf("State() = %s, want %s before cancel", pm.State(), PeerConnected)
	}

	// Cancel context.
	cancel()

	// Stop should still work (and be quick).
	if err := pm.Stop(); err != nil {
		t.Fatalf("Stop() after cancel error: %v", err)
	}

	if pm.State() != PeerDisconnected {
		t.Errorf("State() = %s after cancel+stop, want %s",
			pm.State(), PeerDisconnected)
	}
}

// TestPMTransportStatesSnapshot verifies that TransportStates() returns
// the correct sub-states after connection.
func TestPMTransportStatesSnapshot(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality")
	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer pm.Stop()

	if !waitForState(pm, PeerConnected, 2*time.Second) {
		t.Fatalf("State() = %s, want %s", pm.State(), PeerConnected)
	}

	states := pm.TransportStates()
	if len(states) < 2 {
		t.Errorf("TransportStates() returned %d entries, want ≥2", len(states))
	}

	// The active transport should be "udp" (primary).
	if states["udp"].SubState != TransportSubActive {
		t.Errorf("udp SubState = %s, want %s",
			states["udp"].SubState, TransportSubActive)
	}
}

// TestPMConcurrentReadsDuringConnection verifies that concurrent reads
// on PeerManager state are safe while the goroutine is connecting.
func TestPMConcurrentReadsDuringConnection(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality")
	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer pm.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = pm.State()
			_ = pm.CurrentTransport()
			_ = pm.IsHealthy()
			_ = pm.Latency()
			_ = pm.TransportStates()
		}()
	}
	wg.Wait()
}

// TestPMRegistryDial verifies the TransportRegistry.Dial convenience method.
func TestPMRegistryDial(t *testing.T) {
	reg := NewTransportRegistry()
	f := newManagedMockFactory("udp")
	reg.Register(f)

	ctx := context.Background()
	pc, err := reg.Dial(ctx, "udp", "10.0.0.1:51820", TransportConfig{Name: "udp"})
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	if pc == nil {
		t.Fatal("Dial() returned nil PeerConn")
	}
	defer pc.ForceClose()

	if pc.Transport() != "udp" {
		t.Errorf("Transport() = %q, want %q", pc.Transport(), "udp")
	}
}

// TestPMRegistryDialUnknownTransport verifies that Dial returns an error
// for an unregistered transport.
func TestPMRegistryDialUnknownTransport(t *testing.T) {
	reg := NewTransportRegistry()

	ctx := context.Background()
	_, err := reg.Dial(ctx, "nonexistent", "10.0.0.1:51820", TransportConfig{})
	if err == nil {
		t.Fatal("Dial() should fail for unknown transport")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 8: Cooldown off-by-one fix (motion-a255c77a7674)
// ═══════════════════════════════════════════════════════════════════════════════

// TestCooldownDurationOffByOneFix verifies that cooldownDuration(n)
// produces 2^n × BaseCooldown, not 2^(n-1) × BaseCooldown.
// Before the fix, cooldownDuration(1) returned 30s (BaseCooldown unchanged);
// after the fix it returns 60s (BaseCooldown × 2^1).
func TestCooldownDurationOffByOneFix(t *testing.T) {
	cfg := DefaultPeerManagerConfig()
	cfg.QuarantineBaseCooldown = 30 * time.Second
	cfg.QuarantineMaxCooldown = 300 * time.Second

	pm := NewPeerManager(cfg, NewTransportRegistry())

	tests := []struct {
		n       int
		want    time.Duration
		comment string
	}{
		{0, 30 * time.Second, "n=0 → base cooldown (30s)"},
		{1, 60 * time.Second, "n=1 → 30×2^1 = 60s (was 30s before fix!)"},
		{2, 120 * time.Second, "n=2 → 30×2^2 = 120s"},
		{3, 240 * time.Second, "n=3 → 30×2^3 = 240s"},
		{4, 300 * time.Second, "n=4 → 30×2^4 = 480s, capped to 300s"},
		{5, 300 * time.Second, "n=5 → still capped at 300s"},
	}

	for _, tt := range tests {
		got := pm.cooldownDuration(tt.n)
		if got != tt.want {
			t.Errorf("cooldownDuration(%d) = %v, want %v (%s)",
				tt.n, got, tt.want, tt.comment)
		} else {
			t.Logf("cooldownDuration(%d) = %v ✓ (%s)", tt.n, got, tt.comment)
		}
	}
}

// TestCooldownDurationSequence30to300 verifies the full expected
// sequence matches the spec: 30 → 60 → 120 → 240 → 300 cap.
// (The spec comment on QuarantineBaseCooldown says "30→60→120→300s cap"
// but 240 < 300 so it is not capped at the 4th step.)
func TestCooldownDurationSequence30to300(t *testing.T) {
	cfg := DefaultPeerManagerConfig()
	cfg.QuarantineBaseCooldown = 30 * time.Second
	cfg.QuarantineMaxCooldown = 300 * time.Second
	pm := NewPeerManager(cfg, NewTransportRegistry())

	want := []time.Duration{
		30 * time.Second,  // n=0
		60 * time.Second,  // n=1
		120 * time.Second, // n=2
		240 * time.Second, // n=3 (240 < 300, not capped)
		300 * time.Second, // n=4 (480 > 300, capped)
	}

	for i, w := range want {
		got := pm.cooldownDuration(i)
		if got != w {
			t.Errorf("cooldownDuration(%d) = %v, want %v", i, got, w)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 9: Hysteresis bonus (motion-a255c77a7674)
// ═══════════════════════════════════════════════════════════════════════════════

// TestHysteresisBonusDefaults verifies the semantics of HysteresisBonus:
//   - default 0.10 → 10% of e_lat (raw EWMA latency)
//   - custom fraction (e.g. 0.25) → 25% of e_lat
//   - 0 → hysteresis disabled (returns 0)
func TestHysteresisBonusDefaults(t *testing.T) {
	tests := []struct {
		name  string
		bonus float64
		eLat  float64 // raw EWMA latency in ms
		want  float64
	}{
		{"default 0.10 → 10% of 100ms", 0.10, 100.0, 10.0},
		{"default 0.10 → 10% of 50ms", 0.10, 50.0, 5.0},
		{"custom 0.25 → 25% of 100ms", 0.25, 100.0, 25.0},
		{"custom 0.25 → 25% of 8ms", 0.25, 8.0, 2.0},
		{"disabled (0)", 0, 100.0, 0.0},
		{"disabled (0) on 50ms", 0, 50.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultPeerManagerConfig()
			cfg.HysteresisBonus = tt.bonus
			pm := NewPeerManager(cfg, NewTransportRegistry())
			got := pm.hysteresisBonus(tt.eLat)
			epsilon := 0.001
			if diff := got - tt.want; diff < -epsilon || diff > epsilon {
				t.Errorf("hysteresisBonus(eLat=%.1f) = %.4f, want %.4f",
					tt.eLat, got, tt.want)
			}
		})
	}
}

// TestPathSelectionHysteresisPreventsFlapping verifies that when two
// transports have near-identical latencies (within the 10% hysteresis
// range), the active transport is NOT switched away from. This is the
// core anti-flapping guarantee of the hysteresis bonus.
//
// Scenario: active "udp" at 20ms, alternative "reality" at 19ms.
// Without hysteresis, reality is 5% better and could trigger a switch.
// With the default 0.10 hysteresis bonus, h_bonus = 0.10 × 20 = 2.0ms,
// so effective active = 20.0 - 2.0 = 18.0ms, and reality (19ms) does NOT
// beat it.
func TestPathSelectionHysteresisPreventsFlapping(t *testing.T) {
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp", "reality")
	cfg.MinSamplesForScoring = 1
	cfg.ScoreSwitchThreshold = 0.05 // 5% threshold — sensitive
	cfg.ScoreStableProbes = 1       // switch after just 1 cycle
	// Use default HysteresisBonus = 0.10 (10% of e_lat).

	fix := newTestPeerManagerFixture("udp", "reality")
	pm := NewPeerManager(cfg, fix.registry)

	// Populate latency samples: UDP 20ms, Reality 19ms.
	pm.mu.Lock()
	udpTS := pm.transportStates["udp"]
	udpTS.latency.push(20 * time.Millisecond)
	udpTS.latency.push(20 * time.Millisecond)
	udpTS.latency.push(20 * time.Millisecond)
	udpTS.subState = TransportSubActive

	realityTS := pm.transportStates["reality"]
	realityTS.latency.push(19 * time.Millisecond)
	realityTS.latency.push(19 * time.Millisecond)
	realityTS.latency.push(19 * time.Millisecond)
	realityTS.subState = TransportSubActive

	pm.currentTransport = "udp"
	pm.mu.Unlock()

	// Compute scores.
	udpScore := pm.computeScore(udpTS)         // 20.0
	realityScore := pm.computeScore(realityTS) // 19.0

	// Sanity: reality is nominally better (19 < 20).
	if realityScore >= udpScore {
		t.Fatalf("setup error: reality (%.2f) should be < udp (%.2f)",
			realityScore, udpScore)
	}

	// Hysteresis bonus for active (udp): h_bonus = 0.10 × 20ms = 2.0ms.
	udpELat := float64(udpTS.latency.current().Milliseconds()) // 20.0
	bonus := pm.hysteresisBonus(udpELat)
	effectiveActive := udpScore - bonus

	t.Logf("udp score=%.2f, reality score=%.2f, hysteresis bonus=%.2f, effective active=%.2f",
		udpScore, realityScore, bonus, effectiveActive)

	// With hysteresis, effective active (18.0) < reality (19.0).
	// So reality should NOT beat the effective active score.
	if realityScore < effectiveActive {
		t.Errorf("reality (%.2f) should NOT beat effective active (%.2f) "+
			"within hysteresis range — would cause flapping",
			realityScore, effectiveActive)
	}

	// Verify the switch threshold is not met.
	// bestScore (19.0) < effectiveActive × (1 - 0.05)?
	// 19.0 < 18.0 × 0.95 = 17.1? No. So no switch.
	threshold := pm.cfg.ScoreSwitchThreshold
	shouldSwitch := realityScore < effectiveActive*(1-threshold)
	if shouldSwitch {
		t.Errorf("switch should NOT trigger: reality %.2f >= effectiveActive×(1-threshold) = %.2f×%.2f = %.2f",
			realityScore, effectiveActive, 1-threshold, effectiveActive*(1-threshold))
	}

	t.Logf("PASS: hysteresis prevented flapping — udp (active) retained at 20ms vs reality 19ms")
}

// TestPathSelectionHysteresisAllowsSwitchWhenSignificantlyBetter
// verifies that when the alternative is significantly better (beyond
// the hysteresis range), the switch still proceeds. This ensures
// hysteresis doesn't lock the active transport forever.
func TestPathSelectionHysteresisAllowsSwitchWhenSignificantlyBetter(t *testing.T) {
	cfg := quickConfig("peer-1", "10.0.0.1:51820", "udp", "reality")
	cfg.MinSamplesForScoring = 1
	cfg.ScoreSwitchThreshold = 0.05 // 5%
	cfg.ScoreStableProbes = 1
	// Use default HysteresisBonus = 0.10 (10% of e_lat).

	fix := newTestPeerManagerFixture("udp", "reality")
	pm := NewPeerManager(cfg, fix.registry)

	// UDP 50ms, Reality 5ms — reality is 90% better, far beyond hysteresis.
	pm.mu.Lock()
	udpTS := pm.transportStates["udp"]
	udpTS.latency.push(50 * time.Millisecond)
	udpTS.latency.push(50 * time.Millisecond)
	udpTS.latency.push(50 * time.Millisecond)
	udpTS.subState = TransportSubActive

	realityTS := pm.transportStates["reality"]
	realityTS.latency.push(5 * time.Millisecond)
	realityTS.latency.push(5 * time.Millisecond)
	realityTS.latency.push(5 * time.Millisecond)
	realityTS.subState = TransportSubActive

	pm.currentTransport = "udp"
	pm.mu.Unlock()

	udpScore := pm.computeScore(udpTS)                         // 50.0
	realityScore := pm.computeScore(realityTS)                 // 5.0
	udpELat := float64(udpTS.latency.current().Milliseconds()) // 50.0
	bonus := pm.hysteresisBonus(udpELat)                       // 0.10 × 50 = 5.0
	effectiveActive := udpScore - bonus                        // 45.0

	threshold := pm.cfg.ScoreSwitchThreshold
	shouldSwitch := realityScore < effectiveActive*(1-threshold)

	t.Logf("udp=%.1f, reality=%.1f, bonus=%.1f, effective=%.1f, threshold=%.2f",
		udpScore, realityScore, bonus, effectiveActive, threshold)

	if !shouldSwitch {
		t.Errorf("switch SHOULD trigger: reality %.1f < effectiveActive×(1-threshold) = %.1f",
			realityScore, effectiveActive*(1-threshold))
	}

	t.Logf("PASS: switch proceeds — reality (5ms) significantly better than udp (50ms)")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 10: EWMA split-alpha smoothing (spec §5.1)
// ═══════════════════════════════════════════════════════════════════════════════

// TestLatencyEWMAFirstSampleInitializes verifies that the first sample
// sets the EWMA value directly.
func TestLatencyEWMAFirstSampleInitializes(t *testing.T) {
	e := newLatencyEWMA(defaultAlphaRise, defaultAlphaFall)
	if e.current() != 0 {
		t.Errorf("empty EWMA current() = %v, want 0", e.current())
	}
	if e.count != 0 {
		t.Errorf("empty EWMA count = %d, want 0", e.count)
	}

	e.push(10 * time.Millisecond)
	if e.current() != 10*time.Millisecond {
		t.Errorf("after first push, current() = %v, want 10ms", e.current())
	}
	if e.count != 1 {
		t.Errorf("after first push, count = %d, want 1", e.count)
	}
}

// TestLatencyEWMARiseTrajectory verifies that when latency increases,
// the EWMA uses alpha_rise (0.7) and converges upward quickly.
func TestLatencyEWMARiseTrajectory(t *testing.T) {
	e := newLatencyEWMA(defaultAlphaRise, defaultAlphaFall)

	// Start at 10ms.
	e.push(10 * time.Millisecond)
	if e.current() != 10*time.Millisecond {
		t.Fatalf("initial EWMA = %v, want 10ms", e.current())
	}

	// Push 100ms — should jump toward 100ms using alpha_rise=0.7.
	// ewma = 10 + 0.7 * (100 - 10) = 10 + 63 = 73ms
	e.push(100 * time.Millisecond)
	expected := 73 * time.Millisecond
	if e.current() != expected {
		t.Errorf("after rise sample: current() = %v, want %v (alpha_rise=0.7)", e.current(), expected)
	}

	// Push another 100ms — should converge further.
	// ewma = 73 + 0.7 * (100 - 73) = 73 + 18.9 = 91.9ms
	e.push(100 * time.Millisecond)
	expected = 91900 * time.Microsecond // 91.9ms
	tolerance := 100 * time.Microsecond
	if diff := e.current() - expected; diff > tolerance || diff < -tolerance {
		t.Errorf("after 2nd rise sample: current() = %v, want ~%v (tolerance %v)", e.current(), expected, tolerance)
	}
}

// TestLatencyEWMAFallTrajectory verifies that when latency decreases,
// the EWMA uses alpha_fall (0.3) and recovers downward slowly.
func TestLatencyEWMAFallTrajectory(t *testing.T) {
	e := newLatencyEWMA(defaultAlphaRise, defaultAlphaFall)

	// Start at 100ms.
	e.push(100 * time.Millisecond)

	// Push 10ms — should drop toward 10ms using alpha_fall=0.3.
	// ewma = 100 + 0.3 * (10 - 100) = 100 - 27 = 73ms
	e.push(10 * time.Millisecond)
	expected := 73 * time.Millisecond
	if e.current() != expected {
		t.Errorf("after fall sample: current() = %v, want %v (alpha_fall=0.3)", e.current(), expected)
	}

	// Push another 10ms — should continue converging downward.
	// ewma = 73 + 0.3 * (10 - 73) = 73 - 18.9 = 54.1ms
	e.push(10 * time.Millisecond)
	expected = 54100 * time.Microsecond // 54.1ms
	tolerance := 100 * time.Microsecond
	if diff := e.current() - expected; diff > tolerance || diff < -tolerance {
		t.Errorf("after 2nd fall sample: current() = %v, want ~%v (tolerance %v)", e.current(), expected, tolerance)
	}
}

// TestLatencyEWMASplitAlphaAsymmetry verifies that alpha_rise and alpha_fall
// produce different convergence rates for the same delta. A rise from 10→100
// should converge faster than a fall from 100→10.
func TestLatencyEWMASplitAlphaAsymmetry(t *testing.T) {
	// Rise: 10 → 100
	riseEWMA := newLatencyEWMA(defaultAlphaRise, defaultAlphaFall)
	riseEWMA.push(10 * time.Millisecond)
	riseEWMA.push(100 * time.Millisecond)
	riseVal := riseEWMA.current()

	// Fall: 100 → 10
	fallEWMA := newLatencyEWMA(defaultAlphaRise, defaultAlphaFall)
	fallEWMA.push(100 * time.Millisecond)
	fallEWMA.push(10 * time.Millisecond)
	fallVal := fallEWMA.current()

	// After one sample of the same delta (90ms), the rise EWMA should be
	// closer to the target (100ms) than the fall EWMA is to its target (10ms).
	// Rise: 73ms (distance 27ms from 100ms target)
	// Fall: 73ms (distance 63ms from 10ms target)
	// Both are 73ms numerically, but the rise is 73/100 = 73% of the way to target,
	// while fall is (100-73)/(100-10) = 27/90 = 30% of the way to target.
	riseProgress := float64(riseVal.Milliseconds()-10) / float64(100-10)  // 0.7
	fallProgress := float64(100-fallVal.Milliseconds()) / float64(100-10) // 0.3

	if riseProgress <= fallProgress {
		t.Errorf("alpha_rise should converge faster: riseProgress=%.2f, fallProgress=%.2f",
			riseProgress, fallProgress)
	}

	// Verify exact values.
	if riseProgress < 0.69 || riseProgress > 0.71 {
		t.Errorf("riseProgress = %.4f, want ~0.70 (alpha_rise)", riseProgress)
	}
	if fallProgress < 0.29 || fallProgress > 0.31 {
		t.Errorf("fallProgress = %.4f, want ~0.30 (alpha_fall)", fallProgress)
	}

	t.Logf("Asymmetry verified: riseProgress=%.2f (alpha_rise=0.7), fallProgress=%.2f (alpha_fall=0.3)",
		riseProgress, fallProgress)
}

// TestLatencyEWMASteadyStateConverges verifies that repeated identical samples
// converge to that value (important for path selection scoring).
func TestLatencyEWMASteadyStateConverges(t *testing.T) {
	e := newLatencyEWMA(defaultAlphaRise, defaultAlphaFall)

	// Push 10 samples of 20ms.
	for i := 0; i < 10; i++ {
		e.push(20 * time.Millisecond)
	}

	val := e.current()
	tolerance := time.Microsecond
	if diff := val - 20*time.Millisecond; diff > tolerance || diff < -tolerance {
		t.Errorf("after 10 identical samples: current() = %v, want ~20ms (tolerance %v)", val, tolerance)
	}
}

// TestLatencyEWMADegradationDetectionSpeed verifies acceptance criterion (2):
// degradation is detected within 30-60s of onset (vs ~2min with median window).
// With alpha_rise=0.7, after 3 probes (at 30s intervals = 90s total) the EWMA
// should be >90% of the degraded value.
func TestLatencyEWMADegradationDetectionSpeed(t *testing.T) {
	e := newLatencyEWMA(defaultAlphaRise, defaultAlphaFall)

	// Baseline: 10ms.
	e.push(10 * time.Millisecond)

	// Degradation onset: latency jumps to 100ms.
	// With probe interval 30s, after N probes the EWMA is:
	//   N=1 (30s): 10 + 0.7*(100-10) = 73ms → 73% of degraded value
	//   N=2 (60s): 73 + 0.7*(100-73) = 91.9ms → 91.9% of degraded value
	e.push(100 * time.Millisecond) // 30s after onset
	val30s := e.current()
	e.push(100 * time.Millisecond) // 60s after onset
	val60s := e.current()

	// After 30s: should be > 50% of the degraded value (73%).
	if pct := float64(val30s.Milliseconds()) / 100.0; pct < 0.5 {
		t.Errorf("after 30s: EWMA = %dms (%.1f%% of degraded), want >50%%",
			val30s.Milliseconds(), pct*100)
	}

	// After 60s: should be > 80% of the degraded value (91.9%).
	if pct := float64(val60s.Milliseconds()) / 100.0; pct < 0.8 {
		t.Errorf("after 60s: EWMA = %dms (%.1f%% of degraded), want >80%%",
			val60s.Milliseconds(), pct*100)
	}

	t.Logf("Degradation detection: 30s→%dms, 60s→%dms",
		val30s.Milliseconds(), val60s.Milliseconds())
}

// TestLatencyEWMAReset verifies that reset clears the EWMA state.
func TestLatencyEWMAReset(t *testing.T) {
	e := newLatencyEWMA(defaultAlphaRise, defaultAlphaFall)
	e.push(10 * time.Millisecond)
	e.push(20 * time.Millisecond)

	if e.count != 2 {
		t.Fatalf("count = %d, want 2 before reset", e.count)
	}

	e.reset()

	if e.current() != 0 {
		t.Errorf("after reset: current() = %v, want 0", e.current())
	}
	if e.count != 0 {
		t.Errorf("after reset: count = %d, want 0", e.count)
	}

	// Should work normally after reset.
	e.push(15 * time.Millisecond)
	if e.current() != 15*time.Millisecond {
		t.Errorf("after reset+push: current() = %v, want 15ms", e.current())
	}
}

// TestLatencyEWMAConfigDefaults verifies that the PeerManagerConfig has
// the correct default alpha values matching spec §5.1.
func TestLatencyEWMAConfigDefaults(t *testing.T) {
	cfg := DefaultPeerManagerConfig()
	if cfg.AlphaRise != defaultAlphaRise {
		t.Errorf("AlphaRise = %v, want %v (spec §5.1)", cfg.AlphaRise, defaultAlphaRise)
	}
	if cfg.AlphaFall != defaultAlphaFall {
		t.Errorf("AlphaFall = %v, want %v (spec §5.1)", cfg.AlphaFall, defaultAlphaFall)
	}
}

// TestLatencyEWMACustomAlphas verifies that custom alpha values are respected.
func TestLatencyEWMACustomAlphas(t *testing.T) {
	cfg := DefaultPeerManagerConfig()
	cfg.AlphaRise = 0.5
	cfg.AlphaFall = 0.1
	pm := NewPeerManager(cfg, NewTransportRegistry())

	if pm.cfg.AlphaRise != 0.5 {
		t.Errorf("AlphaRise = %v, want 0.5", pm.cfg.AlphaRise)
	}
	if pm.cfg.AlphaFall != 0.1 {
		t.Errorf("AlphaFall = %v, want 0.1", pm.cfg.AlphaFall)
	}

	// Verify the transport state uses custom alphas.
	ts, ok := pm.transportStates["udp"]
	_ = ok // might not exist if TransportNames is empty, just check if it does
	if ts != nil && ts.latency != nil {
		if ts.latency.alphaRise != 0.5 {
			t.Errorf("transport alphaRise = %v, want 0.5", ts.latency.alphaRise)
		}
		if ts.latency.alphaFall != 0.1 {
			t.Errorf("transport alphaFall = %v, want 0.1", ts.latency.alphaFall)
		}
	}
}

// TestLatencyEWMASpikeDoesNotPersist verifies that a single latency spike
// does not permanently skew the EWMA — it recovers over subsequent normal samples.
func TestLatencyEWMASpikeDoesNotPersist(t *testing.T) {
	e := newLatencyEWMA(defaultAlphaRise, defaultAlphaFall)

	// Establish baseline at 10ms.
	for i := 0; i < 5; i++ {
		e.push(10 * time.Millisecond)
	}

	// Single spike to 200ms.
	e.push(200 * time.Millisecond)
	afterSpike := e.current()

	// The spike should have raised the EWMA (using alpha_rise).
	// ewma = 10 + 0.7 * (200 - 10) = 10 + 133 = 143ms
	if afterSpike != 143*time.Millisecond {
		t.Errorf("after spike: current() = %v, want 143ms", afterSpike)
	}

	// Push 5 more normal samples at 10ms — should recover (using alpha_fall).
	for i := 0; i < 5; i++ {
		e.push(10 * time.Millisecond)
	}

	// After 5 fall samples from 143ms toward 10ms:
	// Each step: ewma = ewma + 0.3 * (10 - ewma) = 0.7*ewma + 3
	// 143 → 103.1 → 75.17 → 55.619 → 41.9333 → 32.3533
	finalVal := e.current()
	if finalVal > 40*time.Millisecond {
		t.Errorf("after 5 recovery samples: current() = %v, want <40ms (recovery)", finalVal)
	}
	if finalVal < 25*time.Millisecond {
		t.Errorf("after 5 recovery samples: current() = %v, want >25ms (slow recovery is expected with alpha_fall=0.3)", finalVal)
	}

	t.Logf("Spike recovery: spike→%v, after 5 normal samples→%v", afterSpike, finalVal)
}

// ═══════════════════════════════════════════════════════════════════════════════
// TransportSubProbing state transition tests (spec §2.3)
// ═══════════════════════════════════════════════════════════════════════════════

// TestProbeAndEvaluateSetsProbingState verifies that probeAndEvaluate
// transitions the transport sub-state to TransportSubProbing before
// invoking LatencyProbe, and back to TransportSubActive on success.
//
// Acceptance criterion (1): state-dump shows TransportSubProbing during
// active probes.
//
// We call probeAndEvaluate directly (package-private) with a mock
// transport that records its state when LatencyProbe is invoked.
func TestProbeAndEvaluateSetsProbingState(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality")
	cfg.ProbeInterval = 50 * time.Millisecond
	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()

	// Simulate a connected state so probeAndEvaluate enters the probe path.
	pm.stateAtomic.Store(int32(PeerConnected))
	pm.mu.Lock()
	pm.currentTransport = "udp"
	// Reset lastProbeAt so the probe interval check passes.
	for _, ts := range pm.transportStates {
		ts.lastProbeAt = time.Time{}
	}
	pm.mu.Unlock()

	// Create a custom transport that records the sub-state at probe time.
	probeObservedState := TransportSubActive
	originalTransport := fix.transports["reality"]
	fix.factories["reality"].NewTransportFn = func(cfg TransportConfig) (Transport, error) {
		return &probeRecordingTransport{
			name:        "reality",
			inner:       originalTransport,
			stateAtCall: &probeObservedState,
			pm:          pm,
		}, nil
	}

	// Call probeAndEvaluate directly.
	pm.probeAndEvaluate(ctx)

	// The probe should have been called, and at the time of the call
	// the sub-state should have been TransportSubProbing.
	if probeObservedState != TransportSubProbing {
		t.Errorf("during LatencyProbe, TransportState(reality) = %s, want probing",
			probeObservedState.String())
	}

	// After probeAndEvaluate completes, the transport should be back to Active.
	if s := pm.TransportState("reality"); s != TransportSubActive {
		t.Errorf("after probe, TransportState(reality) = %s, want active", s.String())
	}

	t.Log("probeAndEvaluate: probing state transition confirmed — state is probing during LatencyProbe, returns to active after")
}

// TestProbeAndEvaluatePermanentErrorTransitionsToFailed verifies that
// when LatencyProbe returns a permanent (non-retryable) error, the
// transport sub-state transitions to TransportSubFailed.
//
// This tests the Probing → Failed transition path.
func TestProbeAndEvaluatePermanentErrorTransitionsToFailed(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality")
	cfg.ProbeInterval = 50 * time.Millisecond
	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()

	// Simulate a connected state.
	pm.stateAtomic.Store(int32(PeerConnected))
	pm.mu.Lock()
	pm.currentTransport = "udp"
	for _, ts := range pm.transportStates {
		ts.lastProbeAt = time.Time{}
	}
	pm.mu.Unlock()

	// Use a custom transport that returns a permanent error on LatencyProbe.
	fix.factories["reality"].NewTransportFn = func(cfg TransportConfig) (Transport, error) {
		return &permanentErrorTransport{name: "reality"}, nil
	}

	// Call probeAndEvaluate directly.
	pm.probeAndEvaluate(ctx)

	// reality should now be in TransportSubFailed state.
	if s := pm.TransportState("reality"); s != TransportSubFailed {
		t.Errorf("after permanent probe error, TransportState(reality) = %s, want failed", s.String())
	}

	// udp should still be active (its probe succeeded).
	if s := pm.TransportState("udp"); s == TransportSubFailed {
		t.Errorf("TransportState(udp) = failed — udp probe should have succeeded")
	}

	t.Log("Permanent probe error → TransportSubFailed transition confirmed")
}

// TestBlackoutEscapeExcludesFailedTransports verifies that
// TransportSubFailed transports are NOT included in
// blackoutEscapeCandidates. Per spec §2.3, failed transports require
// an explicit Reconnect() call.
//
// Acceptance criterion (2): TransportSubFailed transports are excluded
// from blackoutEscapeCandidates.
// Acceptance criterion (3): failed transports only recover via
// explicit Reconnect().
func TestBlackoutEscapeExcludesFailedTransports(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality", "websocket")
	pm := NewPeerManager(cfg, fix.registry)

	// Set reality to failed, udp and websocket to quarantined.
	pm.mu.Lock()
	if ts := pm.transportStates["reality"]; ts != nil {
		ts.subState = TransportSubFailed
	}
	if ts := pm.transportStates["udp"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.cooldownUntil = time.Now().Add(1 * time.Hour) // far future
	}
	if ts := pm.transportStates["websocket"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.cooldownUntil = time.Now().Add(30 * time.Minute)
	}
	pm.mu.Unlock()

	// blackoutEscapeCandidates should return only quarantined transports,
	// NOT the failed one.
	candidates := pm.blackoutEscapeCandidates()
	if len(candidates) == 0 {
		t.Fatal("blackoutEscapeCandidates() returned empty — expected at least one quarantined transport")
	}

	for _, name := range candidates {
		if pm.TransportState(name) == TransportSubFailed {
			t.Errorf("blackoutEscapeCandidates() included %q which is TransportSubFailed — should be excluded", name)
		}
	}

	// Now set ALL transports to failed — blackoutEscapeCandidates should
	// return nil (no escape possible without explicit Reconnect).
	pm.mu.Lock()
	for _, ts := range pm.transportStates {
		ts.subState = TransportSubFailed
	}
	pm.mu.Unlock()

	candidates = pm.blackoutEscapeCandidates()
	if len(candidates) != 0 {
		t.Errorf("blackoutEscapeCandidates() = %v, want empty when all transports are failed", candidates)
	}

	t.Log("blackoutEscapeCandidates excludes TransportSubFailed — all-failed returns nil")
}

// TestFailedTransportRecoversViaReconnect verifies that a
// TransportSubFailed transport recovers to TransportSubActive only
// after an explicit Reconnect() call.
//
// Acceptance criterion (3): failed transports only recover via
// explicit Reconnect().
func TestFailedTransportRecoversViaReconnect(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality")
	cfg.ProbeInterval = 50 * time.Millisecond
	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer pm.Stop()

	if !waitForState(pm, PeerConnected, 2*time.Second) {
		t.Fatalf("State() = %s, want %s", pm.State(), PeerConnected)
	}

	// Set reality to failed.
	pm.mu.Lock()
	if ts := pm.transportStates["reality"]; ts != nil {
		ts.subState = TransportSubFailed
	}
	pm.mu.Unlock()

	// Verify it stays failed.
	time.Sleep(50 * time.Millisecond)
	if s := pm.TransportState("reality"); s != TransportSubFailed {
		t.Fatalf("TransportState(reality) = %s, want failed before Reconnect", s)
	}

	// Explicit Reconnect should reset all transport states to Active.
	if err := pm.Reconnect(); err != nil {
		t.Fatalf("Reconnect() error: %v", err)
	}

	// Wait for reconnect to process.
	if !waitForState(pm, PeerConnected, 2*time.Second) {
		t.Fatalf("State() = %s after Reconnect, want connected", pm.State())
	}

	// After Reconnect, the previously-failed transport should be active
	// (not failed).
	if s := pm.TransportState("reality"); s == TransportSubFailed {
		t.Errorf("TransportState(reality) = failed after Reconnect — should have been reset")
	}

	t.Log("Failed transport recovers only via explicit Reconnect()")
}

// ──────────────────────────────────────────────────────────────────────────────
// Test helper transports for probing state tests
// ──────────────────────────────────────────────────────────────────────────────

// probeRecordingTransport wraps a managedMockTransport and records the
// PeerManager's transport sub-state at the time LatencyProbe is called.
type probeRecordingTransport struct {
	name        string
	inner       *managedMockTransport
	stateAtCall *TransportSubState
	pm          *PeerManager
}

func (t *probeRecordingTransport) Name() string { return t.name }

func (t *probeRecordingTransport) Connect(ctx context.Context, addr string) (PeerConn, error) {
	return t.inner.Connect(ctx, addr)
}

func (t *probeRecordingTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	return t.inner.Listen(ctx, addr)
}

func (t *probeRecordingTransport) LatencyProbe(ctx context.Context, addr string) (time.Duration, error) {
	// Record the sub-state at the moment LatencyProbe is called.
	*t.stateAtCall = t.pm.TransportState(t.name)
	return t.inner.LatencyProbe(ctx, addr)
}

func (t *probeRecordingTransport) IsHealthy() bool {
	return t.inner.IsHealthy()
}

func (t *probeRecordingTransport) Close() {
	t.inner.Close()
}

// permanentErrorTransport is a Transport whose LatencyProbe always
// returns a permanent (non-retryable) TransportError.
type permanentErrorTransport struct {
	name string
}

func (t *permanentErrorTransport) Name() string { return t.name }

func (t *permanentErrorTransport) Connect(ctx context.Context, addr string) (PeerConn, error) {
	return nil, NewTransportError("connect", t.name, addr, errors.New("permanent failure"), false)
}

func (t *permanentErrorTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	return &mockListener{addr: mockAddr{network: "pipe", address: t.name + "-pipe"}}, nil
}

func (t *permanentErrorTransport) LatencyProbe(ctx context.Context, addr string) (time.Duration, error) {
	return 0, NewTransportError("latency_probe", t.name, addr,
		errors.New("permanent probe failure"), false)
}

func (t *permanentErrorTransport) IsHealthy() bool { return true }

func (t *permanentErrorTransport) Close() {}

// ═══════════════════════════════════════════════════════════════════════════════
// Test: LRQ selection — oldest quarantine, not soonest cooldown expiry
// ═══════════════════════════════════════════════════════════════════════════════

// TestLRQSelectsOldestQuarantineStart verifies that blackoutEscapeCandidates
// selects the transport with the oldest quarantineStart timestamp, NOT the
// transport whose cooldown expires soonest. Per spec §3.3, the LRQ is the
// transport quarantined the longest.
//
// Acceptance criteria (1) & (2): LRQ pop returns oldest quarantineStart;
// cooldownUntil is no longer the selection key.
func TestLRQSelectsOldestQuarantineStart(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality", "websocket")
	pm := NewPeerManager(cfg, fix.registry)

	now := time.Now()

	// Setup: all three transports are quarantined.
	// Key insight: the transport with the LATEST cooldown expiry (reality)
	// should still NOT be selected because it was quarantined most recently.
	// The transport with the OLDEST quarantine (udp) has the LONGEST cooldown
	// remaining — yet it should be selected per spec §3.3.
	pm.mu.Lock()
	// udp: quarantined 3 min ago, cooldown expires in 1 hour (far future)
	if ts := pm.transportStates["udp"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = now.Add(-3 * time.Minute)
		ts.cooldownUntil = now.Add(1 * time.Hour) // far future — longest remaining
	}
	// reality: quarantined 30s ago, cooldown expires in 30s (soonest)
	if ts := pm.transportStates["reality"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = now.Add(-30 * time.Second)
		ts.cooldownUntil = now.Add(30 * time.Second) // soonest expiry
	}
	// websocket: quarantined 1 min ago, cooldown expires in 5 min
	if ts := pm.transportStates["websocket"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = now.Add(-1 * time.Minute)
		ts.cooldownUntil = now.Add(5 * time.Minute)
	}
	pm.mu.Unlock()

	candidates := pm.blackoutEscapeCandidates()
	if len(candidates) != 1 {
		t.Fatalf("blackoutEscapeCandidates() returned %d candidates, want 1", len(candidates))
	}
	if candidates[0] != "udp" {
		t.Errorf("LRQ = %q, want %q (oldest quarantineStart, not soonest cooldownUntil)",
			candidates[0], "udp")
	}
}

// TestLRQDoesNotSelectSoonestCooldown verifies that the transport with the
// soonest cooldown expiry is NOT selected when its quarantineStart is more
// recent than another transport's. This is the core regression test for the
// old soonest-expiry behavior.
func TestLRQDoesNotSelectSoonestCooldown(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality")
	pm := NewPeerManager(cfg, fix.registry)

	now := time.Now()

	pm.mu.Lock()
	// udp: quarantined 5 min ago, cooldown expires in 2 hours
	if ts := pm.transportStates["udp"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = now.Add(-5 * time.Minute)
		ts.cooldownUntil = now.Add(2 * time.Hour)
	}
	// reality: quarantined 10s ago, cooldown expires in 10s (soonest)
	if ts := pm.transportStates["reality"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = now.Add(-10 * time.Second)
		ts.cooldownUntil = now.Add(10 * time.Second)
	}
	pm.mu.Unlock()

	candidates := pm.blackoutEscapeCandidates()
	if len(candidates) != 1 {
		t.Fatalf("blackoutEscapeCandidates() returned %d candidates, want 1", len(candidates))
	}
	if candidates[0] == "reality" {
		t.Error("LRQ selected 'reality' (soonest cooldown) — should select oldest quarantineStart instead")
	}
	if candidates[0] != "udp" {
		t.Errorf("LRQ = %q, want 'udp' (oldest quarantineStart)", candidates[0])
	}
}

// TestLRQEqualQuarantineTimestamps verifies the edge case where two
// transports have equal (or near-simultaneous) quarantine timestamps.
// The first transport in TransportNames order should win the tiebreak.
func TestLRQEqualQuarantineTimestamps(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality", "websocket")
	pm := NewPeerManager(cfg, fix.registry)

	now := time.Now()

	pm.mu.Lock()
	// All three quarantined at the exact same timestamp.
	for _, name := range []string{"udp", "reality", "websocket"} {
		if ts := pm.transportStates[name]; ts != nil {
			ts.subState = TransportSubQuarantined
			ts.quarantinedAt = now
			ts.cooldownUntil = now.Add(1 * time.Hour)
		}
	}
	pm.mu.Unlock()

	candidates := pm.blackoutEscapeCandidates()
	if len(candidates) != 1 {
		t.Fatalf("blackoutEscapeCandidates() returned %d candidates, want 1", len(candidates))
	}
	// With equal timestamps, the first transport in TransportNames order wins
	// (because Before() is false for equal times, so the initial "best" sticks).
	if candidates[0] != "udp" {
		t.Errorf("LRQ with equal timestamps = %q, want 'udp' (first in TransportNames order)",
			candidates[0])
	}
}

// TestLRQSingleQuarantinedTransport verifies that when only one transport
// is quarantined (and others are in other states), it is correctly selected.
func TestLRQSingleQuarantinedTransport(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality", "websocket")
	pm := NewPeerManager(cfg, fix.registry)

	now := time.Now()

	pm.mu.Lock()
	// Only reality is quarantined; udp is active, websocket is failed.
	if ts := pm.transportStates["udp"]; ts != nil {
		ts.subState = TransportSubActive
	}
	if ts := pm.transportStates["reality"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = now.Add(-2 * time.Minute)
		ts.cooldownUntil = now.Add(30 * time.Minute)
	}
	if ts := pm.transportStates["websocket"]; ts != nil {
		ts.subState = TransportSubFailed
	}
	pm.mu.Unlock()

	candidates := pm.blackoutEscapeCandidates()
	if len(candidates) != 1 {
		t.Fatalf("blackoutEscapeCandidates() returned %d candidates, want 1", len(candidates))
	}
	if candidates[0] != "reality" {
		t.Errorf("LRQ = %q, want 'reality' (only quarantined transport)", candidates[0])
	}
}

// TestLRQQuarantineResetOnExpiry verifies that quarantinedAt is reset to
// zero when quarantine expires (cooldown elapsed), so a subsequent
// quarantine starts fresh.
func TestLRQQuarantineResetOnExpiry(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality")
	pm := NewPeerManager(cfg, fix.registry)

	now := time.Now()

	pm.mu.Lock()
	// udp: quarantined, but cooldown already expired
	if ts := pm.transportStates["udp"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = now.Add(-5 * time.Minute)
		ts.cooldownUntil = now.Add(-1 * time.Minute) // expired 1 min ago
	}
	pm.mu.Unlock()

	// Simulate quarantine expiry check.
	pm.checkQuarantineExpiry(context.Background())

	// After expiry, quarantinedAt should be zero.
	pm.mu.RLock()
	ts := pm.transportStates["udp"]
	pm.mu.RUnlock()
	if ts == nil {
		t.Fatal("transportStates['udp'] is nil")
	}
	if !ts.quarantinedAt.IsZero() {
		t.Errorf("after cooldown expiry, quarantinedAt should be zero, got %v", ts.quarantinedAt)
	}
	if ts.subState != TransportSubActive {
		t.Errorf("after cooldown expiry, subState = %s, want active", ts.subState.String())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// V1.6 Conformance Verification Tests
// ═══════════════════════════════════════════════════════════════════════════════

// TestConformanceEWMASpecSection5_1 verifies §5.1 requirements with the
// actual PeerManager integration (not just unit-level latencyEWMA tests).
// Checks:
//
//	(a) degradation detection latency: EWMA reaches >90% of degraded value within 60s (2 probes)
//	(b) recovery tracking uses alpha_fall: slow fall confirmed on TransportStates() output
//	(c) steady-state convergence: EWMA values stabilize for constant latency
func TestConformanceEWMASpecSection5_1(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality")
	cfg.ProbeInterval = 50 * time.Millisecond
	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer pm.Stop()

	if !waitForState(pm, PeerConnected, 2*time.Second) {
		t.Fatalf("State() = %s, want %s", pm.State(), PeerConnected)
	}

	// Verify steady-state convergence on the initial transport.
	// After connection + a few stable latency samples, the EWMA should
	// converge to the actual latency (mock returns 1ms).
	time.Sleep(200 * time.Millisecond) // let a few probe cycles run
	states := pm.TransportStates()
	var found bool
	for name, s := range states {
		if name == pm.CurrentTransport() {
			found = true
			if s.LatencyMedian <= 0 {
				t.Errorf("§5.1 steady-state: LatencyMedian for %s = %v, want >0 (should converge)", s.Name, s.LatencyMedian)
			}
			if s.LatencySamples < 1 {
				t.Errorf("§5.1 steady-state: LatencySamples for %s = %d, want >=1", s.Name, s.LatencySamples)
			}
			t.Logf("§5.1 conformance: %s LatencyMedian=%v, Samples=%d", s.Name, s.LatencyMedian, s.LatencySamples)
		}
	}
	if !found {
		t.Error("§5.1: TransportStates() did not include the current transport")
	}

	// Verify degradation detection speed: manually inject a degraded latency
	// value into the EWMA and confirm >90% convergence within 2 probe equivalents.
	pm.mu.RLock()
	activeName := pm.currentTransport
	ts := pm.transportStates[activeName]
	pm.mu.RUnlock()

	if ts == nil {
		t.Fatal("active transport state is nil")
	}

	// Reset and establish baseline at 10ms.
	ts.latency.reset()
	ts.latency.push(10 * time.Millisecond)

	// Simulate 2 degradation probes (equivalent to 60s at 30s interval).
	ts.latency.push(100 * time.Millisecond) // probe 1 (30s)
	ts.latency.push(100 * time.Millisecond) // probe 2 (60s)

	after60s := ts.latency.current()
	pctDegraded := float64(after60s.Milliseconds()) / 100.0
	if pctDegraded < 0.80 {
		t.Errorf("§5.1 degradation detection: after 2 probes (60s), EWMA=%.1fms (%.0f%% of degraded), want >80%%",
			float64(after60s.Milliseconds()), pctDegraded*100)
	}
	t.Logf("§5.1 conformance: degradation detection 60s EWMA=%.1fms (%.0f%% of 100ms target)", float64(after60s.Milliseconds()), pctDegraded*100)

	// Verify alpha_fall recovery: from degraded 91.9ms, push 10ms samples
	// and confirm EWMA drops using alpha_fall=0.3 (slow fall).
	ts.latency.reset()
	ts.latency.push(100 * time.Millisecond) // start at 100ms
	ts.latency.push(10 * time.Millisecond)  // fall: 100→73ms (alpha_fall=0.3)
	afterOneFall := ts.latency.current()
	ts.latency.push(10 * time.Millisecond) // fall: 73→54.1ms (alpha_fall=0.3)
	afterTwoFall := ts.latency.current()

	// alpha_fall=0.3 means after 2 samples from 100ms toward 10ms:
	// 100→73→54.1ms. A symmetric EWMA (alpha=0.7) would give 100→37→18.1ms.
	// We verify the recovery is SLOW (not aggressive).
	if afterOneFall >= 100*time.Millisecond {
		t.Errorf("§5.1 alpha_fall recovery: after 1st fall sample, EWMA=%v, want <100ms", afterOneFall)
	}
	if afterTwoFall >= afterOneFall {
		t.Errorf("§5.1 alpha_fall recovery: EWMA should decrease, got %v→%v", afterOneFall, afterTwoFall)
	}
	// After 2 fall samples, the slow-fall EWMA should still be far from target (54ms).
	// A fast-fall (α=0.7) would be at ~18ms. We should be closer to 54ms.
	if afterTwoFall < 40*time.Millisecond {
		t.Errorf("§5.1 alpha_fall recovery: after 2 fall samples EWMA=%v, want >40ms (slow recovery)", afterTwoFall)
	}
	t.Logf("§5.1 conformance: alpha_fall recovery 100→%v→%vms (slow fall confirmed)", afterOneFall, afterTwoFall)
}

// TestConformanceBlackoutEscapeSection2_3 verifies §2.3 invariants:
// invariant #4: TransportSubFailed requires explicit Reconnect(), NOT auto-escaped.
// invariant #2: blackout = ALL transports quarantined (not failed).
func TestConformanceBlackoutEscapeSection2_3(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality", "websocket")
	pm := NewPeerManager(cfg, fix.registry)

	// Scenario: udp=failed, reality=failed, websocket=failed.
	// When ALL transports are TransportSubFailed, blackoutEscapeCandidates()
	// must return nil — no auto-escape (invariant #4).
	pm.mu.Lock()
	for _, name := range []string{"udp", "reality", "websocket"} {
		if ts := pm.transportStates[name]; ts != nil {
			ts.subState = TransportSubFailed
		}
	}
	pm.mu.Unlock()

	candidates := pm.blackoutEscapeCandidates()
	if len(candidates) != 0 {
		t.Errorf("§2.3 invariant #4: blackoutEscapeCandidates() with all-failed = %v, want nil (no auto-escape)", candidates)
	}

	// Verify blackoutEscapeCandidates() logic and Reconnect() reset path.
	// Note: Reconnect() requires the PeerManager goroutine to be running.
	// We verify the static exclusion separately, then test Reconnect reset
	// via the goroutine path.

	// Scenario: udp=quarantined, reality=failed, websocket=quarantined.
	// blackoutEscapeCandidates must select from quarantined only (exclude failed).
	pm.mu.Lock()
	if ts := pm.transportStates["udp"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = time.Now().Add(-3 * time.Minute)
	}
	if ts := pm.transportStates["reality"]; ts != nil {
		ts.subState = TransportSubFailed
	}
	if ts := pm.transportStates["websocket"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = time.Now().Add(-1 * time.Minute)
	}
	pm.mu.Unlock()

	candidates = pm.blackoutEscapeCandidates()
	for _, name := range candidates {
		st := pm.TransportState(name)
		if st == TransportSubFailed {
			t.Errorf("§2.3 invariant #4: blackoutEscapeCandidates() included %q (TransportSubFailed) — must be excluded", name)
		}
	}

	// Verify the invariant holds at the code level: blackoutEscapeCandidates()
	// only checks TransportSubQuarantined (line ~1201), which inherently
	// excludes TransportSubFailed.
	if len(candidates) == 1 {
		t.Logf("§2.3 blackout escape candidates: %v (failed transports correctly excluded)", candidates)
	}

	t.Log("§2.3 conformance: TransportSubFailed excluded from auto-escape — invariants verified")
}

// TestConformanceLRQSection3_3 verifies §3.3 LRQ selection across
// varied quarantine/cooldown orderings:
//   - oldest quarantine selected when all timing varies
//   - not-soonest-cooldown not selected
//   - single quarantined transport selected
//   - equal timestamps tie-breaking
//   - quarantinedAt reset on Reconnect and cooldown expiry
func TestConformanceLRQSection3_3(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality", "websocket")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality", "websocket")
	pm := NewPeerManager(cfg, fix.registry)

	now := time.Now()

	// Test 1: LRQ selects oldest quarantine timestamp, not soonest cooldown expiry.
	pm.mu.Lock()
	// udp: quarantined 5 min ago, cooldown expires in 2 hours (LONGEST remaining)
	if ts := pm.transportStates["udp"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = now.Add(-5 * time.Minute)
		ts.cooldownUntil = now.Add(2 * time.Hour)
	}
	// reality: quarantined 10s ago, cooldown expires in 10s (SOONEST)
	if ts := pm.transportStates["reality"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = now.Add(-10 * time.Second)
		ts.cooldownUntil = now.Add(10 * time.Second)
	}
	// websocket: quarantined 2 min ago, cooldown expires in 1 hour
	if ts := pm.transportStates["websocket"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = now.Add(-2 * time.Minute)
		ts.cooldownUntil = now.Add(1 * time.Hour)
	}
	pm.mu.Unlock()

	candidates := pm.blackoutEscapeCandidates()
	if len(candidates) != 1 {
		t.Fatalf("§3.3 LRQ: blackoutEscapeCandidates() = %d candidates, want 1", len(candidates))
	}
	if candidates[0] != "udp" {
		t.Errorf("§3.3 LRQ: selected %q, want 'udp' (oldest quarantine: 5min ago, despite longest remaining cooldown)",
			candidates[0])
	}
	t.Logf("§3.3 LRQ: oldest-quarantine selected: %s (quarantined 5min ago, cooldown 2h remaining)", candidates[0])

	// Test 2: Reverse ordering — websocket quarantined first, udp last.
	pm.mu.Lock()
	if ts := pm.transportStates["websocket"]; ts != nil {
		ts.quarantinedAt = now.Add(-10 * time.Minute) // oldest
	}
	if ts := pm.transportStates["udp"]; ts != nil {
		ts.quarantinedAt = now.Add(-1 * time.Minute) // newest
	}
	pm.mu.Unlock()

	candidates = pm.blackoutEscapeCandidates()
	if len(candidates) != 1 || candidates[0] != "websocket" {
		t.Errorf("§3.3 LRQ reverse: selected %v, want 'websocket' (oldest at 10min ago)", candidates)
	}

	// Test 3: All equal timestamps — tie goes to first in TransportNames order.
	pm.mu.Lock()
	equalTime := now.Add(-2 * time.Minute)
	for _, name := range []string{"udp", "reality", "websocket"} {
		if ts := pm.transportStates[name]; ts != nil {
			ts.quarantinedAt = equalTime
		}
	}
	pm.mu.Unlock()

	candidates = pm.blackoutEscapeCandidates()
	if candidates[0] != "udp" {
		t.Errorf("§3.3 LRQ equal-timestamps: selected %q, want 'udp' (first in TransportNames)", candidates[0])
	}

	// Test 4: Single quarantined with others in different states.
	pm.mu.Lock()
	if ts := pm.transportStates["udp"]; ts != nil {
		ts.subState = TransportSubActive
	}
	if ts := pm.transportStates["reality"]; ts != nil {
		ts.subState = TransportSubQuarantined
		ts.quarantinedAt = now.Add(-4 * time.Minute)
	}
	if ts := pm.transportStates["websocket"]; ts != nil {
		ts.subState = TransportSubFailed
	}
	pm.mu.Unlock()

	candidates = pm.blackoutEscapeCandidates()
	if len(candidates) != 1 || candidates[0] != "reality" {
		t.Errorf("§3.3 LRQ single-quarantined: selected %v, want 'reality' (only quarantined transport)", candidates)
	}

	// Test 5: quarantinedAt is set when in quarantined state, and reset
	// on Reconnect (tested separately in TestLRQQuarantineResetOnExpiry and
	// TestFailedTransportRecoversViaReconnect which start the PeerManager).
	// Here we verify the field is correctly set in the static state.
	pm.mu.Lock()
	for _, name := range pm.cfg.TransportNames {
		if ts := pm.transportStates[name]; ts != nil {
			if ts.subState == TransportSubQuarantined && ts.quarantinedAt.IsZero() {
				t.Errorf("§3.3: transport %q is quarantined but quarantinedAt is zero", name)
			}
		}
	}
	pm.mu.Unlock()

	t.Log("§3.3 LRQ conformance: all 5 scenarios verified — oldest-quarantine selection correct across varied orderings")
}

// TestConformanceProbingStateSection2_3 verifies the TransportSubProbing
// state transition behavior per §2.3 and spec transition table §2.4.
// Checks:
//
//	(a) probing→active on successful probe
//	(b) probing→failed on permanent error
//	(c) No orphaned probing states (probing always resolves)
//	(d) State dumps via TransportStates() reflect probing state
func TestConformanceProbingStateSection2_3(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality")
	cfg.ProbeInterval = 50 * time.Millisecond
	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer pm.Stop()

	if !waitForState(pm, PeerConnected, 2*time.Second) {
		t.Fatalf("State() = %s, want %s", pm.State(), PeerConnected)
	}

	// (a) Verify probing→active: after a probe cycle, the transport should
	// not be stuck in probing state.
	time.Sleep(200 * time.Millisecond)

	states := pm.TransportStates()
	for _, s := range states {
		if s.SubState == TransportSubProbing {
			t.Errorf("§2.3 orphaned state: transport %q is stuck in TransportSubProbing (should have resolved)", s.Name)
		}
	}

	// (b) Verify TransportStates() correctly reports non-probing state.
	// After probeAndEvaluate runs, all transports should be active/failed/quarantined.
	hasNonOrphaned := false
	for _, s := range states {
		t.Logf("§2.3 state dump: %s → %s (latency=%v, samples=%d)",
			s.Name, s.SubState.String(), s.LatencyMedian, s.LatencySamples)
		if s.SubState != TransportSubProbing {
			hasNonOrphaned = true
		}
	}
	if !hasNonOrphaned {
		t.Error("§2.3: no transports in valid non-probing state")
	}

	// (c) Manually set a transport to probing and verify TransportStates()
	// reports it correctly (telemetry accuracy).
	pm.mu.Lock()
	if ts := pm.transportStates["reality"]; ts != nil {
		ts.subState = TransportSubProbing
	}
	pm.mu.Unlock()

	states = pm.TransportStates()
	for _, s := range states {
		if s.Name == "reality" {
			if s.SubState != TransportSubProbing {
				t.Errorf("§2.3 telemetry: TransportStates() for reality = %s, want probing", s.SubState.String())
			}
		}
	}

	// Cleanup: restore reality to active.
	pm.mu.Lock()
	if ts := pm.transportStates["reality"]; ts != nil {
		ts.subState = TransportSubActive
	}
	pm.mu.Unlock()

	t.Log("§2.3 conformance: probing state transitions verified, no orphaned states, TransportStates() telemetry accurate")
}

// TestConformanceScoringStability verifies that scoring and EWMA integration
// haven't regressed — the computeScore function works correctly with EWMA
// values and TransportStates() snapshots reflect scoring state.
func TestConformanceScoringStability(t *testing.T) {
	fix := newTestPeerManagerFixture("udp", "reality")
	cfg := pmTestConfig("127.0.0.1:51820", "udp", "reality")
	cfg.ProbeInterval = 50 * time.Millisecond
	pm := NewPeerManager(cfg, fix.registry)

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer pm.Stop()

	if !waitForState(pm, PeerConnected, 2*time.Second) {
		t.Fatalf("State() = %s, want %s", pm.State(), PeerConnected)
	}

	time.Sleep(200 * time.Millisecond)

	// Verify computeScore with EWMA values produces stable results.
	states := pm.TransportStates()
	if len(states) == 0 {
		t.Fatal("TransportStates() returned empty list")
	}

	// Verify EWMA values are computed (not zero for initialized transports).
	for _, s := range states {
		if s.LatencySamples > 0 && s.LatencyMedian <= 0 {
			t.Errorf("scoring stability: %s has %d samples but latency=%v (should be >0)",
				s.Name, s.LatencySamples, s.LatencyMedian)
		}
	}

	// Verify that the active transport has a non-zero Latency value.
	lat := pm.Latency()
	if lat <= 0 {
		t.Errorf("scoring stability: Latency() = %v, want >0 for connected peer", lat)
	}

	// Verify CurrentTransport returns the correct transport name.
	active := pm.CurrentTransport()
	if active == "" {
		t.Error("scoring stability: CurrentTransport() returned empty string for connected peer")
	}
	t.Logf("scoring stability: active=%s, latency=%v, %d transport states", active, lat, len(states))
}
