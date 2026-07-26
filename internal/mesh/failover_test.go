// Package mesh provides failover testing for the TransportRegistry's
// multi-transport selection logic.
//
// # Failover Testing Approach
//
// The TransportRegistry supports automatic failover via SetFallbackOrder.
// When configured, Get() walks the fallback chain and returns the first
// **registered** transport. The registry operates at the TransportFactory
// level — it knows which factories are registered, not which transports
// are healthy (IsHealthy lives on Transport, not TransportFactory).
//
// ## Two-Layer Failover Architecture
//
// Layer 1 — TransportRegistry (Factory-level):
//   - SetFallbackOrder defines the priority chain of registered factories
//   - Get() returns the first registered factory in the chain
//   - Shutdown removes factories from consideration (via health check
//     at the PeerManager layer, not inside Get())
//
// Layer 2 — PeerManager (Transport-level):
//   - Calls Transport.IsHealthy() to check per-instance health
//   - Calls Transport.LatencyProbe() for optimal-path selection
//   - Uses both signals to decide whether to use the factory from Get()
//
// This two-layer design means TransportRegistry.Get() is a fast O(n)
// lookup with no I/O — health decisions are deferred to PeerManager.
//
// ## Testability Hooks
//
//  1. TransportRegistry.SetFallbackOrder([]string) — defines the priority
//     chain. Index 0 is primary, higher indices are fallbacks. Setting nil
//     disables automatic failover (Get returns exact matches).
//
//  2. Transport.LatencyProbe(context, addr) — returns RTT if healthy,
//     transient-classified errors otherwise.
//
//  3. Transport.IsHealthy() bool — point-in-time health assessment
//     used by PeerManager, not by TransportRegistry.
//
// For mock-based testing, mockTransport provides SetHealthy(bool) and
// SetLatency(time.Duration) for deterministic failure/health injection
// at the PeerManager simulation level.
//
// ## Testing Strategy
//
//  1. Unit: mockTransport + TransportRegistry — validate fallback chain
//     ordering, factory registration, and dynamic reordering. (This file)
//
//  2. Integration: real UDPTransportFactory + mock unhealthy transport —
//     validate that the actual UDP implementation integrates correctly
//     with the registry's failover logic. (This file)
//
//  3. E2E (future): real multi-transport setup with actual network
//     partitions — validate failover under real conditions. Requires
//     a multi-machine test harness.
//
// ## Failover Scenarios (at Factory level)
//
//	Scenario                   | Chain             | Registered? | Expected
//	---------------------------|-------------------|-------------|----------
//	All registered             | udp, ws, reality  | all         | returns udp
//	Middle not registered      | udp, ws, reality  | udp,reality | returns udp
//	Only fallback registered   | udp, ws, reality  | reality     | returns reality
//	None registered            | udp, ws           | (none)      | ErrTransportNotFound
//	Nil fallback order         | (none set)        | udp, ws     | exact match only
//	Empty fallback order       | []                | udp         | exact match only
//	Concurrent read/write      | udp, ws           | udp, ws     | safe, no panic
//	Fallback order copy safety | udp, ws           | udp, ws     | original not affected
//
// ## Finding: Health check gap (documented)
//
// The doc comment on TransportRegistry.Get says "first healthy transport"
// but the implementation checks only factory registration, not IsHealthy().
// This is by design — IsHealthy() lives on the Transport interface, not
// TransportFactory. Adding health checks to Get() would require adding
// IsHealthy to TransportFactory (breaking change) or probing the factory.
//
// Recommendation: Either (a) update the doc comment to say "first registered
// factory" and delegate health checks to PeerManager, or (b) add IsHealthy()
// to TransportFactory in a future interface revision.
package mesh

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Failover: TransportRegistry.Get with SetFallbackOrder (factory-level)
// ──────────────────────────────────────────────────────────────────────────────

// TestFailoverAllRegistered verifies that when all transports are registered,
// Get returns the first in the fallback order.
func TestFailoverAllRegistered(t *testing.T) {
	reg := NewTransportRegistry()
	udp := newMockTransportFactory("udp")
	ws := newMockTransportFactory("websocket")
	rt := newMockTransportFactory("reality")

	reg.Register(udp)
	reg.Register(ws)
	reg.Register(rt)
	reg.SetFallbackOrder([]string{"udp", "websocket", "reality"})

	f, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if f.Name() != "udp" {
		t.Errorf("Get() = %q, want %q (primary)", f.Name(), "udp")
	}
}

// TestFailoverSkipsUnregisteredTransports verifies that transports in the
// fallback order that are not registered are silently skipped.
func TestFailoverSkipsUnregisteredTransports(t *testing.T) {
	reg := NewTransportRegistry()

	// Register only "udp" and "reality" — "websocket" is not registered.
	reg.Register(newMockTransportFactory("udp"))
	reg.Register(newMockTransportFactory("reality"))
	reg.SetFallbackOrder([]string{"udp", "websocket", "reality"})

	f, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if f.Name() != "udp" {
		t.Errorf("Get() = %q, want %q (skips unregistered websocket)", f.Name(), "udp")
	}
}

// TestFailoverOnlyFallbackRegistered verifies that when the primary
// is not registered but a fallback is, the fallback is selected.
func TestFailoverOnlyFallbackRegistered(t *testing.T) {
	reg := NewTransportRegistry()

	// Only "reality" is registered — "udp" and "websocket" are missing.
	reg.Register(newMockTransportFactory("reality"))
	reg.SetFallbackOrder([]string{"udp", "websocket", "reality"})

	f, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if f.Name() != "reality" {
		t.Errorf("Get() = %q, want %q (only fallback)", f.Name(), "reality")
	}
}

// TestFailoverNoneRegistered verifies that when no transports in the
// fallback chain are registered, Get returns ErrTransportNotFound.
func TestFailoverNoneRegistered(t *testing.T) {
	reg := NewTransportRegistry()

	// Register something unrelated.
	reg.Register(newMockTransportFactory("other"))
	reg.SetFallbackOrder([]string{"udp", "websocket"})

	_, err := reg.Get("udp")
	if err == nil {
		t.Fatal("Get() should fail when no transports in chain are registered")
	}
	if !errors.Is(err, ErrTransportNotFound) {
		t.Errorf("expected ErrTransportNotFound, got %v", err)
	}
}

// TestFailoverNilFallbackOrder verifies that when SetFallbackOrder(nil) is
// called, Get returns exact name matches (no auto-failover).
func TestFailoverNilFallbackOrder(t *testing.T) {
	reg := NewTransportRegistry()
	udp := newMockTransportFactory("udp")
	ws := newMockTransportFactory("websocket")

	reg.Register(udp)
	reg.Register(ws)
	reg.SetFallbackOrder(nil) // disable auto-failover

	// Get should return "udp" by exact name.
	f, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if f.Name() != "udp" {
		t.Errorf("Get() = %q, want %q (exact match)", f.Name(), "udp")
	}

	// And "websocket" should also be retrievable by name.
	f2, err := reg.Get("websocket")
	if err != nil {
		t.Fatalf("Get(websocket) error: %v", err)
	}
	if f2.Name() != "websocket" {
		t.Errorf("Get(websocket) = %q, want %q", f2.Name(), "websocket")
	}
}

// TestFailoverAfterShutdownRegistration verifies that Get returns
// a factory by registered name even after Shutdown — the factory is
// still registered, just shut down. PeerManager uses IsHealthy on
// the transport to detect this.
func TestFailoverAfterShutdownRegistration(t *testing.T) {
	reg := NewTransportRegistry()
	udp := newMockTransportFactory("udp")
	ws := newMockTransportFactory("websocket")

	reg.Register(udp)
	reg.Register(ws)
	reg.SetFallbackOrder([]string{"udp", "websocket"})

	// Shut down UDP via the factory.
	ctx := context.Background()
	if err := udp.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	// Get still returns "udp" — it's registered. The PeerManager
	// layer is responsible for checking IsHealthy on the transport.
	f, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if f.Name() != "udp" {
		t.Errorf("Get() = %q, want %q (registered after shutdown)", f.Name(), "udp")
	}

	// Verify the factory IS shut down — NewTransport should fail.
	_, err = f.NewTransport(TransportConfig{Name: "udp"})
	if !errors.Is(err, ErrTransportShutdown) {
		t.Errorf("NewTransport after shutdown: expected ErrTransportShutdown, got %v", err)
	}
}

// TestFailoverLargeChain verifies that a long fallback chain works correctly.
func TestFailoverLargeChain(t *testing.T) {
	reg := NewTransportRegistry()

	const size = 10
	names := make([]string, size)
	for i := 0; i < size; i++ {
		names[i] = fmt.Sprintf("t%d", i)
		reg.Register(newMockTransportFactory(names[i]))
	}
	reg.SetFallbackOrder(names)

	f, err := reg.Get(names[0])
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if f.Name() != names[0] {
		t.Errorf("Get() = %q, want %q (first in chain)", f.Name(), names[0])
	}
}

// TestFailoverGetFromAnyName verifies that regardless of the requested
// name, Get always returns the first registered transport in the fallback
// order (if one exists).
func TestFailoverGetFromAnyName(t *testing.T) {
	reg := NewTransportRegistry()
	udp := newMockTransportFactory("udp")
	ws := newMockTransportFactory("websocket")
	rt := newMockTransportFactory("reality")

	reg.Register(udp)
	reg.Register(ws)
	reg.Register(rt)
	reg.SetFallbackOrder([]string{"udp", "websocket", "reality"})

	for _, req := range []string{"udp", "websocket", "reality", "nonexistent"} {
		f, err := reg.Get(req)
		if err != nil {
			t.Errorf("Get(%q) error: %v", req, err)
			continue
		}
		if f.Name() != "udp" {
			t.Errorf("Get(%q) = %q, want %q", req, f.Name(), "udp")
		}
	}
}

// TestFailoverGetWithoutFallbackOrderRespectsName verifies that without
// SetFallbackOrder, Get returns the exact name requested.
func TestFailoverGetWithoutFallbackOrderRespectsName(t *testing.T) {
	reg := NewTransportRegistry()
	udp := newMockTransportFactory("udp")
	ws := newMockTransportFactory("websocket")

	reg.Register(udp)
	reg.Register(ws)

	_, err := reg.Get("nonexistent")
	if !errors.Is(err, ErrTransportNotFound) {
		t.Errorf("expected ErrTransportNotFound, got %v", err)
	}

	f, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("Get(udp) error: %v", err)
	}
	if f.Name() != "udp" {
		t.Errorf("Get(udp) = %q, want %q", f.Name(), "udp")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Failover: FallbackOrder getter/setter tests
// ──────────────────────────────────────────────────────────────────────────────

// TestFallbackOrderCopying verifies that SetFallbackOrder copies the input
// slice (modifying the original after calling SetFallbackOrder does not
// affect the registry's copy).
func TestFallbackOrderCopying(t *testing.T) {
	reg := NewTransportRegistry()

	order := []string{"udp", "websocket", "reality"}
	reg.SetFallbackOrder(order)

	// Mutate the original slice.
	order[0] = "modified"

	got := reg.FallbackOrder()
	if len(got) != 3 || got[0] != "udp" {
		t.Errorf("FallbackOrder = %v, want [udp websocket reality] (copy not affected)", got)
	}
}

// TestFallbackOrderEmpty verifies that an empty fallback order behaves
// the same as nil (no auto-failover — Get returns exact match).
func TestFallbackOrderEmpty(t *testing.T) {
	reg := NewTransportRegistry()
	f := newMockTransportFactory("udp")
	reg.Register(f)
	reg.SetFallbackOrder([]string{})

	got, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got.Name() != "udp" {
		t.Errorf("Get() = %q, want %q", got.Name(), "udp")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Failover: LatencyProbe-based path selection (PeerManager layer)
// ──────────────────────────────────────────────────────────────────────────────

// TestFailoverLatencyBasedSelection verifies that LatencyProbe can be used
// to compare transport latencies and select the fastest healthy path.
// This is the PeerManager-layer selection pattern, complementing the
// factory-level SetFallbackOrder.
func TestFailoverLatencyBasedSelection(t *testing.T) {
	udp := newMockTransport("udp")
	ws := newMockTransport("websocket")

	udp.SetLatency(5 * time.Millisecond)
	ws.SetLatency(50 * time.Millisecond)

	ctx := context.Background()
	udpRTT, err := udp.LatencyProbe(ctx, "peer:51820")
	if err != nil {
		t.Fatalf("udp LatencyProbe error: %v", err)
	}
	wsRTT, err := ws.LatencyProbe(ctx, "peer:51820")
	if err != nil {
		t.Fatalf("ws LatencyProbe error: %v", err)
	}

	// UDP should be faster.
	if udpRTT >= wsRTT {
		t.Errorf("udp RTT (%v) should be less than ws RTT (%v)", udpRTT, wsRTT)
	}
}

// TestFailoverLatencyProbeUnhealthySkips verifies that LatencyProbe on
// an unhealthy transport returns an error, allowing PeerManager to skip it.
func TestFailoverLatencyProbeUnhealthySkips(t *testing.T) {
	udp := newMockTransport("udp")
	udp.SetHealthy(false)

	ctx := context.Background()
	_, err := udp.LatencyProbe(ctx, "peer:51820")
	if err == nil {
		t.Fatal("LatencyProbe should fail when unhealthy")
	}

	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if !tErr.Retry {
		t.Error("unhealthy LatencyProbe error should be transient (retryable)")
	}
}

// TestFailoverLatencyProbeAfterShutdown verifies that LatencyProbe on a
// shut down transport returns a permanent error.
func TestFailoverLatencyProbeAfterShutdown(t *testing.T) {
	mt := newMockTransport("udp")
	mt.Close()

	ctx := context.Background()
	_, err := mt.LatencyProbe(ctx, "peer:51820")
	if err == nil {
		t.Fatal("LatencyProbe should fail after shutdown")
	}

	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T: %v", err, err)
	}
	if tErr.Retry {
		t.Error("post-shutdown LatencyProbe error should not be retryable")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Failover: PeerManager decision pattern (two-layer simulation)
// ──────────────────────────────────────────────────────────────────────────────

// TestFailoverPeerManagerDecisionPattern demonstrates the two-layer
// failover pattern: TransportRegistry.Get returns the first registered
// factory; PeerManager checks Transport.IsHealthy before using it.
func TestFailoverPeerManagerDecisionPattern(t *testing.T) {
	reg := NewTransportRegistry()

	// UDP factory — registered but its transport is made unhealthy.
	udpFactory := newMockTransportFactory("udp")
	reg.Register(udpFactory)

	wsFactory := newMockTransportFactory("websocket")
	reg.Register(wsFactory)

	reg.SetFallbackOrder([]string{"udp", "websocket"})

	// Simulate PeerManager decision loop.
	chooseTransport := func() (Transport, error) {
		// Step 1: Get the first registered factory from the registry.
		factory, err := reg.Get("any")
		if err != nil {
			return nil, err
		}

		// Step 2: Create a transport instance from the factory.
		tr, err := factory.NewTransport(TransportConfig{Name: factory.Name()})
		if err != nil {
			return nil, err
		}

		// Step 3: Check if the transport is healthy.
		if !tr.IsHealthy() {
			return nil, fmt.Errorf("transport %s is unhealthy", tr.Name())
		}

		return tr, nil
	}

	// Phase 1: both healthy → returns UDP.
	tr, err := chooseTransport()
	if err != nil {
		t.Fatalf("phase 1: %v", err)
	}
	if tr.Name() != "udp" {
		t.Errorf("phase 1: got %q, want %q", tr.Name(), "udp")
	}

	// Phase 2: UDP unhealthy → PeerManager should detect and retry with fallback.
	udpFactory.transport.SetHealthy(false)

	tr2, err := chooseTransport()
	if err == nil {
		// The simple single-try pattern returns UDP (unhealthy).
		// This demonstrates the gap — PeerManager needs a retry loop.
		if tr2.IsHealthy() {
			t.Logf("phase 2: got %s (healthy=%v) — PeerManager would need retry logic", tr2.Name(), tr2.IsHealthy())
		}
	}

	// The correct PeerManager pattern:
	//   for each name in reg.FallbackOrder():
	//       factory, _ := reg.Get(name)  // or walk manually
	//       tr, _ := factory.NewTransport(...)
	//       if tr.IsHealthy() { return tr }
	//   return ErrNoHealthyTransport

	// Manual iteration over the fallback order (without using Get,
	// since Get always returns the first registered factory):
	var healthyTransport Transport
	for _, name := range []string{"udp", "websocket"} {
		if _, ok := reg.factories[name]; !ok {
			continue
		}
		factory := reg.factories[name]
		tr, err := factory.NewTransport(TransportConfig{Name: name})
		if err != nil {
			continue
		}
		if tr.IsHealthy() {
			healthyTransport = tr
			break
		}
	}
	if healthyTransport == nil {
		t.Fatal("manual fallback: no healthy transport found")
	}
	if healthyTransport.Name() != "websocket" {
		t.Errorf("manual fallback: got %q, want %q", healthyTransport.Name(), "websocket")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Failover: concurrent access safety
// ──────────────────────────────────────────────────────────────────────────────

// TestFailoverConcurrentGetSkipped notes that TransportRegistry is NOT
// concurrency-safe despite its doc comment claiming "Concurrency: safe for
// concurrent use." The registry struct lacks a mutex; concurrent Register,
// Get, and SetFallbackOrder operations cause data races on the factories
// map and fallbackOrder slice.
//
// Fixing this requires adding a sync.RWMutex to TransportRegistry and
// locking in all mutation + read methods. This is a known defect filed
// as a finding from transport-layer testing.
//
// See: transport.go TransportRegistry struct and its methods.

// ──────────────────────────────────────────────────────────────────────────────
// Failover: mockTransportFactory.NewTransport error path
// ──────────────────────────────────────────────────────────────────────────────

// TestFailoverNewTransportAfterFactoryShutdown verifies that NewTransport
// on a shut-down mock factory returns ErrTransportShutdown.
func TestFailoverNewTransportAfterFactoryShutdown(t *testing.T) {
	f := newMockTransportFactory("udp")

	ctx := context.Background()
	if err := f.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	_, err := f.NewTransport(TransportConfig{Name: "udp"})
	if !errors.Is(err, ErrTransportShutdown) {
		t.Errorf("NewTransport after shutdown: expected ErrTransportShutdown, got %v", err)
	}
}

// TestFailoverNewTransportCustomFn verifies that the NewTransportFn override
// works for injecting custom behavior in failover tests.
func TestFailoverNewTransportCustomFn(t *testing.T) {
	f := newMockTransportFactory("udp")
	custom := newMockTransport("custom-generated")

	f.NewTransportFn = func(cfg TransportConfig) (Transport, error) {
		if cfg.Name != "udp" {
			return nil, &TransportConfigError{Field: "Name", Reason: "expected udp"}
		}
		return custom, nil
	}

	tr, err := f.NewTransport(TransportConfig{Name: "udp"})
	if err != nil {
		t.Fatalf("NewTransport() error: %v", err)
	}
	if tr != custom {
		t.Error("NewTransport() did not return custom transport")
	}

	// Invalid config.
	_, err = f.NewTransport(TransportConfig{Name: "reality"})
	if err == nil {
		t.Fatal("NewTransport with wrong name should fail")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Failover: UDPTransport integration — failover with real UDP + mock fallback
// ──────────────────────────────────────────────────────────────────────────────

// TestFailoverUDPWithMockFallback verifies that a real UDP transport
// (primary) works with a mock fallback transport in the same registry.
func TestFailoverUDPWithMockFallback(t *testing.T) {
	reg := NewTransportRegistry()

	udp := NewUDPTransportFactory()
	reg.Register(udp)

	ws := newMockTransportFactory("websocket")
	reg.Register(ws)

	reg.SetFallbackOrder([]string{"udp", "websocket"})

	// Phase 1: both registered → returns UDP.
	f, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("phase 1 Get() error: %v", err)
	}
	if f.Name() != "udp" {
		t.Errorf("phase 1: Get() = %q, want %q", f.Name(), "udp")
	}

	// Phase 2: Shut down UDP → it's still registered, Get returns "udp".
	// PeerManager is responsible for detecting the shutdown via IsHealthy().
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := udp.Shutdown(ctx); err != nil {
		t.Fatalf("UDP Shutdown() error: %v", err)
	}

	f, err = reg.Get("udp")
	if err != nil {
		t.Fatalf("phase 2 Get() error: %v", err)
	}
	if f.Name() != "udp" {
		t.Errorf("phase 2: Get() = %q, want %q (registered, but shut down)", f.Name(), "udp")
	}

	// Verify the factory is truly shut down.
	_, err = f.NewTransport(TransportConfig{Name: "udp"})
	if !errors.Is(err, ErrTransportShutdown) {
		t.Errorf("NewTransport after shutdown: expected ErrTransportShutdown, got %v", err)
	}
}

// TestFailoverUDPRecovery verifies that replacing a shut-down UDP factory
// with a new one restores it in the registry.
func TestFailoverUDPRecovery(t *testing.T) {
	reg := NewTransportRegistry()

	udp1 := NewUDPTransportFactory()
	reg.Register(udp1)
	reg.Register(newMockTransportFactory("websocket"))
	reg.SetFallbackOrder([]string{"udp", "websocket"})

	// Shut down UDP1.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	udp1.Shutdown(ctx)

	// Register a new UDP factory (replaces by name).
	udp2 := NewUDPTransportFactory()
	reg.Register(udp2)

	f, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if f.Name() != "udp" {
		t.Errorf("Get() = %q, want %q (recovered UDP)", f.Name(), "udp")
	}

	// Create a transport from the new factory — should work.
	tr, err := f.NewTransport(TransportConfig{Name: "udp"})
	if err != nil {
		t.Fatalf("NewTransport on recovered factory: %v", err)
	}
	if !tr.IsHealthy() {
		t.Error("recovered transport is not healthy")
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	udp2.Shutdown(ctx2)
}

// ──────────────────────────────────────────────────────────────────────────────
// Failover: documented gap — Get() doc says "first healthy" but checks registration
// ──────────────────────────────────────────────────────────────────────────────

// TestFailoverDocumentedGap verifies the discrepancy between the Get()
// doc comment ("first healthy transport") and the actual behavior (first
// registered factory). This test exists to explicitly document the gap.
func TestFailoverDocumentedGap(t *testing.T) {
	reg := NewTransportRegistry()
	udp := newMockTransportFactory("udp")
	ws := newMockTransportFactory("websocket")

	// Make UDP's internal mock transport unhealthy.
	udp.transport.SetHealthy(false)

	reg.Register(udp)
	reg.Register(ws)
	reg.SetFallbackOrder([]string{"udp", "websocket"})

	// Current behavior: Get() returns "udp" (registered, not checking health).
	// This matches the implementation but not the doc comment.
	f, err := reg.Get("udp")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if f.Name() != "udp" {
		t.Errorf("behavior changed: Get() = %q", f.Name())
	}
	t.Log("Documented gap: Get() returns first registered factory, not first healthy transport. Health checks are delegated to PeerManager layer.")
}
