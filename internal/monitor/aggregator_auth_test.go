package monitor

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/config"
)

// mockMonitorAuthChecker is a test AuthChecker that allows/denies
// based on a preset map. It is safe for concurrent use.
type mockMonitorAuthChecker struct {
	mu           sync.Mutex
	allowedPeers map[string]bool
	called       bool
}

func (m *mockMonitorAuthChecker) AuthorizeMonitorWrite(sourcePeer string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.called = true
	return m.allowedPeers[sourcePeer]
}

func (m *mockMonitorAuthChecker) wasCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.called
}

// TestAggregatorRejectsUnauthorizedPush verifies that the aggregator
// with an auth checker rejects metric pushes from peers without the
// monitor_write capability.
func TestAggregatorRejectsUnauthorizedPush(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	checker := &mockMonitorAuthChecker{
		allowedPeers: map[string]bool{
			"authorized-agent": true,
			// "unauthorized-agent" is NOT in the map
		},
	}

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4201,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	// Push metrics from an unauthorized peer
	env := &MetricEnvelope{
		SourceID: "unauthorized-agent",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "unauthorized-agent",
			Hostname:  "host",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 50.0, CoreCount: 4},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4201)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	// Write in goroutine — net.Pipe is synchronous
	go func() {
		WriteEnvelope(conn, env)
	}()

	// Give the aggregator time to process
	time.Sleep(500 * time.Millisecond)

	// Verify auth checker was called
	if !checker.wasCalled() {
		t.Error("expected auth checker to be called")
	}

	// Verify metrics were NOT stored
	latest := store.Latest("unauthorized-agent")
	if latest != nil {
		t.Error("metrics from unauthorized peer should not be stored")
	}
}

// TestAggregatorAcceptsAuthorizedPush verifies that the aggregator
// with an auth checker accepts metric pushes from authorized peers.
func TestAggregatorAcceptsAuthorizedPush(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	checker := &mockMonitorAuthChecker{
		allowedPeers: map[string]bool{
			"authorized-agent": true,
		},
	}

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4202,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: "authorized-agent",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "authorized-agent",
			Hostname:  "host",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 42.0, CoreCount: 8},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4202)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	go func() {
		WriteEnvelope(conn, env)
	}()

	time.Sleep(500 * time.Millisecond)

	// Verify auth checker was called
	if !checker.wasCalled() {
		t.Error("expected auth checker to be called")
	}

	// Verify metrics WERE stored
	latest := store.Latest("authorized-agent")
	if latest == nil {
		t.Fatal("metrics from authorized peer should be stored")
	}
	if latest.CPU.UsagePercent != 42.0 {
		t.Errorf("CPU = %f, want 42.0", latest.CPU.UsagePercent)
	}
}

// TestAggregatorNilAuthCheckerAcceptsAll verifies that a nil auth checker
// (testing mode) accepts all pushes.
func TestAggregatorNilAuthCheckerAcceptsAll(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	agg := NewAggregator(AggregatorConfig{
		Store:  store,
		Dialer: mesh,
		Port:   4203,
		// no AuthChecker — nil
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: "any-agent",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "any-agent",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 10.0},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4203)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	go func() {
		WriteEnvelope(conn, env)
	}()

	time.Sleep(500 * time.Millisecond)

	latest := store.Latest("any-agent")
	if latest == nil {
		t.Fatal("nil auth checker should accept all pushes")
	}
}

// --- Integration tests using real MonitorAuthChecker (auth.CapabilityEngine) ---
//
// These tests verify the re-enable of the monitor auth checker: instead of
// a trivial mock, they inject the real auth.MonitorAuthChecker backed by
// CapabilityEngine into the aggregator and verify that:
//   1. Peers with monitor_write capability are authorized → pushes accepted.
//   2. Peers without monitor_write capability are denied → pushes dropped.
//   3. Revoked peers are denied → pushes dropped.
//   4. Concurrent pushes from mixed authorized/unauthorized peers are handled correctly.

// newRealMonitorAuthChecker creates a MonitorAuthChecker backed by
// CapabilityEngine with the given authorized peers.
func newRealMonitorAuthChecker(authorizedPeers ...string) *auth.MonitorAuthChecker {
	cfg := &config.Config{}
	for _, pk := range authorizedPeers {
		cfg.Peers = append(cfg.Peers, config.PeerConfig{
			PublicKey:    pk,
			Capabilities: []string{auth.CapMonitorWrite},
		})
	}
	engine := auth.NewCapabilityEngine(cfg, auth.NewAuditLogger(nil))
	return auth.NewMonitorAuthChecker(engine)
}

// TestAggregatorWithRealAuthChecker_AuthorizedPeerAccepted verifies that
// the real MonitorAuthChecker (backed by CapabilityEngine) allows pushes
// from peers with the monitor_write capability.
func TestAggregatorWithRealAuthChecker_AuthorizedPeerAccepted(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	checker := newRealMonitorAuthChecker("authorized-agent-real")

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4211,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: "authorized-agent-real",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "authorized-agent-real",
			Hostname:  "real-authorized",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 55.0, CoreCount: 4},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4211)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	go func() {
		WriteEnvelope(conn, env)
	}()

	time.Sleep(500 * time.Millisecond)

	latest := store.Latest("authorized-agent-real")
	if latest == nil {
		t.Fatal("metrics from authorized peer should be stored (real checker)")
	}
	if latest.CPU.UsagePercent != 55.0 {
		t.Errorf("CPU = %f, want 55.0", latest.CPU.UsagePercent)
	}
}

// TestAggregatorWithRealAuthChecker_UnauthorizedPeerDropped verifies that
// the real MonitorAuthChecker rejects pushes from peers that are NOT in
// the capability engine (unknown peers).
func TestAggregatorWithRealAuthChecker_UnauthorizedPeerDropped(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	checker := newRealMonitorAuthChecker("legit-agent-only")

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4212,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: "intruder-agent",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "intruder-agent",
			Hostname:  "intruder",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 99.0, CoreCount: 1},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4212)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	go func() {
		WriteEnvelope(conn, env)
	}()

	time.Sleep(500 * time.Millisecond)

	latest := store.Latest("intruder-agent")
	if latest != nil {
		t.Error("metrics from unknown peer should NOT be stored (real checker)")
	}
}

// TestAggregatorWithRealAuthChecker_MonitorReadNotEnough verifies that a
// peer with the monitor_read capability but NOT monitor_write is still
// rejected for metric pushes. push != read.
func TestAggregatorWithRealAuthChecker_MonitorReadNotEnough(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	// This peer has monitor_read but NOT monitor_write
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:    "readonly-peer",
				Capabilities: []string{auth.CapMonitorRead},
			},
		},
	}
	engine := auth.NewCapabilityEngine(cfg, auth.NewAuditLogger(nil))
	checker := auth.NewMonitorAuthChecker(engine)

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4213,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: "readonly-peer",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "readonly-peer",
			Hostname:  "readonly",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 30.0, CoreCount: 2},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4213)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	go func() {
		WriteEnvelope(conn, env)
	}()

	time.Sleep(500 * time.Millisecond)

	latest := store.Latest("readonly-peer")
	if latest != nil {
		t.Error("monitor_read should NOT grant monitor_write — push must be dropped")
	}
}

// TestAggregatorWithRealAuthChecker_RevokedPeerDropped verifies that
// after a peer is revoked, its pushes are dropped even if it previously
// had the monitor_write capability.
func TestAggregatorWithRealAuthChecker_RevokedPeerDropped(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:    "to-be-revoked-peer",
				Capabilities: []string{auth.CapMonitorWrite},
			},
		},
	}
	engine := auth.NewCapabilityEngine(cfg, auth.NewAuditLogger(nil))
	checker := auth.NewMonitorAuthChecker(engine)

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4214,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	// Revoke the peer that otherwise has monitor_write
	engine.Revoke("to-be-revoked-peer", "admin", "sig", "compromised")

	env := &MetricEnvelope{
		SourceID: "to-be-revoked-peer",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "to-be-revoked-peer",
			Hostname:  "revoked",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 80.0, CoreCount: 8},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4214)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	go func() {
		WriteEnvelope(conn, env)
	}()

	time.Sleep(500 * time.Millisecond)

	latest := store.Latest("to-be-revoked-peer")
	if latest != nil {
		t.Error("revoked peer's push should be dropped even with monitor_write grant")
	}
}

// TestAggregatorWithRealAuthChecker_ConcurrentMixedPushes verifies that
// when multiple peers push (sequentially for reliability), only authorized
// ones are accepted and unauthorized ones are dropped.
func TestAggregatorWithRealAuthChecker_ConcurrentMixedPushes(t *testing.T) {
	peers := []struct {
		id         string
		authorized bool
	}{
		{"peer-A", true},
		{"peer-B", false},
		{"peer-C", true},
		{"peer-D", false},
		{"peer-E", true},
		{"peer-F", false},
	}

	mesh := NewInProcMesh()

	for _, p := range peers {
		t.Run(p.id, func(t *testing.T) {
			store := NewStore()
			checker := newRealMonitorAuthChecker("peer-A", "peer-C", "peer-E")
			port := 4230 + len(p.id)%5

			agg := NewAggregator(AggregatorConfig{
				Store:       store,
				Dialer:      mesh,
				Port:        port,
				AuthChecker: checker,
			})
			if err := agg.Start(); err != nil {
				t.Fatalf("%s: Aggregator Start: %v", p.id, err)
			}
			defer agg.Stop()

			env := &MetricEnvelope{
				SourceID: p.id,
				Sequence: 1,
				Metrics: &Metrics{
					NodeID:    p.id,
					Timestamp: time.Now().UTC(),
					CPU:       CPUMetrics{UsagePercent: 42.0},
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := mesh.DialMesh(ctx, p.id, port)
			if err != nil {
				t.Fatalf("DialMesh: %v", err)
			}
			defer conn.Close()

			go func() {
				WriteEnvelope(conn, env)
			}()

			time.Sleep(500 * time.Millisecond)

			latest := store.Latest(p.id)
			if p.authorized && latest == nil {
				t.Errorf("%s: authorized peer should have metrics stored", p.id)
			}
			if !p.authorized && latest != nil {
				t.Errorf("%s: unauthorized peer should NOT have metrics stored", p.id)
			}
		})
	}
}

// TestAggregatorWithRealAuthChecker_AuditTrail verifies that the real
// MonitorAuthChecker produces audit log entries for both allow and deny
// decisions when used with the aggregator.
func TestAggregatorWithRealAuthChecker_AuditTrail(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()
	var auditBuf bytes.Buffer

	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:    "audit-authorized",
				Capabilities: []string{auth.CapMonitorWrite},
			},
		},
	}
	engine := auth.NewCapabilityEngine(cfg, auth.NewAuditLogger(&auditBuf))
	checker := auth.NewMonitorAuthChecker(engine)

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4215,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	// Push from authorized peer
	doPush := func(peerID string) {
		env := &MetricEnvelope{
			SourceID: peerID,
			Sequence: 1,
			Metrics: &Metrics{
				NodeID:    peerID,
				Timestamp: time.Now().UTC(),
				CPU:       CPUMetrics{UsagePercent: 1.0},
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := mesh.DialMesh(ctx, peerID, 4215)
		if err != nil {
			return
		}
		defer conn.Close()
		go func() {
			WriteEnvelope(conn, env)
		}()
		time.Sleep(300 * time.Millisecond)
	}

	doPush("audit-authorized") // should be allowed
	doPush("audit-intruder")   // should be denied

	agg.Stop()
	time.Sleep(100 * time.Millisecond)

	// Audit log should have entries
	entries := auditBuf.String()
	if entries == "" {
		t.Fatal("expected audit log entries, got empty")
	}

	// Should contain at least one "allow" and one "deny"
	if !bytes.Contains(auditBuf.Bytes(), []byte(`"allow"`)) {
		t.Error("audit log should contain at least one allow entry")
	}
	if !bytes.Contains(auditBuf.Bytes(), []byte(`"deny"`)) {
		t.Error("audit log should contain at least one deny entry")
	}
}

// --- Integration tests using MeshIdentityAuthChecker ---
//
// These tests wire the MeshIdentityAuthChecker (the v2 mesh-identity-based
// authorization) into the Aggregator and verify the full end-to-end path:
//   reporter push → aggregator AuthorizeMonitorWrite → accept/reject
//
// The MeshIdentityAuthChecker authorizes peers based on routing table
// membership (plus self-push), without requiring explicit capability
// grants in config.yaml. This is the production path used in main.go.

// TestAggregatorWithMeshIdentityChecker_SelfPushAccepted verifies that
// the local node's self-push is always accepted, even when the routing
// table contains no other peers.
func TestAggregatorWithMeshIdentityChecker_SelfPushAccepted(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	localPubkey := "local-node-pubkey"
	knownPeers := map[string]bool{} // empty routing table — no other peers

	checker := auth.NewMeshIdentityAuthChecker(
		localPubkey,
		func(peerID string) bool { return knownPeers[peerID] },
		nil,
	)

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4301,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: localPubkey, // self-push
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    localPubkey,
			Hostname:  "local-node",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 25.0, CoreCount: 4},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4301)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	go func() {
		WriteEnvelope(conn, env)
	}()

	time.Sleep(500 * time.Millisecond)

	latest := store.Latest(localPubkey)
	if latest == nil {
		t.Fatal("self-push should be accepted by MeshIdentityAuthChecker")
	}
	if latest.CPU.UsagePercent != 25.0 {
		t.Errorf("CPU = %f, want 25.0", latest.CPU.UsagePercent)
	}
}

// TestAggregatorWithMeshIdentityChecker_KnownPeerAccepted verifies that
// a peer present in the routing table is authorized to push metrics.
// This is the core production scenario: mesh members push to the aggregator
// and are authorized by routing table membership.
func TestAggregatorWithMeshIdentityChecker_KnownPeerAccepted(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	localPubkey := "aggregator-node"
	knownPeers := map[string]bool{
		"reporter-node-abc": true,
		"reporter-node-xyz": true,
	}

	checker := auth.NewMeshIdentityAuthChecker(
		localPubkey,
		func(peerID string) bool { return knownPeers[peerID] },
		nil,
	)

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4302,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: "reporter-node-abc", // in routing table
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "reporter-node-abc",
			Hostname:  "reporter-abc",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 60.0, CoreCount: 8},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4302)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	go func() {
		WriteEnvelope(conn, env)
	}()

	time.Sleep(500 * time.Millisecond)

	latest := store.Latest("reporter-node-abc")
	if latest == nil {
		t.Fatal("known mesh peer (in routing table) should be accepted")
	}
	if latest.CPU.UsagePercent != 60.0 {
		t.Errorf("CPU = %f, want 60.0", latest.CPU.UsagePercent)
	}
	if latest.Hostname != "reporter-abc" {
		t.Errorf("Hostname = %q, want \"reporter-abc\"", latest.Hostname)
	}
}

// TestAggregatorWithMeshIdentityChecker_UnknownPeerRejected verifies that
// a peer NOT in the routing table is rejected (fail-closed). This is the
// zero-trust behavior: only mesh members can push monitoring data.
func TestAggregatorWithMeshIdentityChecker_UnknownPeerRejected(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	localPubkey := "aggregator-node"
	knownPeers := map[string]bool{
		"trusted-peer": true,
	}

	checker := auth.NewMeshIdentityAuthChecker(
		localPubkey,
		func(peerID string) bool { return knownPeers[peerID] },
		nil,
	)

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4303,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	env := &MetricEnvelope{
		SourceID: "intruder-peer", // NOT in routing table
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "intruder-peer",
			Hostname:  "intruder",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 99.0, CoreCount: 1},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mesh.DialMesh(ctx, "test", 4303)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn.Close()

	go func() {
		WriteEnvelope(conn, env)
	}()

	time.Sleep(500 * time.Millisecond)

	latest := store.Latest("intruder-peer")
	if latest != nil {
		t.Error("unknown peer (not in routing table) should be rejected")
	}

	// Sanity: trusted-peer should still be accepted (the checker is
	// not broken by the intruder attempt).
	env2 := &MetricEnvelope{
		SourceID: "trusted-peer",
		Sequence: 1,
		Metrics: &Metrics{
			NodeID:    "trusted-peer",
			Timestamp: time.Now().UTC(),
			CPU:       CPUMetrics{UsagePercent: 33.0},
		},
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	conn2, err := mesh.DialMesh(ctx2, "test", 4303)
	if err != nil {
		t.Fatalf("DialMesh: %v", err)
	}
	defer conn2.Close()

	go func() {
		WriteEnvelope(conn2, env2)
	}()

	time.Sleep(500 * time.Millisecond)

	latest2 := store.Latest("trusted-peer")
	if latest2 == nil {
		t.Error("trusted peer should still be accepted after intruder attempt")
	}
}

// TestAggregatorWithMeshIdentityChecker_DynamicRoutingTable verifies
// the full dynamic tracking path: a peer is accepted while present in
// the routing table, then rejected after removal, then accepted again
// after re-addition. This proves the checker re-evaluates routing table
// membership on every push — no stale caching.
func TestAggregatorWithMeshIdentityChecker_DynamicRoutingTable(t *testing.T) {
	mesh := NewInProcMesh()

	localPubkey := "aggregator-node"
	peers := map[string]bool{
		"dynamic-peer": true,
		"stable-peer":  true,
	}

	checker := auth.NewMeshIdentityAuthChecker(
		localPubkey,
		func(peerID string) bool { return peers[peerID] },
		nil,
	)

	pushAndCheck := func(sourceID string, port int, expectStored bool) {
		t.Helper()
		store := NewStore()
		agg := NewAggregator(AggregatorConfig{
			Store:       store,
			Dialer:      mesh,
			Port:        port,
			AuthChecker: checker,
		})
		if err := agg.Start(); err != nil {
			t.Fatalf("Aggregator Start on port %d: %v", port, err)
		}
		defer agg.Stop()

		env := &MetricEnvelope{
			SourceID: sourceID,
			Sequence: 1,
			Metrics: &Metrics{
				NodeID:    sourceID,
				Timestamp: time.Now().UTC(),
				CPU:       CPUMetrics{UsagePercent: 42.0},
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := mesh.DialMesh(ctx, sourceID, port)
		if err != nil {
			t.Fatalf("DialMesh: %v", err)
		}
		defer conn.Close()

		go func() {
			WriteEnvelope(conn, env)
		}()

		time.Sleep(500 * time.Millisecond)

		latest := store.Latest(sourceID)
		stored := latest != nil
		if stored != expectStored {
			if expectStored {
				t.Errorf("peer %q should be accepted but was rejected", sourceID)
			} else {
				t.Errorf("peer %q should be rejected but was accepted", sourceID)
			}
		}
	}

	// Phase 1: dynamic-peer is in routing table → accepted.
	pushAndCheck("dynamic-peer", 4311, true)

	// Phase 2: remove from routing table → rejected.
	delete(peers, "dynamic-peer")
	pushAndCheck("dynamic-peer", 4312, false)

	// Phase 3: re-add to routing table → accepted again.
	peers["dynamic-peer"] = true
	pushAndCheck("dynamic-peer", 4313, true)

	// Sanity: stable-peer is unaffected by the dynamics.
	pushAndCheck("stable-peer", 4314, true)
}

// TestAggregatorWithMeshIdentityChecker_MixedPeers verifies that the
// aggregator correctly handles sequenced pushes from a mix of authorized
// and unauthorized peers: mesh members are accepted, non-members are
// dropped, all in a single aggregator instance.
func TestAggregatorWithMeshIdentityChecker_MixedPeers(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()

	localPubkey := "aggregator-node"
	knownPeers := map[string]bool{
		"mesh-node-A": true,
		"mesh-node-C": true,
		"mesh-node-E": true,
	}

	checker := auth.NewMeshIdentityAuthChecker(
		localPubkey,
		func(peerID string) bool { return knownPeers[peerID] },
		nil,
	)

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4320,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	tests := []struct {
		sourceID   string
		wantStored bool
	}{
		{"mesh-node-A", true},  // in routing table → accepted
		{"mesh-node-B", false}, // NOT in routing table → rejected
		{"mesh-node-C", true},  // in routing table → accepted
		{"mesh-node-D", false}, // NOT in routing table → rejected
		{"mesh-node-E", true},  // in routing table → accepted
		{"intruder", false},    // completely unknown → rejected
	}

	for _, tt := range tests {
		t.Run(tt.sourceID, func(t *testing.T) {
			env := &MetricEnvelope{
				SourceID: tt.sourceID,
				Sequence: 1,
				Metrics: &Metrics{
					NodeID:    tt.sourceID,
					Timestamp: time.Now().UTC(),
					CPU:       CPUMetrics{UsagePercent: float64(len(tt.sourceID) * 10)},
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := mesh.DialMesh(ctx, tt.sourceID, 4320)
			if err != nil {
				t.Fatalf("DialMesh: %v", err)
			}
			defer conn.Close()

			go func() {
				WriteEnvelope(conn, env)
			}()

			time.Sleep(500 * time.Millisecond)

			latest := store.Latest(tt.sourceID)
			stored := latest != nil
			if stored != tt.wantStored {
				if tt.wantStored {
					t.Errorf("%s: in routing table, should be accepted but was rejected", tt.sourceID)
				} else {
					t.Errorf("%s: NOT in routing table, should be rejected but was accepted", tt.sourceID)
				}
			}
		})
	}
}

// TestAggregatorWithMeshIdentityChecker_AuditLogging verifies that the
// MeshIdentityAuthChecker produces audit log entries (allow and deny)
// when wired into the aggregator.
func TestAggregatorWithMeshIdentityChecker_AuditLogging(t *testing.T) {
	mesh := NewInProcMesh()
	store := NewStore()
	var auditBuf bytes.Buffer

	localPubkey := "aggregator-node"
	knownPeers := map[string]bool{
		"audit-peer-ok": true,
	}

	auditLogger := auth.NewAuditLogger(&auditBuf)
	checker := auth.NewMeshIdentityAuthChecker(
		localPubkey,
		func(peerID string) bool { return knownPeers[peerID] },
		auditLogger,
	)

	agg := NewAggregator(AggregatorConfig{
		Store:       store,
		Dialer:      mesh,
		Port:        4330,
		AuthChecker: checker,
	})
	if err := agg.Start(); err != nil {
		t.Fatalf("Aggregator Start: %v", err)
	}
	defer agg.Stop()

	push := func(sourceID string) {
		env := &MetricEnvelope{
			SourceID: sourceID,
			Sequence: 1,
			Metrics: &Metrics{
				NodeID:    sourceID,
				Timestamp: time.Now().UTC(),
				CPU:       CPUMetrics{UsagePercent: 1.0},
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := mesh.DialMesh(ctx, sourceID, 4330)
		if err != nil {
			return
		}
		defer conn.Close()
		go func() {
			WriteEnvelope(conn, env)
		}()
		time.Sleep(300 * time.Millisecond)
	}

	// Push from self (should be "allow" with reason "self").
	push(localPubkey)
	// Push from known peer (should be "allow" with reason "mesh_member").
	push("audit-peer-ok")
	// Push from unknown peer (should be "deny" with reason "unknown_peer").
	push("audit-peer-bad")

	agg.Stop()
	time.Sleep(100 * time.Millisecond)

	entries := auditBuf.String()
	if entries == "" {
		t.Fatal("expected audit log entries, got empty")
	}

	if !bytes.Contains(auditBuf.Bytes(), []byte(`"allow"`)) {
		t.Error("audit log should contain at least one 'allow' entry")
	}
	if !bytes.Contains(auditBuf.Bytes(), []byte(`"deny"`)) {
		t.Error("audit log should contain at least one 'deny' entry")
	}
	if !bytes.Contains(auditBuf.Bytes(), []byte(`"self"`)) {
		t.Error("audit log should contain 'self' reason for self-push")
	}
	if !bytes.Contains(auditBuf.Bytes(), []byte(`"mesh_member"`)) {
		t.Error("audit log should contain 'mesh_member' reason for known peer")
	}
	if !bytes.Contains(auditBuf.Bytes(), []byte(`"unknown_peer"`)) {
		t.Error("audit log should contain 'unknown_peer' reason for rejected peer")
	}
}

// TestAggregatorWithMockAuthChecker_RejectedPushIsDropped is a focused
// table-driven variant that exercises all three mock-auth paths (accept,
// reject, nil) in a single test to serve as a contract for re-enable
// verification.
func TestAggregatorWithMockAuthChecker_RejectedPushIsDropped(t *testing.T) {
	tests := []struct {
		name       string
		sourceID   string
		allowedMap map[string]bool
		wantStored bool
	}{
		{
			name:     "authorized pubkey accepted",
			sourceID: "ok-peer",
			allowedMap: map[string]bool{
				"ok-peer": true,
			},
			wantStored: true,
		},
		{
			name:     "unauthorized pubkey rejected",
			sourceID: "bad-peer",
			allowedMap: map[string]bool{
				"ok-peer": true,
				// "bad-peer" NOT in map
			},
			wantStored: false,
		},
		{
			name:       "nil checker accepts all",
			sourceID:   "any-peer",
			allowedMap: nil, // will use nil checker
			wantStored: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mesh := NewInProcMesh()
			store := NewStore()

			var checker AuthChecker
			if tt.allowedMap != nil {
				checker = &mockMonitorAuthChecker{
					allowedPeers: tt.allowedMap,
				}
			}
			// else: checker stays nil → nil checker mode

			agg := NewAggregator(AggregatorConfig{
				Store:       store,
				Dialer:      mesh,
				Port:        4220 + len(tt.sourceID)%3,
				AuthChecker: checker,
			})
			if err := agg.Start(); err != nil {
				t.Fatalf("Aggregator Start: %v", err)
			}
			defer agg.Stop()

			env := &MetricEnvelope{
				SourceID: tt.sourceID,
				Sequence: 1,
				Metrics: &Metrics{
					NodeID:    tt.sourceID,
					Timestamp: time.Now().UTC(),
					CPU:       CPUMetrics{UsagePercent: 42.0},
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := mesh.DialMesh(ctx, "test", 4220+len(tt.sourceID)%3)
			if err != nil {
				t.Fatalf("DialMesh: %v", err)
			}
			defer conn.Close()

			go func() {
				WriteEnvelope(conn, env)
			}()

			time.Sleep(500 * time.Millisecond)

			latest := store.Latest(tt.sourceID)
			stored := latest != nil
			if stored != tt.wantStored {
				if tt.wantStored {
					t.Error("metrics should be stored but were not")
				} else {
					t.Error("metrics should NOT be stored but were")
				}
			}
		})
	}
}
