package p2p

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// === NAT Type Tests ===

func TestClassifyNat_SameAddress(t *testing.T) {
	first := &EndpointDiscovery{MappedAddress: "203.0.113.5:51820"}
	second := &EndpointDiscovery{MappedAddress: "203.0.113.5:51820"}

	result := classifyNat(first, second)
	if result != NatTypeFullCone {
		t.Errorf("classifyNat(same addr) = %s, want full_cone", result)
	}
}

func TestClassifyNat_SymmetricSameIPDiffPort(t *testing.T) {
	first := &EndpointDiscovery{MappedAddress: "203.0.113.5:51820"}
	second := &EndpointDiscovery{MappedAddress: "203.0.113.5:51821"}

	result := classifyNat(first, second)
	if result != NatTypeSymmetric {
		t.Errorf("classifyNat(same IP, diff port) = %s, want symmetric", result)
	}
}

func TestClassifyNat_DifferentIP(t *testing.T) {
	first := &EndpointDiscovery{MappedAddress: "203.0.113.5:51820"}
	second := &EndpointDiscovery{MappedAddress: "198.51.100.7:51820"}

	result := classifyNat(first, second)
	if result != NatTypeSymmetric {
		t.Errorf("classifyNat(diff IP) = %s, want symmetric", result)
	}
}

func TestCanHolePunch_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		local    NatType
		remote   NatType
		expected bool
	}{
		{"both full_cone", NatTypeFullCone, NatTypeFullCone, true},
		{"local none, remote full_cone", NatTypeNone, NatTypeFullCone, true},
		{"local full_cone, remote none", NatTypeFullCone, NatTypeNone, true},
		{"both symmetric", NatTypeSymmetric, NatTypeSymmetric, false},
		{"local symmetric, remote full_cone", NatTypeSymmetric, NatTypeFullCone, true},
		{"local full_cone, remote symmetric", NatTypeFullCone, NatTypeSymmetric, true},
		{"both restricted", NatTypeRestricted, NatTypeRestricted, true},
		{"both port_restricted", NatTypePortRestricted, NatTypePortRestricted, true},
		{"local restricted, remote symmetric", NatTypeRestricted, NatTypeSymmetric, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CanHolePunch(tt.local, tt.remote)
			if result != tt.expected {
				t.Errorf("CanHolePunch(%s, %s) = %v, want %v", tt.local, tt.remote, result, tt.expected)
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"203.0.113.5", true},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"172.32.0.1", true},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"100.64.0.1", false}, // CGNAT
		{"0.0.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := isPublicIP(tt.ip)
			if result != tt.public {
				t.Errorf("isPublicIP(%s) = %v, want %v", tt.ip, result, tt.public)
			}
		})
	}
}

// === NatState String Tests ===

func TestNatState_String(t *testing.T) {
	tests := []struct {
		state NatState
		want  string
	}{
		{NatInit, "INIT"},
		{NatStunDiscovery, "STUN_DISCOVERY"},
		{NatDirectProbe, "DIRECT_PROBE"},
		{NatDirect, "DIRECT"},
		{NatRelayFallback, "RELAY_FALLBACK"},
		{NatDirectReprobe, "DIRECT_REPROBE"},
		{NatActive, "ACTIVE"},
		{NatRetry, "RETRY"},
		{NatFailed, "FAILED"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("NatState(%d).String() = %s, want %s", int(tt.state), got, tt.want)
			}
		})
	}
}

// === StunClient Tests ===

func TestStunClient_DefaultServers(t *testing.T) {
	sc := NewStunClient(nil, 0)
	if len(sc.servers) != 2 {
		t.Errorf("expected 2 default STUN servers, got %d", len(sc.servers))
	}
	if sc.timeout != 5*time.Second {
		t.Errorf("expected default timeout 5s, got %v", sc.timeout)
	}
}

func TestStunClient_CustomServers(t *testing.T) {
	servers := []string{"stun.example.com:3478"}
	sc := NewStunClient(servers, 10*time.Second)
	if len(sc.servers) != 1 || sc.servers[0] != "stun.example.com:3478" {
		t.Errorf("expected custom server, got %v", sc.servers)
	}
	if sc.timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", sc.timeout)
	}
}

// === HolePuncher Tests ===

func TestHolePuncher_Punch_InvalidEndpoint(t *testing.T) {
	hp := NewHolePuncher("203.0.113.5:51820", 51820)
	ctx := context.Background()
	result := hp.Punch(ctx, "invalid-endpoint-no-port")

	if result.Success {
		t.Error("expected failure for invalid endpoint")
	}
	if result.Error == nil {
		t.Error("expected error for invalid endpoint")
	}
}

func TestHolePuncher_Punch_UnreachableEndpoint(t *testing.T) {
	// Use a port that's guaranteed to be closed on a non-routable address.
	hp := NewHolePuncher("203.0.113.5:51820", 51820)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := hp.Punch(ctx, "192.0.2.1:9999") // TEST-NET-1, RFC 5737

	// This should not succeed but the punch should send packets.
	// The result may report success (sent packets) even though no response.
	// We mainly check that it doesn't hang or panic.
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestHolePunchCoordinator_RegisterUnregister(t *testing.T) {
	hc := NewHolePunchCoordinator()
	peerKey := "abc123def456"

	hc.RegisterPeer(peerKey, "203.0.113.5:51820", 51820)
	if !hc.IsRegistered(peerKey) {
		t.Error("expected peer to be registered")
	}

	hc.UnregisterPeer(peerKey)
	if hc.IsRegistered(peerKey) {
		t.Error("expected peer to be unregistered")
	}
}

func TestHolePunchCoordinator_AttemptPunch_Unregistered(t *testing.T) {
	hc := NewHolePunchCoordinator()
	ctx := context.Background()
	result := hc.AttemptPunch(ctx, "unregistered_key", "203.0.113.5:51820")

	if result.Success {
		t.Error("expected failure for unregistered peer")
	}
	if result.Error == nil {
		t.Error("expected error for unregistered peer")
	}
}

// === NatTraversal State Machine Tests ===

// newTestNatTraversal creates a NatTraversal instance with a mock PeerManager
// and test config. It does NOT start the traversal layer (no STUN queries).
func newTestNatTraversal(pm *mockPeerManager, relay *RelaySelector, events *meshEventDelegate) *NatTraversal {
	cfg := NatTraversalConfig{
		StunServers:           []string{"stun.l.google.com:19302"},
		DirectReprobeInterval: 100 * time.Millisecond,
		MaxRetries:            3,
		ProbeTimeout:          50 * time.Millisecond,
		RelayMode:             "auto",
		MaxRelayHops:          2,
	}
	nt := &NatTraversal{
		cfg:        cfg,
		wgDelegate: pm,
		relay:      relay,
		events:     events,
		stun:       NewStunClient(cfg.StunServers, 5*time.Second),
		puncher:    NewHolePunchCoordinator(),
		meshPort:   51820,
		sessions:   make(map[string]*NatSession),
		stopCh:     make(chan struct{}),
	}
	return nt
}

// setupTestRelay creates a RelaySelector with mock relay candidates in the
// event delegate's relay pool.
func setupTestRelay(t *testing.T, events *meshEventDelegate, relayKey, meshIP string) {
	t.Helper()
	events.mu.Lock()
	defer events.mu.Unlock()
	events.relayPool[relayKey] = &NodeMeta{
		PublicKey:   relayKey,
		CapRelay:    true,
		Endpoints:   []string{meshIP + ":51820"},
		NatType:     string(NatTypeFullCone),
		LoadCPU:     0.1,
		LoadMem:     0.1,
		MaxCircuits: 1024,
	}
}

func TestNatTraversal_SessionState_NoSession(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)

	state := nt.SessionState("nonexistent")
	if state != NatInit {
		t.Errorf("expected NatInit for nonexistent session, got %s", state)
	}
}

func TestNatTraversal_InitiateConnection_CreatesSession(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)

	// Set local discovery so STUN_DISCOVERY can proceed.
	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeFullCone)

	// Session should exist.
	session := nt.GetSession(peerKey)
	if session == nil {
		t.Fatal("expected session to be created")
	}

	// Give the state machine a moment to run.
	time.Sleep(100 * time.Millisecond)

	// The state machine should have transitioned past INIT.
	state := nt.SessionState(peerKey)
	if state == NatInit {
		t.Error("expected state to transition past INIT")
	}
}

// AC-5: NAT Traversal — Direct Connection
// GIVEN node A (full-cone NAT) and node B (full-cone NAT), both with STUN
// WHEN A initiates NAT traversal to B
// THEN A's NatSession transitions: INIT → STUN_DISCOVERY → DIRECT_PROBE → DIRECT
func TestNatTraversal_AC5_DirectConnection(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	// Set local STUN discovery with full-cone NAT.
	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peerKey := "aaaabbbbccccdddd"
	// Mark peer as healthy (simulating successful WG handshake).
	pm.SetConnected(peerKey, true)

	// Initiate connection — both sides full-cone → hole-punch viable.
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeFullCone)

	// Wait for state machine to run through.
	time.Sleep(200 * time.Millisecond)

	state := nt.SessionState(peerKey)
	if state != NatDirect && state != NatActive {
		t.Errorf("AC-5: expected DIRECT or ACTIVE, got %s", state)
	}

	// Verify handshake time was updated (direct connection succeeded).
	if !pm.IsConnected(peerKey) {
		t.Error("AC-5: expected UpdateHandshakeTime to be called")
	}
}

// AC-6: NAT Traversal — Relay Fallback
// GIVEN node A (symmetric NAT) and node B (symmetric NAT)
// AND relay node R (public endpoint, CapRelay=true)
// WHEN A initiates NAT traversal to B
// THEN A's NatSession transitions: INIT → STUN_DISCOVERY → RELAY_FALLBACK
// AND A's WireGuard endpoint for B is set to R's mesh IP
func TestNatTraversal_AC6_RelayFallback(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	// Set local STUN discovery with symmetric NAT.
	nt.SetLocalDiscovery("203.0.113.5:51821", NatTypeSymmetric)

	// Set up a relay candidate.
	relayKey := "eeeeffff00001111"
	relayIP := "10.10.5.6"
	setupTestRelay(t, events, relayKey, relayIP)

	peerKey := "aaaabbbbccccdddd"
	// Both sides symmetric → forced relay (§3.9).
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeSymmetric)

	// Wait for state machine to process.
	time.Sleep(200 * time.Millisecond)

	state := nt.SessionState(peerKey)
	if state != NatRelayFallback {
		t.Errorf("AC-6: expected RELAY_FALLBACK, got %s", state)
	}

	// Verify WireGuard endpoint was updated to relay's mesh IP.
	updatedEP, ok := pm.GetUpdatedEndpoints(peerKey)
	if !ok {
		t.Fatal("AC-6: expected endpoint update to relay mesh IP")
	}
	expectedEP := relayIP + ":51820"
	if len(updatedEP) == 0 || updatedEP[0] != expectedEP {
		t.Errorf("AC-6: endpoint = %v, want %s", updatedEP, expectedEP)
	}
}

// AC-7: NAT Traversal — Direct Re-Probe
// GIVEN A is in RELAY_FALLBACK state with B
// WHEN 120 seconds elapse
// THEN A attempts DIRECT_REPROBE to B's STUN endpoints
func TestNatTraversal_AC7_DirectReprobe(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.DirectReprobeInterval = 50 * time.Millisecond
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	// Set local STUN discovery with symmetric NAT.
	nt.SetLocalDiscovery("203.0.113.5:51821", NatTypeSymmetric)

	// Set up relay candidate.
	relayKey := "eeeeffff00001111"
	relayIP := "10.10.5.6"
	setupTestRelay(t, events, relayKey, relayIP)

	peerKey := "aaaabbbbccccdddd"
	// Both sides symmetric → goes to relay.
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeSymmetric)

	// Wait for relay fallback to complete.
	time.Sleep(150 * time.Millisecond)

	// Verify we're in RELAY_FALLBACK.
	state := nt.SessionState(peerKey)
	if state != NatRelayFallback {
		t.Fatalf("AC-7: expected RELAY_FALLBACK before re-probe, got %s", state)
	}

	// Now simulate NAT type change — make the peer's NAT become full_cone
	// by updating the local discovery to full_cone.
	nt.SetLocalDiscovery("203.0.113.5:51821", NatTypeFullCone)

	// Mark peer as healthy (simulating successful handshake on re-probe).
	pm.SetConnected(peerKey, true)

	// Start the re-probe loop.
	nt.reprobeTC = time.NewTicker(nt.cfg.DirectReprobeInterval)
	go nt.reprobeLoop()
	defer func() {
		nt.reprobeTC.Stop()
	}()

	// Wait for re-probe to fire and complete.
	time.Sleep(300 * time.Millisecond)

	// The re-probe should have attempted direct connection.
	// Since the peer is now healthy, it should transition to DIRECT.
	state = nt.SessionState(peerKey)
	if state != NatDirect && state != NatActive {
		t.Errorf("AC-7: expected DIRECT or ACTIVE after re-probe, got %s", state)
	}

	// Verify endpoint was updated to direct endpoint (not relay).
	updatedEP, ok := pm.GetUpdatedEndpoints(peerKey)
	if !ok {
		t.Fatal("AC-7: expected endpoint update after re-probe")
	}
	// Should be updated to the peer's direct endpoint.
	if len(updatedEP) == 0 || updatedEP[0] != "203.0.113.10:51820" {
		t.Errorf("AC-7: expected direct endpoint 203.0.113.10:51820, got %s", updatedEP)
	}
}

// Test that a session in RELAY_FALLBACK with failed re-probe goes back to relay.
func TestNatTraversal_ReprobeFailed_BackToRelay(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.DirectReprobeInterval = 200 * time.Millisecond
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	// Local symmetric NAT.
	nt.SetLocalDiscovery("203.0.113.5:51821", NatTypeSymmetric)

	// Set up relay.
	relayKey := "eeeeffff00001111"
	relayIP := "10.10.5.6"
	setupTestRelay(t, events, relayKey, relayIP)

	peerKey := "aaaabbbbccccdddd"
	// Both symmetric → relay.
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeSymmetric)

	// Wait for relay fallback.
	time.Sleep(150 * time.Millisecond)

	// Change NAT type to full_cone so hole-punch is attempted.
	nt.SetLocalDiscovery("203.0.113.5:51821", NatTypeFullCone)

	// Peer is NOT healthy (simulating failed direct probe).
	// pm.healthyPeers[peerKey] remains false

	// Start re-probe loop.
	nt.reprobeTC = time.NewTicker(nt.cfg.DirectReprobeInterval)
	go nt.reprobeLoop()

	// Wait for one re-probe cycle to complete.
	time.Sleep(250 * time.Millisecond)

	// Stop the ticker to prevent further reprobes before we check.
	nt.reprobeTC.Stop()

	// Wait a bit more for the current reprobe to finish.
	time.Sleep(50 * time.Millisecond)

	// Should be back in RELAY_FALLBACK (direct probe failed).
	state := nt.SessionState(peerKey)
	if state != NatRelayFallback {
		t.Errorf("expected RELAY_FALLBACK after failed re-probe, got %s", state)
	}
}

// Test relay disabled mode — no relay, goes to RETRY.
func TestNatTraversal_RelayDisabled(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.RelayMode = "disabled"
	nt.cfg.ProbeTimeout = 20 * time.Millisecond
	nt.cfg.MaxRetries = 1

	// Local full-cone, remote full-cone, but no endpoints.
	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peerKey := "aaaabbbbccccdddd"
	// No endpoints + relay disabled → should go to RETRY.
	nt.InitiateConnection(peerKey, []string{}, NatTypeFullCone)

	time.Sleep(200 * time.Millisecond)

	state := nt.SessionState(peerKey)
	// With no endpoints and relay disabled, should be in RETRY or FAILED.
	if state != NatRetry && state != NatFailed {
		t.Errorf("expected RETRY or FAILED with relay disabled, got %s", state)
	}
}

// Test that RemoveConnection cleans up sessions.
func TestNatTraversal_RemoveConnection(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeFullCone)

	time.Sleep(100 * time.Millisecond)

	// Verify session exists.
	if nt.GetSession(peerKey) == nil {
		t.Fatal("expected session to exist")
	}

	// Remove it.
	nt.RemoveConnection(peerKey)

	// Verify session is gone.
	if nt.GetSession(peerKey) != nil {
		t.Error("expected session to be removed")
	}

	// Verify puncher registration is gone.
	if nt.puncher.IsRegistered(peerKey) {
		t.Error("expected peer to be unregistered from puncher")
	}
}

// Test AllSessions returns a snapshot.
func TestNatTraversal_AllSessions(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	nt.InitiateConnection("peer1", []string{"203.0.113.10:51820"}, NatTypeFullCone)
	nt.InitiateConnection("peer2", []string{"203.0.113.11:51820"}, NatTypeFullCone)

	time.Sleep(100 * time.Millisecond)

	sessions := nt.AllSessions()
	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(sessions))
	}
}

// Test LocalEndpoint and LocalNatType accessors.
func TestNatTraversal_LocalDiscovery(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	if nt.LocalEndpoint() != "203.0.113.5:51820" {
		t.Errorf("LocalEndpoint = %s, want 203.0.113.5:51820", nt.LocalEndpoint())
	}
	if nt.LocalNatType() != NatTypeFullCone {
		t.Errorf("LocalNatType = %s, want full_cone", nt.LocalNatType())
	}
}

// Test NatTraversalConfig defaults.
func TestDefaultNatTraversalConfig(t *testing.T) {
	cfg := DefaultNatTraversalConfig()

	if cfg.DirectReprobeInterval != 120*time.Second {
		t.Errorf("expected reprobe interval 120s, got %v", cfg.DirectReprobeInterval)
	}
	if cfg.MaxRetries != 10 {
		t.Errorf("expected max retries 10, got %d", cfg.MaxRetries)
	}
	if cfg.RelayMode != "auto" {
		t.Errorf("expected relay mode auto, got %s", cfg.RelayMode)
	}
	if cfg.MaxRelayHops != 2 {
		t.Errorf("expected max relay hops 2, got %d", cfg.MaxRelayHops)
	}
	if len(cfg.StunServers) != 2 {
		t.Errorf("expected 2 default STUN servers, got %d", len(cfg.StunServers))
	}
}

// Test NatTraversalFromP2pConfig conversion.
func TestNatTraversalFromP2pConfig(t *testing.T) {
	p2pCfg := P2pConfig{
		StunServers:           []string{"stun.custom.com:3478"},
		DirectReprobeInterval: 60,
		RelayMode:             "manual",
		MaxRelayHops:          3,
	}

	nc := NatTraversalFromP2pConfig(p2pCfg)

	if len(nc.StunServers) != 1 || nc.StunServers[0] != "stun.custom.com:3478" {
		t.Errorf("expected custom STUN server, got %v", nc.StunServers)
	}
	if nc.DirectReprobeInterval != 60*time.Second {
		t.Errorf("expected reprobe interval 60s, got %v", nc.DirectReprobeInterval)
	}
	if nc.RelayMode != "manual" {
		t.Errorf("expected relay mode manual, got %s", nc.RelayMode)
	}
	if nc.MaxRelayHops != 3 {
		t.Errorf("expected max relay hops 3, got %d", nc.MaxRelayHops)
	}
}

// Test that the state machine handles both-symmetric NAT (§3.9)
// by skipping DIRECT_PROBE and going straight to RELAY_FALLBACK.
func TestNatTraversal_BothSymmetric_ForcedRelay(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	// Both sides symmetric.
	nt.SetLocalDiscovery("203.0.113.5:51821", NatTypeSymmetric)

	// Set up relay.
	relayKey := "eeeeffff00001111"
	relayIP := "10.10.5.6"
	setupTestRelay(t, events, relayKey, relayIP)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeSymmetric)

	// Wait for state machine.
	time.Sleep(200 * time.Millisecond)

	state := nt.SessionState(peerKey)
	if state != NatRelayFallback {
		t.Errorf("expected RELAY_FALLBACK for both-symmetric, got %s", state)
	}

	// Should NOT have attempted hole-punching.
	if pm.IsConnected(peerKey) {
		t.Error("expected no handshake update for both-symmetric (forced relay)")
	}
}

// Test concurrent session access (no data races).
func TestNatTraversal_ConcurrentAccess(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.ProbeTimeout = 10 * time.Millisecond

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			peerKey := "peer" + string(rune('A'+idx))
			nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeFullCone)
			_ = nt.GetSession(peerKey)
			_ = nt.SessionState(peerKey)
			_ = nt.AllSessions()
		}(i)
	}
	wg.Wait()
}

// === STUN Server Test (Integration, may be skipped) ===

func TestStunClient_Discover_RealServer(t *testing.T) {
	// This test requires internet access to a public STUN server.
	// Skip if we can't reach Google's STUN server.
	conn, err := net.DialTimeout("udp", "stun.l.google.com:19302", 2*time.Second)
	if err != nil {
		t.Skip("no internet access to STUN server, skipping integration test")
	}
	conn.Close()

	sc := NewStunClient([]string{"stun.l.google.com:19302"}, 5*time.Second)
	discovery, err := sc.Discover()
	if err != nil {
		t.Skipf("STUN discovery failed (network issue): %v", err)
	}

	if discovery.MappedAddress == "" {
		t.Error("expected non-empty mapped address")
	}
	if discovery.NatType == NatTypeUnknown {
		// With only one server, NAT type is unknown — that's OK.
		t.Logf("NAT type: %s (expected unknown with single server)", discovery.NatType)
	}

	t.Logf("STUN discovery: endpoint=%s, NAT=%s, server=%s",
		discovery.MappedAddress, discovery.NatType, discovery.Server)
}
