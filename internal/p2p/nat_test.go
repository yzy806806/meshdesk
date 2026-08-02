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

// === Edge Case Tests (added by tester strategy) ===

// TestGenerateCircuitID verifies circuit ID format, length, and uniqueness.
func TestGenerateCircuitID(t *testing.T) {
	// Format: hex string.
	id1 := generateCircuitID()
	if len(id1) != 32 {
		t.Errorf("generateCircuitID length = %d, want 32 (16 bytes hex-encoded)", len(id1))
	}
	// Should be lowercase hex.
	for _, c := range id1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("generateCircuitID contains non-hex character: %c", c)
		}
	}

	// Uniqueness across multiple calls.
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateCircuitID()
		if ids[id] {
			t.Errorf("generateCircuitID collision: %s", id)
		}
		ids[id] = true
	}
}

// TestInferNAT verifies inferNAT returns the conservative "restricted_cone".
func TestInferNAT(t *testing.T) {
	result := inferNAT("203.0.113.5:51820")
	if result != "restricted_cone" {
		t.Errorf("inferNAT = %s, want restricted_cone", result)
	}

	// Empty endpoint should still return restricted_cone.
	result = inferNAT("")
	if result != "restricted_cone" {
		t.Errorf("inferNAT(\"\") = %s, want restricted_cone", result)
	}
}

// TestSafeShortKey verifies safeShortKey handles all boundary cases.
func TestSafeShortKey(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"a", "a"},
		{"abcdefg", "abcdefg"},
		{"abcdefgh", "abcdefgh"},
		{"abcdefghi", "abcdefgh"},
		{"aaaabbbbccccddddeeeeffffgggghhhhiiiijjjj", "aaaabbbb"},
	}

	for _, tt := range tests {
		got := safeShortKey(tt.input)
		if got != tt.want {
			t.Errorf("safeShortKey(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestCanHolePunch_FullMatrix tests all 36 NAT type combinations.
func TestCanHolePunch_FullMatrix(t *testing.T) {
	allTypes := []NatType{
		NatTypeNone,
		NatTypeFullCone,
		NatTypeRestricted,
		NatTypePortRestricted,
		NatTypeSymmetric,
		NatTypeUnknown,
	}

	// Expected rule: only false when BOTH are symmetric.
	// Everything else should return true.
	for _, local := range allTypes {
		for _, remote := range allTypes {
			got := CanHolePunch(local, remote)
			want := !(local == NatTypeSymmetric && remote == NatTypeSymmetric)
			if got != want {
				t.Errorf("CanHolePunch(%s, %s) = %v, want %v", local, remote, got, want)
			}
		}
	}
}

// TestNatType_StringValues verifies all NatType constants return expected values.
func TestNatType_StringValues(t *testing.T) {
	tests := []struct {
		nt   NatType
		want string
	}{
		{NatTypeNone, "none"},
		{NatTypeFullCone, "full_cone"},
		{NatTypeRestricted, "restricted"},
		{NatTypePortRestricted, "port_restricted"},
		{NatTypeSymmetric, "symmetric"},
		{NatTypeUnknown, "unknown"},
	}

	for _, tt := range tests {
		if string(tt.nt) != tt.want {
			t.Errorf("NatType %s string value = %q, want %q", tt.want, string(tt.nt), tt.want)
		}
	}
}

// TestStunClient_Discover_NoServers verifies that Discover with explicitly
// empty servers (forced to empty after construction) returns an error.
func TestStunClient_Discover_NoServers(t *testing.T) {
	// NewStunClient auto-fills defaults when given empty server list,
	// so we must explicitly set servers to empty after construction.
	sc := NewStunClient([]string{"stun.l.google.com:19302"}, 5*time.Second)
	sc.servers = []string{}
	_, err := sc.Discover()
	if err == nil {
		t.Error("Discover() with empty servers should return error")
	}
}

// TestNatTraversal_DoubleStart verifies Start() twice returns error.
func TestNatTraversal_DoubleStart(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)

	// Disable direct reprobe to prevent ticker goroutine from interfering.
	nt.cfg.DirectReprobeInterval = 0

	// First start should succeed.
	err := nt.Start()
	if err != nil {
		t.Fatalf("first Start() failed: %v", err)
	}

	// Second start should fail.
	err = nt.Start()
	if err == nil {
		t.Error("second Start() should return error")
	}

	// Clean up.
	nt.Stop()
}

// TestNatTraversal_StopNotStarted verifies Stop() when not started is a no-op.
func TestNatTraversal_StopNotStarted(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)

	// Stop without Start should not panic or error.
	err := nt.Stop()
	if err != nil {
		t.Errorf("Stop() on unstarted traversal returned error: %v", err)
	}
}

// TestNatTraversal_InitiateConnection_Deduplicate verifies that calling
// InitiateConnection twice for the same peer does not create duplicate sessions.
func TestNatTraversal_InitiateConnection_Deduplicate(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peerKey := "aaaabbbbccccdddd"

	// First call creates a session.
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeFullCone)

	// Second call for same peer should be a no-op.
	nt.InitiateConnection(peerKey, []string{"203.0.113.20:51820"}, NatTypeSymmetric)

	// Wait for state machine.
	time.Sleep(100 * time.Millisecond)

	// Only one session should exist.
	sessions := nt.AllSessions()
	if len(sessions) != 1 {
		t.Errorf("expected 1 session after duplicate InitiateConnection, got %d", len(sessions))
	}

	// The session should still use the original endpoints (first call wins).
	if len(sessions) > 0 && len(sessions[0].Endpoints) > 0 {
		if sessions[0].Endpoints[0] != "203.0.113.10:51820" {
			t.Errorf("session endpoints changed after duplicate call: got %v, want [203.0.113.10:51820]",
				sessions[0].Endpoints)
		}
	}
}

// TestNatTraversal_HandleRetry_TransitionsToFailed verifies that RETRY
// transitions to FAILED when MaxRetries is exceeded. With MaxRetries=0,
// the first RETRY check immediately transitions to FAILED (no backoff wait).
func TestNatTraversal_HandleRetry_TransitionsToFailed(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	// MaxRetries=0 means the first RETRY immediately transitions to FAILED.
	nt.cfg.MaxRetries = 0
	nt.cfg.ProbeTimeout = 20 * time.Millisecond
	// Disable relay so we always go to RETRY.
	nt.cfg.RelayMode = "disabled"

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peerKey := "aaaabbbbccccdddd"
	// No endpoints + relay disabled → DIRECT_PROBE fails → RETRY → FAILED (MaxRetries=0).
	nt.InitiateConnection(peerKey, []string{}, NatTypeFullCone)

	// Wait for state machine to process through: STUN_DISCOVERY → DIRECT_PROBE → RETRY → FAILED
	time.Sleep(200 * time.Millisecond)

	state := nt.SessionState(peerKey)
	if state != NatFailed {
		t.Errorf("expected FAILED after MaxRetries=0, got %s", state)
	}
}

// TestNatTraversal_TransitionToRelay_NilRelay verifies that when relay selector
// is nil, transitionToRelay sets state to FAILED.
func TestNatTraversal_TransitionToRelay_NilRelay(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	nt := newTestNatTraversal(pm, nil, events) // nil relay
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	nt.SetLocalDiscovery("203.0.113.5:51821", NatTypeSymmetric)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeSymmetric)

	// Wait for state machine — both symmetric → tries relay → nil relay → FAILED.
	time.Sleep(200 * time.Millisecond)

	state := nt.SessionState(peerKey)
	if state != NatFailed {
		t.Errorf("expected FAILED when relay is nil, got %s", state)
	}
}

// TestNatSessionSnapshot_Immutability verifies that modifying the original
// NatSession does not affect an already-taken snapshot.
func TestNatSessionSnapshot_Immutability(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{"198.51.100.1:51820"}, NatTypeFullCone)

	time.Sleep(50 * time.Millisecond)

	// Take snapshot.
	sessions := nt.AllSessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session for snapshot, got %d", len(sessions))
	}
	snap := sessions[0]

	// Verify snapshot has the original endpoints.
	if len(snap.Endpoints) != 1 || snap.Endpoints[0] != "198.51.100.1:51820" {
		t.Fatalf("snapshot endpoints = %v, want [198.51.100.1:51820]", snap.Endpoints)
	}

	// Modify the session's endpoints through the state machine (removing it
	// would clear the session entirely, but we verify the snapshot copy holds).
	nt.RemoveConnection(peerKey)

	// Snapshot must be unchanged.
	if len(snap.Endpoints) != 1 || snap.Endpoints[0] != "198.51.100.1:51820" {
		t.Errorf("snapshot mutated after RemoveConnection: endpoints = %v", snap.Endpoints)
	}
	if snap.PeerKey != peerKey {
		t.Errorf("snapshot PeerKey mutated: got %s, want %s", snap.PeerKey, peerKey)
	}
}

// TestHolePunchCoordinator_ConcurrentRegister verifies thread-safe concurrent
// register/unregister operations.
func TestHolePunchCoordinator_ConcurrentRegister(t *testing.T) {
	hc := NewHolePunchCoordinator()
	var wg sync.WaitGroup

	// Concurrent registration.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			peerKey := "peer" + string(rune('A'+idx))
			hc.RegisterPeer(peerKey, "203.0.113.5:51820", 51820)
			if !hc.IsRegistered(peerKey) {
				t.Errorf("peer %s should be registered", peerKey)
			}
		}(i)
	}
	wg.Wait()

	// Concurrent unregistration.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			peerKey := "peer" + string(rune('A'+idx))
			hc.UnregisterPeer(peerKey)
		}(i)
	}
	wg.Wait()

	// All should be unregistered.
	for i := 0; i < 20; i++ {
		peerKey := "peer" + string(rune('A'+i))
		if hc.IsRegistered(peerKey) {
			t.Errorf("peer %s should be unregistered", peerKey)
		}
	}
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

// === Comprehensive NAT Traversal Test Strategy Coverage ===
//
// The following tests fill gaps identified by the tester strategy:
// 1. State machine paths: DIRECT_PROBE with no endpoints, reprobe with no endpoints
// 2. Retry backoff behavior: RETRY stays in retry with active backoff
// 3. FAILED terminal state: no further transitions from FAILED
// 4. Relay messaging: nil gossip layer for SETUP/TEARDOWN
// 5. No relay candidates → RETRY path
// 6. Gossip layer wiring verification
// 7. Concurrent InitiateConnection + RemoveConnection safety
// 8. Session field consistency after transitions
// 9. AllSessions snapshot under concurrent modification
// 10. StunClient error handling (bad server address)

// TestNatTraversal_DirectProbe_NoEndpoints_ToRelay verifies that DIRECT_PROBE
// with no known peer endpoints falls back to relay when relay mode is auto.
func TestNatTraversal_DirectProbe_NoEndpoints_ToRelay(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	// Set up relay candidate.
	relayKey := "eeeeffff00001111"
	relayIP := "10.10.5.6"
	setupTestRelay(t, events, relayKey, relayIP)

	peerKey := "aaaabbbbccccdddd"
	// Initiate with empty endpoints — DIRECT_PROBE will see no endpoints.
	nt.InitiateConnection(peerKey, []string{}, NatTypeFullCone)

	time.Sleep(200 * time.Millisecond)

	state := nt.SessionState(peerKey)
	if state != NatRelayFallback {
		t.Errorf("expected RELAY_FALLBACK when no peer endpoints, got %s", state)
	}

	updatedEP, ok := pm.GetUpdatedEndpoints(peerKey)
	if !ok || len(updatedEP) == 0 || updatedEP[0] != relayIP+":51820" {
		t.Errorf("expected endpoint updated to relay %s:51820, got %v", relayIP, updatedEP)
	}
}

// TestNatTraversal_DirectProbe_NoEndpoints_RelayDisabled verifies that
// DIRECT_PROBE with no endpoints and relay=disabled transitions to RETRY.
func TestNatTraversal_DirectProbe_NoEndpoints_RelayDisabled(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.RelayMode = "disabled"
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{}, NatTypeFullCone)

	time.Sleep(200 * time.Millisecond)

	state := nt.SessionState(peerKey)
	if state != NatRetry {
		t.Errorf("expected RETRY with no endpoints + relay disabled, got %s", state)
	}
}

// TestNatTraversal_Reprobe_NoEndpoints_BackToRelay verifies that
// DIRECT_REPROBE with no peer endpoints goes back to RELAY_FALLBACK.
func TestNatTraversal_Reprobe_NoEndpoints_BackToRelay(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.DirectReprobeInterval = 30 * time.Millisecond
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	// Place session in RELAY_FALLBACK state.
	nt.SetLocalDiscovery("203.0.113.5:51821", NatTypeSymmetric)

	relayKey := "eeeeffff00001111"
	relayIP := "10.10.5.6"
	setupTestRelay(t, events, relayKey, relayIP)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeSymmetric)

	// Wait for relay fallback.
	time.Sleep(150 * time.Millisecond)

	state := nt.SessionState(peerKey)
	if state != NatRelayFallback {
		t.Fatalf("expected RELAY_FALLBACK before reprobe, got %s", state)
	}

	// Clear endpoints to simulate peer losing STUN endpoints.
	session := nt.GetSession(peerKey)
	if session == nil {
		t.Fatal("session should exist")
	}
	session.mu.Lock()
	session.Endpoints = []string{}
	session.mu.Unlock()

	// Start reprobe loop.
	nt.reprobeTC = time.NewTicker(nt.cfg.DirectReprobeInterval)
	go nt.reprobeLoop()
	defer nt.reprobeTC.Stop()

	time.Sleep(200 * time.Millisecond)

	state = nt.SessionState(peerKey)
	if state != NatRelayFallback {
		t.Errorf("expected RELAY_FALLBACK after reprobe with no endpoints, got %s", state)
	}

	// Verify relay endpoint is restored.
	updatedEP, ok := pm.GetUpdatedEndpoints(peerKey)
	if !ok || len(updatedEP) == 0 || updatedEP[0] != relayIP+":51820" {
		t.Errorf("expected relay endpoint %s:51820 after reprobe, got %v", relayIP, updatedEP)
	}
}

// TestNatTraversal_Retry_BackoffActive verifies that the RETRY state applies
// exponential backoff before transitioning to STUN_DISCOVERY.
func TestNatTraversal_Retry_BackoffActive(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.MaxRetries = 2
	nt.cfg.ProbeTimeout = 20 * time.Millisecond
	nt.cfg.RelayMode = "disabled"

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{}, NatTypeFullCone)

	// Wait for STUN_DISCOVERY → DIRECT_PROBE → RETRY.
	time.Sleep(100 * time.Millisecond)

	state := nt.SessionState(peerKey)
	if state != NatRetry {
		t.Fatalf("expected RETRY, got %s", state)
	}

	// Verify retry count was incremented.
	session := nt.GetSession(peerKey)
	session.mu.Lock()
	retries := session.Retries
	session.mu.Unlock()
	if retries != 1 {
		t.Errorf("expected Retries=1 after first retry, got %d", retries)
	}

	// The backoff for retry 1 should be 10 seconds (2^1 * 5s).
	// After 500ms, the state should still be RETRY (backoff hasn't elapsed).
	time.Sleep(500 * time.Millisecond)
	state = nt.SessionState(peerKey)
	if state != NatRetry {
		t.Errorf("expected RETRY state during backoff, got %s", state)
	}
}

// TestNatTraversal_Failed_TerminalState verifies that FAILED is a terminal state:
// once a session reaches FAILED, no further state transitions can occur.
func TestNatTraversal_Failed_TerminalState(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.MaxRetries = 0
	nt.cfg.ProbeTimeout = 20 * time.Millisecond
	nt.cfg.RelayMode = "disabled"

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{}, NatTypeFullCone)

	time.Sleep(200 * time.Millisecond)

	state := nt.SessionState(peerKey)
	if state != NatFailed {
		t.Fatalf("expected FAILED, got %s", state)
	}

	// Verify the runStateMachine goroutine exited — the session state
	// should stay FAILED regardless of how long we wait.
	session := nt.GetSession(peerKey)
	if session == nil {
		t.Fatal("session should exist")
	}
	session.mu.Lock()
	state = session.State
	session.mu.Unlock()
	if state != NatFailed {
		t.Errorf("session.State changed from FAILED to %s after goroutine exit", state)
	}

	// After an additional wait, still FAILED.
	time.Sleep(100 * time.Millisecond)
	state = nt.SessionState(peerKey)
	if state != NatFailed {
		t.Errorf("expected FAILED terminal, got %s", state)
	}
}

// TestNatTraversal_SetGossipLayer verifies SetGossipLayer wires the gossip
// layer's LocalMeta public key to localKey.
func TestNatTraversal_SetGossipLayer(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)

	// Before SetGossipLayer, localKey should be empty.
	nt.mu.RLock()
	key := nt.localKey
	nt.mu.RUnlock()
	if key != "" {
		t.Errorf("expected empty localKey before SetGossipLayer, got %s", key)
	}

	// Create a GossipLayer with a delegate that has localMeta set.
	localKey := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	md := newMeshDelegate(&NodeMeta{PublicKey: localKey})
	gl := &GossipLayer{
		delegate:  md,
		localMeta: &NodeMeta{PublicKey: localKey},
	}

	nt.SetGossipLayer(gl)

	// After SetGossipLayer, localKey should be set from delegate.
	nt.mu.RLock()
	key = nt.localKey
	nt.mu.RUnlock()
	if key != localKey {
		t.Errorf("expected localKey=%s after SetGossipLayer, got %s", localKey, key)
	}

	// Setting nil should NOT clear the local key (only gossip layer is nil'd).
	nt.SetGossipLayer(nil)
	nt.mu.RLock()
	key = nt.localKey
	gossipNil := nt.gossipLayer == nil
	nt.mu.RUnlock()
	if !gossipNil {
		t.Error("expected gossipLayer to be nil after SetGossipLayer(nil)")
	}
	// localKey is not cleared on SetGossipLayer(nil) — that's intentional.
	if key == "" {
		t.Error("expected localKey to persist after SetGossipLayer(nil)")
	}
}

// TestNatTraversal_SendRelaySetup_NilGossip verifies sendRelaySetup returns
// empty circuit ID when gossip layer is nil.
func TestNatTraversal_SendRelaySetup_NilGossip(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)

	circuitID := nt.sendRelaySetup("relaykey123", "targetkey456", []string{"203.0.113.10:51820"})
	if circuitID != "" {
		t.Errorf("expected empty circuit ID with nil gossip layer, got %s", circuitID)
	}
}

// TestNatTraversal_SendRelayTeardown_NilGossip verifies sendRelayTeardown is
// a no-op when gossip layer is nil.
func TestNatTraversal_SendRelayTeardown_NilGossip(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)

	// This should not panic — just a no-op.
	nt.sendRelayTeardown("relaykey123", "circuit-abc123")
}

// TestNatTraversal_NoRelayCandidates_Retry verifies that transitionToRelay
// falls back to RETRY when relay selector has no candidates.
func TestNatTraversal_NoRelayCandidates_Retry(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events) // empty relay pool
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeSymmetric)

	time.Sleep(200 * time.Millisecond)

	state := nt.SessionState(peerKey)
	if state != NatRetry {
		t.Errorf("expected RETRY when no relay candidates, got %s", state)
	}

	session := nt.GetSession(peerKey)
	if session == nil {
		t.Fatal("session should exist")
	}
	session.mu.Lock()
	retries := session.Retries
	session.mu.Unlock()
	if retries != 1 {
		t.Errorf("expected Retries incremented to 1, got %d", retries)
	}
}

// TestNatTraversal_ConcurrentInitiateRemove verifies thread safety of
// concurrent InitiateConnection and RemoveConnection.
func TestNatTraversal_ConcurrentInitiateRemove(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.ProbeTimeout = 10 * time.Millisecond

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	peers := []string{"peerA", "peerB", "peerC", "peerD", "peerE"}
	var wg sync.WaitGroup

	// Concurrently initiate connections.
	for _, pk := range peers {
		wg.Add(1)
		go func(peerKey string) {
			defer wg.Done()
			nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeFullCone)
		}(pk)
	}

	// Concurrently remove some.
	for _, pk := range peers {
		wg.Add(1)
		go func(peerKey string) {
			defer wg.Done()
			time.Sleep(20 * time.Millisecond) // slight delay to let init run
			nt.RemoveConnection(peerKey)
		}(pk)
	}

	wg.Wait()

	// After all operations, sessions map should be empty.
	sessions := nt.AllSessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after concurrent init+remove, got %d", len(sessions))
	}
}

// TestNatTraversal_SessionFieldsAfterRelayFallback verifies session fields
// are correctly populated after relay fallback transition.
func TestNatTraversal_SessionFieldsAfterRelayFallback(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	nt.SetLocalDiscovery("203.0.113.5:51821", NatTypeSymmetric)

	relayKey := "eeeeffff00001111"
	relayIP := "10.10.5.6"
	setupTestRelay(t, events, relayKey, relayIP)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeSymmetric)

	time.Sleep(200 * time.Millisecond)

	session := nt.GetSession(peerKey)
	if session == nil {
		t.Fatal("session should exist")
	}

	session.mu.Lock()
	state := session.State
	endpoints := session.Endpoints
	remoteNat := session.RemoteNatType
	relayVia := session.RelayVia
	circuitID := session.CircuitID
	session.mu.Unlock()

	if state != NatRelayFallback {
		t.Errorf("expected RELAY_FALLBACK, got %s", state)
	}
	if len(endpoints) != 1 || endpoints[0] != "203.0.113.10:51820" {
		t.Errorf("expected endpoints preserved as [203.0.113.10:51820], got %v", endpoints)
	}
	if remoteNat != NatTypeSymmetric {
		t.Errorf("expected RemoteNatType=symmetric, got %s", remoteNat)
	}
	if relayVia != relayKey {
		t.Errorf("expected RelayVia=%s, got %s", relayKey, relayVia)
	}
	// CircuitID may be empty when gossip layer is not wired.
	// This is correct: sendRelaySetup returns "" when gossipLayer is nil.
	if circuitID != "" {
		t.Logf("CircuitID=%s (gossip layer is nil — empty is expected)", circuitID)
	}
}

// TestNatTraversal_AllSessions_ConcurrentModification verifies AllSessions
// snapshot is thread-safe during concurrent state changes.
func TestNatTraversal_AllSessions_ConcurrentModification(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.ProbeTimeout = 10 * time.Millisecond

	nt.SetLocalDiscovery("203.0.113.5:51820", NatTypeFullCone)

	// Add several sessions.
	for i := 0; i < 20; i++ {
		peerKey := "peer" + string(rune('A'+i))
		nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeFullCone)
	}

	done := make(chan struct{})

	// Concurrent reader goroutine.
	go func() {
		for i := 0; i < 100; i++ {
			sessions := nt.AllSessions()
			if len(sessions) < 0 {
				t.Error("AllSessions returned negative length") // should never happen
			}
		}
		done <- struct{}{}
	}()

	// Concurrent mutator goroutine.
	go func() {
		for i := 0; i < 20; i++ {
			peerKey := "peer" + string(rune('A'+i))
			nt.RemoveConnection(peerKey)
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}

// TestStunClient_Discover_BadServer verifies StunClient.Discover handles
// unresolvable server addresses gracefully.
func TestStunClient_Discover_BadServer(t *testing.T) {
	sc := NewStunClient([]string{"bad-server.invalid:9999"}, 2*time.Second)
	_, err := sc.Discover()
	if err == nil {
		t.Error("expected error from bad server address")
	}
}

// TestStunClient_Discover_ServerFailover verifies StunClient.Discover
// fails over to the second server when the first is unreachable.
func TestStunClient_Discover_ServerFailover(t *testing.T) {
	// This test queries the real Google STUN server, so skip if offline.
	conn, err := net.DialTimeout("udp", "stun.l.google.com:19302", 2*time.Second)
	if err != nil {
		t.Skip("STUN server not reachable, skipping failover test")
	}
	conn.Close()

	sc := NewStunClient([]string{"unreachable.stun.server:3478", "stun.l.google.com:19302"}, 5*time.Second)
	discovery, err := sc.Discover()
	if err != nil {
		t.Fatalf("Discover should succeed via second server: %v", err)
	}
	if discovery.MappedAddress == "" {
		t.Error("expected non-empty mapped address")
	}
	t.Logf("STUN failover: endpoint=%s via %s", discovery.MappedAddress, discovery.Server)
}

// TestNatTraversal_Reprobe_MultipleCycles verifies that multiple re-probe
// cycles work correctly for sessions in RELAY_FALLBACK.
func TestNatTraversal_Reprobe_MultipleCycles(t *testing.T) {
	pm := newMockPeerManager()
	events := newMeshEventDelegate(newMeshDelegate(&NodeMeta{}), pm)
	relay := NewRelaySelector(events)
	nt := newTestNatTraversal(pm, relay, events)
	nt.cfg.DirectReprobeInterval = 30 * time.Millisecond
	nt.cfg.ProbeTimeout = 20 * time.Millisecond

	nt.SetLocalDiscovery("203.0.113.5:51821", NatTypeSymmetric)

	relayKey := "eeeeffff00001111"
	relayIP := "10.10.5.6"
	setupTestRelay(t, events, relayKey, relayIP)

	peerKey := "aaaabbbbccccdddd"
	nt.InitiateConnection(peerKey, []string{"203.0.113.10:51820"}, NatTypeSymmetric)

	// Poll until the state settles to RELAY_FALLBACK (both-symmetric → forced relay).
	// Using a polling loop instead of fixed sleep to avoid timing-dependent flakes.
	var state NatState
	deadline := time.After(500 * time.Millisecond)
	for {
		state = nt.SessionState(peerKey)
		if state == NatRelayFallback {
			break
		}
		if state == NatFailed {
			t.Fatalf("unexpected FAILED before reaching RELAY_FALLBACK")
		}
		select {
		case <-deadline:
			t.Fatalf("state did not reach RELAY_FALLBACK after timeout, got %s", state)
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Start re-probe loop.
	nt.reprobeTC = time.NewTicker(nt.cfg.DirectReprobeInterval)
	go nt.reprobeLoop()
	defer nt.reprobeTC.Stop()

	// Wait for multiple re-probe cycles to complete and state to settle.
	// Each cycle: RELAY_FALLBACK → DIRECT_REPROBE → (probe fails) → RELAY_FALLBACK.
	// Poll until state is RELAY_FALLBACK (not caught mid-transition).
	deadline = time.After(500 * time.Millisecond)
	for {
		state = nt.SessionState(peerKey)
		if state == NatRelayFallback {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("state did not settle to RELAY_FALLBACK after timeout, got %s", state)
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Verify endpoint was updated (should still be relay endpoint).
	updatedEP, ok := pm.GetUpdatedEndpoints(peerKey)
	if !ok || len(updatedEP) == 0 || updatedEP[0] != relayIP+":51820" {
		t.Errorf("expected relay endpoint %s:51820, got %v", relayIP, updatedEP)
	}
}
