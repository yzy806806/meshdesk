package p2p

import (
	"sync"
	"testing"
	"time"
)

// testRelayEnv is a test harness for RelaySessionManager tests.
// It provides a mock message sender and captures sent messages.
type testRelayEnv struct {
	rsm      *RelaySessionManager
	sentMu   sync.Mutex
	sent     []*sentMsg
	localKey string
}

type sentMsg struct {
	peerKey string
	msg     *RelayMessage
}

func newTestRelayEnv(t *testing.T, maxCircuits int) *testRelayEnv {
	t.Helper()
	localKey := "localkey1234567890abcdef"

	// Create minimal delegate + events for the RSM.
	// We need a meshDelegate (for load metric updates) and an
	// meshEventDelegate (for peer metadata lookups).
	localMeta := &NodeMeta{
		PublicKey:   localKey,
		Hostname:    "test-relay",
		Role:        "relay",
		CapRelay:    true,
		MaxCircuits: maxCircuits,
		Seq:         1,
	}
	delegate := newMeshDelegate(localMeta)
	events := newMeshEventDelegate(delegate, nil) // nil PeerManager is OK for these tests

	cfg := RelaySessionManagerConfig{
		MaxCircuits:         maxCircuits,
		IdleTimeout:         100 * time.Millisecond, // short for testing
		HealthCheckInterval: 20 * time.Millisecond,  // short for testing
	}
	rsm := NewRelaySessionManager(localKey, events, delegate, cfg, nil) // nil PeerManager is OK for these tests

	env := &testRelayEnv{
		rsm:      rsm,
		localKey: localKey,
	}

	// Wire a mock message sender that captures messages.
	rsm.SetMessageSender(func(peerKey string, msg *RelayMessage) {
		env.sentMu.Lock()
		env.sent = append(env.sent, &sentMsg{peerKey: peerKey, msg: msg})
		env.sentMu.Unlock()
	})

	return env
}

func (e *testRelayEnv) getSent() []*sentMsg {
	e.sentMu.Lock()
	defer e.sentMu.Unlock()
	return append([]*sentMsg{}, e.sent...)
}

func (e *testRelayEnv) clearSent() {
	e.sentMu.Lock()
	e.sent = nil
	e.sentMu.Unlock()
}

func TestRelaySessionSetupAccept(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	entryKey := "entrykey1234567890abcdef"
	targetKey := "targetkey1234567890ab"
	circuitID := "circuit-test-001"

	// Send a setup request.
	setupMsg := RelaySetupRequest(entryKey, env.localKey, circuitID, targetKey, []string{"10.10.1.5"})
	if err := env.rsm.HandleMessage(setupMsg); err != nil {
		t.Fatalf("HandleMessage(setup) failed: %v", err)
	}

	// Verify the circuit was accepted.
	if env.rsm.TotalCircuitCount() != 1 {
		t.Errorf("TotalCircuitCount = %d, want 1", env.rsm.TotalCircuitCount())
	}
	if env.rsm.ActiveCircuitCount() != 1 {
		t.Errorf("ActiveCircuitCount = %d, want 1", env.rsm.ActiveCircuitCount())
	}

	// Verify an ACCEPT message was sent back to the entry.
	sent := env.getSent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(sent))
	}
	if sent[0].peerKey != entryKey {
		t.Errorf("sent to %s, want %s", sent[0].peerKey, entryKey)
	}
	if sent[0].msg.Type != MsgRelayAccept {
		t.Errorf("sent %s, want ACCEPT", sent[0].msg.Type)
	}
	if sent[0].msg.CircuitID != circuitID {
		t.Errorf("circuit ID = %s, want %s", sent[0].msg.CircuitID, circuitID)
	}

	// Verify session info.
	info := env.rsm.GetSessionInfo(circuitID)
	if info == nil {
		t.Fatal("GetSessionInfo returned nil")
	}
	if info.State != RelaySessionActive {
		t.Errorf("session state = %s, want ACTIVE", info.State)
	}
	if info.EntryKey != entryKey {
		t.Errorf("entry key = %s, want %s", info.EntryKey, entryKey)
	}
	if info.TargetKey != targetKey {
		t.Errorf("target key = %s, want %s", info.TargetKey, targetKey)
	}
	if len(info.TargetEndpoints) == 0 || info.TargetEndpoints[0] != "10.10.1.5" {
		t.Errorf("target endpoints = %v, want [10.10.1.5]", info.TargetEndpoints)
	}
}

func TestRelaySessionDuplicateReject(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	entryKey := "entrykey1234567890abcdef"
	circuitID := "circuit-dup-001"

	// First setup should succeed.
	setup1 := RelaySetupRequest(entryKey, env.localKey, circuitID, "targetkey1234567890ab", []string{"10.10.1.5"})
	if err := env.rsm.HandleMessage(setup1); err != nil {
		t.Fatalf("first HandleMessage failed: %v", err)
	}
	env.clearSent()

	// Second setup with same circuit ID should be rejected.
	setup2 := RelaySetupRequest(entryKey, env.localKey, circuitID, "targetkey1234567890ab", []string{"10.10.1.5"})
	if err := env.rsm.HandleMessage(setup2); err != nil {
		t.Fatalf("second HandleMessage failed: %v", err)
	}

	sent := env.getSent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(sent))
	}
	if sent[0].msg.Type != MsgRelayReject {
		t.Errorf("sent %s, want REJECT", sent[0].msg.Type)
	}
	if sent[0].msg.RejectReason != RejectDuplicate {
		t.Errorf("reject reason = %s, want %s", sent[0].msg.RejectReason, RejectDuplicate)
	}

	// Total circuits should still be 1 (the original).
	if env.rsm.TotalCircuitCount() != 1 {
		t.Errorf("TotalCircuitCount = %d, want 1", env.rsm.TotalCircuitCount())
	}
}

func TestRelaySessionCapacityReject(t *testing.T) {
	// MaxCircuits = 1
	env := newTestRelayEnv(t, 1)

	entryKey := "entrykey1234567890abcdef"

	// First circuit should succeed.
	setup1 := RelaySetupRequest(entryKey, env.localKey, "c1", "target1key1234567890a", []string{"10.10.1.5"})
	if err := env.rsm.HandleMessage(setup1); err != nil {
		t.Fatalf("first HandleMessage failed: %v", err)
	}
	env.clearSent()

	// Second circuit should be rejected (at capacity).
	setup2 := RelaySetupRequest(entryKey, env.localKey, "c2", "target2key1234567890a", []string{"10.10.1.6"})
	if err := env.rsm.HandleMessage(setup2); err != nil {
		t.Fatalf("second HandleMessage failed: %v", err)
	}

	sent := env.getSent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(sent))
	}
	if sent[0].msg.Type != MsgRelayReject {
		t.Errorf("sent %s, want REJECT", sent[0].msg.Type)
	}
	if sent[0].msg.RejectReason != RejectAtCapacity {
		t.Errorf("reject reason = %s, want %s", sent[0].msg.RejectReason, RejectAtCapacity)
	}

	// With 1 active circuit and maxCircuits=1, we ARE at capacity.
	if !env.rsm.IsAtCapacity() {
		t.Error("IsAtCapacity should be true with 1 active circuit and max=1")
	}
}

func TestRelaySessionTeardown(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	entryKey := "entrykey1234567890abcdef"
	circuitID := "circuit-td-001"

	// Setup a circuit.
	setup := RelaySetupRequest(entryKey, env.localKey, circuitID, "targetkey1234567890ab", []string{"10.10.1.5"})
	if err := env.rsm.HandleMessage(setup); err != nil {
		t.Fatalf("HandleMessage(setup) failed: %v", err)
	}
	env.clearSent()

	if env.rsm.TotalCircuitCount() != 1 {
		t.Fatalf("expected 1 circuit, got %d", env.rsm.TotalCircuitCount())
	}

	// Teardown the circuit.
	td := RelayTeardownRequest(entryKey, env.localKey, circuitID)
	if err := env.rsm.HandleMessage(td); err != nil {
		t.Fatalf("HandleMessage(teardown) failed: %v", err)
	}

	// Circuit should be removed.
	if env.rsm.TotalCircuitCount() != 0 {
		t.Errorf("TotalCircuitCount = %d, want 0", env.rsm.TotalCircuitCount())
	}
	if env.rsm.GetSessionInfo(circuitID) != nil {
		t.Error("GetSessionInfo should return nil after teardown")
	}
}

func TestRelaySessionTeardownUnauthorized(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	entryKey := "entrykey1234567890abcdef"
	otherKey := "otherkey1234567890abcdef0"
	circuitID := "circuit-unauth-001"

	// Setup a circuit from entryKey.
	setup := RelaySetupRequest(entryKey, env.localKey, circuitID, "targetkey1234567890ab", []string{"10.10.1.5"})
	if err := env.rsm.HandleMessage(setup); err != nil {
		t.Fatalf("HandleMessage(setup) failed: %v", err)
	}
	env.clearSent()

	// Attempt teardown from a different key.
	td := RelayTeardownRequest(otherKey, env.localKey, circuitID)
	err := env.rsm.HandleMessage(td)
	if err == nil {
		t.Error("expected error for unauthorized teardown")
	}

	// Circuit should still exist.
	if env.rsm.TotalCircuitCount() != 1 {
		t.Errorf("TotalCircuitCount = %d, want 1 (unauthorized teardown should not remove)", env.rsm.TotalCircuitCount())
	}
}

func TestRelaySessionPingPong(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	entryKey := "entrykey1234567890abcdef"
	circuitID := "circuit-ping-001"

	// Setup a circuit.
	setup := RelaySetupRequest(entryKey, env.localKey, circuitID, "targetkey1234567890ab", []string{"10.10.1.5"})
	if err := env.rsm.HandleMessage(setup); err != nil {
		t.Fatalf("HandleMessage(setup) failed: %v", err)
	}
	env.clearSent()

	// Send a ping.
	ping := RelayPingMessage(entryKey, env.localKey, circuitID)
	if err := env.rsm.HandleMessage(ping); err != nil {
		t.Fatalf("HandleMessage(ping) failed: %v", err)
	}

	// Verify a PONG was sent back.
	sent := env.getSent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(sent))
	}
	if sent[0].msg.Type != MsgRelayPong {
		t.Errorf("sent %s, want PONG", sent[0].msg.Type)
	}
	if sent[0].peerKey != entryKey {
		t.Errorf("PONG sent to %s, want %s", sent[0].peerKey, entryKey)
	}

	// Verify LastActivity was updated.
	info := env.rsm.GetSessionInfo(circuitID)
	if info == nil {
		t.Fatal("GetSessionInfo returned nil")
	}
	if time.Since(info.LastActivity) > time.Second {
		t.Error("LastActivity not updated after ping")
	}
}

func TestRelaySessionPingUnknownCircuit(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	// Ping for a non-existent circuit should be silently ignored.
	ping := RelayPingMessage("entrykey1234567890abcdef", env.localKey, "nonexistent")
	if err := env.rsm.HandleMessage(ping); err != nil {
		t.Fatalf("HandleMessage(ping unknown) failed: %v", err)
	}

	// No PONG should be sent.
	sent := env.getSent()
	if len(sent) != 0 {
		t.Errorf("expected 0 sent messages, got %d", len(sent))
	}
}

func TestRelaySessionTeardownUnknownCircuit(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	// Teardown for a non-existent circuit should be a no-op (idempotent).
	td := RelayTeardownRequest("entrykey1234567890abcdef", env.localKey, "nonexistent")
	if err := env.rsm.HandleMessage(td); err != nil {
		t.Fatalf("HandleMessage(teardown unknown) failed: %v", err)
	}
}

func TestRelaySessionIdleSweep(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	// Don't start the RSM — we'll test sweepIdleCircuits directly.
	entryKey := "entrykey1234567890abcdef"
	circuitID := "circuit-idle-001"

	// Setup a circuit.
	setup := RelaySetupRequest(entryKey, env.localKey, circuitID, "targetkey1234567890ab", []string{"10.10.1.5"})
	if err := env.rsm.HandleMessage(setup); err != nil {
		t.Fatalf("HandleMessage(setup) failed: %v", err)
	}

	// Circuit should exist.
	if env.rsm.TotalCircuitCount() != 1 {
		t.Fatalf("expected 1 circuit, got %d", env.rsm.TotalCircuitCount())
	}

	// Wait for idle timeout to pass (100ms in test config).
	time.Sleep(150 * time.Millisecond)

	// Manually trigger sweep.
	env.rsm.sweepIdleCircuits()

	// Circuit should be swept.
	if env.rsm.TotalCircuitCount() != 0 {
		t.Errorf("expected 0 circuits after idle sweep, got %d", env.rsm.TotalCircuitCount())
	}
}

func TestRelaySessionStartStop(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	if err := env.rsm.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Double start should fail.
	if err := env.rsm.Start(); err == nil {
		t.Error("second Start should fail")
	}

	// Stop.
	if err := env.rsm.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Double stop should be a no-op.
	if err := env.rsm.Stop(); err != nil {
		t.Fatalf("second Stop failed: %v", err)
	}
}

func TestRelaySessionAllSessions(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	// Setup 3 circuits.
	for i := 0; i < 3; i++ {
		circuitID := "circuit-all-" + string(rune('0'+i))
		setup := RelaySetupRequest(
			"entrykey1234567890abcdef",
			env.localKey,
			circuitID,
			"targetkey1234567890ab",
			[]string{"10.10.1.5"},
		)
		if err := env.rsm.HandleMessage(setup); err != nil {
			t.Fatalf("HandleMessage(%d) failed: %v", i, err)
		}
	}

	sessions := env.rsm.AllSessions()
	if len(sessions) != 3 {
		t.Errorf("AllSessions returned %d, want 3", len(sessions))
	}

	// Verify each session has correct info.
	for _, s := range sessions {
		if s.State != RelaySessionActive {
			t.Errorf("session %s state = %s, want ACTIVE", s.CircuitID, s.State)
		}
		if s.EntryKey != "entrykey1234567890abcdef" {
			t.Errorf("session %s entry = %s, want entrykey...", s.CircuitID, s.EntryKey)
		}
	}

	// CircuitIDs should return all IDs.
	ids := env.rsm.CircuitIDs()
	if len(ids) != 3 {
		t.Errorf("CircuitIDs returned %d, want 3", len(ids))
	}
}

func TestRelaySessionMessageNotForUs(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	// Message addressed to a different relay should be ignored.
	msg := RelaySetupRequest(
		"entrykey1234567890abcdef",
		"differentrelaykey1234567", // not our key
		"circuit-notforus",
		"targetkey1234567890ab",
		[]string{"10.10.1.5"},
	)
	// The ToKey is set to "differentrelaykey1234567", which is not us.
	if err := env.rsm.HandleMessage(msg); err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	// No circuit should be created.
	if env.rsm.TotalCircuitCount() != 0 {
		t.Errorf("TotalCircuitCount = %d, want 0 (message not for us)", env.rsm.TotalCircuitCount())
	}
}

func TestRelaySessionLoadMetricUpdate(t *testing.T) {
	env := newTestRelayEnv(t, 10)

	// Setup a circuit — this should update LoadCircuits in local meta.
	setup := RelaySetupRequest(
		"entrykey1234567890abcdef",
		env.localKey,
		"circuit-load-001",
		"targetkey1234567890ab",
		[]string{"10.10.1.5"},
	)
	if err := env.rsm.HandleMessage(setup); err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	// The delegate's local meta should have LoadCircuits = 1.
	// We can verify this through the rsm.ActiveCircuitCount().
	if env.rsm.ActiveCircuitCount() != 1 {
		t.Errorf("ActiveCircuitCount = %d, want 1", env.rsm.ActiveCircuitCount())
	}

	// Teardown should decrement.
	td := RelayTeardownRequest("entrykey1234567890abcdef", env.localKey, "circuit-load-001")
	if err := env.rsm.HandleMessage(td); err != nil {
		t.Fatalf("HandleMessage(teardown) failed: %v", err)
	}

	if env.rsm.ActiveCircuitCount() != 0 {
		t.Errorf("ActiveCircuitCount = %d, want 0 after teardown", env.rsm.ActiveCircuitCount())
	}
}

func TestRelaySessionMaxCircuitsAccessor(t *testing.T) {
	env := newTestRelayEnv(t, 42)
	if env.rsm.MaxCircuits() != 42 {
		t.Errorf("MaxCircuits = %d, want 42", env.rsm.MaxCircuits())
	}
}

func TestRelaySessionStateString(t *testing.T) {
	tests := []struct {
		state RelaySessionState
		want  string
	}{
		{RelaySessionPending, "PENDING"},
		{RelaySessionActive, "ACTIVE"},
		{RelaySessionClosing, "CLOSING"},
		{RelaySessionState(99), "UNKNOWN(99)"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("state(%d).String() = %s, want %s", tt.state, got, tt.want)
		}
	}
}

func TestDelegateNotifyMsgRelay(t *testing.T) {
	// Test that the delegate's NotifyMsg correctly dispatches
	// relay messages to the installed handler.
	localMeta := &NodeMeta{
		PublicKey: "relaykey1234567890abcdef",
	}
	delegate := newMeshDelegate(localMeta)

	// Track handler calls.
	var handlerCalled bool
	var receivedMsg *RelayMessage
	delegate.SetRelayMessageHandler(func(msg *RelayMessage) error {
		handlerCalled = true
		receivedMsg = msg
		return nil
	})

	// Create and send a relay message.
	origMsg := RelaySetupRequest("entrykey1234567890abcdef", "relaykey1234567890abcdef", "c1", "target", []string{"10.10.1.5"})
	data, err := origMsg.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Simulate gossip delivery.
	delegate.NotifyMsg(data)

	if !handlerCalled {
		t.Error("handler was not called")
	}
	if receivedMsg == nil {
		t.Fatal("received message is nil")
	}
	if receivedMsg.Type != MsgRelaySetup {
		t.Errorf("received type = %s, want SETUP", receivedMsg.Type)
	}
	if receivedMsg.CircuitID != "c1" {
		t.Errorf("received circuit ID = %s, want c1", receivedMsg.CircuitID)
	}
}

func TestDelegateNotifyMsgNonRelay(t *testing.T) {
	delegate := newMeshDelegate(&NodeMeta{PublicKey: "test"})

	var handlerCalled bool
	delegate.SetRelayMessageHandler(func(msg *RelayMessage) error {
		handlerCalled = true
		return nil
	})

	// Non-relay data should not trigger the handler.
	delegate.NotifyMsg([]byte("not a relay message"))
	if handlerCalled {
		t.Error("handler called for non-relay message")
	}

	// Empty data should be a no-op.
	delegate.NotifyMsg([]byte{})
	delegate.NotifyMsg(nil)
}
