package p2p

import (
	"context"
	"sync"
	"testing"
	"time"
)

// --- Test helpers ---

// testJoinSetup creates a JoinProtocol with wired callbacks for testing.
type testJoinSetup struct {
	jp         *JoinProtocol
	delegate   *meshDelegate
	events     *meshEventDelegate
	sentMsgs   []joinSentMsg
	broadcasts []*JoinMessage
	alerts     []alertEvent
	mu         sync.Mutex
}

type joinSentMsg struct {
	peerKey string
	msg     *JoinMessage
}

type alertEvent struct {
	eventType string
	peerKey   string
	reason    string
}

func newTestJoinSetup(localKey string, authorizedKeys []string, approvalMode string) *testJoinSetup {
	localMeta := &NodeMeta{
		PublicKey: localKey,
		Hostname:  "test-node",
		Role:      "agent",
		MeshIP:    testMeshIP(localKey),
		Version:   "1.0.0",
		Seq:       1,
	}
	delegate := newMeshDelegate(localMeta)
	wgMgr := newMockPeerManager()
	events := newMeshEventDelegate(delegate, wgMgr)

	cfg := JoinConfig{
		LocalPublicKey: localKey,
		JoinApproval:   approvalMode,
		AuthorizedKeys: authorizedKeys,
		MaxPeers:       256,
		JoinTimeout:    5,
		RetryCooldown:  1,
		LeaveTimeout:   1,
	}
	jp := NewJoinProtocol(cfg, delegate, events)

	setup := &testJoinSetup{
		jp:       jp,
		delegate: delegate,
		events:   events,
	}

	jp.SetMessageSender(func(peerKey string, msg *JoinMessage) {
		setup.mu.Lock()
		setup.sentMsgs = append(setup.sentMsgs, joinSentMsg{peerKey: peerKey, msg: msg})
		setup.mu.Unlock()
	})

	jp.SetBroadcastSender(func(msg *JoinMessage) {
		setup.mu.Lock()
		setup.broadcasts = append(setup.broadcasts, msg)
		setup.mu.Unlock()
	})

	jp.SetPeerListProvider(func() []*NodeMeta {
		return events.AllKnownPeers()
	})

	jp.SetPeerCountProvider(func() int {
		return events.KnownPeerCount()
	})

	jp.SetAlertHandler(func(eventType, peerKey, reason string) {
		setup.mu.Lock()
		setup.alerts = append(setup.alerts, alertEvent{
			eventType: eventType,
			peerKey:   peerKey,
			reason:    reason,
		})
		setup.mu.Unlock()
	})

	return setup
}

func (s *testJoinSetup) getSentMsgs() []joinSentMsg {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]joinSentMsg{}, s.sentMsgs...)
}

func (s *testJoinSetup) getBroadcasts() []*JoinMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*JoinMessage{}, s.broadcasts...)
}

func (s *testJoinSetup) getAlerts() []alertEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]alertEvent{}, s.alerts...)
}

// --- Message serialization tests ---

func TestJoinMessageMarshalUnmarshal(t *testing.T) {
	meta := &NodeMeta{
		PublicKey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Hostname:  "test-node",
		Role:      "agent",
		MeshIP:    "10.10.172.206",
		Version:   "1.0.0",
		Seq:       1,
	}

	original := NewJoinMessage(MsgJoinRequest, "fromkey1234567890", "tokey123456789012345")
	original.NodeMeta = meta

	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Marshal returned empty data")
	}

	decoded, err := UnmarshalJoinMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalJoinMessage failed: %v", err)
	}

	if decoded.Type != MsgJoinRequest {
		t.Errorf("Type = %d, want %d", decoded.Type, MsgJoinRequest)
	}
	if decoded.FromKey != original.FromKey {
		t.Errorf("FromKey = %s, want %s", decoded.FromKey, original.FromKey)
	}
	if decoded.ToKey != original.ToKey {
		t.Errorf("ToKey = %s, want %s", decoded.ToKey, original.ToKey)
	}
	if decoded.NodeMeta == nil {
		t.Fatal("NodeMeta is nil after unmarshal")
	}
	if decoded.NodeMeta.PublicKey != meta.PublicKey {
		t.Errorf("NodeMeta.PublicKey = %s, want %s", decoded.NodeMeta.PublicKey, meta.PublicKey)
	}
	if decoded.NodeMeta.Hostname != meta.Hostname {
		t.Errorf("NodeMeta.Hostname = %s, want %s", decoded.NodeMeta.Hostname, meta.Hostname)
	}
}

func TestJoinMessageAllTypes(t *testing.T) {
	types := []JoinMsgType{MsgJoinRequest, MsgJoinAccept, MsgJoinReject, MsgLeaveNotice}
	for _, mt := range types {
		msg := NewJoinMessage(mt, "fromkey", "tokey")
		data, err := msg.Marshal()
		if err != nil {
			t.Fatalf("Marshal type %d: %v", mt, err)
		}
		decoded, err := UnmarshalJoinMessage(data)
		if err != nil {
			t.Fatalf("Unmarshal type %d: %v", mt, err)
		}
		if decoded.Type != mt {
			t.Errorf("Type = %d, want %d", decoded.Type, mt)
		}
	}
}

func TestJoinMessageTypeString(t *testing.T) {
	tests := []struct {
		typ  JoinMsgType
		want string
	}{
		{MsgJoinRequest, "JOIN_REQUEST"},
		{MsgJoinAccept, "JOIN_ACCEPT"},
		{MsgJoinReject, "JOIN_REJECT"},
		{MsgLeaveNotice, "LEAVE_NOTICE"},
		{JoinMsgType(99), "UNKNOWN(99)"},
	}
	for _, tt := range tests {
		got := tt.typ.String()
		if got != tt.want {
			t.Errorf("Type %d String() = %q, want %q", tt.typ, got, tt.want)
		}
	}
}

func TestIsJoinMessage(t *testing.T) {
	// Valid join message.
	msg := NewJoinMessage(MsgJoinRequest, "fromkey", "tokey")
	data, _ := msg.Marshal()
	if !IsJoinMessage(data) {
		t.Error("IsJoinMessage returned false for a valid join message")
	}

	// Relay message should not be a join message.
	relayMsg := NewRelayMessage(MsgRelaySetup, "fromkey", "tokey", "circuit1")
	relayData, _ := relayMsg.Marshal()
	if IsJoinMessage(relayData) {
		t.Error("IsJoinMessage returned true for a relay message")
	}

	// Empty data.
	if IsJoinMessage([]byte{}) {
		t.Error("IsJoinMessage returned true for empty data")
	}

	// Too-short data.
	if IsJoinMessage([]byte{0x01, 0x02}) {
		t.Error("IsJoinMessage returned true for too-short data")
	}

	// Random garbage.
	if IsJoinMessage([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Error("IsJoinMessage returned true for garbage data")
	}
}

// --- JoinRequest handling (bootstrap side) ---

func TestHandleJoinRequest_AutoApproved(t *testing.T) {
	// Bootstrap with authorized_keys containing the joiner's key.
	joinerKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"

	setup := newTestJoinSetup(bootstrapKey, []string{joinerKey}, "auto")

	// Simulate a JoinRequest from the joiner.
	joinerMeta := &NodeMeta{
		PublicKey: joinerKey,
		Hostname:  "joiner-node",
		Role:      "agent",
		MeshIP:    testMeshIP(joinerKey),
		Version:   "1.0.0",
		Seq:       1,
	}
	req := NewJoinMessage(MsgJoinRequest, joinerKey, bootstrapKey)
	req.NodeMeta = joinerMeta

	err := setup.jp.HandleMessage(req)
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	// Should have sent a JoinAccept.
	sent := setup.getSentMsgs()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(sent))
	}
	if sent[0].msg.Type != MsgJoinAccept {
		t.Errorf("sent message type = %s, want JOIN_ACCEPT", sent[0].msg.Type)
	}
	if sent[0].peerKey != joinerKey {
		t.Errorf("sent to %s, want %s", sent[0].peerKey, joinerKey)
	}
	// JoinAccept should include bootstrap's mesh IP.
	if sent[0].msg.BootstrapMeshIP == "" {
		t.Error("JoinAccept missing BootstrapMeshIP")
	}
	// JoinAccept should include bootstrap's public key.
	if sent[0].msg.BootstrapPubKey != bootstrapKey {
		t.Errorf("BootstrapPubKey = %s, want %s", sent[0].msg.BootstrapPubKey, bootstrapKey)
	}
	// No alerts should fire for auto-approved joins.
	alerts := setup.getAlerts()
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for auto-approved join, got %d", len(alerts))
	}
}

func TestHandleJoinRequest_Unauthorized(t *testing.T) {
	joinerKey := "unauthorized_key_1234567890abcdef"
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"

	// Bootstrap with empty authorized_keys (auto mode).
	setup := newTestJoinSetup(bootstrapKey, []string{}, "auto")

	joinerMeta := &NodeMeta{
		PublicKey: joinerKey,
		Hostname:  "evil-node",
		Role:      "agent",
		MeshIP:    testMeshIP(joinerKey),
		Version:   "1.0.0",
		Seq:       1,
	}
	req := NewJoinMessage(MsgJoinRequest, joinerKey, bootstrapKey)
	req.NodeMeta = joinerMeta

	err := setup.jp.HandleMessage(req)
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	// Should have sent a JoinReject.
	sent := setup.getSentMsgs()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(sent))
	}
	if sent[0].msg.Type != MsgJoinReject {
		t.Errorf("sent message type = %s, want JOIN_REJECT", sent[0].msg.Type)
	}
	if sent[0].msg.RejectReason != RejectJoinUnauthorized {
		t.Errorf("reject reason = %s, want %s", sent[0].msg.RejectReason, RejectJoinUnauthorized)
	}

	// Should have fired an alert.
	alerts := setup.getAlerts()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].eventType != "unauthorized_join_attempt" {
		t.Errorf("alert type = %s, want unauthorized_join_attempt", alerts[0].eventType)
	}
	if alerts[0].peerKey != joinerKey {
		t.Errorf("alert peerKey = %s, want %s", alerts[0].peerKey, joinerKey)
	}
}

func TestHandleJoinRequest_AtCapacity(t *testing.T) {
	joinerKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"

	// Bootstrap with a maxPeersExceeded function that returns true.
	setup := newTestJoinSetup(bootstrapKey, []string{joinerKey}, "auto")
	setup.jp.maxPeersExceeded = func() bool {
		return true
	}

	joinerMeta := &NodeMeta{
		PublicKey: joinerKey,
		Hostname:  "joiner-node",
		MeshIP:    testMeshIP(joinerKey),
		Version:   "1.0.0",
		Seq:       1,
	}
	req := NewJoinMessage(MsgJoinRequest, joinerKey, bootstrapKey)
	req.NodeMeta = joinerMeta

	err := setup.jp.HandleMessage(req)
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	sent := setup.getSentMsgs()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(sent))
	}
	if sent[0].msg.Type != MsgJoinReject {
		t.Errorf("sent message type = %s, want JOIN_REJECT", sent[0].msg.Type)
	}
	if sent[0].msg.RejectReason != RejectJoinAtCapacity {
		t.Errorf("reject reason = %s, want %s", sent[0].msg.RejectReason, RejectJoinAtCapacity)
	}

	// Should have fired a capacity alert.
	alerts := setup.getAlerts()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].eventType != "join_rejected_capacity" {
		t.Errorf("alert type = %s, want join_rejected_capacity", alerts[0].eventType)
	}
}

func TestHandleJoinRequest_ManualMode(t *testing.T) {
	joinerKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"

	// Bootstrap in manual mode.
	setup := newTestJoinSetup(bootstrapKey, nil, "manual")

	joinerMeta := &NodeMeta{
		PublicKey: joinerKey,
		Hostname:  "joiner-node",
		MeshIP:    testMeshIP(joinerKey),
		Version:   "1.0.0",
		Seq:       1,
	}
	req := NewJoinMessage(MsgJoinRequest, joinerKey, bootstrapKey)
	req.NodeMeta = joinerMeta

	err := setup.jp.HandleMessage(req)
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	// In manual mode, no accept/reject is sent immediately —
	// the join request waits for admin approval.
	sent := setup.getSentMsgs()
	if len(sent) != 0 {
		t.Fatalf("expected 0 sent messages in manual mode, got %d", len(sent))
	}

	// Should have a pending join.
	pending := setup.jp.PendingJoins()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending join, got %d", len(pending))
	}
	if pending[0].PublicKey != joinerKey {
		t.Errorf("pending join key = %s, want %s", pending[0].PublicKey, joinerKey)
	}
	if pending[0].Hostname != "joiner-node" {
		t.Errorf("pending join hostname = %s, want joiner-node", pending[0].Hostname)
	}

	// Should have fired a pending-approval alert.
	alerts := setup.getAlerts()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].eventType != "join_pending_approval" {
		t.Errorf("alert type = %s, want join_pending_approval", alerts[0].eventType)
	}
}

func TestManualApproveJoin(t *testing.T) {
	joinerKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"

	setup := newTestJoinSetup(bootstrapKey, nil, "manual")

	// Submit a join request.
	joinerMeta := &NodeMeta{
		PublicKey: joinerKey,
		Hostname:  "joiner-node",
		MeshIP:    testMeshIP(joinerKey),
		Version:   "1.0.0",
		Seq:       1,
	}
	req := NewJoinMessage(MsgJoinRequest, joinerKey, bootstrapKey)
	req.NodeMeta = joinerMeta
	setup.jp.HandleMessage(req)

	// Approve the join.
	err := setup.jp.ApproveJoin(joinerKey)
	if err != nil {
		t.Fatalf("ApproveJoin failed: %v", err)
	}

	// Should have sent a JoinAccept.
	sent := setup.getSentMsgs()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message after approval, got %d", len(sent))
	}
	if sent[0].msg.Type != MsgJoinAccept {
		t.Errorf("sent message type = %s, want JOIN_ACCEPT", sent[0].msg.Type)
	}
	if sent[0].peerKey != joinerKey {
		t.Errorf("sent to %s, want %s", sent[0].peerKey, joinerKey)
	}

	// Pending joins should be empty.
	pending := setup.jp.PendingJoins()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending joins after approval, got %d", len(pending))
	}
}

func TestManualDenyJoin(t *testing.T) {
	joinerKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"

	setup := newTestJoinSetup(bootstrapKey, nil, "manual")

	joinerMeta := &NodeMeta{
		PublicKey: joinerKey,
		Hostname:  "joiner-node",
		MeshIP:    testMeshIP(joinerKey),
		Version:   "1.0.0",
		Seq:       1,
	}
	req := NewJoinMessage(MsgJoinRequest, joinerKey, bootstrapKey)
	req.NodeMeta = joinerMeta
	setup.jp.HandleMessage(req)

	// Deny the join.
	err := setup.jp.DenyJoin(joinerKey, "rejected_by_admin")
	if err != nil {
		t.Fatalf("DenyJoin failed: %v", err)
	}

	sent := setup.getSentMsgs()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message after denial, got %d", len(sent))
	}
	if sent[0].msg.Type != MsgJoinReject {
		t.Errorf("sent message type = %s, want JOIN_REJECT", sent[0].msg.Type)
	}
	if sent[0].msg.RejectReason != "rejected_by_admin" {
		t.Errorf("reject reason = %s, want rejected_by_admin", sent[0].msg.RejectReason)
	}

	pending := setup.jp.PendingJoins()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending joins after denial, got %d", len(pending))
	}
}

func TestApproveJoin_NoPending(t *testing.T) {
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"
	setup := newTestJoinSetup(bootstrapKey, nil, "manual")

	err := setup.jp.ApproveJoin("nonexistent_key_1234567890abcdef")
	if err == nil {
		t.Error("ApproveJoin should fail for non-pending key")
	}
}

// --- JoinAccept / JoinReject handling (joiner side) ---

func TestHandleJoinAccept(t *testing.T) {
	joinerKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"

	setup := newTestJoinSetup(joinerKey, nil, "auto")

	// Simulate a JoinAccept from the bootstrap.
	bootstrapMeta := &NodeMeta{
		PublicKey: bootstrapKey,
		Hostname:  "bootstrap-node",
		Role:      "web",
		MeshIP:    "10.10.172.206",
		Version:   "1.0.0",
		Seq:       5,
	}
	knownPeers := []*NodeMeta{
		{PublicKey: "peer1key1234567890", Hostname: "peer1", MeshIP: "10.10.1.1"},
		{PublicKey: "peer2key1234567890", Hostname: "peer2", MeshIP: "10.10.2.2"},
	}
	accept := NewJoinMessage(MsgJoinAccept, bootstrapKey, joinerKey)
	accept.NodeMeta = bootstrapMeta
	accept.BootstrapMeshIP = "10.10.172.206"
	accept.BootstrapPubKey = bootstrapKey
	accept.KnownPeers = knownPeers

	// Start a RequestJoin in a goroutine (it will block waiting for response).
	resultCh := make(chan *RequestJoinResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result, err := setup.jp.RequestJoin(ctx, bootstrapKey)
		if err != nil {
			t.Logf("RequestJoin error: %v", err)
		}
		resultCh <- result
	}()

	// Give the goroutine time to register its result channel.
	time.Sleep(100 * time.Millisecond)

	// Deliver the JoinAccept.
	err := setup.jp.HandleMessage(accept)
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	// Wait for the result.
	select {
	case result := <-resultCh:
		if !result.Accepted {
			t.Error("expected Accepted=true")
		}
		if result.Bootstrap == nil {
			t.Error("expected Bootstrap metadata")
		}
		if result.Bootstrap.MeshIP != "10.10.172.206" {
			t.Errorf("Bootstrap MeshIP = %s, want 10.10.172.206", result.Bootstrap.MeshIP)
		}
		if len(result.KnownPeers) != 2 {
			t.Errorf("KnownPeers count = %d, want 2", len(result.KnownPeers))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for RequestJoin result")
	}
}

func TestHandleJoinReject(t *testing.T) {
	joinerKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"

	setup := newTestJoinSetup(joinerKey, nil, "auto")

	reject := NewJoinMessage(MsgJoinReject, bootstrapKey, joinerKey)
	reject.RejectReason = RejectJoinUnauthorized

	resultCh := make(chan *RequestJoinResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result, _ := setup.jp.RequestJoin(ctx, bootstrapKey)
		resultCh <- result
	}()

	time.Sleep(100 * time.Millisecond)

	err := setup.jp.HandleMessage(reject)
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	select {
	case result := <-resultCh:
		if result.Accepted {
			t.Error("expected Accepted=false")
		}
		if result.RejectReason != RejectJoinUnauthorized {
			t.Errorf("RejectReason = %s, want %s", result.RejectReason, RejectJoinUnauthorized)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for RequestJoin result")
	}
}

func TestRequestJoin_Timeout(t *testing.T) {
	joinerKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"

	setup := newTestJoinSetup(joinerKey, nil, "auto")
	// Short timeout for the test.
	setup.jp.cfg.JoinTimeout = 1

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := setup.jp.RequestJoin(ctx, bootstrapKey)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if result != nil {
		t.Error("expected nil result on timeout")
	}
}

func TestRequestJoin_NoSender(t *testing.T) {
	joinerKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"

	// Create a JoinProtocol without a message sender.
	localMeta := &NodeMeta{
		PublicKey: joinerKey,
		MeshIP:    testMeshIP(joinerKey),
	}
	delegate := newMeshDelegate(localMeta)
	wgMgr := newMockPeerManager()
	events := newMeshEventDelegate(delegate, wgMgr)
	jp := NewJoinProtocol(DefaultJoinConfig(), delegate, events)
	// No SetMessageSender called.

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := jp.RequestJoin(ctx, "bootstrapkey")
	if err == nil {
		t.Fatal("expected error when no message sender is set")
	}
}

// --- Leave protocol tests ---

func TestSendLeaveNotice(t *testing.T) {
	localKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	setup := newTestJoinSetup(localKey, nil, "auto")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := setup.jp.SendLeaveNotice(ctx)
	if err != nil {
		t.Fatalf("SendLeaveNotice failed: %v", err)
	}

	broadcasts := setup.getBroadcasts()
	if len(broadcasts) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(broadcasts))
	}
	if broadcasts[0].Type != MsgLeaveNotice {
		t.Errorf("broadcast type = %s, want LEAVE_NOTICE", broadcasts[0].Type)
	}
	if broadcasts[0].FromKey != localKey {
		t.Errorf("broadcast FromKey = %s, want %s", broadcasts[0].FromKey, localKey)
	}
	if broadcasts[0].NodeMeta == nil {
		t.Error("LeaveNotice should include NodeMeta")
	}
}

func TestHandleLeaveNotice(t *testing.T) {
	localKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	leavingKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"

	setup := newTestJoinSetup(localKey, nil, "auto")

	notice := NewJoinMessage(MsgLeaveNotice, leavingKey, "")
	notice.NodeMeta = &NodeMeta{
		PublicKey: leavingKey,
		MeshIP:    testMeshIP(leavingKey),
	}

	err := setup.jp.HandleMessage(notice)
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	// Should fire a node_leave alert.
	alerts := setup.getAlerts()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].eventType != "node_leave" {
		t.Errorf("alert type = %s, want node_leave", alerts[0].eventType)
	}
	if alerts[0].peerKey != leavingKey {
		t.Errorf("alert peerKey = %s, want %s", alerts[0].peerKey, leavingKey)
	}
	if alerts[0].reason != "graceful" {
		t.Errorf("alert reason = %s, want graceful", alerts[0].reason)
	}
}

func TestSendLeaveNotice_NoBroadcastSender(t *testing.T) {
	localKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"

	localMeta := &NodeMeta{
		PublicKey: localKey,
		MeshIP:    testMeshIP(localKey),
	}
	delegate := newMeshDelegate(localMeta)
	wgMgr := newMockPeerManager()
	events := newMeshEventDelegate(delegate, wgMgr)
	jp := NewJoinProtocol(DefaultJoinConfig(), delegate, events)
	// No SetBroadcastSender called.

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := jp.SendLeaveNotice(ctx)
	if err == nil {
		t.Fatal("expected error when no broadcast sender is set")
	}
}

// --- Bootstrap address parsing tests ---

func TestParseBootstrapAddr(t *testing.T) {
	tests := []struct {
		addr        string
		defaultPort int
		wantHost    string
		wantPort    string
		wantErr     bool
	}{
		{"203.0.113.5:51820", 7946, "203.0.113.5", "51820", false},
		{"10.10.0.5:7946", 7946, "10.10.0.5", "7946", false},
		{"example.com:7946", 7946, "example.com", "7946", false},
		{"example.com", 7946, "example.com", "7946", false},
		{"203.0.113.5", 51820, "203.0.113.5", "51820", false},
		{"", 7946, "", "", true},
		{"example.com", 0, "example.com", "7946", false}, // defaults to 7946
	}
	for _, tt := range tests {
		host, port, err := ParseBootstrapAddr(tt.addr, tt.defaultPort)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseBootstrapAddr(%q) expected error, got nil", tt.addr)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseBootstrapAddr(%q) unexpected error: %v", tt.addr, err)
			continue
		}
		if host != tt.wantHost {
			t.Errorf("ParseBootstrapAddr(%q) host = %s, want %s", tt.addr, host, tt.wantHost)
		}
		if port != tt.wantPort {
			t.Errorf("ParseBootstrapAddr(%q) port = %s, want %s", tt.addr, port, tt.wantPort)
		}
	}
}

// --- Delegate NotifyMsg integration tests ---

func TestDelegateNotifyMsg_JoinMessage(t *testing.T) {
	localKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	setup := newTestJoinSetup(localKey, nil, "auto")

	// Wire the join handler into the delegate.
	setup.delegate.SetJoinMessageHandler(func(msg *JoinMessage) error {
		return setup.jp.HandleMessage(msg)
	})

	// Create a JoinRequest and serialize it.
	joinerMeta := &NodeMeta{
		PublicKey: "bbbb2222cccc3333",
		Hostname:  "test-joiner",
		MeshIP:    "10.10.1.2",
	}
	req := NewJoinMessage(MsgJoinRequest, "bbbb2222cccc3333", localKey)
	req.NodeMeta = joinerMeta

	data, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Deliver via NotifyMsg.
	setup.delegate.NotifyMsg(data)

	// The join protocol should have processed it.
	// Since the key is not authorized, it should have sent a reject.
	sent := setup.getSentMsgs()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(sent))
	}
	if sent[0].msg.Type != MsgJoinReject {
		t.Errorf("sent message type = %s, want JOIN_REJECT", sent[0].msg.Type)
	}
}

func TestDelegateNotifyMsg_RelayAndJoinCoexist(t *testing.T) {
	localKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	setup := newTestJoinSetup(localKey, nil, "auto")

	// Wire both handlers.
	setup.delegate.SetJoinMessageHandler(func(msg *JoinMessage) error {
		return setup.jp.HandleMessage(msg)
	})
	relayHandlerCalled := false
	setup.delegate.SetRelayMessageHandler(func(msg *RelayMessage) error {
		relayHandlerCalled = true
		return nil
	})

	// Send a relay message — should go to relay handler.
	relayMsg := NewRelayMessage(MsgRelayPing, "fromkey", localKey, "circuit1")
	relayData, _ := relayMsg.Marshal()
	setup.delegate.NotifyMsg(relayData)

	if !relayHandlerCalled {
		t.Error("relay handler was not called for relay message")
	}

	// Send a join message — should go to join handler.
	leaveNotice := NewJoinMessage(MsgLeaveNotice, "peerkey1234567890", "")
	leaveData, _ := leaveNotice.Marshal()
	setup.delegate.NotifyMsg(leaveData)

	alerts := setup.getAlerts()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert from leave notice, got %d", len(alerts))
	}
	if alerts[0].eventType != "node_leave" {
		t.Errorf("alert type = %s, want node_leave", alerts[0].eventType)
	}
}

func TestDelegateNotifyMsg_EmptyData(t *testing.T) {
	localKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	setup := newTestJoinSetup(localKey, nil, "auto")

	// Empty data should be silently ignored.
	setup.delegate.NotifyMsg([]byte{})

	sent := setup.getSentMsgs()
	if len(sent) != 0 {
		t.Errorf("expected 0 sent messages for empty data, got %d", len(sent))
	}
}

// --- IsAuthorized tests ---

func TestIsAuthorized(t *testing.T) {
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"
	authorizedKey := "authorized_key_1234567890abcdef"
	unauthorizedKey := "unauthorized_key_1234567890ab"

	tests := []struct {
		name         string
		approvalMode string
		authKeys     []string
		checkKey     string
		want         bool
	}{
		{"auto-authorized", "auto", []string{authorizedKey}, authorizedKey, true},
		{"auto-unauthorized", "auto", []string{authorizedKey}, unauthorizedKey, false},
		{"auto-empty-list", "auto", []string{}, unauthorizedKey, false},
		{"manual-always-true", "manual", []string{authorizedKey}, unauthorizedKey, true},
		{"manual-no-keys", "manual", nil, unauthorizedKey, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := newTestJoinSetup(bootstrapKey, tt.authKeys, tt.approvalMode)
			got := setup.jp.isAuthorized(tt.checkKey)
			if got != tt.want {
				t.Errorf("isAuthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- JoinProtocol Stop tests ---

func TestJoinProtocolStop(t *testing.T) {
	localKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	setup := newTestJoinSetup(localKey, nil, "auto")

	// Start a RequestJoin that will block.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		setup.jp.RequestJoin(ctx, "bootstrapkey")
	}()

	time.Sleep(100 * time.Millisecond)

	// Stop should unblock the waiting RequestJoin.
	setup.jp.Stop()

	// Calling Stop again should not panic.
	setup.jp.Stop()
}

// --- PendingJoins expiry test ---

func TestPendingJoinsExpiry(t *testing.T) {
	// This test verifies that pending joins are tracked with timestamps.
	joinerKey := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666"
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"

	setup := newTestJoinSetup(bootstrapKey, nil, "manual")

	joinerMeta := &NodeMeta{
		PublicKey: joinerKey,
		Hostname:  "joiner-node",
		MeshIP:    testMeshIP(joinerKey),
		Version:   "1.0.0",
		Seq:       1,
	}
	req := NewJoinMessage(MsgJoinRequest, joinerKey, bootstrapKey)
	req.NodeMeta = joinerMeta
	setup.jp.HandleMessage(req)

	pending := setup.jp.PendingJoins()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}

	// Verify the RequestedAt timestamp is recent.
	if time.Since(pending[0].RequestedAt) > 5*time.Second {
		t.Error("pending join RequestedAt is too old")
	}
}

// --- Concurrent access test ---

func TestJoinProtocolConcurrent(t *testing.T) {
	bootstrapKey := "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111"
	setup := newTestJoinSetup(bootstrapKey, nil, "manual")

	var wg sync.WaitGroup
	// 10 concurrent join requests.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			joinerKey := "joiner_key_" + string(rune('A'+idx)) + "1234567890abcdef"
			joinerMeta := &NodeMeta{
				PublicKey: joinerKey,
				Hostname:  "joiner",
				MeshIP:    testMeshIP(joinerKey),
				Version:   "1.0.0",
				Seq:       1,
			}
			req := NewJoinMessage(MsgJoinRequest, joinerKey, bootstrapKey)
			req.NodeMeta = joinerMeta
			setup.jp.HandleMessage(req)
		}(i)
	}
	wg.Wait()

	pending := setup.jp.PendingJoins()
	if len(pending) != 10 {
		t.Errorf("expected 10 pending joins, got %d", len(pending))
	}
}
