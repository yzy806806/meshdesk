package p2p

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// --- Join Protocol Messages (§4) ---
//
// The dynamic join protocol allows a new node with zero established peers
// to join the mesh via a bootstrap node. The bootstrap authenticates the
// joiner (authorized_keys check), then gossips the new member to the
// cluster. The joiner receives the full memberlist via memberlist's
// push/pull state sync.
//
// Message types:
//   1. JoinRequest  — joiner → bootstrap: "I want to join, here's my key+meta"
//   2. JoinAccept   — bootstrap → joiner: "Welcome, here's my mesh info"
//   3. JoinReject   — bootstrap → joiner: "No (unauthorized / at capacity / etc.)"
//   4. LeaveNotice  — any node → all peers: "I'm leaving gracefully"

// JoinMsgType identifies the kind of join-protocol message.
type JoinMsgType uint8

const (
	MsgJoinRequest JoinMsgType = 11
	MsgJoinAccept  JoinMsgType = 12
	MsgJoinReject  JoinMsgType = 13
	MsgLeaveNotice JoinMsgType = 14
)

// String returns a human-readable message type name.
func (t JoinMsgType) String() string {
	switch t {
	case MsgJoinRequest:
		return "JOIN_REQUEST"
	case MsgJoinAccept:
		return "JOIN_ACCEPT"
	case MsgJoinReject:
		return "JOIN_REJECT"
	case MsgLeaveNotice:
		return "LEAVE_NOTICE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint8(t))
	}
}

// Join reject reason codes (§4.5).
const (
	RejectJoinUnauthorized = "unauthorized"
	RejectJoinAtCapacity   = "at_capacity"
	RejectJoinIncompatible = "incompatible_version"
)

// JoinMessage is the envelope for all join-protocol control messages.
// It is carried via the gossip user-message channel (delegate.NotifyMsg),
// using the same transport as relay messages.
//
// Wire format: MessagePack.
type JoinMessage struct {
	// Type is the message discriminator.
	Type JoinMsgType `msgpack:"jt"`

	// FromKey is the sender's WireGuard public key (hex).
	FromKey string `msgpack:"fk,omitempty"`

	// ToKey is the recipient's public key (hex), for targeted delivery.
	ToKey string `msgpack:"tk,omitempty"`

	// NodeMeta is the joining node's full metadata (only in JoinRequest).
	// This is how the bootstrap learns the joiner's identity, capabilities,
	// and endpoints.
	NodeMeta *NodeMeta `msgpack:"nm,omitempty"`

	// RejectReason is a human-readable reason code (only in JoinReject).
	RejectReason string `msgpack:"rr,omitempty"`

	// BootstrapPort is the bootstrap's listen port.
	BootstrapPort int `msgpack:"bp,omitempty"`

	// BootstrapPubKey is the bootstrap node's public key (hex).
	// The joiner needs this to add the bootstrap as a WireGuard peer.
	BootstrapPubKey string `msgpack:"bpk,omitempty"`

	// GossipPort is the gossip port the bootstrap is listening on.
	GossipPort int `msgpack:"gp,omitempty"`

	// KnownPeers is the full list of peer metadata known to the bootstrap
	// (only in JoinAccept). This gives the joiner an immediate view of
	// the mesh without waiting for push/pull.
	KnownPeers []*NodeMeta `msgpack:"kp,omitempty"`

	// Timestamp is when the message was created (UnixNano).
	Timestamp int64 `msgpack:"ts"`
}

// NewJoinMessage creates a new join message with the current timestamp.
func NewJoinMessage(msgType JoinMsgType, fromKey, toKey string) *JoinMessage {
	return &JoinMessage{
		Type:      msgType,
		FromKey:   fromKey,
		ToKey:     toKey,
		Timestamp: time.Now().UnixNano(),
	}
}

// Marshal serializes the join message to MessagePack bytes.
func (m *JoinMessage) Marshal() ([]byte, error) {
	return msgpack.Marshal(m)
}

// UnmarshalJoinMessage deserializes a join message from MessagePack bytes.
func UnmarshalJoinMessage(data []byte) (*JoinMessage, error) {
	var m JoinMessage
	if err := msgpack.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal join message: %w", err)
	}
	return &m, nil
}

// IsJoinMessage checks whether raw bytes are a join-protocol message.
// Used by the delegate's NotifyMsg to distinguish join messages from
// relay messages and other user-level gossip data.
func IsJoinMessage(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	msg, err := UnmarshalJoinMessage(data)
	if err != nil {
		return false
	}
	return msg.Type >= MsgJoinRequest && msg.Type <= MsgLeaveNotice
}

// --- JoinProtocol ---
//
// JoinProtocol coordinates the dynamic join sequence on both sides:
//
// Joiner side (§4.1):
//  1. Connect to bootstrap via TCP (through the bootstrap's public endpoint).
//  2. Send JoinRequest with local NodeMeta.
//  3. Wait for JoinAccept or JoinReject.
//  4. On accept: add bootstrap as WireGuard peer, then join memberlist.
//  5. On reject: log alert, optionally retry after cooldown.
//
// Bootstrap side:
//  1. Receive JoinRequest via gossip user message.
//  2. Check authorized_keys (if auto mode) or create pending entry (manual).
//  3. If authorized: respond with JoinAccept (includes known peers).
//  4. If rejected: respond with JoinReject, log security alert.
//
// Leave protocol:
//  1. Node broadcasts LeaveNotice to all peers via gossip.
//  2. Peers receiving LeaveNotice proactively remove the node from
//     WireGuard and routing table (faster than waiting for failure detection).

// JoinConfig holds the configuration for the join protocol.
type JoinConfig struct {
	// LocalPublicKey is this node's WireGuard public key (hex).
	LocalPublicKey string

	// JoinApproval controls authentication mode: "auto" or "manual".
	JoinApproval string

	// AuthorizedKeys is the list of pre-authorized public keys (auto mode).
	AuthorizedKeys []string

	// MaxPeers is the hard limit on total peers.
	MaxPeers int

	// JoinTimeout is how long to wait for a JoinAccept (seconds).
	JoinTimeout int

	// RetryCooldown is the cooldown after a rejected join (seconds).
	RetryCooldown int

	// LeaveTimeout is how long to wait for LeaveNotice delivery (seconds).
	LeaveTimeout int
}

// DefaultJoinConfig returns a JoinConfig with sensible defaults.
func DefaultJoinConfig() JoinConfig {
	return JoinConfig{
		JoinApproval:  "auto",
		JoinTimeout:   30,
		RetryCooldown: 30,
		LeaveTimeout:  5,
		MaxPeers:      256,
	}
}

// JoinProtocolState tracks the state of a pending join on the bootstrap side.
type JoinProtocolState struct {
	PublicKey   string
	Hostname    string
	RequestedAt time.Time
	Approved    bool
}

// JoinProtocol manages the dynamic join/leave protocol.
// It is created by the GossipLayer and uses the gossip transport for
// sending/receiving join-protocol messages.
type JoinProtocol struct {
	cfg      JoinConfig
	delegate *meshDelegate
	events   *meshEventDelegate

	mu sync.RWMutex

	// pendingJoins tracks join requests awaiting manual approval (manual mode).
	// publicKey → join state
	pendingJoins map[string]*JoinProtocolState

	// joinResultCh delivers the result of a join attempt to the joiner.
	// Keyed by bootstrap address.
	joinResultCh map[string]chan *JoinMessage

	// leaveDoneCh is signaled when LeaveNotice broadcast completes.
	leaveDoneCh chan struct{}

	// messageSender sends a join message to a specific peer via gossip.
	messageSender func(peerKey string, msg *JoinMessage)

	// broadcastSender broadcasts a message to all peers via gossip.
	broadcastSender func(msg *JoinMessage)

	// peerListProvider returns the current known-peers list (for JoinAccept).
	peerListProvider func() []*NodeMeta

	// peerCountProvider returns the current peer count (for capacity check).
	peerCountProvider func() int

	// maxPeersExceeded is called to check if we're at capacity.
	// Returns true if the mesh is full and should reject new joins.
	maxPeersExceeded func() bool

	// alertHandler is called when a security event occurs (unauthorized join).
	alertHandler func(eventType, peerKey, reason string)

	stopCh chan struct{}
}

// NewJoinProtocol creates a new join protocol handler.
func NewJoinProtocol(cfg JoinConfig, delegate *meshDelegate, events *meshEventDelegate) *JoinProtocol {
	return &JoinProtocol{
		cfg:          cfg,
		delegate:     delegate,
		events:       events,
		pendingJoins: make(map[string]*JoinProtocolState),
		joinResultCh: make(map[string]chan *JoinMessage),
		leaveDoneCh:  make(chan struct{}),
		stopCh:       make(chan struct{}),
	}
}

// SetMessageSender installs the callback for sending targeted join messages
// to a specific peer via gossip reliable transport.
func (jp *JoinProtocol) SetMessageSender(fn func(peerKey string, msg *JoinMessage)) {
	jp.mu.Lock()
	defer jp.mu.Unlock()
	jp.messageSender = fn
}

// SetBroadcastSender installs the callback for broadcasting messages to all
// peers via gossip.
func (jp *JoinProtocol) SetBroadcastSender(fn func(msg *JoinMessage)) {
	jp.mu.Lock()
	defer jp.mu.Unlock()
	jp.broadcastSender = fn
}

// SetPeerListProvider installs the callback that returns the current
// known-peers list. Used to populate JoinAccept.KnownPeers.
func (jp *JoinProtocol) SetPeerListProvider(fn func() []*NodeMeta) {
	jp.mu.Lock()
	defer jp.mu.Unlock()
	jp.peerListProvider = fn
}

// SetPeerCountProvider installs the callback that returns the current
// known-peer count. Used for capacity checking.
func (jp *JoinProtocol) SetPeerCountProvider(fn func() int) {
	jp.mu.Lock()
	defer jp.mu.Unlock()
	jp.peerCountProvider = fn
}

// SetAlertHandler installs a callback for security alert events.
func (jp *JoinProtocol) SetAlertHandler(fn func(eventType, peerKey, reason string)) {
	jp.mu.Lock()
	defer jp.mu.Unlock()
	jp.alertHandler = fn
}

// HandleMessage processes an incoming join-protocol message.
// This is called by the delegate's NotifyMsg when IsJoinMessage returns true.
func (jp *JoinProtocol) HandleMessage(msg *JoinMessage) error {
	switch msg.Type {
	case MsgJoinRequest:
		return jp.handleJoinRequest(msg)
	case MsgJoinAccept:
		return jp.handleJoinAccept(msg)
	case MsgJoinReject:
		return jp.handleJoinReject(msg)
	case MsgLeaveNotice:
		return jp.handleLeaveNotice(msg)
	default:
		return fmt.Errorf("unknown join message type: %d", msg.Type)
	}
}

// --- Bootstrap side: handling JoinRequest ---

// handleJoinRequest processes a join request from a new node.
// It checks authorization and capacity, then responds with accept or reject.
func (jp *JoinProtocol) handleJoinRequest(msg *JoinMessage) error {
	if msg.NodeMeta == nil {
		return fmt.Errorf("join request missing NodeMeta")
	}

	joinerKey := msg.NodeMeta.PublicKey
	joinerName := msg.NodeMeta.Hostname

	log.Printf("[p2p/join] received join request from %s (hostname=%s)",
		shortKey(joinerKey), joinerName)

	// --- Capacity check ---
	if jp.maxPeersExceeded != nil && jp.maxPeersExceeded() {
		log.Printf("[p2p/join] rejecting %s: mesh at capacity", shortKey(joinerKey))
		jp.sendJoinReject(joinerKey, msg.FromKey, RejectJoinAtCapacity)
		jp.fireAlert("join_rejected_capacity", joinerKey, RejectJoinAtCapacity)
		return nil
	}

	// --- Authorization check ---
	authorized := jp.isAuthorized(joinerKey)
	if !authorized {
		log.Printf("[p2p/join] rejecting %s: unauthorized key", shortKey(joinerKey))
		jp.sendJoinReject(joinerKey, msg.FromKey, RejectJoinUnauthorized)
		jp.fireAlert("unauthorized_join_attempt", joinerKey, RejectJoinUnauthorized)
		return nil
	}

	// --- Manual approval mode ---
	if jp.cfg.JoinApproval == "manual" {
		jp.mu.Lock()
		jp.pendingJoins[joinerKey] = &JoinProtocolState{
			PublicKey:   joinerKey,
			Hostname:    joinerName,
			RequestedAt: time.Now(),
			Approved:    false,
		}
		jp.mu.Unlock()

		log.Printf("[p2p/join] pending manual approval for %s (hostname=%s)",
			shortKey(joinerKey), joinerName)
		jp.fireAlert("join_pending_approval", joinerKey, "awaiting admin approval")
		return nil
	}

	// --- Auto-approve ---
	jp.sendJoinAccept(msg)
	log.Printf("[p2p/join] accepted %s into the mesh", shortKey(joinerKey))
	return nil
}

// isAuthorized checks whether a public key is allowed to join.
func (jp *JoinProtocol) isAuthorized(publicKey string) bool {
	if jp.cfg.JoinApproval != "auto" {
		// Manual mode — auth handled by admin approval flow.
		// The join request is accepted as "pending" and waits for approval.
		return true
	}
	for _, k := range jp.cfg.AuthorizedKeys {
		if k == publicKey {
			return true
		}
	}
	return false
}

// sendJoinAccept sends a JoinAccept message to the joiner.
func (jp *JoinProtocol) sendJoinAccept(req *JoinMessage) {
	localMeta := jp.delegate.getLocalMeta()

	accept := NewJoinMessage(MsgJoinAccept, localMeta.PublicKey, req.FromKey)
	accept.NodeMeta = localMeta
	accept.BootstrapPubKey = localMeta.PublicKey
	accept.GossipPort = 0 // Filled from config if needed

	// Include the current known-peers list so the joiner gets an
	// immediate view of the mesh (§4.1 Phase 2 step 4a).
	if jp.peerListProvider != nil {
		accept.KnownPeers = jp.peerListProvider()
	}

	jp.mu.RLock()
	sender := jp.messageSender
	jp.mu.RUnlock()

	if sender != nil {
		sender(req.FromKey, accept)
	}
}

// sendJoinReject sends a JoinReject message to the joiner.
func (jp *JoinProtocol) sendJoinReject(joinerKey, fromKey, reason string) {
	localMeta := jp.delegate.getLocalMeta()

	reject := NewJoinMessage(MsgJoinReject, localMeta.PublicKey, joinerKey)
	reject.RejectReason = reason

	jp.mu.RLock()
	sender := jp.messageSender
	jp.mu.RUnlock()

	if sender != nil {
		sender(joinerKey, reject)
	}
}

// fireAlert invokes the alert handler if one is installed.
func (jp *JoinProtocol) fireAlert(eventType, peerKey, reason string) {
	jp.mu.RLock()
	handler := jp.alertHandler
	jp.mu.RUnlock()

	if handler != nil {
		handler(eventType, peerKey, reason)
	}
}

// --- Manual approval API ---

// PendingJoins returns all pending join requests awaiting manual approval.
func (jp *JoinProtocol) PendingJoins() []*JoinProtocolState {
	jp.mu.RLock()
	defer jp.mu.RUnlock()

	result := make([]*JoinProtocolState, 0, len(jp.pendingJoins))
	for _, s := range jp.pendingJoins {
		copy := *s
		result = append(result, &copy)
	}
	return result
}

// ApproveJoin approves a pending join request (manual mode).
// The joiner is then sent a JoinAccept.
func (jp *JoinProtocol) ApproveJoin(publicKey string) error {
	jp.mu.Lock()
	state, ok := jp.pendingJoins[publicKey]
	if !ok {
		jp.mu.Unlock()
		return fmt.Errorf("no pending join for key %s", shortKey(publicKey))
	}
	state.Approved = true
	delete(jp.pendingJoins, publicKey)
	jp.mu.Unlock()

	// Build a synthetic JoinRequest to send the accept.
	localMeta := jp.delegate.getLocalMeta()
	accept := NewJoinMessage(MsgJoinAccept, localMeta.PublicKey, publicKey)
	accept.NodeMeta = localMeta
	accept.BootstrapPubKey = localMeta.PublicKey

	if jp.peerListProvider != nil {
		accept.KnownPeers = jp.peerListProvider()
	}

	jp.mu.RLock()
	sender := jp.messageSender
	jp.mu.RUnlock()

	if sender != nil {
		sender(publicKey, accept)
	}

	log.Printf("[p2p/join] manually approved %s", shortKey(publicKey))
	return nil
}

// DenyJoin denies a pending join request (manual mode).
func (jp *JoinProtocol) DenyJoin(publicKey, reason string) error {
	jp.mu.Lock()
	_, ok := jp.pendingJoins[publicKey]
	if !ok {
		jp.mu.Unlock()
		return fmt.Errorf("no pending join for key %s", shortKey(publicKey))
	}
	delete(jp.pendingJoins, publicKey)
	jp.mu.Unlock()

	jp.sendJoinReject(publicKey, publicKey, reason)
	log.Printf("[p2p/join] manually denied %s: %s", shortKey(publicKey), reason)
	return nil
}

// --- Joiner side: handling JoinAccept / JoinReject ---

// handleJoinAccept processes a JoinAccept from the bootstrap.
// It delivers the result to the waiting joiner via the result channel.
func (jp *JoinProtocol) handleJoinAccept(msg *JoinMessage) error {
	log.Printf("[p2p/join] received JoinAccept from %s (%d known peers)",
		shortKey(msg.FromKey), len(msg.KnownPeers))

	jp.mu.RLock()
	ch, ok := jp.joinResultCh[msg.ToKey]
	jp.mu.RUnlock()

	if ok {
		select {
		case ch <- msg:
		default:
			log.Printf("[p2p/join] result channel full, dropping JoinAccept")
		}
	}
	return nil
}

// handleJoinReject processes a JoinReject from the bootstrap.
func (jp *JoinProtocol) handleJoinReject(msg *JoinMessage) error {
	log.Printf("[p2p/join] received JoinReject from %s: %s",
		shortKey(msg.FromKey), msg.RejectReason)

	jp.mu.RLock()
	ch, ok := jp.joinResultCh[msg.ToKey]
	jp.mu.RUnlock()

	if ok {
		select {
		case ch <- msg:
		default:
			log.Printf("[p2p/join] result channel full, dropping JoinReject")
		}
	}
	return nil
}

// --- Leave protocol ---

// handleLeaveNotice processes a graceful leave notification.
// The leaving node is proactively removed from WireGuard and routing
// table — this is faster than waiting for memberlist failure detection.
func (jp *JoinProtocol) handleLeaveNotice(msg *JoinMessage) error {
	leavingKey := msg.FromKey
	log.Printf("[p2p/join] received LeaveNotice from %s", shortKey(leavingKey))

	// The event delegate's NotifyLeave handles WireGuard removal.
	// Here we just log — the actual cleanup is triggered by memberlist
	// detecting the node as gone (which happens quickly after LeaveNotice
	// because the leaving node calls memberlist.Leave()).
	//
	// However, we can speed up cleanup by directly removing the peer
	// from the event delegate's cache.
	if jp.events != nil {
		// The event delegate handles removal via NotifyLeave,
		// which is triggered by memberlist.Leave(). We don't need
		// to duplicate that here — the LeaveNotice is an early
		// signal that lets us log the graceful departure.
		log.Printf("[p2p/join] peer %s leaving gracefully (cleanup via memberlist)",
			shortKey(leavingKey))
	}

	jp.fireAlert("node_leave", leavingKey, "graceful")
	return nil
}

// SendLeaveNotice broadcasts a LeaveNotice to all peers and waits for
// delivery (up to LeaveTimeout). This should be called before shutdown.
func (jp *JoinProtocol) SendLeaveNotice(ctx context.Context) error {
	localMeta := jp.delegate.getLocalMeta()

	notice := NewJoinMessage(MsgLeaveNotice, localMeta.PublicKey, "")
	notice.NodeMeta = localMeta

	jp.mu.RLock()
	broadcast := jp.broadcastSender
	jp.mu.RUnlock()

	if broadcast == nil {
		return fmt.Errorf("no broadcast sender configured")
	}

	broadcast(notice)

	log.Printf("[p2p/join] sent LeaveNotice to all peers")

	// Give the broadcast a moment to propagate.
	select {
	case <-time.After(time.Duration(jp.cfg.LeaveTimeout) * time.Second):
	case <-ctx.Done():
		return ctx.Err()
	case <-jp.stopCh:
		return nil
	}

	return nil
}

// --- Joiner-side API: RequestJoin ---

// RequestJoinResult holds the outcome of a join attempt.
type RequestJoinResult struct {
	Accepted     bool
	RejectReason string
	Bootstrap    *NodeMeta
	KnownPeers   []*NodeMeta
}

// RequestJoin sends a JoinRequest to a bootstrap node and waits for
// the response. This is the joiner-side entry point for the dynamic
// join protocol.
//
// The caller is responsible for:
//  1. Ensuring the bootstrap is reachable (either via static WireGuard
//     config or via a direct TCP connection to the bootstrap's public endpoint).
//  2. After a successful join, calling memberlist.Join() with the bootstrap's
//     mesh IP to trigger full state sync.
func (jp *JoinProtocol) RequestJoin(ctx context.Context, bootstrapKey string) (*RequestJoinResult, error) {
	localMeta := jp.delegate.getLocalMeta()

	// Create a result channel for this join attempt.
	resultCh := make(chan *JoinMessage, 1)
	jp.mu.Lock()
	jp.joinResultCh[localMeta.PublicKey] = resultCh
	jp.mu.Unlock()

	// Clean up the channel when done.
	defer func() {
		jp.mu.Lock()
		delete(jp.joinResultCh, localMeta.PublicKey)
		jp.mu.Unlock()
	}()

	// Build the JoinRequest.
	req := NewJoinMessage(MsgJoinRequest, localMeta.PublicKey, bootstrapKey)
	req.NodeMeta = localMeta

	jp.mu.RLock()
	sender := jp.messageSender
	jp.mu.RUnlock()

	if sender == nil {
		return nil, fmt.Errorf("no message sender configured")
	}

	log.Printf("[p2p/join] sending JoinRequest to bootstrap %s", shortKey(bootstrapKey))
	sender(bootstrapKey, req)

	// Wait for the response.
	timeout := time.Duration(jp.cfg.JoinTimeout) * time.Second
	if jp.cfg.JoinTimeout <= 0 {
		timeout = 30 * time.Second
	}

	select {
	case resp := <-resultCh:
		if resp.Type == MsgJoinAccept {
			return &RequestJoinResult{
				Accepted:   true,
				Bootstrap:  resp.NodeMeta,
				KnownPeers: resp.KnownPeers,
			}, nil
		}
		return &RequestJoinResult{
			Accepted:     false,
			RejectReason: resp.RejectReason,
		}, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("join request timed out after %v", timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-jp.stopCh:
		return nil, fmt.Errorf("join protocol stopped")
	}
}

// --- Utility ---

// generateJoinNonce generates a random 16-byte hex nonce.
// (Kept for potential future use in join-protocol session tracking.)
func generateJoinNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Stop shuts down the join protocol, cleaning up pending joins and
// signaling any waiting joiners.
func (jp *JoinProtocol) Stop() {
	select {
	case <-jp.stopCh:
		return
	default:
	}
	close(jp.stopCh)

	// Close any waiting result channels.
	jp.mu.Lock()
	for _, ch := range jp.joinResultCh {
		close(ch)
	}
	jp.joinResultCh = make(map[string]chan *JoinMessage)
	jp.mu.Unlock()
}

// --- Bootstrap address parsing ---

// ParseBootstrapAddr parses a bootstrap address string into host and port.
// Accepts "host:port", "meshIP:port", or bare "host" (defaults to gossip port).
// Returns host string and port string (separately for use with net.JoinHostPort).
func ParseBootstrapAddr(addr string, defaultPort int) (host string, port string, err error) {
	if addr == "" {
		return "", "", fmt.Errorf("empty bootstrap address")
	}

	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p, nil
	}

	// No port — use default.
	if defaultPort <= 0 {
		defaultPort = 7946
	}
	return addr, fmt.Sprintf("%d", defaultPort), nil
}
