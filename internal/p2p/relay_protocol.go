package p2p

import (
	"fmt"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// RelayMsgType identifies the kind of relay control message carried
// through the gossip user-message channel (memberlist Delegate.NotifyMsg).
//
// These messages implement the relay session lifecycle from
// P2P_NETWORKING_SPEC.md §5.3:
//
//	CREATION:  circuit_setup  → circuit_accept / circuit_reject
//	ACTIVE:    relay_ping     → relay_pong   (health check every 30s)
//	TEARDOWN:  circuit_teardown
type RelayMsgType uint8

const (
	MsgRelaySetup    RelayMsgType = 1 // entry → relay: request circuit creation
	MsgRelayAccept   RelayMsgType = 2 // relay → entry: circuit accepted
	MsgRelayReject   RelayMsgType = 3 // relay → entry: circuit rejected
	MsgRelayTeardown RelayMsgType = 4 // entry → relay: tear down circuit
	MsgRelayPing     RelayMsgType = 5 // entry → relay: health check
	MsgRelayPong     RelayMsgType = 6 // relay → entry: health check response
)

// String returns a human-readable message type name.
func (t RelayMsgType) String() string {
	switch t {
	case MsgRelaySetup:
		return "SETUP"
	case MsgRelayAccept:
		return "ACCEPT"
	case MsgRelayReject:
		return "REJECT"
	case MsgRelayTeardown:
		return "TEARDOWN"
	case MsgRelayPing:
		return "PING"
	case MsgRelayPong:
		return "PONG"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint8(t))
	}
}

// RelayRejectReason explains why a relay refused a circuit.
const (
	RejectAtCapacity = "at_capacity"
	RejectLoadSpike  = "load_spike"
	RejectInvalidKey = "invalid_key"
	RejectDuplicate  = "duplicate_circuit"
	RejectNotRelay   = "not_relay_capable"
)

// RelayMessage is the envelope for all relay control messages carried
// via gossip user messages (memberlist Delegate.NotifyMsg / GetBroadcasts).
//
// Wire format: MessagePack. The Type byte is the discriminator; only
// the fields relevant to the message type are populated.
//
// All messages are addressed by publicKey — the gossip layer guarantees
// message authenticity because only mesh members (WireGuard peers) can
// participate in gossip.
type RelayMessage struct {
	// Type is the message discriminator.
	Type RelayMsgType `msgpack:"t"`

	// CircuitID is the unique circuit identifier (hex, 16 bytes).
	// Used in all message types except initial SETUP (where it's proposed).
	CircuitID string `msgpack:"cid,omitempty"`

	// FromKey is the sender's WireGuard public key (hex).
	FromKey string `msgpack:"fk,omitempty"`

	// ToKey is the recipient's WireGuard public key (hex).
	// Used for targeted delivery (relay → entry responses).
	ToKey string `msgpack:"tk,omitempty"`

	// TargetKey is the peer that the relay should forward to.
	// In SETUP: the peer whose traffic the relay will forward.
	TargetKey string `msgpack:"tgk,omitempty"`

	// TargetMeshIP is the mesh IP of the target peer.
	// The relay uses this to configure WireGuard AllowedIPs for forwarding.
	TargetMeshIP string `msgpack:"tmi,omitempty"`

	// RejectReason is a human-readable reason code (only in REJECT).
	RejectReason string `msgpack:"rr,omitempty"`

	// Timestamp is when the message was created (UnixNano).
	// Used for staleness detection and debugging.
	Timestamp int64 `msgpack:"ts"`
}

// NewRelayMessage creates a new relay message with the current timestamp.
func NewRelayMessage(msgType RelayMsgType, fromKey, toKey, circuitID string) *RelayMessage {
	return &RelayMessage{
		Type:      msgType,
		FromKey:   fromKey,
		ToKey:     toKey,
		CircuitID: circuitID,
		Timestamp: time.Now().UnixNano(),
	}
}

// Marshal serializes the relay message to MessagePack bytes.
func (m *RelayMessage) Marshal() ([]byte, error) {
	return msgpack.Marshal(m)
}

// UnmarshalRelayMessage deserializes a relay message from MessagePack bytes.
func UnmarshalRelayMessage(data []byte) (*RelayMessage, error) {
	var m RelayMessage
	if err := msgpack.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal relay message: %w", err)
	}
	return &m, nil
}

// IsRelayMessage checks whether raw bytes are a relay message by
// attempting a partial decode. This is used by the delegate's NotifyMsg
// to distinguish relay messages from other user-level gossip messages.
func IsRelayMessage(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// MessagePack fixmap with at least 1 field (Type).
	// The first byte of a msgpack-encoded RelayMessage is a fixmap
	// header (0x80-0x8f for 1-15 fields). We check for a reasonable
	// minimum length and attempt full unmarshal in the caller.
	if len(data) < 4 {
		return false
	}
	msg, err := UnmarshalRelayMessage(data)
	if err != nil {
		return false
	}
	return msg.Type >= MsgRelaySetup && msg.Type <= MsgRelayPong
}

// RelaySetupRequest is a convenience constructor for a SETUP message.
// The entry node sends this to a relay-capable peer to request a new
// relay circuit.
func RelaySetupRequest(fromKey, relayKey, circuitID, targetKey, targetMeshIP string) *RelayMessage {
	m := NewRelayMessage(MsgRelaySetup, fromKey, relayKey, circuitID)
	m.TargetKey = targetKey
	m.TargetMeshIP = targetMeshIP
	return m
}

// RelayAcceptResponse is a convenience constructor for an ACCEPT message.
// The relay sends this to the entry node to confirm circuit creation.
func RelayAcceptResponse(relayKey, entryKey, circuitID string) *RelayMessage {
	return NewRelayMessage(MsgRelayAccept, relayKey, entryKey, circuitID)
}

// RelayRejectResponse is a convenience constructor for a REJECT message.
// The relay sends this to the entry node with a reason code.
func RelayRejectResponse(relayKey, entryKey, circuitID, reason string) *RelayMessage {
	m := NewRelayMessage(MsgRelayReject, relayKey, entryKey, circuitID)
	m.RejectReason = reason
	return m
}

// RelayTeardownRequest is a convenience constructor for a TEARDOWN message.
// The entry node sends this to the relay to tear down a circuit.
func RelayTeardownRequest(fromKey, relayKey, circuitID string) *RelayMessage {
	return NewRelayMessage(MsgRelayTeardown, fromKey, relayKey, circuitID)
}

// RelayPingMessage is a convenience constructor for a PING message.
// The entry node sends this through the relay path every 30s.
func RelayPingMessage(fromKey, relayKey, circuitID string) *RelayMessage {
	return NewRelayMessage(MsgRelayPing, fromKey, relayKey, circuitID)
}

// RelayPongResponse is a convenience constructor for a PONG message.
// The relay responds to confirm the circuit is still active.
func RelayPongResponse(relayKey, entryKey, circuitID string) *RelayMessage {
	return NewRelayMessage(MsgRelayPong, relayKey, entryKey, circuitID)
}
