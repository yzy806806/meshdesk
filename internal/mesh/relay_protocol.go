package mesh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// MeshRelayVirtualPort is the virtual port for mesh-internal relay control.
// 0x524C = 'R' (0x52) 'L' (0x4C) — mnemonic for "Relay".
const MeshRelayVirtualPort = 0x524C // 21068

// MeshRelayMsgType identifies the kind of mesh-internal relay control message.
type MeshRelayMsgType uint8

const (
	MsgRelayRequest   MeshRelayMsgType = 1 // initiator → relay: request relay tunnel
	MsgRelayAccept    MeshRelayMsgType = 2 // relay → initiator: tunnel accepted
	MsgRelayReject    MeshRelayMsgType = 3 // relay → initiator: tunnel rejected
	MsgRelayDial      MeshRelayMsgType = 4 // relay → target: please open a relay stream back
	MsgRelayTeardown  MeshRelayMsgType = 5 // either side → relay: tear down tunnel
	MsgRelayHeartbeat MeshRelayMsgType = 6 // relay → both sides: keepalive
)

// String returns a human-readable message type name.
func (t MeshRelayMsgType) String() string {
	switch t {
	case MsgRelayRequest:
		return "RELAY_REQUEST"
	case MsgRelayAccept:
		return "RELAY_ACCEPT"
	case MsgRelayReject:
		return "RELAY_REJECT"
	case MsgRelayDial:
		return "RELAY_DIAL"
	case MsgRelayTeardown:
		return "RELAY_TEARDOWN"
	case MsgRelayHeartbeat:
		return "RELAY_HEARTBEAT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint8(t))
	}
}

// MeshRelayRequest is sent by the initiating node to the relay node,
// requesting a relay tunnel to the target peer.
//
// Port carries the virtual port that the initiator wants to reach on the
// target. It is propagated through the relay chain so the target's
// OnRelayDial callback can dial the correct local virtual port service.
type MeshRelayRequest struct {
	Type         MeshRelayMsgType `msgpack:"t"`
	TunnelID     string           `msgpack:"tid"` // 16-byte hex, random
	TargetKey    string           `msgpack:"tgk"` // target peer identity hex
	InitiatorKey string           `msgpack:"ik"`  // initiator peer identity hex (for target-side auth)
	Port         uint16           `msgpack:"pt"`  // target virtual port (0 = legacy/unset)
	Timestamp    int64            `msgpack:"ts"`  // UnixNano

	// Path is the chain of relay nodes already traversed for this
	// tunnel (initiator-excluded, relay-added). Used for multi-hop
	// relay loop prevention: a relay never forwards to a node already
	// on the path. Empty for single-hop (legacy-compatible).
	Path []string `msgpack:"path,omitempty"`
}

// MeshRelayResponse is sent by the relay node back to the initiator
// (or target) to indicate acceptance or rejection of a relay tunnel.
type MeshRelayResponse struct {
	Type         MeshRelayMsgType `msgpack:"t"`            // MsgRelayAccept or MsgRelayReject
	TunnelID     string           `msgpack:"tid"`          // matches request
	RejectReason string           `msgpack:"rr,omitempty"` // only if rejected
	Timestamp    int64            `msgpack:"ts"`
}

// MeshRelayDial is sent by the relay node to the target peer on a
// separate stream, asking the target to open a relay stream back to
// the relay with the same tunnelID so the relay can bridge them.
//
// Port carries the virtual port the initiator wants to reach on the
// target, propagated from MeshRelayRequest. The target's OnRelayDial
// callback uses it to dial the correct local virtual port service.
//
// InitiatorKey carries the identity hex of the original initiator,
// propagated from MeshRelayRequest.InitiatorKey. The target's
// OnRelayDial callback passes it to DialLocalVirtualPort for
// per-peer authorization (ACL, source allowlist, etc.).
type MeshRelayDial struct {
	Type         MeshRelayMsgType `msgpack:"t"`
	TunnelID     string           `msgpack:"tid"` // matches the initiator's tunnel
	InitiatorKey string           `msgpack:"ik"`  // who wants to talk to you
	Port         uint16           `msgpack:"pt"`  // target virtual port (0 = legacy/unset)
	Timestamp    int64            `msgpack:"ts"`
}

// MeshRelayTeardown is sent by either side or the relay to close a tunnel.
type MeshRelayTeardown struct {
	Type      MeshRelayMsgType `msgpack:"t"`
	TunnelID  string           `msgpack:"tid"`
	Timestamp int64            `msgpack:"ts"`
}

// MeshRelayHeartbeat is a keepalive sent by the relay to both sides.
type MeshRelayHeartbeat struct {
	Type      MeshRelayMsgType `msgpack:"t"`
	TunnelID  string           `msgpack:"tid"`
	Timestamp int64            `msgpack:"ts"`
}

// newTunnelID generates a random 16-byte hex tunnel ID.
func newTunnelID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// nowNano returns the current time as UnixNano.
func nowNano() int64 {
	return time.Now().UnixNano()
}

// marshalRelayMsg encodes any relay message struct to msgpack bytes.
func marshalRelayMsg(msg any) ([]byte, error) {
	return msgpack.Marshal(msg)
}

// unmarshalRelayMsg decodes msgpack bytes into the appropriate relay
// message struct based on the message type field in the raw map.
// Returns the decoded message as an any, or an error.
func unmarshalRelayMsg(data []byte) (any, error) {
	// First decode as a map to peek at the type field.
	var peek struct {
		Type MeshRelayMsgType `msgpack:"t"`
	}
	if err := msgpack.Unmarshal(data, &peek); err != nil {
		return nil, fmt.Errorf("mesh relay: decode type: %w", err)
	}

	switch peek.Type {
	case MsgRelayRequest:
		var m MeshRelayRequest
		if err := msgpack.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("mesh relay: decode request: %w", err)
		}
		return &m, nil
	case MsgRelayAccept, MsgRelayReject:
		var m MeshRelayResponse
		if err := msgpack.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("mesh relay: decode response: %w", err)
		}
		return &m, nil
	case MsgRelayDial:
		var m MeshRelayDial
		if err := msgpack.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("mesh relay: decode dial: %w", err)
		}
		return &m, nil
	case MsgRelayTeardown:
		var m MeshRelayTeardown
		if err := msgpack.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("mesh relay: decode teardown: %w", err)
		}
		return &m, nil
	case MsgRelayHeartbeat:
		var m MeshRelayHeartbeat
		if err := msgpack.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("mesh relay: decode heartbeat: %w", err)
		}
		return &m, nil
	default:
		return nil, fmt.Errorf("mesh relay: unknown message type %d", peek.Type)
	}
}

// RelayRejectReason constants — human-readable reason strings returned in
// MeshRelayResponse.RejectReason.
const (
	RelayRejectAtCapacity        = "at_capacity"
	RelayRejectNoSessionToTarget = "no_session_to_target"
	RelayRejectTargetRejected    = "target_rejected"
	RelayRejectInvalidTarget     = "invalid_target"
	RelayRejectDuplicateTunnel   = "duplicate_tunnel"
	RelayRejectNotRelayCapable   = "not_relay_capable"
)
