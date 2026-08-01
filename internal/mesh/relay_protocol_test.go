package mesh

import (
	"testing"
)

func TestMeshRelayMsgType_String(t *testing.T) {
	tests := []struct {
		msgType MeshRelayMsgType
		want    string
	}{
		{MsgRelayRequest, "RELAY_REQUEST"},
		{MsgRelayAccept, "RELAY_ACCEPT"},
		{MsgRelayReject, "RELAY_REJECT"},
		{MsgRelayDial, "RELAY_DIAL"},
		{MsgRelayTeardown, "RELAY_TEARDOWN"},
		{MsgRelayHeartbeat, "RELAY_HEARTBEAT"},
		{MeshRelayMsgType(99), "UNKNOWN(99)"},
	}
	for _, tt := range tests {
		got := tt.msgType.String()
		if got != tt.want {
			t.Errorf("MsgType(%d).String() = %q, want %q", uint8(tt.msgType), got, tt.want)
		}
	}
}

func TestNewTunnelID(t *testing.T) {
	id1 := newTunnelID()
	id2 := newTunnelID()

	if len(id1) != 32 {
		t.Errorf("tunnel ID length = %d, want 32 (16 bytes hex)", len(id1))
	}
	if id1 == id2 {
		t.Error("two consecutive tunnel IDs should differ")
	}
}

func TestMarshalUnmarshalRelayRequest(t *testing.T) {
	original := &MeshRelayRequest{
		Type:      MsgRelayRequest,
		TunnelID:  "abcdef0123456789abcdef0123456789",
		TargetKey: "targetpeerkeyhex",
		Timestamp: 1700000000000000000,
	}

	data, err := marshalRelayMsg(original)
	if err != nil {
		t.Fatalf("marshalRelayMsg: %v", err)
	}

	msg, err := unmarshalRelayMsg(data)
	if err != nil {
		t.Fatalf("unmarshalRelayMsg: %v", err)
	}

	req, ok := msg.(*MeshRelayRequest)
	if !ok {
		t.Fatalf("expected *MeshRelayRequest, got %T", msg)
	}

	if req.TunnelID != original.TunnelID {
		t.Errorf("TunnelID = %q, want %q", req.TunnelID, original.TunnelID)
	}
	if req.TargetKey != original.TargetKey {
		t.Errorf("TargetKey = %q, want %q", req.TargetKey, original.TargetKey)
	}
	if req.Timestamp != original.Timestamp {
		t.Errorf("Timestamp = %d, want %d", req.Timestamp, original.Timestamp)
	}
	if req.Type != MsgRelayRequest {
		t.Errorf("Type = %d, want %d", req.Type, MsgRelayRequest)
	}
}

func TestMarshalUnmarshalRelayResponse(t *testing.T) {
	tests := []struct {
		name string
		resp *MeshRelayResponse
	}{
		{
			name: "accept",
			resp: &MeshRelayResponse{
				Type:      MsgRelayAccept,
				TunnelID:  "abcdef0123456789abcdef0123456789",
				Timestamp: 1700000000000000000,
			},
		},
		{
			name: "reject",
			resp: &MeshRelayResponse{
				Type:         MsgRelayReject,
				TunnelID:     "abcdef0123456789abcdef0123456789",
				RejectReason: RelayRejectAtCapacity,
				Timestamp:    1700000000000000000,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := marshalRelayMsg(tt.resp)
			if err != nil {
				t.Fatalf("marshalRelayMsg: %v", err)
			}

			msg, err := unmarshalRelayMsg(data)
			if err != nil {
				t.Fatalf("unmarshalRelayMsg: %v", err)
			}

			resp, ok := msg.(*MeshRelayResponse)
			if !ok {
				t.Fatalf("expected *MeshRelayResponse, got %T", msg)
			}

			if resp.TunnelID != tt.resp.TunnelID {
				t.Errorf("TunnelID = %q, want %q", resp.TunnelID, tt.resp.TunnelID)
			}
			if resp.Type != tt.resp.Type {
				t.Errorf("Type = %d, want %d", resp.Type, tt.resp.Type)
			}
			if resp.RejectReason != tt.resp.RejectReason {
				t.Errorf("RejectReason = %q, want %q", resp.RejectReason, tt.resp.RejectReason)
			}
		})
	}
}

func TestMarshalUnmarshalRelayDial(t *testing.T) {
	original := &MeshRelayDial{
		Type:         MsgRelayDial,
		TunnelID:     "abcdef0123456789abcdef0123456789",
		InitiatorKey: "initiatorkeyhex",
		Timestamp:    1700000000000000000,
	}

	data, err := marshalRelayMsg(original)
	if err != nil {
		t.Fatalf("marshalRelayMsg: %v", err)
	}

	msg, err := unmarshalRelayMsg(data)
	if err != nil {
		t.Fatalf("unmarshalRelayMsg: %v", err)
	}

	dial, ok := msg.(*MeshRelayDial)
	if !ok {
		t.Fatalf("expected *MeshRelayDial, got %T", msg)
	}

	if dial.TunnelID != original.TunnelID {
		t.Errorf("TunnelID = %q, want %q", dial.TunnelID, original.TunnelID)
	}
	if dial.InitiatorKey != original.InitiatorKey {
		t.Errorf("InitiatorKey = %q, want %q", dial.InitiatorKey, original.InitiatorKey)
	}
	if dial.Type != MsgRelayDial {
		t.Errorf("Type = %d, want %d", dial.Type, MsgRelayDial)
	}
}

func TestMarshalUnmarshalRelayTeardown(t *testing.T) {
	original := &MeshRelayTeardown{
		Type:      MsgRelayTeardown,
		TunnelID:  "abcdef0123456789abcdef0123456789",
		Timestamp: 1700000000000000000,
	}

	data, err := marshalRelayMsg(original)
	if err != nil {
		t.Fatalf("marshalRelayMsg: %v", err)
	}

	msg, err := unmarshalRelayMsg(data)
	if err != nil {
		t.Fatalf("unmarshalRelayMsg: %v", err)
	}

	td, ok := msg.(*MeshRelayTeardown)
	if !ok {
		t.Fatalf("expected *MeshRelayTeardown, got %T", msg)
	}

	if td.TunnelID != original.TunnelID {
		t.Errorf("TunnelID = %q, want %q", td.TunnelID, original.TunnelID)
	}
	if td.Type != MsgRelayTeardown {
		t.Errorf("Type = %d, want %d", td.Type, MsgRelayTeardown)
	}
}

func TestMarshalUnmarshalRelayHeartbeat(t *testing.T) {
	original := &MeshRelayHeartbeat{
		Type:      MsgRelayHeartbeat,
		TunnelID:  "abcdef0123456789abcdef0123456789",
		Timestamp: 1700000000000000000,
	}

	data, err := marshalRelayMsg(original)
	if err != nil {
		t.Fatalf("marshalRelayMsg: %v", err)
	}

	msg, err := unmarshalRelayMsg(data)
	if err != nil {
		t.Fatalf("unmarshalRelayMsg: %v", err)
	}

	hb, ok := msg.(*MeshRelayHeartbeat)
	if !ok {
		t.Fatalf("expected *MeshRelayHeartbeat, got %T", msg)
	}

	if hb.TunnelID != original.TunnelID {
		t.Errorf("TunnelID = %q, want %q", hb.TunnelID, original.TunnelID)
	}
	if hb.Type != MsgRelayHeartbeat {
		t.Errorf("Type = %d, want %d", hb.Type, MsgRelayHeartbeat)
	}
}

func TestUnmarshalRelayMsg_InvalidData(t *testing.T) {
	_, err := unmarshalRelayMsg([]byte("not msgpack"))
	if err == nil {
		t.Error("expected error for invalid data, got nil")
	}
}

func TestUnmarshalRelayMsg_UnknownType(t *testing.T) {
	// Create a message with an unknown type.
	unknown := &MeshRelayRequest{
		Type:      MeshRelayMsgType(99),
		TunnelID:  "test",
		TargetKey: "test",
		Timestamp: 1,
	}

	data, err := marshalRelayMsg(unknown)
	if err != nil {
		t.Fatalf("marshalRelayMsg: %v", err)
	}

	_, err = unmarshalRelayMsg(data)
	if err == nil {
		t.Error("expected error for unknown message type, got nil")
	}
}

func TestRelayRejectReasonConstants(t *testing.T) {
	// Verify that all reject reason constants are non-empty and distinct.
	reasons := []string{
		RelayRejectAtCapacity,
		RelayRejectNoSessionToTarget,
		RelayRejectTargetRejected,
		RelayRejectInvalidTarget,
		RelayRejectDuplicateTunnel,
		RelayRejectNotRelayCapable,
	}
	seen := make(map[string]bool)
	for _, r := range reasons {
		if r == "" {
			t.Error("reject reason constant is empty")
		}
		if seen[r] {
			t.Errorf("duplicate reject reason: %q", r)
		}
		seen[r] = true
	}
}
