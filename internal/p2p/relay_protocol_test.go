package p2p

import (
	"testing"
	"time"
)

func TestRelayMessageMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  *RelayMessage
	}{
		{
			name: "setup message",
			msg:  RelaySetupRequest("entrykey1234567890abcdef", "relaykey1234567890abcdef", "circuit001", "targetkey1234567890ab", []string{"10.10.1.5"}),
		},
		{
			name: "accept message",
			msg:  RelayAcceptResponse("relaykey1234567890abcdef", "entrykey1234567890abcdef", "circuit001"),
		},
		{
			name: "reject message",
			msg:  RelayRejectResponse("relaykey1234567890abcdef", "entrykey1234567890abcdef", "circuit001", RejectAtCapacity),
		},
		{
			name: "teardown message",
			msg:  RelayTeardownRequest("entrykey1234567890abcdef", "relaykey1234567890abcdef", "circuit001"),
		},
		{
			name: "ping message",
			msg:  RelayPingMessage("entrykey1234567890abcdef", "relaykey1234567890abcdef", "circuit001"),
		},
		{
			name: "pong message",
			msg:  RelayPongResponse("relaykey1234567890abcdef", "entrykey1234567890abcdef", "circuit001"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.msg.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("Marshal returned empty data")
			}

			decoded, err := UnmarshalRelayMessage(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if decoded.Type != tt.msg.Type {
				t.Errorf("Type mismatch: got %v, want %v", decoded.Type, tt.msg.Type)
			}
			if decoded.CircuitID != tt.msg.CircuitID {
				t.Errorf("CircuitID mismatch: got %s, want %s", decoded.CircuitID, tt.msg.CircuitID)
			}
			if decoded.FromKey != tt.msg.FromKey {
				t.Errorf("FromKey mismatch: got %s, want %s", decoded.FromKey, tt.msg.FromKey)
			}
			if decoded.ToKey != tt.msg.ToKey {
				t.Errorf("ToKey mismatch: got %s, want %s", decoded.ToKey, tt.msg.ToKey)
			}
			if decoded.TargetKey != tt.msg.TargetKey {
				t.Errorf("TargetKey mismatch: got %s, want %s", decoded.TargetKey, tt.msg.TargetKey)
			}
			if len(decoded.TargetEndpoints) != len(tt.msg.TargetEndpoints) {
				t.Errorf("TargetEndpoints length mismatch: got %v, want %v", decoded.TargetEndpoints, tt.msg.TargetEndpoints)
			}
			if decoded.RejectReason != tt.msg.RejectReason {
				t.Errorf("RejectReason mismatch: got %s, want %s", decoded.RejectReason, tt.msg.RejectReason)
			}
			if decoded.Timestamp != tt.msg.Timestamp {
				t.Errorf("Timestamp mismatch: got %d, want %d", decoded.Timestamp, tt.msg.Timestamp)
			}
		})
	}
}

func TestIsRelayMessage(t *testing.T) {
	// Valid relay message
	msg := RelaySetupRequest("from", "to", "c1", "target", []string{"10.10.0.1"})
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !IsRelayMessage(data) {
		t.Error("IsRelayMessage returned false for valid relay message")
	}

	// Empty data
	if IsRelayMessage([]byte{}) {
		t.Error("IsRelayMessage returned true for empty data")
	}

	// Nil data
	if IsRelayMessage(nil) {
		t.Error("IsRelayMessage returned true for nil data")
	}

	// Too short
	if IsRelayMessage([]byte{0x01}) {
		t.Error("IsRelayMessage returned true for 1-byte data")
	}

	// Random garbage
	if IsRelayMessage([]byte("hello world this is not a relay message")) {
		t.Error("IsRelayMessage returned true for garbage data")
	}
}

func TestRelayMsgTypeString(t *testing.T) {
	tests := []struct {
		typ  RelayMsgType
		want string
	}{
		{MsgRelaySetup, "SETUP"},
		{MsgRelayAccept, "ACCEPT"},
		{MsgRelayReject, "REJECT"},
		{MsgRelayTeardown, "TEARDOWN"},
		{MsgRelayPing, "PING"},
		{MsgRelayPong, "PONG"},
		{RelayMsgType(99), "UNKNOWN(99)"},
	}

	for _, tt := range tests {
		if got := tt.typ.String(); got != tt.want {
			t.Errorf("RelayMsgType(%d).String() = %s, want %s", tt.typ, got, tt.want)
		}
	}
}

func TestNewRelayMessageTimestamp(t *testing.T) {
	before := time.Now().UnixNano()
	msg := NewRelayMessage(MsgRelayPing, "from", "to", "c1")
	after := time.Now().UnixNano()

	if msg.Timestamp < before || msg.Timestamp > after {
		t.Errorf("Timestamp %d not in range [%d, %d]", msg.Timestamp, before, after)
	}
}

func TestRelayMessageCompactness(t *testing.T) {
	// A typical setup message with full 64-char hex keys should be
	// well under 512 bytes (memberlist's indirect broadcast limit).
	// With 64-char keys, the msgpack encoding is ~250 bytes — acceptable.
	msg := RelaySetupRequest(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"circuit001",
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		[]string{"10.10.1.5"},
	)
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if len(data) > 512 {
		t.Errorf("Setup message too large: %d bytes (should be < 512 for memberlist)", len(data))
	}
	t.Logf("Setup message size: %d bytes", len(data))
}
