package mesh

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// --- none mode tests ---

func TestNoneObfuscator(t *testing.T) {
	o := NewObfuscator(ObfuscationNone)
	if o.Mode() != ObfuscationNone {
		t.Errorf("Mode() = %v, want %v", o.Mode(), ObfuscationNone)
	}

	original := []byte("hello wireguard")
	out, err := o.WrapOutbound(original)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}
	if !bytes.Equal(out, original) {
		t.Error("none mode should not modify packets")
	}

	back, err := o.UnwrapInbound(out)
	if err != nil {
		t.Fatalf("UnwrapInbound error: %v", err)
	}
	if !bytes.Equal(back, original) {
		t.Error("none mode round-trip should preserve data")
	}
}

// --- padded mode tests ---

func TestPaddedObfuscatorRoundTrip(t *testing.T) {
	o := NewObfuscator(ObfuscationPadded)
	if o.Mode() != ObfuscationPadded {
		t.Errorf("Mode() = %v, want %v", o.Mode(), ObfuscationPadded)
	}

	original := []byte("wireguard handshake init")
	out, err := o.WrapOutbound(original)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}

	// Output should be larger than input (has padding + 4-byte length header).
	if len(out) <= len(original) {
		t.Errorf("padded output %d should be larger than original %d", len(out), len(original))
	}

	// The frame format is: [4-byte length][random padding][original packet]
	origLen := binary.BigEndian.Uint32(out[:4])
	if int(origLen) != len(original) {
		t.Errorf("declared original length = %d, want %d", origLen, len(original))
	}

	back, err := o.UnwrapInbound(out)
	if err != nil {
		t.Fatalf("UnwrapInbound error: %v", err)
	}
	if !bytes.Equal(back, original) {
		t.Error("padded mode round-trip should preserve data")
	}
}

func TestPaddedObfuscatorRandomPadding(t *testing.T) {
	o := NewObfuscator(ObfuscationPadded)
	original := []byte("same input")

	out1, _ := o.WrapOutbound(original)
	out2, _ := o.WrapOutbound(original)

	// The padding should be random, so outputs should differ in length
	// or content (with high probability).
	if bytes.Equal(out1, out2) {
		t.Error("two padded outputs should differ (random padding)")
	}
}

func TestPaddedObfuscatorFrameStructure(t *testing.T) {
	o := NewObfuscator(ObfuscationPadded)
	original := []byte("test payload")

	out, err := o.WrapOutbound(original)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}

	// Frame: [4-byte big-endian length][padding bytes][original]
	if len(out) < 4+paddedMinPadding+len(original) {
		t.Errorf("frame too small: %d, min %d", len(out), 4+paddedMinPadding+len(original))
	}

	declaredLen := binary.BigEndian.Uint32(out[:4])
	if int(declaredLen) != len(original) {
		t.Errorf("declared length = %d, want %d", declaredLen, len(original))
	}

	// The original packet should be at the end of the frame.
	actualOriginal := out[len(out)-int(declaredLen):]
	if !bytes.Equal(actualOriginal, original) {
		t.Error("original packet not found at end of frame")
	}
}

func TestPaddedObfuscatorUnwrapInvalidInput(t *testing.T) {
	o := NewObfuscator(ObfuscationPadded)

	// Too short.
	_, err := o.UnwrapInbound([]byte{0, 1})
	if err == nil {
		t.Error("UnwrapInbound should fail on short input")
	}

	// Declared length exceeds data.
	shortFrame := make([]byte, 8)
	binary.BigEndian.PutUint32(shortFrame[:4], 1000) // declare 1000 bytes
	_, err = o.UnwrapInbound(shortFrame)
	if err == nil {
		t.Error("UnwrapInbound should fail when declared length exceeds data")
	}
}

// --- websocket mode tests ---

func TestWebsocketObfuscatorRoundTrip(t *testing.T) {
	o := NewObfuscator(ObfuscationWebSocket)
	if o.Mode() != ObfuscationWebSocket {
		t.Errorf("Mode() = %v, want %v", o.Mode(), ObfuscationWebSocket)
	}

	tests := []struct {
		name    string
		payload []byte
	}{
		{"small", []byte("hello")},
		{"medium", bytes.Repeat([]byte{0xAB}, 200)},
		{"large", bytes.Repeat([]byte{0xCD}, 70000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := o.WrapOutbound(tt.payload)
			if err != nil {
				t.Fatalf("WrapOutbound error: %v", err)
			}

			back, err := o.UnwrapInbound(out)
			if err != nil {
				t.Fatalf("UnwrapInbound error: %v", err)
			}
			if !bytes.Equal(back, tt.payload) {
				t.Errorf("round-trip mismatch: got %d bytes, want %d bytes", len(back), len(tt.payload))
			}
		})
	}
}

func TestWebsocketFrameFormat(t *testing.T) {
	o := NewObfuscator(ObfuscationWebSocket)

	// Small payload (<=125): uses 2-byte header.
	small := []byte("hi")
	out, err := o.WrapOutbound(small)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}
	if len(out) != 2+len(small) {
		t.Errorf("small frame length = %d, want %d", len(out), 2+len(small))
	}
	if out[0] != wsFrameType {
		t.Errorf("frame type = 0x%02x, want 0x%02x", out[0], wsFrameType)
	}
	if out[1] != byte(len(small)) {
		t.Errorf("payload length byte = %d, want %d", out[1], len(small))
	}
}

// --- factory tests ---

func TestParseObfuscationMode(t *testing.T) {
	tests := []struct {
		input string
		want  ObfuscationMode
	}{
		{"none", ObfuscationNone},
		{"padded", ObfuscationPadded},
		{"", ObfuscationPadded}, // empty defaults to padded
		{"websocket", ObfuscationWebSocket},
		{"unknown", ObfuscationPadded}, // unknown defaults to padded
	}
	for _, tt := range tests {
		got := ParseObfuscationMode(tt.input)
		if got != tt.want {
			t.Errorf("ParseObfuscationMode(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestObfuscationModeString(t *testing.T) {
	tests := []struct {
		mode ObfuscationMode
		want string
	}{
		{ObfuscationNone, "none"},
		{ObfuscationPadded, "padded"},
		{ObfuscationWebSocket, "websocket"},
	}
	for _, tt := range tests {
		got := tt.mode.String()
		if got != tt.want {
			t.Errorf("Mode(%v).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

// --- obfuscating bind tests ---

func TestObfuscatingBindSetGet(t *testing.T) {
	bind := NewObfuscatingBind(nil) // nil inner is fine for this test

	// Default obfuscator should be padded.
	o := bind.GetObfuscator("unknown-peer")
	if o.Mode() != ObfuscationPadded {
		t.Errorf("default obfuscator mode = %v, want %v", o.Mode(), ObfuscationPadded)
	}

	// Set a specific mode.
	bind.SetObfuscator("peer-1", ObfuscationNone)
	o = bind.GetObfuscator("peer-1")
	if o.Mode() != ObfuscationNone {
		t.Errorf("peer-1 obfuscator mode = %v, want %v", o.Mode(), ObfuscationNone)
	}
}

// --- hexEncode test ---

func TestHexEncode(t *testing.T) {
	got := hexEncode([]byte{0x01, 0x02, 0xff})
	if got != "0102ff" {
		t.Errorf("hexEncode = %q, want %q", got, "0102ff")
	}
}

// --- deriveMeshIP test (in node_test.go since it's in node.go) ---

func TestDeriveMeshIP(t *testing.T) {
	// Test with a known public key hex.
	ip := deriveMeshIP("aabbccdd0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c")
	if ip == "" {
		t.Error("deriveMeshIP returned empty")
	}
	// Should be in 10.10.x.y range.
	if len(ip) < 8 {
		t.Errorf("deriveMeshIP too short: %q", ip)
	}
}

func TestDeriveMeshIPShortKey(t *testing.T) {
	ip := deriveMeshIP("ab")
	if ip != "10.10.0.1" {
		t.Errorf("deriveMeshIP(short) = %q, want %q", ip, "10.10.0.1")
	}
}
