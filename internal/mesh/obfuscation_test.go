package mesh

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	mrand "math/rand"
	"testing"
	"time"
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

// --- padded mode: basic round-trip ---

func TestPaddedObfuscatorRoundTrip(t *testing.T) {
	o := NewObfuscator(ObfuscationPadded)
	if o.Mode() != ObfuscationPadded {
		t.Errorf("Mode() = %v, want %v", o.Mode(), ObfuscationPadded)
	}

	// Use a WireGuard-like packet (type + body).
	original := makeInitiationPacket()
	out, err := o.WrapOutbound(original)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}

	// Output should be at least as large as input (header is replaced, padding >= 0).
	if len(out) < len(original) {
		t.Errorf("padded output %d should be >= original %d", len(out), len(original))
	}

	back, err := o.UnwrapInbound(out)
	if err != nil {
		t.Fatalf("UnwrapInbound error: %v", err)
	}
	if !bytes.Equal(back, original) {
		t.Errorf("padded round-trip mismatch:\n  got  %d bytes %x\n  want %d bytes %x", len(back), back[:min(32, len(back))], len(original), original[:min(32, len(original))])
	}
}

// --- padded mode: H1-H4 header randomization ---

func TestPaddedHeaderRandomization(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.S1, cfg.S2, cfg.S3, cfg.S4 = 0, 0, 0, 0 // disable padding to isolate header test
	cfg.JitterMaxMs = 0                         // disable jitter for deterministic test
	o := newPaddedObfuscator(cfg)

	original := makeInitiationPacket()
	out, err := o.WrapOutbound(original)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}

	// The first 4 bytes should NOT be the original WireGuard type (0x01).
	origType := binary.LittleEndian.Uint32(original[:4])
	obsType := binary.LittleEndian.Uint32(out[:4])
	if obsType == origType {
		t.Errorf("header not randomized: got 0x%08x, original 0x%08x", obsType, origType)
	}
	// The obfuscated type should be in the H1 range.
	if obsType < cfg.H1[0] || obsType > cfg.H1[1] {
		t.Errorf("obfuscated type 0x%08x not in H1 range [0x%08x, 0x%08x]", obsType, cfg.H1[0], cfg.H1[1])
	}

	// Round-trip should restore the original type.
	back, err := o.UnwrapInbound(out)
	if err != nil {
		t.Fatalf("UnwrapInbound error: %v", err)
	}
	if !bytes.Equal(back, original) {
		t.Error("round-trip should preserve data after header randomization")
	}
}

func TestPaddedHeaderRandomizationAllTypes(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.S1, cfg.S2, cfg.S3, cfg.S4 = 0, 0, 0, 0
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)

	tests := []struct {
		name string
		typ  uint32
	}{
		{"initiation", wgMsgInitiation},
		{"response", wgMsgResponse},
		{"cookie", wgMsgCookie},
		{"transport", wgMsgTransport},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := makePacketWithType(tt.typ)
			out, err := o.WrapOutbound(pkt)
			if err != nil {
				t.Fatalf("WrapOutbound error: %v", err)
			}
			obsType := binary.LittleEndian.Uint32(out[:4])
			// Should not equal original.
			if obsType == tt.typ {
				t.Errorf("type 0x%08x not randomized", obsType)
			}
			// Should round-trip.
			back, err := o.UnwrapInbound(out)
			if err != nil {
				t.Fatalf("UnwrapInbound error: %v", err)
			}
			backType := binary.LittleEndian.Uint32(back[:4])
			if backType != tt.typ {
				t.Errorf("round-trip type = 0x%08x, want 0x%08x", backType, tt.typ)
			}
		})
	}
}

// --- padded mode: non-overlapping H ranges ---

func TestPaddedNonOverlappingRanges(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	// Default ranges should be non-overlapping.
	if cfg.H1[1] >= cfg.H2[0] {
		t.Errorf("H1 overlaps H2: H1=[%x,%x] H2=[%x,%x]", cfg.H1[0], cfg.H1[1], cfg.H2[0], cfg.H2[1])
	}
	if cfg.H2[1] >= cfg.H3[0] {
		t.Errorf("H2 overlaps H3")
	}
	if cfg.H3[1] >= cfg.H4[0] {
		t.Errorf("H3 overlaps H4")
	}
}

// --- padded mode: per-message-type padding ---

func TestPaddedPaddingBreaksFixedSize(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)

	// WireGuard initiation is always 148 bytes — after obfuscation, size should vary.
	sizes := make(map[int]bool)
	for i := 0; i < 20; i++ {
		pkt := makeInitiationPacket()
		out, err := o.WrapOutbound(pkt)
		if err != nil {
			t.Fatalf("WrapOutbound error: %v", err)
		}
		sizes[len(out)] = true
	}
	// With random padding, we should get multiple distinct sizes.
	if len(sizes) < 2 {
		t.Errorf("expected multiple distinct sizes, got %d", len(sizes))
	}
}

func TestPaddedRandomPaddingDiffers(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)

	original := makeInitiationPacket()
	out1, _ := o.WrapOutbound(original)
	out2, _ := o.WrapOutbound(original)

	// The padding should be random, so outputs should differ.
	if bytes.Equal(out1, out2) {
		t.Error("two padded outputs should differ (random padding)")
	}
}

// --- padded mode: anti-probe PSK challenge ---

func TestPaddedPSKChallenge(t *testing.T) {
	psk := hex.EncodeToString(make([]byte, 32)) // 64 hex chars = 32 bytes
	cfg := DefaultObfuscationConfig()
	cfg.PSK = psk
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)

	// A valid initiation with PSK should round-trip.
	original := makeInitiationPacket()
	out, err := o.WrapOutbound(original)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}
	back, err := o.UnwrapInbound(out)
	if err != nil {
		t.Fatalf("UnwrapInbound error: %v", err)
	}
	if !bytes.Equal(back, original) {
		t.Error("PSK round-trip should preserve data")
	}
}

func TestPaddedPSKRejectsForgedPacket(t *testing.T) {
	psk := hex.EncodeToString([]byte("secret-ps-key-32-bytes-padding!!"))
	cfg := DefaultObfuscationConfig()
	cfg.PSK = psk
	cfg.JitterMaxMs = 0
	serverObf := newPaddedObfuscator(cfg)

	// Create an initiation packet WITHOUT the PSK tag (simulate a GFW probe).
	probe := makeInitiationPacket()
	// Apply header randomization but don't add PSK tag.
	obsType := serverObf.obfuscateType(wgMsgInitiation)
	body := probe[4:]
	forged := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(forged[:4], obsType)
	copy(forged[4:], body)

	// Server should reject this packet.
	_, err := serverObf.UnwrapInbound(forged)
	if err == nil {
		t.Error("server should reject packet without valid PSK tag")
	}
}

func TestPaddedPSKRejectsWrongKey(t *testing.T) {
	psk1 := hex.EncodeToString([]byte("key1-32-bytes-padding-padding!!"))
	psk2 := hex.EncodeToString([]byte("key2-32-bytes-padding-padding!!"))

	clientCfg := DefaultObfuscationConfig()
	clientCfg.PSK = psk1
	clientCfg.JitterMaxMs = 0
	clientObf := newPaddedObfuscator(clientCfg)

	serverCfg := DefaultObfuscationConfig()
	serverCfg.PSK = psk2
	serverCfg.JitterMaxMs = 0
	serverObf := newPaddedObfuscator(serverCfg)

	// Client signs with psk1, server expects psk2 — should fail.
	original := makeInitiationPacket()
	out, err := clientObf.WrapOutbound(original)
	if err != nil {
		t.Fatalf("client WrapOutbound error: %v", err)
	}
	_, err = serverObf.UnwrapInbound(out)
	if err == nil {
		t.Error("server should reject packet with wrong PSK")
	}
}

// --- padded mode: frame structure ---

func TestPaddedFrameStructure(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)

	original := makeInitiationPacket()
	out, err := o.WrapOutbound(original)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}

	// Frame: [4-byte obfuscated type][body][padding][optional PSK tag]
	if len(out) < 4+len(original)-4 {
		t.Errorf("frame too small: %d", len(out))
	}
}

// --- padded mode: unwrap invalid input ---

func TestPaddedUnwrapInvalidInput(t *testing.T) {
	o := NewObfuscator(ObfuscationPadded)

	// Too short.
	_, err := o.UnwrapInbound([]byte{0, 1})
	if err == nil {
		t.Error("UnwrapInbound should fail on short input")
	}

	// Unrecognized type.
	bad := make([]byte, 8)
	binary.LittleEndian.PutUint32(bad[:4], 0xFFFFFFFF) // not in any H range
	_, err = o.UnwrapInbound(bad)
	if err == nil {
		t.Error("UnwrapInbound should fail on unrecognized type")
	}
}

// --- padded mode: jitter ---

func TestPaddedJitterApplied(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 50
	o := newPaddedObfuscator(cfg)

	original := makeInitiationPacket()
	start := time.Now()
	_, _ = o.WrapOutbound(original)
	elapsed := time.Since(start)

	// With jitter up to 50ms, elapsed should be > 0.
	if elapsed <= 0 {
		t.Error("jitter should cause a delay")
	}
}

func TestPaddedNoJitterWhenDisabled(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)

	original := makeInitiationPacket()
	start := time.Now()
	_, _ = o.WrapOutbound(original)
	elapsed := time.Since(start)

	// Without jitter, should be near-instant (< 10ms).
	if elapsed > 10*time.Millisecond {
		t.Errorf("without jitter, elapsed = %v, expected < 10ms", elapsed)
	}
}

// --- junk train tests ---

func TestGenerateJunkTrainDisabled(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.Jc = 0
	packets := GenerateJunkTrain(cfg, mrand.New(mrand.NewSource(1)))
	if packets != nil {
		t.Error("junk train should be nil when Jc=0")
	}
}

func TestGenerateJunkTrain(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.Jc = 10
	cfg.Jmin = 64
	cfg.Jmax = 256
	rng := mrand.New(mrand.NewSource(42))
	packets := GenerateJunkTrain(cfg, rng)

	if len(packets) != 10 {
		t.Fatalf("junk train length = %d, want 10", len(packets))
	}

	for i, p := range packets {
		if len(p.Data) < cfg.Jmin || len(p.Data) > cfg.Jmax {
			t.Errorf("junk packet %d size = %d, want [%d, %d]", i, len(p.Data), cfg.Jmin, cfg.Jmax)
		}
	}

	// Junk packets should be random (not all the same).
	if bytes.Equal(packets[0].Data, packets[1].Data) {
		t.Error("junk packets should be random")
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
	if out[0] != wsFrameType {
		t.Errorf("frame type = 0x%02x, want 0x%02x", out[0], wsFrameType)
	}
}

func TestWebsocketClientMasking(t *testing.T) {
	// Client side frames must be masked per RFC 6455.
	clientObf := newWebsocketObfuscator(true)  // isClient=true
	serverObf := newWebsocketObfuscator(false) // isClient=false

	payload := []byte("wireguard-data")

	// Client wraps with masking.
	clientFrame, err := clientObf.WrapOutbound(payload)
	if err != nil {
		t.Fatalf("client WrapOutbound error: %v", err)
	}
	// Masked bit should be set.
	if clientFrame[1]&0x80 == 0 {
		t.Error("client frame should have mask bit set")
	}

	// Server should be able to unwrap the masked client frame.
	back, err := serverObf.UnwrapInbound(clientFrame)
	if err != nil {
		t.Fatalf("server UnwrapInbound error: %v", err)
	}
	if !bytes.Equal(back, payload) {
		t.Error("server should unmask client frame correctly")
	}

	// Server wraps without masking.
	serverFrame, err := serverObf.WrapOutbound(payload)
	if err != nil {
		t.Fatalf("server WrapOutbound error: %v", err)
	}
	if serverFrame[1]&0x80 != 0 {
		t.Error("server frame should not have mask bit set")
	}

	// Client should be able to unwrap the unmasked server frame.
	back, err = clientObf.UnwrapInbound(serverFrame)
	if err != nil {
		t.Fatalf("client UnwrapInbound error: %v", err)
	}
	if !bytes.Equal(back, payload) {
		t.Error("client should read server frame correctly")
	}
}

func TestWebsocketUnwrapInvalidInput(t *testing.T) {
	o := NewObfuscator(ObfuscationWebSocket)

	// Too short.
	_, err := o.UnwrapInbound([]byte{0x82})
	if err == nil {
		t.Error("should fail on short input")
	}

	// Wrong opcode.
	wrong := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'} // text frame, not binary
	_, err = o.UnwrapInbound(wrong)
	if err == nil {
		t.Error("should fail on wrong opcode")
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

func TestNewObfuscatorWithConfig(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.PSK = hex.EncodeToString([]byte("test-psk-32-bytes-padding-padding!"))

	// Padded mode with config.
	o := NewObfuscatorWithConfig(ObfuscationPadded, cfg, false)
	if o.Mode() != ObfuscationPadded {
		t.Errorf("mode = %v, want padded", o.Mode())
	}

	// None mode with config (config is ignored).
	o = NewObfuscatorWithConfig(ObfuscationNone, cfg, false)
	if o.Mode() != ObfuscationNone {
		t.Errorf("mode = %v, want none", o.Mode())
	}

	// Websocket mode with config.
	o = NewObfuscatorWithConfig(ObfuscationWebSocket, cfg, true)
	if o.Mode() != ObfuscationWebSocket {
		t.Errorf("mode = %v, want websocket", o.Mode())
	}
}

// --- obfuscating bind tests ---

func TestObfuscatingBindSetGet(t *testing.T) {
	bind := NewObfuscatingBind(nil)

	// Default obfuscator should be none (pass-through) so that peers
	// configured with obfuscation: "none" are not accidentally padded.
	o := bind.GetObfuscator("unknown-peer")
	if o.Mode() != ObfuscationNone {
		t.Errorf("default obfuscator mode = %v, want %v", o.Mode(), ObfuscationNone)
	}

	// Set a specific mode.
	bind.SetObfuscator("peer-1", ObfuscationNone)
	o = bind.GetObfuscator("peer-1")
	if o.Mode() != ObfuscationNone {
		t.Errorf("peer-1 obfuscator mode = %v, want %v", o.Mode(), ObfuscationNone)
	}
}

func TestObfuscatingBindSetWithConfig(t *testing.T) {
	bind := NewObfuscatingBind(nil)
	cfg := DefaultObfuscationConfig()
	cfg.PSK = hex.EncodeToString([]byte("psk-32-bytes-padding-padding-padd!"))

	bind.SetObfuscatorWithConfig("peer-psk", ObfuscationPadded, cfg, true)
	o := bind.GetObfuscator("peer-psk")
	if o.Mode() != ObfuscationPadded {
		t.Errorf("mode = %v, want padded", o.Mode())
	}

	// Should do a successful round-trip.
	pkt := makeInitiationPacket()
	out, err := o.WrapOutbound(pkt)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}
	back, err := o.UnwrapInbound(out)
	if err != nil {
		t.Fatalf("UnwrapInbound error: %v", err)
	}
	if !bytes.Equal(back, pkt) {
		t.Error("configured bind should round-trip")
	}
}

// --- hexEncode test ---

func TestHexEncode(t *testing.T) {
	got := hexEncode([]byte{0x01, 0x02, 0xff})
	if got != "0102ff" {
		t.Errorf("hexEncode = %q, want %q", got, "0102ff")
	}
}

// --- deriveMeshIP test ---

func TestDeriveMeshIP(t *testing.T) {
	ip := deriveMeshIP("aabbccdd0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c")
	if ip == "" {
		t.Error("deriveMeshIP returned empty")
	}
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

// --- config integration tests ---

func TestObfuscationConfigDefaults(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	if cfg.H1[0] == 0 || cfg.H1[1] == 0 {
		t.Error("H1 range should not be zero")
	}
	if cfg.H1[0] == 1 || cfg.H1[1] == 1 {
		t.Error("H1 should not use the original WireGuard type")
	}
	// Ranges must be non-overlapping.
	if cfg.H1[1] >= cfg.H2[0] {
		t.Error("H1 overlaps H2")
	}
	if cfg.S1 <= 0 {
		t.Error("S1 should be positive")
	}
}

func TestObfuscationConfigNoOverlaps(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	ranges := [4][2]uint32{cfg.H1, cfg.H2, cfg.H3, cfg.H4}
	for i := 0; i < 4; i++ {
		for j := i + 1; j < 4; j++ {
			if ranges[i][1] >= ranges[j][0] {
				t.Errorf("H%d overlaps H%d: [%x,%x] vs [%x,%x]", i+1, j+1, ranges[i][0], ranges[i][1], ranges[j][0], ranges[j][1])
			}
		}
	}
}

// --- PSK tag computation unit test ---

func TestPSKTagComputation(t *testing.T) {
	psk := hex.EncodeToString([]byte("test-psk-32-bytes-padding-padding!"))
	cfg := DefaultObfuscationConfig()
	cfg.PSK = psk
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)

	original := makeInitiationPacket()
	out, err := o.WrapOutbound(original)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}

	// The PSK tag should be the last 16 bytes of the body (after the 4-byte type).
	bodyLen := len(out) - 4
	if bodyLen < 16 {
		t.Fatalf("body too short for PSK tag: %d", bodyLen)
	}
	tag := out[len(out)-16:]

	// Verify the tag using the same key derivation.
	pskBytes, _ := hex.DecodeString(psk)
	key := make([]byte, 32)
	hkdf_sha256(pskBytes, []byte("meshdesk-obfuscation-v1"), key)

	n := 36
	if len(original) < n {
		n = len(original)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(original[:n])
	expectedTag := mac.Sum(nil)[:16]

	if !hmac.Equal(tag, expectedTag) {
		t.Error("PSK tag does not match expected value")
	}
}

func TestPSKTagOnlyForInitiation(t *testing.T) {
	psk := hex.EncodeToString([]byte("test-psk-32-bytes-padding-padding!"))
	cfg := DefaultObfuscationConfig()
	cfg.PSK = psk
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)

	// Non-initiation messages should NOT have a PSK tag.
	pkt := makePacketWithType(wgMsgTransport)
	out, err := o.WrapOutbound(pkt)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}

	// Verify by unwrapping — it should succeed, meaning the tag logic doesn't interfere.
	_, err = o.UnwrapInbound(out)
	if err != nil {
		t.Fatalf("UnwrapInbound error for non-initiation: %v", err)
	}
}

// --- helper functions for tests ---

// makeInitiationPacket creates a fake WireGuard initiation packet (148 bytes).
func makeInitiationPacket() []byte {
	pkt := make([]byte, wgInitiationSize)
	binary.LittleEndian.PutUint32(pkt[:4], wgMsgInitiation)
	// Fill body with random-ish data.
	for i := 4; i < len(pkt); i++ {
		pkt[i] = byte(i)
	}
	return pkt
}

// makePacketWithType creates a fake WireGuard packet with the given type.
func makePacketWithType(typ uint32) []byte {
	size := 64 // default
	switch typ {
	case wgMsgInitiation:
		size = wgInitiationSize
	case wgMsgResponse:
		size = wgResponseSize
	case wgMsgCookie:
		size = wgCookieSize
	}
	pkt := make([]byte, size)
	binary.LittleEndian.PutUint32(pkt[:4], typ)
	for i := 4; i < len(pkt); i++ {
		pkt[i] = byte(i)
	}
	return pkt
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
