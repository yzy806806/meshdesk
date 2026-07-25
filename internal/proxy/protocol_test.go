package proxy

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// TestForwardingHeaderRoundTrip verifies that a forwarding header can be
// encoded and decoded correctly with the relay key.
func TestForwardingHeaderRoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	tests := []struct {
		name    string
		nextHop string
	}{
		{"short", "10.10.0.5"},
		{"medium", "2001:db8::1:51820"},
		{"long", "a-very-long-relay-id-that-is-still-within-61-byte-limit"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := &ForwardingHeader{NextHop: tt.nextHop}
			encoded, err := orig.Encode(key)
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			if len(encoded) != ForwardingHeaderSize {
				t.Errorf("encoded length = %d, want %d", len(encoded), ForwardingHeaderSize)
			}

			decoded, err := DecodeForwardingHeader(encoded, key)
			if err != nil {
				t.Fatalf("DecodeForwardingHeader failed: %v", err)
			}

			if decoded.NextHop != tt.nextHop {
				t.Errorf("NextHop = %q, want %q", decoded.NextHop, tt.nextHop)
			}
		})
	}
}

// TestForwardingHeaderTooLong verifies that an overly long next-hop
// address is rejected.
func TestForwardingHeaderTooLong(t *testing.T) {
	key := make([]byte, KeySize)
	h := &ForwardingHeader{
		NextHop: string(make([]byte, ForwardingHeaderSize)), // too long
	}
	_, err := h.Encode(key)
	if err == nil {
		t.Error("expected error for too-long next-hop address")
	}
}

// TestForwardingHeaderUniqueCiphertext verifies that encoding the same
// header twice produces different ciphertext (because the padding is random).
func TestForwardingHeaderUniqueCiphertext(t *testing.T) {
	key := make([]byte, KeySize)
	h := &ForwardingHeader{NextHop: "10.10.0.1"}

	enc1, err := h.Encode(key)
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := h.Encode(key)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(enc1, enc2) {
		t.Error("two encodings of the same header should differ (random padding)")
	}

	// Both should decode to the same next-hop.
	d1, _ := DecodeForwardingHeader(enc1, key)
	d2, _ := DecodeForwardingHeader(enc2, key)
	if d1.NextHop != d2.NextHop {
		t.Errorf("decoded next-hop differs: %q vs %q", d1.NextHop, d2.NextHop)
	}
}

// TestChunkEncodeDecodeRoundTrip verifies that a chunk can be encrypted
// and decrypted correctly with E2E encryption.
func TestChunkEncodeDecodeRoundTrip(t *testing.T) {
	// Generate E2E key pair.
	entryKP, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	exitKP, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Derive shared keys.
	entryE2EKey, err := DeriveSharedKey(entryKP.Private, exitKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	exitE2EKey, err := DeriveSharedKey(exitKP.Private, entryKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(entryE2EKey, exitE2EKey) {
		t.Fatal("ECDH key derivation mismatch — entry and exit keys differ")
	}

	relayKey := make([]byte, KeySize)
	for i := range relayKey {
		relayKey[i] = byte(i + 1)
	}

	circuitID, _ := GenerateCircuitID()

	origChunk := Chunk{
		StreamID:   42,
		Sequence:   7,
		Total:      10,
		Type:       ChunkData,
		Payload:    []byte("hello multi-path proxy world!"),
		PaddingLen: 512,
	}

	wc, err := EncodeChunk(origChunk, entryE2EKey, relayKey, "10.10.0.5", circuitID)
	if err != nil {
		t.Fatalf("EncodeChunk failed: %v", err)
	}

	if len(wc.Header) != ForwardingHeaderSize {
		t.Errorf("header length = %d, want %d", len(wc.Header), ForwardingHeaderSize)
	}
	if len(wc.Nonce) != NonceSize {
		t.Errorf("nonce length = %d, want %d", len(wc.Nonce), NonceSize)
	}

	decoded, err := DecodeChunk(wc, exitE2EKey, circuitID)
	if err != nil {
		t.Fatalf("DecodeChunk failed: %v", err)
	}

	if decoded.StreamID != origChunk.StreamID {
		t.Errorf("StreamID = %d, want %d", decoded.StreamID, origChunk.StreamID)
	}
	if decoded.Sequence != origChunk.Sequence {
		t.Errorf("Sequence = %d, want %d", decoded.Sequence, origChunk.Sequence)
	}
	if decoded.Total != origChunk.Total {
		t.Errorf("Total = %d, want %d", decoded.Total, origChunk.Total)
	}
	if decoded.Type != origChunk.Type {
		t.Errorf("Type = %v, want %v", decoded.Type, origChunk.Type)
	}
	if decoded.PaddingLen != origChunk.PaddingLen {
		t.Errorf("PaddingLen = %d, want %d", decoded.PaddingLen, origChunk.PaddingLen)
	}
	if !bytes.Equal(decoded.Payload, origChunk.Payload) {
		t.Errorf("Payload mismatch: got %q, want %q", decoded.Payload, origChunk.Payload)
	}
}

// TestChunkEncodeTampered verifies that AEAD detects tampering with
// the ciphertext or associated data (forwarding header).
func TestChunkEncodeTampered(t *testing.T) {
	entryKP, _ := GenerateECDHKeyPair()
	exitKP, _ := GenerateECDHKeyPair()

	e2eKey, _ := DeriveSharedKey(entryKP.Private, exitKP.Public)
	relayKey := make([]byte, KeySize)
	circuitID, _ := GenerateCircuitID()

	chunk := Chunk{
		StreamID: 1,
		Sequence: 0,
		Type:     ChunkData,
		Payload:  []byte("sensitive data"),
	}

	wc, err := EncodeChunk(chunk, e2eKey, relayKey, "10.10.0.1", circuitID)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with ciphertext.
	tampered := *wc
	tampered.Ciphertext = make([]byte, len(wc.Ciphertext))
	copy(tampered.Ciphertext, wc.Ciphertext)
	tampered.Ciphertext[0] ^= 0xFF

	_, err = DecodeChunk(&tampered, e2eKey, circuitID)
	if err == nil {
		t.Error("expected AEAD decryption failure for tampered ciphertext")
	}

	// Tamper with header (associated data).
	tampered2 := *wc
	tampered2.Header = make([]byte, len(wc.Header))
	copy(tampered2.Header, wc.Header)
	tampered2.Header[0] ^= 0xFF

	_, err = DecodeChunk(&tampered2, e2eKey, circuitID)
	if err == nil {
		t.Error("expected AEAD decryption failure for tampered header")
	}

	// Verify cross-circuit replay protection: decoding with a different
	// circuit ID should fail with ErrCircuitIDMismatch.
	otherCircuitID, _ := GenerateCircuitID()
	// Make sure they're actually different
	for bytes.Equal(otherCircuitID, circuitID) {
		otherCircuitID, _ = GenerateCircuitID()
	}
	_, err = DecodeChunk(wc, e2eKey, otherCircuitID)
	if err == nil {
		t.Error("expected error for circuit ID mismatch")
	}
	if err != nil && !errors.Is(err, ErrCircuitIDMismatch) {
		t.Errorf("expected ErrCircuitIDMismatch, got %v", err)
	}
}

// TestECDHKeyAgreement verifies that two parties derive the same shared key.
func TestECDHKeyAgreement(t *testing.T) {
	alice, _ := GenerateECDHKeyPair()
	bob, _ := GenerateECDHKeyPair()

	aliceKey, err := DeriveSharedKey(alice.Private, bob.Public)
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := DeriveSharedKey(bob.Private, alice.Public)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceKey, bobKey) {
		t.Error("ECDH key agreement failed — keys differ")
	}

	if len(aliceKey) != KeySize {
		t.Errorf("shared key length = %d, want %d", len(aliceKey), KeySize)
	}
}

// TestCircuitSetupRoundTrip verifies serialization of circuit setup messages.
func TestCircuitSetupRoundTrip(t *testing.T) {
	circuitID, _ := GenerateCircuitID()
	ecdhKP, _ := GenerateECDHKeyPair()

	orig := &CircuitSetup{
		CircuitID:  circuitID,
		ECDHPubKey: ecdhKP.Public,
		TargetAddr: "example.com:443",
	}

	encoded, err := orig.Encode()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeCircuitSetup(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded.CircuitID, orig.CircuitID) {
		t.Errorf("CircuitID mismatch")
	}
	if !bytes.Equal(decoded.ECDHPubKey, orig.ECDHPubKey) {
		t.Errorf("ECDHPubKey mismatch")
	}
	if decoded.TargetAddr != orig.TargetAddr {
		t.Errorf("TargetAddr = %q, want %q", decoded.TargetAddr, orig.TargetAddr)
	}
}

// TestCircuitAckRoundTrip verifies serialization of circuit ack messages.
func TestCircuitAckRoundTrip(t *testing.T) {
	circuitID, _ := GenerateCircuitID()
	ecdhKP, _ := GenerateECDHKeyPair()

	tests := []struct {
		name     string
		accepted bool
		reason   string
	}{
		{"accepted", true, ""},
		{"rejected", false, "port not allowed"},
		{"rejected-long", false, "circuit limit reached: too many active circuits from this relay"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := &CircuitAck{
				CircuitID:  circuitID,
				ECDHPubKey: ecdhKP.Public,
				Accepted:   tt.accepted,
				Reason:     tt.reason,
			}

			encoded, err := orig.Encode()
			if err != nil {
				t.Fatal(err)
			}

			decoded, err := DecodeCircuitAck(encoded)
			if err != nil {
				t.Fatal(err)
			}

			if decoded.Accepted != tt.accepted {
				t.Errorf("Accepted = %v, want %v", decoded.Accepted, tt.accepted)
			}
			if decoded.Reason != tt.reason {
				t.Errorf("Reason = %q, want %q", decoded.Reason, tt.reason)
			}
		})
	}
}

// TestTeardownMsgRoundTrip verifies serialization of teardown messages.
func TestTeardownMsgRoundTrip(t *testing.T) {
	circuitID, _ := GenerateCircuitID()

	orig := &TeardownMsg{
		CircuitID: circuitID,
		Reason:    "idle timeout",
	}

	encoded, err := orig.Encode()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeTeardown(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded.CircuitID, orig.CircuitID) {
		t.Error("CircuitID mismatch")
	}
	if decoded.Reason != orig.Reason {
		t.Errorf("Reason = %q, want %q", decoded.Reason, orig.Reason)
	}
}

// TestKeepaliveMsgRoundTrip verifies serialization of keepalive messages.
func TestKeepaliveMsgRoundTrip(t *testing.T) {
	circuitID, _ := GenerateCircuitID()

	orig := &KeepaliveMsg{
		CircuitID: circuitID,
		Timestamp: 1700000000000000000,
	}

	encoded, err := orig.Encode()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeKeepalive(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded.CircuitID, orig.CircuitID) {
		t.Error("CircuitID mismatch")
	}
	if decoded.Timestamp != orig.Timestamp {
		t.Errorf("Timestamp = %d, want %d", decoded.Timestamp, orig.Timestamp)
	}
}

// TestNACKMsgRoundTrip verifies serialization of NACK messages.
func TestNACKMsgRoundTrip(t *testing.T) {
	circuitID, _ := GenerateCircuitID()

	orig := &NACKMsg{
		CircuitID:   circuitID,
		StreamID:    42,
		MissingSeqs: []uint32{3, 7, 12, 15},
	}

	encoded, err := orig.Encode()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeNACK(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded.CircuitID, orig.CircuitID) {
		t.Error("CircuitID mismatch")
	}
	if decoded.StreamID != orig.StreamID {
		t.Errorf("StreamID = %d, want %d", decoded.StreamID, orig.StreamID)
	}
	if len(decoded.MissingSeqs) != len(orig.MissingSeqs) {
		t.Fatalf("MissingSeqs length = %d, want %d", len(decoded.MissingSeqs), len(orig.MissingSeqs))
	}
	for i, seq := range orig.MissingSeqs {
		if decoded.MissingSeqs[i] != seq {
			t.Errorf("MissingSeqs[%d] = %d, want %d", i, decoded.MissingSeqs[i], seq)
		}
	}
}

// TestNACKMsgEmpty verifies that a NACK with no missing sequences works.
func TestNACKMsgEmpty(t *testing.T) {
	circuitID, _ := GenerateCircuitID()

	orig := &NACKMsg{
		CircuitID:   circuitID,
		StreamID:    1,
		MissingSeqs: nil,
	}

	encoded, err := orig.Encode()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeNACK(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(decoded.MissingSeqs) != 0 {
		t.Errorf("expected 0 missing seqs, got %d", len(decoded.MissingSeqs))
	}
}

// TestGenerateCircuitID verifies circuit IDs are unique and correct size.
func TestGenerateCircuitID(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id, err := GenerateCircuitID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != CircuitIDSize {
			t.Errorf("circuit ID length = %d, want %d", len(id), CircuitIDSize)
		}
		key := string(id)
		if ids[key] {
			t.Errorf("duplicate circuit ID generated at iteration %d", i)
		}
		ids[key] = true
	}
}

// TestDefaultCircuitConfig verifies sensible defaults.
func TestDefaultCircuitConfig(t *testing.T) {
	cfg := DefaultCircuitConfig()
	if cfg.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout = %v, want 5m", cfg.IdleTimeout)
	}
	if cfg.KeepaliveInterval != 30*time.Second {
		t.Errorf("KeepaliveInterval = %v, want 30s", cfg.KeepaliveInterval)
	}
	if cfg.NACKTimeout != 5*time.Second {
		t.Errorf("NACKTimeout = %v, want 5s", cfg.NACKTimeout)
	}
	if cfg.OrphanTimeout != 30*time.Second {
		t.Errorf("OrphanTimeout = %v, want 30s", cfg.OrphanTimeout)
	}
	if cfg.MaxReassemblyWindow != 256 {
		t.Errorf("MaxReassemblyWindow = %d, want 256", cfg.MaxReassemblyWindow)
	}
}
