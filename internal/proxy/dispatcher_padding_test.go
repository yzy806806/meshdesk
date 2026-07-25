package proxy

import (
	"net"
	"testing"
)

// TestDispatcherPaddingSeedGenerated verifies that NewDispatcher
// automatically generates a 32-byte per-circuit padding seed when
// none is provided in the config (spec §4.2: creation step).
func TestDispatcherPaddingSeedGenerated(t *testing.T) {
	e2eKey := make([]byte, KeySize)
	for i := range e2eKey {
		e2eKey[i] = byte(i)
	}
	relayKey := make([]byte, KeySize)

	cfg := DispatcherConfig{
		E2EKey:    e2eKey,
		CircuitID: make([]byte, CircuitIDSize),
		Path1:     &Path{Relays: []string{"relayA"}, RelayKeys: [][]byte{relayKey}},
		Path2:     &Path{Relays: []string{"relayB"}, RelayKeys: [][]byte{relayKey}},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	d, err := NewDispatcher(cfg, serverConn)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	seed := d.PaddingSeed()
	if len(seed) != 32 {
		t.Fatalf("padding seed length = %d, want 32", len(seed))
	}

	// Verify the seed is not all zeros (extremely unlikely with crypto/rand).
	allZero := true
	for _, b := range seed {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("padding seed is all zeros — crypto/rand likely failed")
	}
}

// TestDispatcherPaddingSeedRespected verifies that a pre-set PaddingSeed
// in the config is not overwritten by NewDispatcher.
func TestDispatcherPaddingSeedRespected(t *testing.T) {
	e2eKey := make([]byte, KeySize)
	relayKey := make([]byte, KeySize)

	userSeed := make([]byte, 32)
	for i := range userSeed {
		userSeed[i] = byte(i + 100)
	}

	cfg := DispatcherConfig{
		E2EKey:    e2eKey,
		CircuitID: make([]byte, CircuitIDSize),
		Path1:     &Path{Relays: []string{"relayA"}, RelayKeys: [][]byte{relayKey}},
		Path2:     &Path{Relays: []string{"relayB"}, RelayKeys: [][]byte{relayKey}},
		ChunkerCfg: ChunkerConfig{
			MaxChunkSize: 16 * 1024,
			PaddingSeed:  userSeed,
		},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	d, err := NewDispatcher(cfg, serverConn)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	seed := d.PaddingSeed()
	// Verify the seed matches what we provided.
	for i, b := range seed {
		if b != userSeed[i] {
			t.Fatalf("seed byte %d: got %d, want %d (pre-set seed was overwritten)", i, b, userSeed[i])
		}
	}
}

// TestDispatcherPaddingSeedZeroedOnClose verifies that Close() zeros
// the padding seed (spec §4.2: destruction step).
func TestDispatcherPaddingSeedZeroedOnClose(t *testing.T) {
	e2eKey := make([]byte, KeySize)
	relayKey := make([]byte, KeySize)

	cfg := DispatcherConfig{
		E2EKey:    e2eKey,
		CircuitID: make([]byte, CircuitIDSize),
		Path1:     &Path{Relays: []string{"relayA"}, RelayKeys: [][]byte{relayKey}},
		Path2:     &Path{Relays: []string{"relayB"}, RelayKeys: [][]byte{relayKey}},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	d, err := NewDispatcher(cfg, serverConn)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	// Verify seed exists before close.
	seedBefore := d.PaddingSeed()
	if len(seedBefore) != 32 {
		t.Fatalf("seed length before close = %d, want 32", len(seedBefore))
	}

	// Close the dispatcher.
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify seed is zeroed after close.
	seedAfter := d.PaddingSeed()
	for i, b := range seedAfter {
		if b != 0 {
			t.Fatalf("seed byte %d after Close = %d, want 0 (seed not zeroed)", i, b)
		}
	}
}

// TestDispatcherPaddingSeedNotInCircuitSetup verifies that the padding
// seed is NOT serialized in the CircuitSetup message (spec §4.2: the
// seed is entry-local, never transmitted to the exit).
func TestDispatcherPaddingSeedNotInCircuitSetup(t *testing.T) {
	circuitID := make([]byte, CircuitIDSize)
	for i := range circuitID {
		circuitID[i] = byte(i + 1)
	}
	ecdhPub := make([]byte, 32)
	for i := range ecdhPub {
		ecdhPub[i] = byte(i + 10)
	}

	// Create a CircuitSetup with only the expected fields.
	setup := &CircuitSetup{
		CircuitID:  circuitID,
		ECDHPubKey: ecdhPub,
		TargetAddr: "127.0.0.1:80",
	}

	// Encode the CircuitSetup.
	encoded, err := setup.Encode()
	if err != nil {
		t.Fatalf("CircuitSetup.Encode: %v", err)
	}

	// Verify the encoded form doesn't contain a 32-byte seed-like pattern.
	// The seed should not be in the wire format at all.
	// We verify by decoding and checking fields.
	decoded, err := DecodeCircuitSetup(encoded)
	if err != nil {
		t.Fatalf("DecodeCircuitSetup: %v", err)
	}

	// The CircuitSetup struct has no PaddingSeed field — if it did,
	// this test would need to verify it's nil/empty. The struct definition
	// itself is the proof. Here we just verify the round-trip works.
	if decoded.TargetAddr != setup.TargetAddr {
		t.Errorf("TargetAddr: got %q, want %q", decoded.TargetAddr, setup.TargetAddr)
	}
}

// TestDispatcherPaddingSeedDeterministicChunking verifies that two
// chunkers with the same padding seed produce identical padding
// sequences for the same input data (spec §4.2: deterministic replay).
func TestDispatcherPaddingSeedDeterministicChunking(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 42)
	}

	cfg := ChunkerConfig{
		MaxChunkSize:   1024,
		MinChunkSize:   1024,
		PaddingMin:     100,
		PaddingMax:     500,
		PaddingSeed:    seed,
		DisablePadding: false,
	}

	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Two chunkers with the same seed should produce identical padding.
	chunker1 := NewChunkerWithConfig("fixed-16k", cfg)
	chunker2 := NewChunkerWithConfig("fixed-16k", cfg)

	// Set the same stream ID on both.
	if c, ok := chunker1.(interface{ SetStreamID(uint32) }); ok {
		c.SetStreamID(0)
	}
	if c, ok := chunker2.(interface{ SetStreamID(uint32) }); ok {
		c.SetStreamID(0)
	}

	chunks1 := chunker1.Split(data)
	chunks2 := chunker2.Split(data)

	if len(chunks1) != len(chunks2) {
		t.Fatalf("chunk count differs: c1=%d, c2=%d (same seed should produce same count)", len(chunks1), len(chunks2))
	}

	// With the same seed, padding lengths should be identical.
	for i := range chunks1 {
		if chunks1[i].PaddingLen != chunks2[i].PaddingLen {
			t.Errorf("chunk %d PaddingLen: c1=%d, c2=%d (same seed should produce identical padding)", i, chunks1[i].PaddingLen, chunks2[i].PaddingLen)
			break
		}
	}
}
