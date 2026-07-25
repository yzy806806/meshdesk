package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// --- Wire format tests ---

// TestSerializeDeserializeWireChunk verifies the wire serialization
// round-trips correctly for a typical WireChunk.
func TestSerializeDeserializeWireChunk(t *testing.T) {
	header := make([]byte, ForwardingHeaderSize)
	for i := range header {
		header[i] = byte(i)
	}
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	ciphertext := []byte("this is encrypted AEAD ciphertext that the relay never sees")

	orig := &WireChunk{
		Header:     header,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	data, err := SerializeWireChunk(orig)
	if err != nil {
		t.Fatalf("SerializeWireChunk failed: %v", err)
	}

	decoded, consumed, err := DeserializeWireChunk(data)
	if err != nil {
		t.Fatalf("DeserializeWireChunk failed: %v", err)
	}

	if consumed != len(data) {
		t.Errorf("consumed = %d, want %d", consumed, len(data))
	}
	if !bytes.Equal(decoded.Header, orig.Header) {
		t.Errorf("header mismatch")
	}
	if !bytes.Equal(decoded.Nonce, orig.Nonce) {
		t.Errorf("nonce mismatch")
	}
	if !bytes.Equal(decoded.Ciphertext, orig.Ciphertext) {
		t.Errorf("ciphertext mismatch")
	}
}

// TestSerializeWireChunkValidation verifies that malformed WireChunks
// are rejected during serialization.
func TestSerializeWireChunkValidation(t *testing.T) {
	tests := []struct {
		name   string
		wc     *WireChunk
		errMsg string
	}{
		{
			name:   "nil header",
			wc:     &WireChunk{Nonce: make([]byte, NonceSize), Ciphertext: []byte("x")},
			errMsg: "header must be",
		},
		{
			name:   "wrong nonce size",
			wc:     &WireChunk{Header: make([]byte, ForwardingHeaderSize), Nonce: []byte("short"), Ciphertext: []byte("x")},
			errMsg: "nonce must be",
		},
		{
			name:   "empty ciphertext",
			wc:     &WireChunk{Header: make([]byte, ForwardingHeaderSize), Nonce: make([]byte, NonceSize), Ciphertext: nil},
			errMsg: "ciphertext is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SerializeWireChunk(tt.wc)
			if err == nil {
				t.Errorf("expected error containing %q, got nil", tt.errMsg)
			}
		})
	}
}

// TestDeserializeWireChunkTruncated verifies that truncated wire data
// is rejected properly.
func TestDeserializeWireChunkTruncated(t *testing.T) {
	wc := &WireChunk{
		Header:     make([]byte, ForwardingHeaderSize),
		Nonce:      make([]byte, NonceSize),
		Ciphertext: []byte("payload"),
	}

	data, _ := SerializeWireChunk(wc)

	// Truncate at various points.
	for cut := 1; cut < len(data); cut += 7 {
		_, _, err := DeserializeWireChunk(data[:cut])
		if err == nil {
			t.Errorf("expected error for truncated data at cut=%d, got nil", cut)
		}
	}
}

// TestReadWriteWireChunkStream verifies the streaming read/write
// functions work over a pipe (simulating a TCP connection).
func TestReadWriteWireChunkStream(t *testing.T) {
	r1, w1 := net.Pipe()
	r2, w2 := net.Pipe()
	defer r1.Close()
	defer w1.Close()
	defer r2.Close()
	defer w2.Close()

	// Pipe: w1 → r1 and w2 → r2
	// We write to w1 and read from r1.
	wc1 := &WireChunk{
		Header:     make([]byte, ForwardingHeaderSize),
		Nonce:      make([]byte, NonceSize),
		Ciphertext: []byte("first chunk payload"),
	}
	wc2 := &WireChunk{
		Header:     make([]byte, ForwardingHeaderSize),
		Nonce:      make([]byte, NonceSize),
		Ciphertext: []byte("second chunk payload, longer"),
	}

	// Write two chunks to w1.
	go func() {
		WriteWireChunk(w1, wc1)
		WriteWireChunk(w1, wc2)
	}()

	// Read them from r1.
	read1, err := ReadWireChunk(r1)
	if err != nil {
		t.Fatalf("ReadWireChunk 1 failed: %v", err)
	}
	if !bytes.Equal(read1.Ciphertext, wc1.Ciphertext) {
		t.Errorf("chunk 1 ciphertext mismatch")
	}

	read2, err := ReadWireChunk(r1)
	if err != nil {
		t.Fatalf("ReadWireChunk 2 failed: %v", err)
	}
	if !bytes.Equal(read2.Ciphertext, wc2.Ciphertext) {
		t.Errorf("chunk 2 ciphertext mismatch")
	}
}

// --- Relay forwarding tests ---

// TestRelayForwardChunk verifies that a relay correctly:
//  1. Decrypts the forwarding header to extract the next-hop address
//  2. Passes the ciphertext and header through UNTOUCHED
//  3. The relay never modifies any part of the WireChunk
func TestRelayForwardChunk(t *testing.T) {
	// Create relay keys.
	relayKey := make([]byte, KeySize)
	for i := range relayKey {
		relayKey[i] = byte(i + 1)
	}
	nextRelayKey := make([]byte, KeySize)
	for i := range nextRelayKey {
		nextRelayKey[i] = byte(i + 100)
	}

	// Create a WireChunk as if produced by the entry node.
	// The header is encrypted with relayKey, containing nextHop = "10.10.0.5"
	origHeader, err := (&ForwardingHeader{NextHop: "10.10.0.5"}).Encode(relayKey)
	if err != nil {
		t.Fatal(err)
	}

	origChunk := &WireChunk{
		Header:     origHeader,
		Nonce:      make([]byte, NonceSize),
		Ciphertext: []byte("encrypted payload the relay should not see"),
	}

	// Set up relay with jitter disabled for deterministic testing.
	relay := NewRelay(RelayConfig{DisableJitter: true})
	circuitID := "test-circuit-1"
	relay.AddCircuit(circuitID, relayKey, nextRelayKey)

	nextHop, forwarded, err := relay.ForwardChunk(circuitID, origChunk)
	if err != nil {
		t.Fatalf("ForwardChunk failed: %v", err)
	}

	// Verify next-hop was extracted correctly.
	if nextHop != "10.10.0.5" {
		t.Errorf("nextHop = %q, want %q", nextHop, "10.10.0.5")
	}

	// Verify ciphertext was passed through UNTOUCHED.
	if !bytes.Equal(forwarded.Ciphertext, origChunk.Ciphertext) {
		t.Error("ciphertext was modified by the relay — relay must be blind")
	}

	// Verify nonce was passed through.
	if !bytes.Equal(forwarded.Nonce, origChunk.Nonce) {
		t.Error("nonce was modified by the relay")
	}

	// Verify the header is passed through UNCHANGED. The AEAD ciphertext
	// is bound to the original header as associated data, so the relay
	// must not modify the header bytes — the exit needs the exact same
	// header to verify the AEAD tag.
	if !bytes.Equal(forwarded.Header, origChunk.Header) {
		t.Error("header was modified by the relay — must pass through unchanged for AEAD verification")
	}
}

// TestRelayForwardChunkLastHop verifies behavior when the relay is the
// last before the exit (nextRelayKey is nil). The header is still passed
// through unchanged — the AEAD ciphertext is bound to the original header.
func TestRelayForwardChunkLastHop(t *testing.T) {
	relayKey := make([]byte, KeySize)
	for i := range relayKey {
		relayKey[i] = byte(i + 1)
	}

	origHeader, err := (&ForwardingHeader{NextHop: "exit-node-1"}).Encode(relayKey)
	if err != nil {
		t.Fatal(err)
	}

	origChunk := &WireChunk{
		Header:     origHeader,
		Nonce:      make([]byte, NonceSize),
		Ciphertext: []byte("encrypted payload"),
	}

	// Last relay — no nextRelayKey.
	relay := NewRelay(RelayConfig{DisableJitter: true})
	relay.AddCircuit("circuit-last", relayKey, nil)

	nextHop, forwarded, err := relay.ForwardChunk("circuit-last", origChunk)
	if err != nil {
		t.Fatalf("ForwardChunk failed: %v", err)
	}

	if nextHop != "exit-node-1" {
		t.Errorf("nextHop = %q, want %q", nextHop, "exit-node-1")
	}

	// Header should be passed through unchanged (same bytes).
	if !bytes.Equal(forwarded.Header, origChunk.Header) {
		t.Error("header was modified on last hop — should pass through")
	}

	// Ciphertext still untouched.
	if !bytes.Equal(forwarded.Ciphertext, origChunk.Ciphertext) {
		t.Error("ciphertext modified on last hop")
	}
}

// TestRelayForwardChunkUnknownCircuit verifies that forwarding a
// chunk for an unregistered circuit is rejected.
func TestRelayForwardChunkUnknownCircuit(t *testing.T) {
	relay := NewRelay(RelayConfig{DisableJitter: true})

	wc := &WireChunk{
		Header:     make([]byte, ForwardingHeaderSize),
		Nonce:      make([]byte, NonceSize),
		Ciphertext: []byte("payload"),
	}

	_, _, err := relay.ForwardChunk("nonexistent", wc)
	if err == nil {
		t.Error("expected error for unknown circuit")
	}
}

// TestRelayForwardChunkBadHeader verifies that a chunk with a
// wrong-size header is rejected.
func TestRelayForwardChunkBadHeader(t *testing.T) {
	relayKey := make([]byte, KeySize)
	relay := NewRelay(RelayConfig{DisableJitter: true})
	relay.AddCircuit("test", relayKey, nil)

	wc := &WireChunk{
		Header:     make([]byte, 32), // wrong size
		Nonce:      make([]byte, NonceSize),
		Ciphertext: []byte("payload"),
	}

	_, _, err := relay.ForwardChunk("test", wc)
	if err == nil {
		t.Error("expected error for wrong-size header")
	}
}

// TestRelayJitter verifies that jitter is applied and falls within
// the configured range. We use a tighter range to make the test fast.
func TestRelayJitter(t *testing.T) {
	relayKey := make([]byte, KeySize)
	for i := range relayKey {
		relayKey[i] = byte(i + 1)
	}

	relay := NewRelay(RelayConfig{
		JitterMin: 2 * time.Millisecond,
		JitterMax: 10 * time.Millisecond,
	})
	relay.AddCircuit("jitter-test", relayKey, nil)

	origHeader, _ := (&ForwardingHeader{NextHop: "10.10.0.1"}).Encode(relayKey)
	wc := &WireChunk{
		Header:     origHeader,
		Nonce:      make([]byte, NonceSize),
		Ciphertext: []byte("payload"),
	}

	// Forward multiple chunks and measure timing.
	for i := 0; i < 5; i++ {
		start := time.Now()
		_, _, err := relay.ForwardChunk("jitter-test", wc)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("ForwardChunk failed: %v", err)
		}
		// Should have at least JitterMin of delay.
		if elapsed < 1*time.Millisecond {
			t.Errorf("iteration %d: elapsed = %v, expected >= %v (jitter not applied)",
				i, elapsed, 2*time.Millisecond)
		}
		// Should not exceed JitterMax by more than a small margin
		// for scheduling overhead.
		if elapsed > 50*time.Millisecond {
			t.Errorf("iteration %d: elapsed = %v, expected <= ~%v", i, elapsed, 10*time.Millisecond)
		}
	}
}

// TestRelayJitterDisabled verifies that when DisableJitter is true,
// forwarding is essentially instant.
func TestRelayJitterDisabled(t *testing.T) {
	relayKey := make([]byte, KeySize)
	relay := NewRelay(RelayConfig{DisableJitter: true})
	relay.AddCircuit("no-jitter", relayKey, nil)

	origHeader, _ := (&ForwardingHeader{NextHop: "10.10.0.1"}).Encode(relayKey)
	wc := &WireChunk{
		Header:     origHeader,
		Nonce:      make([]byte, NonceSize),
		Ciphertext: []byte("payload"),
	}

	start := time.Now()
	_, _, err := relay.ForwardChunk("no-jitter", wc)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ForwardChunk failed: %v", err)
	}
	if elapsed > 1*time.Millisecond {
		t.Errorf("elapsed = %v, expected < 1ms with jitter disabled", elapsed)
	}
}

// TestRelayAddRemoveCircuit verifies circuit lifecycle management.
func TestRelayAddRemoveCircuit(t *testing.T) {
	relayKey := make([]byte, KeySize)
	relay := NewRelay(RelayConfig{DisableJitter: true})

	// Add.
	err := relay.AddCircuit("c1", relayKey, nil)
	if err != nil {
		t.Fatalf("AddCircuit failed: %v", err)
	}
	if relay.CircuitCount() != 1 {
		t.Errorf("CircuitCount = %d, want 1", relay.CircuitCount())
	}

	// Duplicate.
	err = relay.AddCircuit("c1", relayKey, nil)
	if err == nil {
		t.Error("expected error for duplicate circuit")
	}

	// Remove.
	relay.RemoveCircuit("c1")
	if relay.CircuitCount() != 0 {
		t.Errorf("CircuitCount = %d, want 0", relay.CircuitCount())
	}

	// Remove nonexistent (should not panic).
	relay.RemoveCircuit("nonexistent")
}

// TestRelayMaxCircuits verifies the circuit capacity limit.
func TestRelayMaxCircuits(t *testing.T) {
	relayKey := make([]byte, KeySize)
	relay := NewRelay(RelayConfig{DisableJitter: true, MaxCircuits: 3})

	for i := 0; i < 3; i++ {
		err := relay.AddCircuit(string(rune('a'+i)), relayKey, nil)
		if err != nil {
			t.Fatalf("AddCircuit %d failed: %v", i, err)
		}
	}

	// Fourth should fail.
	err := relay.AddCircuit("d", relayKey, nil)
	if err == nil {
		t.Error("expected error when at capacity")
	}
}

// TestRelayAddCircuitBadKey verifies that invalid key sizes are rejected.
func TestRelayAddCircuitBadKey(t *testing.T) {
	relay := NewRelay(RelayConfig{DisableJitter: true})

	// Wrong relay key size.
	err := relay.AddCircuit("c1", make([]byte, 16), nil)
	if err == nil {
		t.Error("expected error for wrong relay key size")
	}

	// Wrong next relay key size.
	err = relay.AddCircuit("c2", make([]byte, KeySize), make([]byte, 16))
	if err == nil {
		t.Error("expected error for wrong next relay key size")
	}
}

// TestRelayDefaultConfig verifies that defaults are applied correctly.
func TestRelayDefaultConfig(t *testing.T) {
	cfg := DefaultRelayConfig()
	if cfg.JitterMin != 5*time.Millisecond {
		t.Errorf("JitterMin = %v, want 5ms", cfg.JitterMin)
	}
	if cfg.JitterMax != 50*time.Millisecond {
		t.Errorf("JitterMax = %v, want 50ms", cfg.JitterMax)
	}
	if cfg.MaxCircuits != 1024 {
		t.Errorf("MaxCircuits = %d, want 1024", cfg.MaxCircuits)
	}
	if cfg.MaxQueueDepth != 256 {
		t.Errorf("MaxQueueDepth = %d, want 256", cfg.MaxQueueDepth)
	}
}

// TestRelayDefaultConfigAutoFill verifies that NewRelay fills in
// defaults for zero-value config fields.
func TestRelayDefaultConfigAutoFill(t *testing.T) {
	r := NewRelay(RelayConfig{})
	if r.cfg.JitterMin != DefaultJitterMin {
		t.Errorf("JitterMin = %v, want %v", r.cfg.JitterMin, DefaultJitterMin)
	}
	if r.cfg.JitterMax != DefaultJitterMax {
		t.Errorf("JitterMax = %v, want %v", r.cfg.JitterMax, DefaultJitterMax)
	}
	if r.cfg.MaxCircuits != 1024 {
		t.Errorf("MaxCircuits = %d, want 1024", r.cfg.MaxCircuits)
	}
	if r.cfg.MaxQueueDepth != 256 {
		t.Errorf("MaxQueueDepth = %d, want 256", r.cfg.MaxQueueDepth)
	}
}

// --- End-to-end relay stream tests ---

// TestRelayForwardStream verifies the streaming forwarding loop over
// a net.Pipe, simulating a real relay connection.
//
// In v1, the forwarding header is single-layer encrypted (entry → first
// relay). The first relay decrypts it to learn the next-hop, then passes
// the chunk through unchanged. Downstream relays cannot decrypt the header
// (it was encrypted with the first relay's key), so they use the circuit
// routing table (nextHop cached by a prior call or pre-configured).
//
// For this test, we simulate a single-relay path (entry → relay → exit)
// to verify the core streaming behavior.
func TestRelayForwardStream(t *testing.T) {
	relayKey := make([]byte, KeySize)
	for i := range relayKey {
		relayKey[i] = byte(i + 1)
	}

	// Set up a single relay (last hop before exit — no nextRelayKey).
	relay := NewRelay(RelayConfig{DisableJitter: true})
	relay.AddCircuit("c1", relayKey, nil)

	// Build a WireChunk as the entry would produce it.
	origHeader, err := (&ForwardingHeader{NextHop: "exit-addr"}).Encode(relayKey)
	if err != nil {
		t.Fatal(err)
	}

	origChunk := &WireChunk{
		Header:     origHeader,
		Nonce:      make([]byte, NonceSize),
		Ciphertext: []byte("end-to-end encrypted payload"),
	}

	// pipe1: entry → relay (w1 → r1)
	// pipe2: relay → exit  (w2 → r2)
	r1, w1 := net.Pipe()
	r2, w2 := net.Pipe()
	defer r1.Close()
	defer w1.Close()
	defer r2.Close()
	defer w2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start relay's ForwardStream: reads from r1, writes to w2.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		relay.ForwardStream(ctx, "c1", r1, w2)
	}()

	// Write the original chunk to w1 (entry → relay).
	if err := WriteWireChunk(w1, origChunk); err != nil {
		t.Fatalf("WriteWireChunk failed: %v", err)
	}

	// Read the forwarded chunk from r2 (relay → exit).
	finalChunk, err := ReadWireChunk(r2)
	if err != nil {
		t.Fatalf("ReadWireChunk at exit failed: %v", err)
	}

	// The ciphertext should be UNTOUCHED through the relay.
	if !bytes.Equal(finalChunk.Ciphertext, origChunk.Ciphertext) {
		t.Error("ciphertext modified through relay — relay must be blind")
	}

	// The nonce should also be untouched.
	if !bytes.Equal(finalChunk.Nonce, origChunk.Nonce) {
		t.Error("nonce modified through relay")
	}

	// The header should be passed through unchanged.
	if !bytes.Equal(finalChunk.Header, origChunk.Header) {
		t.Error("header modified through relay — must pass through unchanged")
	}

	cancel()
	wg.Wait()
}

// TestRelayForwardStreamMultipleChunks verifies that multiple chunks
// can be forwarded sequentially through a relay without issues.
func TestRelayForwardStreamMultipleChunks(t *testing.T) {
	relayKey := make([]byte, KeySize)
	for i := range relayKey {
		relayKey[i] = byte(i + 1)
	}

	relay := NewRelay(RelayConfig{DisableJitter: true})
	relay.AddCircuit("multi", relayKey, nil)

	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	rOut, wOut := net.Pipe()
	defer rOut.Close()
	defer wOut.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go relay.ForwardStream(ctx, "multi", r, wOut)

	// Write 10 chunks.
	origChunks := make([]*WireChunk, 10)
	for i := 0; i < 10; i++ {
		header, _ := (&ForwardingHeader{NextHop: "10.10.0.1"}).Encode(relayKey)
		origChunks[i] = &WireChunk{
			Header:     header,
			Nonce:      make([]byte, NonceSize),
			Ciphertext: []byte("payload-" + string(rune('a'+i))),
		}
	}

	go func() {
		for _, wc := range origChunks {
			WriteWireChunk(w, wc)
		}
	}()

	// Read and verify 10 chunks.
	for i := 0; i < 10; i++ {
		received, err := ReadWireChunk(rOut)
		if err != nil {
			t.Fatalf("ReadWireChunk %d failed: %v", i, err)
		}
		if !bytes.Equal(received.Ciphertext, origChunks[i].Ciphertext) {
			t.Errorf("chunk %d ciphertext mismatch", i)
		}
	}
}

// TestRelayForwardStreamContextCancel verifies that cancelling the
// context properly stops the ForwardStream loop.
func TestRelayForwardStreamContextCancel(t *testing.T) {
	relayKey := make([]byte, KeySize)
	relay := NewRelay(RelayConfig{DisableJitter: true})
	relay.AddCircuit("cancel-test", relayKey, nil)

	// Use a pipe that we never write to, so the ForwardStream blocks
	// on ReadWireChunk. Cancelling the context should unblock it.
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	rOut, wOut := net.Pipe()
	defer rOut.Close()
	defer wOut.Close()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- relay.ForwardStream(ctx, "cancel-test", r, wOut)
	}()

	// Give it a moment to start reading.
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("ForwardStream did not stop after context cancel")
	}
}

// TestRelayForwardStreamEOF verifies that EOF on the inbound reader
// causes ForwardStream to return nil.
func TestRelayForwardStreamEOF(t *testing.T) {
	relayKey := make([]byte, KeySize)
	relay := NewRelay(RelayConfig{DisableJitter: true})
	relay.AddCircuit("eof-test", relayKey, nil)

	// Use a pipe — closing the write side will cause EOF on the read side.
	r, w := net.Pipe()
	rOut, wOut := net.Pipe()
	defer r.Close()
	defer rOut.Close()
	defer wOut.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- relay.ForwardStream(ctx, "eof-test", r, wOut)
	}()

	// Close the write side to trigger EOF.
	w.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error on EOF, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("ForwardStream did not return on EOF")
	}
}

// TestRelayForwardStreamUnregisteredCircuit verifies that forwarding
// for an unregistered circuit returns an error.
func TestRelayForwardStreamUnregisteredCircuit(t *testing.T) {
	relay := NewRelay(RelayConfig{DisableJitter: true})

	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	rOut, wOut := net.Pipe()
	defer rOut.Close()
	defer wOut.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := relay.ForwardStream(ctx, "nonexistent", r, wOut)
	if err == nil {
		t.Error("expected error for unregistered circuit")
	}
}

// --- End-to-end E2E encryption through relay chain ---

// TestRelayChainE2EDecrypt verifies that the end-to-end AEAD encryption
// survives relay forwarding: the entry encrypts with the E2E key, the relay
// forwards the ciphertext blindly, and the exit decrypts successfully.
// This is the critical security property: relays cannot read the payload.
//
// In v1, the forwarding header is single-layer encrypted (entry → relay).
// The relay decrypts it to learn next-hop, but passes the entire WireChunk
// through unchanged. The exit receives the same header bytes that the entry
// produced, so AEAD verification (which binds the header as associated data)
// succeeds.
func TestRelayChainE2EDecrypt(t *testing.T) {
	// Generate ECDH key pairs for entry and exit.
	entryKP, _ := GenerateECDHKeyPair()
	exitKP, _ := GenerateECDHKeyPair()

	e2eKey, _ := DeriveSharedKey(entryKP.Private, exitKP.Public)

	// Relay key (shared between entry and relay for header encryption).
	relayKey := make([]byte, KeySize)
	for i := range relayKey {
		relayKey[i] = byte(i + 1)
	}

	// Set up relay (single relay, last hop before exit).
	relay := NewRelay(RelayConfig{DisableJitter: true})
	relay.AddCircuit("e2e-test", relayKey, nil)

	// Create the original chunk.
	origChunk := Chunk{
		StreamID:   42,
		Sequence:   0,
		Total:      1,
		Type:       ChunkData,
		Payload:    []byte("secret message that relays must not see"),
		PaddingLen: 0,
	}

	// Entry encodes the chunk: E2E encrypts payload, header encrypted with relayKey.
	wc, err := EncodeChunk(origChunk, e2eKey, relayKey, "exit-addr")
	if err != nil {
		t.Fatalf("EncodeChunk failed: %v", err)
	}

	// Relay forwards the chunk blindly.
	_, forwarded, err := relay.ForwardChunk("e2e-test", wc)
	if err != nil {
		t.Fatalf("relay ForwardChunk failed: %v", err)
	}

	// Exit decrypts the E2E payload.
	decoded, err := DecodeChunk(forwarded, e2eKey)
	if err != nil {
		t.Fatalf("DecodeChunk at exit failed: %v", err)
	}

	// Verify the payload survived the relay forwarding intact.
	if decoded.StreamID != origChunk.StreamID {
		t.Errorf("StreamID = %d, want %d", decoded.StreamID, origChunk.StreamID)
	}
	if decoded.Sequence != origChunk.Sequence {
		t.Errorf("Sequence = %d, want %d", decoded.Sequence, origChunk.Sequence)
	}
	if !bytes.Equal(decoded.Payload, origChunk.Payload) {
		t.Errorf("Payload mismatch: got %q, want %q", decoded.Payload, origChunk.Payload)
	}
}

// TestRelayStatsWrapper verifies the stats wrapper.
func TestRelayStatsWrapper(t *testing.T) {
	relayKey := make([]byte, KeySize)
	for i := range relayKey {
		relayKey[i] = byte(i + 1)
	}

	sr, _ := NewRelayWithStats(RelayConfig{DisableJitter: true})
	sr.AddCircuit("stats-test", relayKey, nil)

	origHeader, _ := (&ForwardingHeader{NextHop: "10.10.0.1"}).Encode(relayKey)
	wc := &WireChunk{
		Header:     origHeader,
		Nonce:      make([]byte, NonceSize),
		Ciphertext: []byte("payload data here"),
	}

	for i := 0; i < 5; i++ {
		_, _, err := sr.ForwardChunkWithStats("stats-test", wc)
		if err != nil {
			t.Fatalf("ForwardChunkWithStats %d failed: %v", i, err)
		}
	}

	stats := sr.Stats()
	if stats.TotalForwarded != 5 {
		t.Errorf("TotalForwarded = %d, want 5", stats.TotalForwarded)
	}
	if stats.Circuits != 1 {
		t.Errorf("Circuits = %d, want 1", stats.Circuits)
	}
	// 5 chunks × len("payload data here") = 5 × 17 = 85
	if stats.TotalBytes != 85 {
		t.Errorf("TotalBytes = %d, want 85", stats.TotalBytes)
	}
}

// TestRandomJitterRange verifies that randomJitter produces values
// within the configured range.
func TestRandomJitterRange(t *testing.T) {
	r := NewRelay(RelayConfig{
		JitterMin: 5 * time.Millisecond,
		JitterMax: 10 * time.Millisecond,
	})

	for i := 0; i < 100; i++ {
		j := r.randomJitter()
		if j < 5*time.Millisecond {
			t.Errorf("jitter = %v, want >= %v", j, 5*time.Millisecond)
		}
		if j > 10*time.Millisecond {
			t.Errorf("jitter = %v, want <= %v", j, 10*time.Millisecond)
		}
	}
}

// TestRelayForwardChunkConcurrent verifies that concurrent forwarding
// on different circuits is safe.
func TestRelayForwardChunkConcurrent(t *testing.T) {
	relay := NewRelay(RelayConfig{DisableJitter: true})

	// Set up 10 circuits.
	for i := 0; i < 10; i++ {
		relayKey := make([]byte, KeySize)
		for j := range relayKey {
			relayKey[j] = byte(i*10 + j)
		}
		relay.AddCircuit(string(rune('a'+i)), relayKey, nil)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			circuitID := string(rune('a' + idx))
			relayKey := make([]byte, KeySize)
			for j := range relayKey {
				relayKey[j] = byte(idx*10 + j)
			}
			origHeader, _ := (&ForwardingHeader{NextHop: "10.10.0.1"}).Encode(relayKey)
			wc := &WireChunk{
				Header:     origHeader,
				Nonce:      make([]byte, NonceSize),
				Ciphertext: []byte("concurrent payload"),
			}
			for j := 0; j < 10; j++ {
				_, _, err := relay.ForwardChunk(circuitID, wc)
				if err != nil {
					t.Errorf("circuit %s chunk %d: %v", circuitID, j, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestWireChunkLargePayload verifies that a large payload (close to
// the max) serializes and deserializes correctly.
func TestWireChunkLargePayload(t *testing.T) {
	largePayload := make([]byte, MaxChunkPayloadSize)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	wc := &WireChunk{
		Header:     make([]byte, ForwardingHeaderSize),
		Nonce:      make([]byte, NonceSize),
		Ciphertext: largePayload,
	}

	data, err := SerializeWireChunk(wc)
	if err != nil {
		t.Fatalf("SerializeWireChunk failed: %v", err)
	}

	decoded, consumed, err := DeserializeWireChunk(data)
	if err != nil {
		t.Fatalf("DeserializeWireChunk failed: %v", err)
	}
	if consumed != len(data) {
		t.Errorf("consumed = %d, want %d", consumed, len(data))
	}
	if !bytes.Equal(decoded.Ciphertext, largePayload) {
		t.Error("large payload mismatch after round-trip")
	}
}

// TestRelayForwardStreamReadError verifies that a read error (not EOF)
// propagates correctly from ForwardStream.
func TestRelayForwardStreamReadError(t *testing.T) {
	relayKey := make([]byte, KeySize)
	relay := NewRelay(RelayConfig{DisableJitter: true})
	relay.AddCircuit("err-test", relayKey, nil)

	// Use a reader that always returns an error.
	errReader := &errorReader{err: io.ErrUnexpectedEOF}
	wOut := &bytes.Buffer{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := relay.ForwardStream(ctx, "err-test", errReader, wOut)
	if err == nil {
		t.Error("expected error from ForwardStream with error reader")
	}
}

// errorReader is a test helper that always returns an error on Read.
type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (int, error) {
	return 0, e.err
}
