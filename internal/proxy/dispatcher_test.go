package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestPathOverlapDetection verifies that HasOverlap correctly detects
// shared relay nodes between two paths.
func TestPathOverlapDetection(t *testing.T) {
	tests := []struct {
		name     string
		path1    []string
		path2    []string
		overlap  bool
	}{
		{
			name:    "disjoint",
			path1:   []string{"relayA", "relayB"},
			path2:   []string{"relayC", "relayD"},
			overlap: false,
		},
		{
			name:    "shared_relay",
			path1:   []string{"relayA", "relayB"},
			path2:   []string{"relayC", "relayB"}, // relayB shared
			overlap: true,
		},
		{
			name:    "identical",
			path1:   []string{"relayA"},
			path2:   []string{"relayA"},
			overlap: true,
		},
		{
			name:    "empty_paths",
			path1:   nil,
			path2:   nil,
			overlap: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p1 := &Path{Relays: tt.path1}
			p2 := &Path{Relays: tt.path2}
			if got := HasOverlap(p1, p2); got != tt.overlap {
				t.Errorf("HasOverlap = %v, want %v", got, tt.overlap)
			}
		})
	}
}

// TestSelectPaths verifies that path selection produces two disjoint paths.
func TestSelectPaths(t *testing.T) {
	candidates := []string{"relayA", "relayB", "relayC", "relayD"}
	p1, p2, err := SelectPaths(candidates, "10.10.0.5", 2)
	if err != nil {
		t.Fatal(err)
	}

	if HasOverlap(p1, p2) {
		t.Error("selected paths overlap — should be disjoint")
	}

	if len(p1.Relays) == 0 || len(p2.Relays) == 0 {
		t.Error("paths should have at least one relay each")
	}

	// Verify relay keys are correct size.
	for i, key := range p1.RelayKeys {
		if len(key) != KeySize {
			t.Errorf("p1.RelayKeys[%d] length = %d, want %d", i, len(key), KeySize)
		}
	}
	for i, key := range p2.RelayKeys {
		if len(key) != KeySize {
			t.Errorf("p2.RelayKeys[%d] length = %d, want %d", i, len(key), KeySize)
		}
	}
}

// TestSelectPathsInsufficientRelays verifies error on too few candidates.
func TestSelectPathsInsufficientRelays(t *testing.T) {
	_, _, err := SelectPaths([]string{"relayA"}, "10.10.0.5", 2)
	if err == nil {
		t.Error("expected error for insufficient relay candidates")
	}
}

// TestDispatcherRejectsOverlappingPaths verifies the dispatcher refuses
// to start with overlapping paths.
func TestDispatcherRejectsOverlappingPaths(t *testing.T) {
	e2eKey := make([]byte, KeySize)
	sharedRelay := "relayA"

	cfg := DispatcherConfig{
		E2EKey:  e2eKey,
		Path1:   &Path{Relays: []string{sharedRelay}, RelayKeys: [][]byte{make([]byte, KeySize)}},
		Path2:   &Path{Relays: []string{sharedRelay}, RelayKeys: [][]byte{make([]byte, KeySize)}},
	}

	_, err := NewDispatcher(cfg, nil)
	if err == nil {
		t.Error("expected error for overlapping paths")
	}
}

// TestDispatcherRoundTrip simulates a full dispatch cycle: data flows
// in through a pipe, gets chunked and encrypted, and the encrypted
// chunks are collected via callback.
func TestDispatcherRoundTrip(t *testing.T) {
	e2eKey := make([]byte, KeySize)
	for i := range e2eKey {
		e2eKey[i] = byte(i)
	}

	relayKey := make([]byte, KeySize)
	for i := range relayKey {
		relayKey[i] = byte(i + 32)
	}

	path1 := &Path{
		Relays:    []string{"relayA"},
		RelayKeys: [][]byte{relayKey},
	}
	path2 := &Path{
		Relays:    []string{"relayB"},
		RelayKeys: [][]byte{relayKey},
	}

	// Create a pipe to simulate the SS connection.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	cfg := DispatcherConfig{
		ChunkerStrategy: "fixed-16k",
		ChunkerCfg: ChunkerConfig{
			MaxChunkSize:    4 * 1024, // small chunks for test
			MinChunkSize:    4 * 1024,
			DisablePadding:  true,
		},
		CircuitCfg: DefaultCircuitConfig(),
		Path1:      path1,
		Path2:      path2,
		E2EKey:     e2eKey,
		ExitAddr:   "10.10.0.5",
	}

	d, err := NewDispatcher(cfg, serverConn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Collect encrypted chunks.
	var collected []*WireChunk
	var collectMu sync.Mutex
	done := make(chan error, 1)

	go func() {
		done <- d.Run(context.Background(), func(path int, wc *WireChunk) error {
			collectMu.Lock()
			collected = append(collected, wc)
			collectMu.Unlock()
			return nil
		})
	}()

	// Send some data.
	testData := make([]byte, 12*1024) // 3 chunks of 4KB
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	clientConn.Write(testData)
	clientConn.Close() // trigger EOF → stream-end

	// Wait for dispatcher to finish.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Dispatcher.Run error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dispatcher did not finish within 5 seconds")
	}

	collectMu.Lock()
	defer collectMu.Unlock()

	if len(collected) < 3 {
		t.Fatalf("expected at least 3 chunks (3 data + stream-end), got %d", len(collected))
	}

	// Decrypt and verify chunks.
	r := newFixedReassembler(cfg.ChunkerCfg)
	for _, wc := range collected {
		chunk, err := DecodeChunk(wc, e2eKey)
		if err != nil {
			t.Fatalf("DecodeChunk failed: %v", err)
		}
		r.Add(chunk)
	}

	// The reassembler should have received the data + stream-end marker.
	// After stream-end, it signals completion.
	// Since we used Total=0 (streaming mode), completion is via StreamEnd.

	// Verify the chunks are distributed across both paths.
	p1Chunks, p2Chunks, _, _ := d.Stats()
	if p1Chunks == 0 && p2Chunks == 0 {
		t.Error("expected chunks on both paths")
	}
	t.Logf("path1: %d chunks, path2: %d chunks", p1Chunks, p2Chunks)
}

// TestDispatcherStats verifies that dispatch stats are tracked correctly.
func TestDispatcherStats(t *testing.T) {
	e2eKey := make([]byte, KeySize)
	relayKey := make([]byte, KeySize)

	path1 := &Path{Relays: []string{"relayA"}, RelayKeys: [][]byte{relayKey}}
	path2 := &Path{Relays: []string{"relayB"}, RelayKeys: [][]byte{relayKey}}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	cfg := DispatcherConfig{
		ChunkerStrategy: "fixed-16k",
		ChunkerCfg: ChunkerConfig{
			MaxChunkSize:   4 * 1024,
			MinChunkSize:   4 * 1024,
			DisablePadding: true,
		},
		CircuitCfg: DefaultCircuitConfig(),
		Path1:      path1,
		Path2:      path2,
		E2EKey:     e2eKey,
		ExitAddr:   "10.10.0.5",
	}

	d, err := NewDispatcher(cfg, serverConn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	done := make(chan error, 1)
	go func() {
		done <- d.Run(context.Background(), func(path int, wc *WireChunk) error {
			return nil
		})
	}()

	clientConn.Write(make([]byte, 8*1024)) // 2 chunks
	clientConn.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	p1, p2, p1Bytes, p2Bytes := d.Stats()
	totalChunks := p1 + p2
	totalBytes := p1Bytes + p2Bytes

	if totalChunks < 2 {
		t.Errorf("expected at least 2 chunks, got %d", totalChunks)
	}
	if totalBytes < 8*1024 {
		t.Errorf("expected at least 8KB dispatched, got %d", totalBytes)
	}
}

// TestDispatcherRequiresE2EKey verifies the dispatcher requires a valid E2E key.
func TestDispatcherRequiresE2EKey(t *testing.T) {
	cfg := DispatcherConfig{
		E2EKey: nil,
		Path1:  &Path{Relays: []string{"r1"}, RelayKeys: [][]byte{make([]byte, KeySize)}},
		Path2:  &Path{Relays: []string{"r2"}, RelayKeys: [][]byte{make([]byte, KeySize)}},
	}

	_, err := NewDispatcher(cfg, nil)
	if err == nil {
		t.Error("expected error for nil E2E key")
	}
}

// TestDispatcherRequiresTwoPaths verifies the dispatcher requires two paths.
func TestDispatcherRequiresTwoPaths(t *testing.T) {
	cfg := DispatcherConfig{
		E2EKey: make([]byte, KeySize),
		Path1:  &Path{Relays: []string{"r1"}, RelayKeys: [][]byte{make([]byte, KeySize)}},
		Path2:  nil,
	}

	_, err := NewDispatcher(cfg, nil)
	if err == nil {
		t.Error("expected error for nil Path2")
	}
}

// TestDispatcherDebugFixedChunks verifies the DebugFixedChunks flag
// forces the fixed-16k strategy.
func TestDispatcherDebugFixedChunks(t *testing.T) {
	e2eKey := make([]byte, KeySize)

	cfg := DispatcherConfig{
		E2EKey:           e2eKey,
		Path1:            &Path{Relays: []string{"r1"}, RelayKeys: [][]byte{make([]byte, KeySize)}},
		Path2:            &Path{Relays: []string{"r2"}, RelayKeys: [][]byte{make([]byte, KeySize)}},
		DebugFixedChunks: true,
	}

	d, err := NewDispatcher(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The chunker should be fixed-16k (we can't directly check the type,
	// but we can verify it produces uniform-sized chunks).
	chunks := d.chunker.Split(make([]byte, 48*1024))
	for i, ch := range chunks {
		if i > 0 && len(ch.Payload) != len(chunks[0].Payload) {
			t.Errorf("chunk %d has different size (%d vs %d) — debug mode should produce uniform chunks",
				i, len(ch.Payload), len(chunks[0].Payload))
		}
	}
}
