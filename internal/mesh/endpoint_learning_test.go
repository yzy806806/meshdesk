package mesh

import (
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

// mockEndpointNotifier records all OnEndpointDiscovered calls for testing.
type mockEndpointNotifier struct {
	mu    sync.Mutex
	calls []endpointCall
}

type endpointCall struct {
	peerKey  string
	endpoint string
}

func (m *mockEndpointNotifier) OnEndpointDiscovered(peerKey, endpoint string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, endpointCall{peerKey, endpoint})
}

func (m *mockEndpointNotifier) getCalls() []endpointCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]endpointCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// TestEndpointNotifierNil tests that wrapReceiveFunc works correctly
// when no notifier is registered (default — endpoint learning disabled).
func TestEndpointNotifierNil(t *testing.T) {
	bind := NewObfuscatingBind(&capturingBind{})

	// No notifier set — should be nil.
	// Create a simple receive function that returns one packet.
	rawPacket := []byte("hello wireguard")
	recvFunc := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		copy(packets[0], rawPacket)
		sizes[0] = len(rawPacket)
		eps[0] = &testEndpoint{addr: "1.2.3.4:51820"}
		return 1, nil
	}

	wrapped := bind.wrapReceiveFunc(recvFunc)
	packets := make([][]byte, 1)
	packets[0] = make([]byte, 1500)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	n, err := wrapped(packets, sizes, eps)
	if err != nil {
		t.Fatalf("wrapped receive failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 packet, got %d", n)
	}
	// With no notifier, the packet should still be processed (deobfuscated
	// with none mode = pass-through).
	if sizes[0] != len(rawPacket) {
		t.Errorf("packet size mismatch: got %d, want %d", sizes[0], len(rawPacket))
	}
}

// TestEndpointNotifierFiresOnKnownEndpoint tests that the notifier is called
// when a packet arrives from a mapped endpoint (AC-9).
func TestEndpointNotifierFiresOnKnownEndpoint(t *testing.T) {
	bind := NewObfuscatingBind(&capturingBind{})

	// Register a known endpoint → peerKey mapping.
	peerKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	endpoint := "203.0.113.5:51820"
	bind.AddEndpointMapping(endpoint, peerKey)

	// Install the mock notifier.
	notifier := &mockEndpointNotifier{}
	bind.SetEndpointNotifier(notifier)

	// Create a receive function that returns a packet from the mapped endpoint.
	rawPacket := []byte("wireguard data packet")
	recvFunc := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		copy(packets[0], rawPacket)
		sizes[0] = len(rawPacket)
		eps[0] = &testEndpoint{addr: endpoint}
		return 1, nil
	}

	wrapped := bind.wrapReceiveFunc(recvFunc)
	packets := make([][]byte, 1)
	packets[0] = make([]byte, 1500)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	n, err := wrapped(packets, sizes, eps)
	if err != nil {
		t.Fatalf("wrapped receive failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 packet, got %d", n)
	}

	calls := notifier.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 notifier call, got %d", len(calls))
	}
	if calls[0].peerKey != peerKey {
		t.Errorf("notifier peerKey: got %s, want %s", calls[0].peerKey, peerKey)
	}
	if calls[0].endpoint != endpoint {
		t.Errorf("notifier endpoint: got %s, want %s", calls[0].endpoint, endpoint)
	}
}

// TestEndpointNotifierSkipsUnknownEndpoint tests that the notifier is NOT called
// when a packet arrives from an endpoint that is not in the reverse index.
func TestEndpointNotifierSkipsUnknownEndpoint(t *testing.T) {
	bind := NewObfuscatingBind(&capturingBind{})

	// Register a mapping for a known endpoint.
	bind.AddEndpointMapping("203.0.113.5:51820", "knownkey00000000000000000000000000000000000000000000000000000000")

	// Install the mock notifier.
	notifier := &mockEndpointNotifier{}
	bind.SetEndpointNotifier(notifier)

	// Packet arrives from an unknown endpoint.
	recvFunc := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		copy(packets[0], []byte("data"))
		sizes[0] = 4
		eps[0] = &testEndpoint{addr: "198.51.100.1:9999"} // not in the reverse index
		return 1, nil
	}

	wrapped := bind.wrapReceiveFunc(recvFunc)
	packets := make([][]byte, 1)
	packets[0] = make([]byte, 1500)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	n, _ := wrapped(packets, sizes, eps)
	if n != 1 {
		t.Fatalf("expected 1 packet, got %d", n)
	}

	calls := notifier.getCalls()
	if len(calls) != 0 {
		t.Errorf("notifier should not be called for unknown endpoint, got %d calls", len(calls))
	}
}

// TestEndpointNotifierIdempotent tests that multiple packets from the same
// endpoint each trigger a notification (dedup is the callee's responsibility).
func TestEndpointNotifierMultiplePackets(t *testing.T) {
	bind := NewObfuscatingBind(&capturingBind{})

	peerKey := "peerkey0000000000000000000000000000000000000000000000000000000"
	endpoint := "203.0.113.5:51820"
	bind.AddEndpointMapping(endpoint, peerKey)

	notifier := &mockEndpointNotifier{}
	bind.SetEndpointNotifier(notifier)

	// Simulate a batch of 3 packets from the same endpoint.
	recvFunc := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for i := 0; i < 3; i++ {
			copy(packets[i], []byte("data"))
			sizes[i] = 4
			eps[i] = &testEndpoint{addr: endpoint}
		}
		return 3, nil
	}

	wrapped := bind.wrapReceiveFunc(recvFunc)
	packets := make([][]byte, 3)
	for i := range packets {
		packets[i] = make([]byte, 1500)
	}
	sizes := make([]int, 3)
	eps := make([]conn.Endpoint, 3)

	n, _ := wrapped(packets, sizes, eps)
	if n != 3 {
		t.Fatalf("expected 3 packets, got %d", n)
	}

	calls := notifier.getCalls()
	if len(calls) != 3 {
		t.Errorf("expected 3 notifier calls (one per packet), got %d", len(calls))
	}
	for _, c := range calls {
		if c.peerKey != peerKey {
			t.Errorf("call peerKey: got %s, want %s", c.peerKey, peerKey)
		}
		if c.endpoint != endpoint {
			t.Errorf("call endpoint: got %s, want %s", c.endpoint, endpoint)
		}
	}
}

// TestAddEndpointMapping tests that AddEndpointMapping correctly populates
// the reverse index.
func TestAddEndpointMapping(t *testing.T) {
	bind := NewObfuscatingBind(&capturingBind{})

	// Initially the map should be nil (lazy init).
	bind.epMu.RLock()
	if bind.endpointToPeer != nil {
		bind.epMu.RUnlock()
		t.Fatal("endpointToPeer should be nil before first AddEndpointMapping")
	}
	bind.epMu.RUnlock()

	// Add a mapping.
	ep1 := "1.2.3.4:51820"
	key1 := "key1"
	bind.AddEndpointMapping(ep1, key1)

	bind.epMu.RLock()
	v, ok := bind.endpointToPeer[ep1]
	bind.epMu.RUnlock()
	if !ok || v != key1 {
		t.Errorf("mapping not found or wrong: got %s, want %s", v, key1)
	}

	// Add another mapping.
	ep2 := "5.6.7.8:51820"
	key2 := "key2"
	bind.AddEndpointMapping(ep2, key2)

	bind.epMu.RLock()
	if len(bind.endpointToPeer) != 2 {
		bind.epMu.RUnlock()
		t.Errorf("expected 2 mappings, got %d", len(bind.endpointToPeer))
	} else {
		bind.epMu.RUnlock()
	}
}

// TestSetEndpointNotifier tests that SetEndpointNotifier correctly sets
// and clears the notifier.
func TestSetEndpointNotifier(t *testing.T) {
	bind := NewObfuscatingBind(&capturingBind{})

	// Initially nil.
	bind.mu.RLock()
	if bind.notifier != nil {
		bind.mu.RUnlock()
		t.Fatal("notifier should be nil by default")
	}
	bind.mu.RUnlock()

	// Set a notifier.
	n := &mockEndpointNotifier{}
	bind.SetEndpointNotifier(n)

	bind.mu.RLock()
	if bind.notifier != n {
		bind.mu.RUnlock()
		t.Error("notifier not set correctly")
	} else {
		bind.mu.RUnlock()
	}

	// Clear by setting nil.
	bind.SetEndpointNotifier(nil)

	bind.mu.RLock()
	if bind.notifier != nil {
		bind.mu.RUnlock()
		t.Error("notifier should be nil after clearing")
	} else {
		bind.mu.RUnlock()
	}
}

// TestEndpointNotifierConcurrent tests thread safety of the notifier path.
// Runs under -race to detect data races.
func TestEndpointNotifierConcurrent(t *testing.T) {
	bind := NewObfuscatingBind(&capturingBind{})

	peerKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	endpoint := "203.0.113.5:51820"
	bind.AddEndpointMapping(endpoint, peerKey)

	notifier := &mockEndpointNotifier{}
	bind.SetEndpointNotifier(notifier)

	wrapped := bind.wrapReceiveFunc(func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		copy(packets[0], []byte("data"))
		sizes[0] = 4
		eps[0] = &testEndpoint{addr: endpoint}
		return 1, nil
	})

	// Run concurrent receives.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			packets := make([][]byte, 1)
			packets[0] = make([]byte, 1500)
			sizes := make([]int, 1)
			eps := make([]conn.Endpoint, 1)
			wrapped(packets, sizes, eps)
		}()
	}
	wg.Wait()

	calls := notifier.getCalls()
	if len(calls) != 50 {
		t.Errorf("expected 50 calls, got %d", len(calls))
	}
}
