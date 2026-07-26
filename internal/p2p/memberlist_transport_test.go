package p2p

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// mockMeshNode is a test-only implementation of meshNodeIface.
type mockMeshNode struct {
	mu sync.Mutex

	// dialFunc controls what Dial returns. If nil, returns errMockDialFail.
	dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

	// waitFunc controls what WaitForPeerHandshake returns. If nil, returns nil (immediate success).
	waitFunc func(ctx context.Context, pubKey string, poll, stale time.Duration) error

	// routes is the routing table for this mock node.
	routes *mesh.RoutingTable

	// dialCount tracks how many times Dial was called.
	dialCount int32

	// waitCount tracks how many times WaitForPeerHandshake was called.
	waitCount int32
}

var errMockDialFail = errors.New("mock dial failure")

func newMockMeshNode() *mockMeshNode {
	return &mockMeshNode{
		routes: mesh.NewRoutingTable(),
	}
}

func (m *mockMeshNode) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	atomic.AddInt32(&m.dialCount, 1)
	m.mu.Lock()
	fn := m.dialFunc
	m.mu.Unlock()
	if fn != nil {
		return fn(ctx, network, addr)
	}
	return nil, errMockDialFail
}

func (m *mockMeshNode) WaitForPeerHandshake(ctx context.Context, pubKey string, poll, stale time.Duration) error {
	atomic.AddInt32(&m.waitCount, 1)
	m.mu.Lock()
	fn := m.waitFunc
	m.mu.Unlock()
	if fn != nil {
		return fn(ctx, pubKey, poll, stale)
	}
	return nil // immediate success by default
}

func (m *mockMeshNode) RoutingTable() *mesh.RoutingTable {
	return m.routes
}

func (m *mockMeshNode) Net() *netstack.Net {
	return nil // not needed for DialTimeout tests
}

func (m *mockMeshNode) getDialCount() int32 { return atomic.LoadInt32(&m.dialCount) }
func (m *mockMeshNode) getWaitCount() int32 { return atomic.LoadInt32(&m.waitCount) }
func (m *mockMeshNode) setDialFunc(fn func(context.Context, string, string) (net.Conn, error)) {
	m.mu.Lock()
	m.dialFunc = fn
	m.mu.Unlock()
}
func (m *mockMeshNode) setWaitFunc(fn func(context.Context, string, time.Duration, time.Duration) error) {
	m.mu.Lock()
	m.waitFunc = fn
	m.mu.Unlock()
}

// --- Tests ---

// TestDialTimeout_NonMeshAddress verifies that for addresses not in the
// routing table, the handshake wait is skipped and Dial is called directly.
func TestDialTimeout_NonMeshAddress(t *testing.T) {
	node := newMockMeshNode()
	transport := &MeshTransport{
		node:       node,
		meshIP:     "10.10.1.1",
		gossipPort: 7946,
		packetCh:   make(chan *memberlist.Packet, 64),
		streamCh:   make(chan net.Conn, 16),
	}

	// Set dial to succeed.
	node.setDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &net.TCPConn{}, nil
	})

	conn, err := transport.DialTimeout("8.8.8.8:53", 5*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}
	if node.getWaitCount() != 0 {
		t.Errorf("expected 0 handshake waits, got %d", node.getWaitCount())
	}
	if node.getDialCount() != 1 {
		t.Errorf("expected 1 dial, got %d", node.getDialCount())
	}
}

// TestDialTimeout_MeshAddress_WaitsForHandshake verifies that for a known
// mesh peer, the transport waits for the handshake before dialing.
func TestDialTimeout_MeshAddress_WaitsForHandshake(t *testing.T) {
	node := newMockMeshNode()
	pubKey := "aabb0000000000000000000000000000000000000000000000000000000000cc"
	node.RoutingTable().AddPeer(&mesh.PeerEntry{
		ID:         pubKey,
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.10.5.5/32"},
	})

	waitCalled := make(chan struct{})
	node.setWaitFunc(func(ctx context.Context, pk string, poll, stale time.Duration) error {
		close(waitCalled)
		return nil
	})

	node.setDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &net.TCPConn{}, nil
	})

	transport := &MeshTransport{
		node:       node,
		meshIP:     "10.10.1.1",
		gossipPort: 7946,
		packetCh:   make(chan *memberlist.Packet, 64),
		streamCh:   make(chan net.Conn, 16),
	}

	conn, err := transport.DialTimeout("10.10.5.5:7946", 5*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}

	select {
	case <-waitCalled:
		// good
	case <-time.After(time.Second):
		t.Fatal("WaitForPeerHandshake was not called")
	}

	if node.getDialCount() != 1 {
		t.Errorf("expected 1 dial, got %d", node.getDialCount())
	}
}

// TestDialTimeout_HandshakeWaitFails verifies that if the handshake wait
// fails (context cancelled), DialTimeout returns an error without dialing.
func TestDialTimeout_HandshakeWaitFails(t *testing.T) {
	node := newMockMeshNode()
	pubKey := "aabb0000000000000000000000000000000000000000000000000000000000cc"
	node.RoutingTable().AddPeer(&mesh.PeerEntry{
		ID:         pubKey,
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.10.5.5/32"},
	})

	node.setWaitFunc(func(ctx context.Context, pk string, poll, stale time.Duration) error {
		<-ctx.Done()
		return ctx.Err()
	})

	transport := &MeshTransport{
		node:       node,
		meshIP:     "10.10.1.1",
		gossipPort: 7946,
		packetCh:   make(chan *memberlist.Packet, 64),
		streamCh:   make(chan net.Conn, 16),
	}

	_, err := transport.DialTimeout("10.10.5.5:7946", 300*time.Millisecond)
	if err == nil {
		t.Fatal("expected error from handshake wait failure")
	}
	if node.getDialCount() != 0 {
		t.Errorf("expected 0 dials, got %d", node.getDialCount())
	}
}

// TestDialTimeout_RetryWithBackoff verifies that DialTimeout retries the
// TCP dial up to 3 times when it fails, and eventually succeeds.
func TestDialTimeout_RetryWithBackoff(t *testing.T) {
	node := newMockMeshNode()

	var attempts atomic.Int32
	node.setDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		n := attempts.Add(1)
		if n < 3 {
			return nil, errMockDialFail
		}
		return &net.TCPConn{}, nil
	})

	transport := &MeshTransport{
		node:       node,
		meshIP:     "10.10.1.1",
		gossipPort: 7946,
		packetCh:   make(chan *memberlist.Packet, 64),
		streamCh:   make(chan net.Conn, 16),
	}

	conn, err := transport.DialTimeout("8.8.8.8:53", 10*time.Second)
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}
	if node.getDialCount() != 3 {
		t.Errorf("expected 3 dial attempts, got %d", node.getDialCount())
	}
}

// TestDialTimeout_RetryExhausted verifies that DialTimeout returns the
// last error after all 3 retry attempts fail.
func TestDialTimeout_RetryExhausted(t *testing.T) {
	node := newMockMeshNode()
	testErr := errors.New("connection refused")

	node.setDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, testErr
	})

	transport := &MeshTransport{
		node:       node,
		meshIP:     "10.10.1.1",
		gossipPort: 7946,
		packetCh:   make(chan *memberlist.Packet, 64),
		streamCh:   make(chan net.Conn, 16),
	}

	_, err := transport.DialTimeout("8.8.8.8:53", 2*time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, testErr) {
		t.Errorf("expected error %v, got %v", testErr, err)
	}
	if node.getDialCount() != 3 {
		t.Errorf("expected 3 dial attempts, got %d", node.getDialCount())
	}
}

// TestDialTimeout_MalformedAddress verifies that a malformed address
// (no host:port) skips the handshake wait and proceeds to dial.
func TestDialTimeout_MalformedAddress(t *testing.T) {
	node := newMockMeshNode()

	node.setDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &net.TCPConn{}, nil
	})

	transport := &MeshTransport{
		node:       node,
		meshIP:     "10.10.1.1",
		gossipPort: 7946,
		packetCh:   make(chan *memberlist.Packet, 64),
		streamCh:   make(chan net.Conn, 16),
	}

	conn, err := transport.DialTimeout("not-a-valid-addr", 5*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}
	if node.getWaitCount() != 0 {
		t.Errorf("expected 0 handshake waits, got %d", node.getWaitCount())
	}
}

// TestDialTimeout_AlreadyHandshaked verifies that if the handshake is
// already complete (WaitForPeerHandshake returns nil immediately), the
// dial proceeds without delay.
func TestDialTimeout_AlreadyHandshaked(t *testing.T) {
	node := newMockMeshNode()
	pubKey := "aabb0000000000000000000000000000000000000000000000000000000000cc"
	node.RoutingTable().AddPeer(&mesh.PeerEntry{
		ID:         pubKey,
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.10.5.5/32"},
	})

	// WaitForPeerHandshake returns nil immediately (default behavior).
	node.setDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &net.TCPConn{}, nil
	})

	transport := &MeshTransport{
		node:       node,
		meshIP:     "10.10.1.1",
		gossipPort: 7946,
		packetCh:   make(chan *memberlist.Packet, 64),
		streamCh:   make(chan net.Conn, 16),
	}

	start := time.Now()
	conn, err := transport.DialTimeout("10.10.5.5:7946", 5*time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("DialTimeout failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("expected fast completion, took %v", elapsed)
	}
	if node.getWaitCount() != 1 {
		t.Errorf("expected 1 wait call, got %d", node.getWaitCount())
	}
}

// TestDialTimeout_MeshIPWithoutCIDR verifies that the handshake wait
// works when the routing table has a CIDR (10.10.5.5/32) but the dial
// address uses a bare IP (10.10.5.5:7946).
func TestDialTimeout_MeshIPWithoutCIDR(t *testing.T) {
	node := newMockMeshNode()
	pubKey := "ccdd0000000000000000000000000000000000000000000000000000000000ee"
	// Note: routing table stores "10.10.5.5/32" but addr uses "10.10.5.5".
	node.RoutingTable().AddPeer(&mesh.PeerEntry{
		ID:         pubKey,
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.10.5.5/32"},
	})

	waitCalled := false
	node.setWaitFunc(func(ctx context.Context, pk string, poll, stale time.Duration) error {
		waitCalled = true
		return nil
	})

	node.setDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &net.TCPConn{}, nil
	})

	transport := &MeshTransport{
		node:       node,
		meshIP:     "10.10.1.1",
		gossipPort: 7946,
		packetCh:   make(chan *memberlist.Packet, 64),
		streamCh:   make(chan net.Conn, 16),
	}

	_, err := transport.DialTimeout("10.10.5.5:7946", 5*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout failed: %v", err)
	}
	if !waitCalled {
		t.Error("WaitForPeerHandshake was not called for mesh IP with CIDR in routing table")
	}
}
