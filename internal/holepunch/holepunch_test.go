package holepunch

import (
	"context"
	"net"
	"testing"
	"time"
)

// pipeDialer implements Dialer over in-memory pipes. Each peer has an
// inbound channel; DialVirtualPort creates a net.Pipe and delivers one
// end to the target's inbound channel.
type pipeDialer struct {
	in chan net.Conn
}

func (d *pipeDialer) DialVirtualPort(ctx context.Context, peerKey string, port int) (net.Conn, error) {
	c1, c2 := net.Pipe()
	select {
	case d.in <- c1:
		return c2, nil
	case <-ctx.Done():
		c1.Close()
		c2.Close()
		return nil, ctx.Err()
	}
}

// TestEngineLifecycle verifies trigger → punch → established with two
// engines over in-memory pipes (no NAT — holes must open directly).
func TestEngineLifecycle(t *testing.T) {
	// A dials B; B serves A's coordination streams.
	bIn := make(chan net.Conn, 8)
	aIn := make(chan net.Conn, 8)

	a := New(&pipeDialer{in: bIn})
	b := New(&pipeDialer{in: aIn})

	// Serve inbound coordination streams on both sides.
	go func() {
		for conn := range bIn {
			go b.HandleCoordinatorStream(conn)
		}
	}()
	go func() {
		for conn := range aIn {
			go a.HandleCoordinatorStream(conn)
		}
	}()

	a.SetLocalInfo("127.0.0.1:19001", NatPortRestricted)
	b.SetLocalInfo("127.0.0.1:19002", NatPortRestricted)

	established := make(chan string, 1)
	a.OnHoleEstablished = func(peerKey, ep, holeType string) {
		established <- ep
	}

	a.Trigger("B", []string{"127.0.0.1:19002"}, NatPortRestricted)

	select {
	case ep := <-established:
		if ep == "" {
			t.Fatal("empty punched endpoint")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("hole not established within timeout")
	}
}

// TestTriggerIdempotent verifies repeated triggers don't double-punch
// while a session is already established.
func TestTriggerIdempotent(t *testing.T) {
	a := New(&pipeDialer{})
	a.SetLocalInfo("127.0.0.1:19001", NatPortRestricted)
	a.Trigger("X", []string{"127.0.0.1:19002"}, NatPortRestricted)
	a.Trigger("X", []string{"127.0.0.1:19002"}, NatPortRestricted)

	a.mu.Lock()
	s := a.sessions["X"]
	a.mu.Unlock()
	if s == nil {
		t.Fatal("session not created")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", s.attempts)
	}
}

// TestDiscoverLocal verifies STUN discovery works against a real
// server (or fails gracefully when offline).
func TestDiscoverLocal(t *testing.T) {
	res, err := Discover(4 * time.Second)
	if err != nil {
		t.Logf("STUN unavailable (offline?): %v", err)
		return // acceptable in restricted CI
	}
	if res.MappedEP == "" {
		t.Fatal("empty mapped endpoint from STUN")
	}
	t.Logf("mapped=%s nat=%v", res.MappedEP, res.NatType)
}
