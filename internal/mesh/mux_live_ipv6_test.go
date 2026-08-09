package mesh

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
)

// TestMuxTransport_JoinIPv6Peer_Live is a live-network test that joins
// a real IPv6 peer (N1) using MuxTransport as the memberlist transport.
// It reproduces the production failure: meshdesk's MuxTransport memberlist
// join to an IPv6 peer times out while a pure NetTransport join succeeds.
//
// Run: go test ./internal/mesh/ -run TestMuxTransport_JoinIPv6Peer_Live -v
// Requires N1 meshdesk running at [2001:db8::1]:52888
func TestMuxTransport_JoinIPv6Peer_Live(t *testing.T) {
	addr := "[2001:db8::1]:52888"

	// Build MuxTransport client (production BindAddr: 0.0.0.0 → dual-stack).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port
	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener:   ln,
		BindAddr:      "0.0.0.0",
		AdvertiseAddr: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("NewMuxTransport: %v", err)
	}
	defer mt.Shutdown()

	cfg := memberlist.DefaultLocalConfig()
	cfg.Name = fmt.Sprintf("mux-live-%d", actualPort)
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = actualPort
	cfg.AdvertiseAddr = "127.0.0.1"
	cfg.AdvertisePort = actualPort
	cfg.Transport = mt
	cfg.TCPTimeout = 5 * time.Second
	cfg.ProbeInterval = 2 * time.Second
	cfg.ProbeTimeout = 1 * time.Second
	cfg.PushPullInterval = 2 * time.Second

	ml, err := memberlist.Create(cfg)
	if err != nil {
		t.Fatalf("memberlist.Create: %v", err)
	}
	defer ml.Shutdown()

	t.Logf("joining %s via MuxTransport...", addr)
	n, err := ml.Join([]string{addr})
	if err != nil {
		t.Fatalf("MuxTransport join failed (NetTransport works): %v", err)
	}
	t.Logf("join OK, nodes contacted: %d", n)

	time.Sleep(5 * time.Second)
	for _, m := range ml.Members() {
		t.Logf("member %s@%s:%d meta_len=%d", m.Name, m.Addr, m.Port, len(m.Meta))
	}
}
