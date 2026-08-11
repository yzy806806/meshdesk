package mesh

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
)

// TestMuxTransport_MemberlistIntegration verifies that two memberlist
// instances using MuxTransport can discover each other and complete
// push/pull sync.
func TestMuxTransport_MemberlistIntegration(t *testing.T) {
	// Create two MuxTransport nodes on different ports
	node1 := createMuxMemberlistNode(t, 0) // port 0 = auto-assign
	node2 := createMuxMemberlistNode(t, 0)

	defer node1.ml.Shutdown()
	defer node2.ml.Shutdown()
	defer node1.mt.Shutdown()
	defer node2.mt.Shutdown()

	// Get the actual addresses
	ip1, port1, _ := node1.mt.FinalAdvertiseAddr("", 0)
	ip2, port2, _ := node2.mt.FinalAdvertiseAddr("", 0)

	t.Logf("Node1: %s:%d", ip1, port1)
	t.Logf("Node2: %s:%d", ip2, port2)

	// Node2 joins Node1
	_, err := node2.ml.Join([]string{fmt.Sprintf("127.0.0.1:%d", port1)})
	if err != nil {
		t.Fatalf("node2 join node1: %v", err)
	}

	// Wait for membership convergence
	time.Sleep(3 * time.Second)

	// Check membership
	members1 := node1.ml.Members()
	members2 := node2.ml.Members()

	t.Logf("Node1 members: %d", len(members1))
	t.Logf("Node2 members: %d", len(members2))

	if len(members1) < 2 {
		t.Fatalf("Node1 should have at least 2 members, got %d", len(members1))
	}
	if len(members2) < 2 {
		t.Fatalf("Node2 should have at least 2 members, got %d", len(members2))
	}

	t.Logf("SUCCESS: Both nodes see each other in memberlist!")
}

type muxMemberlistNode struct {
	mt *MuxTransport
	ml *memberlist.Memberlist
}

func createMuxMemberlistNode(t *testing.T, port int) *muxMemberlistNode {
	t.Helper()

	// Create TCP listener on a random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	actualPort := ln.Addr().(*net.TCPAddr).Port

	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: ln,
		BindAddr:    "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("NewMuxTransport: %v", err)
	}

	cfg := memberlist.DefaultLocalConfig()
	cfg.Name = fmt.Sprintf("node-%d", actualPort)
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = actualPort
	cfg.AdvertiseAddr = "127.0.0.1"
	cfg.AdvertisePort = actualPort
	cfg.Transport = mt
	cfg.TCPTimeout = 5 * time.Second
	cfg.ProbeInterval = 1 * time.Second
	cfg.ProbeTimeout = 200 * time.Millisecond
	cfg.PushPullInterval = 1 * time.Second

	ml, err := memberlist.Create(cfg)
	if err != nil {
		mt.Shutdown()
		t.Fatalf("memberlist.Create: %v", err)
	}

	return &muxMemberlistNode{mt: mt, ml: ml}
}
