package tun

import (
	"net"
	"sync"
	"testing"
)

// mockCmdRunner records all executed `ip route` commands for verification.
type mockCmdRunner struct {
	mu       sync.Mutex
	commands [][]string
	failOn   map[string]bool // "add:cidr" or "del:cidr" → fail
}

func newMockCmdRunner() *mockCmdRunner {
	return &mockCmdRunner{
		failOn: make(map[string]bool),
	}
}

func (m *mockCmdRunner) run(args ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cmdCopy := make([]string, len(args))
	copy(cmdCopy, args)
	m.commands = append(m.commands, cmdCopy)

	// Check if this command should fail.
	cidr := args[2]   // "route add <cidr> ..." or "route del <cidr ..."
	action := args[1] // "add" or "del"
	key := action + ":" + cidr
	if m.failOn[key] {
		return errMock
	}
	return nil
}

func (m *mockCmdRunner) getCommands() [][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([][]string, len(m.commands))
	copy(result, m.commands)
	return result
}

func (m *mockCmdRunner) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commands = nil
}

var errMock = errMockType{}

func (e errMockType) Error() string { return "mock error" }

type errMockType struct{}

// ─── RouteManager tests ───

func TestRouteManager_AddPeerSubnets(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{"192.168.1.0/24"})

	cmds := mock.getCommands()
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	// Should be: route add 192.168.1.0/24 via 10.10.0.5 dev mesh0
	if cmds[0][1] != "add" || cmds[0][2] != "192.168.1.0/24" || cmds[0][4] != "10.10.0.5" || cmds[0][6] != "mesh0" {
		t.Fatalf("unexpected command: %v", cmds[0])
	}

	if rm.RouteCount() != 1 {
		t.Fatalf("RouteCount = %d, want 1", rm.RouteCount())
	}
}

func TestRouteManager_AddMultipleSubnets(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
	})

	cmds := mock.getCommands()
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
	if rm.RouteCount() != 2 {
		t.Fatalf("RouteCount = %d, want 2", rm.RouteCount())
	}
}

func TestRouteManager_RemovePeerSubnets(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{"192.168.1.0/24"})
	mock.reset()

	rm.RemovePeerSubnets("pubkeyAAA")

	cmds := mock.getCommands()
	if len(cmds) != 1 {
		t.Fatalf("expected 1 del command, got %d", len(cmds))
	}
	if cmds[0][1] != "del" || cmds[0][2] != "192.168.1.0/24" || cmds[0][4] != "mesh0" {
		t.Fatalf("unexpected del command: %v", cmds[0])
	}
	if rm.RouteCount() != 0 {
		t.Fatalf("RouteCount = %d, want 0", rm.RouteCount())
	}
}

func TestRouteManager_RemoveNonexistentPeer(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	// Should be a no-op.
	rm.RemovePeerSubnets("unknown")
	if rm.RouteCount() != 0 {
		t.Fatalf("RouteCount = %d, want 0", rm.RouteCount())
	}
	if len(mock.getCommands()) != 0 {
		t.Fatalf("expected no commands for unknown peer")
	}
}

func TestRouteManager_UpdatePeerSubnets(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	// Add initial subnets.
	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
	})
	mock.reset()

	// Update: remove 10.0.0.0/8, add 172.16.0.0/12.
	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{
		"192.168.1.0/24",
		"172.16.0.0/12",
	})

	cmds := mock.getCommands()
	// Should have 1 add (172.16.0.0/12) and 1 del (10.0.0.0/8).
	adds := 0
	dels := 0
	for _, cmd := range cmds {
		if cmd[1] == "add" {
			adds++
		}
		if cmd[1] == "del" {
			dels++
		}
	}
	if adds != 1 || dels != 1 {
		t.Fatalf("expected 1 add + 1 del, got %d adds + %d dels", adds, dels)
	}
	if rm.RouteCount() != 2 {
		t.Fatalf("RouteCount = %d, want 2", rm.RouteCount())
	}
}

func TestRouteManager_InvalidCIDR(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{"not-a-cidr"})

	if rm.RouteCount() != 0 {
		t.Fatalf("RouteCount = %d, want 0 (invalid CIDR should be ignored)", rm.RouteCount())
	}
	if len(mock.getCommands()) != 0 {
		t.Fatalf("expected no commands for invalid CIDR")
	}
}

func TestRouteManager_ResolveSubnetProxy(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{"192.168.1.0/24"})
	rm.AddPeerSubnets("pubkeyBBB", "10.10.0.6", []string{"10.0.0.0/8"})

	// 192.168.1.100 should route via 10.10.0.5.
	gw, ok := rm.ResolveSubnetProxy(net.ParseIP("192.168.1.100"))
	if !ok {
		t.Fatal("expected to resolve 192.168.1.100")
	}
	if gw != "10.10.0.5" {
		t.Fatalf("gateway = %s, want 10.10.0.5", gw)
	}

	// 10.0.0.1 should route via 10.10.0.6.
	gw, ok = rm.ResolveSubnetProxy(net.ParseIP("10.0.0.1"))
	if !ok {
		t.Fatal("expected to resolve 10.0.0.1")
	}
	if gw != "10.10.0.6" {
		t.Fatalf("gateway = %s, want 10.10.0.6", gw)
	}

	// 8.8.8.8 should not match any subnet.
	_, ok = rm.ResolveSubnetProxy(net.ParseIP("8.8.8.8"))
	if ok {
		t.Fatal("should not resolve 8.8.8.8")
	}
}

func TestRouteManager_LongestPrefixMatch(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	// Two overlapping subnets — 10.0.0.0/8 and 10.1.0.0/16.
	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{"10.0.0.0/8"})
	rm.AddPeerSubnets("pubkeyBBB", "10.10.0.6", []string{"10.1.0.0/16"})

	// 10.1.2.3 should match the more specific /16, not the /8.
	gw, ok := rm.ResolveSubnetProxy(net.ParseIP("10.1.2.3"))
	if !ok {
		t.Fatal("expected to resolve 10.1.2.3")
	}
	if gw != "10.10.0.6" {
		t.Fatalf("gateway = %s, want 10.10.0.6 (longest prefix match)", gw)
	}

	// 10.2.3.4 should match the /8 only.
	gw, ok = rm.ResolveSubnetProxy(net.ParseIP("10.2.3.4"))
	if !ok {
		t.Fatal("expected to resolve 10.2.3.4")
	}
	if gw != "10.10.0.5" {
		t.Fatalf("gateway = %s, want 10.10.0.5", gw)
	}
}

func TestRouteManager_SubnetReassignment(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	// Peer A claims 192.168.1.0/24.
	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{"192.168.1.0/24"})
	mock.reset()

	// Peer B claims the same subnet — should reassign.
	rm.AddPeerSubnets("pubkeyBBB", "10.10.0.6", []string{"192.168.1.0/24"})

	cmds := mock.getCommands()
	// Should have 1 del (old route) + 1 add (new route).
	dels := 0
	adds := 0
	for _, cmd := range cmds {
		if cmd[1] == "del" {
			dels++
		}
		if cmd[1] == "add" {
			adds++
		}
	}
	if dels != 1 {
		t.Fatalf("expected 1 del, got %d", dels)
	}
	if adds != 1 {
		t.Fatalf("expected 1 add, got %d", adds)
	}

	// The subnet should now route via 10.10.0.6.
	gw, ok := rm.ResolveSubnetProxy(net.ParseIP("192.168.1.100"))
	if !ok {
		t.Fatal("expected to resolve 192.168.1.100")
	}
	if gw != "10.10.0.6" {
		t.Fatalf("gateway = %s, want 10.10.0.6 (reassigned)", gw)
	}
}

func TestRouteManager_AllSubnetProxies(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{"192.168.1.0/24", "10.0.0.0/8"})

	all := rm.AllSubnetProxies()
	if len(all) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(all))
	}
	if all["192.168.1.0/24"] != "10.10.0.5" {
		t.Fatalf("192.168.1.0/24 → %s, want 10.10.0.5", all["192.168.1.0/24"])
	}
	if all["10.0.0.0/8"] != "10.10.0.5" {
		t.Fatalf("10.0.0.0/8 → %s, want 10.10.0.5", all["10.0.0.0/8"])
	}
}

func TestRouteManager_NoOpUpdate(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	// Add subnets.
	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{"192.168.1.0/24"})
	mock.reset()

	// Update with the same subnets — should be a no-op.
	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{"192.168.1.0/24"})

	if len(mock.getCommands()) != 0 {
		t.Fatalf("expected 0 commands for no-op update, got %d", len(mock.getCommands()))
	}
}

func TestRouteManager_KernelRouteErrorNonFatal(t *testing.T) {
	mock := newMockCmdRunner()
	rm := NewRouteManager("mesh0")
	rm.cmdRunner = mock.run

	// Make `ip route add` fail for this CIDR.
	mock.failOn["add:192.168.1.0/24"] = true

	// Should not panic or return an error — route add errors are logged.
	rm.AddPeerSubnets("pubkeyAAA", "10.10.0.5", []string{"192.168.1.0/24"})

	// The route should still be tracked in the in-memory map
	// (we don't roll back on kernel error — the route may already exist).
	if rm.RouteCount() != 1 {
		t.Fatalf("RouteCount = %d, want 1 (in-memory tracking should succeed)", rm.RouteCount())
	}
}
