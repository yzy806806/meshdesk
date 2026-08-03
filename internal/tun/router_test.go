package tun

import (
	"net"
	"strings"
	"testing"
)

func TestRouter_AddAndResolve(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	ip1 := net.ParseIP("10.10.0.5")
	ip2 := net.ParseIP("10.10.0.6")

	r.AddRoute(ip1, "peerA")
	r.AddRoute(ip2, "peerB")

	// Forward lookup.
	key, ok := r.ResolveIP(ip1)
	if !ok || key != "peerA" {
		t.Fatalf("ResolveIP(%s) = %s, %v; want peerA, true", ip1, key, ok)
	}

	key, ok = r.ResolveIP(ip2)
	if !ok || key != "peerB" {
		t.Fatalf("ResolveIP(%s) = %s, %v; want peerB, true", ip2, key, ok)
	}

	// Reverse lookup.
	gotIP, ok := r.ResolvePeer("peerA")
	if !ok || !gotIP.Equal(ip1) {
		t.Fatalf("ResolvePeer(peerA) = %v, %v; want %v, true", gotIP, ok, ip1)
	}

	gotIP, ok = r.ResolvePeer("peerB")
	if !ok || !gotIP.Equal(ip2) {
		t.Fatalf("ResolvePeer(peerB) = %v, %v; want %v, true", gotIP, ok, ip2)
	}
}

func TestRouter_RemoveRoute(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	ip := net.ParseIP("10.10.0.5")
	r.AddRoute(ip, "peerA")

	// Remove by peer key.
	removedIP, ok := r.RemoveRoute("peerA")
	if !ok || !removedIP.Equal(ip) {
		t.Fatalf("RemoveRoute(peerA) = %v, %v; want %v, true", removedIP, ok, ip)
	}

	// Should be gone.
	_, ok = r.ResolveIP(ip)
	if ok {
		t.Fatal("route should be removed")
	}

	// Remove non-existent.
	_, ok = r.RemoveRoute("nonexistent")
	if ok {
		t.Fatal("RemoveRoute for non-existent should return false")
	}
}

func TestRouter_RemoveByIP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	ip := net.ParseIP("10.10.0.5")
	r.AddRoute(ip, "peerA")

	key, ok := r.RemoveByIP(ip)
	if !ok || key != "peerA" {
		t.Fatalf("RemoveByIP(%s) = %s, %v; want peerA, true", ip, key, ok)
	}

	_, ok = r.ResolvePeer("peerA")
	if ok {
		t.Fatal("peer should be removed")
	}
}

func TestRouter_UpdateRoute(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	ip1 := net.ParseIP("10.10.0.5")
	ip2 := net.ParseIP("10.10.0.6")

	// Add a route.
	r.AddRoute(ip1, "peerA")

	// Update the same peer to a new IP.
	r.AddRoute(ip2, "peerA")

	// Old IP should be gone.
	_, ok := r.ResolveIP(ip1)
	if ok {
		t.Fatal("old IP should be removed when peer gets new IP")
	}

	// New IP should resolve.
	key, ok := r.ResolveIP(ip2)
	if !ok || key != "peerA" {
		t.Fatalf("ResolveIP(%s) = %s, %v; want peerA, true", ip2, key, ok)
	}

	// Reverse lookup should give the new IP.
	gotIP, ok := r.ResolvePeer("peerA")
	if !ok || !gotIP.Equal(ip2) {
		t.Fatalf("ResolvePeer(peerA) = %v, %v; want %v, true", gotIP, ok, ip2)
	}
}

func TestRouter_IPOverwrite(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	ip := net.ParseIP("10.10.0.5")

	// Assign IP to peerA.
	r.AddRoute(ip, "peerA")

	// Overwrite: assign the same IP to peerB.
	r.AddRoute(ip, "peerB")

	// IP should now resolve to peerB.
	key, ok := r.ResolveIP(ip)
	if !ok || key != "peerB" {
		t.Fatalf("ResolveIP(%s) = %s, %v; want peerB, true", ip, key, ok)
	}

	// peerA should no longer have an IP.
	_, ok = r.ResolvePeer("peerA")
	if ok {
		t.Fatal("peerA should be removed when its IP is taken by peerB")
	}

	// peerB should have the IP.
	gotIP, ok := r.ResolvePeer("peerB")
	if !ok || !gotIP.Equal(ip) {
		t.Fatalf("ResolvePeer(peerB) = %v, %v; want %v, true", gotIP, ok, ip)
	}
}

func TestRouter_SetLocalIP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	localIP := net.ParseIP("10.10.0.1")
	r.SetLocalIP(localIP)

	// Local IP should resolve to self.
	key, ok := r.ResolveIP(localIP)
	if !ok || key != "localkey" {
		t.Fatalf("ResolveIP(localIP) = %s, %v; want localkey, true", key, ok)
	}

	// IsLocalIP should return true.
	if !r.IsLocalIP(localIP) {
		t.Fatal("IsLocalIP should return true for local IP")
	}

	// IsLocalIP should return false for other IPs.
	otherIP := net.ParseIP("10.10.0.2")
	if r.IsLocalIP(otherIP) {
		t.Fatal("IsLocalIP should return false for non-local IP")
	}

	// IsSelf should return true for own key.
	if !r.IsSelf("localkey") {
		t.Fatal("IsSelf should return true for own key")
	}
}

func TestRouter_RemoveRoutePreservesSelf(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	localIP := net.ParseIP("10.10.0.1")
	r.SetLocalIP(localIP)

	// Try to remove self route.
	_, ok := r.RemoveRoute("localkey")
	if ok {
		t.Fatal("RemoveRoute should return false for self (or preserve self)")
	}

	// Self route should still exist.
	key, ok := r.ResolveIP(localIP)
	if !ok || key != "localkey" {
		t.Fatal("self route should be preserved after RemoveRoute")
	}
}

func TestRouter_IsInSubnet(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	inSubnet := net.ParseIP("10.10.0.100")
	outSubnet := net.ParseIP("192.168.1.1")

	if !r.IsInSubnet(inSubnet) {
		t.Fatal("10.10.0.100 should be in 10.10.0.0/24")
	}
	if r.IsInSubnet(outSubnet) {
		t.Fatal("192.168.1.1 should NOT be in 10.10.0.0/24")
	}
}

func TestRouter_RouteCount(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	r.SetLocalIP(net.ParseIP("10.10.0.1"))
	r.AddRoute(net.ParseIP("10.10.0.5"), "peerA")
	r.AddRoute(net.ParseIP("10.10.0.6"), "peerB")

	// Should be 2 (excluding self).
	count := r.RouteCount()
	if count != 2 {
		t.Fatalf("RouteCount = %d; want 2", count)
	}
}

func TestRouter_AllRoutes(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	r.SetLocalIP(net.ParseIP("10.10.0.1"))
	r.AddRoute(net.ParseIP("10.10.0.5"), "peerA")
	r.AddRoute(net.ParseIP("10.10.0.6"), "peerB")

	routes := r.AllRoutes()
	if len(routes) != 3 { // self + 2 peers
		t.Fatalf("AllRoutes length = %d; want 3", len(routes))
	}
	if routes["10.10.0.1"] != "localkey" {
		t.Errorf("AllRoutes[10.10.0.1] = %s; want localkey", routes["10.10.0.1"])
	}
	if routes["10.10.0.5"] != "peerA" {
		t.Errorf("AllRoutes[10.10.0.5] = %s; want peerA", routes["10.10.0.5"])
	}
}

func TestRouter_SyncFromPeers(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")
	r.SetLocalIP(net.ParseIP("10.10.0.1"))

	// Initial routes.
	r.AddRoute(net.ParseIP("10.10.0.5"), "peerA")
	r.AddRoute(net.ParseIP("10.10.0.6"), "peerB")

	// Sync with a new set that has peerB and peerC (peerA removed).
	peers := []PeerRoute{
		{PublicKey: "peerB", VirtualIP: net.ParseIP("10.10.0.6")},
		{PublicKey: "peerC", VirtualIP: net.ParseIP("10.10.0.7")},
	}
	r.SyncFromPeers(peers)

	// peerA should be gone.
	_, ok := r.ResolvePeer("peerA")
	if ok {
		t.Fatal("peerA should be removed after sync")
	}

	// peerB should still exist.
	_, ok = r.ResolvePeer("peerB")
	if !ok {
		t.Fatal("peerB should still exist after sync")
	}

	// peerC should be added.
	key, ok := r.ResolveIP(net.ParseIP("10.10.0.7"))
	if !ok || key != "peerC" {
		t.Fatalf("ResolveIP(10.10.0.7) = %s, %v; want peerC, true", key, ok)
	}

	// Self should be preserved.
	key, ok = r.ResolveIP(net.ParseIP("10.10.0.1"))
	if !ok || key != "localkey" {
		t.Fatal("self route should be preserved after sync")
	}
}

func TestRouter_SyncFromPeers_DuplicateIPs(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")
	r.SetLocalIP(net.ParseIP("10.10.0.1"))

	// Two peers claim the same IP — first one wins.
	peers := []PeerRoute{
		{PublicKey: "peerA", VirtualIP: net.ParseIP("10.10.0.5")},
		{PublicKey: "peerB", VirtualIP: net.ParseIP("10.10.0.5")},
	}
	r.SyncFromPeers(peers)

	// Should resolve to peerA (first wins).
	key, ok := r.ResolveIP(net.ParseIP("10.10.0.5"))
	if !ok || key != "peerA" {
		t.Fatalf("ResolveIP(10.10.0.5) = %s, %v; want peerA, true", key, ok)
	}
}

func TestRouter_Concurrent(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")
	r.SetLocalIP(net.ParseIP("10.10.0.1"))

	done := make(chan struct{})

	// Writer goroutine.
	go func() {
		defer close(done)
		for i := 2; i < 100; i++ {
			ip := net.IPv4(10, 10, 0, byte(i))
			r.AddRoute(ip, "peer"+string(rune(i)))
		}
	}()

	// Reader goroutine.
	for i := 0; i < 1000; i++ {
		r.AllRoutes()
		r.RouteCount()
		r.ResolveIP(net.ParseIP("10.10.0.5"))
	}

	<-done
}

// ─── Router CRUD edge-case tests ───

func TestRouter_RemoveByIPProtectsSelf(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	localIP := net.ParseIP("10.10.0.1")
	r.SetLocalIP(localIP)

	// Try to remove self by IP.
	pubKey, removed := r.RemoveByIP(localIP)
	if removed {
		t.Fatalf("RemoveByIP should return false for self IP, got true (pubKey=%s)", pubKey)
	}

	// Self route must still exist.
	key, ok := r.ResolveIP(localIP)
	if !ok || key != "localkey" {
		t.Fatal("self route must be preserved after RemoveByIP")
	}
}

func TestRouter_RemoveNonExistent(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	// RemoveRoute for non-existent peer.
	_, ok := r.RemoveRoute("nonexistent")
	if ok {
		t.Fatal("RemoveRoute should return false for non-existent peer")
	}

	// RemoveByIP for non-existent IP.
	_, ok = r.RemoveByIP(net.ParseIP("10.10.0.99"))
	if ok {
		t.Fatal("RemoveByIP should return false for non-existent IP")
	}

	// ResolveIP for non-existent IP.
	_, ok = r.ResolveIP(net.ParseIP("10.10.0.99"))
	if ok {
		t.Fatal("ResolveIP should return false for non-existent IP")
	}

	// ResolvePeer for non-existent peer.
	_, ok = r.ResolvePeer("nonexistent")
	if ok {
		t.Fatal("ResolvePeer should return false for non-existent peer")
	}
}

func TestRouter_AddRemoveReAdd(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	ip := net.ParseIP("10.10.0.5")
	peer := "peerA"

	// Add.
	r.AddRoute(ip, peer)
	if _, ok := r.ResolveIP(ip); !ok {
		t.Fatal("route should exist after AddRoute")
	}

	// Remove.
	_, ok := r.RemoveRoute(peer)
	if !ok {
		t.Fatal("RemoveRoute should succeed")
	}
	if _, ok := r.ResolveIP(ip); ok {
		t.Fatal("route should NOT exist after RemoveRoute")
	}

	// Re-add — should work.
	r.AddRoute(ip, peer)
	if _, ok := r.ResolveIP(ip); !ok {
		t.Fatal("route should exist after re-AddRoute")
	}
}

func TestRouter_AddRouteIdempotent(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	ip := net.ParseIP("10.10.0.5")
	peer := "peerA"

	// Add the same route twice — should not panic, not corrupt state.
	r.AddRoute(ip, peer)
	r.AddRoute(ip, peer)

	key, ok := r.ResolveIP(ip)
	if !ok || key != peer {
		t.Fatalf("ResolveIP after idempotent AddRoute = %s, %v; want %s, true", key, ok, peer)
	}

	ip2, ok := r.ResolvePeer(peer)
	if !ok || !ip2.Equal(ip) {
		t.Fatalf("ResolvePeer after idempotent AddRoute = %v, %v; want %v, true", ip2, ok, ip)
	}

	// RouteCount should still be 1.
	if count := r.RouteCount(); count != 1 {
		t.Fatalf("RouteCount = %d; want 1", count)
	}
}

func TestRouter_ConcurrentRemoveAndResolve(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	ip := net.ParseIP("10.10.0.5")
	peer := "peerA"
	r.AddRoute(ip, peer)

	done := make(chan struct{})

	// Writer: add/remove in loop.
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			r.AddRoute(net.ParseIP("10.10.0.10"), "peerB")
			r.RemoveRoute("peerB")
		}
	}()

	// Reader: resolve concurrently.
	for i := 0; i < 2000; i++ {
		// These should never panic, even if data races exist (they don't
		// because of RWMutex, but this verifies it at runtime).
		r.ResolveIP(ip)
		r.ResolvePeer(peer)
		r.RouteCount()
		r.AllRoutes()
	}

	<-done
}

func TestRouter_SyncFromPeers_EmptyInput(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")
	localIP := net.ParseIP("10.10.0.1")
	r.SetLocalIP(localIP)

	// Add some routes.
	r.AddRoute(net.ParseIP("10.10.0.5"), "peerA")
	r.AddRoute(net.ParseIP("10.10.0.6"), "peerB")

	// Sync with empty input — self should be preserved, peers removed.
	r.SyncFromPeers([]PeerRoute{})

	// Self must still be there.
	key, ok := r.ResolveIP(localIP)
	if !ok || key != "localkey" {
		t.Fatalf("self route must survive empty sync: %s, %v", key, ok)
	}

	// Peers must be gone.
	_, ok = r.ResolvePeer("peerA")
	if ok {
		t.Fatal("peerA should be removed after empty sync")
	}
	_, ok = r.ResolvePeer("peerB")
	if ok {
		t.Fatal("peerB should be removed after empty sync")
	}

	// RouteCount should be 0 (self excluded).
	if count := r.RouteCount(); count != 0 {
		t.Fatalf("RouteCount = %d; want 0", count)
	}
}

func TestRouter_SyncFromPeers_NilEntriesIgnored(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")
	r.SetLocalIP(net.ParseIP("10.10.0.1"))

	// Input includes nil IP and empty pubkey entries.
	peers := []PeerRoute{
		{PublicKey: "", VirtualIP: net.ParseIP("10.10.0.5")},         // empty key → ignored
		{PublicKey: "peerA", VirtualIP: nil},                         // nil IP → ignored
		{PublicKey: "peerB", VirtualIP: net.ParseIP("10.10.0.6")},    // valid
	}
	r.SyncFromPeers(peers)

	// Only peerB should be present.
	_, ok := r.ResolvePeer("peerB")
	if !ok {
		t.Fatal("peerB should be present after sync")
	}

	// peerA and empty-key should NOT be present.
	if _, ok := r.ResolvePeer("peerA"); ok {
		t.Fatal("peerA (nil IP) should be ignored")
	}

	// Self should be preserved.
	key, ok := r.ResolveIP(net.ParseIP("10.10.0.1"))
	if !ok || key != "localkey" {
		t.Fatal("self should be preserved")
	}
}

func TestRouter_SyncFromPeers_PreservesSelf(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")
	localIP := net.ParseIP("10.10.0.1")
	r.SetLocalIP(localIP)

	// Sync with peers that don't include self.
	peers := []PeerRoute{
		{PublicKey: "peerA", VirtualIP: net.ParseIP("10.10.0.5")},
		{PublicKey: "peerB", VirtualIP: net.ParseIP("10.10.0.6")},
	}
	r.SyncFromPeers(peers)

	// Self must still be in the table.
	key, ok := r.ResolveIP(localIP)
	if !ok || key != "localkey" {
		t.Fatalf("self must be preserved: %s, %v", key, ok)
	}

	// AllRoutes must include self.
	routes := r.AllRoutes()
	if routes["10.10.0.1"] != "localkey" {
		t.Errorf("AllRoutes missing self: %v", routes)
	}
}

func TestRouter_LocalIPCopySafety(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")
	localIP := net.ParseIP("10.10.0.1")
	r.SetLocalIP(localIP)

	// Get LocalIP, mutate the returned slice.
	returned := r.LocalIP()
	if returned == nil {
		t.Fatal("LocalIP returned nil")
	}
	returned[3] = 99 // Try to mutate.

	// Router's internal state must be unchanged.
	stillLocal := r.IsLocalIP(net.ParseIP("10.10.0.1"))
	if !stillLocal {
		t.Fatal("IsLocalIP(10.10.0.1) should still be true after mutating returned LocalIP")
	}

	// The mutated IP 10.10.0.99 should NOT be local.
	if r.IsLocalIP(returned) {
		t.Fatal("mutated IP should NOT be considered local")
	}
}

func TestRouter_RouteCount_OnlySelf(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")
	r.SetLocalIP(net.ParseIP("10.10.0.1"))

	if count := r.RouteCount(); count != 0 {
		t.Fatalf("RouteCount with only self = %d; want 0", count)
	}
}

func TestRouter_IsInSubnet_NilSubnet(t *testing.T) {
	r := NewRouter(nil, "localkey")
	if r.IsInSubnet(net.ParseIP("10.10.0.1")) {
		t.Fatal("IsInSubnet should return false when subnet is nil")
	}
}

func TestRouter_String(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")
	r.SetLocalIP(net.ParseIP("10.10.0.1"))
	r.AddRoute(net.ParseIP("10.10.0.5"), "peerA")

	s := r.String()
	if s == "" {
		t.Fatal("String() should not return empty string")
	}
	// Should contain the subnet and count.
	if !strings.Contains(s, "10.10.0.0/24") {
		t.Errorf("String() should contain subnet: %s", s)
	}
}

func TestRouter_ResolvePeerCopySafety(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")
	ip := net.ParseIP("10.10.0.5")
	r.AddRoute(ip, "peerA")

	returned, ok := r.ResolvePeer("peerA")
	if !ok {
		t.Fatal("ResolvePeer failed")
	}

	// Mutate returned slice.
	returned[3] = 99

	// Router must still resolve the original IP.
	original, ok := r.ResolvePeer("peerA")
	if !ok || !original.Equal(ip) {
		t.Errorf("mutating ResolvePeer return affected router state: got %s, want %s",
			original, ip)
	}
}

func TestRouter_AllRoutesIncludesSelf(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	// Without SetLocalIP, AllRoutes should be empty.
	routes := r.AllRoutes()
	if len(routes) != 0 {
		t.Errorf("AllRoutes without local IP = %d entries; want 0", len(routes))
	}

	// After SetLocalIP.
	r.SetLocalIP(net.ParseIP("10.10.0.1"))
	routes = r.AllRoutes()
	if routes["10.10.0.1"] != "localkey" {
		t.Errorf("AllRoutes should include self after SetLocalIP")
	}
}

func TestRouter_IsLocalIP_BeforeSetLocalIP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.10.0.0/24")
	r := NewRouter(subnet, "localkey")

	// Before SetLocalIP, nothing is local.
	if r.IsLocalIP(net.ParseIP("10.10.0.1")) {
		t.Fatal("IsLocalIP should return false before SetLocalIP")
	}
}
