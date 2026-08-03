package tun

import (
	"net"
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
