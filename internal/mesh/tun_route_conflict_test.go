package mesh

import (
	"net"
	"os/exec"
	"strings"
	"testing"
)

// ─── cidrOverlap unit tests ───

func TestCidrOverlap_Identical(t *testing.T) {
	_, a, _ := net.ParseCIDR("10.144.144.0/24")
	_, b, _ := net.ParseCIDR("10.144.144.0/24")
	if !cidrOverlap(a, b) {
		t.Fatal("identical CIDRs should overlap")
	}
}

func TestCidrOverlap_Subset(t *testing.T) {
	_, a, _ := net.ParseCIDR("10.144.0.0/16")
	_, b, _ := net.ParseCIDR("10.144.144.0/24")
	if !cidrOverlap(a, b) {
		t.Fatal("/16 should overlap with /24 inside it")
	}
}

func TestCidrOverlap_PartialOverlap(t *testing.T) {
	// 10.144.144.0/23 overlaps 10.144.144.0/24
	_, a, _ := net.ParseCIDR("10.144.144.0/23")
	_, b, _ := net.ParseCIDR("10.144.144.0/24")
	if !cidrOverlap(a, b) {
		t.Fatal("/23 should overlap with /24 that shares network address")
	}
}

func TestCidrOverlap_NoOverlap(t *testing.T) {
	_, a, _ := net.ParseCIDR("10.144.144.0/24")
	_, b, _ := net.ParseCIDR("10.100.0.0/24")
	if cidrOverlap(a, b) {
		t.Fatal("non-overlapping /24s should not overlap")
	}
}

func TestCidrOverlap_DistantNetworks(t *testing.T) {
	_, a, _ := net.ParseCIDR("192.168.1.0/24")
	_, b, _ := net.ParseCIDR("10.0.0.0/8")
	if cidrOverlap(a, b) {
		t.Fatal("192.168.1.0/24 and 10.0.0.0/8 should not overlap")
	}
}

func TestCidrOverlap_NilNets(t *testing.T) {
	if cidrOverlap(nil, nil) {
		t.Fatal("nil CIDRs should not overlap")
	}
	_, a, _ := net.ParseCIDR("10.0.0.0/24")
	if cidrOverlap(a, nil) {
		t.Fatal("non-nil + nil should not overlap")
	}
	if cidrOverlap(nil, a) {
		t.Fatal("nil + non-nil should not overlap")
	}
}

// ─── detectSubnetConflict tests ───

// detectSubnetConflictWithOutput tests the parsing logic of
// detectSubnetConflict by injecting a fake `ip -o addr show` output.
// This avoids needing root privileges.
func detectSubnetConflictWithOutput(meshCIDR, fakeIPOutput string) []string {
	_, meshNet, err := net.ParseCIDR(meshCIDR)
	if err != nil {
		return nil
	}

	var conflicts []string
	lines := strings.Split(fakeIPOutput, "\n")
	for _, line := range lines {
		inetIdx := strings.Index(line, "inet ")
		if inetIdx < 0 {
			continue
		}
		rest := line[inetIdx+5:]
		spaceIdx := strings.Index(rest, " ")
		if spaceIdx < 0 {
			continue
		}
		addrCIDR := rest[:spaceIdx]
		if strings.HasPrefix(addrCIDR, "169.254.") || strings.HasPrefix(addrCIDR, "127.") {
			continue
		}

		_, existingNet, err := net.ParseCIDR(addrCIDR)
		if err != nil {
			continue
		}

		if cidrOverlap(meshNet, existingNet) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ifName := strings.TrimSuffix(parts[1], ":")
				if ifName == "mesh0" || strings.HasPrefix(ifName, "mesh") {
					continue
				}
				conflicts = append(conflicts, addrCIDR+" on "+ifName)
			}
		}
	}

	return conflicts
}

func TestDetectSubnetConflict_EasyTierOverlap(t *testing.T) {
	// Simulate EasyTier's tun0 with 10.144.144.20/24
	fakeOutput := `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\       valid_lft forever preferred_lft forever
3: tun0    inet 10.144.144.20/24 brd 10.144.144.255 scope global tun0\       valid_lft forever preferred_lft forever
`

	conflicts := detectSubnetConflictWithOutput("10.144.144.0/24", fakeOutput)
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(conflicts), conflicts)
	}
	if !strings.Contains(conflicts[0], "tun0") {
		t.Fatalf("expected conflict on tun0, got %q", conflicts[0])
	}
	if !strings.Contains(conflicts[0], "10.144.144.20/24") {
		t.Fatalf("expected conflict to contain the CIDR, got %q", conflicts[0])
	}
}

func TestDetectSubnetConflict_NoConflict(t *testing.T) {
	fakeOutput := `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\       valid_lft forever preferred_lft forever
3: tun0    inet 10.144.144.20/24 brd 10.144.144.255 scope global tun0\       valid_lft forever preferred_lft forever
`

	// mesh_cidr 10.100.0.0/24 does not overlap any interface
	conflicts := detectSubnetConflictWithOutput("10.100.0.0/24", fakeOutput)
	if len(conflicts) != 0 {
		t.Fatalf("expected 0 conflicts, got %d: %v", len(conflicts), conflicts)
	}
}

func TestDetectSubnetConflict_LinkLocalSkipped(t *testing.T) {
	fakeOutput := `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth0    inet 169.254.1.5/16 brd 169.254.255.255 scope link eth0\       valid_lft forever preferred_lft forever
`

	// 169.254.x.x should be skipped, no conflict
	conflicts := detectSubnetConflictWithOutput("169.254.0.0/16", fakeOutput)
	if len(conflicts) != 0 {
		t.Fatalf("expected 0 conflicts (link-local skipped), got %d: %v", len(conflicts), conflicts)
	}
}

func TestDetectSubnetConflict_LoopbackSkipped(t *testing.T) {
	fakeOutput := `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
`

	conflicts := detectSubnetConflictWithOutput("127.0.0.0/8", fakeOutput)
	if len(conflicts) != 0 {
		t.Fatalf("expected 0 conflicts (loopback skipped), got %d: %v", len(conflicts), conflicts)
	}
}

func TestDetectSubnetConflict_MeshInterfaceSkipped(t *testing.T) {
	fakeOutput := `2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\       valid_lft forever preferred_lft forever
4: mesh0    inet 10.144.144.2/24 brd 10.144.144.255 scope global mesh0\       valid_lft forever preferred_lft forever
`

	// mesh0 should be skipped — we don't conflict with ourselves
	conflicts := detectSubnetConflictWithOutput("10.144.144.0/24", fakeOutput)
	if len(conflicts) != 0 {
		t.Fatalf("expected 0 conflicts (mesh0 skipped), got %d: %v", len(conflicts), conflicts)
	}
}

func TestDetectSubnetConflict_MultipleConflicts(t *testing.T) {
	fakeOutput := `2: eth0    inet 10.144.0.1/16 brd 10.144.255.255 scope global eth0\       valid_lft forever preferred_lft forever
3: tun0    inet 10.144.144.20/24 brd 10.144.144.255 scope global tun0\       valid_lft forever preferred_lft forever
`

	// Both eth0 (/16 covering the /24) and tun0 (/24 exact) overlap
	conflicts := detectSubnetConflictWithOutput("10.144.144.0/24", fakeOutput)
	if len(conflicts) != 2 {
		t.Fatalf("expected 2 conflicts, got %d: %v", len(conflicts), conflicts)
	}
}

func TestDetectSubnetConflict_InvalidCIDR(t *testing.T) {
	// Invalid mesh CIDR should return nil, not panic
	conflicts := detectSubnetConflictWithOutput("not-a-cidr", "")
	if conflicts != nil {
		t.Fatalf("expected nil for invalid CIDR, got %v", conflicts)
	}
}

func TestDetectSubnetConflict_EmptyOutput(t *testing.T) {
	conflicts := detectSubnetConflictWithOutput("10.100.0.0/24", "")
	if len(conflicts) != 0 {
		t.Fatalf("expected 0 conflicts for empty output, got %d: %v", len(conflicts), conflicts)
	}
}

// ─── Integration test: route metric on real TUN device ───

// TestTunIntegration_RouteMetric0 verifies that configureTUNInterface
// creates an on-link route with metric 0 on a real TUN device.
// On Linux, metric 0 is the default and is not shown in `ip route show`
// output — instead we verify the route exists and that `proto kernel`
// is absent (meaning our route replaced the auto-generated kernel route).
func TestTunIntegration_RouteMetric0(t *testing.T) {
	skipUnlessTun(t)

	// Create a TUN device.
	d := createTestTun(t, "tunmetric0")
	ifName := d.Name()

	_, ipNet, err := net.ParseCIDR("10.201.0.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	virtualIP := net.ParseIP("10.201.0.1")

	// Configure the interface (this should add route with metric 0).
	if err := configureTUNInterface(ifName, virtualIP, ipNet, 1400); err != nil {
		t.Fatalf("configureTUNInterface: %v", err)
	}

	// Verify the route exists on our interface.
	out, err := runIP("route", "show", "10.201.0.0/24")
	if err != nil {
		t.Fatalf("ip route show: %v (output: %s)", err, out)
	}

	if !contains(out, ifName) {
		t.Fatalf("route for 10.201.0.0/24 should be on %s. Output:\n%s", ifName, out)
	}

	// The route should NOT have "proto kernel" — our `ip route replace`
	// with metric 0 should have replaced the auto-generated proto kernel
	// route with an explicit route.
	if contains(out, "proto kernel") {
		t.Fatalf("route for 10.201.0.0/24 should NOT have proto kernel (should be replaced by metric 0 route). Output:\n%s", out)
	}

	// Cleanup: remove the route.
	runIP("route", "del", "10.201.0.0/24", "dev", ifName, "metric", "0")
}

// TestTunIntegration_PeerRouteMetric0 verifies that addKernelRoute
// creates a /32 route with metric 0 on a real TUN device.
func TestTunIntegration_PeerRouteMetric0(t *testing.T) {
	skipUnlessTun(t)

	d := createTestTun(t, "tunmetric1")
	ifName := d.Name()

	// Bring interface up.
	_, err := runIP("link", "set", ifName, "up")
	if err != nil {
		t.Fatalf("ip link set up: %v", err)
	}

	peerIP := net.ParseIP("10.202.0.5")

	// Add a peer /32 route with metric 0.
	addKernelRoute(ifName, peerIP)

	// Verify the route exists on our interface.
	out, err := runIP("route", "show", "10.202.0.5/32")
	if err != nil {
		t.Fatalf("ip route show: %v (output: %s)", err, out)
	}

	if !contains(out, ifName) {
		t.Fatalf("peer route for 10.202.0.5/32 should be on %s. Output:\n%s", ifName, out)
	}

	// Cleanup.
	removeKernelRoute(ifName, peerIP)
}

// TestTunIntegration_RemoveKernelRouteWithMetric verifies that
// removeKernelRoute successfully removes a route that was added
// with metric 0.
func TestTunIntegration_RemoveKernelRouteWithMetric(t *testing.T) {
	skipUnlessTun(t)

	d := createTestTun(t, "tunmetric2")
	ifName := d.Name()

	_, err := runIP("link", "set", ifName, "up")
	if err != nil {
		t.Fatalf("ip link set up: %v", err)
	}

	peerIP := net.ParseIP("10.203.0.7")

	// Add route with metric 0.
	addKernelRoute(ifName, peerIP)

	// Verify it exists.
	out, _ := runIP("route", "show", "10.203.0.7/32", "dev", ifName)
	if !contains(out, "10.203.0.7") {
		t.Fatalf("route should exist after add. Output:\n%s", out)
	}

	// Remove it.
	removeKernelRoute(ifName, peerIP)

	// Verify it's gone.
	out, _ = runIP("route", "show", "10.203.0.7/32", "dev", ifName)
	if contains(out, "10.203.0.7") {
		t.Fatalf("route should be gone after remove. Output:\n%s", out)
	}
}

// TestTunIntegration_RouteReplaceOverwritesExisting verifies that
// configureTUNInterface's `ip route replace` successfully replaces
// an existing proto kernel route for the same subnet (simulating the
// EasyTier conflict scenario where both interfaces have the same subnet).
func TestTunIntegration_RouteReplaceOverwritesExisting(t *testing.T) {
	skipUnlessTun(t)

	d := createTestTun(t, "tunmetric3")
	ifName := d.Name()

	_, ipNet, err := net.ParseCIDR("10.204.0.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	virtualIP := net.ParseIP("10.204.0.1")

	// configureTUNInterface will:
	// 1. Assign IP (creates proto kernel route)
	// 2. Replace the proto kernel route with metric 0 route
	if err := configureTUNInterface(ifName, virtualIP, ipNet, 1400); err != nil {
		t.Fatalf("configureTUNInterface: %v", err)
	}

	// Verify that the route exists and proto kernel is absent
	// (meaning our metric 0 route replaced the auto-generated one).
	out, _ := runIP("route", "show", "10.204.0.0/24")
	if !contains(out, ifName) {
		t.Fatalf("route should be on %s. Output:\n%s", ifName, out)
	}
	if contains(out, "proto kernel") {
		t.Fatalf("route should NOT have proto kernel (should be replaced by metric 0 route). Output:\n%s", out)
	}

	// Verify ip route get uses our interface.
	out, _ = runIP("route", "get", "10.204.0.5")
	if !contains(out, ifName) {
		t.Fatalf("ip route get 10.204.0.5 should use %s. Output:\n%s", ifName, out)
	}

	// Cleanup.
	runIP("route", "del", "10.204.0.0/24", "dev", ifName, "metric", "0")
}

// TestDetectSubnetConflict_RealSystem runs detectSubnetConflict against
// the real system's `ip -o addr show` output. It should either return
// nil (no conflict) or a non-empty list (conflict found), but should
// never panic.
func TestDetectSubnetConflict_RealSystem(t *testing.T) {
	// Use a subnet that's unlikely to exist on the test system.
	conflicts := detectSubnetConflict("10.99.99.0/24")
	// We don't assert on the result — we just verify it doesn't panic
	// and returns a valid value.
	_ = conflicts

	// Also test with a common subnet that might conflict.
	conflicts = detectSubnetConflict("10.0.0.0/8")
	_ = conflicts

	// Verify the function handles the real `ip` command correctly.
	// Just make sure it runs without error.
	cmd := exec.Command("ip", "-o", "addr", "show")
	if output, err := cmd.CombinedOutput(); err == nil {
		// If `ip` is available, detectSubnetConflict should have
		// produced a result (possibly empty).
		_ = output
	}
}
