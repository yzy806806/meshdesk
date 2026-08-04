package mesh

import (
	"net"
	"testing"
)

// TestAddrWithPrefix verifies that addrWithPrefix formats IP+CIDR correctly
// for various prefix lengths. This is the core of the /32 vs /24 fix —
// both addKernelAddr and removeKernelAddr must use the same prefix from
// the mesh subnet, not a hardcoded /32.
func TestAddrWithPrefix(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		cidr string
		want string
	}{
		{
			name: "/24 prefix",
			ip:   "10.100.0.1",
			cidr: "10.100.0.0/24",
			want: "10.100.0.1/24",
		},
		{
			name: "/16 prefix",
			ip:   "10.100.5.3",
			cidr: "10.100.0.0/16",
			want: "10.100.5.3/16",
		},
		{
			name: "/30 prefix",
			ip:   "10.100.0.2",
			cidr: "10.100.0.0/30",
			want: "10.100.0.2/30",
		},
		{
			name: "/8 prefix",
			ip:   "10.100.0.1",
			cidr: "10.0.0.0/8",
			want: "10.100.0.1/8",
		},
		{
			name: "old IP /24 (the bug scenario)",
			ip:   "10.100.0.1",
			cidr: "10.100.0.0/24",
			want: "10.100.0.1/24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("ParseCIDR(%q): %v", tt.cidr, err)
			}
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("ParseIP(%q) returned nil", tt.ip)
			}

			got := addrWithPrefix(ip, ipNet)
			if got != tt.want {
				t.Errorf("addrWithPrefix(%s, %s) = %q, want %q",
					tt.ip, tt.cidr, got, tt.want)
			}

			// Critical: the result must NOT be /32 when the subnet is not /32.
			// This is the exact bug that was fixed.
			if !ipNet.IP.Equal(net.IPv4(255, 255, 255, 255)) {
				if got == tt.ip+"/32" {
					t.Errorf("addrWithPrefix returned /32 for non-/32 subnet %s — this is the bug!", tt.cidr)
				}
			}
		})
	}
}

// TestRemoveKernelAddr_PrefixMatch is a TUN integration test that verifies
// removeKernelAddr uses the same prefix as addKernelAddr. It adds an IP
// with /24 prefix, then removes it — the removal must succeed without
// "Address not found" because the prefix matches.
func TestRemoveKernelAddr_PrefixMatch(t *testing.T) {
	skipUnlessTun(t)

	// Create a TUN device for testing.
	d := createTestTun(t, "tunprefix0")
	ifName := d.Name()

	_, ipNet, err := net.ParseCIDR("10.200.0.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	testIP := net.ParseIP("10.200.0.99")

	// Add the IP with /24 prefix (same as addKernelAddr does).
	addKernelAddr(ifName, testIP, ipNet)

	// Verify the IP was added with /24 prefix (not /32).
	out, err := runIP("addr", "show", "dev", ifName)
	if err != nil {
		t.Fatalf("ip addr show: %v (output: %s)", err, out)
	}
	// The address should appear as 10.200.0.99/24, not 10.200.0.99/32.
	if !contains(out, "10.200.0.99/24") {
		t.Fatalf("IP not added with /24 prefix. ip addr show output:\n%s", out)
	}

	// Now remove the IP — this should succeed because removeKernelAddr
	// now uses the same /24 prefix as addKernelAddr.
	removeKernelAddr(ifName, testIP, ipNet)

	// Verify the IP was actually removed.
	out, err = runIP("addr", "show", "dev", ifName)
	if err != nil {
		t.Fatalf("ip addr show after remove: %v (output: %s)", err, out)
	}
	if contains(out, "10.200.0.99") {
		t.Fatalf("IP 10.200.0.99 still present after removeKernelAddr. Output:\n%s", out)
	}
}

// contains is a simple substring check (avoiding importing strings here
// since the test file already imports it via other tests).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
