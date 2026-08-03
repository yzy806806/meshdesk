package tun

import (
	"net"
	"os"
	"testing"
)

// TestConfigValidation verifies that Create rejects invalid configs
// before attempting to open /dev/net/tun.
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name: "invalid subnet",
			cfg: Config{
				Subnet: "not-a-cidr",
				MTU:    1400,
			},
			wantErr: "invalid subnet",
		},
		{
			name: "zero MTU",
			cfg: Config{
				Subnet: "10.10.0.0/24",
				MTU:    0,
			},
			wantErr: "MTU must be positive",
		},
		{
			name: "negative MTU",
			cfg: Config{
				Subnet: "10.10.0.0/24",
				MTU:    -1,
			},
			wantErr: "MTU must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Create(tt.cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestDeviceAddrDerivation verifies that the device IP address is
// correctly derived as the first usable host in the subnet.
// We can only test this if we have permission to create a TUN device.
func TestDeviceAddrDerivation(t *testing.T) {
	// Skip if we can't open /dev/net/tun (no CAP_NET_ADMIN).
	if os.Getuid() != 0 {
		t.Skip("skipping TUN creation test (requires root/CAP_NET_ADMIN)")
	}

	d, err := Create(Config{
		Name:   "testtun0",
		MTU:    1400,
		Subnet: "10.99.0.0/24",
	})
	if err != nil {
		t.Skipf("could not create TUN device (expected in CI without tun module): %v", err)
	}
	defer d.Close()

	// First usable address in 10.99.0.0/24 is 10.99.0.1.
	expected := net.ParseIP("10.99.0.1")
	if !d.Addr().Equal(expected) {
		t.Errorf("Addr() = %s, want %s", d.Addr(), expected)
	}

	// Verify subnet.
	if d.Subnet().String() != "10.99.0.0/24" {
		t.Errorf("Subnet() = %s, want 10.99.0.0/24", d.Subnet().String())
	}

	// Verify MTU.
	if d.MTU() != 1400 {
		t.Errorf("MTU() = %d, want 1400", d.MTU())
	}

	// Verify interface name was assigned.
	if d.Name() != "testtun0" {
		t.Errorf("Name() = %q, want %q", d.Name(), "testtun0")
	}

	// Verify the file is usable (non-nil).
	if d.File() == nil {
		t.Error("File() returned nil")
	}
}

// TestDeviceClose verifies that Close can be called safely and that
// double-close does not panic.
func TestDeviceClose(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping TUN creation test (requires root/CAP_NET_ADMIN)")
	}

	d, err := Create(Config{
		Name:   "testtun1",
		MTU:    1400,
		Subnet: "10.98.0.0/24",
	})
	if err != nil {
		t.Skipf("could not create TUN device: %v", err)
	}

	// First close should succeed.
	if err := d.Close(); err != nil {
		t.Errorf("first Close() error: %v", err)
	}

	// Second close should not panic (file is nil after first close
	// because os.File.Close sets internal state; but our Device.Close
	// checks for nil file).
	if err := d.Close(); err != nil {
		t.Errorf("second Close() error: %v", err)
	}
}

// TestNameTruncation verifies that interface names longer than
// IFNAMSIZ-1 (15) characters are truncated without error.
func TestNameTruncation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping TUN creation test (requires root/CAP_NET_ADMIN)")
	}

	longName := "this-is-a-very-long-tun-name-that-exceeds-limit"
	d, err := Create(Config{
		Name:   longName,
		MTU:    1400,
		Subnet: "10.97.0.0/24",
	})
	if err != nil {
		t.Skipf("could not create TUN device: %v", err)
	}
	defer d.Close()

	// The kernel should have truncated the name to 15 chars max.
	if len(d.Name()) > IFNAMSIZ-1 {
		t.Errorf("Name() length = %d, max %d", len(d.Name()), IFNAMSIZ-1)
	}
}

// TestAddrDerivationForIPv6 verifies IPv6 subnet address derivation.
func TestAddrDerivationForIPv6(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping TUN creation test (requires root/CAP_NET_ADMIN)")
	}

	d, err := Create(Config{
		Name:   "testtun6",
		MTU:    1400,
		Subnet: "fd00::/64",
	})
	if err != nil {
		t.Skipf("could not create TUN device: %v", err)
	}
	defer d.Close()

	// First usable address in fd00::/64 is fd00::1.
	expected := net.ParseIP("fd00::1")
	if !d.Addr().Equal(expected) {
		t.Errorf("Addr() = %s, want %s", d.Addr(), expected)
	}
}

// contains is a minimal strings.Contains to avoid importing strings
// just for one test helper.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
