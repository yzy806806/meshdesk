package monitor

import (
	"testing"
	"time"
)

func TestSystemCollectorCollect(t *testing.T) {
	c := NewSystemCollector("test-node", "test-host")

	m, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if m.NodeID != "test-node" {
		t.Errorf("NodeID = %s, want test-node", m.NodeID)
	}
	if m.Hostname != "test-host" {
		t.Errorf("Hostname = %s, want test-host", m.Hostname)
	}
	if m.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	if m.CPU.CoreCount <= 0 {
		t.Errorf("CPU.CoreCount = %d, want > 0", m.CPU.CoreCount)
	}
	if m.Memory.Total == 0 {
		t.Log("Warning: Memory.Total is 0 (may be non-Linux)")
	}
}

func TestSystemCollectorCPUDelta(t *testing.T) {
	c := NewSystemCollector("test-node", "")

	// First collection — CPU delta cannot be computed yet
	m1, err := c.Collect()
	if err != nil {
		t.Fatalf("First Collect: %v", err)
	}

	// On first sample, CPU usage should be 0 (no delta yet)
	if m1.CPU.UsagePercent != 0 {
		t.Logf("First sample CPU = %f (expected 0 on first sample)", m1.CPU.UsagePercent)
	}

	// Wait a moment for CPU activity
	time.Sleep(100 * time.Millisecond)

	// Second collection — should have a non-zero delta
	m2, err := c.Collect()
	if err != nil {
		t.Fatalf("Second Collect: %v", err)
	}

	// On the second sample, CPU usage should be computed
	// (it could be very low, but the mechanism should work)
	t.Logf("Second sample CPU usage: %.2f%%", m2.CPU.UsagePercent)
	if len(m2.CPU.PerCore) != m2.CPU.CoreCount {
		t.Errorf("PerCore len = %d, want %d", len(m2.CPU.PerCore), m2.CPU.CoreCount)
	}
}

func TestSystemCollectorHostname(t *testing.T) {
	// Empty hostname should auto-detect
	c := NewSystemCollector("n1", "")
	m, _ := c.Collect()
	if m.Hostname == "" {
		t.Error("Hostname should be auto-detected when empty")
	}
}

func TestSystemCollectorMemoryConsistency(t *testing.T) {
	c := NewSystemCollector("n1", "h1")
	m, _ := c.Collect()

	// Used + Available should be <= Total (some memory may be shared/cached)
	if m.Memory.Used > m.Memory.Total {
		t.Errorf("Used (%d) > Total (%d)", m.Memory.Used, m.Memory.Total)
	}
	if m.Memory.Available > m.Memory.Total {
		t.Errorf("Available (%d) > Total (%d)", m.Memory.Available, m.Memory.Total)
	}
}

func TestSystemCollectorNetwork(t *testing.T) {
	c := NewSystemCollector("n1", "h1")
	m, _ := c.Collect()

	// Network may be empty on some systems, but if present, fields should be sane
	for _, n := range m.Network {
		if n.Name == "" {
			t.Error("Network interface name should not be empty")
		}
		if n.Name == "lo" {
			t.Error("Loopback should be excluded")
		}
	}
}

func TestSystemCollectorDisk(t *testing.T) {
	c := NewSystemCollector("n1", "h1")
	m, _ := c.Collect()

	for _, d := range m.Disk {
		if d.MountPoint == "" {
			t.Error("Disk mount point should not be empty")
		}
		if d.Total == 0 {
			t.Errorf("Disk %s Total = 0", d.MountPoint)
		}
		// Used + Free should be <= Total (reserved blocks)
		if d.Used+d.Free > d.Total {
			t.Errorf("Disk %s: Used(%d)+Free(%d) > Total(%d)", d.MountPoint, d.Used, d.Free, d.Total)
		}
	}
}

func TestSystemCollectorLoadAvg(t *testing.T) {
	c := NewSystemCollector("n1", "h1")
	m, _ := c.Collect()

	// Load averages should be non-negative
	if m.LoadAvg.Load1 < 0 {
		t.Errorf("Load1 = %f, should be >= 0", m.LoadAvg.Load1)
	}
}

func TestSystemCollectorUptime(t *testing.T) {
	c := NewSystemCollector("n1", "h1")
	m, _ := c.Collect()

	if m.Uptime < 0 {
		t.Errorf("Uptime = %d, should be >= 0", m.Uptime)
	}
}

func TestIsPseudoFS(t *testing.T) {
	pseudo := []string{"proc", "sysfs", "tmpfs", "devtmpfs", "cgroup", "cgroup2"}
	for _, fs := range pseudo {
		if !isPseudoFS(fs) {
			t.Errorf("isPseudoFS(%q) = false, want true", fs)
		}
	}

	real := []string{"ext4", "xfs", "btrfs", "zfs", "f2fs"}
	for _, fs := range real {
		if isPseudoFS(fs) {
			t.Errorf("isPseudoFS(%q) = true, want false", fs)
		}
	}
}
