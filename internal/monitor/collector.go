package monitor

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SystemCollector collects real system metrics from the host.
// On Linux it reads /proc for CPU, memory, disk, and network stats.
// On non-Linux platforms it returns best-effort stubs so the code compiles
// and tests can run.
type SystemCollector struct {
	nodeID   string
	hostname string

	// prevCPU holds the previous CPU sample for delta calculation.
	prevCPU *cpuSample
}

type cpuSample struct {
	total uint64
	idle  uint64
	// per-core stats for per-core utilisation
	perCoreTotal []uint64
	perCoreIdle  []uint64
}

// NewSystemCollector creates a collector for the given node identity.
func NewSystemCollector(nodeID, hostname string) *SystemCollector {
	if hostname == "" {
		h, _ := os.Hostname()
		hostname = h
	}
	return &SystemCollector{
		nodeID:   nodeID,
		hostname: hostname,
	}
}

// Collect gathers all system metrics in a single call.
func (c *SystemCollector) Collect() (*Metrics, error) {
	m := &Metrics{
		Timestamp: time.Now().UTC(),
		NodeID:    c.nodeID,
		Hostname:  c.hostname,
	}

	var err error
	m.CPU, err = c.collectCPU()
	if err != nil {
		// CPU is non-fatal; log and continue
		m.CPU = CPUMetrics{CoreCount: runtime.NumCPU()}
	}

	m.Memory, err = c.collectMemory()
	if err != nil {
		m.Memory = MemoryMetrics{}
	}

	m.LoadAvg = c.collectLoadAvg()

	m.Disk = c.collectDisk()

	m.Network = c.collectNetwork()

	m.Uptime = c.collectUptime()

	return m, nil
}

// ---------- CPU ----------

func (c *SystemCollector) collectCPU() (CPUMetrics, error) {
	if runtime.GOOS != "linux" {
		return CPUMetrics{CoreCount: runtime.NumCPU()}, nil
	}

	lines, err := readProcFile("/proc/stat")
	if err != nil {
		return CPUMetrics{}, err
	}

	var aggTotal, aggIdle uint64
	var perCoreTotal, perCoreIdle []uint64
	coreCount := 0

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// "cpu" aggregate or "cpu0", "cpu1", etc.
		if !strings.HasPrefix(fields[0], "cpu") {
			continue
		}

		// fields[1..] = user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
		var cpuFields [10]uint64
		for i := 1; i < len(fields) && i <= 10; i++ {
			val, _ := strconv.ParseUint(fields[i], 10, 64)
			cpuFields[i-1] = val
		}
		// total = sum of all fields; idle = idle + iowait
		var total uint64
		for _, v := range cpuFields {
			total += v
		}
		idle := cpuFields[3] + cpuFields[4]

		if fields[0] == "cpu" {
			aggTotal = total
			aggIdle = idle
		} else {
			// Per-core line
			perCoreTotal = append(perCoreTotal, total)
			perCoreIdle = append(perCoreIdle, idle)
			coreCount++
		}
	}

	if coreCount == 0 {
		coreCount = runtime.NumCPU()
	}

	metrics := CPUMetrics{CoreCount: coreCount}

	// Calculate overall usage from delta
	if c.prevCPU != nil {
		totalDelta := aggTotal - c.prevCPU.total
		idleDelta := aggIdle - c.prevCPU.idle
		if totalDelta > 0 {
			metrics.UsagePercent = (1.0 - float64(idleDelta)/float64(totalDelta)) * 100.0
		}

		// Per-core usage
		for i := 0; i < len(perCoreTotal) && i < len(c.prevCPU.perCoreTotal); i++ {
			td := perCoreTotal[i] - c.prevCPU.perCoreTotal[i]
			id := perCoreIdle[i] - c.prevCPU.perCoreIdle[i]
			if td > 0 {
				metrics.PerCore = append(metrics.PerCore, (1.0-float64(id)/float64(td))*100.0)
			} else {
				metrics.PerCore = append(metrics.PerCore, 0)
			}
		}
	} else {
		// First sample: cannot compute delta yet
		metrics.UsagePercent = 0
		for i := 0; i < coreCount; i++ {
			metrics.PerCore = append(metrics.PerCore, 0)
		}
	}

	// Save for next delta
	c.prevCPU = &cpuSample{
		total:        aggTotal,
		idle:         aggIdle,
		perCoreTotal: perCoreTotal,
		perCoreIdle:  perCoreIdle,
	}

	return metrics, nil
}

// ---------- Memory ----------

func (c *SystemCollector) collectMemory() (MemoryMetrics, error) {
	if runtime.GOOS != "linux" {
		return MemoryMetrics{}, nil
	}

	lines, err := readProcFile("/proc/meminfo")
	if err != nil {
		return MemoryMetrics{}, err
	}

	m := MemoryMetrics{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64) // in kB
		val *= 1024                                    // convert to bytes

		switch fields[0] {
		case "MemTotal:":
			m.Total = val
		case "MemAvailable:":
			m.Available = val
		case "SwapTotal:":
			m.SwapTotal = val
		case "SwapFree:":
			swapUsed := m.SwapTotal - val
			if m.SwapTotal >= val {
				m.SwapUsed = swapUsed
			}
		}
	}
	m.Used = m.Total - m.Available
	return m, nil
}

// ---------- Load Average ----------

func (c *SystemCollector) collectLoadAvg() LoadAvgMetrics {
	if runtime.GOOS != "linux" {
		return LoadAvgMetrics{}
	}

	lines, err := readProcFile("/proc/loadavg")
	if err != nil {
		return LoadAvgMetrics{}
	}

	fields := strings.Fields(strings.Join(lines, " "))
	if len(fields) < 3 {
		return LoadAvgMetrics{}
	}

	load := LoadAvgMetrics{}
	load.Load1, _ = strconv.ParseFloat(fields[0], 64)
	load.Load5, _ = strconv.ParseFloat(fields[1], 64)
	load.Load15, _ = strconv.ParseFloat(fields[2], 64)
	return load
}

// ---------- Disk ----------

func (c *SystemCollector) collectDisk() []DiskMetrics {
	if runtime.GOOS != "linux" {
		return nil
	}

	// Parse /proc/mounts for real filesystems
	lines, err := readProcFile("/proc/mounts")
	if err != nil {
		return nil
	}

	var disks []DiskMetrics
	seen := make(map[string]bool)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		device := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]

		// Skip pseudo filesystems
		if isPseudoFS(fsType) {
			continue
		}
		// Skip duplicate mounts
		if seen[mountPoint] {
			continue
		}
		seen[mountPoint] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountPoint, &stat); err != nil {
			continue
		}

		total := stat.Blocks * uint64(stat.Bsize)
		// Skip zero-size mounts (snap squashfs, bind mounts, etc.)
		if total == 0 {
			continue
		}
		free := stat.Bfree * uint64(stat.Bsize)
		avail := stat.Bavail * uint64(stat.Bsize)
		used := total - free
		var inodePercent float64
		if stat.Files > 0 {
			inodePercent = float64(stat.Files-stat.Ffree) / float64(stat.Files) * 100.0
		}

		_ = avail // avail reported as Free below

		disks = append(disks, DiskMetrics{
			Device:       device,
			MountPoint:   mountPoint,
			FSType:       fsType,
			Total:        total,
			Used:         used,
			Free:         free,
			InodePercent: inodePercent,
		})
	}

	return disks
}

func isPseudoFS(fsType string) bool {
	switch fsType {
	case "proc", "sysfs", "devtmpfs", "tmpfs", "devpts", "cgroup",
		"cgroup2", "pstore", "bpf", "mqueue", "hugetlbfs", "fusectl",
		"configfs", "securityfs", "debugfs", "tracefs", "rpc_pipefs",
		"autofs", "binfmt_misc", "efivarfs":
		return true
	}
	return false
}

// ---------- Network ----------

func (c *SystemCollector) collectNetwork() []NetMetrics {
	if runtime.GOOS != "linux" {
		return nil
	}

	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}

	var nets []NetMetrics
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		// Skip loopback
		if name == "lo" {
			continue
		}
		rest := strings.Fields(line[idx+1:])
		if len(rest) < 16 {
			continue
		}

		rxBytes, _ := strconv.ParseUint(rest[0], 10, 64)
		rxPackets, _ := strconv.ParseUint(rest[1], 10, 64)
		rxErrors, _ := strconv.ParseUint(rest[2], 10, 64)
		txBytes, _ := strconv.ParseUint(rest[8], 10, 64)
		txPackets, _ := strconv.ParseUint(rest[9], 10, 64)
		txErrors, _ := strconv.ParseUint(rest[10], 10, 64)

		nets = append(nets, NetMetrics{
			Name:      name,
			RxBytes:   rxBytes,
			TxBytes:   txBytes,
			RxPackets: rxPackets,
			TxPackets: txPackets,
			RxErrors:  rxErrors,
			TxErrors:  txErrors,
			SpeedMbps: getInterfaceSpeed(name),
		})
	}

	return nets
}

// getInterfaceSpeed reads the link speed from /sys/class/net/<iface>/speed.
func getInterfaceSpeed(name string) int {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", name, "speed"))
	if err != nil {
		return 0
	}
	speed, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return speed
}

// ---------- Uptime ----------

func (c *SystemCollector) collectUptime() int64 {
	if runtime.GOOS != "linux" {
		return 0
	}

	info, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(info))
	if len(fields) < 1 {
		return 0
	}
	up, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(up)
}

// ---------- Helpers ----------

func readProcFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	// /proc/stat can have very long "cpu" lines; bump buffer
	scanner.Buffer(make([]byte, 0, 16384), 16384)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// DiskUsage is a convenience function for getting human-readable disk info (for CLI use).
func DiskUsage(path string) (total, used, free uint64, err error) {
	var stat syscall.Statfs_t
	if err = syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0, err
	}
	total = stat.Blocks * uint64(stat.Bsize)
	free = stat.Bfree * uint64(stat.Bsize)
	used = total - free
	return total, used, free, nil
}

// CommandOutput runs a command and returns trimmed stdout (for fallback metric collection).
func CommandOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
