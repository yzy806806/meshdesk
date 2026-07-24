package monitor

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMetricsEncodeDecode(t *testing.T) {
	original := &Metrics{
		Timestamp: time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC),
		NodeID:   "abc123",
		Hostname: "test-node",
		CPU: CPUMetrics{
			UsagePercent: 45.5,
			PerCore:      []float64{40.0, 51.0},
			CoreCount:     2,
		},
		Memory: MemoryMetrics{
			Total:     8589934592, // 8 GB
			Used:      4294967296, // 4 GB
			Available: 4294967296,
		},
		Disk: []DiskMetrics{
			{Device: "/dev/sda1", MountPoint: "/", FSType: "ext4", Total: 107374182400, Used: 53687091200, Free: 53687091200},
		},
		Network: []NetMetrics{
			{Name: "eth0", RxBytes: 1000000, TxBytes: 2000000},
		},
		LoadAvg: LoadAvgMetrics{Load1: 0.5, Load5: 0.3, Load15: 0.1},
		Uptime:  3600,
	}

	data, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodeMetrics(data)
	if err != nil {
		t.Fatalf("DecodeMetrics failed: %v", err)
	}

	if decoded.NodeID != original.NodeID {
		t.Errorf("NodeID mismatch: got %s, want %s", decoded.NodeID, original.NodeID)
	}
	if decoded.CPU.UsagePercent != original.CPU.UsagePercent {
		t.Errorf("CPU.UsagePercent mismatch: got %f, want %f", decoded.CPU.UsagePercent, original.CPU.UsagePercent)
	}
	if decoded.Memory.Total != original.Memory.Total {
		t.Errorf("Memory.Total mismatch: got %d, want %d", decoded.Memory.Total, original.Memory.Total)
	}
	if len(decoded.Disk) != 1 || decoded.Disk[0].MountPoint != "/" {
		t.Errorf("Disk mismatch: %+v", decoded.Disk)
	}
	if decoded.Uptime != original.Uptime {
		t.Errorf("Uptime mismatch: got %d, want %d", decoded.Uptime, original.Uptime)
	}
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("Timestamp mismatch: got %v, want %v", decoded.Timestamp, original.Timestamp)
	}
}

func TestMetricEnvelopeJSON(t *testing.T) {
	env := &MetricEnvelope{
		SourceID: "node-1",
		Sequence: 42,
		Metrics: &Metrics{
			NodeID: "node-1",
			CPU:    CPUMetrics{UsagePercent: 50.0, CoreCount: 4},
		},
	}

	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded MetricEnvelope
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.SourceID != env.SourceID || decoded.Sequence != env.Sequence {
		t.Errorf("Envelope mismatch: %+v", decoded)
	}
	if decoded.Metrics == nil || decoded.Metrics.CPU.CoreCount != 4 {
		t.Errorf("Metrics mismatch: %+v", decoded.Metrics)
	}
}

func TestDecodeMetricsInvalid(t *testing.T) {
	_, err := DecodeMetrics([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}

	_, err = DecodeMetrics([]byte(`{"node_id":"test"}`))
	if err != nil {
		t.Errorf("partial decode should not error: %v", err)
	}
}
