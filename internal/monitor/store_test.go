package monitor

import (
	"testing"
	"time"
)

func TestStoreAppendAndLatest(t *testing.T) {
	s := NewStore()

	now := time.Now().UTC()
	m := &Metrics{NodeID: "node-1", Timestamp: now, CPU: CPUMetrics{UsagePercent: 50}}

	s.Append("node-1", m)

	latest := s.Latest("node-1")
	if latest == nil {
		t.Fatal("Latest should not be nil")
	}
	if latest.CPU.UsagePercent != 50 {
		t.Errorf("Latest CPU = %f, want 50", latest.CPU.UsagePercent)
	}

	// Unknown node
	if s.Latest("unknown") != nil {
		t.Error("Unknown node Latest should be nil")
	}
}

func TestStoreMultipleNodes(t *testing.T) {
	s := NewStore()

	now := time.Now().UTC()
	s.Append("node-a", &Metrics{NodeID: "node-a", Timestamp: now})
	s.Append("node-b", &Metrics{NodeID: "node-b", Timestamp: now})
	s.Append("node-c", &Metrics{NodeID: "node-c", Timestamp: now})

	ids := s.NodeIDs()
	if len(ids) != 3 {
		t.Fatalf("NodeIDs len = %d, want 3", len(ids))
	}
	if s.NodeCount() != 3 {
		t.Fatalf("NodeCount = %d, want 3", s.NodeCount())
	}
}

func TestStoreAllLatest(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()

	s.Append("a", &Metrics{NodeID: "a", Timestamp: now, CPU: CPUMetrics{UsagePercent: 10}})
	s.Append("b", &Metrics{NodeID: "b", Timestamp: now, CPU: CPUMetrics{UsagePercent: 20}})

	all := s.AllLatest()
	if len(all) != 2 {
		t.Fatalf("AllLatest len = %d, want 2", len(all))
	}
	if all["a"].CPU.UsagePercent != 10 {
		t.Error("AllLatest[a] wrong")
	}
	if all["b"].CPU.UsagePercent != 20 {
		t.Error("AllLatest[b] wrong")
	}
}

func TestStoreRange(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()

	for i := 0; i < 60; i++ {
		s.Append("n1", &Metrics{
			NodeID:    "n1",
			Timestamp: now.Add(time.Duration(i) * time.Minute),
		})
	}

	from := now.Add(10 * time.Minute)
	to := now.Add(20 * time.Minute)
	result := s.Range("n1", from, to)

	if len(result) != 10 {
		t.Fatalf("Range len = %d, want 10", len(result))
	}
}

func TestStoreRemoveNode(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()

	s.Append("n1", &Metrics{NodeID: "n1", Timestamp: now})
	s.Append("n2", &Metrics{NodeID: "n2", Timestamp: now})

	s.RemoveNode("n1")

	if s.Latest("n1") != nil {
		t.Error("Removed node should have nil Latest")
	}
	if s.Latest("n2") == nil {
		t.Error("Remaining node should have data")
	}
	if s.NodeCount() != 1 {
		t.Errorf("NodeCount = %d, want 1", s.NodeCount())
	}
}

func TestStoreHighResLowRes(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()

	// Add 20 samples at 1-min intervals
	for i := 0; i < 20; i++ {
		s.Append("n1", &Metrics{
			NodeID:    "n1",
			Timestamp: now.Add(time.Duration(i) * time.Minute),
		})
	}

	hr := s.HighRes("n1")
	if len(hr) != 20 {
		t.Fatalf("HighRes len = %d, want 20", len(hr))
	}

	lr := s.LowRes("n1")
	if len(lr) != 4 { // 20 / 5 = 4
		t.Fatalf("LowRes len = %d, want 4", len(lr))
	}
}

func TestStoreUnknownNode(t *testing.T) {
	s := NewStore()

	if s.HighRes("unknown") != nil {
		t.Error("HighRes unknown should be nil")
	}
	if s.LowRes("unknown") != nil {
		t.Error("LowRes unknown should be nil")
	}
	if s.Range("unknown", time.Time{}, time.Time{}) != nil {
		t.Error("Range unknown should be nil")
	}
}
