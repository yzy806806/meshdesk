package monitor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
)

// TestReporterAddCollector verifies that AddCollector adds a collector
// to the reporter's list and that duplicates are deduplicated.
func TestReporterAddCollector(t *testing.T) {
	rep := NewReporter(ReporterConfig{
		NodeID:   "test-node-1",
		Hostname: "host1",
		Dialer:   &mockDialer{},
		Interval: 300,
	})

	// Initially no collectors.
	if len(rep.Collectors()) != 0 {
		t.Fatalf("expected 0 collectors initially, got %d", len(rep.Collectors()))
	}

	// Add a collector.
	rep.AddCollector("collector-key-1")

	collectors := rep.Collectors()
	if len(collectors) != 1 {
		t.Fatalf("expected 1 collector after add, got %d", len(collectors))
	}
	if collectors[0] != "collector-key-1" {
		t.Errorf("expected collector-key-1, got %s", collectors[0])
	}

	// Add the same collector again (dedup).
	rep.AddCollector("collector-key-1")

	collectors = rep.Collectors()
	if len(collectors) != 1 {
		t.Errorf("expected 1 collector after dedup, got %d", len(collectors))
	}

	// Add a different collector.
	rep.AddCollector("collector-key-2")

	collectors = rep.Collectors()
	if len(collectors) != 2 {
		t.Errorf("expected 2 collectors, got %d", len(collectors))
	}
}

// TestReporterAddCollectorConcurrent verifies that AddCollector is safe
// for concurrent use.
func TestReporterAddCollectorConcurrent(t *testing.T) {
	rep := NewReporter(ReporterConfig{
		NodeID:   "test-node-2",
		Hostname: "host2",
		Dialer:   &mockDialer{},
		Interval: 300,
	})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep.AddCollector("same-collector-key")
		}()
	}
	wg.Wait()

	collectors := rep.Collectors()
	if len(collectors) != 1 {
		t.Errorf("expected 1 collector after 10 concurrent adds of same key, got %d", len(collectors))
	}
}

// mockDialer is a no-op dialer for testing.
type mockDialer struct{}

func (m *mockDialer) DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error) {
	return nil, fmt.Errorf("mock dialer: no real connection")
}
