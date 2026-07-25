package proxy

import (
	"sync"
	"testing"
)

func TestPathProbeCache_New(t *testing.T) {
	c := NewPathProbeCache()
	if c == nil {
		t.Fatal("NewPathProbeCache returned nil")
	}
	if c.Count() != 0 {
		t.Errorf("Expected 0 entries, got %d", c.Count())
	}
}

func TestPathProbeCache_SetAndGet(t *testing.T) {
	c := NewPathProbeCache()
	c.Set("nodeA", "nodeB", 12.5)

	lat := c.Get("nodeA", "nodeB")
	if lat != 12.5 {
		t.Errorf("Expected 12.5, got %f", lat)
	}
}

func TestPathProbeCache_GetUnknown(t *testing.T) {
	c := NewPathProbeCache()
	lat := c.Get("unknown", "also-unknown")
	if lat != -1 {
		t.Errorf("Expected -1 for unknown pair, got %f", lat)
	}
}

func TestPathProbeCache_Overwrite(t *testing.T) {
	c := NewPathProbeCache()
	c.Set("a", "b", 10.0)
	c.Set("a", "b", 20.0)

	lat := c.Get("a", "b")
	if lat != 20.0 {
		t.Errorf("Expected 20.0 after overwrite, got %f", lat)
	}
}

func TestPathProbeCache_Directional(t *testing.T) {
	c := NewPathProbeCache()
	c.Set("a", "b", 10.0)

	// a→b has a measurement.
	if lat := c.Get("a", "b"); lat != 10.0 {
		t.Errorf("Expected 10.0 for a→b, got %f", lat)
	}

	// b→a does not (directional cache).
	if lat := c.Get("b", "a"); lat != -1 {
		t.Errorf("Expected -1 for b→a (directional), got %f", lat)
	}
}

func TestPathProbeCache_AllPairs(t *testing.T) {
	c := NewPathProbeCache()
	c.Set("a", "b", 10.0)
	c.Set("b", "c", 20.0)
	c.Set("c", "a", 30.0)

	pairs := c.AllPairs()
	if len(pairs) != 3 {
		t.Fatalf("Expected 3 pairs, got %d", len(pairs))
	}

	// Find each pair.
	found := make(map[string]float64)
	for _, p := range pairs {
		found[p.Src+"→"+p.Dst] = p.Latency
	}

	if found["a→b"] != 10.0 {
		t.Errorf("Expected a→b=10.0, got %f", found["a→b"])
	}
	if found["b→c"] != 20.0 {
		t.Errorf("Expected b→c=20.0, got %f", found["b→c"])
	}
	if found["c→a"] != 30.0 {
		t.Errorf("Expected c→a=30.0, got %f", found["c→a"])
	}
}

func TestPathProbeCache_AllPairs_Empty(t *testing.T) {
	c := NewPathProbeCache()
	pairs := c.AllPairs()
	if len(pairs) != 0 {
		t.Errorf("Expected 0 pairs for empty cache, got %d", len(pairs))
	}
}

func TestPathProbeCache_AllPairs_Snapshot(t *testing.T) {
	c := NewPathProbeCache()
	c.Set("a", "b", 10.0)

	pairs := c.AllPairs()

	// Modify the returned slice — should not affect the cache.
	pairs[0].Latency = 999.0

	lat := c.Get("a", "b")
	if lat != 10.0 {
		t.Errorf("Cache was modified by snapshot mutation: expected 10.0, got %f", lat)
	}
}

func TestPathProbeCache_Clear(t *testing.T) {
	c := NewPathProbeCache()
	c.Set("a", "b", 10.0)
	c.Set("b", "c", 20.0)

	c.Clear()

	if c.Count() != 0 {
		t.Errorf("Expected 0 after Clear, got %d", c.Count())
	}
	if lat := c.Get("a", "b"); lat != -1 {
		t.Errorf("Expected -1 after Clear, got %f", lat)
	}
}

func TestPathProbeCache_Count(t *testing.T) {
	c := NewPathProbeCache()
	if c.Count() != 0 {
		t.Errorf("Expected 0, got %d", c.Count())
	}

	c.Set("a", "b", 10.0)
	if c.Count() != 1 {
		t.Errorf("Expected 1, got %d", c.Count())
	}

	c.Set("b", "c", 20.0)
	if c.Count() != 2 {
		t.Errorf("Expected 2, got %d", c.Count())
	}

	// Overwrite existing — count should not increase.
	c.Set("a", "b", 15.0)
	if c.Count() != 2 {
		t.Errorf("Expected 2 after overwrite, got %d", c.Count())
	}
}

func TestPathProbeCache_Concurrent(t *testing.T) {
	c := NewPathProbeCache()
	var wg sync.WaitGroup

	// 10 goroutines writing concurrently.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Set(
					"node-"+string(rune('A'+idx)),
					"node-"+string(rune('A'+(idx+1)%10)),
					float64(j),
				)
			}
		}(i)
	}

	// 5 goroutines reading concurrently.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = c.Get("node-A", "node-B")
				_ = c.AllPairs()
				_ = c.Count()
			}
		}()
	}

	wg.Wait()
	// Should not panic or race.
}
