package monitor

import (
	"testing"
	"time"
)

func TestRingBufferAppendAndLatest(t *testing.T) {
	rb := NewRingBuffer()

	if rb.Len() != 0 {
		t.Fatalf("empty buffer Len = %d, want 0", rb.Len())
	}
	if rb.Latest() != nil {
		t.Fatal("empty buffer Latest should be nil")
	}

	now := time.Now().UTC()
	m1 := &Metrics{NodeID: "n1", Timestamp: now, CPU: CPUMetrics{UsagePercent: 10}}
	rb.Append(m1)

	if rb.Len() != 1 {
		t.Fatalf("Len = %d, want 1", rb.Len())
	}
	latest := rb.Latest()
	if latest == nil || latest.CPU.UsagePercent != 10 {
		t.Fatalf("Latest = %+v, want 10%%", latest)
	}

	m2 := &Metrics{NodeID: "n1", Timestamp: now.Add(time.Minute), CPU: CPUMetrics{UsagePercent: 20}}
	rb.Append(m2)

	if rb.Len() != 2 {
		t.Fatalf("Len = %d, want 2", rb.Len())
	}
	latest = rb.Latest()
	if latest.CPU.UsagePercent != 20 {
		t.Fatalf("Latest = %+v, want 20%%", latest)
	}
}

func TestRingBufferHighRes(t *testing.T) {
	rb := NewRingBuffer()
	now := time.Now().UTC()

	for i := 0; i < 10; i++ {
		rb.Append(&Metrics{
			NodeID:    "n1",
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			CPU:       CPUMetrics{UsagePercent: float64(i)},
		})
	}

	hr := rb.HighRes()
	if len(hr) != 10 {
		t.Fatalf("HighRes len = %d, want 10", len(hr))
	}
	// Verify chronological order
	for i, m := range hr {
		if m.CPU.UsagePercent != float64(i) {
			t.Errorf("HighRes[%d] = %f, want %d", i, m.CPU.UsagePercent, i)
		}
	}
}

func TestRingBufferLowResPromotion(t *testing.T) {
	rb := NewRingBuffer()
	now := time.Now().UTC()

	// Add 15 samples at 1-minute intervals. Low-res should have
	// ceil(15 / 5) = 3 entries (at minutes 0, 5, 10).
	for i := 0; i < 15; i++ {
		rb.Append(&Metrics{
			NodeID:    "n1",
			Timestamp: now.Add(time.Duration(i) * time.Minute),
		})
	}

	hr := rb.HighRes()
	if len(hr) != 15 {
		t.Fatalf("HighRes len = %d, want 15", len(hr))
	}

	lr := rb.LowRes()
	if len(lr) != 3 {
		t.Fatalf("LowRes len = %d, want 3", len(lr))
	}
}

func TestRingBufferWraparound(t *testing.T) {
	rb := NewRingBuffer()
	now := time.Now().UTC()

	// Add more samples than high-res capacity to test wraparound.
	total := highResSlots + 50
	for i := 0; i < total; i++ {
		rb.Append(&Metrics{
			NodeID:    "n1",
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			CPU:       CPUMetrics{UsagePercent: float64(i)},
		})
	}

	if rb.Len() != highResSlots {
		t.Fatalf("Len after wraparound = %d, want %d", rb.Len(), highResSlots)
	}

	hr := rb.HighRes()
	if len(hr) != highResSlots {
		t.Fatalf("HighRes len = %d, want %d", len(hr), highResSlots)
	}

	// The oldest entry should be the one right after wraparound starts,
	// i.e., index (total - highResSlots) in the original sequence.
	// That's sample #50.
	if hr[0].CPU.UsagePercent != 50 {
		t.Errorf("oldest after wraparound = %f, want 50", hr[0].CPU.UsagePercent)
	}

	// The newest should be sample #(total-1) = #(highResSlots+49)
	if hr[len(hr)-1].CPU.UsagePercent != float64(total-1) {
		t.Errorf("newest after wraparound = %f, want %d", hr[len(hr)-1].CPU.UsagePercent, total-1)
	}
}

func TestRingBufferRange(t *testing.T) {
	rb := NewRingBuffer()
	now := time.Now().UTC()

	for i := 0; i < 60; i++ {
		rb.Append(&Metrics{
			NodeID:    "n1",
			Timestamp: now.Add(time.Duration(i) * time.Minute),
		})
	}

	// Range from minute 10 to minute 20
	from := now.Add(10 * time.Minute)
	to := now.Add(20 * time.Minute)
	result := rb.Range(from, to)

	if len(result) != 10 {
		t.Fatalf("Range len = %d, want 10", len(result))
	}
	for _, m := range result {
		if m.Timestamp.Before(from) || !m.Timestamp.Before(to) {
			t.Errorf("Range result out of bounds: %v", m.Timestamp)
		}
	}

	// Range from 0 (all)
	result = rb.Range(time.Time{}, time.Time{})
	if len(result) != 60 {
		t.Fatalf("Range all len = %d, want 60", len(result))
	}
}

func TestRingBufferClear(t *testing.T) {
	rb := NewRingBuffer()
	rb.Append(&Metrics{NodeID: "n1", Timestamp: time.Now().UTC()})
	rb.Append(&Metrics{NodeID: "n1", Timestamp: time.Now().UTC()})

	if rb.Len() != 2 {
		t.Fatalf("Len = %d, want 2", rb.Len())
	}

	rb.Clear()

	if rb.Len() != 0 {
		t.Fatalf("Len after Clear = %d, want 0", rb.Len())
	}
	if rb.Latest() != nil {
		t.Fatal("Latest after Clear should be nil")
	}
}

func TestRingBufferNilAndZeroTS(t *testing.T) {
	rb := NewRingBuffer()
	rb.Append(nil)
	rb.Append(&Metrics{NodeID: "n1", Timestamp: time.Time{}})

	if rb.Len() != 0 {
		t.Fatalf("Len after nil/zero append = %d, want 0", rb.Len())
	}
}
