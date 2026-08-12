package monitor

import (
	"sync"
	"time"
)

// RingBuffer is a two-tier time-series buffer for monitoring data.
//
// Tier 1 (high-resolution): 1-minute resolution, 24 hours = 1440 slots.
// Tier 2 (low-resolution):  5-minute resolution, 7 days = 2016 slots.
//
// Data is stored in pre-allocated circular arrays for O(1) append and
// O(n) sequential scan. Memory usage is bounded and known at construction.
type RingBuffer struct {
	mu sync.RWMutex

	// High-resolution tier: 1 point per minute, 24h.
	highRes     [highResSlots]*Metrics
	highResHead int // next write position
	highResLen  int // number of valid entries

	// Low-resolution tier: 1 point per 5 minutes, 7d.
	// Each low-res slot stores the last sample in its 5-minute window.
	lowRes     [lowResSlots]*Metrics
	lowResHead int
	lowResLen  int

	// lastHighResTS tracks the timestamp of the last high-res entry
	// to decide when to promote to low-res.
	lastHighResTS time.Time
}

const (
	highResSlots      = 12 * 60     // 720 — one per minute for 12 hours (memory/disk tradeoff)
	lowResSlots       = 7 * 24 * 12 // 2016 — one per 5 min for 7 days
	highResResolution = 1 * time.Minute
	lowResResolution  = 5 * time.Minute
)

// NewRingBuffer creates a new empty ring buffer.
func NewRingBuffer() *RingBuffer {
	return &RingBuffer{}
}

// Append adds a metrics sample to the ring buffer.
// The sample is placed in the high-res tier; when enough time has passed
// (lowResResolution since the last low-res write), it is also promoted
// to the low-res tier.
func (rb *RingBuffer) Append(m *Metrics) {
	if m == nil || m.Timestamp.IsZero() {
		return
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Write to high-res tier.
	rb.highRes[rb.highResHead] = m
	rb.highResHead = (rb.highResHead + 1) % highResSlots
	if rb.highResLen < highResSlots {
		rb.highResLen++
	}

	// Promote to low-res tier if lowResResolution has elapsed since last promotion.
	if rb.lastHighResTS.IsZero() || m.Timestamp.Sub(rb.lastHighResTS) >= lowResResolution {
		rb.lowRes[rb.lowResHead] = m
		rb.lowResHead = (rb.lowResHead + 1) % lowResSlots
		if rb.lowResLen < lowResSlots {
			rb.lowResLen++
		}
		rb.lastHighResTS = m.Timestamp
	}
}

// Latest returns the most recent metrics sample, or nil if empty.
func (rb *RingBuffer) Latest() *Metrics {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.highResLen == 0 {
		return nil
	}
	// The latest entry is at (head - 1 + slots) % slots
	idx := (rb.highResHead - 1 + highResSlots) % highResSlots
	return rb.highRes[idx]
}

// HighRes returns all high-resolution samples in chronological order.
// The slice is a copy; callers can modify it freely.
func (rb *RingBuffer) HighRes() []*Metrics {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	result := make([]*Metrics, 0, rb.highResLen)
	start := (rb.highResHead - rb.highResLen + highResSlots) % highResSlots
	for i := 0; i < rb.highResLen; i++ {
		idx := (start + i) % highResSlots
		if rb.highRes[idx] != nil {
			result = append(result, rb.highRes[idx])
		}
	}
	return result
}

// LowRes returns all low-resolution samples in chronological order.
func (rb *RingBuffer) LowRes() []*Metrics {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	result := make([]*Metrics, 0, rb.lowResLen)
	start := (rb.lowResHead - rb.lowResLen + lowResSlots) % lowResSlots
	for i := 0; i < rb.lowResLen; i++ {
		idx := (start + i) % lowResSlots
		if rb.lowRes[idx] != nil {
			result = append(result, rb.lowRes[idx])
		}
	}
	return result
}

// Range returns samples within [from, to) from the high-res tier.
// If from is zero, returns from the oldest available; if to is zero,
// returns up to the newest.
func (rb *RingBuffer) Range(from, to time.Time) []*Metrics {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	result := make([]*Metrics, 0, rb.highResLen)
	start := (rb.highResHead - rb.highResLen + highResSlots) % highResSlots
	for i := 0; i < rb.highResLen; i++ {
		idx := (start + i) % highResSlots
		m := rb.highRes[idx]
		if m == nil {
			continue
		}
		if !from.IsZero() && m.Timestamp.Before(from) {
			continue
		}
		if !to.IsZero() && !m.Timestamp.Before(to) {
			break
		}
		result = append(result, m)
	}
	return result
}

// Len returns the number of high-resolution samples stored.
func (rb *RingBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.highResLen
}

// LowResLen returns the number of low-resolution samples stored.
func (rb *RingBuffer) LowResLen() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.lowResLen
}

// Clear empties the ring buffer.
func (rb *RingBuffer) Clear() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for i := range rb.highRes {
		rb.highRes[i] = nil
	}
	for i := range rb.lowRes {
		rb.lowRes[i] = nil
	}
	rb.highResHead = 0
	rb.highResLen = 0
	rb.lowResHead = 0
	rb.lowResLen = 0
	rb.lastHighResTS = time.Time{}
}

// Snapshot returns a copy of buffered samples (for persistence):
// high-res tier + low-res tier merged.
func (rb *RingBuffer) Snapshot() []*Metrics {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	seen := make(map[int64]bool)
	out := make([]*Metrics, 0, rb.highResLen+rb.lowResLen)
	for _, m := range rb.highRes {
		if m != nil && !seen[m.Timestamp.Unix()] {
			seen[m.Timestamp.Unix()] = true
			out = append(out, m)
		}
	}
	for _, m := range rb.lowRes {
		if m != nil && !seen[m.Timestamp.Unix()] {
			seen[m.Timestamp.Unix()] = true
			out = append(out, m)
		}
	}
	return out
}
