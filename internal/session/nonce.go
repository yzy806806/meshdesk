package session

import (
	"sync"
	"time"
)

// MaxNonceCache is the maximum number of recent nonces tracked per
// responder. When the cache is full, the oldest entry is evicted.
// At ~10 key exchanges per second, 1024 entries cover ~100 seconds
// of history — far longer than any realistic replay window.
const MaxNonceCache = 1024

// nonceCache is a thread-safe bounded set of recently seen nonces.
// It prevents replay attacks by tracking nonces that have already been
// processed. When the cache reaches its capacity, the oldest entry
// is evicted (FIFO order), maintaining a sliding window of recent nonces.
//
// The cache is keyed by [32]byte (the full nonce), not a hash. At
// 32 bytes per key and 1024 entries, the total memory is ~32KB —
// negligible for a per-responder cache.
type nonceCache struct {
	mu    sync.Mutex
	seen  map[[32]byte]int64 // nonce → unix timestamp (seconds)
	order [][32]byte         // FIFO eviction queue
	max   int                // maximum entries (default: MaxNonceCache)
}

// newNonceCache creates a nonceCache with the given capacity.
// If size is 0 or negative, MaxNonceCache is used.
func newNonceCache(size int) *nonceCache {
	if size <= 0 {
		size = MaxNonceCache
	}
	return &nonceCache{
		seen:  make(map[[32]byte]int64, size),
		order: make([][32]byte, 0, size),
		max:   size,
	}
}

// checkAndRecord returns true if the nonce has NOT been seen before
// (and records it). Returns false if the nonce is a replay (already
// in the cache).
//
// This method is thread-safe and designed for concurrent access from
// multiple ServerKeyExchange goroutines. The mutex serializes all
// check-and-record operations, ensuring that a nonce cannot be
// accepted twice even under high concurrency.
//
// Eviction is FIFO: when the cache is full, the oldest entry is
// removed before the new one is inserted.
func (c *nonceCache) checkAndRecord(nonce [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already seen (replay detection).
	if _, ok := c.seen[nonce]; ok {
		return false
	}

	// Evict oldest if at capacity.
	if len(c.order) >= c.max {
		oldest := c.order[0]
		delete(c.seen, oldest)
		c.order = c.order[1:]
	}

	// Record the new nonce.
	c.seen[nonce] = time.Now().Unix()
	c.order = append(c.order, nonce)

	return true
}
