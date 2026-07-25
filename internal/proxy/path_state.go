// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements PathProbeCache — a concurrency-safe cache of
// last-known inter-node latency measurements. It is populated by the
// path selector's probe loop and consumed by the topology API via
// the TopologyPathInfo interface adapter in the web package.
//
// This is the ONLY coupling point between the proxy package and the
// topology visualization system. The proxy package does not import
// internal/topology; instead, the web layer's adapter calls AllPairs()
// to build edge data.

package proxy

import "sync"

// PathProbeCache is a concurrency-safe cache of last-known inter-node
// latency measurements. It is populated by the path selector's probe
// loop and consumed by the topology API via the TopologyPathInfo
// interface adapter.
//
// Usage:
//   - The path selector calls Set(src, dst, rtt) after each probe.
//   - The topology handler calls Get(src, dst) or AllPairs() to read.
//
// This type is safe for concurrent use by multiple goroutines.
type PathProbeCache struct {
	mu        sync.RWMutex
	latencies map[pairKey]float64 // (src, dst) → RTT in ms
}

// pairKey is an ordered pair of node IDs used as the map key.
// Latency is directional in the cache (src→dst) to support asymmetric
// measurements, though in practice RTT is symmetric.
type pairKey struct {
	src, dst string
}

// PathLatency is a single measured latency pair returned by AllPairs.
type PathLatency struct {
	Src     string
	Dst     string
	Latency float64 // RTT in milliseconds
}

// NewPathProbeCache creates a new empty probe cache.
func NewPathProbeCache() *PathProbeCache {
	return &PathProbeCache{
		latencies: make(map[pairKey]float64),
	}
}

// Set records a latency measurement (RTT in milliseconds) for the
// directed pair (src → dst). Overwrites any previous value.
func (c *PathProbeCache) Set(src, dst string, latencyMs float64) {
	c.mu.Lock()
	c.latencies[pairKey{src, dst}] = latencyMs
	c.mu.Unlock()
}

// Get returns the last-known latency for the directed pair (src → dst),
// or -1 if no measurement exists.
func (c *PathProbeCache) Get(src, dst string) float64 {
	c.mu.RLock()
	lat, ok := c.latencies[pairKey{src, dst}]
	c.mu.RUnlock()
	if !ok {
		return -1
	}
	return lat
}

// AllPairs returns all measured pairs as (src, dst, latency) triples.
// This is the stable read API for the topology layer.
// The returned slice is a snapshot; the caller may sort or modify it
// without affecting the cache.
func (c *PathProbeCache) AllPairs() []PathLatency {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]PathLatency, 0, len(c.latencies))
	for k, v := range c.latencies {
		result = append(result, PathLatency{
			Src:     k.src,
			Dst:     k.dst,
			Latency: v,
		})
	}
	return result
}

// Clear removes all entries from the cache.
func (c *PathProbeCache) Clear() {
	c.mu.Lock()
	c.latencies = make(map[pairKey]float64)
	c.mu.Unlock()
}

// Count returns the number of measured pairs in the cache.
func (c *PathProbeCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.latencies)
}
