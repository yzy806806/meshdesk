package monitor

import (
	"sync"
	"time"
)

// Store manages ring buffers for multiple nodes. On a collector node,
// it holds the aggregated metrics from all reporting agents. On an
// agent node, it holds the local replica (self-metrics + buffered
// metrics during collector outage).
type Store struct {
	mu      sync.RWMutex
	buffers map[string]*RingBuffer // nodeID → ring buffer
}

// NewStore creates an empty multi-node metrics store.
func NewStore() *Store {
	return &Store{
		buffers: make(map[string]*RingBuffer),
	}
}

// Append stores a metrics sample for the given node.
func (s *Store) Append(nodeID string, m *Metrics) {
	s.mu.Lock()
	buf, ok := s.buffers[nodeID]
	if !ok {
		buf = NewRingBuffer()
		s.buffers[nodeID] = buf
	}
	s.mu.Unlock()
	buf.Append(m)
}

// Latest returns the most recent metrics for a node, or nil if unknown.
func (s *Store) Latest(nodeID string) *Metrics {
	s.mu.RLock()
	buf, ok := s.buffers[nodeID]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	return buf.Latest()
}

// NodeIDs returns the IDs of all nodes with stored metrics.
func (s *Store) NodeIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.buffers))
	for id := range s.buffers {
		ids = append(ids, id)
	}
	return ids
}

// Range returns high-res samples for a node within [from, to).
func (s *Store) Range(nodeID string, from, to time.Time) []*Metrics {
	s.mu.RLock()
	buf, ok := s.buffers[nodeID]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	return buf.Range(from, to)
}

// AllLatest returns the most recent metrics for every known node.
// This is the primary API for the dashboard to render the node overview.
func (s *Store) AllLatest() map[string]*Metrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*Metrics, len(s.buffers))
	for id, buf := range s.buffers {
		if m := buf.Latest(); m != nil {
			result[id] = m
		}
	}
	return result
}

// AllLatestFlat is the same data as AllLatest but as a slice (sorted by caller).
func (s *Store) AllLatestFlat() []*Metrics {
	all := s.AllLatest()
	result := make([]*Metrics, 0, len(all))
	for _, m := range all {
		result = append(result, m)
	}
	return result
}

// HighRes returns all high-res samples for the given node.
func (s *Store) HighRes(nodeID string) []*Metrics {
	s.mu.RLock()
	buf, ok := s.buffers[nodeID]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	return buf.HighRes()
}

// LowRes returns all low-res samples for the given node.
func (s *Store) LowRes(nodeID string) []*Metrics {
	s.mu.RLock()
	buf, ok := s.buffers[nodeID]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	return buf.LowRes()
}

// RemoveNode removes all stored data for a node (e.g., after revocation).
func (s *Store) RemoveNode(nodeID string) {
	s.mu.Lock()
	delete(s.buffers, nodeID)
	s.mu.Unlock()
}

// NodeCount returns the number of nodes with stored metrics.
func (s *Store) NodeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.buffers)
}
