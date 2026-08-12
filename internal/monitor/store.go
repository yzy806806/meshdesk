package monitor

import (
	"bytes"
	"compress/gzip"
	"io"

	"encoding/json"
	"os"
	"sync"
	"time"
)

// Store manages ring buffers for multiple nodes. On a collector node,
// it holds the aggregated metrics from all reporting agents. On an
// agent node, it holds the local replica (self-metrics + buffered
// metrics during collector outage).
type Store struct {
	mu       sync.RWMutex
	buffers  map[string]*RingBuffer // nodeID → ring buffer
	lastSeen map[string]time.Time   // nodeID → last update time
}

// NewStore creates an empty multi-node metrics store.
func NewStore() *Store {
	return &Store{
		buffers:  make(map[string]*RingBuffer),
		lastSeen: make(map[string]time.Time),
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
	s.lastSeen[nodeID] = time.Now()
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
	delete(s.lastSeen, nodeID)
	s.mu.Unlock()
}

// RemoveStaleNodes removes all nodes whose last update is older than
// the given threshold. This prevents unbounded growth when nodes leave
// the mesh permanently. Returns the number of nodes removed.
func (s *Store) RemoveStaleNodes(threshold time.Duration) int {
	cutoff := time.Now().Add(-threshold)
	s.mu.Lock()
	removed := 0
	for id, seen := range s.lastSeen {
		if seen.Before(cutoff) {
			delete(s.buffers, id)
			delete(s.lastSeen, id)
			removed++
		}
	}
	s.mu.Unlock()
	return removed
}

// NodeCount returns the number of nodes with stored metrics.
func (s *Store) NodeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.buffers)
}

// Persist writes all buffered metrics to a JSON file (T4.2). Used for
// keeping monitoring history across restarts.
func (s *Store) Persist(path string) error {
	s.mu.RLock()
	snapshot := make(map[string][]*Metrics, len(s.buffers))
	for id, buf := range s.buffers {
		snapshot[id] = buf.Snapshot()
	}
	s.mu.RUnlock()

	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	// gzip-compress the history file (JSON compresses well; the raw
	// dump was ~130MB for 6 nodes, gzip cuts it to ~15MB).
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// Load restores buffered metrics from a (possibly gzip-compressed) JSON
// file produced by Persist. Plain-JSON files from older versions are
// detected by magic and still load.
func (s *Store) Load(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	data := raw
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b { // gzip magic
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		data, err = io.ReadAll(zr)
		zr.Close()
		if err != nil {
			return err
		}
	}
	var snapshot map[string][]*Metrics
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, samples := range snapshot {
		buf := NewRingBuffer()
		for _, m := range samples {
			if m != nil {
				buf.Append(m)
			}
		}
		if buf.Len() > 0 {
			s.buffers[id] = buf
			s.lastSeen[id] = time.Now()
		}
	}
	return nil
}
