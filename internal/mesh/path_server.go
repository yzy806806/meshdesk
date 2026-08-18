package mesh

import (
	"container/heap"
	"sync"
	"time"
)

// LatencyGraph is a global, time-stamped directed graph of measured
// RTTs between mesh nodes. It is populated from monitor reports
// (Metrics.PeerLatency) and inter-shared-node sync.
//
// Each entry stores the RTT from source → target and the timestamp
// of the report, so stale edges can be pruned.
type LatencyGraph struct {
	mu      sync.RWMutex
	entries map[string]map[string]rttEntry // source → {target → entry}
}

type rttEntry struct {
	rtt       int       // milliseconds
	timestamp time.Time // when the report was received
	zone      string   // target's zone (if known)
}

// NewLatencyGraph creates an empty latency graph.
func NewLatencyGraph() *LatencyGraph {
	return &LatencyGraph{
		entries: make(map[string]map[string]rttEntry),
	}
}

// UpdateFromReport merges a single node's PeerLatency report into
// the graph. Called when a monitor report with PeerLatency is
// received (on the shared node).
func (g *LatencyGraph) UpdateFromReport(sourceKey string, latency map[string]int, zone string) {
	if sourceKey == "" || len(latency) == 0 {
		return
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	// Replace all edges from source (stale edges removed).
	g.entries[sourceKey] = make(map[string]rttEntry, len(latency))
	for target, rtt := range latency {
		if rtt > 0 {
			g.entries[sourceKey][target] = rttEntry{
				rtt:       rtt,
				timestamp: now,
				zone:      zone,
			}
		}
	}
}

// MergeFromSync merges edges received from another shared node.
// Only newer entries overwrite existing ones.
func (g *LatencyGraph) MergeFromSync(remote map[string]map[string]rttEntry) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for src, targets := range remote {
		if g.entries[src] == nil {
			g.entries[src] = make(map[string]rttEntry)
		}
		for dst, entry := range targets {
			existing, ok := g.entries[src][dst]
			if !ok || entry.timestamp.After(existing.timestamp) {
				g.entries[src][dst] = entry
			}
		}
	}
}

// PruneStaleEdges removes all edges whose timestamp is older than
// maxAge. Called periodically to clean up entries from nodes that
// have gone offline (their monitor reports stopped arriving).
func (g *LatencyGraph) PruneStaleEdges(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	g.mu.Lock()
	defer g.mu.Unlock()
	for src, targets := range g.entries {
		staleCount := 0
		for dst, entry := range targets {
			if entry.timestamp.Before(cutoff) {
				delete(targets, dst)
				staleCount++
			}
		}
		// If all edges from a source are stale, remove the source entirely.
		if len(targets) == 0 {
			delete(g.entries, src)
		}
	}
}


// ExportForSync returns the full graph for synchronisation to a
// peer shared node. The caller should send this via META or a
// dedicated virtual port.
func (g *LatencyGraph) ExportForSync() map[string]map[string]rttEntry {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make(map[string]map[string]rttEntry, len(g.entries))
	for src, targets := range g.entries {
		out[src] = make(map[string]rttEntry, len(targets))
		for dst, entry := range targets {
			out[src][dst] = entry
		}
	}
	return out
}

// AllEdges returns all (source, target, rtt) triples. Used by the
// Dashboard topology view to draw latency-weighted edges.
func (g *LatencyGraph) AllEdges() []GraphEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var edges []GraphEdge
	for src, targets := range g.entries {
		for dst, entry := range targets {
			edges = append(edges, GraphEdge{
				Source: src,
				Target: dst,
				RTT:    entry.rtt,
				Zone:   entry.zone,
			})
		}
	}
	return edges
}

// GraphEdge represents a single measured latency edge in the graph.
type GraphEdge struct {
	Source string
	Target string
	RTT    int
	Zone   string
}

// QueryPath returns the lowest-total-latency path from source to
// target using Dijkstra's algorithm on the latency graph. The path
// is returned as an ordered list of peer keys:
//
//	[result[0]=source, result[1]=first relay, ..., result[n]=target]
//
// If no path exists (graph disconnected for this pair), returns nil.
// The source is always included; a direct edge (source→target) is
// preferred (path length 2: [source, target]).
func (g *LatencyGraph) QueryPath(source, target string) []string {
	if source == "" || target == "" || source == target {
		return nil
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	// Dijkstra: shortest path by total RTT.
	dist := make(map[string]int)
	prev := make(map[string]string)
	visited := make(map[string]bool)

	// Priority queue (min-heap by distance).
	pq := &nodeHeap{}
	heap.Init(pq)

	dist[source] = 0
	heap.Push(pq, &heapItem{key: source, dist: 0})

	// Collect all reachable nodes from source's adjacency.
	// We don't know all nodes upfront; Dijkstra discovers them
	// as it relaxes edges. Nodes with no outgoing edges that
	// are targets of edges are also reachable.
	adjacency := g.adjacencyLocked()

	maxHops := 4 // bound to prevent infinite loops in malformed graphs
	hopCount := make(map[string]int)

	for pq.Len() > 0 {
		cur := heap.Pop(pq).(*heapItem)
		if visited[cur.key] {
			continue
		}
		visited[cur.key] = true

		if cur.key == target {
			// Reconstruct path.
			path := []string{target}
			for p, ok := prev[target]; ok; p, ok = prev[p] {
				path = append([]string{p}, path...)
			}
			return path
		}

		// Relax neighbours.
		for neighbor, edge := range adjacency[cur.key] {
			if visited[neighbor] {
				continue
			}
			if hopCount[cur.key] >= maxHops {
				continue
			}
			newDist := dist[cur.key] + edge.rtt
			oldDist, exists := dist[neighbor]
			if !exists || newDist < oldDist {
				dist[neighbor] = newDist
				prev[neighbor] = cur.key
				hopCount[neighbor] = hopCount[cur.key] + 1
				heap.Push(pq, &heapItem{key: neighbor, dist: newDist})
			}
		}
	}

	return nil // no path found
}

// adjacencyLocked builds a flat adjacency map from the nested entries.
// Must be called under RLock.
func (g *LatencyGraph) adjacencyLocked() map[string]map[string]rttEntry {
	// entries is already the adjacency list; return a shallow copy
	// to avoid mutations during iteration.
	out := make(map[string]map[string]rttEntry, len(g.entries))
	for src, targets := range g.entries {
		out[src] = targets
	}
	return out
}

// --- Min-heap for Dijkstra ---

type heapItem struct {
	key  string
	dist int
}

type nodeHeap []*heapItem

func (h nodeHeap) Len() int           { return len(h) }
func (h nodeHeap) Less(i, j int) bool  { return h[i].dist < h[j].dist }
func (h nodeHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *nodeHeap) Push(x interface{}) { *h = append(*h, x.(*heapItem)) }
func (h *nodeHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}
