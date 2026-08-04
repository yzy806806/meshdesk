package monitor

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// AuthChecker is the interface for capability-based authorization of
// incoming metric pushes. In production this is implemented by wrapping
// *auth.CapabilityEngine. The aggregator calls AuthorizeMonitorWrite
// before accepting any metric data, enforcing Decision E (zero-trust).
//
// If the checker is nil, all peers are accepted (for testing only).
// In production, always set an auth checker.
type AuthChecker interface {
	// AuthorizeMonitorWrite checks whether sourcePeer is authorized to
	// push monitoring data. Returns true if allowed, false otherwise.
	// Every call should produce an audit log entry.
	AuthorizeMonitorWrite(sourcePeer string) bool
}

// CollectorLister enumerates collector-capable peers known to the mesh.
// The aggregator uses this to forward received metric envelopes to other
// collector nodes so that every collector has visibility into all metrics.
// In production this is backed by the gossip layer's GetCollectorCandidates.
type CollectorLister interface {
	// CollectorPeerIDs returns the peer IDs of all known collector-capable
	// nodes (excluding the local node, which the caller filters out).
	CollectorPeerIDs() []string
}

// Aggregator runs on collector nodes (nodes with --web or designated aggregators).
// It listens on a mesh-internal port for incoming metric pushes from agents,
// validates them, and stores them in the local Store for dashboard consumption.
type Aggregator struct {
	store  *Store
	dialer MeshListener // listens for mesh-internal connections
	port   int

	// meshDialer is used to forward received metric envelopes to other
	// collector nodes. If nil, forwarding is disabled (the aggregator
	// only stores metrics locally). Set via AggregatorConfig.MeshDialer.
	meshDialer MeshDialer

	// collectorLister enumerates other collector-capable peers in the mesh.
	// The aggregator forwards non-forwarded envelopes to these peers.
	// If nil, forwarding is disabled even if meshDialer is set.
	collectorLister CollectorLister

	// selfPeerID is the local node's peer ID, used to skip self when
	// forwarding envelopes to other collectors.
	selfPeerID string

	authChecker AuthChecker

	// Dedup: track highest sequence seen per source to avoid storing
	// the same (SourceID, Sequence) pair twice (e.g., direct push +
	// forwarded copy from another collector).
	dedup   map[string]uint64 // sourceID → last sequence
	dedupMu sync.Mutex

	// dedupLastSeen tracks when each sourceID was last updated, for
	// periodic cleanup of stale entries (prevents unbounded growth).
	dedupLastSeen        map[string]time.Time
	dedupCleanupInterval time.Duration // zero = default 1h
	staleThreshold       time.Duration // zero = default 2*cleanupInterval

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// MeshListener abstracts the mesh network's listen capability. In production
// this wraps mesh.MeshNode.Net().ListenTCPAddrPort(). The interface allows
// testing without a real mesh.
type MeshListener interface {
	// ListenMesh returns a net.Listener that accepts mesh-internal TCP connections.
	ListenMesh(port int) (net.Listener, error)
}

// AggregatorConfig holds the parameters for creating an Aggregator.
type AggregatorConfig struct {
	Store  *Store
	Dialer MeshListener
	Port   int

	// MeshDialer, if set, enables the aggregator to forward received
	// metric envelopes to other collector nodes. If nil, the aggregator
	// only stores metrics locally (no forwarding).
	MeshDialer MeshDialer

	// CollectorLister, if set, provides the list of other collector peer
	// IDs to forward envelopes to. Forwarding is enabled only when both
	// MeshDialer and CollectorLister are non-nil.
	CollectorLister CollectorLister

	// SelfPeerID is the local node's peer ID. The aggregator skips this
	// ID when forwarding to avoid sending envelopes back to itself.
	SelfPeerID string

	// AuthChecker, if set, requires every incoming metric push to
	// pass a capability check (Decision E). If nil, all pushes are
	// accepted (testing mode only).
	AuthChecker AuthChecker
}

// NewAggregator creates an aggregator that receives metric pushes.
func NewAggregator(cfg AggregatorConfig) *Aggregator {
	port := cfg.Port
	if port == 0 {
		port = DefaultMonitorPort
	}
	store := cfg.Store
	if store == nil {
		store = NewStore()
	}
	return &Aggregator{
		store:           store,
		dialer:          cfg.Dialer,
		port:            port,
		meshDialer:      cfg.MeshDialer,
		collectorLister: cfg.CollectorLister,
		selfPeerID:      cfg.SelfPeerID,
		authChecker:     cfg.AuthChecker,
		dedup:           make(map[string]uint64),
		stopCh:          make(chan struct{}),
	}
}

// Store returns the aggregator's metrics store (for the web dashboard).
func (a *Aggregator) Store() *Store {
	return a.store
}

// Start begins listening for metric pushes on the mesh.
func (a *Aggregator) Start() error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("aggregator already running")
	}
	a.running = true
	a.stopCh = make(chan struct{})
	if a.dedup == nil {
		a.dedup = make(map[string]uint64)
	}
	if a.dedupLastSeen == nil {
		a.dedupLastSeen = make(map[string]time.Time)
	}
	cleanupInterval := a.dedupCleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = time.Hour
	}
	staleThreshold := a.staleThreshold
	if staleThreshold == 0 {
		staleThreshold = 2 * cleanupInterval
	}
	a.staleThreshold = staleThreshold
	a.mu.Unlock()

	ln, err := a.dialer.ListenMesh(a.port)
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", a.port, err)
	}

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.acceptLoop(ln)
	}()

	// Periodic cleanup of stale dedup entries to prevent unbounded growth.
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				a.cleanupDedup()
			case <-a.stopCh:
				return
			}
		}
	}()

	return nil
}

// Stop halts the aggregator.
func (a *Aggregator) Stop() {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return
	}
	a.running = false
	close(a.stopCh)
	a.mu.Unlock()
	a.wg.Wait()
}

// acceptLoop accepts incoming connections and handles them in goroutines.
func (a *Aggregator) acceptLoop(ln net.Listener) {
	// Monitor stopCh in a separate goroutine to unblock Accept.
	go func() {
		<-a.stopCh
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			a.mu.Lock()
			stopped := !a.running
			a.mu.Unlock()
			if stopped {
				return
			}
			log.Printf("monitor: accept error: %v", err)
			continue
		}
		a.wg.Add(1)
		go func(c net.Conn) {
			defer a.wg.Done()
			a.handlePush(c)
		}(conn)
	}
}

// handlePush reads a metric envelope from a connection and stores it.
// If an auth checker is configured, the source peer must have the
// monitor_write capability (Decision E). Unauthorized pushes are
// silently dropped after the check (an audit entry is produced).
func (a *Aggregator) handlePush(conn net.Conn) {
	defer conn.Close()

	env, err := ReadEnvelope(conn)
	if err != nil {
		log.Printf("monitor: read envelope: %v", err)
		return
	}

	if env.Metrics == nil || env.SourceID == "" {
		return
	}

	// Capability check: verify the source peer is authorized to push
	// monitoring data (Decision E — zero-trust). This runs before
	// storing any metrics from the peer.
	if a.authChecker != nil {
		if !a.authChecker.AuthorizeMonitorWrite(env.SourceID) {
			log.Printf("monitor: rejected metric push from unauthorized peer %s", env.SourceID)
			return
		}
	}

	// Dedup by SourceID+Sequence: skip envelopes with sequences we've
	// already seen (e.g., direct push + forwarded copy from another
	// collector). The Sequence field is monotonically increasing per
	// source; a sequence <= the last seen sequence is a duplicate.
	// First-time sources (not in the map) are always accepted.
	a.dedupMu.Lock()
	lastSeq, seen := a.dedup[env.SourceID]
	if seen && env.Sequence <= lastSeq {
		a.dedupMu.Unlock()
		return
	}
	a.dedup[env.SourceID] = env.Sequence
	a.dedupLastSeen[env.SourceID] = time.Now()
	a.dedupMu.Unlock()

	// Store the metrics. The Store handles deduplication naturally
	// (ring buffer overwrites old data; newer timestamp wins).
	a.store.Append(env.SourceID, env.Metrics)

	// Forward the envelope to other known collectors if:
	//   - this envelope was not already forwarded (prevents loops),
	//   - a mesh dialer is configured,
	//   - a collector lister is configured.
	a.forwardToCollectors(env)
}

// cleanupDedup removes stale entries from the dedup map that haven't
// been updated in over 2x the cleanup interval. This prevents unbounded
// growth when nodes leave the mesh permanently.
func (a *Aggregator) cleanupDedup() {
	threshold := a.staleThreshold
	if threshold == 0 {
		threshold = 2 * time.Hour
	}
	cutoff := time.Now().Add(-threshold)
	a.dedupMu.Lock()
	for sourceID, lastSeen := range a.dedupLastSeen {
		if lastSeen.Before(cutoff) {
			delete(a.dedup, sourceID)
			delete(a.dedupLastSeen, sourceID)
		}
	}
	a.dedupMu.Unlock()
	if a.store != nil {
		a.store.RemoveStaleNodes(threshold)
	}
}

// forwardToCollectors forwards the given envelope to all known collector
// peers except the local node. The envelope's Forwarded field is set to
// true so that receiving collectors do not re-forward it (loop prevention).
// Failures are logged but do not affect the local store; the worst case
// is that a collector misses a metric sample, which will be refreshed on
// the next push cycle.
func (a *Aggregator) forwardToCollectors(env *MetricEnvelope) {
	if env.Forwarded {
		return // already forwarded by another collector; don't re-forward
	}
	if a.meshDialer == nil || a.collectorLister == nil {
		return // forwarding not configured
	}

	peers := a.collectorLister.CollectorPeerIDs()
	if len(peers) == 0 {
		return
	}

	// Mark the envelope as forwarded so receivers skip it.
	fwdEnv := &MetricEnvelope{
		SourceID:  env.SourceID,
		Sequence:  env.Sequence,
		Forwarded: true,
		Metrics:   env.Metrics,
	}

	for _, peerID := range peers {
		// Skip self to avoid loops.
		if peerID == a.selfPeerID {
			continue
		}
		if err := a.forwardEnvelope(peerID, fwdEnv); err != nil {
			id := peerID
			if len(id) > 16 {
				id = id[:16]
			}
			log.Printf("monitor: forward to collector %s: %v", id, err)
		}
	}
}

// forwardEnvelope dials a collector peer and sends the envelope using the
// same length-prefixed JSON protocol as the reporter's pushToCollectors.
func (a *Aggregator) forwardEnvelope(peerID string, env *MetricEnvelope) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := a.meshDialer.DialMesh(ctx, peerID, a.port)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if err := WriteEnvelope(conn, env); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// IsRunning returns whether the aggregator is currently accepting pushes.
func (a *Aggregator) IsRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

// --- For testing without a real mesh ---

// AggregatorInProc is a lightweight in-process aggregator that can be used
// in tests. It directly accepts envelopes without a network listener.
type AggregatorInProc struct {
	store *Store
}

// NewAggregatorInProc creates an in-process aggregator for testing.
func NewAggregatorInProc(store *Store) *AggregatorInProc {
	if store == nil {
		store = NewStore()
	}
	return &AggregatorInProc{store: store}
}

// Receive directly accepts and stores a metric envelope (no network).
func (a *AggregatorInProc) Receive(env *MetricEnvelope) {
	if env == nil || env.Metrics == nil || env.SourceID == "" {
		return
	}
	a.store.Append(env.SourceID, env.Metrics)
}

// Store returns the underlying store.
func (a *AggregatorInProc) Store() *Store {
	return a.store
}

// --- In-memory mesh dialer/listener for testing ---

// InProcMesh is an in-memory mesh transport for testing. It simulates
// mesh-internal connections between reporters and aggregators.
type InProcMesh struct {
	mu        sync.Mutex
	listeners map[int]chan net.Conn // port → channel for incoming connections
}

// NewInProcMesh creates a new in-memory mesh transport.
func NewInProcMesh() *InProcMesh {
	return &InProcMesh{
		listeners: make(map[int]chan net.Conn),
	}
}

// ListenMesh implements MeshListener. It registers a port and returns a listener.
func (m *InProcMesh) ListenMesh(port int) (net.Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[port]; exists {
		return nil, fmt.Errorf("port %d already in use", port)
	}

	ch := make(chan net.Conn, 64)
	m.listeners[port] = ch

	return &inProcListener{mesh: m, port: port, ch: ch}, nil
}

// DialMesh implements MeshDialer. It creates a pair of in-memory connections.
func (m *InProcMesh) DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error) {
	m.mu.Lock()
	ch, ok := m.listeners[port]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no listener on port %d", port)
	}

	c1, c2 := net.Pipe()
	select {
	case ch <- c2:
		return c1, nil
	case <-ctx.Done():
		c1.Close()
		c2.Close()
		return nil, ctx.Err()
	}
}

type inProcListener struct {
	mesh *InProcMesh
	port int
	ch   chan net.Conn
}

func (l *inProcListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok {
		return nil, fmt.Errorf("listener closed")
	}
	return conn, nil
}

func (l *inProcListener) Close() error {
	l.mesh.mu.Lock()
	defer l.mesh.mu.Unlock()
	delete(l.mesh.listeners, l.port)
	close(l.ch)
	return nil
}

func (l *inProcListener) Addr() net.Addr {
	return &net.TCPAddr{Port: l.port}
}
