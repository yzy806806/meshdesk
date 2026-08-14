package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Reporter runs on every node. It collects local metrics at the configured
// interval and pushes them to a set of collector nodes. When all collectors
// are unreachable, it buffers metrics locally (ring buffer) so that they
// survive a collector outage and can be replayed once connectivity is restored.
type Reporter struct {
	collector  *SystemCollector
	store      *Store     // local ring buffer store (self-metrics + buffer during outage)
	dialer     MeshDialer // dials mesh-internal connections to collectors
	collectors []string   // peer IDs of collector nodes
	// peerLister returns all known mesh peers (used as the default
	// push target when no collectors are configured/discovered).
	peerLister  func() []string
	localPeerID string
	interval    time.Duration
	port        int // mesh-internal port that collectors listen on

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// sequence is a monotonically increasing counter per source.
	sequence uint64

	// bufferedCount tracks how many metrics are in the local buffer
	// awaiting delivery (for diagnostics).
	bufferedCount int64

	// maxBufferAge is the maximum age of a buffered metric before it is
	// discarded (prevents unbounded memory growth during long outages).
	maxBufferAge time.Duration

	// trafficProvider, when set, is called during each collection cycle
	// to enrich metrics with mesh-internal traffic statistics (smux bytes,
	// relay tunnels, TUN packets). Returns zero values if no traffic to report.
	trafficProvider func() TrafficSnapshot
}

// TrafficSnapshot is a provider-supplied snapshot of mesh traffic stats.
// The Reporter converts this into monitor.TrafficMetrics for push to collectors.
type TrafficSnapshot struct {
	InBytes       uint64
	OutBytes      uint64
	SmuxStreams   int
	RelayForwards int
	TunRxPackets  uint64
	TunTxPackets  uint64
	PeerCount     int
}

// MeshDialer abstracts the mesh network's dial capability. In production
// this is mesh.MeshNode.Dial(). The interface allows testing without a
// real mesh.
type MeshDialer interface {
	// DialMesh opens a TCP connection to peerID:port through the mesh VPN.
	DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error)
}

// ReporterConfig holds the parameters for creating a Reporter.
type ReporterConfig struct {
	NodeID     string
	Hostname   string
	Dialer     MeshDialer
	Collectors []string // peer IDs
	Interval   int      // seconds (clamped to [10, 300])
	Port       int      // collector listen port (default 4191)
}

// NewReporter creates a metrics reporter that collects and pushes metrics.
func NewReporter(cfg ReporterConfig) *Reporter {
	interval := time.Duration(cfg.Interval) * time.Second
	if interval < 10*time.Second {
		interval = 15 * time.Second
	}
	if interval > 5*time.Minute {
		interval = 5 * time.Minute
	}
	port := cfg.Port
	if port == 0 {
		port = DefaultMonitorPort
	}

	return &Reporter{
		collector:    NewSystemCollector(cfg.NodeID, cfg.Hostname),
		localPeerID:  cfg.NodeID,
		store:        NewStore(),
		dialer:       cfg.Dialer,
		collectors:   cfg.Collectors,
		interval:     interval,
		port:         port,
		stopCh:       make(chan struct{}),
		maxBufferAge: 24 * time.Hour,
	}
}

// DefaultMonitorPort is the mesh-internal port for the monitoring protocol.
const DefaultMonitorPort = 4191

// AddCollector adds a collector peer ID to the reporter's collector list.
// This is called dynamically when a collector peer is discovered via gossip
// (CapCollector=true in NodeMeta). The addition is idempotent — duplicate
// peer keys are silently ignored.
//
// This method is safe to call concurrently with the reporter's push loop.
func (r *Reporter) AddCollector(peerKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Dedup: check if already present.
	for _, c := range r.collectors {
		if c == peerKey {
			return
		}
	}

	r.collectors = append(r.collectors, peerKey)
	log.Printf("[monitor] collector added via gossip discovery: %s",
		peerKey[:min(len(peerKey), 16)])

	// Trigger an immediate flush in case metrics were buffered during
	// the period when no collectors were known.
	go r.FlushBuffer()
}

// RemoveCollector removes a collector peer ID from the reporter's collector
// list. This is called dynamically when a collector peer leaves the mesh
// (NotifyLeave) so that stale entries don't accumulate and waste dial
// attempts on dead peers. The removal is idempotent — removing a peer key
// that is not present is silently ignored.
//
// This method is safe to call concurrently with the reporter's push loop.
func (r *Reporter) RemoveCollector(peerKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, c := range r.collectors {
		if c == peerKey {
			r.collectors = append(r.collectors[:i], r.collectors[i+1:]...)
			log.Printf("[monitor] collector removed: %s", peerKey[:min(len(peerKey), 16)])
			return
		}
	}
}

// Collectors returns a copy of the current collector peer ID list.
func (r *Reporter) Collectors() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]string, len(r.collectors))
	copy(result, r.collectors)
	return result
}

// SetInterval updates the collection/push interval. The new interval
// takes effect on the next tick cycle. If the reporter is running, the
// ticker is reset to the new interval.
func (r *Reporter) SetInterval(seconds int) {
	interval := time.Duration(seconds) * time.Second
	if interval < 10*time.Second {
		interval = 15 * time.Second
	}
	if interval > 5*time.Minute {
		interval = 5 * time.Minute
	}
	r.mu.Lock()
	r.interval = interval
	r.mu.Unlock()
}

// SetPort updates the mesh-internal port used to push metrics to collectors.
// Takes effect on the next push attempt.
func (r *Reporter) SetPort(port int) {
	if port == 0 {
		port = DefaultMonitorPort
	}
	r.mu.Lock()
	r.port = port
	r.mu.Unlock()
}

// SetPeerLister sets the callback that returns all known mesh peers —
// used as the default push target when no collectors are configured or
// discovered (monitoring works out of the box, no manual collectors).
func (r *Reporter) SetPeerLister(fn func() []string) {
	r.mu.Lock()
	r.peerLister = fn
	r.mu.Unlock()
}

// SetCollectors replaces the entire collector list. This is used by the
// hot-reload mechanism when the monitoring.collectors config field is
// updated from the Dashboard.
func (r *Reporter) SetCollectors(peerIDs []string) {
	r.mu.Lock()
	r.collectors = make([]string, len(peerIDs))
	copy(r.collectors, peerIDs)
	r.mu.Unlock()
}

// Interval returns the current collection interval in seconds.
func (r *Reporter) Interval() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int(r.interval.Seconds())
}

// Port returns the current collector push port.
func (r *Reporter) Port() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.port
}

// LocalStore returns the reporter's local store (for self-metrics access).
func (r *Reporter) LocalStore() *Store {
	return r.store
}

// SetTrafficProvider installs a callback that supplies mesh-internal
// traffic statistics. When set, each collection cycle enriches the
// metrics with traffic data before storing and pushing to collectors.
func (r *Reporter) SetTrafficProvider(fn func() TrafficSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trafficProvider = fn
}

// monitorTrafficFromProvider converts a TrafficSnapshot to TrafficMetrics.
func monitorTrafficFromProvider(ts TrafficSnapshot) TrafficMetrics {
	return TrafficMetrics{
		InBytes:       ts.InBytes,
		OutBytes:      ts.OutBytes,
		SmuxStreams:   ts.SmuxStreams,
		RelayForwards: ts.RelayForwards,
		TunRxPackets:  ts.TunRxPackets,
		TunTxPackets:  ts.TunTxPackets,
		PeerCount:     ts.PeerCount,
	}
}

// Start begins the collection and push loop in a background goroutine.
// The first collection happens immediately; subsequent ones at the interval.
func (r *Reporter) Start() error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return fmt.Errorf("reporter already running")
	}
	r.running = true
	r.stopCh = make(chan struct{})
	r.mu.Unlock()

	r.wg.Add(1)
	go r.run()
	return nil
}

// Stop halts the collection and push loop.
func (r *Reporter) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.running = false
	close(r.stopCh)
	r.mu.Unlock()
	r.wg.Wait()
}

// run is the main collection/push loop.
func (r *Reporter) run() {
	defer r.wg.Done()

	// Collect immediately on start.
	r.collectAndPush()

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			// Check if the interval was updated via SetInterval.
			r.mu.Lock()
			currentInterval := r.interval
			r.mu.Unlock()
			ticker.Reset(currentInterval)
			r.collectAndPush()
		}
	}
}

// collectAndPush performs one collection cycle: collect, store locally,
// then push to all collectors. Failed pushes are buffered for retry.
func (r *Reporter) collectAndPush() {
	m, err := r.collector.Collect()
	if err != nil {
		log.Printf("monitor: collect error: %v", err)
		return
	}

	// Enrich with traffic stats if a provider is set.
	r.mu.Lock()
	provider := r.trafficProvider
	r.mu.Unlock()
	if provider != nil {
		ts := provider()
		m.Traffic = monitorTrafficFromProvider(ts)
	}

	// Always store locally (self-replica). sequence is read under
	// r.mu elsewhere (FlushBuffer) — increment it under the lock to
	// avoid a data race.
	r.mu.Lock()
	r.sequence++
	r.store.Append(r.collector.nodeID, m)
	r.mu.Unlock()

	// Check if we have any collectors (snapshot under lock).
	r.mu.Lock()
	hasCollectors := len(r.collectors) > 0
	r.mu.Unlock()

	if !hasCollectors {
		return
	}

	// Try to push to collectors.
	env := &MetricEnvelope{
		SourceID: r.collector.nodeID,
		Sequence: r.sequence,
		Metrics:  m,
	}

	pushed := r.pushToCollectors(env)
	if !pushed {
		// All collectors failed; metric is already in local store.
		r.mu.Lock()
		r.bufferedCount++
		r.mu.Unlock()
	}
}

// pushToCollectors attempts to push the envelope to every collector.
// All collectors receive the data (not just the first reachable one) —
// with multiple dashboards (e.g. N1 and txcloud both running web mode)
// the user expects every dashboard to show the full node set, so a
// collector that would only "win" by being first in the list must not
// starve the others. Returns true if at least one push succeeded.
func (r *Reporter) pushToCollectors(env *MetricEnvelope) bool {
	data, err := json.Marshal(env)
	if err != nil {
		log.Printf("monitor: marshal envelope: %v", err)
		return false
	}

	// Snapshot the collector list under the lock to avoid races with
	// concurrent AddCollector/RemoveCollector calls.
	r.mu.Lock()
	collectors := make([]string, len(r.collectors))
	copy(collectors, r.collectors)
	r.mu.Unlock()

	// Default: when no collectors are configured or discovered (e.g.
	// degraded memberlist never propagated CapCollector), push to ALL
	// known mesh peers — monitoring is expected to work out of the box.
	if len(collectors) == 0 && r.peerLister != nil {
		for _, p := range r.peerLister() {
			if p == r.localPeerID {
				continue
			}
			collectors = append(collectors, p)
		}
	}

	var okCount, failCount int
	for _, collectorID := range collectors {
		if r.tryPush(collectorID, data) {
			okCount++
			continue
		}
		// tryPush already logged the error; track for summary.
		failCount++
	}
	if failCount > 0 && okCount == 0 {
		log.Printf("[monitor] pushToCollectors: all %d collectors failed", failCount)
	}
	return okCount > 0
}

// tryPush attempts to dial a collector and send the metrics envelope.
func (r *Reporter) tryPush(collectorID string, data []byte) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := r.dialer.DialMesh(ctx, collectorID, r.port)
	if err != nil {
		log.Printf("[monitor] tryPush: DialMesh to %s failed: %v", collectorID[:min(len(collectorID), 16)], err)
		return false
	}
	defer conn.Close()

	// Protocol: 4-byte big-endian length prefix + JSON payload.
	// This is the same framing used by the file transfer protocol (Decision F).
	header := []byte{
		byte(len(data) >> 24),
		byte(len(data) >> 16),
		byte(len(data) >> 8),
		byte(len(data)),
	}

	if _, err := conn.Write(header); err != nil {
		return false
	}
	if _, err := conn.Write(data); err != nil {
		return false
	}

	return true
}

// FlushBuffer attempts to replay buffered metrics to collectors.
// This should be called periodically (or on collector discovery) to
// ensure data from a collector outage period is not lost.
func (r *Reporter) FlushBuffer() int {
	// Snapshot the collector list under the lock.
	r.mu.Lock()
	collectors := make([]string, len(r.collectors))
	copy(collectors, r.collectors)
	r.mu.Unlock()

	if r.dialer == nil || len(collectors) == 0 {
		return 0
	}

	// Get all self-metrics from local store within the maxBufferAge window.
	from := time.Now().UTC().Add(-r.maxBufferAge)
	samples := r.store.Range(r.collector.nodeID, from, time.Time{})

	flushed := 0
	for _, m := range samples {
		r.mu.Lock()
		seq := r.sequence + 1
		r.sequence = seq
		r.mu.Unlock()

		env := &MetricEnvelope{
			SourceID: r.collector.nodeID,
			Sequence: seq,
			Metrics:  m,
		}
		data, _ := json.Marshal(env)
		for _, collectorID := range collectors {
			if r.tryPush(collectorID, data) {
				flushed++
				break
			}
		}
	}

	return flushed
}

// CollectOnce performs a single collection without pushing (for testing).
func (r *Reporter) CollectOnce() (*Metrics, error) {
	return r.collector.Collect()
}

// BufferedCount returns the number of metrics buffered during collector outages.
func (r *Reporter) BufferedCount() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bufferedCount
}

// ReadEnvelope reads a length-prefixed MetricEnvelope from a connection.
// This is used by the Aggregator to decode incoming pushes.
func ReadEnvelope(r io.Reader) (*MetricEnvelope, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	length := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length <= 0 || length > 10*1024*1024 { // 10 MB safety limit
		return nil, fmt.Errorf("invalid envelope length: %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var env MetricEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	return &env, nil
}

// WriteEnvelope writes a length-prefixed MetricEnvelope to a connection.
func WriteEnvelope(w io.Writer, env *MetricEnvelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	header := []byte{
		byte(len(data) >> 24),
		byte(len(data) >> 16),
		byte(len(data) >> 8),
		byte(len(data)),
	}
	buf := bytes.NewBuffer(header)
	buf.Write(data)
	_, err = w.Write(buf.Bytes())
	return err
}
