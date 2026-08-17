package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/monitor"
)

// startMonitor starts the monitoring reporter: metric collection +
// push to collectors (or all known peers by default), history
// persistence, collector auto-discovery, traffic stats wiring.
func (a *App) startMonitor() {
	// Start monitoring reporter (runs on every node — agent or web mode).
	nodeID := a.node.Identity().PublicKey
	hostname := a.cfg.Node.Hostname

	reporter := monitor.NewReporter(monitor.ReporterConfig{
		NodeID:     nodeID,
		Hostname:   hostname,
		Dialer:     &meshDialerAdapter{node: a.node},
		Collectors: a.cfg.Monitoring.Collectors,
		Interval:   a.cfg.Monitoring.Interval,
		Port:       a.cfg.Monitoring.Port,
	})
	// Default monitoring: when no collectors are configured/discovered,
	// push to every known mesh peer — sessions plus meta-learned peers
	// (works out of the box, even without direct sessions).
	reporter.SetPeerLister(func() []string {
		keys := a.node.SessionPeerKeys()
		seen := make(map[string]bool, len(keys))
		for _, k := range keys {
			seen[k] = true
		}
		for k := range a.node.PeerVirtualIPs() {
			if !seen[k] {
				keys = append(keys, k)
			}
		}
		return keys
	})
	if err := reporter.Start(); err != nil {
		log.Printf("Warning: failed to start monitoring reporter: %v", err)
	} else {
		a.monitorStore = reporter.LocalStore()
		log.Printf("  Monitor:   reporter active (interval=%ds)", a.cfg.Monitoring.Interval)
		// Persist monitoring history (T4.2): restore on start, dump
		// every 5 minutes so recent samples survive restarts.
		histPath := "/var/lib/meshdesk/monitor-history.json"
		if a.monitorStore.Load(histPath) == nil {
			log.Printf("  Monitor:   restored %d node(s) from history", len(a.monitorStore.NodeIDs()))
		}
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				if err := a.monitorStore.Persist(histPath); err != nil {
					log.Printf("[monitor] history persist failed: %v", err)
				}
			}
		}()
	}

	// META-based collector discovery (relay-attached nodes): the same
	// AddCollector handler is wired to the session meta exchange, which
	// propagates Collector=true over smux/relay sessions — reaching
	// nodes whose memberlist (gossip CapCollector) never does. Local
	// node advertises itself as a collector when web mode is enabled.
	a.node.SetCollectorHandler(reporter.AddCollector)
	a.node.SetLocalCollector(a.cfg.Node.WebAddr != "")

	// Wire traffic stats provider: enriches each metrics push with
	// mesh-internal traffic data (smux bytes, relay tunnels, TUN packets).
	reporter.SetTrafficProvider(func() monitor.TrafficSnapshot {
		ts := a.node.TrafficStats()
		return monitor.TrafficSnapshot{
			InBytes:       ts.InBytes,
			OutBytes:      ts.OutBytes,
			SmuxStreams:   ts.SmuxStreams,
			RelayForwards: ts.RelayForwards,
			TunRxPackets:  ts.TunRxPackets,
			TunTxPackets:  ts.TunTxPackets,
			PeerCount:     ts.PeerCount,
		}
	})

	// Provide peer RTT for path planning: each monitor report carries
	// this node's latency to all session peers, so the nearest shared
	// node can build a global latency graph.
	reporter.SetRTTProvider(func() map[string]int {
		result := make(map[string]int)
		for _, peerKey := range a.node.SessionPeerKeys() {
			rtt := a.node.PeerRTT(peerKey)
			if rtt > 0 {
				result[peerKey] = int(rtt.Milliseconds())
			}
		}
		return result
	})

	a.reporter = reporter
}

type meshDialerAdapter struct {
	node *mesh.MeshNode
}

func (d *meshDialerAdapter) DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error) {
	// DialMesh opens a virtual-port stream over an existing smux
	// session. The peer must already be connected (via AddPeer or an
	// inbound session). peerID is the peer's identity hex.
	conn, err := d.node.DialVirtualPort(ctx, peerID, port)
	if err != nil {
		return nil, fmt.Errorf("mesh: DialMesh to %s failed: %w", peerID[:min(len(peerID), 16)]+"...", err)
	}
	return conn, nil
}

// startMonitorAggregator starts the metric aggregator (web nodes):
// receives pushes, enforces mesh-identity auth, feeds the store.
// The audit logger backs auth + capability denials.
func (a *App) startMonitorAggregator() {
	if a.webMode {
		// Create the auth capability engine first, so it can be wired
		// into the aggregator for monitor_write enforcement (Decision E).
		// Use rotation-enabled audit logger: 100 MB max, 5 backups.
		auditLogger, err := auth.NewAuditFileLoggerWithRotation("/var/log/meshdesk-audit.jsonl",
			auth.DefaultAuditMaxBytes, auth.DefaultAuditMaxRotates)
		if err != nil {
			log.Printf("Warning: could not open audit log file: %v — using stderr", err)
			auditLogger = auth.NewAuditLogger(log.Writer())
		}
		a.auditLogger = auditLogger

		a.authEngine = auth.NewCapabilityEngine(a.cfg, auditLogger)

		// Wire mesh identity-based auth checker into the aggregator.
		// Every incoming metric push is checked: the source peer must
		// be a known mesh member (routing table lookup) or the local
		// node itself. Unknown peers are rejected (fail-closed).
		// This implements Decision E (zero-trust) at the mesh-identity
		// level: mesh membership is the trust boundary for monitor_write.
		monitorAuthChecker := auth.NewMeshIdentityAuthChecker(
			a.node.Identity().PublicKey,
			func(peerID string) bool {
				// Known = routing-table PeerEntry OR a peer learned via
				// the meta exchange (VIP route — degraded memberlist
				// leaves meta-learned peers without a PeerEntry).
				if _, ok := a.node.RoutingTable().GetPeer(peerID); ok {
					return true
				}
				_, ok := a.node.PeerVirtualIPs()[peerID]
				return ok
			},
			auditLogger,
		)

		// On web nodes, also run the aggregator to receive metric pushes.
		aggregator := monitor.NewAggregator(monitor.AggregatorConfig{
			Store:           a.monitorStore,
			Dialer:          &meshListenerAdapter{node: a.node},
			MeshDialer:      &meshDialerAdapter{node: a.node},
			SelfPeerID:      a.node.Identity().PublicKey,
			Port:            a.cfg.Monitoring.Port,
			AuthChecker:     monitorAuthChecker,
		})
		if err := aggregator.Start(); err != nil {
			log.Printf("Warning: failed to start metric aggregator: %v", err)
		} else {
			log.Printf("  Aggregator: listening on mesh port %d", a.cfg.Monitoring.Port)
		}
		// On shared nodes, wire PeerLatency → LatencyGraph update.
		if a.cfg.Reality.Enabled {
			aggregator.SetPeerLatencyHandler(func(sourceKey string, latency map[string]int, hostname string) {
				zone := a.node.PeerZone(sourceKey)
				a.node.UpdateLatencyGraph(sourceKey, latency, zone)
			})
		}
		a.monitorAggregator = aggregator

		// Use the aggregator's store (which may have collected metrics from other nodes).
		if aggregator.Store() != nil {
			a.monitorStore = aggregator.Store()
		}
	}
}
