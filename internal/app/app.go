// Package app assembles and runs the meshdesk daemon.
//
// The former ~2900-line cmd/meshdesk/main.go monolith is split here
// into small functional modules. Assembly is three-phase:
//
//	Build(cfg): ① construct all components (not started)
//	            ② app.wire() — centralize cross-layer callback wiring
//	            ③ return an unstarted App
//	Start(ctx): start components in dependency order
//	Stop():     stop in reverse order (explicit list, tested)
//	Reload(cfg): hot-reload cross-subsystem wiring (SIGHUP)
package app

import (
	"context"
	"log"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/dns"
	"github.com/yzy806806/meshdesk/internal/join"
	"github.com/yzy806806/meshdesk/internal/logging"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/p2p"
	"github.com/yzy806806/meshdesk/internal/proxy"
	"github.com/yzy806806/meshdesk/internal/service"
	"github.com/yzy806806/meshdesk/internal/topology"
	"github.com/yzy806806/meshdesk/internal/transfer"
	"github.com/yzy806806/meshdesk/internal/web"
	"github.com/yzy806806/meshdesk/internal/webssh"
	"sync"
)

// App is the assembled meshdesk daemon. Fields are the shared state
// that the old main() held as local variables / closure captures.
type App struct {
	cfg *config.Config

	// Version info (injected from cmd/meshdesk ldflags).
	Version   string
	Commit    string
	BuildTime string

	// Core mesh.
	node             *mesh.MeshNode
	gossipLayer      *p2p.GossipLayer
	natTraversal     *p2p.NatTraversal
	tunForwarder     *mesh.TunForwarder
	relayHandler     *mesh.RelayHandler
	metaExchanger    *mesh.MetaExchanger
	wgDelegate       *p2p.WireGuardDelegate
	gossipP2pCfg     p2p.P2pConfig
	peerCache        *p2p.PeerCache
	relayPathBuilder p2p.RelayPathBuilder

	// NAT traversal join/leave handlers (shared with TUN integration;
	// SetJoinHandler overwrites, so they merge into one closure).
	natJoinHandler  func(meta *p2p.NodeMeta)
	natLeaveHandler func(peerKey string)

	// Auto-dial dedup (join handler may re-fire during memberlist flaps).
	autoDialMu       sync.Mutex
	autoDialInFlight map[string]bool

	// CLI flags injected from main (Build options).
	webMode         bool
	relayMode       bool
	socks5Listen    string
	socks5ExitNode  string
	socks5ExitNodes string

	// Virtual-port services.
	dnsServer         *dns.Server
	remoteSvcServer   *service.RemoteServer
	transferServer    *transfer.Receiver
	sshServer         *webssh.SSHServer
	proxyEntryNode    *proxy.EntryNode
	proxyExitNode     *proxy.ExitNode
	proxyExitCancel   context.CancelFunc
	reporter          *monitor.Reporter
	monitorStore      *monitor.Store
	monitorAggregator *monitor.Aggregator
	auditLogger       *auth.AuditLogger
	webServer         *web.Server
	joinServer        *join.JoinServer
	sdNotifier        interface {
		Start() error
		Close() error
	}
	authEngine         *auth.CapabilityEngine
	sshHub             *webssh.Hub
	svcMgr             service.ServiceManager
	webLiveness        web.PeerLiveness
	topoPaths          topology.TopologyPathInfo
	alertStore         *web.AlertStore
	configPath         string
	logWriter          *logging.RotatingWriter
	proxySecSink       *proxy.SecurityEventSink
	remoteAuthEngine   *auth.CapabilityEngine
	transferAuthEngine *auth.CapabilityEngine

	// Wire-time callbacks (populated by app.wire()).
	wired bool
}

// SetConfigPath sets the config file path (for SIGHUP reload).
func (a *App) SetConfigPath(path string) { a.configPath = path }

// SetLogWriter sets the rotating log writer (for SIGHUP logging reload).
func (a *App) SetLogWriter(w *logging.RotatingWriter) { a.logWriter = w }

// SetFlags injects CLI flag values (from main) that components need.
func (a *App) SetFlags(webMode, relayMode bool, socks5Listen, socks5ExitNode, socks5ExitNodes string) {
	a.webMode = webMode
	a.relayMode = relayMode
	a.socks5Listen = socks5Listen
	a.socks5ExitNode = socks5ExitNode
	a.socks5ExitNodes = socks5ExitNodes
}

// Build constructs all components and wires cross-layer callbacks,
// returning an UNSTARTED App. Nothing is started until Start().
func Build(cfg *config.Config) (*App, error) {
	a := &App{cfg: cfg}
	if err := a.construct(); err != nil {
		return nil, err
	}
	a.wire()
	return a, nil
}

// construct creates every component in dependency order. No
// networking, no goroutines — pure construction.
func (a *App) construct() error {
	a.autoDialInFlight = make(map[string]bool)
	return a.constructMeshNode()
}

// wire centralizes ALL cross-layer callback wiring. This is the home
// for the 15+ SetXxxProvider/Broadcaster/Handler closures that used
// to live scattered through main() with nil guards.
func (a *App) wire() {
	a.wireMeshNodeCallbacks()
	a.wired = true
}

// Start brings the daemon up in dependency order: node → virtual-port
// services → proxy entry → gossip/NAT → TUN integration → services →
// monitor → aggregator → join → web.
func (a *App) Start(ctx context.Context) error {
	if err := a.startMeshNode(); err != nil {
		return err
	}
	a.registerVirtualPortServices()
	a.startProxy()
	a.startP2P()
	a.integrateTUN()
	a.startServices()
	a.startProxyCircuit()
	a.startMonitor()
	a.startMonitorAggregator()
	a.startJoinServer()
	a.startWeb()
	return nil
}

// Stop shuts the daemon down in REVERSE dependency order — explicit
// ordered list (the old implicit defer order, now pinned by tests):
// leave notice → web → join → aggregator → monitor → proxy circuit →
// services → gossip → mesh.
func (a *App) Stop() {
	log.Printf("[app] stop: shutting down (reverse dependency order)")
	a.notifyStopping()
	a.sendLeaveNotice()

	// Web (last started, first stopped).
	if a.webServer != nil {
		a.webServer.Stop()
	}
	if a.joinServer != nil {
		a.joinServer.Stop()
	}
	if a.monitorAggregator != nil {
		a.monitorAggregator.Stop()
	}
	if a.reporter != nil {
		a.reporter.Stop()
	}
	if a.proxyEntryNode != nil {
		a.proxyEntryNode.Close()
	}
	if a.proxyExitCancel != nil {
		a.proxyExitCancel()
	}
	if a.proxyExitNode != nil {
		a.proxyExitNode.Close()
	}
	if a.sshServer != nil {
		a.sshServer.Close()
	}
	if a.transferServer != nil {
		a.transferServer.Stop()
	}
	if a.remoteSvcServer != nil {
		a.remoteSvcServer.Stop()
	}
	if a.dnsServer != nil {
		a.dnsServer.Stop()
	}
	if a.auditLogger != nil {
		a.auditLogger.Close()
	}
	a.stopGossip()
	a.stopMeshNode()
}
