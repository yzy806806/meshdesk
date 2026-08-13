package app

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/yzy806806/meshdesk/internal/p2p"
	"github.com/yzy806806/meshdesk/internal/proxy"
	"github.com/yzy806806/meshdesk/internal/service"
	"github.com/yzy806806/meshdesk/internal/web"
	"github.com/yzy806806/meshdesk/internal/webssh"
)

// startWeb starts the Dashboard web server (web mode), wiring
// auth/ssh/service/liveness deps, alert wiring, reloaders, and the
// join handler. On shared nodes the Dashboard rides the mux port.
func (a *App) startWeb() {
	if !a.webMode {
		log.Printf("  Mode:       agent-only")
		return
	}
	// Create the WebSSH hub for terminal sessions.
	knownHosts := webssh.NewKnownHostsStore()
	sshClient := webssh.NewSSHClient(
		web.NewMeshDialer(a.node),
		time.Duration(a.cfg.WebSSH.DialTimeout)*time.Second,
		knownHosts.HostKeyCallback(),
	)
	sshHub := webssh.NewHub(
		sshClient,
		web.NewPeerResolver(a.node.RoutingTable()),
		a.cfg.WebSSH.Port,
		a.cfg.WebSSH.MaxSessions,
		time.Duration(a.cfg.WebSSH.ReadDeadline)*time.Second,
		time.Duration(a.cfg.WebSSH.WriteDeadline)*time.Second,
	)

	// Create the service manager (systemctl backend, with NullBackend fallback).
	var svcMgr service.ServiceManager
	if execBackend, err := service.NewExecBackend("", 30*time.Second); err != nil {
		log.Printf("Warning: systemctl not available: %v — service management disabled", err)
		a.svcMgr = service.NewNullBackend()
		a.svcMgr = svcMgr
	} else {
		svcMgr = execBackend
	}

	// Create and start the web server.
	// Wire gossip liveness into the web server for topology.
	if a.gossipLayer != nil {
		a.webLiveness = &gossipLiveness{
			gl:       a.gossipLayer,
			localKey: a.node.Identity().PublicKey,
		}
	}

	// Wire the 3D topology edges to the global link map (P1):
	// edges = measured direct links between nodes.
	if a.gossipLayer != nil {
		a.topoPaths = &linkMapTopologyPaths{lm: a.gossipLayer.LinkMap()}
	}

	webServer, err := web.New(web.Deps{
		Config:               a.cfg,
		Node:                 a.node,
		MonitorStore:         a.monitorStore,
		SSHHub:               a.sshHub,
		AuthEngine:           a.authEngine,
		ServiceMgr:           a.svcMgr,
		MeshDialer:           web.NewPeerMeshDialer(a.node),
		ProxyStatusProvider:  &entryNodeStatusAdapter{entryNode: a.proxyEntryNode},
		TopologyPaths:        a.topoPaths,
		SOCKS5StatusProvider: a.node,
		Liveness:             a.webLiveness,
		ConfigPath:           a.configPath,
		VersionInfo: web.VersionInfo{
			Version:   a.Version,
			Commit:    a.Commit,
			BuildTime: a.BuildTime,
		},
		JoinTokenGenerator: &nodeJoinTokenGenerator{
			cfg:      a.cfg,
			identity: a.node.Identity(),
		},
	})
	if err != nil {
		log.Fatalf("Failed to create web server: %v", err)
	}

	// Wire security alerting callbacks:
	// - auth.CapabilityEngine denials → capability_denied alerts
	// - mesh.RoutingTable join/leave → node_join/node_leave alerts
	// - proxy.SecurityEventSink → suspicious proxy activity alerts
	//
	// All three feed into the web server's AlertStore, which powers
	// the /api/alerts dashboard endpoint.
	alertStore := webServer.AlertStore()
	a.alertStore = alertStore
	if alertStore != nil {
		if a.authEngine != nil {
			a.authEngine.SetDenyCallback(alertStore.HandleAuthDenial)
		}
		// Wire the remote service auth engine (used for mesh-internal
		// service management requests) to the same alert store.
		if a.remoteAuthEngine != nil {
			a.remoteAuthEngine.SetDenyCallback(alertStore.HandleAuthDenial)
		}
		// Wire the transfer auth engine (used for file transfer
		// authorization) to the same alert store.
		if a.transferAuthEngine != nil {
			a.transferAuthEngine.SetDenyCallback(alertStore.HandleAuthDenial)
		}
		if a.node != nil {
			rt := a.node.RoutingTable()
			rt.SetJoinCallback(alertStore.HandlePeerJoin)
			rt.SetLeaveCallback(alertStore.HandlePeerLeave)
		}
		// Threshold rules (T4.1): CPU/mem/offline alerts from monitor data.
		if a.monitorStore != nil {
			evaluator := web.NewRuleEvaluator(a.monitorStore, alertStore)
			evaluator.SetRules([]web.AlertRule{
				{Metric: "cpu", Threshold: 90, DurationSec: 120, Severity: web.AlertWarning, Description: "high CPU usage on {node}"},
				{Metric: "mem", Threshold: 90, DurationSec: 120, Severity: web.AlertWarning, Description: "high memory usage on {node}"},
				{Metric: "offline", DurationSec: 180, Severity: web.AlertCritical, Description: "node offline"},
			})
			evaluator.Start()
		}
		// Wire proxy security events into the alert store.
		if a.proxySecSink != nil {
			a.proxySecSink.SetCallback(func(event proxy.SecurityEvent) {
				alertStore.HandleProxySecurityEvent(event)
			})
		}
	}

	// Register production hot-reloaders for subsystems that support
	// dynamic config updates. When a user changes a hot-reload field
	// via the Dashboard and clicks "Hot Reload", each registered
	// reloader is called with the new config to apply changes at runtime
	// without requiring a process restart.
	webServer.RegisterReloader(web.NewMonitorReloader(a.reporter))
	if sshHub != nil {
		webServer.RegisterReloader(web.NewWebSSHReloader(sshHub))
	}
	webServer.RegisterReloader(web.NewLoggingReloader())
	// Register ACL reloader (uses node as ACLProvider).
	webServer.RegisterReloader(web.NewACLReloaderFromProvider(a.node))
	// Register proxy reloader (acknowledges in-memory config update).
	webServer.RegisterReloader(web.NewProxyReloader())

	// Attach the join server handler to the web mux so POST /api/join
	// is served on the same port as the Dashboard. This happens
	// regardless of mux mode: on shared nodes the join endpoint rides
	// the multiplexed port; on regular web nodes it rides the web port.
	if a.joinServer != nil {
		webServer.SetJoinHandler(a.joinServer.Handler())
	}

	// If the node has a MuxTransport (shared node mode), serve the
	// Dashboard on the multiplexed port (the mesh port, 52888 by
	// default — cfg.Mesh.Port) instead of a separate port. This
	// allows single-port deployment: Reality + gossip + mesh +
	// + Dashboard + join all on one TCP port.
	if muxTransport := a.node.MuxTransport(); muxTransport != nil {
		httpLn := muxTransport.HTTPListener()
		if err := webServer.ServeWithListener(httpLn); err != nil {
			log.Fatalf("Failed to start web server on mux listener: %v", err)
		}
		a.webServer = webServer
		log.Printf("  Web UI:     muxed on mesh port (HTTP)")
		if a.joinServer != nil {
			log.Printf("  Join:       muxed on mesh port (/api/join)")
		}
	} else {
		if err := webServer.Start(a.cfg.Node.WebAddr); err != nil {
			log.Fatalf("Failed to start web server: %v", err)
		}
		a.webServer = webServer
		log.Printf("  Web UI:     http://%s", a.cfg.Node.WebAddr)
	}
	if !a.webMode {
		log.Printf("  Mode:       agent-only")
	}
}

type gossipLiveness struct {
	gl       *p2p.GossipLayer
	localKey string
}

type entryNodeStatusAdapter struct {
	entryNode *proxy.EntryNode
}

func (a *entryNodeStatusAdapter) ProxyStatus() any {
	if a.entryNode == nil {
		return web.ProxyStatusData{Running: false}
	}
	s := a.entryNode.Status()
	return web.ProxyStatusData{
		Running:       s.Running,
		SessionCount:  s.SessionCount,
		CFTunnelReady: s.CFTunnelReady,
		Path1Relays:   s.Path1Relays,
		Path2Relays:   s.Path2Relays,
		ExitAddr:      s.ExitAddr,
	}
}

func (g *nodeJoinTokenGenerator) BinaryDownloadURL(arch string) string {
	if arch == "" {
		arch = "amd64"
	}
	return fmt.Sprintf("https://github.com/yzy806806/meshdesk/releases/latest/download/meshdesk-linux-%s", arch)
}

func (g *gossipLiveness) IsAlive(peerID string) bool {
	if peerID == g.localKey {
		return true // local node is always alive
	}
	return g.gl.Events().GetPeerMeta(peerID) != nil
}

func (g *gossipLiveness) AlivePeerIDs() []string {
	peers := g.gl.Events().AllKnownPeers()
	ids := make([]string, 0, len(peers)+1)
	if g.localKey != "" {
		ids = append(ids, g.localKey)
	}
	for _, p := range peers {
		ids = append(ids, p.PublicKey)
	}
	return ids
}

func (g *gossipLiveness) PeerHostname(peerID string) string {
	if peerID == g.localKey {
		// Return local node's hostname from gossip meta.
		if meta := g.gl.LocalMeta(); meta != nil {
			return meta.Hostname
		}
		return ""
	}
	meta := g.gl.Events().GetPeerMeta(peerID)
	if meta == nil {
		return ""
	}
	return meta.Hostname
}

func (g *nodeJoinTokenGenerator) JoinServerURL() string {
	if !g.cfg.Join.Enabled {
		return ""
	}
	host := firstAdvertiseEndpointHost(g.cfg)

	// On shared nodes (Reality + P2P enabled), the join endpoint is served
	// on the mux/mesh port via webServer.SetJoinHandler — not on a standalone
	// join listener. Derive the URL from the Reality listen port.
	if g.cfg.P2P.Enabled && g.cfg.Reality.Enabled {
		port := g.cfg.Reality.ListenPort
		if port == 0 {
			port = 443
		}
		return fmt.Sprintf("http://%s:%d", host, port)
	}

	// Standalone join listener mode (agent-only or non-mux web node).
	addr := g.cfg.Join.ListenAddr
	if addr == "" {
		addr = ":8443"
	}
	port := "8443"
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		port = addr[idx+1:]
	}
	scheme := "https"
	if g.cfg.Join.TLSCertFile == "" || g.cfg.Join.TLSKeyFile == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

func (g *nodeJoinTokenGenerator) JoinEnabled() bool {
	return g.cfg.Join.Enabled && g.cfg.Reality.Enabled
}
