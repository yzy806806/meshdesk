package app

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/yzy806806/meshdesk/internal/proxy"
	"github.com/yzy806806/meshdesk/internal/service"
	"github.com/yzy806806/meshdesk/internal/web"
	"github.com/yzy806806/meshdesk/internal/webssh"
)

// startWeb starts the Dashboard web server (web mode), wiring
// auth/ssh/service/liveness deps, alert wiring, reloaders, and the
// join handler. The Dashboard listens only on the dedicated web port
// (cfg.Node.WebAddr) — the mesh port carries no HTTP (see the
// reality-discipline refactor).
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
	// Gossip liveness is no longer available (gossip layer removed);
	// topology falls back to monitor-only liveness (existing behavior).

	// 3D topology edges: no link map available (gossip removed).

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

	// The Dashboard is served ONLY on the dedicated web port
	// (cfg.Node.WebAddr). It no longer rides the multiplexed mesh
	// port (reality-discipline refactor): intercepting HTTP on the
	// mesh port made shared nodes fingerprintable by DPI active
	// probes (GET / returned the Dashboard instead of the camouflage
	// site). The mesh port now carries Reality/gossip/mesh traffic
	// exclusively, and unrecognized traffic — including HTTP — is
	// proxied to the Reality camouflage destination.
	if err := webServer.Start(a.cfg.Node.WebAddr); err != nil {
		log.Fatalf("Failed to start web server: %v", err)
	}
	a.webServer = webServer
	log.Printf("  Web UI:     http://%s", a.cfg.Node.WebAddr)
	if a.joinServer != nil {
		log.Printf("  Join:       on web port (/api/join)")
	}
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

func (g *nodeJoinTokenGenerator) JoinServerURL() string {
	if !g.cfg.Join.Enabled {
		return ""
	}
	host := firstAdvertiseEndpointHost(g.cfg)

	// The join endpoint (/api/join) is attached to the Dashboard web
	// server (webServer.SetJoinHandler), which listens ONLY on the
	// dedicated web port (cfg.Node.WebAddr) since the
	// reality-discipline refactor removed HTTP from the mesh port.
	// Derive the URL from the web port regardless of mux/Reality
	// mode.
	addr := g.cfg.Node.WebAddr
	if addr == "" {
		addr = ":8080"
	}
	port := "8080"
	if idx := strings.LastIndex(addr, ":"); idx >= 0 && addr[idx+1:] != "" {
		port = addr[idx+1:]
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}

func (g *nodeJoinTokenGenerator) JoinEnabled() bool {
	return g.cfg.Join.Enabled && g.cfg.Reality.Enabled
}
