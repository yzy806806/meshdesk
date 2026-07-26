// Command meshdesk is the single entrypoint for the MeshDesk binary.
// Without --web, the node runs in agent-only mode (mesh transport + monitoring reporter).
// With --web, it also serves the Web UI (dashboard, WebSSH, file transfer, service management).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/p2p"
	"github.com/yzy806806/meshdesk/internal/service"
	"github.com/yzy806806/meshdesk/internal/transfer"
	"github.com/yzy806806/meshdesk/internal/web"
	"github.com/yzy806806/meshdesk/internal/webssh"
	"github.com/yzy806806/meshdesk/internal/xray"
)

func main() {
	// Handle "join" subcommand: meshdesk join <bootstrap-addr>
	if len(os.Args) >= 2 && os.Args[1] == "join" {
		runJoinSubcommand(os.Args[2:])
		return
	}

	var (
		configPath string
		webMode    bool
		genKey     bool
		relayMode  bool
	)
	flag.StringVar(&configPath, "config", "/etc/meshdesk/config.yaml", "path to config file")
	flag.BoolVar(&webMode, "web", false, "enable web UI mode")
	flag.BoolVar(&genKey, "gen-key", false, "generate a new WireGuard keypair and exit")
	flag.BoolVar(&relayMode, "relay", false, "enable relay mode (accept relay circuits from peers)")
	flag.Parse()

	if genKey {
		identity, err := mesh.GenerateIdentity()
		if err != nil {
			log.Fatalf("Failed to generate keypair: %v", err)
		}
		fmt.Printf("Private key: %s\n", identity.PrivateKey)
		fmt.Printf("Public key:  %s\n", identity.PublicKey)
		os.Exit(0)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		// If the config file doesn't exist, use defaults (auto-generates identity).
		if os.IsNotExist(err) {
			log.Printf("Config file %s not found, using defaults", configPath)
			cfg = config.Default()
		} else {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	if webMode {
		if cfg.Node.WebAddr == "" {
			cfg.Node.WebAddr = ":8080"
		}
	}

	// Create and start the mesh node.
	node, err := mesh.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create mesh node: %v", err)
	}
	defer node.Close()

	if err := node.Start(); err != nil {
		log.Fatalf("Failed to start mesh node: %v", err)
	}

	log.Printf("MeshDesk node started")
	log.Printf("  Public key: %s", node.Identity().PublicKey)
	log.Printf("  Mesh port:  %d", cfg.Mesh.Port)
	log.Printf("  Peers:      %d", node.RoutingTable().PeerCount())

	// Initialize the P2P gossip discovery layer (if enabled).
	var gossipLayer *p2p.GossipLayer
	var natTraversal *p2p.NatTraversal
	if cfg.P2P.Enabled {
		// Create the WireGuard delegate for dynamic peer management.
		wgDelegate := p2p.NewWireGuardDelegate(node)

		// Mark statically-configured peers so they are never removed by gossip.
		for _, peerCfg := range cfg.Peers {
			wgDelegate.MarkStaticPeer(peerCfg.PublicKey)
		}

		// Convert config.P2pConfig to p2p.P2pConfig.
		p2pCfg := p2p.FromConfig(cfg.P2P)
		p2pCfg.GossipPort = cfg.Mesh.GossipPort

		gl, err := p2p.NewGossipLayer(p2pCfg, node, wgDelegate)
		if err != nil {
			log.Fatalf("Failed to create P2P gossip layer: %v", err)
		}

		// Set local identity.
		hostname := cfg.Node.Hostname
		if hostname == "" {
			hostname, _ = os.Hostname()
		}
		role := "agent"
		if webMode {
			role = "web"
		}
		gl.SetLocalIdentity(hostname, role)
		gl.SetLocalCapabilities(
			cfg.Proxy.Relay.Enabled,
			len(cfg.Proxy.Exit.AllowedPorts) > 0 || cfg.Proxy.Exit.AllowAllPorts,
			cfg.Proxy.SS.Port != 0,
		)

		if err := gl.Start(); err != nil {
			log.Printf("Warning: failed to start P2P gossip layer: %v", err)
		} else {
			gossipLayer = gl
			log.Printf("  P2P:       gossip active (port %d, %d seeds)",
				cfg.Mesh.GossipPort, len(cfg.P2P.Seeds))
		}

		// Enable relay mode if --relay flag or config proxy.relay.enabled is set.
		// This initializes the RelaySessionManager, which handles circuit
		// setup/teardown/ping messages via gossip and tracks active circuits
		// for load-aware relay selection (P2P_NETWORKING_SPEC.md §5).
		if relayMode || cfg.Proxy.Relay.Enabled {
			maxCircuits := cfg.Proxy.Relay.MaxCircuits
			if maxCircuits <= 0 {
				maxCircuits = 1024
			}
			if err := gossipLayer.EnableRelayMode(maxCircuits); err != nil {
				log.Printf("Warning: failed to enable relay mode: %v", err)
			} else {
				log.Printf("  P2P:       relay mode active (maxCircuits=%d)", maxCircuits)
			}
		}

		// Initialize and start NAT traversal (if enabled).
		if cfg.P2P.NatTraversal {
			natCfg := p2p.NatTraversalFromP2pConfig(p2pCfg)
			natTraversal = p2p.NewNatTraversal(
				natCfg,
				wgDelegate,
				gl.Relay(),
				gl.Events(),
				cfg.Mesh.Port,
			)

			// Register a join handler so that NAT traversal is initiated
			// for each new peer discovered via gossip (§1.5 step 3).
			gl.Events().SetJoinHandler(func(meta *p2p.NodeMeta) {
				peerEndpoints := meta.Endpoints
				peerNatType := p2p.NatType(meta.NatType)
				natTraversal.InitiateConnection(meta.PublicKey, peerEndpoints, peerNatType)
			})

			// Register a leave handler to clean up NAT sessions.
			gl.Events().SetLeaveHandler(func(peerKey string) {
				natTraversal.RemoveConnection(peerKey)
			})

			if err := natTraversal.Start(); err != nil {
				log.Printf("Warning: failed to start NAT traversal: %v", err)
			} else {
				log.Printf("  P2P:       NAT traversal active (STUN + hole-punch + relay fallback)")
			}

			// Wire the gossip layer to the NAT traversal so it can send
			// relay control messages (SETUP, TEARDOWN) via gossip.
			natTraversal.SetGossipLayer(gossipLayer)
		}

		defer func() {
			if natTraversal != nil {
				natTraversal.Stop()
			}
			if gossipLayer != nil {
				gossipLayer.Stop()
			}
		}()
	}

	// Start the remote service management server (listens on mesh).
	// Every node accepts service management commands from authorized peers.
	remoteSvcListener := &meshListenerAdapter{node: node}
	// Use the raw service manager; the RemoteServer wraps it with
	// AuthorizedServiceManager per-request using the caller's PeerID.
	var remoteSvcMgr service.ServiceManager
	if execBackend, err := service.NewExecBackend("", 30*time.Second); err != nil {
		// Graceful degradation: use NullBackend when systemd is unavailable (Gap 5 fix).
		log.Printf("Warning: systemctl not available for remote service server: %v — using null backend", err)
		remoteSvcMgr = service.NewNullBackend()
	} else {
		remoteSvcMgr = execBackend
	}
	// Wire the auth engine into the remote server for per-peer capability
	// enforcement. Each incoming request's PeerID field is used to construct
	// an AuthorizedServiceManager scoped to that caller.
	remoteAuthEngine := auth.NewCapabilityEngine(cfg, auth.NewAuditLogger(log.Writer()))
	var remoteSvcServer *service.RemoteServer
	if remoteAuthEngine != nil {
		remoteSvcServer = service.NewRemoteServerWithAuth(remoteSvcMgr, remoteAuthEngine, remoteSvcListener, service.DefaultServicePort)
	} else {
		remoteSvcServer = service.NewRemoteServer(remoteSvcMgr, remoteSvcListener, service.DefaultServicePort)
	}
	if err := remoteSvcServer.Start(); err != nil {
		log.Printf("Warning: failed to start remote service server: %v", err)
	} else {
		log.Printf("  Service RPC: listening on mesh port %d", service.DefaultServicePort)
	}
	defer remoteSvcServer.Stop()

	// Start the file transfer receiver (listens on mesh).
	// Every node accepts incoming file transfers from authorized peers.
	// The receiver is wired with capability enforcement (Gap 2 fix) and
	// file size limits from config (Gap 4 fix).
	transferListener := &meshListenerAdapter{node: node}
	transferAuthEngine := auth.NewCapabilityEngine(cfg, auth.NewAuditLogger(log.Writer()))
	var transferAuthChecker transfer.AuthChecker
	if transferAuthEngine != nil {
		transferAuthChecker = auth.NewTransferAuthChecker(transferAuthEngine)
	}
	uploadDir := cfg.Transfer.UploadDir
	if uploadDir == "" {
		uploadDir = config.DefaultUploadDir
	}
	transferServer := transfer.NewReceiverWithAuth(
		transferListener, web.TransferPort, uploadDir,
		cfg.Transfer.MaxFileSize, transferAuthChecker,
	)
	if err := transferServer.Start(); err != nil {
		log.Printf("Warning: failed to start file transfer receiver: %v", err)
	} else {
		log.Printf("  File transfer: listening on mesh port %d (max %d bytes)", web.TransferPort, cfg.Transfer.MaxFileSize)
	}
	defer transferServer.Stop()

	// Start monitoring reporter (runs on every node — agent or web mode).
	var monitorStore *monitor.Store
	var reporter *monitor.Reporter
	nodeID := node.Identity().PublicKey
	hostname := cfg.Node.Hostname

	reporter = monitor.NewReporter(monitor.ReporterConfig{
		NodeID:     nodeID,
		Hostname:   hostname,
		Dialer:     &meshDialerAdapter{node: node},
		Collectors: cfg.Monitoring.Collectors,
		Interval:   cfg.Monitoring.Interval,
		Port:       cfg.Monitoring.Port,
	})
	if err := reporter.Start(); err != nil {
		log.Printf("Warning: failed to start monitoring reporter: %v", err)
	} else {
		monitorStore = reporter.LocalStore()
		log.Printf("  Monitor:   reporter active (interval=%ds)", cfg.Monitoring.Interval)
	}
	defer reporter.Stop()

	var webServer *web.Server
	var xrayMgr *xray.XrayConfigManager
	if webMode {
		// Create the auth capability engine first, so it can be wired
		// into the aggregator for monitor_write enforcement (Decision E).
		// Use rotation-enabled audit logger: 100 MB max, 5 backups.
		auditLogger, err := auth.NewAuditFileLoggerWithRotation("/var/log/meshdesk-audit.jsonl",
			auth.DefaultAuditMaxBytes, auth.DefaultAuditMaxRotates)
		if err != nil {
			log.Printf("Warning: could not open audit log file: %v — using stderr", err)
			auditLogger = auth.NewAuditLogger(log.Writer())
		}
		defer auditLogger.Close()

		authEngine := auth.NewCapabilityEngine(cfg, auditLogger)

		// Wire monitor auth checker into the aggregator so that every
		// incoming metric push is checked for the monitor_write capability.
		// If authEngine is nil, the checker is nil and the aggregator
		// accepts all pushes (testing mode only).
		var monitorAuthChecker monitor.AuthChecker
		if authEngine != nil {
			monitorAuthChecker = auth.NewMonitorAuthChecker(authEngine)
		}

		// On web nodes, also run the aggregator to receive metric pushes.
		aggregator := monitor.NewAggregator(monitor.AggregatorConfig{
			Store:       monitorStore,
			Dialer:      &meshListenerAdapter{node: node},
			Port:        cfg.Monitoring.Port,
			AuthChecker: monitorAuthChecker,
		})
		if err := aggregator.Start(); err != nil {
			log.Printf("Warning: failed to start metric aggregator: %v", err)
		} else {
			log.Printf("  Aggregator: listening on mesh port %d", cfg.Monitoring.Port)
		}
		defer aggregator.Stop()

		// Use the aggregator's store (which may have collected metrics from other nodes).
		if aggregator.Store() != nil {
			monitorStore = aggregator.Store()
		}

		// Create the WebSSH hub for terminal sessions.
		sshClient := webssh.NewSSHClient(
			web.NewMeshDialer(node),
			time.Duration(cfg.WebSSH.DialTimeout)*time.Second,
			nil, // accept-first-key for now; TODO: known-hosts store
		)
		sshHub := webssh.NewHub(
			sshClient,
			web.NewPeerResolver(node.RoutingTable()),
			cfg.WebSSH.Port,
			cfg.WebSSH.MaxSessions,
			time.Duration(cfg.WebSSH.ReadDeadline)*time.Second,
			time.Duration(cfg.WebSSH.WriteDeadline)*time.Second,
		)

		// Create the service manager (systemctl backend, with NullBackend fallback).
		var svcMgr service.ServiceManager
		if execBackend, err := service.NewExecBackend("", 30*time.Second); err != nil {
			log.Printf("Warning: systemctl not available: %v — service management disabled", err)
			svcMgr = service.NewNullBackend()
		} else {
			svcMgr = execBackend
		}

		// Create the xray-core config manager (if enabled in config).
		if cfg.Xray.Enabled {
			xrayOpts := xray.ManagerOptions{
				BinaryPath: cfg.Xray.BinaryPath,
				ConfigDir:  cfg.Xray.ConfigDir,
				LogLines:   cfg.Xray.LogLines,
				ApiPort:    cfg.Xray.ApiPort,
				ApiListen:  cfg.Xray.ApiListen,
			}
			if cfg.Xray.HealthCheckInterval > 0 {
				xrayOpts.HealthCheckInterval = time.Duration(cfg.Xray.HealthCheckInterval) * time.Second
			}
			if cfg.Xray.ReadinessTimeout > 0 {
				xrayOpts.ReadinessTimeout = time.Duration(cfg.Xray.ReadinessTimeout) * time.Second
			}
			// Use a file-based config store for persistence across restarts.
			if xrayOpts.ConfigDir == "" {
				xrayOpts.ConfigDir = xray.DefaultConfigDir
			}
			xrayOpts.Store = xray.NewFileConfigStore(
				filepath.Join(xrayOpts.ConfigDir, "state.json"),
			)
			mgr, err := xray.NewManager(xrayOpts)
			if err != nil {
				log.Printf("Warning: failed to create xray config manager: %v — xray integration disabled", err)
			} else {
				xrayMgr = mgr
				// Auto-start xray if there are configured inbounds.
				if len(mgr.ListInbounds()) > 0 {
					if err := mgr.Start(); err != nil {
						log.Printf("Warning: failed to start xray-core: %v — use /api/xray/start to retry", err)
					} else {
						log.Printf("  Xray:       started (pid=%d, config=%s)", mgr.Status().PID, mgr.ConfigPath())
					}
				} else {
					log.Printf("  Xray:       manager ready (no inbounds configured — use /api/xray/inbound to add)")
				}
			}
		}

		// Create and start the web server.
		webServer, err = web.New(web.Deps{
			Config:       cfg,
			Node:         node,
			MonitorStore: monitorStore,
			SSHHub:       sshHub,
			AuthEngine:   authEngine,
			ServiceMgr:   svcMgr,
			MeshDialer:   web.NewPeerMeshDialer(node),
			XrayManager:  xrayMgr,
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
		if alertStore != nil {
			if authEngine != nil {
				authEngine.SetDenyCallback(alertStore.HandleAuthDenial)
			}
			// Wire the remote service auth engine (used for mesh-internal
			// service management requests) to the same alert store.
			if remoteAuthEngine != nil {
				remoteAuthEngine.SetDenyCallback(alertStore.HandleAuthDenial)
			}
			// Wire the transfer auth engine (used for file transfer
			// authorization) to the same alert store.
			if transferAuthEngine != nil {
				transferAuthEngine.SetDenyCallback(alertStore.HandleAuthDenial)
			}
			if node != nil {
				rt := node.RoutingTable()
				rt.SetJoinCallback(alertStore.HandlePeerJoin)
				rt.SetLeaveCallback(alertStore.HandlePeerLeave)
			}
		}

		if err := webServer.Start(cfg.Node.WebAddr); err != nil {
			log.Fatalf("Failed to start web server: %v", err)
		}
		defer webServer.Stop()

		log.Printf("  Web UI:     http://%s", cfg.Node.WebAddr)
	} else {
		log.Printf("  Mode:       agent-only")
	}

	// Save config (in case identity was auto-generated).
	if err := config.Save(configPath, cfg); err != nil {
		log.Printf("Warning: could not save config: %v", err)
	}

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("Shutting down...")

	// Send graceful leave notice before tearing down (§4).
	// The gossip layer's Stop() also sends a LeaveNotice, but sending
	// here ensures it goes out before the web server stops.
	if gossipLayer != nil && gossipLayer.IsStarted() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := gossipLayer.SendLeaveNotice(ctx); err != nil {
			log.Printf("Warning: leave notice: %v", err)
		}
		cancel()
	}

	if webServer != nil {
		webServer.Stop()
	}
	// Stop xray-core subprocess if running.
	if xrayMgr != nil {
		_ = xrayMgr.Stop()
	}
	_ = gossipLayer  // silence unused warning if P2P disabled
	_ = natTraversal // silence unused warning if NAT traversal disabled
}

// meshDialerAdapter adapts mesh.MeshNode to the monitor.MeshDialer interface.
type meshDialerAdapter struct {
	node *mesh.MeshNode
}

func (d *meshDialerAdapter) DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error) {
	// Resolve peer ID to mesh IP via routing table.
	entry, ok := d.node.RoutingTable().GetPeer(peerID)
	if !ok {
		return nil, fmt.Errorf("peer %s not found in routing table", peerID)
	}
	if len(entry.AllowedIPs) == 0 {
		return nil, fmt.Errorf("peer %s has no mesh IP", peerID)
	}
	meshIP := entry.AllowedIPs[0]
	// Strip CIDR if present
	if idx := strings.IndexByte(meshIP, '/'); idx >= 0 {
		meshIP = meshIP[:idx]
	}
	addr := fmt.Sprintf("%s:%d", meshIP, port)
	return d.node.Dial(ctx, "tcp", addr)
}

// meshListenerAdapter adapts mesh.MeshNode to the monitor.MeshListener interface.
type meshListenerAdapter struct {
	node *mesh.MeshNode
}

func (a *meshListenerAdapter) ListenMesh(port int) (net.Listener, error) {
	return a.node.Net().ListenTCP(&net.TCPAddr{Port: port})
}

// runJoinSubcommand implements `meshdesk join <bootstrap-addr>`.
//
// It creates a mesh node, configures the bootstrap as a static peer,
// starts the gossip layer, sends a JoinRequest to the bootstrap, and
// on success triggers full memberlist state sync. This implements the
// Dynamic Join Protocol from P2P_NETWORKING_SPEC.md §4.
//
// Usage:
//
//	meshdesk join 203.0.113.5:51820            # bootstrap endpoint
//	meshdesk join 10.10.0.5:7946                # bootstrap mesh IP:gossip port
//	meshdesk join --config /path/to/config.yaml 203.0.113.5:51820
func runJoinSubcommand(args []string) {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	configPath := fs.String("config", "/etc/meshdesk/config.yaml", "path to config file")
	bootstrapKey := fs.String("bootstrap-key", "", "bootstrap node's WireGuard public key (hex, required if not in config peers)")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		log.Fatalf("Usage: meshdesk join <bootstrap-addr>\n\n" +
			"bootstrap-addr is the bootstrap node's endpoint (host:port)\n" +
			"or mesh IP:gossip port.")
	}

	bootstrapAddr := fs.Arg(0)

	// Load config.
	cfg, err := config.Load(*configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Config file %s not found, using defaults", *configPath)
			cfg = config.Default()
		} else {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	// Enable P2P for join mode.
	cfg.P2P.Enabled = true
	if cfg.Mesh.GossipPort == 0 {
		cfg.Mesh.GossipPort = 7946
	}

	// If no seeds configured, add the bootstrap address as a seed.
	if len(cfg.P2P.Seeds) == 0 {
		// Parse the bootstrap address to extract host:port.
		host, port, err := p2p.ParseBootstrapAddr(bootstrapAddr, cfg.Mesh.GossipPort)
		if err != nil {
			log.Fatalf("Invalid bootstrap address %q: %v", bootstrapAddr, err)
		}
		seedAddr := net.JoinHostPort(host, port)
		cfg.P2P.Seeds = []string{seedAddr}
		log.Printf("Using bootstrap seed: %s", seedAddr)
	}

	// If a bootstrap public key was provided, add it as a static peer
	// so WireGuard can establish the initial connection.
	if *bootstrapKey != "" {
		// Parse the bootstrap address for the endpoint.
		host, port, err := p2p.ParseBootstrapAddr(bootstrapAddr, cfg.Mesh.Port)
		if err != nil {
			log.Fatalf("Invalid bootstrap address: %v", err)
		}
		endpoint := net.JoinHostPort(host, port)

		// Compute the bootstrap's mesh IP from its public key.
		bootstrapMeshIP := p2p.DeriveMeshIPFromHex(*bootstrapKey)

		peerCfg := config.PeerConfig{
			PublicKey:   *bootstrapKey,
			Endpoint:    endpoint,
			AllowedIPs:  []string{bootstrapMeshIP + "/32"},
			Obfuscation: "padded",
		}
		cfg.Peers = append(cfg.Peers, peerCfg)
		log.Printf("Added bootstrap as static peer: %s@%s (mesh IP %s)",
			(*bootstrapKey)[:8], endpoint, bootstrapMeshIP)
	}

	// Create the mesh node.
	node, err := mesh.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create mesh node: %v", err)
	}
	defer node.Close()

	if err := node.Start(); err != nil {
		log.Fatalf("Failed to start mesh node: %v", err)
	}

	log.Printf("MeshDesk join mode starting...")
	log.Printf("  Public key: %s", node.Identity().PublicKey)
	log.Printf("  Mesh port:  %d", cfg.Mesh.Port)

	// Create the WireGuard delegate for dynamic peer management.
	wgDelegate := p2p.NewWireGuardDelegate(node)

	// Mark statically-configured peers (the bootstrap) as static.
	for _, peerCfg := range cfg.Peers {
		wgDelegate.MarkStaticPeer(peerCfg.PublicKey)
	}

	// Create the gossip layer.
	p2pCfg := p2p.FromConfig(cfg.P2P)
	p2pCfg.GossipPort = cfg.Mesh.GossipPort

	gl, err := p2p.NewGossipLayer(p2pCfg, node, wgDelegate)
	if err != nil {
		log.Fatalf("Failed to create gossip layer: %v", err)
	}

	// Set local identity.
	hostname := cfg.Node.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	gl.SetLocalIdentity(hostname, "agent")
	gl.SetLocalCapabilities(
		cfg.Proxy.Relay.Enabled,
		len(cfg.Proxy.Exit.AllowedPorts) > 0 || cfg.Proxy.Exit.AllowAllPorts,
		cfg.Proxy.SS.Port != 0,
	)

	if err := gl.Start(); err != nil {
		log.Fatalf("Failed to start gossip layer: %v", err)
	}
	defer gl.Stop()

	// Wait a moment for the transport to come up, then join seeds.
	time.Sleep(500 * time.Millisecond)

	log.Printf("Joining mesh via bootstrap %s...", bootstrapAddr)

	// Join the gossip cluster via the bootstrap seed.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	contacted, err := gl.JoinSeeds(ctx, cfg.P2P.Seeds)
	if err != nil {
		log.Printf("Warning: initial seed join: %v (contacted %d)", err, contacted)
	} else {
		log.Printf("Joined gossip cluster (%d seed contacted)", contacted)
	}

	// If we know the bootstrap's public key, send a JoinRequest
	// to authenticate and get the full peer list.
	if *bootstrapKey != "" {
		joinCtx, joinCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer joinCancel()

		result, err := gl.RequestJoin(joinCtx, *bootstrapKey)
		if err != nil {
			log.Fatalf("Join request failed: %v", err)
		}

		if !result.Accepted {
			log.Fatalf("Join rejected: %s", result.RejectReason)
		}

		log.Printf("Join accepted by bootstrap")
		if result.Bootstrap != nil {
			log.Printf("  Bootstrap mesh IP: %s", result.Bootstrap.MeshIP)
		}
		log.Printf("  Known peers from bootstrap: %d", len(result.KnownPeers))
		for _, peer := range result.KnownPeers {
			log.Printf("    - %s (mesh IP %s, role %s)",
				peer.PublicKey[:8], peer.MeshIP, peer.Role)
		}
	} else {
		log.Printf("No bootstrap key provided — relying on memberlist push/pull for peer discovery")
	}

	log.Printf("MeshDesk joined the mesh. Waiting for peers to converge...")

	// Give the gossip layer time to converge.
	convergeTimer := time.NewTimer(10 * time.Second)
	defer convergeTimer.Stop()

	// Wait for shutdown signal (like normal mode, but join-only).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		log.Printf("Shutting down...")
	case <-convergeTimer.C:
		log.Printf("Initial convergence complete (%d members in cluster)", gl.MemberCount())
		// Continue running as a normal mesh node.
		<-sigCh
		log.Printf("Shutting down...")
	}

	// Send graceful leave notice.
	leaveCtx, leaveCancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := gl.SendLeaveNotice(leaveCtx); err != nil {
		log.Printf("Warning: leave notice: %v", err)
	}
	leaveCancel()
}
