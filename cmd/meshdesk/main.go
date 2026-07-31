// Command meshdesk is the single entrypoint for the MeshDesk binary.
// Without --web, the node runs in agent-only mode (mesh transport + monitoring reporter).
// With --web, it also serves the Web UI (dashboard, WebSSH, file transfer, service management).
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/p2p"
	"github.com/yzy806806/meshdesk/internal/proxy"
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

	// Attempt to connect statically configured peers with Reality TLS.
	// This establishes v2 mesh sessions (Reality TLS + smux). If the
	// REALITY TLS handshake fails (library compatibility), peers are
	// still discovered via gossip and added to the routing table by
	// the WireGuardDelegate.
	for _, peerCfg := range cfg.Peers {
		if peerCfg.Reality != nil && peerCfg.Endpoint != "" {
			go func(pc config.PeerConfig) {
				backoff := 5 * time.Second
				for attempt := 0; attempt < 3; attempt++ {
					if err := node.AddPeer(pc); err != nil {
						log.Printf("Warning: peer %s connect attempt %d failed: %v", pc.Endpoint, attempt+1, err)
						time.Sleep(backoff)
						backoff *= 2
						continue
					}
					log.Printf("  Connected peer: %s", pc.Endpoint)
					return
				}
				// REALITY TLS may fail due to library compatibility.
				// Gossip discovery will still populate the routing table.
				log.Printf("  Peer %s: REALITY TLS failed, relying on gossip discovery", pc.Endpoint)
			}(peerCfg)
		}
	}

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
		p2pCfg.WgPort = cfg.Mesh.Port

		// Ordinary nodes (no Reality listener) bind gossip to localhost
		// so no external port is exposed. Shared nodes use MuxTransport
		// which handles the bind.
		if !cfg.Reality.Enabled {
			p2pCfg.GossipBindAddr = "127.0.0.1"
		}

		// Decode the Ed25519 private key for gossip identity.
		identityBytes, err := hex.DecodeString(node.Identity().PrivateKey)
		if err != nil {
			log.Fatalf("Failed to decode identity private key: %v", err)
		}
		gl, err := p2p.NewGossipLayer(p2pCfg, identityBytes, wgDelegate)
		if err != nil {
			log.Fatalf("Failed to create P2P gossip layer: %v", err)
		}
		gl.SetWireGuardDelegate(wgDelegate)

		// Inject the MuxTransport from the mesh node so gossip and Reality
		// TLS share the same TCP port.
		if mt := node.MuxTransport(); mt != nil {
			gl.SetTransport(mt)
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
			// TODO(v2): endpoint notifier will be wired via the new protocol layer.
			// v1 used node.ObfuscatingBind().SetEndpointNotifier(gossipLayer).
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

		// Initialize the relay path builder for NAT peer relay selection.
		// This enables automatic relay circuit setup when NAT peers (no
		// public endpoint) are discovered via gossip. The path builder:
		//   1. Selects top-K=2 relay candidates via RelaySelector
		//   2. Sends circuit_setup to the primary relay
		//   3. On accept, extends the relay peer's AllowedIPs to include
		//      the NAT peer's mesh IP (so WireGuard routes through the relay)
		//   4. Health-monitors with PING/PONG every 30s, failover to secondary
		localKey := node.Identity().PublicKey
		rpb := p2p.NewRelayPathBuilder(
			gossipLayer,
			wgDelegate,
			gl.Relay(),
			gl.Events(),
			localKey,
		)

		// Wire the RTT estimator from the gossip layer.
		if impl, ok := rpb.(*p2p.RelayPathBuilderImpl); ok {
			impl.SetRTTEstimator(gossipLayer.EstimateRTT)
		}

		// Install the path builder into the event delegate so NotifyJoin
		// delegates NAT peers to it.
		gl.Events().SetRelayPathBuilder(rpb)

		// Start the NAT peer reconciliation loop (handles relays joining
		// after NAT peers are discovered).
		if impl, ok := rpb.(*p2p.RelayPathBuilderImpl); ok {
			impl.StartReconciliationLoop()
		}

		// Wire the path builder into the relay session manager so that
		// circuit_accept/reject/pong messages are dispatched to it.
		if rsm := gl.RelaySessionManager(); rsm != nil {
			rsm.SetRelayPathBuilder(rpb)
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

	// Start the WebSSH server (listens on mesh).
	// Every node accepts incoming SSH connections from the web node
	// for terminal sessions. The SSH server allocates a PTY and runs
	// a shell, providing remote terminal access via the mesh.
	sshListener := &meshListenerAdapter{node: node}
	sshServer, err := webssh.NewSSHServer(cfg.WebSSH.HostKey, cfg.WebSSH.Shell)
	if err != nil {
		log.Printf("Warning: failed to create WebSSH server: %v", err)
	} else {
		sshLn, err := sshListener.ListenMesh(cfg.WebSSH.Port)
		if err != nil {
			log.Printf("Warning: failed to listen for WebSSH on mesh port %d: %v", cfg.WebSSH.Port, err)
		} else {
			go func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if err := sshServer.Serve(ctx, sshLn); err != nil {
					log.Printf("WebSSH server stopped: %v", err)
				}
			}()
			log.Printf("  WebSSH:     listening on mesh port %d", cfg.WebSSH.Port)
			defer sshServer.Close()
		}
	}

	// ───────────────────────────────────────────────────────────────────
	// Proxy data plane (multi-path anonymous proxy).
	//
	// The proxy subsystem has three roles that can run independently:
	//   - Entry node: accepts Shadowsocks user traffic, chunks it,
	//     and dispatches across two disjoint relay paths to the exit.
	//   - Exit node: receives encrypted chunks, reassembles the stream,
	//     and forwards to the target TCP destination.
	//   - Relay node: forwards chunks between entry and exit (already
	//     wired via gossipLayer.EnableRelayMode above).
	//
	// Entry and exit nodes are created based on config flags:
	//   - Entry: requires cfg.Proxy.SS.Port != 0 AND cfg.Proxy.ExitAddr != ""
	//   - Exit:  requires cfg.Proxy.Exit has AllowedPorts or AllowAllPorts
	//
	// Both follow the graceful-degradation pattern: a failure logs a
	// warning and continues, rather than fatally exiting.
	// ───────────────────────────────────────────────────────────────────
	meshDialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		return node.Dial(ctx, network, address)
	}

	var proxyEntryNode *proxy.EntryNode
	var proxyExitNode *proxy.ExitNode
	var proxySecSink *proxy.SecurityEventSink

	// Create a shared security event sink for all proxy subsystems.
	// When a web server is running, its AlertStore callback is wired
	// after the web server is created (see alert wiring below).
	proxySecSink = proxy.NewSecurityEventSink()

	// ── Entry Node ──
	// The entry node accepts Shadowsocks connections and dispatches
	// them through multi-path circuits to the exit node.
	if cfg.Proxy.SS.Port != 0 && cfg.Proxy.ExitAddr != "" {
		ssListenAddr := cfg.Proxy.SS.ListenAddr
		if ssListenAddr == "" {
			ssListenAddr = fmt.Sprintf(":%d", cfg.Proxy.SS.Port)
		}

		// Build circuit config from the YAML config.
		circuitCfg := proxy.CircuitConfig{
			IdleTimeout:         time.Duration(cfg.Proxy.Circuit.IdleTimeout) * time.Second,
			KeepaliveInterval:   time.Duration(cfg.Proxy.Circuit.KeepaliveInterval) * time.Second,
			NACKTimeout:         time.Duration(cfg.Proxy.Circuit.NACKTimeout) * time.Second,
			OrphanTimeout:       time.Duration(cfg.Proxy.Circuit.OrphanTimeout) * time.Second,
			MaxReassemblyWindow: cfg.Proxy.Circuit.MaxReassemblyWindow,
		}
		if circuitCfg.IdleTimeout == 0 {
			circuitCfg = proxy.DefaultCircuitConfig()
		}

		entryCfg := proxy.EntryNodeConfig{
			SSConfig: proxy.SSConfig{
				Password:   cfg.Proxy.SS.Password,
				Cipher:     cfg.Proxy.SS.Cipher,
				ListenAddr: ssListenAddr,
			},
			CircuitCfg:       circuitCfg,
			ChunkerStrategy:  cfg.Proxy.ChunkerStrategy,
			ChunkerCfg:       proxy.DefaultChunkerConfig(),
			DebugFixedChunks: cfg.Proxy.DebugFixedChunks,
			ExitAddr:         cfg.Proxy.ExitAddr,
			DialFunc:         meshDialFunc,
			SecSink:          proxySecSink,
		}

		// Configure path selection.
		if cfg.Proxy.PathSelection.Mode == "auto" {
			entryCfg.PathSelectionMode = "auto"
			entryCfg.PathSelector = proxy.NewPathSelector(proxy.PathSelectorConfig{
				MaxRelaysPerPath: cfg.Proxy.PathSelection.MaxRelaysPerPath,
				ProbeTimeout:     time.Duration(cfg.Proxy.PathSelection.ProbeTimeoutSec) * time.Second,
				ProbeConcurrency: cfg.Proxy.PathSelection.ProbeConcurrency,
				MaxCandidates:    cfg.Proxy.PathSelection.MaxCandidates,
				PathCount:        2,
			})
			// CandidateRelays would be populated from gossip-discovered
			// relay-capable peers. For now, leave empty — auto selection
			// will fail with a clear error if no candidates are provided.
		} else {
			// Manual mode: build Path structs from config.Paths.
			entryCfg.PathSelectionMode = "manual"
			if len(cfg.Proxy.Paths) >= 2 {
				entryCfg.Path1 = &proxy.Path{Relays: cfg.Proxy.Paths[0]}
				entryCfg.Path2 = &proxy.Path{Relays: cfg.Proxy.Paths[1]}
			}
		}

		proxyEntryNode = proxy.NewEntryNode(entryCfg)
		if err := proxyEntryNode.Start(); err != nil {
			log.Printf("Warning: failed to start proxy entry node: %v", err)
			proxyEntryNode = nil
		} else {
			log.Printf("  Proxy:      entry node active (SS listener on %s, exit=%s)",
				ssListenAddr, cfg.Proxy.ExitAddr)
		}
	}

	// ── Exit Node ──
	// The exit node receives encrypted chunks from relay paths,
	// reassembles them, and dials the target TCP destination.
	if len(cfg.Proxy.Exit.AllowedPorts) > 0 || cfg.Proxy.Exit.AllowAllPorts {
		exitCircuitCfg := proxy.DefaultCircuitConfig()
		if cfg.Proxy.Circuit.OrphanTimeout > 0 {
			exitCircuitCfg.OrphanTimeout = time.Duration(cfg.Proxy.Circuit.OrphanTimeout) * time.Second
		}
		if cfg.Proxy.Circuit.NACKTimeout > 0 {
			exitCircuitCfg.NACKTimeout = time.Duration(cfg.Proxy.Circuit.NACKTimeout) * time.Second
		}
		if cfg.Proxy.Circuit.MaxReassemblyWindow > 0 {
			exitCircuitCfg.MaxReassemblyWindow = cfg.Proxy.Circuit.MaxReassemblyWindow
		}

		exitCfg := proxy.ExitConfig{
			CircuitCfg:       exitCircuitCfg,
			AllowedPorts:     cfg.Proxy.Exit.AllowedPorts,
			AllowAllPorts:    cfg.Proxy.Exit.AllowAllPorts,
			ChunkerStrategy:  cfg.Proxy.ChunkerStrategy,
			ChunkerCfg:       proxy.DefaultChunkerConfig(),
			DebugFixedChunks: cfg.Proxy.DebugFixedChunks,
			Dialer:           net.Dial,
		}

		proxyExitNode = proxy.NewExitNode(exitCfg)
		proxyExitNode.SetSecurityEventSink(proxySecSink)

		// Start orphan cleanup background goroutine.
		exitCtx, exitCancel := context.WithCancel(context.Background())
		go proxyExitNode.StartOrphanCleanup(exitCtx)

		log.Printf("  Proxy:      exit node active (allowed_ports=%v, allow_all=%v)",
			cfg.Proxy.Exit.AllowedPorts, cfg.Proxy.Exit.AllowAllPorts)

		defer func() {
			exitCancel()
			proxyExitNode.Close()
		}()
	}

	if proxyEntryNode != nil {
		defer proxyEntryNode.Close()
	}

	// Start monitoring reporter (runs on every node — agent or web mode).
	var monitorStore *monitor.Store
	var reporter *monitor.Reporter
	nodeID := node.Identity().PublicKey
	hostname := cfg.Node.Hostname

	reporter = monitor.NewReporter(monitor.ReporterConfig{
		NodeID:     nodeID,
		Hostname:   hostname,
		Dialer:     &meshDialerAdapter{node: node, gossip: gossipLayer},
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
		// NOTE: In v2 with mesh-internal connections, the auth checker
		// rejects pushes from peers not in authorized_keys. For now,
		// set to nil to allow all mesh-discovered peers to push metrics.
		// TODO: Implement proper mesh identity authorization.
		var monitorAuthChecker monitor.AuthChecker
		_ = monitorAuthChecker // suppress unused warning

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
		knownHosts := webssh.NewKnownHostsStore()
		sshClient := webssh.NewSSHClient(
			web.NewMeshDialer(node),
			time.Duration(cfg.WebSSH.DialTimeout)*time.Second,
			knownHosts.HostKeyCallback(),
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
			// DrainTimeout: -1 means disable drain entirely, 0 means use default.
			if cfg.Xray.DrainTimeout < 0 {
				xrayOpts.DrainTimeout = -1 // disable
			} else if cfg.Xray.DrainTimeout > 0 {
				xrayOpts.DrainTimeout = time.Duration(cfg.Xray.DrainTimeout) * time.Second
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
		// Wire gossip liveness into the web server for topology.
		var webLiveness web.PeerLiveness
		if gossipLayer != nil {
			webLiveness = &gossipLiveness{
				gl:       gossipLayer,
				localKey: node.Identity().PublicKey,
			}
		}

		webServer, err = web.New(web.Deps{
			Config:              cfg,
			Node:                node,
			MonitorStore:        monitorStore,
			SSHHub:              sshHub,
			AuthEngine:          authEngine,
			ServiceMgr:          svcMgr,
			MeshDialer:          web.NewPeerMeshDialer(node),
			XrayManager:         xrayMgr,
			ProxyStatusProvider: &entryNodeStatusAdapter{entryNode: proxyEntryNode},
			Liveness:            webLiveness,
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
			// Wire proxy security events into the alert store.
			if proxySecSink != nil {
				proxySecSink.SetCallback(func(event proxy.SecurityEvent) {
					alertStore.HandleProxySecurityEvent(event)
				})
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
	// At startup this is fatal: if the auto-generated identity cannot be
	// persisted, the node would get a new identity on every restart,
	// breaking peer trust. Hot-reload saves (via HTTP handlers) remain
	// non-fatal because the process is already running and the error is
	// surfaced to the operator via the API response.
	if err := config.Save(configPath, cfg); err != nil {
		log.Fatalf("Failed to save config to %s: %v", configPath, err)
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
	node   *mesh.MeshNode
	gossip *p2p.GossipLayer
}

func (d *meshDialerAdapter) DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error) {
	// In v2, DialMesh opens a virtual-port stream over an existing smux
	// session. The peer must already be connected (via AddPeer or an
	// inbound session). peerID is the peer's identity hex.
	// If no session exists, DialVirtualPort will try to establish one
	// using the peer's endpoint from the routing table or config.
	// If that fails (routing table doesn't have gossip peers), fall back
	// to looking up the peer's endpoint from the gossip layer.
	conn, err := d.node.DialVirtualPort(ctx, peerID, port)
	if err == nil {
		return conn, nil
	}

	// Fall back: try to get peer endpoint from the gossip layer.
	if d.gossip != nil {
		for _, meta := range d.gossip.KnownPeers() {
			if meta.PublicKey == peerID && len(meta.Endpoints) > 0 {
				log.Printf("[monitor] tryPush: fallback dialing peer %s via endpoints %v", peerID[:min(len(peerID), 16)]+"...", meta.Endpoints)
				for _, ep := range meta.Endpoints {
					// Use a fresh context with generous timeout —
					// the reporter's 10s context may have been
					// consumed by the initial DialVirtualPort attempt.
					dialCtx, dialCancel := context.WithTimeout(context.Background(), 30*time.Second)
					stream, dialErr := d.node.DialPeerByEndpoint(dialCtx, ep)
					dialCancel()
					if dialErr == nil {
						// Session established, now open a stream with
						// the correct virtual port.
						stream.Close() // close port-0 stream
						return d.node.DialVirtualPort(ctx, peerID, port)
					}
					log.Printf("[monitor] tryPush: DialPeerByEndpoint to %s failed: %v", ep, dialErr)
				}
				break
			}
		}
	}

	return nil, fmt.Errorf("mesh: DialMesh to %s failed: %w", peerID[:min(len(peerID), 16)]+"...", err)
}

// meshListenerAdapter adapts mesh.MeshNode to the monitor.MeshListener interface.
type meshListenerAdapter struct {
	node *mesh.MeshNode
}

func (a *meshListenerAdapter) ListenMesh(port int) (net.Listener, error) {
	return a.node.ListenVirtualPort(port)
}

// entryNodeStatusAdapter adapts *proxy.EntryNode to the
// web.ProxyStatusProvider interface. It converts the proxy package's
// EntryNodeStatus to the web package's ProxyStatusData struct, which
// the /api/proxy/status endpoint serializes as JSON.
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

// gossipLiveness adapts *p2p.GossipLayer to web.PeerLiveness.
// It queries the gossip layer's event delegate (metaCache) to determine
// which peers are currently alive in the memberlist cluster.
type gossipLiveness struct {
	gl       *p2p.GossipLayer
	localKey string
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

		// v2: no mesh IP derivation — peer ID is the routing key.
		peerCfg := config.PeerConfig{
			PublicKey: *bootstrapKey,
			Endpoint:  endpoint,
		}
		cfg.Peers = append(cfg.Peers, peerCfg)
		log.Printf("Added bootstrap as static peer: %s@%s",
			(*bootstrapKey)[:8], endpoint)
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
	p2pCfg.WgPort = cfg.Mesh.Port

	// Decode the Ed25519 private key for gossip identity.
	identityBytes, err := hex.DecodeString(node.Identity().PrivateKey)
	if err != nil {
		log.Fatalf("Failed to decode identity private key: %v", err)
	}
	gl, err := p2p.NewGossipLayer(p2pCfg, identityBytes, wgDelegate)
	if err != nil {
		log.Fatalf("Failed to create gossip layer: %v", err)
	}
	gl.SetWireGuardDelegate(wgDelegate)

	// Inject the MuxTransport from the mesh node so gossip and Reality
	// TLS share the same TCP port.
	if mt := node.MuxTransport(); mt != nil {
		gl.SetTransport(mt)
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
			log.Printf("  Bootstrap public key: %s", result.Bootstrap.PublicKey[:8])
		}
		log.Printf("  Known peers from bootstrap: %d", len(result.KnownPeers))
		for _, peer := range result.KnownPeers {
			log.Printf("    - %s (role %s)",
				peer.PublicKey[:8], peer.Role)
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
