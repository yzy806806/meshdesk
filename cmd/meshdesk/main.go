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
	"strings"
	"syscall"
	"time"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/service"
	"github.com/yzy806806/meshdesk/internal/transfer"
	"github.com/yzy806806/meshdesk/internal/web"
	"github.com/yzy806806/meshdesk/internal/webssh"
)

func main() {
	var (
		configPath string
		webMode    bool
		genKey     bool
	)
	flag.StringVar(&configPath, "config", "/etc/meshdesk/config.yaml", "path to config file")
	flag.BoolVar(&webMode, "web", false, "enable web UI mode")
	flag.BoolVar(&genKey, "gen-key", false, "generate a new WireGuard keypair and exit")
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

	// Start the remote service management server (listens on mesh).
	// Every node accepts service management commands from authorized peers.
	remoteSvcListener := &meshListenerAdapter{node: node}
	// Wrap the service manager with AuthorizedServiceManager for capability enforcement.
	var remoteSvcMgr service.ServiceManager
	if execBackend, err := service.NewExecBackend("", 30*time.Second); err != nil {
		// Graceful degradation: use NullBackend when systemd is unavailable (Gap 5 fix).
		log.Printf("Warning: systemctl not available for remote service server: %v — using null backend", err)
		remoteSvcMgr = service.NewNullBackend()
	} else {
		remoteSvcMgr = execBackend
	}
	if authEngine := auth.NewCapabilityEngine(cfg, auth.NewAuditLogger(log.Writer())); authEngine != nil {
		// The remote server uses the source peer ID from the connection
		// (set by the RPC layer). For now, we pass a placeholder that
		// the handler will override with the actual source peer.
		remoteSvcMgr = service.NewAuthorizedServiceManager(remoteSvcMgr, authEngine, "")
	}
	remoteSvcServer := service.NewRemoteServer(remoteSvcMgr, remoteSvcListener, service.DefaultServicePort)
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
	if webMode {
		// On web nodes, also run the aggregator to receive metric pushes.
		aggregator := monitor.NewAggregator(monitor.AggregatorConfig{
			Store:  monitorStore,
			Dialer: &meshListenerAdapter{node: node},
			Port:   cfg.Monitoring.Port,
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

		// Create the auth capability engine.
		auditLogger, err := auth.NewAuditFileLogger("/var/log/meshdesk-audit.jsonl")
		if err != nil {
			log.Printf("Warning: could not open audit log file: %v — using stderr", err)
			auditLogger = auth.NewAuditLogger(log.Writer())
		}
		defer auditLogger.Close()

		authEngine := auth.NewCapabilityEngine(cfg, auditLogger)

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

		// Create and start the web server.
		webServer, err = web.New(web.Deps{
			Config:       cfg,
			Node:         node,
			MonitorStore: monitorStore,
			SSHHub:       sshHub,
			AuthEngine:   authEngine,
			ServiceMgr:   svcMgr,
			MeshDialer:   web.NewPeerMeshDialer(node),
		})
		if err != nil {
			log.Fatalf("Failed to create web server: %v", err)
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
	_ = webServer // silence unused warning if not web mode
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
