// Command meshdesk is the single entrypoint for the MeshDesk binary.
// Without --web, the node runs in agent-only mode (mesh transport + monitoring reporter).
// With --web, it also serves the Web UI (dashboard, WebSSH, file transfer, service management).
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/config"
	meshdns "github.com/yzy806806/meshdesk/internal/dns"
	"github.com/yzy806806/meshdesk/internal/identity"
	"github.com/yzy806806/meshdesk/internal/join"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/p2p"
	"github.com/yzy806806/meshdesk/internal/proxy"
	"github.com/yzy806806/meshdesk/internal/service"
	"github.com/yzy806806/meshdesk/internal/transfer"
	"github.com/yzy806806/meshdesk/internal/web"
	"github.com/yzy806806/meshdesk/internal/webssh"
)

// Build-time variables set via -ldflags "-X main.Version=... -X main.Commit=... -X main.BuildTime=...".
// Defaults to "dev"/"unknown" when built without CI.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	// Handle "join-token" subcommand: meshdesk join-token <secret> [server-fp]
	if len(os.Args) >= 2 && os.Args[1] == "join-token" {
		runJoinTokenSubcommand(os.Args[2:])
		return
	}

	// Handle "join" subcommand: meshdesk join <bootstrap-addr>
	if len(os.Args) >= 2 && os.Args[1] == "join" {
		runJoinSubcommand(os.Args[2:])
		return
	}

	// Handle "validate" subcommand: meshdesk validate <config.yaml>
	if len(os.Args) >= 2 && os.Args[1] == "validate" {
		runValidateSubcommand(os.Args[2:])
		return
	}

	var (
		configPath     string
		webMode        bool
		genKey         bool
		relayMode      bool
		socks5Listen   string
		socks5ExitNode string
		showVersion    bool
	)
	flag.StringVar(&configPath, "config", "/etc/meshdesk/config.yaml", "path to config file")
	flag.BoolVar(&webMode, "web", false, "enable web UI mode")
	flag.BoolVar(&genKey, "gen-key", false, "generate a new Ed25519 identity keypair and exit")
	flag.BoolVar(&relayMode, "relay", false, "enable relay mode (accept relay circuits from peers)")
	flag.StringVar(&socks5Listen, "socks5-listen", "", "SOCKS5 client listen address (e.g. 127.0.0.1:1080)")
	flag.StringVar(&socks5ExitNode, "socks5-exit-node", "", "exit node public key for SOCKS5 client mode")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("meshdesk %s\n", Version)
		fmt.Printf("  commit:     %s\n", Commit)
		fmt.Printf("  build time: %s\n", BuildTime)
		os.Exit(0)
	}

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
	var gossipLayer *p2p.GossipLayer
	node, err := mesh.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create mesh node: %v", err)
	}
	defer node.Close()

	// Wire the TUN IPAM peer meta provider callback before node.Start()
	// so setupTUN can query known peer VirtualIPs for conflict resolution.
	// The closure captures gossipLayer by reference; it will be nil until
	// gossip starts, so we guard with a nil check.
	if cfg.Mesh.TunEnabled {
		node.SetPeerMetaProvider(func() map[string]string {
			if gossipLayer == nil {
				return nil
			}
			result := make(map[string]string)
			for _, meta := range gossipLayer.KnownPeers() {
				if meta.VirtualIP != "" {
					result[meta.PublicKey] = meta.VirtualIP
				}
			}
			return result
		})
	}

	// Wire the TUN VirtualIP and subnet proxy broadcasters before node.Start()
	// so setupTUN can propagate them to the gossip layer immediately.
	// Use closures that capture gossipLayer by reference (nil-safe), matching
	// the SetPeerMetaProvider pattern above.
	if cfg.Mesh.TunEnabled {
		node.SetVirtualIPBroadcaster(func(vip string) {
			if gossipLayer != nil {
				gossipLayer.SetLocalVirtualIP(vip)
			}
		})
		node.SetSubnetProxyBroadcaster(func(subnets []string) {
			if gossipLayer != nil {
				gossipLayer.SetLocalSubnetProxies(subnets)
			}
		})
		node.SetACLRulesBroadcaster(func(rules []string) {
			if gossipLayer != nil {
				gossipLayer.SetLocalACLRules(rules)
			}
		})
	}

	// Wire the relay metadata provider so tryRelayFallback can make
	// intelligent, RTT-sorted, health-filtered relay candidate selection
	// using gossip-propagated NodeMeta. The closure captures gossipLayer
	// by reference; it will be nil until gossip starts.
	node.SetRelayMetaProvider(func() []mesh.RelayPeerInfo {
		if gossipLayer == nil {
			return nil
		}
		var result []mesh.RelayPeerInfo
		for _, meta := range gossipLayer.KnownPeers() {
			var rtt time.Duration
			if meta.RTTUs > 0 {
				rtt = time.Duration(meta.RTTUs) * time.Microsecond
			}
			result = append(result, mesh.RelayPeerInfo{
				PeerKey:      meta.PublicKey,
				RTT:          rtt,
				CapRelay:     meta.CapRelay,
				MaxCircuits:  meta.MaxCircuits,
				LoadCircuits: meta.LoadCircuits,
				NatType:      meta.NatType,
			})
		}
		return result
	})

	if err := node.Start(); err != nil {
		log.Fatalf("Failed to start mesh node: %v", err)
	}

	log.Printf("MeshDesk %s started (commit=%s, built=%s)", Version, Commit, BuildTime)
	log.Printf("  Public key: %s", node.Identity().PublicKey)
	log.Printf("  Mesh port:  %d", cfg.Mesh.Port)
	log.Printf("  Peers:      %d", node.RoutingTable().PeerCount())

	// Register the smux stream relay handler if relay mode is enabled.
	// This allows the node to accept relay requests on virtual port 0x524C
	// and bridge smux streams between peers that cannot directly connect
	// (e.g. cross-network-family: IPv4-only ↔ IPv6-only through a
	// dual-stack relay node). The handler is cleaned up by node.Close().
	if relayMode || cfg.Proxy.Relay.Enabled {
		if _, err := node.RegisterRelayHandler(); err != nil {
			log.Printf("Warning: failed to register smux relay handler: %v", err)
		} else {
			log.Printf("  Smux relay: listening on virtual port 0x524C (maxTunnels=%d)", mesh.DefaultMaxRelayTunnels)
		}
	}

	// Register the SOCKS5 proxy handler if SOCKS5 is enabled in config.
	// This allows mesh peers to route SOCKS5 CONNECT requests through
	// this node to reach arbitrary internet destinations. The handler
	// listens on virtual port 0x5350 and reuses the existing smux virtual
	// port dispatch mechanism (no new MuxTransport marker needed).
	if cfg.Proxy.SOCKS5.Enabled {
		socks5Cfg := mesh.SOCKS5Config{
			DialTimeout:       time.Duration(cfg.Proxy.SOCKS5.DialTimeoutSec) * time.Second,
			IdleTimeout:       time.Duration(cfg.Proxy.SOCKS5.IdleTimeoutSec) * time.Second,
			AllowAllPorts:     cfg.Proxy.SOCKS5.AllowAllPorts,
			DestinationFilter: cfg.Proxy.SOCKS5.DestinationFilter,
			MaxConnections:    cfg.Proxy.SOCKS5.MaxConnections,
			AllowedPeers:      cfg.Proxy.SOCKS5.AllowedPeers,
			RequireMeshPeer:   cfg.Proxy.SOCKS5.RequireMeshPeer,
		}
		if !socks5Cfg.AllowAllPorts && len(cfg.Proxy.SOCKS5.AllowedPorts) > 0 {
			socks5Cfg.AllowedPorts = make(map[int]bool, len(cfg.Proxy.SOCKS5.AllowedPorts))
			for _, p := range cfg.Proxy.SOCKS5.AllowedPorts {
				socks5Cfg.AllowedPorts[p] = true
			}
		}
		if _, err := node.RegisterSOCKS5Handler(socks5Cfg); err != nil {
			log.Printf("Warning: failed to register SOCKS5 handler: %v", err)
		} else {
			log.Printf("  SOCKS5 proxy: listening on virtual port 0x5350 (maxConns=%d)", socks5Cfg.MaxConnections)
		}
	}

	// Start SOCKS5 client listener (bridges local SOCKS5 to mesh exit node).
	if socks5Listen != "" && socks5ExitNode != "" {
		go runSOCKS5Client(node, socks5Listen, socks5ExitNode)
	}

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

		// Ordinary nodes (no Reality listener) get a UDP-only MuxTransport
		// created in node.Start() that binds to 0.0.0.0 so UDP gossip can
		// send to public addresses. Do NOT override GossipBindAddr here.

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

		// Initialize peer cache for persistence of discovered endpoints.
		// Loaded from disk so previously discovered peers are immediately
		// available as gossip seeds on restart.
		peerCache := p2p.NewPeerCache(cfg.P2P.PeerCachePath)
		if err := peerCache.Load(); err != nil {
			log.Printf("Warning: failed to load peer cache: %v (starting fresh)", err)
		}
		gl.SetPeerCache(peerCache)

		// Merge cached peer endpoints into the seed list so gossip
		// can bootstrap from previously discovered peers.
		cachedSeeds := peerCache.CachedEndpointsAsSeeds()
		if len(cachedSeeds) > 0 {
			existing := make(map[string]bool, len(p2pCfg.Seeds))
			for _, s := range p2pCfg.Seeds {
				existing[s] = true
			}
			added := 0
			for _, s := range cachedSeeds {
				if !existing[s] {
					p2pCfg.Seeds = append(p2pCfg.Seeds, s)
					existing[s] = true
					added++
				}
			}
			if added > 0 {
				log.Printf("  P2P:       added %d cached peer endpoint(s) as seeds", added)
			}
		}

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
			webMode,
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
		// NAT join/leave callbacks are stored in these closures so the TUN
		// handler can call them — SetJoinHandler overwrites, not appends.
		var natJoinHandler func(meta *p2p.NodeMeta)
		var natLeaveHandler func(peerKey string)
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
			// NOTE: SetJoinHandler/SetLeaveHandler are assignment semantics
			// (overwrite, not append). If TUN is also enabled, we must merge
			// both handlers into a single closure to avoid one clobbering
			// the other. The TUN block below will check natTraversal != nil
			// and call it from within its own handler.

			natJoinHandler = func(meta *p2p.NodeMeta) {
				peerEndpoints := meta.Endpoints
				peerNatType := p2p.NatType(meta.NatType)
				natTraversal.InitiateConnection(meta.PublicKey, peerEndpoints, peerNatType)
			}
			natLeaveHandler = func(peerKey string) {
				natTraversal.RemoveConnection(peerKey)
			}

			if err := natTraversal.Start(); err != nil {
				log.Printf("Warning: failed to start NAT traversal: %v", err)
			} else {
				log.Printf("  P2P:       NAT traversal active (STUN + hole-punch + relay fallback)")
			}

			// Wire the gossip layer to the NAT traversal so it can send
			// relay control messages (SETUP, TEARDOWN) via gossip.
			natTraversal.SetGossipLayer(gossipLayer)
		}

		// If TUN is not enabled but NAT is, register NAT handlers directly.
		if natJoinHandler != nil && !(cfg.Mesh.TunEnabled && gossipLayer != nil) {
			gl.Events().SetJoinHandler(natJoinHandler)
			gl.Events().SetLeaveHandler(natLeaveHandler)
		}

		// Wire TUN integration with the gossip layer.
		// This bridges the mesh package (TUN/IPAM) with the p2p package
		// (gossip), avoiding an import cycle.
		//
		// NOTE: SetVirtualIPBroadcaster and SetSubnetProxyBroadcaster are
		// now wired BEFORE node.Start() so setupTUN can propagate them
		// immediately. Only join/leave routing handlers are set here.
		if cfg.Mesh.TunEnabled && gossipLayer != nil {
			// Wire gossip join/leave handlers to sync kernel routes
			// for peer VirtualIPs. When a peer joins with a VirtualIP,
			// add a /32 route; when it leaves, remove it.
			// Also detect IPAM conflicts: if a new peer claims the
			// same VirtualIP, trigger re-allocation.
			// IMPORTANT: This handler also calls the NAT traversal join
			// handler if NAT traversal is enabled, because
			// SetJoinHandler overwrites (not appends).
			gl.Events().SetJoinHandler(func(meta *p2p.NodeMeta) {
				// NAT traversal (if enabled).
				if natJoinHandler != nil {
					natJoinHandler(meta)
				}
				// TUN routing.
				if meta.VirtualIP != "" {
					localVIP := node.GetTUNVirtualIP()
					if localVIP != nil && localVIP.String() == meta.VirtualIP {
						peerIPs := make(map[string]net.IP)
						for _, pm := range gossipLayer.KnownPeers() {
							if pm.VirtualIP != "" {
								peerIPs[pm.PublicKey] = net.ParseIP(pm.VirtualIP)
							}
						}
						node.ReallocateAfterGossip(peerIPs)
					}
					node.AddPeerVirtualIPRoute(meta.PublicKey, meta.VirtualIP)
				}
			})
			gl.Events().SetLeaveHandler(func(peerKey string) {
				// NAT traversal cleanup (if enabled).
				if natLeaveHandler != nil {
					natLeaveHandler(peerKey)
				}
				// Decouple TUN route cleanup from memberlist NotifyLeave.
				// memberlist may flap (UDP ping timeout) while the smux
				// session is still alive and functional. Only remove TUN
				// routes if the session is truly dead.
				if node.HasActiveSession(peerKey) {
					log.Printf("[p2p] NotifyLeave: keeping TUN routes for peer %s (smux session still alive)",
						peerKey[:8])
					return
				}
				log.Printf("[p2p] NotifyLeave: removing TUN routes for peer %s (no active session)",
					peerKey[:8])
				node.RemoveAllTUNRoutesForPeer(peerKey)
			})

			// Wire the subnet proxy handler: when a peer advertises
			// subnet proxies, add kernel routes via its VirtualIP.
			gossipLayer.SetSubnetProxyHandler(func(pubKey, virtualIP string, subnets []string) {
				if len(subnets) > 0 {
					node.AddPeerSubnetProxies(pubKey, virtualIP, subnets)
				} else {
					node.RemovePeerSubnetProxies(pubKey)
				}
			})

			// Process already-known peers (in case gossip started
			// before the TUN integration was wired).
			for _, meta := range gossipLayer.KnownPeers() {
				if meta.VirtualIP != "" {
					node.AddPeerVirtualIPRoute(meta.PublicKey, meta.VirtualIP)
				}
				if len(meta.SubnetProxies) > 0 && meta.VirtualIP != "" {
					node.AddPeerSubnetProxies(meta.PublicKey, meta.VirtualIP, meta.SubnetProxies)
				}
			}

			// Re-broadcast the local VirtualIP now that gossip is active.
			// During setupTUN (called inside node.Start()), gossipLayer was
			// still nil, so the VirtualIP broadcast was deferred. Now that
			// gossip is running, we push it so peers can discover our IP.
			//
			// Also handle IPAM conflict: if a peer has the same VirtualIP,
			// re-allocate to a different IP.
			if ti := node.TUNIntegration(); ti != nil {
				// Collect peer VirtualIPs from gossip.
				peerIPs := make(map[string]net.IP)
				for _, meta := range gossipLayer.KnownPeers() {
					if meta.VirtualIP != "" {
						peerIPs[meta.PublicKey] = net.ParseIP(meta.VirtualIP)
					}
				}
				log.Printf("[tun] re-broadcast: %d known peers", len(peerIPs))
				// Re-allocate if there's a conflict.
				node.ReallocateAfterGossip(peerIPs)
				// Re-broadcast (may have changed due to re-allocation).
				if vip := node.GetTUNVirtualIP(); vip != nil {
					node.SetTUNLocalVirtualIP(vip.String())
					if len(cfg.Mesh.SubnetProxy) > 0 {
						node.SetTUNSubnetProxies(cfg.Mesh.SubnetProxy)
					}
				}
			}

			// Wire the update handler to detect peer VirtualIP changes
			// (including the initial broadcast from re-joined peers).
			gl.Events().SetUpdateHandler(func(meta *p2p.NodeMeta) {
				if meta.VirtualIP == "" {
					return
				}
				// Check for IPAM conflict with local VirtualIP.
				localVIP := node.GetTUNVirtualIP()
				if localVIP != nil && localVIP.String() == meta.VirtualIP {
					// Conflict: peer claims the same VirtualIP.
					// Collect all known peer VirtualIPs and re-allocate.
					peerIPs := make(map[string]net.IP)
					for _, pm := range gossipLayer.KnownPeers() {
						if pm.VirtualIP != "" {
							peerIPs[pm.PublicKey] = net.ParseIP(pm.VirtualIP)
						}
					}
					node.ReallocateAfterGossip(peerIPs)
				}
				node.AddPeerVirtualIPRoute(meta.PublicKey, meta.VirtualIP)
				if len(meta.SubnetProxies) > 0 {
					node.AddPeerSubnetProxies(meta.PublicKey, meta.VirtualIP, meta.SubnetProxies)
				}
			})

			// Wire the session death handler: when a smux session truly dies
			// (detected by the reconnect watcher), clean up TUN routes.
			// This is the correct cleanup path, as opposed to memberlist
			// NotifyLeave which may fire on UDP flaps while the session is
			// still alive.
			node.SetSessionDeathHandler(func(peerKey string) {
				log.Printf("[mesh] session death: cleaning up TUN routes for peer %s", peerKey[:8])
				node.RemoveAllTUNRoutesForPeer(peerKey)
			})

			// Wire the session reconnect handler: after a smux session
			// is successfully re-established, re-add TUN routes that
			// were removed by the sessionDeathHandler. Since the peer
			// stays in memberlist, no new NotifyJoin fires, so the
			// join handler never re-runs. This callback fills that gap
			// by looking up the peer's NodeMeta from the gossip layer
			// and re-adding both the /32 route and subnet proxy routes.
			node.SetSessionReconnectHandler(func(peerKey string) {
				for _, meta := range gossipLayer.KnownPeers() {
					if meta.PublicKey == peerKey {
						if meta.VirtualIP != "" {
							log.Printf("[mesh] reconnect: restoring TUN routes for peer %s (vip=%s)", peerKey[:8], meta.VirtualIP)
							node.AddPeerVirtualIPRoute(meta.PublicKey, meta.VirtualIP)
						}
						if len(meta.SubnetProxies) > 0 && meta.VirtualIP != "" {
							node.AddPeerSubnetProxies(meta.PublicKey, meta.VirtualIP, meta.SubnetProxies)
						}
						return
					}
				}
				log.Printf("[mesh] reconnect: peer %s not found in gossip KnownPeers, skipping TUN route restoration", peerKey[:8])
			})

			log.Printf("  TUN:        gossip integration active (VirtualIP routing + subnet proxy)")
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

	// Start the mesh DNS server (if enabled).
	// The DNS server resolves <hostname>.mesh queries to VirtualIP
	// addresses using gossip-synchronized peer metadata. It requires
	// the gossip layer to be active for peer metadata.
	if cfg.Mesh.DNSEnabled && gossipLayer != nil {
		dnsProvider := &gossipDNSAdapter{gl: gossipLayer}
		dnsServer := meshdns.NewServer(dnsProvider, cfg.Mesh.DNSPort)
		if err := dnsServer.Start(); err != nil {
			log.Printf("Warning: failed to start mesh DNS server: %v", err)
		} else {
			defer dnsServer.Stop()
		}
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

	// Create a shared security event sink for all proxy subsystems.
	// When a web server is running, its AlertStore callback is wired
	// after the web server is created (see alert wiring below).
	proxySecSink := proxy.NewSecurityEventSink()

	// ── Entry Node (Legacy SS) ──
	// The SS-based entry node accepts Shadowsocks connections and dispatches
	// them through multi-path circuits to the exit node.
	//
	// DEPRECATED: SOCKS5 over Reality TLS (virtual port 0x5350) is the
	// default proxy entry. The SS entry node is only started when
	// proxy.ss.enabled is explicitly set to true. The SOCKS5 handler
	// is registered separately via RegisterSOCKS5ForwardHandler/ExitHandler.
	if cfg.Proxy.SS.Enabled && cfg.Proxy.SS.Port != 0 && cfg.Proxy.ExitAddr != "" {
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

	// Wire collector auto-discovery: when a peer with CapCollector=true is
	// discovered via gossip, automatically add it to the reporter's collector
	// list. This enables monitor auto-routing without static configuration —
	// the Dashboard's public key propagates through gossip and every agent's
	// reporter learns where to push metrics.
	if gossipLayer != nil {
		gossipLayer.SetCollectorHandler(reporter.AddCollector)
		gossipLayer.SetCollectorRemovedHandler(reporter.RemoveCollector)
		// Re-seed the collector list from the persisted peer cache so
		// monitor routing is immediately available after a restart,
		// without waiting for gossip to re-discover collector nodes.
		gossipLayer.SeedCollectorsFromCache()
	}

	defer reporter.Stop()

	var webServer *web.Server
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
		_ = authEngine // used by web layer for capability checks

		// Wire mesh identity-based auth checker into the aggregator.
		// Every incoming metric push is checked: the source peer must
		// be a known mesh member (routing table lookup) or the local
		// node itself. Unknown peers are rejected (fail-closed).
		// This implements Decision E (zero-trust) at the mesh-identity
		// level: mesh membership is the trust boundary for monitor_write.
		monitorAuthChecker := auth.NewMeshIdentityAuthChecker(
			nodeID,
			func(peerID string) bool {
				_, ok := node.RoutingTable().GetPeer(peerID)
				return ok
			},
			auditLogger,
		)

		// On web nodes, also run the aggregator to receive metric pushes.
		aggregator := monitor.NewAggregator(monitor.AggregatorConfig{
			Store:           monitorStore,
			Dialer:          &meshListenerAdapter{node: node},
			MeshDialer:      &meshDialerAdapter{node: node, gossip: gossipLayer},
			CollectorLister: &collectorListerAdapter{gossip: gossipLayer},
			SelfPeerID:      nodeID,
			Port:            cfg.Monitoring.Port,
			AuthChecker:     monitorAuthChecker,
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
			Config:               cfg,
			Node:                 node,
			MonitorStore:         monitorStore,
			SSHHub:               sshHub,
			AuthEngine:           authEngine,
			ServiceMgr:           svcMgr,
			MeshDialer:           web.NewPeerMeshDialer(node),
			ProxyStatusProvider:  &entryNodeStatusAdapter{entryNode: proxyEntryNode},
			SOCKS5StatusProvider: node,
			Liveness:             webLiveness,
			ConfigPath:           configPath,
			VersionInfo: web.VersionInfo{
				Version:   Version,
				Commit:    Commit,
				BuildTime: BuildTime,
			},
			JoinTokenGenerator: &nodeJoinTokenGenerator{
				cfg:      cfg,
				identity: node.Identity(),
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

		// Register production hot-reloaders for subsystems that support
		// dynamic config updates. When a user changes a hot-reload field
		// via the Dashboard and clicks "Hot Reload", each registered
		// reloader is called with the new config to apply changes at runtime
		// without requiring a process restart.
		webServer.RegisterReloader(web.NewMonitorReloader(reporter))
		if sshHub != nil {
			webServer.RegisterReloader(web.NewWebSSHReloader(sshHub))
		}
		webServer.RegisterReloader(web.NewLoggingReloader())

		if err := webServer.Start(cfg.Node.WebAddr); err != nil {
			log.Fatalf("Failed to start web server: %v", err)
		}
		defer webServer.Stop()

		log.Printf("  Web UI:     http://%s", cfg.Node.WebAddr)
	} else {
		log.Printf("  Mode:       agent-only")
	}

	// Start the auto-join server (if enabled on this shared node).
	// The join server accepts join requests from new nodes, validates
	// tokens (HMAC signature + expiration + replay protection), and
	// distributes the config bundle (identity, REALITY keys, collector list).
	// Only meaningful on shared nodes with Reality TLS enabled.
	var joinServer *join.JoinServer
	if cfg.Join.Enabled && cfg.Reality.Enabled {
		// Derive the X25519 public key from the server's private key.
		// The joiner needs the PUBLIC key to connect via Reality TLS.
		realityPubHex := ""
		if privBytes, err := hex.DecodeString(cfg.Reality.PrivateKey); err == nil && len(privBytes) == 32 {
			if realityPriv, err := ecdh.X25519().NewPrivateKey(privBytes); err == nil {
				realityPubHex = hex.EncodeToString(realityPriv.PublicKey().Bytes())
			}
		}
		if realityPubHex == "" {
			log.Printf("Warning: invalid reality.private_key — join server disabled")
		} else {
			joinServerCfg := join.ServerConfig{
				Secret:            []byte(cfg.Join.Secret),
				ServerIdentity:    node.Identity(),
				BootstrapEndpoint: firstAdvertiseEndpoint(cfg),
				GossipPort:        cfg.Mesh.GossipPort,
				RealityPublicKey:  realityPubHex, // Derived X25519 public key
				RealityShortID:    firstShortID(cfg.Reality.ShortIDs),
				RealityServerName: firstServerName(cfg.Reality.ServerNames),
				Collectors:        cfg.Monitoring.Collectors,
				TokenLifetime:     time.Duration(cfg.Join.TokenLifetime) * time.Second,
			}

			// If the join secret is empty, generate a random one and log a warning.
			if cfg.Join.Secret == "" {
				randomSecret := make([]byte, 32)
				if _, err := rand.Read(randomSecret); err != nil {
					log.Printf("Warning: failed to generate random join secret: %v — join server disabled", err)
				} else {
					cfg.Join.Secret = hex.EncodeToString(randomSecret)
					log.Printf("WARNING: join.secret not set — generated random secret: %s", cfg.Join.Secret)
					log.Printf("  Use this secret with `meshdesk join-token` to generate tokens.")
				}
			}
			joinServerCfg.Secret = []byte(cfg.Join.Secret)

			joinServer = join.NewJoinServer(joinServerCfg)

			// Wire the known-peers provider if gossip is active.
			if gossipLayer != nil {
				joinServer.SetKnownPeersFunc(func() []join.PeerInfo {
					peers := gossipLayer.KnownPeers()
					result := make([]join.PeerInfo, 0, len(peers))
					for _, p := range peers {
						result = append(result, join.PeerInfo{
							PublicKey: p.PublicKey,
							Hostname:  p.Hostname,
							Role:      p.Role,
						})
					}
					return result
				})
			}

			if cfg.Join.TLSCertFile != "" && cfg.Join.TLSKeyFile != "" {
				if err := joinServer.StartTLS(cfg.Join.ListenAddr, cfg.Join.TLSCertFile, cfg.Join.TLSKeyFile); err != nil {
					log.Printf("Warning: failed to start join TLS server: %v", err)
				} else {
					log.Printf("  Join:       TLS server on %s", cfg.Join.ListenAddr)
				}
			} else {
				if err := joinServer.Start(cfg.Join.ListenAddr); err != nil {
					log.Printf("Warning: failed to start join server: %v", err)
				} else {
					log.Printf("  Join:       server on %s (WARNING: no TLS — use tls_cert_file/tls_key_file for production)", cfg.Join.ListenAddr)
				}
			}
			defer joinServer.Stop()
		}
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
}

// meshDialerAdapter adapts mesh.MeshNode to the monitor.MeshDialer interface.
type meshDialerAdapter struct {
	node   *mesh.MeshNode
	gossip *p2p.GossipLayer
}

// collectorListerAdapter adapts the gossip layer to the monitor.CollectorLister
// interface. It enumerates collector-capable peers known via gossip.
type collectorListerAdapter struct {
	gossip *p2p.GossipLayer
}

func (c *collectorListerAdapter) CollectorPeerIDs() []string {
	if c.gossip == nil {
		return nil
	}
	var ids []string
	for _, meta := range c.gossip.KnownPeers() {
		if meta.CapCollector {
			ids = append(ids, meta.PublicKey)
		}
	}
	return ids
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

// firstShortID returns the first short ID from the list, or empty string.
func firstShortID(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

// nodeJoinTokenGenerator implements web.JoinTokenGenerator using the node's
// config and identity. It provides join server URL derivation and binary
// download URL construction for the one-click join Dashboard page.
type nodeJoinTokenGenerator struct {
	cfg      *config.Config
	identity *identity.Identity
}

func (g *nodeJoinTokenGenerator) GenerateJoinToken(lifetime time.Duration) (string, error) {
	if g.cfg.Join.Secret == "" {
		return "", fmt.Errorf("join.secret not configured")
	}
	serverFP := ""
	if g.identity != nil {
		serverFP = g.identity.PublicKey
	}
	return join.GenerateToken([]byte(g.cfg.Join.Secret), serverFP, lifetime)
}

func (g *nodeJoinTokenGenerator) JoinServerURL() string {
	if !g.cfg.Join.Enabled {
		return ""
	}
	host := firstAdvertiseEndpointHost(g.cfg)
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

func (g *nodeJoinTokenGenerator) BinaryDownloadURL(arch string) string {
	if arch == "" {
		arch = "amd64"
	}
	return fmt.Sprintf("https://github.com/yzy806806/meshdesk/releases/latest/download/meshdesk-linux-%s", arch)
}

func (g *nodeJoinTokenGenerator) JoinEnabled() bool {
	return g.cfg.Join.Enabled && g.cfg.Reality.Enabled
}

// firstAdvertiseEndpointHost returns just the host portion of the first
// advertise endpoint, or the node hostname as fallback.
func firstAdvertiseEndpointHost(cfg *config.Config) string {
	if len(cfg.P2P.AdvertiseEndpoints) > 0 {
		ep := cfg.P2P.AdvertiseEndpoints[0]
		if idx := strings.LastIndex(ep, ":"); idx > 0 {
			return ep[:idx]
		}
		return ep
	}
	host := cfg.Node.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	return host
}

// firstServerName returns the first server name from the list, or empty string.
func firstServerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// firstAdvertiseEndpoint returns the first advertise endpoint from config,
// or falls back to auto-detected outbound IP + mesh port.
func firstAdvertiseEndpoint(cfg *config.Config) string {
	if len(cfg.P2P.AdvertiseEndpoints) > 0 {
		return cfg.P2P.AdvertiseEndpoints[0]
	}
	// Fallback: use the node's hostname or localhost.
	host := cfg.Node.Hostname
	if host == "" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", cfg.Mesh.GossipPort))
}

// runJoinSubcommand implements `meshdesk join <bootstrap-addr>`.
//
// It creates a mesh node, configures the bootstrap as a static peer,
// starts the gossip layer, sends a JoinRequest to the bootstrap, and
// on success triggers full memberlist state sync. This implements the
// Dynamic Join Protocol from P2P_NETWORKING_SPEC.md §4.
//
// When --join-url and --join-token are provided, it uses the auto-join
// protocol: the node first contacts the join server via HTTPS to obtain
// the config bundle (identity, REALITY keys, collector list), then
// proceeds with the normal join flow using the received config.
//
// Usage:
//
//	meshdesk join 203.0.113.5:51820            # bootstrap endpoint
//	meshdesk join 10.10.0.5:7946                # bootstrap mesh IP:gossip port
//	meshdesk join --config /path/to/config.yaml 203.0.113.5:51820
//	meshdesk join --join-url https://bootstrap:8443 --join-token <token> [bootstrap-addr]
func runJoinSubcommand(args []string) {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	configPath := fs.String("config", "/etc/meshdesk/config.yaml", "path to config file")
	bootstrapKey := fs.String("bootstrap-key", "", "bootstrap node's Ed25519 public key (hex, required if not in config peers)")
	joinURL := fs.String("join-url", "", "join server URL (e.g., https://bootstrap:8443) for auto-join protocol")
	joinToken := fs.String("join-token", "", "join token for auto-join protocol (base64-encoded)")
	insecureTLS := fs.Bool("insecure-tls", false, "skip TLS certificate verification (testing only)")
	_ = fs.Parse(args)

	bootstrapAddr := ""
	if fs.NArg() >= 1 {
		bootstrapAddr = fs.Arg(0)
	}

	// If using auto-join protocol (token-based), fetch config bundle first.
	if *joinURL != "" && *joinToken != "" {
		log.Printf("[join] using auto-join protocol: server=%s", *joinURL)

		// Load config to get the node's identity (or generate one).
		cfg, err := config.Load(*configPath)
		if err != nil {
			if os.IsNotExist(err) {
				cfg = config.Default()
			} else {
				log.Fatalf("Failed to load config: %v", err)
			}
		}

		// Create a mesh node to get/derive the identity.
		node, err := mesh.New(cfg)
		if err != nil {
			log.Fatalf("Failed to create mesh node for identity: %v", err)
		}
		joinerIdentity := node.Identity()
		joinerPubKey := joinerIdentity.PublicKey
		hostname := cfg.Node.Hostname
		if hostname == "" {
			hostname, _ = os.Hostname()
		}
		node.Close()

		// Build the join client.
		tlsConfig := &tls.Config{}
		if *insecureTLS {
			tlsConfig.InsecureSkipVerify = true
		}
		joinClient := join.NewJoinClient(join.ClientConfig{
			ServerURL:       *joinURL,
			Token:           *joinToken,
			JoinerPublicKey: joinerPubKey,
			JoinerHostname:  hostname,
			JoinerEndpoint:  bootstrapAddr,
			JoinerSigner:    joinerIdentity,
			TLSConfig:       tlsConfig,
			AllowPlainHTTP:  *insecureTLS, // Allow plain HTTP only when insecure mode is explicitly requested
		})

		// Request the config bundle.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		bundle, err := joinClient.RequestJoin(ctx)
		if err != nil {
			log.Fatalf("Auto-join failed: %v", err)
		}

		log.Printf("[join] received config bundle:")
		log.Printf("  Bootstrap pubkey: %s", bundle.BootstrapPublicKey[:16]+"...")
		log.Printf("  Bootstrap endpoint: %s", bundle.BootstrapEndpoint)
		log.Printf("  Gossip port: %d", bundle.GossipPort)
		log.Printf("  Collectors: %d", len(bundle.Collectors))
		log.Printf("  Known peers: %d", len(bundle.KnownPeers))

		// Configure the node using the received bundle.
		if *bootstrapKey == "" {
			*bootstrapKey = bundle.BootstrapPublicKey
		}
		if bootstrapAddr == "" {
			bootstrapAddr = bundle.BootstrapEndpoint
		}
		if cfg.Mesh.GossipPort == 0 {
			cfg.Mesh.GossipPort = bundle.GossipPort
		}
		if len(cfg.Monitoring.Collectors) == 0 {
			cfg.Monitoring.Collectors = bundle.Collectors
		}

		// Add the bootstrap as a peer with REALITY config.
		if bundle.RealityPublicKey != "" {
			peerCfg := config.PeerConfig{
				PublicKey: bundle.BootstrapPublicKey,
				Endpoint:  bundle.BootstrapEndpoint,
				Reality: &config.RealityPeerConfig{
					ServerName:     bundle.RealityServerName,
					PublicKey:      bundle.RealityPublicKey,
					ShortID:        bundle.RealityShortID,
					TLSFingerprint: "chrome",
				},
			}
			cfg.Peers = append(cfg.Peers, peerCfg)
			log.Printf("[join] added bootstrap peer with REALITY config")
		}

		// Persist the updated config so the node can restart without
		// re-joining. This saves the REALITY keys, peer config, collectors,
		// and gossip seeds received from the join server.
		cfg.P2P.Enabled = true
		cfg.P2P.Seeds = []string{bundle.BootstrapEndpoint}
		if err := config.Save(*configPath, cfg); err != nil {
			log.Printf("[join] warning: failed to save config to %s: %v (continuing with in-memory config)", *configPath, err)
		} else {
			log.Printf("[join] config saved to %s", *configPath)
		}
		// Continue with normal join flow below using the updated cfg.
		// We skip re-loading and re-creating the node.
		runJoinWithConfig(cfg, bootstrapAddr, *bootstrapKey, *configPath)
		return
	}

	if bootstrapAddr == "" {
		log.Fatalf("Usage: meshdesk join <bootstrap-addr>\n\n" +
			"bootstrap-addr is the bootstrap node's endpoint (host:port)\n" +
			"or mesh IP:gossip port.\n" +
			"Alternatively, use --join-url and --join-token for auto-join.")
	}

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

	runJoinWithConfig(cfg, bootstrapAddr, *bootstrapKey, *configPath)
}

// runJoinWithConfig runs the join flow with an already-loaded config.
func runJoinWithConfig(cfg *config.Config, bootstrapAddr, bootstrapKey, configPath string) {

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
	if bootstrapKey != "" {
		// Parse the bootstrap address for the endpoint.
		host, port, err := p2p.ParseBootstrapAddr(bootstrapAddr, cfg.Mesh.Port)
		if err != nil {
			log.Fatalf("Invalid bootstrap address: %v", err)
		}
		endpoint := net.JoinHostPort(host, port)

		// v2: no mesh IP derivation — peer ID is the routing key.
		peerCfg := config.PeerConfig{
			PublicKey: bootstrapKey,
			Endpoint:  endpoint,
		}
		cfg.Peers = append(cfg.Peers, peerCfg)
		log.Printf("Added bootstrap as static peer: %s@%s",
			bootstrapKey[:8], endpoint)
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
		false,
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
	if bootstrapKey != "" {
		joinCtx, joinCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer joinCancel()

		result, err := gl.RequestJoin(joinCtx, bootstrapKey)
		if err != nil {
			log.Printf("Warning: join request to bootstrap failed: %v (continuing — gossip push/pull will sync peers)", err)
		} else if !result.Accepted {
			log.Printf("Warning: join rejected by bootstrap: %s (continuing — gossip push/pull will sync peers)", result.RejectReason)
		} else {
			log.Printf("Join accepted by bootstrap")
			if result.Bootstrap != nil {
				log.Printf("  Bootstrap public key: %s", result.Bootstrap.PublicKey[:8])
			}
			log.Printf("  Known peers from bootstrap: %d", len(result.KnownPeers))
			for _, peer := range result.KnownPeers {
				log.Printf("    - %s (role %s)",
					peer.PublicKey[:8], peer.Role)
			}
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

// runSOCKS5Client starts a local SOCKS5 TCP listener that bridges
// connections through the mesh to a remote SOCKS5 exit handler.
// Each SOCKS5 CONNECT from a local client (e.g., curl) is forwarded
// via DialVirtualPort to the exit node's virtual port 0x5350.
func runSOCKS5Client(node *mesh.MeshNode, listenAddr, exitNodeID string) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("SOCKS5 client: failed to listen on %s: %v", listenAddr, err)
		return
	}
	defer ln.Close()
	log.Printf("SOCKS5 client: listening on %s, exit node %s...", listenAddr, exitNodeID[:16])

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("SOCKS5 client: accept error: %v", err)
			return
		}
		go func(c net.Conn) {
			defer c.Close()

			// Phase 1: SOCKS5 greeting from local client.
			buf := make([]byte, 2)
			if _, err := io.ReadFull(c, buf); err != nil {
				return
			}
			if buf[0] != 0x05 {
				return
			}
			nMethods := int(buf[1])
			methods := make([]byte, nMethods)
			io.ReadFull(c, methods)
			c.Write([]byte{0x05, 0x00}) // no-auth

			// Phase 2: Read CONNECT request.
			header := make([]byte, 4)
			if _, err := io.ReadFull(c, header); err != nil {
				return
			}
			if header[1] != 0x01 { // CONNECT only
				socks5Reply(c, 0x07)
				return
			}

			var targetHost string
			origATyp := header[3]
			switch origATyp {
			case 0x01: // IPv4
				addr := make([]byte, 4)
				io.ReadFull(c, addr)
				targetHost = net.IP(addr).String()
			case 0x03: // FQDN
				lb := make([]byte, 1)
				io.ReadFull(c, lb)
				fb := make([]byte, int(lb[0]))
				io.ReadFull(c, fb)
				targetHost = string(fb)
			case 0x04: // IPv6
				addr := make([]byte, 16)
				io.ReadFull(c, addr)
				targetHost = net.IP(addr).String()
			default:
				socks5Reply(c, 0x08)
				return
			}
			portBuf := make([]byte, 2)
			io.ReadFull(c, portBuf)
			targetPort := binary.BigEndian.Uint16(portBuf)
			targetAddr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))

			log.Printf("SOCKS5 client: CONNECT %s via exit %s...", targetAddr, exitNodeID[:16])

			// Phase 3: Dial the exit node's SOCKS5 virtual port.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			meshConn, err := node.DialVirtualPort(ctx, exitNodeID, int(mesh.SOCKS5VirtualPort))
			if err != nil {
				log.Printf("SOCKS5 client: DialVirtualPort: %v", err)
				socks5Reply(c, 0x04)
				return
			}
			defer meshConn.Close()

			// Phase 4: SOCKS5 handshake with exit node.
			meshConn.Write([]byte{0x05, 0x01, 0x00})
			authReply := make([]byte, 2)
			if _, err := io.ReadFull(meshConn, authReply); err != nil {
				socks5Reply(c, 0x01)
				return
			}
			// Send CONNECT to exit.
			sendMeshSocks5Connect(meshConn, origATyp, targetHost, targetPort)
			exitRep := make([]byte, 4)
			if _, err := io.ReadFull(meshConn, exitRep); err != nil {
				socks5Reply(c, 0x01)
				return
			}
			rep := exitRep[1]
			if rep != 0x00 {
				log.Printf("SOCKS5 client: exit replied error 0x%02x for %s", rep, targetAddr)
				socks5Reply(c, rep)
				return
			}
			// Skip BND.ADDR and BND.PORT from exit reply.
			skipBindAddr(meshConn, exitRep[3])

			// Phase 5: Success reply to local client.
			socks5Reply(c, 0x00)

			// Phase 6: Bidirectional relay.
			done := make(chan struct{}, 2)
			go func() { io.Copy(meshConn, c); done <- struct{}{} }()
			go func() { io.Copy(c, meshConn); done <- struct{}{} }()
			<-done
			meshConn.Close()
			c.Close()
			<-done
		}(conn)
	}
}

func socks5Reply(conn net.Conn, rep byte) {
	conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func sendMeshSocks5Connect(conn net.Conn, atyp byte, host string, port uint16) {
	var msg []byte
	msg = append(msg, 0x05, 0x01, 0x00, atyp)
	switch atyp {
	case 0x01:
		msg = append(msg, net.ParseIP(host).To4()...)
	case 0x03:
		msg = append(msg, byte(len(host)))
		msg = append(msg, []byte(host)...)
	case 0x04:
		msg = append(msg, net.ParseIP(host).To16()...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	msg = append(msg, pb[:]...)
	conn.Write(msg)
}

func skipBindAddr(conn net.Conn, atyp byte) {
	switch atyp {
	case 0x01:
		io.ReadFull(conn, make([]byte, 4))
	case 0x03:
		lb := make([]byte, 1)
		io.ReadFull(conn, lb)
		io.ReadFull(conn, make([]byte, int(lb[0])))
	case 0x04:
		io.ReadFull(conn, make([]byte, 16))
	}
	io.ReadFull(conn, make([]byte, 2)) // port
}

// runJoinTokenSubcommand implements `meshdesk join-token <secret> [server-fp]`.
// It generates a join token signed with the given secret. The server-fp
// (server fingerprint = Ed25519 public key hex) is optional but recommended
// for TLS pinning.
//
// Usage:
//
//	meshdesk join-token mysecret                     # generate token without server pin
//	meshdesk join-token mysecret abc123...           # generate token pinned to server pubkey
//	meshdesk join-token --lifetime 1h mysecret abc   # 1-hour token
func runJoinTokenSubcommand(args []string) {
	fs := flag.NewFlagSet("join-token", flag.ExitOnError)
	lifetime := fs.Duration("lifetime", 30*time.Minute, "token lifetime")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		log.Fatalf("Usage: meshdesk join-token <secret> [server-fingerprint]\n\n" +
			"Generates a join token signed with the given HMAC secret.\n" +
			"The server fingerprint is the shared node's Ed25519 public key (hex),\n" +
			"used for TLS pinning (recommended).")
	}

	secret := fs.Arg(0)
	serverFP := ""
	if fs.NArg() >= 2 {
		serverFP = fs.Arg(1)
	}

	token, err := join.GenerateToken([]byte(secret), serverFP, *lifetime)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}

	fmt.Println(token)
}

// runValidateSubcommand handles: meshdesk validate <config.yaml>
// It checks the config file for YAML syntax errors, missing required
// fields, invalid field types/values, and port conflicts across subsystems.
func runValidateSubcommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: meshdesk validate <config.yaml>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Validates a meshdesk config file for syntax errors,")
		fmt.Fprintln(os.Stderr, "missing required fields, invalid values, and port conflicts.")
		os.Exit(2)
	}
	configPath := args[0]
	errs := config.ValidateFile(configPath)
	if len(errs) == 0 {
		fmt.Printf("✓ %s: config is valid\n", configPath)
		return
	}
	fmt.Fprintf(os.Stderr, "✗ %s: %d error(s):\n\n", configPath, len(errs))
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "  %s\n", e.Error())
	}
	os.Exit(1)
}

// gossipDNSAdapter adapts *p2p.GossipLayer to the dns.PeerMetaProvider
// interface. It converts p2p.NodeMeta to dns.NodeMeta, bridging the
// two packages without creating an import cycle.
type gossipDNSAdapter struct {
	gl *p2p.GossipLayer
}

func (a *gossipDNSAdapter) LocalMeta() *meshdns.NodeMeta {
	if a.gl == nil {
		return nil
	}
	meta := a.gl.LocalMeta()
	if meta == nil {
		return nil
	}
	return &meshdns.NodeMeta{
		Hostname:  meta.Hostname,
		VirtualIP: meta.VirtualIP,
	}
}

func (a *gossipDNSAdapter) KnownPeers() []*meshdns.NodeMeta {
	if a.gl == nil {
		return nil
	}
	peers := a.gl.KnownPeers()
	result := make([]*meshdns.NodeMeta, 0, len(peers))
	for _, p := range peers {
		if p == nil {
			continue
		}
		result = append(result, &meshdns.NodeMeta{
			Hostname:  p.Hostname,
			VirtualIP: p.VirtualIP,
		})
	}
	return result
}
