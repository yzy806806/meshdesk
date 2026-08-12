// Command meshdesk is the single entrypoint for the MeshDesk binary.
// Without --web, the node runs in agent-only mode (mesh transport + monitoring reporter).
// With --web, it also serves the Web UI (dashboard, WebSSH, file transfer, service management).
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yzy806806/meshdesk/internal/app"
	"github.com/yzy806806/meshdesk/internal/config"
	meshdns "github.com/yzy806806/meshdesk/internal/dns"
	"github.com/yzy806806/meshdesk/internal/identity"
	"github.com/yzy806806/meshdesk/internal/join"
	"github.com/yzy806806/meshdesk/internal/logging"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/p2p"
	"github.com/yzy806806/meshdesk/internal/proxy"
	"github.com/yzy806806/meshdesk/internal/web"
)

// Build-time variables set via -ldflags "-X main.Version=... -X main.Commit=... -X main.BuildTime=...".
// Defaults to "dev"/"unknown" when built without CI.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// autoDialInFlight tracks peers for which an auto-dial (NotifyJoin →
// DialPeerByEndpoint) is currently in progress, preventing duplicate
// concurrent dials when memberlist flaps and re-fires NotifyJoin for
// the same peer. Entries are removed when the dial attempt completes.
var autoDialMu sync.Mutex
var autoDialInFlight = make(map[string]bool)

func main() {
	// Local-only pprof endpoint for memory/goroutine diagnosis
	// (127.0.0.1:6060 — never exposed).
	go func() {
		_ = http.ListenAndServe("127.0.0.1:6060", nil)
	}()

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

	// Handle "version" subcommand: meshdesk version
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		runVersionSubcommand()
		return
	}

	// Handle "validate" subcommand: meshdesk validate <config.yaml>
	if len(os.Args) >= 2 && os.Args[1] == "validate" {
		runValidateSubcommand(os.Args[2:])
		return
	}

	// Handle "reload" subcommand: meshdesk reload [--pid <pid>]
	// Sends SIGHUP to a running meshdesk process to trigger config reload.
	if len(os.Args) >= 2 && os.Args[1] == "reload" {
		runReloadSubcommand(os.Args[2:])
		return
	}

	var (
		configPath      string
		webMode         bool
		genKey          bool
		relayMode       bool
		socks5Listen    string
		socks5ExitNode  string
		socks5ExitNodes string
		showVersion     bool
	)
	flag.StringVar(&configPath, "config", "/etc/meshdesk/config.yaml", "path to config file")
	flag.BoolVar(&webMode, "web", false, "enable web UI mode")
	flag.BoolVar(&genKey, "gen-key", false, "generate a new Ed25519 identity keypair and exit")
	flag.BoolVar(&relayMode, "relay", false, "enable relay mode (accept relay circuits from peers)")
	flag.StringVar(&socks5Listen, "socks5-listen", "", "SOCKS5 client listen address (e.g. 127.0.0.1:1080)")
	flag.StringVar(&socks5ExitNode, "socks5-exit-node", "", "exit node public key for SOCKS5 client mode")
	flag.StringVar(&socks5ExitNodes, "socks5-exit-nodes", "", "comma-separated exit node public keys (load-balanced, health-checked)")
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

	// Set up log file with rotation if configured.
	var logWriter *logging.RotatingWriter
	if cfg.Logging.LogFile != "" {
		logWriter, err = logging.NewRotatingWriter(
			cfg.Logging.LogFile,
			cfg.Logging.LogMaxSize,
			cfg.Logging.LogMaxBackups,
			cfg.Logging.LogCompress,
		)
		if err != nil {
			log.Printf("Warning: failed to open log file %s: %v (continuing with stderr)", cfg.Logging.LogFile, err)
		} else {
			logWriter.SetMaxAge(cfg.Logging.LogMaxAge)
			log.SetOutput(logWriter)
			log.Printf("Logging to %s (max_size=%d, max_backups=%d, compress=%v)",
				cfg.Logging.LogFile, cfg.Logging.LogMaxSize, cfg.Logging.LogMaxBackups, cfg.Logging.LogCompress)
		}
	}

	if webMode {
		if cfg.Node.WebAddr == "" {
			cfg.Node.WebAddr = ":8080"
		}
	}

	// Build the app (three-phase: construct → wire → unstarted App).
	appInstance, err := app.Build(cfg)
	if err != nil {
		log.Fatalf("Failed to build app: %v", err)
	}
	appInstance.Version = Version
	appInstance.Commit = Commit
	appInstance.BuildTime = BuildTime
	appInstance.SetFlags(webMode, relayMode, socks5Listen, socks5ExitNode, socks5ExitNodes)
	appInstance.SetConfigPath(configPath)
	appInstance.SetLogWriter(logWriter)

	if err := appInstance.Start(context.Background()); err != nil {
		log.Fatalf("Failed to start app: %v", err)
	}
	log.Printf("MeshDesk %s started (commit=%s, built=%s)", Version, Commit, BuildTime)

	// Block until shutdown signal; handles SIGHUP/SIGUSR1 in-loop.
	appInstance.Run()
	log.Printf("MeshDesk exited cleanly")
}

type collectorListerAdapter struct {
	gossip *p2p.GossipLayer
}

type meshDialerAdapter struct {
	node   *mesh.MeshNode
	gossip *p2p.GossipLayer
}

type meshListenerAdapter struct {
	node *mesh.MeshNode
}

type entryNodeStatusAdapter struct {
	entryNode *proxy.EntryNode
}

type gossipLiveness struct {
	gl       *p2p.GossipLayer
	localKey string
}

type nodeJoinTokenGenerator struct {
	cfg      *config.Config
	identity *identity.Identity
}

type exitHealth struct {
	node  *mesh.MeshNode
	mu    sync.Mutex
	state map[string]bool // exitID → healthy
	order []string
	rr    int
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

func (a *meshListenerAdapter) ListenMesh(port int) (net.Listener, error) {
	return a.node.ListenVirtualPort(port)
}

// entryNodeStatusAdapter adapts *proxy.EntryNode to the
// web.ProxyStatusProvider interface. It converts the proxy package's
// EntryNodeStatus to the web package's ProxyStatusData struct, which
// the /api/proxy/status endpoint serializes as JSON.

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
		true, // stream relay handler is always registered — any node can relay
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
func runSOCKS5Client(node *mesh.MeshNode, listenAddr string, exitNodes []string, authUser, authPass string) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("SOCKS5 client: failed to listen on %s: %v", listenAddr, err)
		return
	}
	defer ln.Close()
	log.Printf("SOCKS5 client: listening on %s, exit nodes %v", listenAddr, exitNodes[:min(len(exitNodes), 8)])

	// Health monitor: probe each exit's SOCKS5 virtual port every 30s.
	health := newExitHealth(node, exitNodes)
	go health.run()

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

			// RFC 1929 username/password auth when credentials are set.
			if authUser != "" {
				useAuth := false
				for _, m := range methods {
					if m == 0x02 {
						useAuth = true
						break
					}
				}
				if !useAuth {
					c.Write([]byte{0x05, 0xFF}) // no acceptable methods
					return
				}
				c.Write([]byte{0x05, 0x02}) // username/password
				auth := make([]byte, 2)
				if _, err := io.ReadFull(c, auth); err != nil || auth[0] != 0x01 {
					return
				}
				u := make([]byte, int(auth[1]))
				if _, err := io.ReadFull(c, u); err != nil {
					return
				}
				pl := make([]byte, 1)
				if _, err := io.ReadFull(c, pl); err != nil {
					return
				}
				pw := make([]byte, int(pl[0]))
				if _, err := io.ReadFull(c, pw); err != nil {
					return
				}
				if string(u) != authUser || string(pw) != authPass {
					c.Write([]byte{0x01, 0x01}) // auth failed
					return
				}
				c.Write([]byte{0x01, 0x00}) // auth success
			} else {
				c.Write([]byte{0x05, 0x00}) // no-auth
			}

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

			// Phase 3: pick the best exit — healthy, lowest live RTT —
			// and dial its SOCKS5 virtual port. On failure, fall back
			// to the next-best exit (no more hard reject).
			bestOrder := pickBestExits(health, node, exitNodes)
			if len(bestOrder) == 0 {
				log.Printf("SOCKS5 client: no healthy exit nodes available")
				socks5Reply(c, 0x04)
				return
			}

			var meshConn net.Conn
			var dialErr error
			for i, exitNodeID := range bestOrder {
				log.Printf("SOCKS5 client: CONNECT %s via exit %s...%s (attempt %d/%d)",
					targetAddr, exitNodeID[:min(len(exitNodeID), 16)], "...", i+1, len(bestOrder))

				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				meshConn, dialErr = node.DialVirtualPort(ctx, exitNodeID, int(mesh.SOCKS5VirtualPort))
				cancel()
				if dialErr == nil {
					break
				}
				log.Printf("SOCKS5 client: exit %s...: %v — trying next", exitNodeID[:min(len(exitNodeID), 16)], dialErr)
				health.markDown(exitNodeID)
			}
			if dialErr != nil {
				log.Printf("SOCKS5 client: all %d exit(s) failed, last error: %v", len(bestOrder), dialErr)
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

// versionInfo returns the formatted version string with version, commit,
// build time, Go version, and platform/architecture.
func versionInfo() string {
	return fmt.Sprintf("meshdesk %s\n  commit:     %s\n  build time: %s\n  go version: %s\n  platform:   %s/%s\n",
		Version, Commit, BuildTime, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// runVersionSubcommand implements `meshdesk version`.
// It prints the version, commit hash, build time, Go version, and
// platform/architecture to stdout. The version, commit, and build
// time are injected at build time via -ldflags.
func runVersionSubcommand() {
	fmt.Print(versionInfo())
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

// runReloadSubcommand handles: meshdesk reload [--pid <pid>]
//
// It sends SIGHUP to a running meshdesk process, triggering an
// in-place config reload without restarting the daemon. The PID is
// read from /var/run/meshdesk.pid by default (matching the systemd
// unit's PIDFile directive), or specified explicitly via --pid.
//
// This is the CLI equivalent of clicking "Hot Reload" in the web
// Dashboard or calling `curl -X POST /api/config/reload`. Unlike
// the HTTP API, it works even when the web UI is not enabled (e.g.
// agent-only nodes) — the SIGHUP handler in main.go processes the
// reload independently of the web server.
func runReloadSubcommand(args []string) {
	fs := flag.NewFlagSet("reload", flag.ExitOnError)
	pidFlag := fs.Int("pid", 0, "PID of the meshdesk process to reload (default: read from /var/run/meshdesk.pid)")
	_ = fs.Parse(args)

	pid := *pidFlag
	if pid == 0 {
		// Try to read PID from the default pidfile.
		data, err := os.ReadFile("/var/run/meshdesk.pid")
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error: could not read /var/run/meshdesk.pid")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Usage: meshdesk reload [--pid <pid>]")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Sends SIGHUP to a running meshdesk process to trigger")
			fmt.Fprintln(os.Stderr, "a config reload without restarting the daemon.")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "If --pid is not specified, the PID is read from")
			fmt.Fprintln(os.Stderr, "/var/run/meshdesk.pid (set by the systemd unit).")
			os.Exit(2)
		}
		// Parse PID, trimming whitespace.
		pidStr := strings.TrimSpace(string(data))
		pid, err = strconv.Atoi(pidStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid PID in /var/run/meshdesk.pid: %q\n", pidStr)
			os.Exit(2)
		}
	}

	if pid <= 0 {
		fmt.Fprintf(os.Stderr, "Error: invalid PID %d\n", pid)
		os.Exit(2)
	}

	// Send SIGHUP to the process.
	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not find process %d: %v\n", pid, err)
		os.Exit(1)
	}

	if err := proc.Signal(syscall.SIGHUP); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to send SIGHUP to process %d: %v\n", pid, err)
		os.Exit(1)
	}

	fmt.Printf("✓ Sent SIGHUP to meshdesk (pid %d) — config reload triggered\n", pid)
	fmt.Println("  Check the meshdesk log for reload status.")
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

// systemResolver reads the first nameserver from /etc/resolv.conf.
// Returns "ip:53" or "" if none found.
func systemResolver() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			ip := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
			if ip == "" {
				continue
			}
			// Handle IPv6 (add brackets for the port form).
			if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
				ip = "[" + ip + "]"
			}
			return ip + ":53"
		}
	}
	return ""
}

// pickBestExits returns the exit nodes in preference order: healthy
// exits sorted by live RTT (lowest first). Unknown-RTT exits go last
// but stay eligible. When the config pins a single exit (exit_node),
// that exit is tried first and the rest are fallbacks.
func pickBestExits(h *exitHealth, node *mesh.MeshNode, exits []string) []string {
	type scored struct {
		key string
		rtt time.Duration
	}
	seen := map[string]bool{}
	var out []scored

	// Healthy exits first (RTT-sorted).
	h.mu.Lock()
	for _, e := range exits {
		if h.state[e] {
			out = append(out, scored{key: e, rtt: node.PeerRTT(e)})
			seen[e] = true
		}
	}
	h.mu.Unlock()

	// Untested exits (never probed yet) stay eligible, RTT-sorted.
	for _, e := range exits {
		if !seen[e] {
			out = append(out, scored{key: e, rtt: node.PeerRTT(e)})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := out[i].rtt, out[j].rtt
		if ri == 0 {
			ri = time.Duration(1 << 62)
		}
		if rj == 0 {
			rj = time.Duration(1 << 62)
		}
		return ri < rj
	})

	order := make([]string, len(out))
	for i, sc := range out {
		order[i] = sc.key
	}
	return order
}

// exitHealth tracks SOCKS5 exit node health and does round-robin
// selection (T3.2). Each exit is probed by dialing its SOCKS5 virtual
// port every 30s; failed probes mark it down until the next success.

func newExitHealth(node *mesh.MeshNode, exits []string) *exitHealth {
	h := &exitHealth{
		node:  node,
		state: make(map[string]bool),
		order: exits,
	}
	for _, e := range exits {
		h.state[e] = true
	}
	return h
}

func (h *exitHealth) run() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		for _, e := range h.order {
			h.probe(e)
		}
	}
}

func (h *exitHealth) probe(exitID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := h.node.DialVirtualPort(ctx, exitID, int(mesh.SOCKS5VirtualPort))
	if err != nil {
		h.markDown(exitID)
		return
	}
	conn.Close()
	h.markUp(exitID)
}

func (h *exitHealth) markUp(exitID string) {
	h.mu.Lock()
	h.state[exitID] = true
	h.mu.Unlock()
}

func (h *exitHealth) markDown(exitID string) {
	h.mu.Lock()
	h.state[exitID] = false
	h.mu.Unlock()
}

// pick returns the next healthy exit (round-robin), or "" if none.
func (h *exitHealth) pick() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := 0; i < len(h.order); i++ {
		idx := (h.rr + i) % len(h.order)
		id := h.order[idx]
		if h.state[id] {
			h.rr = (idx + 1) % len(h.order)
			return id
		}
	}
	return ""
}
