// Command meshdesk is the single entrypoint for the MeshDesk binary.
// Without --web, the node runs in agent-only mode (mesh transport + monitoring reporter).
// With --web, it also serves the Web UI (dashboard, WebSSH, file transfer, service management).
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yzy806806/meshdesk/internal/app"
	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/join"
	"github.com/yzy806806/meshdesk/internal/logging"
	"github.com/yzy806806/meshdesk/internal/mesh"
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
		if cfg.Mesh.Port == 0 {
			cfg.Mesh.Port = bundle.GossipPort
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
// The gossip layer has been removed; the join flow now relies on
// static peer configuration + mesh session meta exchange (META
// protocol) for peer discovery.
func runJoinWithConfig(cfg *config.Config, bootstrapAddr, bootstrapKey, configPath string) {
	// If a bootstrap public key was provided, add it as a static peer
	// so the mesh can establish the initial connection.
	if bootstrapKey != "" {
		// Parse the bootstrap address for the endpoint.
		host, port := parseBootstrapAddr(bootstrapAddr, cfg.Mesh.Port)
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

	// Persist the updated config so the node can restart without
	// re-joining.
	if err := config.Save(configPath, cfg); err != nil {
		log.Printf("[join] warning: failed to save config to %s: %v (continuing with in-memory config)", configPath, err)
	} else {
		log.Printf("[join] config saved to %s", configPath)
	}

	log.Printf("MeshDesk joined the mesh (bootstrap=%s). Waiting for peers...", bootstrapAddr)

	// Wait for shutdown signal (like normal mode, but join-only).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("Shutting down...")
	node.Close()
}

// parseBootstrapAddr splits a bootstrap address into host and port,
// using defaultPort if no port is specified.
func parseBootstrapAddr(addr string, defaultPort int) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	// No port — use default.
	if defaultPort <= 0 {
		defaultPort = 7946
	}
	return addr, fmt.Sprintf("%d", defaultPort)
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

// pick returns the next healthy exit (round-robin), or "" if none.
