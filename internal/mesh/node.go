// Package mesh provides the core mesh node abstraction.
//
// The MeshNode implements a self-developed protocol stack:
//   - Layer 0: Ed25519 identity (identity.Identity)
//   - Layer 1: Reality TLS transport or mesh-internal transport (transport.go)
//   - Layer 2a: X25519 ECDH key exchange (handshake package)
//   - Layer 2b: AES-256-GCM SecureConn (crypto.NewSecureConn)
//   - Layer 3: smux multiplexed streams (smux package)
//   - Layer 4: virtual port dispatch (DialVirtualPort / ListenVirtualPort)
//
// The RoutingTable and PeerEntry types map peer IDs to connections and
// are used across the web dashboard, p2p, and security alerting packages.
package mesh

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/crypto"
	"github.com/yzy806806/meshdesk/internal/handshake"
	"github.com/yzy806806/meshdesk/internal/identity"
	"github.com/yzy806806/meshdesk/internal/session"
	"github.com/yzy806806/meshdesk/internal/smux"
)

// MeshNode is the core mesh node. It manages:
//   - An Ed25519 identity (Layer 0)
//   - A Reality TLS transport or mesh-internal transport (Layer 1)
//   - X25519 ECDH key exchange (Layer 2a)
//   - AES-256-GCM SecureConn authenticated encryption (Layer 2b)
//   - A smux-based multiplexed stream layer (Layer 3)
//   - Virtual port dispatch (Layer 4)
type MeshNode struct {
	identity *identity.Identity
	routes   *RoutingTable
	cfg      *config.Config
	registry *TransportRegistry

	// v2 session management
	listener   net.Listener
	hs         handshake.HandshakeLayer
	sessions   map[string]*smux.Session // peer identity hex → smux session (preferred: client)
	sessionsMu sync.Mutex
	// clientSessions stores outbound (client-mode) sessions separately so
	// that DialVirtualPort can prefer them even when a server-mode session
	// from an inbound connection has replaced the entry in sessions.
	clientSessions       map[string]*smux.Session
	sessionEstablishedAt map[string]time.Time
	// sessionEstablished holds callbacks fired when a smux session is
	// established with a peer (multiple may be registered).
	sessionEstablished []func(peerKey string) // hook registry
	// peerManagers tracks per-peer PeerManager instances for outbound
	// connections (one per peer). Inbound sessions from handleConnection
	// do not create a PeerManager — they reuse the session directly.
	peerManagers   map[string]*PeerManager
	peerManagersMu sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc

	// portMux dispatches inbound smux streams to virtual-port listeners.
	// When a peer opens a stream, the first frame carries a 2-byte port
	// number; the stream is then delivered to the VirtualListener
	// registered for that port via ListenVirtualPort.
	portMux *virtualPortMux

	// reconnectState tracks per-peer auto-reconnect goroutines so we
	// don't spawn duplicate reconnect attempts for the same peer.
	reconnectState   map[string]*reconnectTracker
	reconnectStateMu sync.Mutex

	// muxTransport is the shared TCP listener multiplexer between gossip
	// and Reality TLS. When non-nil, Start() creates it and passes its
	// RealityListener() to the Reality handshake layer, and the caller
	// passes the MuxTransport itself to the gossip layer via SetTransport.
	// nil when port multiplexing is not used (P2P disabled).
	muxTransport *MuxTransport

	// relayHandler, when non-nil, is the active mesh-internal smux
	// stream relay handler registered on virtual port 0x524C. It is
	// created by RegisterRelayHandler and closed by Close().
	relayHandler *RelayHandler

	// socks5Handler, when non-nil, is the active SOCKS5 proxy handler
	// registered on virtual port 0x5350. It is created by
	// RegisterSOCKS5Handler (direct-dial exit mode) or
	// RegisterSOCKS5ForwardHandler (forward-to-exit mode) and closed by
	// Close().
	socks5Handler socks5Closer

	// socks5ExitHandler, when non-nil, is the active SOCKS5 exit handler
	// registered on virtual port 0x4558 (ExitVirtualPort). It is created by
	// RegisterSOCKS5ExitHandler and closed by Close(). This is separate from
	// socks5Handler because a node may register both a forward handler
	// (0x5350) and an exit handler (0x4558) simultaneously.
	socks5ExitHandler socks5Closer

	// tunIntegration holds the TUN device, IPAM allocator, router,
	// route manager, and forwarder. Non-nil when cfg.Mesh.TunEnabled
	// is true and setupTUN() has succeeded.
	tunIntegration *TUNIntegration

	// peerMetaProvider is a callback that returns known peer public keys
	// → VirtualIP strings. Set by main.go to bridge the gossip layer
	// with the TUN IPAM allocator, avoiding an import cycle.
	peerMetaProvider func() map[string]string

	// virtualIPBroadcaster is a callback to propagate the local node's
	// VirtualIP to the gossip layer. Set by main.go to
	// gossipLayer.SetLocalVirtualIP.
	virtualIPBroadcaster func(string)

	// subnetProxyBroadcaster is a callback to propagate the local node's
	// subnet proxies to the gossip layer. Set by main.go to
	// gossipLayer.SetLocalSubnetProxies.
	subnetProxyBroadcaster func([]string)

	// aclEngine is the TUN access control list engine. When non-nil,
	// every inbound TUN packet is checked against ACL rules before
	// being written to the TUN device. Set by setupTUN when ACL is
	// configured. Accessible via ACL() for the web Dashboard.
	aclEngine *ACLEngine

	// aclRulesBroadcaster is a callback to propagate the local node's
	// ACL rules to the gossip layer. Set by main.go to
	// gossipLayer.SetLocalACLRules.
	aclRulesBroadcaster func([]string)

	// sessionDeathHandler is called when a smux session with a peer dies
	// (detected by the reconnect watcher). The argument is the peer's
	// identity hex. Set by main.go to clean up TUN routes when the peer
	// is truly unreachable, as opposed to a memberlist UDP flap where the
	// session is still alive.
	sessionDeathHandler func(string)

	// sessionReconnectHandler is called after a smux session with a peer
	// is successfully re-established by the reconnect watcher. The
	// argument is the peer's identity hex. Set by main.go to re-add TUN
	// routes that were removed by the sessionDeathHandler. Since the peer
	// stays in memberlist (only the smux session died, not gossip
	// membership), no new NotifyJoin fires, so the join handler in
	// main.go never re-runs. This callback fills that gap.
	sessionReconnectHandler func(string)

	// collectorHandler is invoked when META exchange reveals a peer
	// with Collector=true (runs the dashboard aggregator). It mirrors
	// the gossip-based CapCollector discovery so relay-attached nodes
	// (degraded memberlist) still learn where to push monitor metrics.
	// Set by main.go to reporter.AddCollector.
	collectorHandler func(string)

	// collectorPeers tracks peers known to run the dashboard aggregator
	// (learned via META Self.Collector or gossip CapCollector). Used by
	// knownPeers() so the capability floods onward — a relay hop must
	// re-advertise the dashboard node's Collector=true to its own peers.
	// Guarded by mu.
	collectorPeers map[string]bool

	// localIsCollector marks this node as running the dashboard
	// aggregator (web mode) — advertised in META as Collector=true so
	// every peer, including relay-attached ones, auto-discovers us.
	localIsCollector bool

	// metaBroadcaster re-sends our full META to all session peers —
	// invoked when collector capability CHANGES (this node became a
	// collector, or learned a new collector peer) so peers that
	// connected earlier still learn the capability. Set by the app
	// layer to MetaExchanger.Broadcast.
	metaBroadcaster func()

	// peerRelayMeta stores relay/NAT knowledge learned via META
	// (Role/NatType/CapRelay/MaxCircuits/LoadCircuits) — the
	// gossip-NodeMeta-exclusive fields migrated to the session meta
	// plane (memberlist-retirement phase 1) so relay selection works
	// when memberlist is degraded. Flooded onward by knownPeers().
	// Guarded by mu.
	peerRelayMeta map[string]MetaRelayInfo

	// metaExtrasProvider returns this node's own relay/NAT knowledge
	// for localMeta() (memberlist-retirement phase 1). Set by the app
	// layer; nil → empty info.
	metaExtrasProvider func() MetaRelayInfo

	// relayConnectMu guards relayConnecting — the set of peers we are
	// currently auto-dialing (AutoConnectRelayPeer dedup).
	relayConnectMu  sync.Mutex
	relayConnecting map[string]bool

	// relayMetaProvider is a callback that returns metadata for all
	// known relay-capable peers from the gossip layer. Each entry is
	// (peerKey, rtt, capRelay, maxCircuits, loadCircuits, natType).
	// Set by main.go to bridge the gossip layer with the relay dialer,
	// avoiding an import cycle between mesh and p2p packages.
	// If nil, tryRelayFallback falls back to the legacy behavior of
	// trying all peers with active sessions.
	relayMetaProvider func() []RelayPeerInfo

	// relayLastSuccess caches the last working relay per target so
	// tryRelayFallback can skip the full candidate scan (which, when
	// re-triggered every monitor tick, burned 100% CPU on healthy
	// relay links).
	relayLastSuccess map[string]relaySuccessEntry

	// peerEndpointResolver returns the STABLE endpoint (advertised
	// address, not the ephemeral source port of an inbound session)
	// for a peer identity hex. Set by main.go to query the gossip
	// layer's KnownPeers, which carries advertise_endpoints. Used by
	// the reconnect watcher to avoid dialing dead NAT mappings.
	// If nil, resolvePeerEndpoint falls back to config peers and the
	// routing table.
	peerEndpointResolver func(string) string

	// peersMu guards n.cfg.Peers: AddPeer appends at runtime while
	// Dial/findPeerConfigByAddress/isKnownPeer iterate concurrently.
	// A separate mutex avoids lock-order interaction with n.mu /
	// sessionsMu.
	peersMu sync.RWMutex

	// peerTransport records the transport each peer session was
	// established over: "reality" (TLS), "0x4d" (mesh-internal), "udp".
	// Guarded by sessionsMu. Used by the topology display.
	peerTransport map[string]string

	// learnedZones caches zone tags learned via the meta exchange
	// (0x4D45) — works even when memberlist/gossip is degraded.
	// Guarded by sessionsMu.
	learnedZones map[string]string

	// learnedEndpoints caches endpoint lists learned via the meta
	// exchange — lets same-zone peers dial UDP/TCP directly even when
	// memberlist (the usual endpoint source) is degraded.
	// Guarded by sessionsMu.
	learnedEndpoints map[string][]string

	// holeEndpoints caches the CONFIRMED data-plane endpoint punched
	// for a peer (OnHoleEstablished). Kept SEPARATE from
	// learnedEndpoints because the meta exchange overwrites that map
	// with gossip-advertised endpoints (52888) that are NOT the
	// punched UDP port — using them for the TUN data plane dials a
	// dead port (observed: tun-udp no-ACK against 52888 while the
	// live hole was on a random UDP port). Hole endpoints win.
	// Guarded by sessionsMu.
	holeEndpoints map[string][]string

	// rttCache caches PeerRTT results so topology renders and exit
	// selection don't hammer the session echo port on every call.
	// Guarded by sessionsMu. rttCacheTTL bounds staleness.
	rttCache map[string]rttCacheEntry

	// relayBackoff tracks failed (target, relay) relay attempts so the
	// dialer stops hammering unreachable targets. Without this, every
	// connection attempt to an unreachable peer (socks5 exit, monitor
	// probe) fired multiple relay requests per second; on shared nodes
	// the accumulated slow connections saturated memberlist's 128-slot
	// push/pull queue ("Too many pending push/pull requests"), which
	// rejected legitimate seed joins with EOF.
	relayBackoff *relayBackoff

	// zoneLearner resolves a peer's zone from gossip (injected by
	// main.go; avoids a mesh→p2p import cycle). nil = no gossip.
	zoneLearner func(peerKey string) string

	mu     sync.RWMutex
	closed bool
}

// New creates a new MeshNode from a config.
func New(cfg *config.Config) (*MeshNode, error) {
	nodeIdentity, err := loadOrCreateIdentity(cfg)
	if err != nil {
		return nil, err
	}

	registry := NewTransportRegistry()
	ctx, cancel := context.WithCancel(context.Background())

	node := &MeshNode{
		identity:             nodeIdentity,
		routes:               NewRoutingTable(),
		cfg:                  cfg,
		registry:             registry,
		sessions:             make(map[string]*smux.Session),
		peerTransport:        make(map[string]string),
		learnedZones:         make(map[string]string),
		learnedEndpoints:     make(map[string][]string),
		holeEndpoints:        make(map[string][]string),
		collectorPeers:       make(map[string]bool),
		peerRelayMeta:        make(map[string]MetaRelayInfo),
		relayConnecting:      make(map[string]bool),
		rttCache:             make(map[string]rttCacheEntry),
		clientSessions:       make(map[string]*smux.Session),
		sessionEstablishedAt: make(map[string]time.Time),
		sessionEstablished:   []func(peerKey string){},
		peerManagers:         make(map[string]*PeerManager),
		portMux:              newVirtualPortMux(),
		reconnectState:       make(map[string]*reconnectTracker),
		relayBackoff:         newRelayBackoff(),
		ctx:                  ctx,
		cancel:               cancel,
	}

	return node, nil
}

// Start begins mesh operation.
//
// Shared node mode (reality.enabled: true):
// It creates a Reality TLS listener, starts an accept loop in a background
// goroutine, and for each accepted connection performs X25519 ECDH key
// exchange, wraps the connection in AES-256-GCM, and creates an smux session.
//
// When P2P is enabled (cfg.P2P.Enabled), Start() creates a MuxTransport
// that shares a single TCP listener between gossip (memberlist) and Reality
// TLS. The MuxTransport is exposed via MuxTransport() for the caller to
// inject into the gossip layer.
//
// Ordinary node mode (reality.enabled: false, p2p.enabled: true):
// The node creates a plain TCP listener (no Reality TLS) on the gossip
// port. This allows memberlist push/pull sync and mesh-internal smux
// sessions (0x4D marker byte) from other nodes. The node joins the
// cluster via configured seeds and establishes smux sessions by dialing
// shared nodes using the mesh-internal path.
func (n *MeshNode) Start() error {
	if !n.cfg.Reality.Enabled {
		// Ordinary node mode: no Reality TLS. Creates a plain TCP
		// listener for mesh-internal smux sessions (0x4D marker byte)
		// from other nodes. When P2P is enabled, the same listener
		// also serves memberlist push/pull sync; when P2P is disabled,
		// memberlist is skipped entirely and peer discovery relies on
		// the META exchange (session-based, memberlist-independent).
		//
		// We create a plain TCP listener (no Reality multiplexing) on
		// the gossip port. The MuxTransport's demux logic routes:
		//   - memberlist traffic (non-0x16, non-0x4D) → StreamCh
		//   - mesh-internal connections (0x4D) → meshCh
		//   - TLS (0x16) → realityCh (ignored — no Reality listener)
		bindAddr := "0.0.0.0"
		tcpPort := n.cfg.Mesh.GossipPort
		if tcpPort == 0 {
			tcpPort = n.cfg.Mesh.Port
		}
		tcpListenAddr := net.JoinHostPort(bindAddr, strconv.Itoa(tcpPort))
		tcpListener, err := net.Listen("tcp", tcpListenAddr)
		if err != nil {
			return fmt.Errorf("mesh: start ordinary node TCP listener on %s: %w", tcpListenAddr, err)
		}

		muxCfg := MuxTransportConfig{
			TCPListener: tcpListener,
			BindAddr:    bindAddr,
			// Ordinary nodes use a DISTINCT random UDP port: Go's
			// runtime breaks public UDP sends when the socket shares
			// its port with the TCP listener or with the other
			// family's socket (verified on txcloud — WriteToUDP
			// returns nil but nothing leaves the box). UDPPort=-1
			// means "two family sockets, each on an OS-assigned
			// random port" — the punch coordination exchange carries
			// the real ports to the peer, so no fixed port is needed.
			// Shared nodes keep single-port multiplexing (UDPPort
			// unset → mirrors the TCP port on one [::] socket).
			UDPPort: -1,
		}
		mt, err := NewMuxTransport(muxCfg)
		if err != nil {
			tcpListener.Close()
			return fmt.Errorf("mesh: create ordinary node mux transport: %w", err)
		}
		n.mu.Lock()
		n.muxTransport = mt
		n.hs = nil
		n.listener = nil
		n.mu.Unlock()

		log.Printf("[mesh] ordinary node mode (TCP+UDP gossip on %s:%d)", bindAddr, tcpPort)

		// Start a mesh-internal accept loop for connections that use
		// the mesh-internal marker byte (0x4D). Other ordinary nodes or
		// shared nodes can dial this node's TCP listener and establish
		// smux sessions directly (without Reality TLS).
		meshLn := n.muxTransport.MeshListener()
		go n.acceptMeshLoop(meshLn)

		// Wire the UDP TUN stream authenticator (multipath D): the
		// tun-forwarder's UDP-preferred data plane authenticates
		// first-frame signatures against known peers.
		n.wireTUNAUDAuthValidator()
	} else {
		// Shared node mode (reality.enabled: true).
		if !n.cfg.Reality.Enabled {
			return fmt.Errorf("mesh: Reality TLS not enabled in config (set reality.enabled=true)")
		}

		// Build the listen address from config.
		addr := buildRealityListenAddr(n.cfg)

		// Create the Reality TLS handshake config.
		hsCfg := handshake.HandshakeConfig{
			ListenAddr:         addr,
			RealityDest:        n.cfg.Reality.Dest,
			RealityPrivateKey:  n.cfg.Reality.PrivateKey,
			RealityShortID:     firstShortID(n.cfg.Reality.ShortIDs),
			RealityServerNames: n.cfg.Reality.ServerNames,
			DialTimeout:        30 * time.Second,
			TLSFingerprint:     "chrome",
		}

		hs := handshake.NewRealityHandshake(hsCfg)

		var ln net.Listener
		var err error

		if n.cfg.P2P.Enabled {
			// Port multiplexing: create a shared TCP listener and MuxTransport,
			// then wrap the MuxTransport's RealityListener with REALITY auth.
			tcpListener, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("mesh: start shared TCP listener on %s: %w", addr, err)
			}

			muxCfg := MuxTransportConfig{
				TCPListener:   tcpListener,
				BindAddr:      "0.0.0.0",
				AdvertiseAddr: "", // auto-detect
			}
			mt, err := NewMuxTransport(muxCfg)
			if err != nil {
				tcpListener.Close()
				return fmt.Errorf("mesh: create mux transport: %w", err)
			}

			n.mu.Lock()
			n.muxTransport = mt
			n.mu.Unlock()

			// Wire the UDP TUN stream authenticator (multipath D) in
			// shared-node mode too — without it the UDP-preferred data
			// plane is silently refused on shared nodes (validator nil
			// → all first frames dropped → always falls back to TCP).
			n.wireTUNAUDAuthValidator()

			// Wrap the MuxTransport's RealityListener with REALITY auth.
			realityLn := mt.RealityListener()
			ln, err = hs.ListenWithListener(n.ctx, realityLn)
			if err != nil {
				mt.Shutdown()
				return fmt.Errorf("mesh: start reality listener on %s: %w", addr, err)
			}
		} else {
			// No P2P — create a standalone Reality TLS listener.
			ln, err = hs.Listen(n.ctx, addr)
			if err != nil {
				return fmt.Errorf("mesh: start reality listener on %s: %w", addr, err)
			}
		}

		n.mu.Lock()
		if n.listener != nil {
			n.listener.Close()
		}
		n.listener = ln
		n.hs = hs
		n.mu.Unlock()

		log.Printf("[mesh] Reality TLS listener started on %s (dest=%s)", addr, n.cfg.Reality.Dest)

		// Start accept loop in background.
		go n.acceptLoop(ln)

		// If MuxTransport is active, also start a mesh-internal accept loop
		// for connections that use the mesh-internal marker byte (0x4D).
		if n.muxTransport != nil {
			meshLn := n.muxTransport.MeshListener()
			go n.acceptMeshLoop(meshLn)
		}
	}

	// Set up TUN integration if enabled.
	if n.cfg.Mesh.TunEnabled {
		if err := n.setupTUN(); err != nil {
			log.Printf("[mesh] warning: TUN setup failed: %v (continuing without TUN)", err)
		}
	}

	return nil
}

// acceptLoop accepts inbound Reality TLS connections, performs the
// full protocol handshake (key exchange → SecureConn → smux), and
// stores the resulting session.
func (n *MeshNode) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-n.ctx.Done():
				return
			default:
			}
			// Check if listener was closed.
			n.mu.RLock()
			closed := n.closed
			n.mu.RUnlock()
			if closed {
				return
			}
			log.Printf("[mesh] accept error: %v", err)
			// Brief sleep before retry on transient errors.
			time.Sleep(100 * time.Millisecond)
			continue
		}

		remoteAddr := conn.RemoteAddr().String()
		log.Printf("[mesh] accepted connection from %s", remoteAddr)

		// Handle each connection in its own goroutine (Reality TLS).
		go n.handleConnection(conn, remoteAddr, "reality")
	}
}

// acceptMeshLoop accepts inbound mesh-internal connections (those that
// sent the 0x4D marker byte). These connections bypass Reality TLS and
// go directly to the session key exchange + smux handshake.
func (n *MeshNode) acceptMeshLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-n.ctx.Done():
				return
			default:
			}
			n.mu.RLock()
			closed := n.closed
			n.mu.RUnlock()
			if closed {
				return
			}
			log.Printf("[mesh] mesh-internal accept error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		remoteAddr := conn.RemoteAddr().String()
		log.Printf("[mesh] accepted mesh-internal connection from %s", remoteAddr)
		go n.handleConnection(conn, remoteAddr, "0x4d")
	}
}

// handleConnection performs the Layer 2–3 handshake on an accepted
// Reality TLS connection:
//  1. Server-side X25519 ECDH key exchange (session.ServerKeyExchange)
//  2. Wrap in AES-256-GCM SecureConn (crypto.NewSecureConn)
//  3. Create smux multiplexer session (smux.Server)
//  4. Store the session keyed by peer identity
func (n *MeshNode) handleConnection(conn net.Conn, remoteAddr, transport string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[mesh] panic handling connection from %s: %v\n%s", remoteAddr, r, debug.Stack())
		}
	}()

	// Set a deadline for the full key exchange.
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Step 1: Server-side X25519 ECDH key exchange.
	keys, peerIdentityHex, err := session.ServerKeyExchange(conn, n.identity)
	if err != nil {
		log.Printf("[mesh] key exchange failed with %s: %v", remoteAddr, err)
		conn.Close()
		return
	}

	// Clear the deadline — the secure channel manages its own timeouts.
	conn.SetDeadline(time.Time{})

	log.Printf("[mesh] key exchange complete with %s (peer=%s)", remoteAddr, peerIdentityHex[:16]+"...")

	// Step 2: Wrap in AES-256-GCM SecureConn.
	secureConn, err := crypto.NewSecureConn(conn, keys.SendKey[:], keys.RecvKey[:])
	if err != nil {
		log.Printf("[mesh] failed to create SecureConn with %s: %v", remoteAddr, err)
		conn.Close()
		return
	}

	// Step 3: Create smux server session.
	smuxSession, err := smux.Server(secureConn, smuxCfg())
	if err != nil {
		log.Printf("[mesh] smux handshake failed with %s: %v", remoteAddr, err)
		secureConn.Close()
		return
	}

	// Step 4: Store the session.
	// If the old session was a client session (outbound), preserve it in
	// clientSessions so DialVirtualPort can still open streams. Only close
	// the old session if it was also a server session (inbound reconnect).
	n.sessionsMu.Lock()
	oldSession, exists := n.sessions[peerIdentityHex]
	n.sessions[peerIdentityHex] = smuxSession
	n.peerTransport[peerIdentityHex] = transport
	n.sessionEstablishedAt[peerIdentityHex] = time.Now()
	n.sessionsMu.Unlock()

	// If the same peer reconnected via an inbound connection, close the old
	// session ONLY if it's not still alive as a client session.
	if exists {
		// Check if the old session is the same as the client session.
		n.sessionsMu.Lock()
		clientSess, hasClient := n.clientSessions[peerIdentityHex]
		n.sessionsMu.Unlock()
		if hasClient && clientSess == oldSession {
			// The old session is the client session — keep it alive.
			log.Printf("[mesh] peer %s reconnected via inbound — preserving outbound client session", peerIdentityHex[:16]+"...")
		} else {
			log.Printf("[mesh] peer %s reconnected — closing old session", peerIdentityHex[:16]+"...")
			oldSession.Close()
		}
	}

	log.Printf("[mesh] session established with %s (peer=%s, addr=%s)",
		remoteAddr, peerIdentityHex[:16]+"...", remoteAddr)
	n.fireSessionEstablished(peerIdentityHex)

	// Add the peer to the routing table.
	n.routes.AddPeer(&PeerEntry{
		ID:       peerIdentityHex,
		Endpoint: remoteAddr,
	})

	// Hand the smux session to the stream handler. This starts a goroutine
	// that accepts inbound streams on the session.
	go n.handleSessionStreams(peerIdentityHex, smuxSession)

	// Restore TUN routes for this peer if it reconnected via an inbound
	// session. If the peer's session died earlier, the death handler
	// removed its TUN routes; a new inbound session means the peer is
	// reachable again and the routes must be re-added. The reconnect
	// handler looks up the peer's VirtualIP from gossip KnownPeers —
	// idempotent if routes already exist.
	n.mu.RLock()
	reconnectHdl := n.sessionReconnectHandler
	n.mu.RUnlock()
	if reconnectHdl != nil {
		reconnectHdl(peerIdentityHex)
	}

	// Start auto-reconnect watcher. For inbound (server-mode) sessions,
	// we pass isClientSession=false so the reconnect logic knows to try
	// the mesh-internal dial path. The endpoint is the remote address.
	n.startSessionWatcher(peerIdentityHex, remoteAddr, false)
}

// handleSessionStreams runs an accept loop on an established smux session,
// dispatching inbound streams. It runs in a background goroutine and exits
// when the session is closed or the node context is cancelled.
//
// In v2, this replaces the PeerManager's stream-handling role for inbound
// connections. The PeerManager (used for outbound) manages transport-level
// connection lifecycle; once a session is established (inbound or outbound),
// this method handles incoming streams.
func (n *MeshNode) handleSessionStreams(peerIdentityHex string, sess *smux.Session) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[mesh] panic in stream handler for peer %s: %v", peerIdentityHex[:16]+"...", r)
		}
	}()

	for {
		// AcceptStream blocks until a stream arrives or the session closes.
		stream, err := sess.AcceptStream(n.ctx)
		if err != nil {
			// Session closed or context cancelled — exit the loop.
			if !sess.IsClosed() {
				log.Printf("[mesh] stream accept error for peer %s: %v", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...", err)
			}
			return
		}

		// Read the virtual port prefix (2 bytes, big-endian uint16).
		port, err := readPortFrame(stream)
		if err != nil {
			log.Printf("[mesh] failed to read virtual port from peer %s: %v", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...", err)
			stream.Close()
			continue
		}

		log.Printf("[mesh] inbound stream from peer %s on virtual port %d", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...", port)

		// Dispatch the stream to the virtual listener registered for this port.
		n.portMux.dispatch(port, stream, peerIdentityHex)
	}
}

// Close shuts down the mesh node and releases all resources.
func (n *MeshNode) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true

	// Cancel the context first — this signals the accept loop to stop.
	if n.cancel != nil {
		n.cancel()
	}

	// Close the Reality TLS listener.
	if n.listener != nil {
		n.listener.Close()
	}
	if n.hs != nil {
		n.hs.Close()
	}

	// Close the MuxTransport if active (shared TCP/UDP listener).
	if n.muxTransport != nil {
		n.muxTransport.Shutdown()
	}

	n.mu.Unlock()

	// Close all smux sessions FIRST. The tun-forwarder's inbound
	// handlers block on smux stream reads; closing sessions unblocks
	// them so the forwarder's Stop() (in teardownTUN below) can drain
	// its waitgroup instead of hanging forever — the stale-process-
	// on-restart root cause (systemd waited 90s+ for a process that
	// could never exit, then manual restart raced into double
	// processes + a dirty TUN device).
	n.sessionsMu.Lock()
	for id, sess := range n.sessions {
		log.Printf("[mesh] closing session for peer %s", id[:16]+"...")
		sess.Close()
	}
	n.sessions = make(map[string]*smux.Session)
	n.clientSessions = make(map[string]*smux.Session)
	n.sessionEstablishedAt = make(map[string]time.Time)
	n.sessionsMu.Unlock()

	// Tear down TUN integration (forwarder Stop now completes quickly).
	n.teardownTUN()

	// Stop all auto-reconnect watchers.
	n.stopAllReconnectWatchers()

	// Stop all PeerManagers.
	n.peerManagersMu.Lock()
	for id, pm := range n.peerManagers {
		log.Printf("[mesh] stopping PeerManager for peer %s", id[:16]+"...")
		pm.Stop()
	}
	n.peerManagers = make(map[string]*PeerManager)
	n.peerManagersMu.Unlock()

	// Close all virtual port listeners.
	if n.portMux != nil {
		n.portMux.mu.Lock()
		for port, vl := range n.portMux.listeners {
			delete(n.portMux.listeners, port)
			vl.Close()
		}
		n.portMux.mu.Unlock()
	}

	// Close the relay handler if active.
	n.mu.Lock()
	if n.relayHandler != nil {
		n.relayHandler.Close()
		n.relayHandler = nil
	}
	// Close the SOCKS5 handlers if active.
	if n.socks5Handler != nil {
		n.socks5Handler.Close()
		n.socks5Handler = nil
	}
	if n.socks5ExitHandler != nil {
		n.socks5ExitHandler.Close()
		n.socks5ExitHandler = nil
	}
	n.mu.Unlock()

	// Shut down transports.
	if n.registry != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = n.registry.ShutdownAll(ctx)
	}
	return nil
}

// GetSession returns the smux session for a peer by identity hex string.
// Returns nil if no session exists for the peer.
// HasActiveSession returns true if there is a live (non-closed) smux session
// with the given peer identity hex. This is used to check whether a peer is
// still reachable at the session layer even when memberlist UDP probing fails.
//
// The distinction matters because memberlist may mark a peer as "left" due to
// UDP ping timeouts (e.g. cross-network latency, NAT, or VPN packet loss)
// while the TCP smux session is still alive and functional. In that case,
// TUN routes and other session-dependent state should be preserved.
func (n *MeshNode) HasActiveSession(peerIdentityHex string) bool {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()

	if sess, ok := n.clientSessions[peerIdentityHex]; ok && sess != nil && !sess.IsClosed() {
		return true
	}
	if sess, ok := n.sessions[peerIdentityHex]; ok && sess != nil && !sess.IsClosed() {
		return true
	}
	return false
}

// GetSession returns the active smux session for the given peer identity hex,
// or nil if no session exists. It checks both the main sessions map and the
// client sessions map, preferring client (outbound) sessions.
func (n *MeshNode) GetSession(peerIdentityHex string) *smux.Session {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()
	if sess, ok := n.clientSessions[peerIdentityHex]; ok && sess != nil {
		return sess
	}
	return n.sessions[peerIdentityHex]
}

// ListSessions returns a copy of all active peer sessions.
// Key: peer identity hex string, Value: smux session.
func (n *MeshNode) ListSessions() map[string]*smux.Session {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()
	out := make(map[string]*smux.Session, len(n.sessions))
	for k, v := range n.sessions {
		out[k] = v
	}
	return out
}

// DumpState writes a comprehensive snapshot of the node's runtime state to the
// given writer. It includes routing table peers, active smux sessions (both
// client and server), and TUN routes/subnet proxies. This is primarily used
// by the SIGUSR1 signal handler for runtime diagnostics, but can also be
// called from tests or the web dashboard.
func (n *MeshNode) DumpState(w io.Writer) {
	// --- Routing table peers ---
	rt := n.RoutingTable()
	peers := rt.AllPeers()
	fmt.Fprintf(w, "=== Routing Table (%d peers) ===\n", len(peers))
	for _, p := range peers {
		fmt.Fprintf(w, "  peer %s  endpoint=%s  allowedIPs=%v\n", p.ID, p.Endpoint, p.AllowedIPs)
	}

	// --- Active smux sessions ---
	n.sessionsMu.Lock()
	fmt.Fprintf(w, "\n=== Sessions (server=%d, client=%d) ===\n", len(n.sessions), len(n.clientSessions))
	seen := make(map[string]bool)
	for peerID, sess := range n.clientSessions {
		seen[peerID] = true
		if sess == nil || sess.IsClosed() {
			fmt.Fprintf(w, "  [client] peer %s  CLOSED\n", peerID)
			continue
		}
		stats := sess.Stats()
		established := ""
		if t, ok := n.sessionEstablishedAt[peerID]; ok {
			established = t.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "  [client] peer %s  streams=%d  rx=%d  tx=%d  established=%s\n",
			peerID, sess.NumStreams(), stats.BytesReceived, stats.BytesSent, established)
	}
	for peerID, sess := range n.sessions {
		if seen[peerID] {
			continue
		}
		if sess == nil || sess.IsClosed() {
			fmt.Fprintf(w, "  [server] peer %s  CLOSED\n", peerID)
			continue
		}
		stats := sess.Stats()
		established := ""
		if t, ok := n.sessionEstablishedAt[peerID]; ok {
			established = t.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "  [server] peer %s  streams=%d  rx=%d  tx=%d  established=%s\n",
			peerID, sess.NumStreams(), stats.BytesReceived, stats.BytesSent, established)
	}
	n.sessionsMu.Unlock()

	// --- TUN routes ---
	if n.tunIntegration != nil {
		if n.tunIntegration.Router != nil {
			routes := n.tunIntegration.Router.AllRoutes()
			fmt.Fprintf(w, "\n=== TUN VirtualIP Routes (%d) ===\n", len(routes))
			for ip, pk := range routes {
				fmt.Fprintf(w, "  %s -> %s\n", ip, pk)
			}
		}
		if n.tunIntegration.RouteManager != nil {
			proxies := n.tunIntegration.RouteManager.AllSubnetProxies()
			fmt.Fprintf(w, "\n=== TUN Subnet Proxy Routes (%d) ===\n", len(proxies))
			for cidr, gw := range proxies {
				fmt.Fprintf(w, "  %s via %s\n", cidr, gw)
			}
		}
		if n.tunIntegration.VirtualIP != nil {
			fmt.Fprintf(w, "\n=== TUN Local VirtualIP ===\n  %s (iface=%s)\n",
				n.tunIntegration.VirtualIP, n.tunIntegration.IfName)
		}
	} else {
		fmt.Fprintf(w, "\n=== TUN: disabled ===\n")
	}

	// --- Relay handler ---
	if n.relayHandler != nil {
		fmt.Fprintf(w, "\n=== Relay: active (tunnels=%d) ===\n", n.relayHandler.TunnelCount())
		n.relayHandler.DumpTunnels(w)
	} else {
		fmt.Fprintf(w, "\n=== Relay: disabled ===\n")
	}
}

// MeshTrafficStats holds aggregated mesh traffic statistics for the local node.
// It sums traffic across all smux sessions, relay tunnels, and TUN forwarder.
type MeshTrafficStats struct {
	InBytes       uint64 // total inbound bytes across all smux sessions
	OutBytes      uint64 // total outbound bytes across all smux sessions
	SmuxStreams   int    // total active smux streams across all peer sessions
	RelayForwards int    // active relay tunnels (0 if relay not enabled)
	TunRxPackets  uint64 // TUN device received packets
	TunTxPackets  uint64 // TUN device sent packets
	PeerCount     int    // number of connected peer sessions
}

// TrafficStats aggregates traffic statistics from all subsystems:
// smux sessions, relay handler, and TUN forwarder.
func (n *MeshNode) TrafficStats() MeshTrafficStats {
	var stats MeshTrafficStats

	// Aggregate smux session stats.
	n.sessionsMu.Lock()
	// Collect from both sessions and clientSessions (dedup by peer ID, preferring client).
	seen := make(map[string]bool)
	for peerID, sess := range n.clientSessions {
		if sess == nil || sess.IsClosed() {
			continue
		}
		seen[peerID] = true
		s := sess.Stats()
		stats.InBytes += s.BytesReceived
		stats.OutBytes += s.BytesSent
		stats.SmuxStreams += sess.NumStreams()
		stats.PeerCount++
	}
	for peerID, sess := range n.sessions {
		if seen[peerID] {
			continue
		}
		if sess == nil || sess.IsClosed() {
			continue
		}
		s := sess.Stats()
		stats.InBytes += s.BytesReceived
		stats.OutBytes += s.BytesSent
		stats.SmuxStreams += sess.NumStreams()
		stats.PeerCount++
	}
	n.sessionsMu.Unlock()

	// Relay handler tunnel count.
	if n.relayHandler != nil {
		stats.RelayForwards = n.relayHandler.TunnelCount()
	}

	// TUN forwarder packet stats.
	if n.tunIntegration != nil && n.tunIntegration.Forwarder != nil {
		tunStats := n.tunIntegration.Forwarder.Stats()
		stats.TunRxPackets = tunStats.PacketsReceived
		stats.TunTxPackets = tunStats.PacketsSent
	}

	return stats
}

// Listener returns the active Reality TLS listener, or nil if not started.
func (n *MeshNode) Listener() net.Listener {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.listener
}

// Context returns the node's lifecycle context. It is cancelled when
// Close() is called, allowing background goroutines to terminate.
func (n *MeshNode) Context() context.Context {
	return n.ctx
}

// SetCollectorHandler installs a callback invoked when META exchange
// reveals a peer with Collector=true (dashboard aggregator). Mirrors
// the gossip CapCollector discovery for relay-attached nodes.
func (n *MeshNode) SetCollectorHandler(h func(string)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.collectorHandler = h
}

// SetLocalCollector marks this node as running the dashboard
// aggregator — advertised in META as Collector=true so every peer
// (including relay-attached ones) auto-discovers us as a metrics
// destination. When the flag flips on, a META broadcast is triggered
// so peers that connected earlier (before this node ran web mode)
// still learn the capability.
func (n *MeshNode) SetLocalCollector(on bool) {
	n.mu.Lock()
	changed := on && !n.localIsCollector
	n.localIsCollector = on
	b := n.metaBroadcaster
	n.mu.Unlock()
	if changed && b != nil {
		b()
	}
}

// SetMetaBroadcaster installs the META re-broadcast callback (the app
// layer wires it to MetaExchanger.Broadcast).
func (n *MeshNode) SetMetaBroadcaster(fn func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.metaBroadcaster = fn
}

// notifyCollectorDiscovered forwards a collector-capable peer to the
// installed handler (reporter.AddCollector), idempotent on the handler
// side, and records the capability so knownPeers() can flood it onward.
// Safe to call even with no handler installed.
func (n *MeshNode) notifyCollectorDiscovered(peerKey string) {
	if peerKey == "" {
		return
	}
	n.mu.Lock()
	changed := !n.collectorPeers[peerKey]
	n.collectorPeers[peerKey] = true
	h := n.collectorHandler
	b := n.metaBroadcaster
	n.mu.Unlock()
	log.Printf("[meta] collector discovered: %s (new=%v)", shortKey(peerKey), changed)
	if h != nil {
		h(peerKey)
	}
	// A newly learned collector must flood onward immediately: peers
	// that already exchanged meta with us would otherwise never learn
	// that this peer runs the dashboard.
	if changed && b != nil {
		log.Printf("[meta] collector changed — broadcasting meta to %d peer(s)", len(n.SessionPeerKeys()))
		b()
	}
}

// IsPeerCollector reports whether the peer is known to run the
// dashboard aggregator (learned via META/gossip collector discovery).
// Used by the meta exchanger to flood Collector=true onward.
func (n *MeshNode) IsPeerCollector(peerKey string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.collectorPeers[peerKey]
}

// localIsCollectorFlag reports whether this node advertises itself as
// a dashboard collector in META.
func (n *MeshNode) localIsCollectorFlag() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.localIsCollector
}

// SetLocalMetaExtras installs the provider of this node's own relay/NAT
// knowledge (Role/NatType/CapRelay/MaxCircuits/LoadCircuits) advertised
// in META — memberlist-retirement phase 1: these fields used to come
// from gossip NodeMeta exclusively.
func (n *MeshNode) SetLocalMetaExtras(provider func() MetaRelayInfo) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.metaExtrasProvider = provider
}

// localMetaExtras returns this node's relay/NAT knowledge for localMeta().
func (n *MeshNode) localMetaExtras() MetaRelayInfo {
	n.mu.RLock()
	p := n.metaExtrasProvider
	n.mu.RUnlock()
	if p == nil {
		return MetaRelayInfo{}
	}
	return p()
}

// RecordPeerRelayMeta stores relay/NAT knowledge about a peer learned
// from META (memberlist-retirement phase 1). Fields merge: a non-empty
// incoming field overwrites the stored one, an empty field keeps the
// stored value — so a partial update (e.g. a flood copy that lost the
// load numbers) never erases known knowledge.
func (n *MeshNode) RecordPeerRelayMeta(peerKey string, info MetaRelayInfo) {
	if peerKey == "" || info.empty() {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	cur := n.peerRelayMeta[peerKey]
	if info.Role != "" {
		cur.Role = info.Role
	}
	if info.NatType != "" {
		cur.NatType = info.NatType
	}
	if info.CapRelay {
		cur.CapRelay = true
	}
	if info.MaxCircuits > 0 {
		cur.MaxCircuits = info.MaxCircuits
	}
	if info.LoadCircuits > 0 {
		cur.LoadCircuits = info.LoadCircuits
	}
	n.peerRelayMeta[peerKey] = cur
}

// PeerRelayMetaInfo returns the relay/NAT knowledge about a peer learned
// via META (memberlist-retirement phase 1). ok=false when nothing is
// known.
func (n *MeshNode) PeerRelayMetaInfo(peerKey string) (MetaRelayInfo, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	info, ok := n.peerRelayMeta[peerKey]
	return info, ok
}

// SetSessionDeathHandler installs a callback that is invoked when a smux
// session with a peer dies (detected by the reconnect watcher). The argument
// is the peer's identity hex. This is used to clean up TUN routes and other
// session-dependent state when the peer is truly unreachable.
func (n *MeshNode) SetSessionDeathHandler(h func(string)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sessionDeathHandler = h
}

// SetSessionReconnectHandler installs a callback that is invoked after a
// smux session with a peer is successfully re-established by the reconnect
// watcher. The argument is the peer's identity hex. This is used to re-add
// TUN routes that were removed when the session died, since the peer stays
// in memberlist and no new NotifyJoin fires to trigger the normal join
// handler.
func (n *MeshNode) SetSessionReconnectHandler(h func(string)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sessionReconnectHandler = h
}

// SetPeerEndpointResolver installs a callback that resolves a peer's
// STABLE advertised endpoint by identity hex. main.go wires this to the
// gossip layer's KnownPeers (which carries advertise_endpoints). The
// reconnect watcher uses it to avoid dialing the ephemeral source port
// of a dead inbound session (a NAT mapping that no longer exists).
func (n *MeshNode) SetPeerEndpointResolver(f func(string) string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.peerEndpointResolver = f
}

// ACL returns the TUN ACL engine, or nil when ACL is not configured.
// The web Dashboard uses this to query stats and update rules at runtime.
func (n *MeshNode) ACL() *ACLEngine {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.aclEngine
}

// SetACLRulesBroadcaster registers a callback to propagate the local
// node's ACL rules to the gossip layer. main.go wires this to
// gossipLayer.SetLocalACLRules.
func (n *MeshNode) SetACLRulesBroadcaster(cb func([]string)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.aclRulesBroadcaster = cb
}

// aclRulesBroadcaster is a callback to propagate the local node's ACL
// rules to the gossip layer. Set by main.go.
func (n *MeshNode) aclRulesBroadcasterCB() func([]string) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.aclRulesBroadcaster
}

// BroadcastACLRules sends the local node's ACL rules to the gossip layer
// via the callback registered by main.go. This is called when ACL rules
// are updated at runtime via the Dashboard.
func (n *MeshNode) BroadcastACLRules(rules []string) {
	if cb := n.aclRulesBroadcasterCB(); cb != nil {
		cb(rules)
	}
}

// MuxTransport returns the shared TCP/UDP transport multiplexer, or nil
// when port multiplexing is not active (P2P disabled). The caller uses
// this to inject the transport into the gossip layer via SetTransport().
func (n *MeshNode) MuxTransport() *MuxTransport {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.muxTransport
}

// TunUDPListener returns a listener for inbound TUN-data UDP streams
// (multipath D). Each accepted conn carries framed TUN packets over the
// UDP ARQ layer. Returns nil when the mux transport is unavailable.
func (n *MeshNode) TunUDPListener() net.Listener {
	mt := n.MuxTransport()
	if mt == nil {
		return nil
	}
	return mt.TunUDPListener()
}

// DialTUNUDPForPeer opens (or reuses) the UDP ARQ TUN stream to a peer,
// resolving its stable endpoint via gossip/config/routing table. The
// first frame carries an Ed25519-signed auth header (pubkey + timestamp
// + signature) so the receiver can authenticate the UDP stream — this
// is what prevents unauthenticated UDP injection into the TUN.
// The returned conn is used by the tun-forwarder as the UDP-preferred
// data path (multipath D); on any error the caller falls back to TCP
// smux.
func (n *MeshNode) DialTUNUDPForPeer(peerKey string) (net.Conn, error) {
	mt := n.MuxTransport()
	if mt == nil {
		return nil, fmt.Errorf("mesh: mux transport unavailable")
	}
	ep := n.resolvePeerEndpoint(peerKey)
	if ep == "" {
		return nil, fmt.Errorf("mesh: no endpoint known for peer %s", shortKey(peerKey))
	}
	authHeader, err := n.buildTUNAuthHeader()
	if err != nil {
		return nil, err
	}
	sc, err := mt.DialTUNUDP(ep, authHeader)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

// buildTUNAuthHeader produces the first-frame auth payload for a TUN
// UDP stream: [pubkey 64][ts 10][sig 128] where sig = Ed25519(pubkey+ts).
func (n *MeshNode) buildTUNAuthHeader() ([]byte, error) {
	if n.identity == nil {
		return nil, fmt.Errorf("mesh: no identity for TUN UDP auth")
	}
	now := time.Now().Unix()
	pubKeyHex := n.identity.PublicKey
	tsStr := fmt.Sprintf("%010d", now)
	signedData := []byte(pubKeyHex + tsStr)
	sigHex, err := n.identity.Sign(signedData)
	if err != nil {
		return nil, fmt.Errorf("mesh: TUN UDP auth sign: %w", err)
	}
	if len(pubKeyHex) != 64 || len(sigHex) != 128 {
		return nil, fmt.Errorf("mesh: unexpected key/sig lengths %d/%d", len(pubKeyHex), len(sigHex))
	}
	header := make([]byte, 0, tunUDPAuthLen)
	header = append(header, pubKeyHex...)
	header = append(header, tsStr...)
	header = append(header, sigHex...)
	return header, nil
}

// wireTUNAUDAuthValidator installs the UDP TUN stream authenticator:
// the pubkey must be a known peer and the Ed25519 signature over
// (pubkey+ts) must verify.
func (n *MeshNode) wireTUNAUDAuthValidator() {
	mt := n.MuxTransport()
	if mt == nil {
		return
	}
	mt.udpMesh.SetTUNUDPAuthValidator(func(pubKeyHex string, data []byte, sigHex string) (string, bool) {
		// The key must be a peer we have a session with (or know via
		// config/routing) — refuse strangers.
		if !n.isKnownPeer(pubKeyHex) {
			return "", false
		}
		if !identity.Verify(pubKeyHex, data, sigHex) {
			return "", false
		}
		return pubKeyHex, true
	})
}

// isKnownPeer reports whether the public key belongs to a peer we have
// (or have had) a session with, or is in the static config.
func (n *MeshNode) isKnownPeer(pubKeyHex string) bool {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()
	if _, ok := n.sessions[pubKeyHex]; ok {
		return true
	}
	if _, ok := n.clientSessions[pubKeyHex]; ok {
		return true
	}
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()
	for i := range n.cfg.Peers {
		if n.cfg.Peers[i].PublicKey == pubKeyHex {
			return true
		}
	}
	if entry, ok := n.routes.GetPeer(pubKeyHex); ok && entry.Endpoint != "" {
		return true
	}
	return false
}

// Identity returns this node's Ed25519 identity.
func (n *MeshNode) Identity() *identity.Identity {
	return n.identity
}

// RoutingTable returns the routing table for peer lookups.
func (n *MeshNode) RoutingTable() *RoutingTable {
	return n.routes
}

// Registry returns the TransportRegistry used by this node.
func (n *MeshNode) Registry() *TransportRegistry {
	return n.registry
}

// Dial opens a cryptographically secure stream to a peer.
//
// It performs the full client-side protocol handshake:
//  1. Looks up the peer's Reality TLS config by address.
//  2. Dials the peer via Reality TLS (Layer 1).
//  3. Performs X25519 ECDH key exchange (Layer 2a).
//  4. Wraps the connection in AES-256-GCM SecureConn (Layer 2b).
//  5. Creates an smux client session (Layer 3).
//  6. Opens a stream and returns it as a net.Conn.
//
// The returned net.Conn is an authenticated, encrypted, multiplexed stream.
// Multiple streams can share one underlying session via subsequent calls to
// Dial with the same address.
//
// network is the transport type ("tcp", "tcp4", "tcp6" — all mapped to TCP).
// address is "host:port" and must match a configured peer's Endpoint field.
func (n *MeshNode) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	// Check for mesh-internal virtual port address (e.g. "mesh:2222").
	if network == "mesh" || isMeshAddress(address) {
		return n.dialVirtualPort(ctx, address)
	}

	// 1. Find the peer's Reality config by address.
	peerCfg, ok := n.findPeerConfigByAddress(address)
	if !ok {
		return nil, fmt.Errorf("mesh: no peer configured at address %s", address)
	}
	if peerCfg.Reality == nil {
		return nil, fmt.Errorf("mesh: peer at %s has no Reality TLS configuration (required for v2)", address)
	}

	// 2. Build a client-side Reality handshake config from the peer config.
	hsCfg := handshake.HandshakeConfig{
		DialTimeout:      30 * time.Second,
		TLSFingerprint:   "chrome",
		RealityPublicKey: peerCfg.Reality.PublicKey,
		RealityShortID:   peerCfg.Reality.ShortID,
		ServerName:       peerCfg.Reality.ServerName,
	}
	if peerCfg.Reality.TLSFingerprint != "" {
		hsCfg.TLSFingerprint = peerCfg.Reality.TLSFingerprint
	}

	// 3. Dial the peer's Reality TLS address (Layer 1).
	hs := handshake.NewRealityHandshake(hsCfg)
	conn, err := hs.Connect(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("mesh: dial %s: %w", address, err)
	}

	// 4. Set a deadline for the key exchange (Layer 2a).
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 5. Perform X25519 ECDH key exchange (client/initiator side).
	keys, peerIdentityHex, err := session.ClientKeyExchange(conn, n.identity)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mesh: key exchange with %s: %w", address, err)
	}

	// 6. Clear the deadline — the secure channel manages its own timeouts.
	conn.SetDeadline(time.Time{})

	log.Printf("[mesh] key exchange complete with %s (peer=%s)", address, peerIdentityHex[:16]+"...")

	// 7. Wrap in AES-256-GCM SecureConn (Layer 2b).
	secureConn, err := crypto.NewSecureConn(conn, keys.SendKey[:], keys.RecvKey[:])
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mesh: create SecureConn with %s: %w", address, err)
	}

	// 8. Create smux client session (Layer 3).
	smuxSession, err := smux.Client(secureConn, smuxCfg())
	if err != nil {
		secureConn.Close()
		return nil, fmt.Errorf("mesh: smux handshake with %s: %w", address, err)
	}

	// 9. Store the session keyed by peer identity.
	//    If the same peer reconnected via Dial, close the old session.
	n.sessionsMu.Lock()
	oldSession, exists := n.sessions[peerIdentityHex]
	n.sessions[peerIdentityHex] = smuxSession
	n.clientSessions[peerIdentityHex] = smuxSession // client session for DialVirtualPort
	n.peerTransport[peerIdentityHex] = "reality"
	n.sessionEstablishedAt[peerIdentityHex] = time.Now()
	n.sessionsMu.Unlock()

	if exists {
		log.Printf("[mesh] peer %s reconnected via Dial — closing old session", peerIdentityHex[:16]+"...")
		oldSession.Close()
	}

	log.Printf("[mesh] session established with %s (peer=%s)", address, peerIdentityHex[:16]+"...")
	n.fireSessionEstablished(peerIdentityHex)

	// 10. Add/update the peer in the routing table.
	n.routes.AddPeer(&PeerEntry{
		ID:       peerIdentityHex,
		Endpoint: address,
	})

	// 11. Open a stream on the session and return it.
	stream, err := smuxSession.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("mesh: open stream to %s: %w", address, err)
	}

	// 12. Write the virtual port prefix. For regular (non-mesh) dials,
	// use port 0 — handleSessionStreams will close the stream if no
	// listener is registered for port 0.
	if err := writePortFrame(stream, 0); err != nil {
		stream.Close()
		return nil, fmt.Errorf("mesh: write port frame to %s: %w", address, err)
	}

	// Start the stream accept loop for this outbound client session.
	// Without it, the peer cannot open inbound streams on our session
	// (e.g. relay dials to this node's 0x524C/0x5350 virtual ports) —
	// they'd hit EOF. Inbound (server) sessions get this in
	// handleConnection; client sessions need it here too.
	go n.handleSessionStreams(peerIdentityHex, smuxSession)

	// Start auto-reconnect watcher for this outbound client session.
	n.startSessionWatcher(peerIdentityHex, address, true)

	return stream, nil
}

// DialUDPPeer dials a peer over the UDP data plane (T0.3). It opens a
// reliable ARQ stream, sends the 0x4D marker, then runs the standard
// v2 stack: X25519 ECDH → SecureConn → smux session. Used by the
// hole-punch direct path. Falls back to TCP DialPeerByEndpoint when the
// UDP stream cannot be established.
func (n *MeshNode) DialUDPPeer(ctx context.Context, address string) (net.Conn, error) {
	mt := n.MuxTransport()
	if mt == nil {
		return nil, fmt.Errorf("mesh: no mux transport for UDP dial")
	}
	sc, err := mt.DialUDP(address)
	if err != nil {
		return nil, fmt.Errorf("mesh: udp dial %s: %w", address, err)
	}

	// DialUDP already sent the 0x4D marker frame; the stream is ready
	// for key exchange.
	sc.SetDeadline(time.Now().Add(30 * time.Second))

	keys, peerIdentityHex, err := session.ClientKeyExchange(sc, n.identity)
	if err != nil {
		sc.Close()
		return nil, fmt.Errorf("mesh: udp key exchange with %s: %w", address, err)
	}
	sc.SetDeadline(time.Time{})

	log.Printf("[mesh] udp key exchange complete with %s (peer=%s)", address, peerIdentityHex[:16]+"...")

	secureConn, err := crypto.NewSecureConn(sc, keys.SendKey[:], keys.RecvKey[:])
	if err != nil {
		sc.Close()
		return nil, fmt.Errorf("mesh: udp create SecureConn with %s: %w", address, err)
	}

	smuxSession, err := smux.Client(secureConn, smuxCfgUDP())
	if err != nil {
		secureConn.Close()
		return nil, fmt.Errorf("mesh: udp smux handshake with %s: %w", address, err)
	}

	n.sessionsMu.Lock()
	oldSession, exists := n.sessions[peerIdentityHex]
	n.sessions[peerIdentityHex] = smuxSession
	n.clientSessions[peerIdentityHex] = smuxSession
	n.peerTransport[peerIdentityHex] = "udp"
	n.sessionEstablishedAt[peerIdentityHex] = time.Now()
	n.sessionsMu.Unlock()

	if exists {
		oldSession.Close()
	}

	log.Printf("[mesh] udp session established with %s (peer=%s)", address, peerIdentityHex[:16]+"...")
	n.fireSessionEstablished(peerIdentityHex)

	n.routes.AddPeer(&PeerEntry{
		ID:       peerIdentityHex,
		Endpoint: address,
	})
	go n.handleSessionStreams(peerIdentityHex, smuxSession)
	n.startSessionWatcher(peerIdentityHex, address, true)

	stream, err := smuxSession.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("mesh: udp open stream to %s: %w", address, err)
	}
	if err := writePortFrame(stream, 0); err != nil {
		stream.Close()
		return nil, fmt.Errorf("mesh: udp write port frame to %s: %w", address, err)
	}
	return stream, nil
}

// smuxCfgUDP returns the smux config for sessions carried over a UDP
// hole. Keepalive pings are DISABLED here: on a UDP-hole session the
// ARQ layer (udpStreamConn) already keeps the path alive with its own
// retransmit/probe machinery, and the smux ping frames would queue
// BEHIND bulk data in the ARQ window — a busy TUN stream starves the
// pings, the peer's PingTimeout (90s) fires while data is still
// flowing, and the session dies mid-transfer (observed: scp over the
// txcloud↔AMD hole aborted at ~780KB with "keepalive timeout —
// session dead (no frames for 1m30s)").
func smuxCfgUDP() smux.Config {
	cfg := smux.DefaultConfig()
	cfg.PingInterval = 0 // disabled — ARQ keeps the path alive
	cfg.MaxFrameSize = 16384
	return cfg
}

// smuxCfg returns the smux config with keepalive enabled. The
// keepalive pings + timeout detect TCP half-closes (FIN-WAIT-2 /
// CLOSE-WAIT) that would otherwise leave session reads blocked
// forever with IsClosed() false — the root cause of zombie sessions
// that silently break direct paths until a dial attempts cleanup.
func smuxCfg() smux.Config {
	cfg := smux.DefaultConfig()
	cfg.PingInterval = 30 * time.Second
	cfg.PingTimeout = 90 * time.Second
	// Frame size: 16KB (default) is the reliable choice on lossy
	// high-latency links — 32KB+ frames abort mid-transfer over both
	// the 0x4D and Reality paths through the link's middleboxes.
	cfg.MaxFrameSize = 16384
	return cfg
}

// findPeerConfigByAddress searches the node's config Peers list for a
// peer whose Endpoint matches the given address (host:port).
// Returns a COPY — callers must not retain a pointer into the shared
// slice (AddPeer may append concurrently, reallocating the backing array).
func (n *MeshNode) findPeerConfigByAddress(address string) (*config.PeerConfig, bool) {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()
	for i := range n.cfg.Peers {
		if n.cfg.Peers[i].Endpoint == address {
			pc := n.cfg.Peers[i]
			return &pc, true
		}
	}
	return nil, false
}

// DialPeerByEndpoint dials a gossip-discovered peer by its endpoint address.
// Unlike Dial(), this method does NOT require a Reality client config — it
// sends the mesh-internal marker byte (0x4D) to tell the remote MuxTransport
// to route the connection to the mesh-internal path (bypassing Reality TLS).
// It then performs the v2 protocol stack: X25519 ECDH key exchange →
// AES-256-GCM SecureConn → smux session.
func (n *MeshNode) DialPeerByEndpoint(ctx context.Context, address string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("mesh: dial %s: %w", address, err)
	}

	// Send the mesh-internal marker byte. The remote MuxTransport will
	// peek this byte and route the connection to the mesh-internal path.
	_, err = conn.Write([]byte{meshInternalMarker})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mesh: send marker to %s: %w", address, err)
	}

	// Set deadline for key exchange.
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Perform client-side X25519 ECDH key exchange (Layer 2a).
	keys, peerIdentityHex, err := session.ClientKeyExchange(conn, n.identity)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mesh: key exchange with %s: %w", address, err)
	}

	// Clear deadline.
	conn.SetDeadline(time.Time{})

	log.Printf("[mesh] key exchange complete with %s (peer=%s)", address, peerIdentityHex[:16]+"...")

	// Wrap in AES-256-GCM SecureConn (Layer 2b).
	secureConn, err := crypto.NewSecureConn(conn, keys.SendKey[:], keys.RecvKey[:])
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mesh: create SecureConn with %s: %w", address, err)
	}

	// Create smux client session (Layer 3).
	smuxSession, err := smux.Client(secureConn, smuxCfg())
	if err != nil {
		secureConn.Close()
		return nil, fmt.Errorf("mesh: smux handshake with %s: %w", address, err)
	}

	// Store the session.
	n.sessionsMu.Lock()
	oldSession, exists := n.sessions[peerIdentityHex]
	n.sessions[peerIdentityHex] = smuxSession
	n.clientSessions[peerIdentityHex] = smuxSession
	n.peerTransport[peerIdentityHex] = "0x4d"
	n.peerTransport[peerIdentityHex] = "udp"
	n.sessionEstablishedAt[peerIdentityHex] = time.Now()
	n.sessionsMu.Unlock()

	if exists {
		oldSession.Close()
	}

	log.Printf("[mesh] session established with %s (peer=%s, addr=%s)", address, peerIdentityHex[:16]+"...", address)
	n.fireSessionEstablished(peerIdentityHex)

	n.routes.AddPeer(&PeerEntry{
		ID:       peerIdentityHex,
		Endpoint: address,
	})

	// Start the session stream handler so inbound streams from the peer
	// (e.g. reverse-pushed metrics from a shared node) are dispatched to
	// the correct virtual port listener.
	go n.handleSessionStreams(peerIdentityHex, smuxSession)

	// Open a stream on the session.
	stream, err := smuxSession.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("mesh: open stream to %s: %w", address, err)
	}

	// Write virtual port 0 (placeholder — caller will close this stream
	// if they only needed the session).
	if err := writePortFrame(stream, 0); err != nil {
		stream.Close()
		return nil, fmt.Errorf("mesh: write port frame to %s: %w", address, err)
	}

	// Start auto-reconnect watcher for this outbound client session.
	n.startSessionWatcher(peerIdentityHex, address, true)

	return stream, nil
}

// isMeshAddress returns true if the address is a mesh-internal virtual
// port address of the form "mesh:PORT" or "mesh://PORT".
func isMeshAddress(address string) bool {
	return len(address) > 5 && address[:5] == "mesh:"
}

// parseMeshPort extracts the port number from a mesh address like "mesh:2222".
func parseMeshPort(address string) (uint16, error) {
	if !isMeshAddress(address) {
		return 0, fmt.Errorf("not a mesh address: %s", address)
	}
	portStr := address[5:]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid mesh port %q: %w", portStr, err)
	}
	if port == 0 {
		return 0, fmt.Errorf("mesh port 0 is reserved")
	}
	return uint16(port), nil
}

// ListenVirtualPort registers a virtual listener for the given port number
// and returns a net.Listener that accepts inbound smux streams addressed
// to that port.
//
// The caller is responsible for calling Close on the returned listener
// when done. If a listener is already registered for the port, an error
// is returned.
func (n *MeshNode) ListenVirtualPort(port int) (net.Listener, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("mesh: virtual port %d out of range", port)
	}
	return n.portMux.register(uint16(port))
}

// DialLocalVirtualPort dials a virtual port listener registered on this
// node (i.e. locally, without going over a smux session). It creates a
// net.Pipe, dispatches one end to the local portMux as if it were an
// inbound stream, and returns the other end to the caller.
//
// This is the production wiring point for relay OnRelayDial callbacks:
// when a relay node forwards a dial request to this node, the OnRelayDial
// callback calls DialLocalVirtualPort to reach the local service
// listening on the target port (e.g. collector 0x105F, TUN 0x4D, SOCKS5
// 0x5350), then bridges the relay stream to the local stream with
// bidirectional io.Copy.
//
// peerID is the mesh identity of the peer that initiated the relay
// request (used for authorization in the portMux dispatch wrapper).
// If empty, the dispatch uses an empty peerID (non-mesh source).
func (n *MeshNode) DialLocalVirtualPort(port int, peerID string) (net.Conn, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("mesh: virtual port %d out of range", port)
	}
	if port == 0 {
		return nil, fmt.Errorf("mesh: virtual port 0 is reserved")
	}

	// Check that a listener is actually registered for this port.
	n.portMux.mu.RLock()
	_, exists := n.portMux.listeners[uint16(port)]
	n.portMux.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("mesh: no listener registered for local virtual port %d", port)
	}

	// Create a pipe: the "remote" end is dispatched to the local listener,
	// the "local" end is returned to the caller.
	localConn, remoteConn := net.Pipe()

	// Dispatch the remote end to the local port mux. This is synchronous
	// (non-blocking via the acceptCh buffer), so the listener's Accept()
	// will pick it up.
	n.portMux.dispatch(uint16(port), remoteConn, peerID)

	return localConn, nil
}

// DialVirtualPort opens a smux stream to a peer's virtual port.
//
// peerIdentityHex identifies the peer (the key in the sessions map).
// port is the virtual port to dial (must be > 0).
//
// The first frame written on the stream carries the 2-byte port number,
// which the remote side reads to dispatch to the correct VirtualListener.
func (n *MeshNode) DialVirtualPort(ctx context.Context, peerIdentityHex string, port int) (net.Conn, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("mesh: virtual port %d out of range", port)
	}
	if port == 0 {
		return nil, fmt.Errorf("mesh: virtual port 0 is reserved")
	}

	// Look up the smux session for this peer.
	// Prefer client-mode sessions (outbound) for dialing, but also
	// accept server-mode sessions now that smux supports OpenStream
	// on both sides (enables ordinary nodes without public listeners).
	// Skip dead (closed) sessions — a dead session in the map will
	// cause OpenStream to fail immediately, wasting time and blocking
	// the relay fallback path.
	n.sessionsMu.Lock()
	sess, ok := n.clientSessions[peerIdentityHex]
	if !ok || sess.IsClosed() {
		sess, ok = n.sessions[peerIdentityHex]
		if ok && sess.IsClosed() {
			// Clean up the dead session entry.
			delete(n.sessions, peerIdentityHex)
			ok = false
		}
	}
	if !ok {
		// Also check if there's a dead client session to clean up.
		if cs, csOK := n.clientSessions[peerIdentityHex]; csOK && cs.IsClosed() {
			delete(n.clientSessions, peerIdentityHex)
		}
	}
	n.sessionsMu.Unlock()

	if !ok {
		// No direct session — try relay fallback if relay-capable
		// peers are known. This enables cross-network-family
		// communication (e.g. IPv4-only → IPv6-only) through a
		// dual-stack relay node.
		if conn, relayErr := n.tryRelayFallback(ctx, peerIdentityHex, uint16(port), nil); relayErr == nil {
			return conn, nil
		} else {
			log.Printf("[mesh] DialVirtualPort: relay fallback for peer %s failed: %v",
				peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...", relayErr)
		}

		// Log available sessions for debugging.
		n.sessionsMu.Lock()
		var keys []string
		for k := range n.sessions {
			keys = append(keys, k[:min(len(k), 16)]+"...")
		}
		for k := range n.clientSessions {
			keys = append(keys, k[:min(len(k), 16)]+"...(client)")
		}
		n.sessionsMu.Unlock()
		log.Printf("[mesh] DialVirtualPort: no session for peer %s (have: %v)", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...", keys)
		return nil, fmt.Errorf("mesh: no session for peer %s", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...")
	}

	// Multi-path selection: even with a direct session, a relay path may
	// have lower total latency (e.g. direct cross-zone Reality vs a
	// same-zone relay hop). Evaluate cheaply (direct RTT heuristic) and
	// prefer the relay when it is likely faster; fall back to direct on
	// failure. Never for the ping port — PeerRTT dials it and would
	// recurse infinitely.
	if port != PingVirtualPort {
		if conn, ok := n.tryFasterRelayPath(ctx, peerIdentityHex, uint16(port)); ok {
			return conn, nil
		}
	}

	// Try to open a stream on the existing session.
	// If the client session is closed, attempt to re-establish it by
	// dialing the peer's configured endpoint.
	stream, err := sess.OpenStream(ctx)
	if err != nil {
		// Try to re-establish an outbound client session.
		// Look up the peer's configured endpoint (not the routing table
		// entry, which may contain an ephemeral source address from an
		// inbound connection).
		var dialAddr string
		n.peersMu.RLock()
		for i := range n.cfg.Peers {
			if n.cfg.Peers[i].PublicKey == peerIdentityHex {
				dialAddr = n.cfg.Peers[i].Endpoint
				break
			}
		}
		n.peersMu.RUnlock()
		if dialAddr == "" {
			// Fall back to routing table endpoint.
			entry, rtOK := n.routes.GetPeer(peerIdentityHex)
			if rtOK && entry.Endpoint != "" {
				dialAddr = entry.Endpoint
			}
		}
		if dialAddr != "" {
			log.Printf("[mesh] DialVirtualPort: session closed, re-dialing peer %s at %s", peerIdentityHex[:16]+"...", dialAddr)

			// First try Dial (requires Reality client config).
			newStream, dialErr := n.Dial(ctx, "tcp", dialAddr)
			if dialErr != nil {
				// Dial failed (likely no Reality client config for
				// gossip-discovered peer). Fall back to
				// dialPeerByEndpoint which uses the mesh-internal
				// marker byte (0x4D) to bypass Reality TLS.
				meshStream, meshErr := n.DialPeerByEndpoint(ctx, dialAddr)
				if meshErr != nil {
					return nil, fmt.Errorf("mesh: open stream to peer %s: %w (re-dial also failed: %v)", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...", err, meshErr)
				}
				// dialPeerByEndpoint already wrote port 0.
				// Close that stream and open a new one with the
				// correct port.
				meshStream.Close()
				n.sessionsMu.Lock()
				newSess, hasNew := n.clientSessions[peerIdentityHex]
				n.sessionsMu.Unlock()
				if hasNew {
					stream, err = newSess.OpenStream(ctx)
					if err != nil {
						return nil, fmt.Errorf("mesh: open stream to peer %s after mesh dial: %w", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...", err)
					}
				} else {
					return nil, fmt.Errorf("mesh: open stream to peer %s: mesh dial did not store session", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...")
				}
			} else {
				// Dial succeeded — it wrote port 0. Close the
				// initial stream and open a new one with the
				// correct port.
				newStream.Close()
				n.sessionsMu.Lock()
				newSess, hasNew := n.clientSessions[peerIdentityHex]
				n.sessionsMu.Unlock()
				if hasNew {
					stream, err = newSess.OpenStream(ctx)
					if err != nil {
						return nil, fmt.Errorf("mesh: open stream to peer %s after re-dial: %w", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...", err)
					}
				} else {
					return nil, fmt.Errorf("mesh: open stream to peer %s: %w (re-dial failed to store session)", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...", err)
				}
			}
		} else {
			// No known endpoint to re-dial. The session is likely dead
			// (TCP half-close that smux hasn't detected — IsClosed stays
			// false while reads block on the half-closed conn). Clean it
			// up so subsequent dials don't keep finding the zombie, then
			// try the relay fallback path (the target may be reachable
			// via a relay even when the direct session is gone).
			log.Printf("[mesh] DialVirtualPort: cleaning zombie session for peer %s (open stream: %v)", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...", err)
			n.sessionsMu.Lock()
			if s, ok := n.clientSessions[peerIdentityHex]; ok {
				delete(n.clientSessions, peerIdentityHex)
				if !s.IsClosed() {
					s.Close()
				}
			}
			if s, ok := n.sessions[peerIdentityHex]; ok {
				delete(n.sessions, peerIdentityHex)
				if !s.IsClosed() {
					s.Close()
				}
			}
			n.sessionsMu.Unlock()

			if conn, relayErr := n.tryRelayFallback(ctx, peerIdentityHex, uint16(port), nil); relayErr == nil {
				log.Printf("[mesh] DialVirtualPort: zombie session cleaned, relay fallback for peer %s succeeded", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...")
				return conn, nil
			}
			return nil, fmt.Errorf("mesh: open stream to peer %s: %w (no endpoint to re-dial, relay fallback failed)", peerIdentityHex[:min(len(peerIdentityHex), 16)]+"...", err)
		}
	}

	// Write the virtual port prefix.
	if err := writePortFrame(stream, uint16(port)); err != nil {
		stream.Close()
		return nil, fmt.Errorf("mesh: write port frame: %w", err)
	}

	return stream, nil
}

// dialVirtualPort handles mesh-internal dialing for addresses like "mesh:2222".
// It finds any active peer session and opens a stream to the virtual port.
// This is used for testing and simple scenarios; production code should use
// DialVirtualPort with an explicit peer identity.
func (n *MeshNode) dialVirtualPort(ctx context.Context, address string) (net.Conn, error) {
	port, err := parseMeshPort(address)
	if err != nil {
		return nil, err
	}

	// Find any active session (for testing / simple mesh dial).
	n.sessionsMu.Lock()
	var peerID string
	var sess *smux.Session
	for id, s := range n.sessions {
		peerID = id
		sess = s
		break
	}
	n.sessionsMu.Unlock()

	if sess == nil {
		return nil, fmt.Errorf("mesh: no active peer session for dial to %s", address)
	}

	return n.DialVirtualPort(ctx, peerID, int(port))
}

// AddPeer adds a new peer to the mesh and, when Reality TLS parameters
// are configured, establishes a persistent secure mesh connection.
//
// When the peer config includes Reality TLS parameters and a non-empty
// Endpoint (the v2 path), AddPeer initiates the full protocol handshake
// (Reality TLS → X25519 ECDH key exchange → AES-256-GCM SecureConn →
// smux session), stores the resulting session in the node's session map,
// and registers the peer in the routing table.
//
// When Reality is not configured (routing-table-only mode), the
// peer is registered in the routing table only. This is a valid
// operational mode for gossip-discovered peers that don't need
// Reality TLS (e.g., same-LAN peers).
func (n *MeshNode) AddPeer(cfg config.PeerConfig) error {
	// v2 path: Reality TLS enabled — establish a persistent secure connection.
	if cfg.Reality != nil && cfg.Endpoint != "" {
		return n.addPeerWithConnection(cfg)
	}

	// Plain peer (no Reality block): dial via the mesh-internal 0x4D
	// path to establish a persistent session. This is the fallback for
	// NAT'd / mixed-family topologies where gossip auto-connect never
	// fires (memberlist degraded) — a static peer entry is a reliable
	// connect target.
	if cfg.Endpoint != "" {
		ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
		stream, err := n.DialPeerByEndpoint(ctx, cfg.Endpoint)
		cancel()
		if err == nil {
			stream.Close() // persistent session lives on in n.sessions
			log.Printf("[mesh] AddPeer: 0x4D session established with %s (%s)", cfg.Endpoint, cfg.PublicKey[:min(len(cfg.PublicKey), 16)]+"...")
		} else {
			log.Printf("[mesh] AddPeer: 0x4D dial to %s failed: %v", cfg.Endpoint, err)
		}
	}

	// Routing table entry regardless (gossip/routing still benefit).
	entry := &PeerEntry{
		ID:         cfg.PublicKey,
		Endpoint:   cfg.Endpoint,
		AllowedIPs: cfg.AllowedIPs,
	}
	n.routes.AddPeer(entry)
	return nil
}

// addPeerWithConnection establishes a persistent secure mesh connection
// to a peer with Reality TLS configuration by calling Dial.
//
// Dial handles the full v2 protocol handshake and already stores the
// resulting smux session (keyed by the peer's verified identity hex)
// and adds the peer to the routing table. AddPeer only ensures the peer
// config is discoverable by Dial's address lookup, then closes the
// returned stream — the session persists independently.
func (n *MeshNode) addPeerWithConnection(cfg config.PeerConfig) error {
	// Ensure the peer config is available for Dial's address lookup.
	if !n.hasPeerConfigByAddress(cfg.Endpoint) {
		n.peersMu.Lock()
		n.cfg.Peers = append(n.cfg.Peers, cfg)
		n.peersMu.Unlock()
		log.Printf("[mesh] AddPeer: registered peer config for %s", cfg.Endpoint)
	}

	// Dial performs the full v2 handshake: Reality TLS → key exchange →
	// SecureConn → smux session creation → session storage → routing table.
	ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
	defer cancel()

	stream, err := n.Dial(ctx, "tcp", cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("mesh: add peer %s (%s): %w",
			cfg.PublicKey[:min(len(cfg.PublicKey), 16)]+"...", cfg.Endpoint, err)
	}

	// Close the stream — AddPeer establishes the persistent session;
	// the caller does not need a data stream right now. The smux session
	// lives on in n.sessions and streams can be opened later via Dial.
	stream.Close()

	log.Printf("[mesh] AddPeer: persistent session established with %s (%s)",
		cfg.PublicKey[:min(len(cfg.PublicKey), 16)]+"...", cfg.Endpoint)

	return nil
}

// hasPeerConfigByAddress checks whether a peer config with the given
// endpoint address exists in the node's config peer list.
func (n *MeshNode) hasPeerConfigByAddress(address string) bool {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()
	for i := range n.cfg.Peers {
		if n.cfg.Peers[i].Endpoint == address {
			return true
		}
	}
	return false
}

// RemovePeer removes a peer from the mesh.
// It performs full cleanup:
//   - Closes the smux session (if any) for the peer
//   - Stops the PeerManager (if any) for the peer
//   - Removes the peer from the sessions map and sessionEstablishedAt map
//   - Removes the peer from the routing table
//
// This is safe to call even if the peer was never fully connected.
func (n *MeshNode) RemovePeer(peerKey string) error {
	// 0. Stop the auto-reconnect watcher for this peer (if active).
	n.stopReconnectWatcher(peerKey)

	// 1. Close and remove the smux session.
	n.sessionsMu.Lock()
	sess, ok := n.sessions[peerKey]
	if ok {
		sess.Close()
		delete(n.sessions, peerKey)
	}
	// Also clean up clientSessions — a stale client session left in the
	// map causes DialVirtualPort to find a dead session and fail with
	// ErrSessionClosed or ErrMaxStreams (if the session is in a
	// half-dead state where Close was never called on individual streams).
	// This was the root cause of scenario 3's metrics failover failure:
	// after the relay node was killed, the client session to the remaining
	// collector was via the dead relay. RemovePeer on the relay didn't
	// clean up the client session, so DialVirtualPort kept finding and
	// failing on it instead of establishing a new direct session.
	clientSess, hasClient := n.clientSessions[peerKey]
	if hasClient {
		clientSess.Close()
		delete(n.clientSessions, peerKey)
	}
	delete(n.sessionEstablishedAt, peerKey)
	n.sessionsMu.Unlock()

	// 2. Stop and remove the PeerManager (if outbound).
	n.peerManagersMu.Lock()
	pm, ok := n.peerManagers[peerKey]
	if ok {
		pm.Stop()
		delete(n.peerManagers, peerKey)
	}
	n.peerManagersMu.Unlock()

	// 3. Remove from the routing table.
	n.routes.RemovePeer(peerKey)

	if ok || pm != nil {
		log.Printf("[mesh] RemovePeer: cleaned up peer %s (session=%v, peerMgr=%v)",
			peerKey[:min(len(peerKey), 16)]+"...", sess != nil, pm != nil)
	}

	return nil
}

// CleanupDeadSessions removes any closed (dead) smux sessions for the
// given peer from both the sessions and clientSessions maps. Live
// sessions are preserved. This is called from WireGuardDelegate.Disconnect
// to immediately clean up dead sessions when a peer leaves the mesh,
// without waiting for the session watcher to detect them via TCP timeout.
//
// This is safe to call even if the peer has no sessions or was never
// connected.
func (n *MeshNode) CleanupDeadSessions(peerKey string) {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()

	removed := 0
	if sess, ok := n.sessions[peerKey]; ok && sess.IsClosed() {
		delete(n.sessions, peerKey)
		removed++
	}
	if sess, ok := n.clientSessions[peerKey]; ok && sess.IsClosed() {
		delete(n.clientSessions, peerKey)
		removed++
	}
	if removed > 0 {
		delete(n.sessionEstablishedAt, peerKey)
		log.Printf("[mesh] cleanupDeadSessions: removed %d dead session(s) for peer %s",
			removed, peerKey[:min(len(peerKey), 16)]+"...")
	}
}

// GenerateIdentity creates a new Ed25519 keypair for the mesh.
func GenerateIdentity() (*identity.Identity, error) {
	return identity.GenerateIdentity()
}

// loadOrCreateIdentity loads an Ed25519 identity from the PEM identity file
// (cfg.Node.IdentityFile), or generates a new one if the file doesn't exist.
//
// Identity is persisted as a PEM file with 0600 permissions, NOT as a hex
// private key in the YAML config. Only the public key fingerprint is stored
// in cfg.Node.Fingerprint for reference.
//
// Backward compatibility: if cfg.Node.Identity (deprecated hex private key)
// is set and the PEM file doesn't exist, the key is migrated to PEM format
// and cfg.Node.Identity is cleared.
func loadOrCreateIdentity(cfg *config.Config) (*identity.Identity, error) {
	identityFile := cfg.Node.IdentityFile
	if identityFile == "" {
		identityFile = config.DefaultIdentityFile
	}

	// Try loading from PEM file first.
	pemData, err := os.ReadFile(identityFile)
	if err == nil && len(pemData) > 0 {
		// PEM file exists — load identity from it.
		id, err := identity.IdentityFromPEM(pemData)
		if err != nil {
			return nil, fmt.Errorf("load identity from PEM %s: %w", identityFile, err)
		}
		cfg.Node.Fingerprint = id.PublicKey
		cfg.Node.IdentityFile = identityFile
		// Clear deprecated hex key if it's still set (migration complete).
		cfg.Node.Identity = ""
		return id, nil
	}

	// PEM file doesn't exist or is empty.
	// Check for backward-compat migration from deprecated hex key.
	if cfg.Node.Identity != "" {
		id, err := identity.IdentityFromHex(cfg.Node.Identity)
		if err != nil {
			return nil, fmt.Errorf("load identity from deprecated hex: %w", err)
		}
		// Migrate: write PEM file, clear hex key from config.
		if err := saveIdentityPEM(identityFile, id); err != nil {
			return nil, fmt.Errorf("migrate identity to PEM %s: %w", identityFile, err)
		}
		log.Printf("Migrated identity from config.yaml to %s", identityFile)
		cfg.Node.Fingerprint = id.PublicKey
		cfg.Node.IdentityFile = identityFile
		cfg.Node.Identity = "" // Clear deprecated hex key.
		return id, nil
	}

	// No existing identity — generate a new one.
	id, err := identity.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	// Persist to PEM file.
	if err := saveIdentityPEM(identityFile, id); err != nil {
		return nil, fmt.Errorf("save identity PEM %s: %w", identityFile, err)
	}
	log.Printf("Generated new identity, saved to %s", identityFile)
	cfg.Node.Fingerprint = id.PublicKey
	cfg.Node.IdentityFile = identityFile
	cfg.Node.Identity = ""
	return id, nil
}

// saveIdentityPEM writes the identity's private key as a PEM file with 0600
// permissions. Creates parent directories if needed.
func saveIdentityPEM(path string, id *identity.Identity) error {
	pemStr, err := id.ToPEM()
	if err != nil {
		return fmt.Errorf("encode identity to PEM: %w", err)
	}
	// Create parent directory if it doesn't exist.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create identity dir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(pemStr), 0600); err != nil {
		return fmt.Errorf("write identity PEM: %w", err)
	}
	return nil
}

// buildRealityListenAddr constructs the Reality TLS listen address from config.
// Uses cfg.Reality.ListenPort if set, otherwise parses cfg.Reality.ListenAddr.
func buildRealityListenAddr(cfg *config.Config) string {
	port := cfg.Reality.ListenPort
	if port == 0 {
		port = 443
	}
	host := cfg.Reality.ListenAddr
	if host == "" {
		host = "0.0.0.0"
	}
	// If host already contains a port, strip it and use our port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// --- SOCKS5 status provider methods ---
//
// These methods satisfy the web.SOCKS5StatusProvider interface so the
// Dashboard's proxy management page can display live runtime state
// (handler running, active connection count) without exposing internal
// fields.

// SOCKS5HandlerActive returns true if the SOCKS5 direct-dial handler
// (virtual port 0x5350) is registered and running.
func (n *MeshNode) SOCKS5HandlerActive() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.socks5Handler != nil
}

// SOCKS5ExitHandlerActive returns true if the SOCKS5 exit handler
// (virtual port 0x4558) is registered and running.
func (n *MeshNode) SOCKS5ExitHandlerActive() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.socks5ExitHandler != nil
}

// SOCKS5ActiveConnections returns the total number of active SOCKS5
// connections across all handlers on this node.
func (n *MeshNode) SOCKS5ActiveConnections() int64 {
	n.mu.RLock()
	var total int64
	if n.socks5Handler != nil {
		total += n.socks5Handler.ActiveConnections()
	}
	if n.socks5ExitHandler != nil {
		total += n.socks5ExitHandler.ActiveConnections()
	}
	n.mu.RUnlock()
	return total
}

// firstShortID returns the first short ID from the list, or empty string.
func firstShortID(ids []string) string {
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
}

// PeerTrafficStat is per-peer traffic detail.
type PeerTrafficStat struct {
	PeerID      string `json:"peer_id"`
	InBytes     uint64 `json:"in_bytes"`
	OutBytes    uint64 `json:"out_bytes"`
	Streams     int    `json:"streams"`
	Established string `json:"established,omitempty"`
}

// PerPeerTrafficStats returns per-peer session traffic (T3.3).
func (n *MeshNode) PerPeerTrafficStats() []PeerTrafficStat {
	out := make([]PeerTrafficStat, 0)
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()

	seen := make(map[string]bool)
	for peerID, sess := range n.clientSessions {
		if sess == nil || sess.IsClosed() {
			continue
		}
		seen[peerID] = true
		st := sess.Stats()
		ps := PeerTrafficStat{
			PeerID:   peerID,
			InBytes:  st.BytesReceived,
			OutBytes: st.BytesSent,
			Streams:  sess.NumStreams(),
		}
		if t, ok := n.sessionEstablishedAt[peerID]; ok {
			ps.Established = t.Format("2006-01-02T15:04:05Z07:00")
		}
		out = append(out, ps)
	}
	for peerID, sess := range n.sessions {
		if seen[peerID] || sess == nil || sess.IsClosed() {
			continue
		}
		st := sess.Stats()
		ps := PeerTrafficStat{
			PeerID:   peerID,
			InBytes:  st.BytesReceived,
			OutBytes: st.BytesSent,
			Streams:  sess.NumStreams(),
		}
		if t, ok := n.sessionEstablishedAt[peerID]; ok {
			ps.Established = t.Format("2006-01-02T15:04:05Z07:00")
		}
		out = append(out, ps)
	}
	return out
}

// SetSessionEstablishedHandler registers a callback fired whenever a
// smux session is established with a peer (any path: server accept,
// client dial, UDP, reconnect). Used by the meta exchanger to push
// VirtualIP knowledge over the session graph. Multiple handlers may be
// registered; each fires in its own goroutine with panic recovery.
func (n *MeshNode) SetSessionEstablishedHandler(h func(peerKey string)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sessionEstablished = append(n.sessionEstablished, h)
}

// fireSessionEstablished invokes the registered handlers.
func (n *MeshNode) fireSessionEstablished(peerKey string) {
	n.mu.RLock()
	handlers := make([]func(string), len(n.sessionEstablished))
	copy(handlers, n.sessionEstablished)
	n.mu.RUnlock()
	for _, h := range handlers {
		go func(fn func(string)) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[mesh] session-established handler panic: %v", r)
				}
			}()
			fn(peerKey)
		}(h)
	}
}

// SessionPeerKeys returns the public keys of all peers with active
// smux sessions (client + server).
func (n *MeshNode) SessionPeerKeys() []string {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()
	seen := map[string]bool{}
	out := []string{}
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for id := range n.clientSessions {
		add(id)
	}
	for id := range n.sessions {
		add(id)
	}
	return out
}

// AutoConnectRelayPeer dials a relay-capable peer (CapRelay=true, learned
// via meta exchange) that we don't have a session with yet. This makes
// shared nodes redundant: a node that joins via ONE shared node learns
// the OTHERS from meta and connects to them directly, so no single
// shared node is a single point of failure.
//
// Dialing is async + deduped: only peers with NO session get dialed,
// and the relayConnecting set prevents concurrent duplicate dials.
// The dial itself goes through DialPeerByEndpoint (Reality TLS for
// cross-zone, mesh-internal for same-zone) — same as a config peer.
func (n *MeshNode) AutoConnectRelayPeer(peerKey string) {
	if peerKey == "" || peerKey == n.Identity().PublicKey {
		return
	}
	// Already connected? Nothing to do.
	if n.HasPeerSession(peerKey) {
		return
	}
	// Dedup concurrent dials.
	n.relayConnectMu.Lock()
	if n.relayConnecting[peerKey] {
		n.relayConnectMu.Unlock()
		return
	}
	n.relayConnecting[peerKey] = true
	n.relayConnectMu.Unlock()

	go func() {
		defer func() {
			n.relayConnectMu.Lock()
			delete(n.relayConnecting, peerKey)
			n.relayConnectMu.Unlock()
		}()
		ep := n.resolvePeerEndpoint(peerKey)
		if ep == "" {
			log.Printf("[mesh] auto-connect relay peer %s: no endpoint known", shortKey(peerKey))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if conn, err := n.DialPeerByEndpoint(ctx, ep); err == nil {
			conn.Close()
			log.Printf("[mesh] auto-connected to relay peer %s via %s", shortKey(peerKey), ep)
		} else {
			log.Printf("[mesh] auto-connect relay peer %s via %s failed: %v", shortKey(peerKey), ep, err)
		}
	}()
}

// LocalPublicKey returns this node's identity public key (hex).
func (n *MeshNode) LocalPublicKey() string {
	if n.identity == nil {
		return ""
	}
	return n.identity.PublicKey
}

// LocalHostname returns the configured node hostname.
func (n *MeshNode) LocalHostname() string {
	if n.cfg == nil {
		return ""
	}
	return n.cfg.Node.Hostname
}

// LocalVirtualIP returns this node's VirtualIP as a string ("" if none).
func (n *MeshNode) LocalVirtualIP() string {
	n.mu.RLock()
	ti := n.tunIntegration
	n.mu.RUnlock()
	if ti == nil || ti.VirtualIP == nil {
		return ""
	}
	return ti.VirtualIP.String()
}

// PeerTransport returns the transport the session to the peer was
// established over: "reality", "0x4d", "udp", or "" (no session).
func (n *MeshNode) PeerTransport(peerKey string) string {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()
	return n.peerTransport[peerKey]
}

// SetZoneLearner injects the gossip zone resolver (avoids import cycle).
func (n *MeshNode) SetZoneLearner(fn func(peerKey string) string) {
	n.mu.Lock()
	n.zoneLearner = fn
	n.mu.Unlock()
}

// LocalZone returns this node's zone tag ("" if unset — unknown).
func (n *MeshNode) LocalZone() string {
	if n.cfg == nil {
		return ""
	}
	return n.cfg.Mesh.Zone
}

// PeerZone returns the zone tag known for a peer: static config first
// (authoritative), gossip meta as fallback. "" = unknown.
func (n *MeshNode) PeerZone(peerKey string) string {
	// Static config peer zone (authoritative).
	n.peersMu.RLock()
	for i := range n.cfg.Peers {
		if n.cfg.Peers[i].PublicKey == peerKey && n.cfg.Peers[i].Zone != "" {
			z := n.cfg.Peers[i].Zone
			n.peersMu.RUnlock()
			return z
		}
	}
	n.peersMu.RUnlock()

	// Meta-exchange-learned zone (works with degraded memberlist).
	n.sessionsMu.Lock()
	lz, ok := n.learnedZones[peerKey]
	n.sessionsMu.Unlock()
	if ok && lz != "" {
		return lz
	}

	// Gossip-learned zone (from NodeMeta) as fallback.
	if gz := n.learnedZone(peerKey); gz != "" {
		return gz
	}
	return ""
}

// LocalEndpoints returns this node's advertised endpoints (from
// config p2p.advertise_endpoints) — propagated via the meta exchange
// so peers can dial us directly.
func (n *MeshNode) LocalEndpoints() []string {
	if n.cfg == nil {
		return nil
	}
	return append([]string(nil), n.cfg.P2P.AdvertiseEndpoints...)
}

// ConfigPeers returns the peers configured in config.yaml (static
// seeds). Used by the punch lazy-scan so the engine can self-start
// after a full restart even when the meta map is still empty.
func (n *MeshNode) ConfigPeers() []config.PeerConfig {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()
	return append([]config.PeerConfig(nil), n.cfg.Peers...)
}

// HasUDPHole reports whether a UDP hole-punched endpoint exists for the
// given peer — i.e. the peer's data plane has been upgraded from relay
// to direct UDP. Used by triggerHolePunch to skip re-punching an already
// direct peer (NOT the same as HasPeerSession — a relay session does
// not count).
func (n *MeshNode) HasUDPHole(peerKey string) bool {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()
	eps, ok := n.holeEndpoints[peerKey]
	return ok && len(eps) > 0
}

// PeerEndpoints returns the endpoints known for a peer: hole-punched
// endpoint first (confirmed data-plane target — highest priority),
// config second, meta-exchange-learned as fallback.
func (n *MeshNode) PeerEndpoints(peerKey string) []string {
	n.sessionsMu.Lock()
	if eps := append([]string(nil), n.holeEndpoints[peerKey]...); len(eps) > 0 {
		n.sessionsMu.Unlock()
		return eps
	}
	eps := append([]string(nil), n.learnedEndpoints[peerKey]...)
	n.sessionsMu.Unlock()
	if len(eps) > 0 {
		return eps
	}
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()
	for i := range n.cfg.Peers {
		if n.cfg.Peers[i].PublicKey == peerKey && n.cfg.Peers[i].Endpoint != "" {
			return []string{n.cfg.Peers[i].Endpoint}
		}
	}
	return nil
}

// SetHoleEndpoint records the CONFIRMED data-plane endpoint for a
// peer, as established by hole punching (OnHoleEstablished). This is
// kept separate from SetLearnedEndpoints (meta exchange) so the
// punched UDP port — a random port on ordinary nodes — is never
// overwritten by gossip-advertised endpoints (which carry the TCP
// port, a dead UDP target).
func (n *MeshNode) SetHoleEndpoint(peerKey string, ep string) {
	if peerKey == "" || ep == "" {
		return
	}
	n.sessionsMu.Lock()
	n.holeEndpoints[peerKey] = []string{ep}
	n.sessionsMu.Unlock()
}

// SetLearnedEndpoints records a peer's endpoints learned via the meta
// exchange (0x4D45) — independent of memberlist health.
func (n *MeshNode) SetLearnedEndpoints(peerKey string, endpoints []string) {
	if peerKey == "" || len(endpoints) == 0 {
		return
	}
	n.sessionsMu.Lock()
	n.learnedEndpoints[peerKey] = append([]string(nil), endpoints...)
	n.sessionsMu.Unlock()
}

// SetLearnedZone records a peer's zone tag learned via the meta
// exchange (0x4D45) — independent of memberlist health.
func (n *MeshNode) SetLearnedZone(peerKey, zone string) {
	if peerKey == "" || zone == "" {
		return
	}
	n.sessionsMu.Lock()
	n.learnedZones[peerKey] = zone
	n.sessionsMu.Unlock()
}

// SameZone reports whether the peer is in the same zone as us.
// Both zones must be non-empty and equal — different or unknown zone
// means "cross-zone" → Reality-only (conservative).
func (n *MeshNode) SameZone(peerKey string) bool {
	myZone := n.LocalZone()
	if myZone == "" {
		return false
	}
	pz := n.PeerZone(peerKey)
	return pz != "" && pz == myZone
}

// learnedZone consults the gossip layer (if wired) for a peer's zone.
func (n *MeshNode) learnedZone(peerKey string) string {
	n.mu.RLock()
	zl := n.zoneLearner
	n.mu.RUnlock()
	if zl == nil {
		return ""
	}
	return zl(peerKey)
}

// TunForwarderStats returns the TUN forwarder's health snapshot, or
// nil when TUN integration is not active.
func (n *MeshNode) TunForwarderStats() *TunForwarderStats {
	n.mu.RLock()
	ti := n.tunIntegration
	n.mu.RUnlock()
	if ti == nil || ti.Forwarder == nil {
		return nil
	}
	st := ti.Forwarder.Stats()
	return &st
}

// ResetPeerUDPCooldown clears the TUN data plane's UDP failure
// cooldown for a peer (and any cached dead UDP stream) so the next
// packet re-attempts the UDP path. Called when a hole-punch succeeds:
// the learned endpoint may have changed (e.g. v6→v4) and a stale
// cooldown from the old endpoint must not keep the data plane on
// relay forever.
func (n *MeshNode) ResetPeerUDPCooldown(peerKey string) {
	n.mu.RLock()
	ti := n.tunIntegration
	n.mu.RUnlock()
	if ti == nil || ti.Forwarder == nil {
		return
	}
	ti.Forwarder.ResetUDPCooldown(peerKey)
}

// PeerVirtualIPs returns all peer → VirtualIP mappings known to the
// router (config peers + meta-exchange learned peers), excluding self.
// Used by the topology to show nodes discovered via the meta exchange
// even when memberlist/gossip is degraded.
func (n *MeshNode) PeerVirtualIPs() map[string]string {
	n.mu.RLock()
	ti := n.tunIntegration
	n.mu.RUnlock()
	if ti == nil || ti.Router == nil {
		return nil
	}
	self := ""
	if n.identity != nil {
		self = n.identity.PublicKey
	}
	routes := ti.Router.AllRoutes()
	out := make(map[string]string, len(routes))
	for ipStr, pubKey := range routes {
		if pubKey == self {
			continue
		}
		out[pubKey] = ipStr
	}
	return out
}

// relaySlowPathThresholdMs: direct paths slower than this (ms) are
// candidates for relay-path comparison. Cross-zone Reality links are
// typically >300ms; same-zone UDP is usually well under. Relay has
// per-hop overhead, so only try it when the direct path is this slow.
const relaySlowPathThresholdMs = 300

// tryFasterRelayPath tries a relay path when the direct session is
// slow (heuristic: direct RTT above the threshold — typically a
// cross-zone Reality link). A same-zone relay hop can beat the direct
// path in total latency. On relay failure it returns (nil, false) so
// the caller falls back to the direct session.
func (n *MeshNode) tryFasterRelayPath(ctx context.Context, targetKey string, port uint16) (net.Conn, bool) {
	direct := n.PeerRTT(targetKey)
	if direct <= 0 || direct < relaySlowPathThresholdMs*time.Millisecond {
		return nil, false
	}
	log.Printf("[mesh] DialVirtualPort: direct path to %s is slow (%v) — trying relay path",
		targetKey[:min(len(targetKey), 16)]+"...", direct)
	conn, err := n.tryRelayFallback(ctx, targetKey, port, nil)
	if err != nil {
		log.Printf("[mesh] DialVirtualPort: relay path slower/failed (%v) — using direct", err)
		return nil, false
	}
	return conn, true
}

// PeerVirtualIP returns the VirtualIP known for a peer ("" if unknown).
func (n *MeshNode) PeerVirtualIP(peerKey string) string {
	n.mu.RLock()
	ti := n.tunIntegration
	n.mu.RUnlock()
	if ti == nil {
		return ""
	}
	ip, ok := ti.Router.ResolvePeer(peerKey)
	if !ok {
		return ""
	}
	return ip.String()
}
