package p2p

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
)

// GossipLayer is the top-level coordinator for the P2P gossip discovery layer.
// It initializes memberlist, manages the delegate and event delegate, and
// provides the API for starting/stopping gossip and querying the peer set.
type GossipLayer struct {
	cfg          P2pConfig
	identity     []byte
	peerManager  PeerManager
	delegate     *meshDelegate
	events       *meshEventDelegate
	wgDelegate   *WireGuardDelegate
	relay        *RelaySelector
	memberlist   *memberlist.Memberlist
	localMeta    *NodeMeta
	mu           sync.RWMutex
	started      bool
	stopCh       chan struct{}
	healthTicker *time.Ticker

	// transport is an optional pre-configured memberlist.Transport.
	// When non-nil, Start() uses it instead of creating a NetTransport.
	// This is used for port multiplexing (MuxTransport shares one TCP
	// listener between gossip and Reality TLS).
	transport memberlist.Transport

	// stopMetaCleanup is the cleanup function returned by
	// StartMetaCacheCleanup; called on Shutdown to stop the goroutine.
	stopMetaCleanup func()

	// peerCache persists discovered peer endpoints to disk so they
	// survive restarts. nil when persistence is disabled.
	peerCache *PeerCache

	// relaySessionMgr manages relay circuits when this node is relay-capable.
	// nil when relay mode is not enabled.
	relaySessionMgr *RelaySessionManager

	// joinProtocol handles the dynamic join/leave protocol (§4).
	// It is always initialized when p2p is enabled.
	joinProtocol *JoinProtocol
}

// NewGossipLayer creates a new gossip layer from the given config, identity,
// and peer manager. The identity is the Ed25519 private key bytes used for
// memberlist config. The peerManager handles dynamic peer management.
// Call Start() to begin gossip.
func NewGossipLayer(cfg P2pConfig, identity []byte, peerManager PeerManager) (*GossipLayer, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("p2p is disabled in config")
	}

	// Derive the Ed25519 public key from the identity private key.
	var pubKeyHex string
	if len(identity) == ed25519.PrivateKeySize {
		privKey := ed25519.PrivateKey(identity)
		pub := privKey.Public().(ed25519.PublicKey)
		pubKeyHex = hex.EncodeToString(pub)
	}

	localMeta := &NodeMeta{
		PublicKey:   pubKeyHex,
		Hostname:    "", // set by caller via SetLocalIdentity
		Role:        "agent",
		Endpoints:   []string{},
		NatType:     "unknown",
		Version:     "1.0.0",
		Seq:         1,
		MaxCircuits: 1024,
	}

	delegate := newMeshDelegate(localMeta)
	events := newMeshEventDelegate(delegate, peerManager)
	relay := NewRelaySelector(events)

	// Initialize the join protocol (§4).
	joinCfg := JoinConfig{
		LocalPublicKey: pubKeyHex,
		JoinApproval:   cfg.JoinApproval,
		AuthorizedKeys: cfg.AuthorizedKeys,
		MaxPeers:       cfg.MaxPeers,
		JoinTimeout:    30,
		RetryCooldown:  30,
		LeaveTimeout:   5,
	}
	joinProtocol := NewJoinProtocol(joinCfg, delegate, events)

	gl := &GossipLayer{
		cfg:          cfg,
		identity:     identity,
		peerManager:  peerManager,
		delegate:     delegate,
		events:       events,
		wgDelegate:   nil, // set via SetWireGuardDelegate if needed
		relay:        relay,
		localMeta:    localMeta,
		joinProtocol: joinProtocol,
		stopCh:       make(chan struct{}),
	}

	return gl, nil
}

// SetWireGuardDelegate wires the WireGuard delegate after construction.
// This is used for health polling and relay session management.
func (g *GossipLayer) SetWireGuardDelegate(wgd *WireGuardDelegate) {
	g.mu.Lock()
	g.wgDelegate = wgd
	g.mu.Unlock()
}

// SetTransport injects a pre-configured memberlist.Transport (e.g.,
// MuxTransport) to use instead of creating a NetTransport in Start().
// When set, Start() skips NetTransport creation and uses this transport.
// The caller is responsible for the transport's lifecycle (it will NOT
// be closed by GossipLayer.Stop() — the owner must close it).
func (g *GossipLayer) SetTransport(t memberlist.Transport) {
	g.mu.Lock()
	g.transport = t
	g.mu.Unlock()
}

// SetPeerCache installs a PeerCache for persisting discovered peer
// endpoints to disk. When set, the gossip event delegate updates the
// cache on peer join/update/leave events, and Start() launches a
// background save loop. Stop() performs a final flush.
func (g *GossipLayer) SetPeerCache(pc *PeerCache) {
	g.mu.Lock()
	g.peerCache = pc
	g.mu.Unlock()
	g.events.SetPeerCache(pc)
}

// SetLocalIdentity sets the local node's hostname and role in metadata.
func (g *GossipLayer) SetLocalIdentity(hostname, role string) {
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.Hostname = hostname
		m.Role = role
		m.Seq++
	})
}

// SetLocalCapabilities sets the local node's capability flags.
func (g *GossipLayer) SetLocalCapabilities(capRelay, capExit, capProxyEntry, capCollector bool) {
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.CapRelay = capRelay
		m.CapExit = capExit
		m.CapProxyEntry = capProxyEntry
		m.CapCollector = capCollector
		m.Seq++
	})
}

// SetLocalLoadMetrics updates the local node's load metrics.
// This should be called periodically (e.g., every 30s) to refresh CPU/memory/circuit load.
func (g *GossipLayer) SetLocalLoadMetrics(cpu, mem float64, circuits int, bw uint64) {
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.LoadCPU = cpu
		m.LoadMem = mem
		m.LoadCircuits = circuits
		m.LoadBW = bw
		m.Seq++
	})
}

// SetLocalEndpoints updates the local node's discovered endpoints and NAT type.
// After updating the delegate's localMeta, it calls memberlist.UpdateNode to
// force a re-broadcast of the alive message with the new per-node Meta bytes.
// Without UpdateNode, the metadata is only set at memberlist.Create() time and
// never propagated to peers via gossip — the root cause of DEFECT-02 in the
// v3 real-machine test (endpoints set locally but empty in NotifyJoin).
func (g *GossipLayer) SetLocalEndpoints(endpoints []string, natType string) {
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.Endpoints = endpoints
		m.NatType = natType
		m.Seq++
	})

	// Propagate the updated metadata through the gossip protocol.
	// memberlist.UpdateNode re-reads Delegate.NodeMeta() (which marshals
	// our localMeta) and broadcasts a fresh alive message to all peers.
	g.mu.RLock()
	ml := g.memberlist
	g.mu.RUnlock()

	if ml != nil {
		if err := ml.UpdateNode(time.Second); err != nil {
			log.Printf("[p2p] endpoint learning: UpdateNode failed: %v", err)
		}
	}
}

// SetLocalVirtualIP sets the local node's TUN VirtualIP in gossip metadata.
// The VirtualIP is assigned by the IPAM deterministic allocator and
// propagated to all peers so they can route packets to this node's
// TUN interface. After updating, it calls memberlist.UpdateNode to
// re-broadcast the alive message.
func (g *GossipLayer) SetLocalVirtualIP(virtualIP string) {
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.VirtualIP = virtualIP
		m.Seq++
	})

	g.mu.RLock()
	ml := g.memberlist
	g.mu.RUnlock()

	if ml != nil {
		if err := ml.UpdateNode(time.Second); err != nil {
			log.Printf("[p2p] virtual IP: UpdateNode failed: %v", err)
		}
	}
}

// SetLocalSubnetProxies sets the local node's advertised subnet proxies
// in gossip metadata. These are local CIDR subnets that this node can
// route to (e.g. a LAN behind it). Other nodes learn about them via
// gossip and add kernel routes via this node's VirtualIP.
func (g *GossipLayer) SetLocalSubnetProxies(subnets []string) {
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.SubnetProxies = subnets
		m.Seq++
	})

	g.mu.RLock()
	ml := g.memberlist
	g.mu.RUnlock()

	if ml != nil {
		if err := ml.UpdateNode(time.Second); err != nil {
			log.Printf("[p2p] subnet proxies: UpdateNode failed: %v", err)
		}
	}
}

// SetLocalACLRules sets the local node's ACL rules in gossip metadata.
// The rules are propagated to all peers so they can enforce ingress
// policy based on the sending node's declared rules. After updating,
// it calls memberlist.UpdateNode to re-broadcast the alive message.
func (g *GossipLayer) SetLocalACLRules(rules []string) {
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.ACLRules = rules
		m.Seq++
	})

	g.mu.RLock()
	ml := g.memberlist
	g.mu.RUnlock()

	if ml != nil {
		if err := ml.UpdateNode(time.Second); err != nil {
			log.Printf("[p2p] ACL rules: UpdateNode failed: %v", err)
		}
	}
}

// SetLocalTrafficStats updates the local node's traffic statistics in
// gossip metadata. These are propagated to all peers so every node
// can see the traffic volume, stream count, relay load, and TUN packet
// counts of every other node via gossip. After updating, it calls
// memberlist.UpdateNode to re-broadcast the alive message.
func (g *GossipLayer) SetLocalTrafficStats(inBytes, outBytes uint64, smuxStreams, relayForwards int, tunRxPackets, tunTxPackets uint64) {
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.TrafficInBytes = inBytes
		m.TrafficOutBytes = outBytes
		m.SmuxStreams = smuxStreams
		m.RelayForwards = relayForwards
		m.TunRxPackets = tunRxPackets
		m.TunTxPackets = tunTxPackets
		m.Seq++
	})

	g.mu.RLock()
	ml := g.memberlist
	g.mu.RUnlock()

	if ml != nil {
		if err := ml.UpdateNode(time.Second); err != nil {
			log.Printf("[p2p] traffic stats: UpdateNode failed: %v", err)
		}
	}
}

// announceLocalEndpoint proactively sets the local node's WireGuard endpoint(s)
// so gossip propagates them to all peers. This breaks the chicken-and-egg
// problem where reactive OnEndpointDiscovered only fires when a peer already
// knows our address and sends us a packet.
//
// Priority:
//  1. cfg.AdvertiseEndpoints (explicit, user-configured — for NAT)
//  2. auto-detected outbound IP + WgPort
//
// If neither is available, the reactive learning path remains the sole source.
func (g *GossipLayer) announceLocalEndpoint() {
	var announced []string

	if len(g.cfg.AdvertiseEndpoints) > 0 {
		// User provided explicit endpoints — trust them.
		announced = g.cfg.AdvertiseEndpoints
	} else if g.cfg.WgPort > 0 {
		// Auto-detect all outbound IPs (both IPv4 and IPv6).
		ips := detectOutboundIPs()
		for _, ip := range ips {
			announced = append(announced, net.JoinHostPort(ip, fmt.Sprintf("%d", g.cfg.WgPort)))
		}
	}

	if len(announced) == 0 {
		log.Printf("[p2p] endpoint learning: no local endpoint to announce (reactive learning only)")
		return
	}

	// Merge announced endpoints with any already-discovered endpoints (e.g.,
	// added by OnEndpointDiscovered from the WireGuard receive path).  We must
	// not call SetLocalEndpoints with only `announced` because that replaces
	// m.Endpoints wholesale, erasing reactively-learned addresses.  Instead,
	// build the full deduplicated list and pass that.
	existing := g.delegate.getLocalMeta().Endpoints
	merged := mergeEndpoints(announced, existing)

	g.SetLocalEndpoints(merged, "unknown")
	log.Printf("[p2p] endpoint learning: announced %d local endpoint(s): %v (merged %d existing)", len(merged), merged, len(existing))
}

// mergeEndpoints returns a new slice containing all unique entries from the
// input slices, preserving the order of `primary` first, then any extras from
// `extra` that are not already present.  This is used by announceLocalEndpoint
// to ensure that endpoints discovered reactively (via OnEndpointDiscovered)
// survive a subsequent announce cycle.
func mergeEndpoints(primary, extra []string) []string {
	seen := make(map[string]bool, len(primary)+len(extra))
	result := make([]string, 0, len(primary)+len(extra))
	for _, ep := range primary {
		if !seen[ep] {
			seen[ep] = true
			result = append(result, ep)
		}
	}
	for _, ep := range extra {
		if !seen[ep] {
			seen[ep] = true
			result = append(result, ep)
		}
	}
	return result
}

// detectOutboundIPs returns all preferred non-loopback outbound IP addresses
// of this machine (both IPv4 and IPv6) by opening UDP sockets to well-known
// public addresses. No actual data is sent — the kernel picks the source IP
// it would use for routing. If no IPs are found via UDP dial, falls back to
// scanning network interfaces. Returns an empty slice if no suitable address
// is found.
func detectOutboundIPs() []string {
	var ips []string
	seen := make(map[string]bool)

	addIP := func(ip string) {
		if ip == "" || ip == "0.0.0.0" || ip == "::" {
			return
		}
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}

	// IPv4: dial a public IPv4 address. The kernel selects the interface
	// it would route through, giving us the correct source IPv4 address.
	if conn, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		addr := conn.LocalAddr().(*net.UDPAddr)
		addIP(addr.IP.String())
		conn.Close()
	}

	// IPv6: dial a public IPv6 address (Google Public DNS). The kernel
	// selects the interface it would route through for IPv6.
	if conn, err := net.Dial("udp", "[2001:4860:4860::8888]:80"); err == nil {
		addr := conn.LocalAddr().(*net.UDPAddr)
		addIP(addr.IP.String())
		conn.Close()
	}

	// Fallback: if no IPs found via UDP dial (e.g., no default route),
	// scan network interfaces for both IPv4 and IPv6 addresses.
	if len(ips) == 0 {
		for _, ip := range detectOutboundIPsFromInterfaces() {
			addIP(ip)
		}
	}

	return ips
}

// detectOutboundIP returns the preferred non-loopback outbound IP address of
// this machine (IPv4 preferred, IPv6 as fallback). This is a convenience
// wrapper around detectOutboundIPs for callers that need only a single
// address (e.g., memberlist AdvertiseAddr). Returns "" if no suitable
// address is found.
func detectOutboundIP() string {
	ips := detectOutboundIPs()
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// detectOutboundIPsFromInterfaces scans network interfaces for all non-loopback,
// non-link-local IP addresses (both IPv4 and IPv6). This is a fallback used
// when the UDP dial trick fails (e.g., no default route).
func detectOutboundIPsFromInterfaces() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var ips []string
	for _, addr := range addrs {
		// addr is either *net.IPNet or *net.IPAddr
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			ip := ipnet.IP
			// Include both IPv4 and IPv6 addresses. Exclude link-local
			// addresses (IPv4 169.254.x.x and IPv6 fe80::/10) since they
			// are not routable beyond the local network segment.
			if !ip.IsLinkLocalUnicast() {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips
}

// OnCollectorDiscovered is called when a peer with CapCollector=true is
// detected via gossip (NotifyJoin or NotifyUpdate). It dispatches to the
// registered collector handler (if any), which typically adds the peer's
// public key to the monitor reporter's collector list.
//
// This method is the GossipLayer's public entry point for collector
// auto-discovery. The actual callback wiring is done via
// SetCollectorHandler, which installs a handler on the event delegate.
// This method is provided for manual/explicit collector discovery
// (e.g., from startup bootstrap code).
func (g *GossipLayer) OnCollectorDiscovered(peerKey string) {
	g.events.mu.RLock()
	hdl := g.events.collectorHandler
	g.events.mu.RUnlock()

	if hdl != nil {
		log.Printf("[p2p] OnCollectorDiscovered: %s", shortKey(peerKey))
		hdl(peerKey)
	}
}

// SetCollectorHandler wires a callback that is invoked when a collector
// peer (CapCollector=true) is discovered via gossip. The callback receives
// the collector's Ed25519 public key (hex-encoded).
//
// In production, this is called from main.go to connect the gossip layer
// to the monitor reporter:
//
//	gossipLayer.SetCollectorHandler(reporter.AddCollector)
func (g *GossipLayer) SetCollectorHandler(hdl CollectorDiscoveredHandler) {
	g.events.SetCollectorHandler(hdl)
}

// SetCollectorRemovedHandler wires a callback that is invoked when a
// collector peer leaves the mesh (NotifyLeave) or loses its CapCollector
// capability (NotifyUpdate). The callback receives the collector's
// Ed25519 public key (hex-encoded).
//
// In production, this is called from main.go to connect the gossip layer
// to the monitor reporter:
//
//	gossipLayer.SetCollectorRemovedHandler(reporter.RemoveCollector)
func (g *GossipLayer) SetCollectorRemovedHandler(hdl CollectorRemovedHandler) {
	g.events.SetCollectorRemovedHandler(hdl)
}

// SetSubnetProxyHandler installs a handler for subnet proxy change events.
// When a peer joins or updates with advertised subnet proxies, the handler
// is invoked with the peer's public key, VirtualIP, and the list of subnet
// CIDRs. When a peer leaves, the handler is invoked with empty subnets.
func (g *GossipLayer) SetSubnetProxyHandler(hdl SubnetProxyChangeHandler) {
	g.events.SetSubnetProxyHandler(hdl)
}

// SeedCollectorsFromCache re-fires the collector discovery callback for
// every collector peer persisted in the peer cache. Call this at startup
// after SetCollectorHandler has been wired, so that the reporter's collector
// list is immediately populated from persisted state — without waiting for
// gossip to re-discover collector nodes.
//
// This is safe to call even if gossip hasn't started yet: it reads the
// PeerCache directly and invokes the callback synchronously. Peers that
// are no longer reachable will be cleaned up by the collector removed
// handler when gossip detects their departure.
func (g *GossipLayer) SeedCollectorsFromCache() {
	if g.peerCache == nil {
		return
	}

	collectorKeys := g.peerCache.CachedCollectors()
	if len(collectorKeys) == 0 {
		return
	}

	g.events.mu.RLock()
	hdl := g.events.collectorHandler
	g.events.mu.RUnlock()

	if hdl == nil {
		return
	}

	for _, key := range collectorKeys {
		log.Printf("[p2p] SeedCollectorsFromCache: re-seeding collector %s from cache", shortKey(key))
		hdl(key)
	}
}

// OnEndpointDiscovered implements mesh.EndpointNotifier.
// Non-blocking: delegates to updateLocalMeta which holds the delegate
// mutex briefly. Called from WireGuard receive goroutines.
func (g *GossipLayer) OnEndpointDiscovered(peerKey, endpoint string) {
	// peerKey is unused in this implementation because endpoint learning
	// updates LOCAL node metadata (what endpoints *we* can be reached at).
	// The peerKey identifies which peer sent us the packet, which could be
	// used for per-peer endpoint tracking in a future enhancement.
	_ = peerKey

	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		// Dedup: check if this endpoint is already in the list.
		// O(n) where n is len(Endpoints), typically 1-3.
		for _, ep := range m.Endpoints {
			if ep == endpoint {
				return // already known, seq not incremented
			}
		}
		m.Endpoints = append(m.Endpoints, endpoint)
		m.NatType = inferNAT(endpoint)
		m.Seq++
	})
}

// resolveAdvertiseAddr determines the address to advertise to gossip peers.
// hashicorp memberlist uses a TCP transport that is IPv4-native, so when
// multiple endpoints are available (dual-stack), we prefer the first IPv4
// endpoint.  If no IPv4 endpoint exists we fall back to the first endpoint
// (which may be IPv6).
//
// Priority:
//  1. first IPv4 endpoint in cfg.AdvertiseEndpoints (explicit, user-configured)
//  2. first endpoint in cfg.AdvertiseEndpoints (any family)
//  3. first IPv4 endpoint in localMeta.Endpoints
//  4. first endpoint in localMeta.Endpoints (any family)
//  5. auto-detected outbound IP (detectOutboundIP already prefers IPv4)
func (g *GossipLayer) resolveAdvertiseAddr() string {
	if host := firstIPv4HostFromEndpoints(g.cfg.AdvertiseEndpoints); host != "" {
		return host
	}
	if len(g.cfg.AdvertiseEndpoints) > 0 {
		if host, _ := hostFromEndpoint(g.cfg.AdvertiseEndpoints[0]); host != "" {
			return host
		}
	}
	if host := firstIPv4HostFromEndpoints(g.localMeta.Endpoints); host != "" {
		return host
	}
	if len(g.localMeta.Endpoints) > 0 {
		if host, _ := hostFromEndpoint(g.localMeta.Endpoints[0]); host != "" {
			return host
		}
	}
	if ip := detectOutboundIP(); ip != "" {
		return ip
	}
	return ""
}

// hostFromEndpoint extracts the host portion from a "host:port" endpoint
// string.  Returns ("", error) if the string cannot be parsed.
func hostFromEndpoint(endpoint string) (string, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}
	return host, nil
}

// firstIPv4HostFromEndpoints iterates through a list of "host:port" endpoints
// and returns the host of the first IPv4 endpoint.  Returns "" if no IPv4
// endpoint is found or the list is empty.
func firstIPv4HostFromEndpoints(endpoints []string) string {
	for _, ep := range endpoints {
		if ep == "" {
			continue
		}
		host, err := hostFromEndpoint(ep)
		if err != nil || host == "" {
			continue
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.To4() != nil {
			return host
		}
	}
	return ""
}

// Start initializes memberlist and begins gossip.
func (g *GossipLayer) Start() error {
	g.mu.Lock()
	if g.started {
		g.mu.Unlock()
		return fmt.Errorf("gossip layer already started")
	}
	g.mu.Unlock()

	// Resolve the bind address for memberlist NetTransport.
	bindAddr := g.cfg.GossipBindAddr
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	// Create memberlist configuration.
	mlConfig := memberlist.DefaultLocalConfig()
	mlConfig.Name = g.localMeta.PublicKey[:16] // first 16 chars of hex key
	mlConfig.BindAddr = bindAddr
	mlConfig.BindPort = g.cfg.GossipPort
	mlConfig.AdvertiseAddr = g.resolveAdvertiseAddr()
	mlConfig.AdvertisePort = g.cfg.GossipPort
	mlConfig.TCPTimeout = 10 * time.Second
	mlConfig.IndirectChecks = 3
	mlConfig.RetransmitMult = 4
	// Increase suspicion timeout to tolerate cross-network UDP latency.
	// The default SuspicionMult=4 with ProbeInterval=1s gives only ~4s before
	// a missed UDP ping triggers suspect→fail. On inter-cloud VPN links
	// (EasyTier), UDP packets can be delayed or dropped by the VPN overlay,
	// causing false positives. Increasing SuspicionMult to 8 gives ~8s of
	// tolerance, which is enough for transient VPN packet loss.
	// Similarly, SuspicionMaxTimeoutMult=12 (from 6) allows more time for
	// peer confirmations to arrive.
	mlConfig.SuspicionMult = 8
	mlConfig.SuspicionMaxTimeoutMult = 12
	mlConfig.PushPullInterval = time.Duration(g.cfg.GossipInterval) * time.Second
	mlConfig.ProbeInterval = time.Duration(g.cfg.GossipProbeInterval) * time.Second
	// ProbeTimeout: allow enough time for cross-network RTT (up to 300ms
	// jitter on inter-cloud VPN links). The TCP fallback ping runs in a
	// goroutine and needs headroom after the UDP ping times out.
	mlConfig.ProbeTimeout = 2 * time.Second
	mlConfig.DisableTcpPings = false
	mlConfig.Delegate = g.delegate
	mlConfig.Events = g.events

	// Use a custom logger that prefixes with [p2p].
	mlConfig.Logger = log.New(log.Writer(), "[p2p/memberlist] ", log.LstdFlags)

	// Use the injected transport (MuxTransport) if set, otherwise create
	// the default NetTransport.
	if g.transport != nil {
		mlConfig.Transport = g.transport
	} else {
		nc := &memberlist.NetTransportConfig{
			BindAddrs: []string{bindAddr},
			BindPort:  g.cfg.GossipPort,
			Logger:    log.New(log.Writer(), "[p2p/transport] ", log.LstdFlags),
		}
		nt, err := memberlist.NewNetTransport(nc)
		if err != nil {
			return fmt.Errorf("create net transport: %w", err)
		}
		mlConfig.Transport = nt
	}

	// Create the memberlist.
	ml, err := memberlist.Create(mlConfig)
	if err != nil {
		return fmt.Errorf("create memberlist: %w", err)
	}
	g.mu.Lock()
	g.memberlist = ml
	g.started = true
	g.mu.Unlock()

	// Start periodic cleanup of stale metaCache entries (prevents
	// unbounded growth from peers that left permanently).
	g.stopMetaCleanup = g.events.StartMetaCacheCleanup()

	// Announce our local endpoint before any join so peers receive it
	// in the initial PushPull state sync. This runs unconditionally —
	// seed nodes (with empty seeds) must also announce their endpoint,
	// otherwise peers joining the seed can never learn its address.
	// (Fix for DEFECT-01 from v3 real-machine test: announceLocalEndpoint
	// was previously gated behind HasSeed(), so seeds with seeds=[]
	// never announced.)
	g.announceLocalEndpoint()

	// Join seed peers if configured.
	if g.cfg.HasSeed() {
		// Run join in a goroutine — it may block if seeds are unreachable.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			_, err := g.JoinSeeds(ctx, g.cfg.Seeds)
			if err != nil {
				log.Printf("[p2p] failed to join seeds: %v (will retry)", err)
				// Retry with backoff.
				g.retryJoinSeeds()
			}
		}()
	}

	// Start health polling goroutine.
	g.healthTicker = time.NewTicker(30 * time.Second)
	go g.healthPollLoop()

	// Wire the join protocol (§4).
	g.wireJoinProtocol()

	// Start peer cache save loop if persistence is enabled.
	g.mu.RLock()
	pc := g.peerCache
	g.mu.RUnlock()
	if pc != nil {
		pc.StartSaveLoop()
	}

	log.Printf("[p2p] gossip layer started (bind %s:%d, advertise %s)",
		bindAddr, g.cfg.GossipPort, mlConfig.AdvertiseAddr)

	return nil
}

// Stop shuts down the gossip layer.
func (g *GossipLayer) Stop() error {
	g.mu.Lock()
	if !g.started {
		g.mu.Unlock()
		return nil
	}
	g.started = false
	rsm := g.relaySessionMgr
	stopCleanup := g.stopMetaCleanup
	g.mu.Unlock()

	close(g.stopCh)

	if stopCleanup != nil {
		stopCleanup()
	}

	if g.healthTicker != nil {
		g.healthTicker.Stop()
	}

	// Stop the relay session manager if active.
	if rsm != nil {
		rsm.Stop()
	}

	// Stop the peer cache (flushes to disk).
	g.mu.RLock()
	pc := g.peerCache
	g.mu.RUnlock()
	if pc != nil {
		pc.Stop()
	}

	// Send a graceful LeaveNotice to all peers (§4).
	// This runs before memberlist.Leave() so peers get an early signal.
	if g.joinProtocol != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := g.joinProtocol.SendLeaveNotice(ctx); err != nil {
			log.Printf("[p2p] warning: leave notice delivery: %v", err)
		}
		cancel()
		g.joinProtocol.Stop()
	}

	if g.memberlist != nil {
		// Leave the cluster gracefully.
		_ = g.memberlist.Leave(5 * time.Second)
		g.memberlist.Shutdown()
	}

	log.Printf("[p2p] gossip layer stopped")
	return nil
}

// JoinSeeds joins the gossip cluster via the given seed addresses.
// Each address should be in "meshIP:port" format.
func (g *GossipLayer) JoinSeeds(ctx context.Context, seeds []string) (int, error) {
	g.mu.RLock()
	ml := g.memberlist
	g.mu.RUnlock()

	if ml == nil {
		return 0, fmt.Errorf("memberlist not initialized")
	}

	// Filter out invalid addresses.
	var validSeeds []string
	for _, s := range seeds {
		if _, _, err := net.SplitHostPort(s); err == nil {
			validSeeds = append(validSeeds, s)
		} else {
			log.Printf("[p2p] invalid seed address %q: %v", s, err)
		}
	}

	if len(validSeeds) == 0 {
		return 0, fmt.Errorf("no valid seed addresses")
	}

	// memberlist.Join blocks until contact is made or timeout.
	contacted, err := ml.Join(validSeeds)
	if err != nil {
		return contacted, fmt.Errorf("join seeds: %w", err)
	}

	log.Printf("[p2p] joined gossip cluster via %d/%d seeds", contacted, len(validSeeds))
	return contacted, nil
}

// retryJoinSeeds retries joining seeds with exponential backoff.
func (g *GossipLayer) retryJoinSeeds() {
	backoff := 5 * time.Second
	maxBackoff := 60 * time.Second

	for {
		select {
		case <-g.stopCh:
			return
		case <-time.After(backoff):
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := g.JoinSeeds(ctx, g.cfg.Seeds)
		cancel()

		if err == nil {
			log.Printf("[p2p] successfully joined seeds after retry")
			return
		}

		log.Printf("[p2p] seed join retry failed: %v (next in %v)", err, backoff*2)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// healthPollLoop periodically checks WireGuard handshake health for all
// dynamic peers. Dead peers (no handshake within 2 minutes) are reported
// but NOT automatically removed — gossip failure detection handles that.
func (g *GossipLayer) healthPollLoop() {
	for {
		select {
		case <-g.stopCh:
			return
		case <-g.healthTicker.C:
		}

		peers := g.wgDelegate.AllDynamicPeers()
		var totalRTT time.Duration
		rttCount := 0
		for _, pk := range peers {
			_ = g.wgDelegate.IsConnected(pk)
			// Measure RTT using the WireGuard handshake estimator.
			rtt := g.EstimateRTT(pk)
			if rtt > 0 && rtt < 5*time.Second {
				totalRTT += rtt
				rttCount++
			}
		}

		// Update the local node's advertised RTT as the average RTT
		// to all known peers. This gives other nodes a latency estimate
		// for relay selection without needing to probe us directly.
		if rttCount > 0 {
			avgRTT := totalRTT / time.Duration(rttCount)
			g.SetLocalRTT(avgRTT)
		}
	}
}

// SetLocalRTT updates the local node's self-measured RTT (round-trip time
// to the mesh seed) in the gossip metadata. The RTT is stored in
// microseconds and propagated to all peers so they can make latency-aware
// relay selection decisions. After updating, it calls memberlist.UpdateNode
// to re-broadcast the alive message.
func (g *GossipLayer) SetLocalRTT(rtt time.Duration) {
	rttUs := uint32(0)
	if rtt > 0 {
		rttUs = uint32(rtt.Microseconds())
		if rttUs == 0 {
			rttUs = 1 // clamp: 0 means "no measurement"
		}
	}
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.RTTUs = rttUs
		m.Seq++
	})

	g.mu.RLock()
	ml := g.memberlist
	g.mu.RUnlock()

	if ml != nil {
		if err := ml.UpdateNode(time.Second); err != nil {
			log.Printf("[p2p] RTT update: UpdateNode failed: %v", err)
		}
	}
}

// PeerRTT returns the advertised RTT for a peer, or 0 if unknown.
// This reads the RTTUs field from the peer's cached NodeMeta.
func (g *GossipLayer) PeerRTT(peerKey string) time.Duration {
	meta := g.events.GetPeerMeta(peerKey)
	if meta == nil || meta.RTTUs == 0 {
		return 0
	}
	return time.Duration(meta.RTTUs) * time.Microsecond
}

// SelectTopKRelays is a convenience method that selects the top K=2 relays
// using the RTT*(1+load) scoring formula from P2P_NETWORKING_SPEC.md §5.2.
// It uses the gossip layer's peer metadata to estimate RTT.
//
// This implements the "pick top K=2" selection algorithm from the task spec:
// relay sessions are assigned to the two best relay candidates based on
// the composite RTT*load score.
func (g *GossipLayer) SelectTopKRelays(k int, rttEstimator func(peerKey string) time.Duration) []*RelayCandidate {
	if k <= 0 {
		k = 2 // default K=2 per task spec
	}
	return g.relay.SelectRelays(k, 3, rttEstimator) // shuffleTopN=3 for load spreading
}

// EstimateRTT estimates the round-trip time to a peer using WireGuard
// handshake timing. It uses the delta between peer addition time and
// last handshake time as a one-way latency estimate. For peers without
// a known handshake, it returns a default of 100ms.
//
// This is the production RTT estimator wired into the RelayPathBuilder
// and RelaySelector.
func (g *GossipLayer) EstimateRTT(peerKey string) time.Duration {
	if g.wgDelegate == nil {
		return 100 * time.Millisecond
	}

	h := g.wgDelegate.GetPeerHealth(peerKey)
	if h == nil {
		return 100 * time.Millisecond
	}

	if !h.LastHandshake.IsZero() && !h.AddedAt.IsZero() {
		initialRTT := h.LastHandshake.Sub(h.AddedAt)
		// Clamp to reasonable range: 1ms - 5s
		if initialRTT > 0 && initialRTT < 5*time.Second {
			return initialRTT
		}
	}

	// Default: 100ms estimate for unknown peers
	return 100 * time.Millisecond
}

// --- Join Protocol (§4) ---

// wireJoinProtocol connects the JoinProtocol to the gossip transport,
// setting up the message sender, broadcast sender, peer list provider,
// and capacity checker. Called during Start().
func (g *GossipLayer) wireJoinProtocol() {
	if g.joinProtocol == nil {
		return
	}

	// Message sender: send a join message to a specific peer via
	// memberlist's reliable transport (TCP).
	g.joinProtocol.SetMessageSender(func(peerKey string, msg *JoinMessage) {
		g.sendJoinMessage(peerKey, msg)
	})

	// Broadcast sender: broadcast a message to all peers.
	g.joinProtocol.SetBroadcastSender(func(msg *JoinMessage) {
		g.broadcastJoinMessage(msg)
	})

	// Peer list provider: returns all known peers for JoinAccept.
	g.joinProtocol.SetPeerListProvider(func() []*NodeMeta {
		return g.events.AllKnownPeers()
	})

	// Peer count provider: for capacity checking.
	g.joinProtocol.SetPeerCountProvider(func() int {
		return g.events.KnownPeerCount()
	})

	// Capacity checker: reject new joins if at MaxPeers.
	g.joinProtocol.maxPeersExceeded = func() bool {
		count := g.events.KnownPeerCount()
		return count >= g.cfg.MaxPeers
	}

	// Wire the join message handler into the delegate's NotifyMsg.
	// The delegate already dispatches relay messages; we add join messages.
	g.delegate.SetJoinMessageHandler(func(msg *JoinMessage) error {
		return g.joinProtocol.HandleMessage(msg)
	})
}

// sendJoinMessage sends a join-protocol message to a specific peer
// via memberlist's reliable transport (TCP).
func (g *GossipLayer) sendJoinMessage(peerKey string, msg *JoinMessage) {
	g.mu.RLock()
	ml := g.memberlist
	g.mu.RUnlock()

	if ml == nil {
		log.Printf("[p2p] cannot send join message: memberlist not initialized")
		return
	}

	data, err := msg.Marshal()
	if err != nil {
		log.Printf("[p2p] failed to marshal join message: %v", err)
		return
	}

	// Find the memberlist node for this peer.
	// memberlist node names are the first 16 chars of the public key.
	var nodeName string
	if len(peerKey) >= 16 {
		nodeName = peerKey[:16]
	} else {
		nodeName = peerKey
	}

	var targetNode *memberlist.Node
	for _, n := range ml.Members() {
		if n.Name == nodeName {
			targetNode = n
			break
		}
	}

	if targetNode == nil {
		log.Printf("[p2p] cannot send join %s: peer %s not in memberlist",
			msg.Type, shortKey(peerKey))
		return
	}

	if err := ml.SendReliable(targetNode, data); err != nil {
		log.Printf("[p2p] failed to send join %s to %s: %v",
			msg.Type, shortKey(peerKey), err)
	}
}

// broadcastJoinMessage sends a join-protocol message to all peers
// via memberlist's reliable transport. Used for LeaveNotice.
func (g *GossipLayer) broadcastJoinMessage(msg *JoinMessage) {
	g.mu.RLock()
	ml := g.memberlist
	g.mu.RUnlock()

	if ml == nil {
		log.Printf("[p2p] cannot broadcast join message: memberlist not initialized")
		return
	}

	data, err := msg.Marshal()
	if err != nil {
		log.Printf("[p2p] failed to marshal join message: %v", err)
		return
	}

	for _, n := range ml.Members() {
		// Skip our own node.
		if n.Name == g.localMeta.PublicKey[:16] {
			continue
		}
		if err := ml.SendReliable(n, data); err != nil {
			log.Printf("[p2p] failed to broadcast join %s to %s: %v",
				msg.Type, n.Name, err)
		}
	}
}

// JoinProtocol returns the join protocol handler.
func (g *GossipLayer) JoinProtocol() *JoinProtocol {
	return g.joinProtocol
}

// RequestJoin sends a JoinRequest to a bootstrap node and waits for
// the response. This is the joiner-side entry point (§4.1).
//
// After a successful join, the caller should call JoinSeeds() with the
// bootstrap's mesh IP to trigger full memberlist state sync.
func (g *GossipLayer) RequestJoin(ctx context.Context, bootstrapKey string) (*RequestJoinResult, error) {
	if g.joinProtocol == nil {
		return nil, fmt.Errorf("join protocol not initialized")
	}
	return g.joinProtocol.RequestJoin(ctx, bootstrapKey)
}

// SendLeaveNotice broadcasts a graceful leave notification to all peers.
// Should be called before shutdown to enable fast peer cleanup.
func (g *GossipLayer) SendLeaveNotice(ctx context.Context) error {
	if g.joinProtocol == nil {
		return fmt.Errorf("join protocol not initialized")
	}
	return g.joinProtocol.SendLeaveNotice(ctx)
}

// --- Accessors ---

// Events returns the event delegate for registering callbacks.
func (g *GossipLayer) Events() *meshEventDelegate {
	return g.events
}

// Relay returns the relay selector.
func (g *GossipLayer) Relay() *RelaySelector {
	return g.relay
}

// Delegate returns the mesh delegate (for updating local metadata).
func (g *GossipLayer) Delegate() *meshDelegate {
	return g.delegate
}

// WgDelegate returns the WireGuard delegate.
func (g *GossipLayer) WgDelegate() *WireGuardDelegate {
	return g.wgDelegate
}

// LocalMeta returns a copy of the local node's metadata.
func (g *GossipLayer) LocalMeta() *NodeMeta {
	return g.delegate.getLocalMeta()
}

// MemberCount returns the number of nodes in the memberlist cluster.
func (g *GossipLayer) MemberCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.memberlist == nil {
		return 0
	}
	return g.memberlist.NumMembers()
}

// IsStarted returns whether the gossip layer is running.
func (g *GossipLayer) IsStarted() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.started
}

// KnownPeers returns metadata for all peers known via gossip.
func (g *GossipLayer) KnownPeers() []*NodeMeta {
	return g.events.AllKnownPeers()
}

// RelaySessionManager returns the relay session manager, or nil if
// relay mode is not enabled.
func (g *GossipLayer) RelaySessionManager() *RelaySessionManager {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.relaySessionMgr
}

// PeerCache returns the peer cache, or nil if persistence is not enabled.
func (g *GossipLayer) PeerCache() *PeerCache {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.peerCache
}

// EnableRelayMode initializes the relay session manager and wires it
// to the gossip message handler. This should be called after Start()
// when the node is configured as a relay-capable peer.
//
// The relay session manager handles circuit setup/teardown/ping messages
// received via gossip, and tracks active circuits for load reporting.
func (g *GossipLayer) EnableRelayMode(maxCircuits int) error {
	g.mu.Lock()
	if g.relaySessionMgr != nil {
		g.mu.Unlock()
		return nil // already enabled
	}
	g.mu.Unlock()

	localKey := g.delegate.getLocalMeta().PublicKey
	cfg := RelaySessionManagerConfig{
		MaxCircuits: maxCircuits,
	}
	if cfg.MaxCircuits <= 0 {
		cfg.MaxCircuits = 1024
	}

	rsm := NewRelaySessionManager(localKey, g.events, g.delegate, cfg, g.wgDelegate)

	// Wire the message handler: delegate.NotifyMsg → rsm.HandleMessage.
	g.delegate.SetRelayMessageHandler(func(msg *RelayMessage) error {
		return rsm.HandleMessage(msg)
	})

	// Wire the message sender: rsm.sendMessage → gossip SendReliable.
	rsm.SetMessageSender(func(peerKey string, msg *RelayMessage) {
		g.sendRelayMessage(peerKey, msg)
	})

	g.mu.Lock()
	g.relaySessionMgr = rsm
	g.mu.Unlock()

	// Update local capabilities: CapRelay = true.
	g.SetLocalCapabilities(true, g.delegate.getLocalMeta().CapExit, g.delegate.getLocalMeta().CapProxyEntry, g.delegate.getLocalMeta().CapCollector)

	// Set MaxCircuits in metadata.
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.MaxCircuits = maxCircuits
		m.Seq++
	})

	if err := rsm.Start(); err != nil {
		return fmt.Errorf("start relay session manager: %w", err)
	}

	log.Printf("[p2p] relay mode enabled (maxCircuits=%d)", maxCircuits)
	return nil
}

// DisableRelayMode shuts down the relay session manager and clears
// the CapRelay flag. Existing circuits are torn down.
func (g *GossipLayer) DisableRelayMode() error {
	g.mu.Lock()
	rsm := g.relaySessionMgr
	g.relaySessionMgr = nil
	g.mu.Unlock()

	if rsm != nil {
		rsm.Stop()
	}

	// Clear CapRelay.
	g.SetLocalCapabilities(false, g.delegate.getLocalMeta().CapExit, g.delegate.getLocalMeta().CapProxyEntry, g.delegate.getLocalMeta().CapCollector)

	log.Printf("[p2p] relay mode disabled")
	return nil
}

// sendRelayMessage sends a relay control message to a specific peer
// via memberlist's reliable transport. The message is serialized to
// MessagePack and delivered to the peer's NotifyMsg handler.
//
// If the peer is not in the memberlist, the message is dropped with
// a log message.
func (g *GossipLayer) sendRelayMessage(peerKey string, msg *RelayMessage) {
	g.mu.RLock()
	ml := g.memberlist
	g.mu.RUnlock()

	if ml == nil {
		log.Printf("[p2p] cannot send relay message: memberlist not initialized")
		return
	}

	data, err := msg.Marshal()
	if err != nil {
		log.Printf("[p2p] failed to marshal relay message: %v", err)
		return
	}

	// Find the memberlist node for this peer.
	// memberlist node names are the first 16 chars of the public key.
	var nodeName string
	if len(peerKey) >= 16 {
		nodeName = peerKey[:16]
	} else {
		nodeName = peerKey
	}

	// Look up the node in the memberlist.
	var targetNode *memberlist.Node
	for _, n := range ml.Members() {
		if n.Name == nodeName {
			targetNode = n
			break
		}
	}

	if targetNode == nil {
		log.Printf("[p2p] cannot send relay %s: peer %s not in memberlist",
			msg.Type, shortKey(peerKey))
		return
	}

	// Send reliably (TCP). This blocks until delivered or timeout.
	if err := ml.SendReliable(targetNode, data); err != nil {
		log.Printf("[p2p] failed to send relay %s to %s: %v",
			msg.Type, shortKey(peerKey), err)
	}
}

// SendRelayMessage is the public API for sending a relay control message
// to a specific peer. It is used by the NAT traversal layer to send
// circuit_setup, circuit_teardown, and ping messages.
func (g *GossipLayer) SendRelayMessage(peerKey string, msg *RelayMessage) error {
	g.mu.RLock()
	ml := g.memberlist
	g.mu.RUnlock()

	if ml == nil {
		return fmt.Errorf("gossip layer not started")
	}

	g.sendRelayMessage(peerKey, msg)
	return nil
}
