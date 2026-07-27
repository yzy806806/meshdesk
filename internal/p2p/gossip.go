package p2p

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/yzy806806/meshdesk/internal/mesh"
)

// GossipLayer is the top-level coordinator for the P2P gossip discovery layer.
// It initializes memberlist, manages the delegate and event delegate, and
// provides the API for starting/stopping gossip and querying the peer set.
type GossipLayer struct {
	cfg          P2pConfig
	node         *mesh.MeshNode
	delegate     *meshDelegate
	events       *meshEventDelegate
	wgDelegate   *WireGuardDelegate
	relay        *RelaySelector
	transport    *MeshTransport
	memberlist   *memberlist.Memberlist
	localMeta    *NodeMeta
	mu           sync.RWMutex
	started      bool
	stopCh       chan struct{}
	healthTicker *time.Ticker

	// relaySessionMgr manages relay circuits when this node is relay-capable.
	// nil when relay mode is not enabled.
	relaySessionMgr *RelaySessionManager

	// joinProtocol handles the dynamic join/leave protocol (§4).
	// It is always initialized when p2p is enabled.
	joinProtocol *JoinProtocol
}

// NewGossipLayer creates a new gossip layer from the given config and mesh node.
// The WireGuardDelegate must be pre-created (it wraps the MeshNode).
// Call Start() to begin gossip.
func NewGossipLayer(cfg P2pConfig, node *mesh.MeshNode, wgDelegate *WireGuardDelegate) (*GossipLayer, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("p2p is disabled in config")
	}

	// Build local NodeMeta from the mesh node's identity.
	identity := node.Identity()
	meshIP := DeriveMeshIPFromHex(identity.PublicKey)

	localMeta := &NodeMeta{
		PublicKey:   identity.PublicKey,
		Hostname:    "", // set by caller via SetLocalIdentity
		Role:        "agent",
		Endpoints:   []string{},
		NatType:     "unknown",
		MeshIP:      meshIP,
		Version:     "1.0.0",
		Seq:         1,
		MaxCircuits: 1024,
	}

	delegate := newMeshDelegate(localMeta)
	events := newMeshEventDelegate(delegate, wgDelegate)
	relay := NewRelaySelector(events)

	// Initialize the join protocol (§4).
	joinCfg := JoinConfig{
		LocalPublicKey: identity.PublicKey,
		JoinApproval:   cfg.JoinApproval,
		AuthorizedKeys: cfg.AuthorizedKeys,
		MaxPeers:       cfg.MaxPeers,
		JoinTimeout:    30,
		RetryCooldown:  30,
		LeaveTimeout:   5,
	}
	joinProtocol := NewJoinProtocol(joinCfg, delegate, events)

	// Create the custom transport that dials via the gVisor netstack.
	transport := NewMeshTransport(node, meshIP, cfg.GossipPort)

	gl := &GossipLayer{
		cfg:          cfg,
		node:         node,
		delegate:     delegate,
		events:       events,
		wgDelegate:   wgDelegate,
		relay:        relay,
		transport:    transport,
		localMeta:    localMeta,
		joinProtocol: joinProtocol,
		stopCh:       make(chan struct{}),
	}

	return gl, nil
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
func (g *GossipLayer) SetLocalCapabilities(capRelay, capExit, capProxyEntry bool) {
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.CapRelay = capRelay
		m.CapExit = capExit
		m.CapProxyEntry = capProxyEntry
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
func (g *GossipLayer) SetLocalEndpoints(endpoints []string, natType string) {
	g.delegate.updateLocalMeta(func(m *NodeMeta) {
		m.Endpoints = endpoints
		m.NatType = natType
		m.Seq++
	})
}

// Start initializes memberlist and begins gossip.
func (g *GossipLayer) Start() error {
	g.mu.Lock()
	if g.started {
		g.mu.Unlock()
		return fmt.Errorf("gossip layer already started")
	}
	g.mu.Unlock()

	// Create memberlist configuration.
	mlConfig := memberlist.DefaultLocalConfig()
	mlConfig.Name = g.localMeta.PublicKey[:16] // first 16 chars of hex key
	mlConfig.BindAddr = g.localMeta.MeshIP
	mlConfig.BindPort = g.cfg.GossipPort
	mlConfig.AdvertiseAddr = g.localMeta.MeshIP
	mlConfig.AdvertisePort = g.cfg.GossipPort
	mlConfig.TCPTimeout = 10 * time.Second
	mlConfig.IndirectChecks = 3
	mlConfig.RetransmitMult = 4
	mlConfig.SuspicionMult = 4
	mlConfig.SuspicionMaxTimeoutMult = 6
	mlConfig.PushPullInterval = time.Duration(g.cfg.GossipInterval) * time.Second
	mlConfig.ProbeInterval = time.Duration(g.cfg.GossipProbeInterval) * time.Second
	mlConfig.ProbeTimeout = 500 * time.Millisecond
	mlConfig.DisableTcpPings = false
	mlConfig.Delegate = g.delegate
	mlConfig.Events = g.events

	// Use a custom logger that prefixes with [p2p].
	mlConfig.Logger = log.New(log.Writer(), "[p2p/memberlist] ", log.LstdFlags)

	// Use our custom transport (gVisor TCP). Start listening first.
	if err := g.transport.Listen(); err != nil {
		return fmt.Errorf("transport listen: %w", err)
	}
	mlConfig.Transport = g.transport

	// Create the memberlist.
	ml, err := memberlist.Create(mlConfig)
	if err != nil {
		return fmt.Errorf("create memberlist: %w", err)
	}
	g.mu.Lock()
	g.memberlist = ml
	g.started = true
	g.mu.Unlock()

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

	log.Printf("[p2p] gossip layer started (mesh IP %s, gossip port %d)",
		g.localMeta.MeshIP, g.cfg.GossipPort)

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
	g.mu.Unlock()

	close(g.stopCh)

	if g.healthTicker != nil {
		g.healthTicker.Stop()
	}

	// Stop the relay session manager if active.
	if rsm != nil {
		rsm.Stop()
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
		for _, pk := range peers {
			if g.wgDelegate.IsHealthy(pk) {
				g.wgDelegate.UpdateHandshakeTime(pk)
			}
		}
	}
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
	g.SetLocalCapabilities(true, g.delegate.getLocalMeta().CapExit, g.delegate.getLocalMeta().CapProxyEntry)

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
	g.SetLocalCapabilities(false, g.delegate.getLocalMeta().CapExit, g.delegate.getLocalMeta().CapProxyEntry)

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
