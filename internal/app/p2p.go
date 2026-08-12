package app

import (
	"encoding/hex"
	"log"
	"os"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/p2p"
)

// constructP2P creates the gossip layer, peer cache and NAT traversal
// objects (nothing started). Static-peer connects, gl.Start, relay
// path builder and NAT traversal start happen in startP2P.
func (a *App) constructP2P() error {
	cfg, node := a.cfg, a.node

	// Create the WireGuard delegate for dynamic peer management.
	wgDelegate := p2p.NewWireGuardDelegate(node)
	a.wgDelegate = wgDelegate
	for _, peerCfg := range cfg.Peers {
		wgDelegate.MarkStaticPeer(peerCfg.PublicKey)
	}

	if !cfg.P2P.Enabled {
		return nil
	}

	p2pCfg := p2p.FromConfig(cfg.P2P)
	p2pCfg.GossipPort = cfg.Mesh.GossipPort
	p2pCfg.WgPort = cfg.Mesh.Port

	identityBytes, err := hex.DecodeString(node.Identity().PrivateKey)
	if err != nil {
		return err
	}
	gl, err := p2p.NewGossipLayer(p2pCfg, identityBytes, wgDelegate)
	if err != nil {
		return err
	}
	gl.SetWireGuardDelegate(wgDelegate)
	a.gossipLayer = gl
	a.gossipP2pCfg = p2pCfg

	// Peer cache for persisted discovered endpoints.
	peerCache := p2p.NewPeerCache(cfg.P2P.PeerCachePath)
	if err := peerCache.Load(); err != nil {
		log.Printf("Warning: failed to load peer cache: %v (starting fresh)", err)
	}
	gl.SetPeerCache(peerCache)
	a.peerCache = peerCache

	// Merge cached peer endpoints into the seed list.
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

	// Inject the MuxTransport so gossip and Reality TLS share the port.
	if mt := node.MuxTransport(); mt != nil {
		gl.SetTransport(mt)
	}

	// Local identity + zone + capabilities.
	hostname := cfg.Node.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	role := "agent"
	if a.webMode {
		role = "web"
	}
	gl.SetLocalIdentity(hostname, role)
	gl.SetLocalZone(cfg.Mesh.Zone)
	node.SetZoneLearner(func(peerKey string) string {
		if z := gl.PeerZone(peerKey); z != "" {
			return z
		}
		return ""
	})
	gl.SetLocalCapabilities(
		true, // stream relay handler is always registered
		len(cfg.Proxy.Exit.AllowedPorts) > 0 || cfg.Proxy.Exit.AllowAllPorts,
		cfg.Proxy.SS.Port != 0,
		a.webMode,
	)

	// NAT traversal object (started in startP2P).
	if cfg.P2P.NatTraversal {
		natCfg := p2p.NatTraversalFromP2pConfig(p2pCfg)
		a.natTraversal = p2p.NewNatTraversal(
			natCfg,
			wgDelegate,
			gl.Relay(),
			gl.Events(),
			cfg.Mesh.Port,
		)
	}
	return nil
}

// startP2P connects static peers, starts gossip, wires relay path
// builder + NAT traversal, and registers join/leave handlers.
func (a *App) startP2P() error {
	cfg, node := a.cfg, a.node

	// Connect statically configured peers.
	for _, peerCfg := range cfg.Peers {
		if peerCfg.Endpoint != "" {
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
				log.Printf("  Peer %s: REALITY TLS failed, relying on gossip discovery", pc.Endpoint)
			}(peerCfg)
		}
	}

	if !cfg.P2P.Enabled || a.gossipLayer == nil {
		return nil
	}
	gl := a.gossipLayer

	if err := gl.Start(); err != nil {
		log.Printf("Warning: failed to start P2P gossip layer: %v", err)
	} else {
		// Wire the peer-link (global topology) handler + periodic broadcast.
		gl.SetPeerLinkHandler()
		go func() {
			direct := func() map[string]int64 {
				links := make(map[string]int64)
				if node == nil {
					return links
				}
				for _, meta := range gl.KnownPeers() {
					if sess := node.GetSession(meta.PublicKey); sess != nil && !sess.IsClosed() {
						links[meta.PublicKey] = int64(meta.RTTUs)
					}
				}
				return links
			}
			bcast := func(m *p2p.PeerLinkMessage) {
				gl.BroadcastPeerLink(m)
			}
			stop := gl.LinkMap().PeriodicBroadcaster(30*time.Second, direct, bcast)
			<-node.Context().Done()
			stop()
		}()
		log.Printf("  P2P:       gossip active (port %d, %d seeds)",
			cfg.Mesh.GossipPort, len(cfg.P2P.Seeds))
	}

	// Enable relay mode if --relay flag or config.
	if a.relayMode || cfg.Proxy.Relay.Enabled {
		maxCircuits := cfg.Proxy.Relay.MaxCircuits
		if maxCircuits <= 0 {
			maxCircuits = 1024
		}
		if err := gl.EnableRelayMode(maxCircuits); err != nil {
			log.Printf("Warning: failed to enable relay mode: %v", err)
		} else {
			log.Printf("  P2P:       relay mode active (maxCircuits=%d)", maxCircuits)
		}
	}

	// Relay path builder for NAT peer relay selection.
	localKey := node.Identity().PublicKey
	rpb := p2p.NewRelayPathBuilder(gl, a.wgDelegate, gl.Relay(), gl.Events(), localKey)
	if impl, ok := rpb.(*p2p.RelayPathBuilderImpl); ok {
		impl.SetRTTEstimator(gl.EstimateRTT)
	}
	gl.Events().SetRelayPathBuilder(rpb)
	if impl, ok := rpb.(*p2p.RelayPathBuilderImpl); ok {
		impl.StartReconciliationLoop()
	}
	if rsm := gl.RelaySessionManager(); rsm != nil {
		rsm.SetRelayPathBuilder(rpb)
	}
	a.relayPathBuilder = rpb

	// NAT traversal start + join/leave handlers.
	if a.natTraversal != nil {
		natTraversal := a.natTraversal
		var natJoinHandler func(meta *p2p.NodeMeta)
		var natLeaveHandler func(peerKey string)

		natJoinHandler = func(meta *p2p.NodeMeta) {
			// Zone-aware: only hole-punch peers in the SAME zone.
			if !node.SameZone(meta.PublicKey) {
				return
			}
			natTraversal.InitiateConnection(meta.PublicKey, meta.Endpoints, p2p.NatType(meta.NatType))
		}
		natLeaveHandler = func(peerKey string) {
			natTraversal.RemoveConnection(peerKey)
		}

		if err := natTraversal.Start(); err != nil {
			log.Printf("Warning: failed to start NAT traversal: %v", err)
		} else {
			log.Printf("  P2P:       NAT traversal active (STUN + hole-punch + relay fallback)")
		}
		natTraversal.SetGossipLayer(gl)

		// If TUN is not enabled, register NAT handlers directly.
		if !(cfg.Mesh.TunEnabled && gl != nil) {
			gl.Events().SetJoinHandler(natJoinHandler)
			gl.Events().SetLeaveHandler(natLeaveHandler)
		}
	}
	return nil
}

// stopGossip stops the gossip layer (sends LeaveNotice).
func (a *App) stopGossip() {
	if a.gossipLayer != nil {
		a.gossipLayer.Stop()
	}
}
