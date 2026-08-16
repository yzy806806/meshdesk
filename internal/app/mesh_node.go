package app

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/yzy806806/meshdesk/internal/mesh"
)

// constructMeshNode creates the core mesh node. Callback wiring
// (TUN providers, relay meta, endpoint resolver) happens separately in
// wireMeshNodeCallbacks (called by app.wire() during Build) so the
// wiring has one home.
func (a *App) constructMeshNode() error {
	node, err := mesh.New(a.cfg)
	if err != nil {
		return err
	}
	a.node = node
	return nil
}

// wireMeshNodeCallbacks wires the mesh node's cross-layer callbacks.
// The gossip layer has been removed; all callbacks that previously
// propagated state through gossip are now no-ops or rely on the
// mesh session meta exchange (META protocol) which is
// memberlist-independent.
func (a *App) wireMeshNodeCallbacks() {
	cfg, node := a.cfg, a.node

	// TUN IPAM peer meta provider — so setupTUN can query known peer
	// VirtualIPs for conflict resolution. Sourced from the mesh
	// session meta exchange (PeerVirtualIPs), not gossip.
	if cfg.Mesh.TunEnabled {
		node.SetPeerMetaProvider(func() map[string]string {
			return node.PeerVirtualIPs()
		})
	}

	// TUN VirtualIP + subnet proxy + ACL broadcasters — no-ops now
	// (gossip layer removed). The mesh session meta exchange handles
	// VirtualIP propagation.
	if cfg.Mesh.TunEnabled {
		node.SetVirtualIPBroadcaster(func(vip string) {})
		node.SetSubnetProxyBroadcaster(func(subnets []string) {})
		node.SetACLRulesBroadcaster(func(rules []string) {})
	}

	// Relay metadata provider — RTT-sorted, health-filtered relay
	// candidates. Sources (memberlist-independent):
	//   1. META-learned relay knowledge (works without gossip),
	//   2. static config peers.
	node.SetRelayMetaProvider(func() []mesh.RelayPeerInfo {
		var result []mesh.RelayPeerInfo
		seen := make(map[string]bool)
		// 1. META-learned candidates (memberlist-independent).
		for _, key := range node.SessionPeerKeys() {
			info, ok := node.PeerRelayMetaInfo(key)
			if !ok || !info.CapRelay {
				continue
			}
			seen[key] = true
			result = append(result, mesh.RelayPeerInfo{
				PeerKey:      key,
				RTT:          node.PeerRTT(key),
				CapRelay:     true,
				MaxCircuits:  info.MaxCircuits,
				LoadCircuits: info.LoadCircuits,
				NatType:      info.NatType,
			})
		}
		// 2. Static config peers.
		for _, pc := range cfg.Peers {
			if pc.PublicKey == "" || seen[pc.PublicKey] {
				continue
			}
			seen[pc.PublicKey] = true
			result = append(result, mesh.RelayPeerInfo{
				PeerKey:  pc.PublicKey,
				CapRelay: true,
			})
		}
		return result
	})

	// Local relay/NAT knowledge advertised in META (memberlist-
	// independent). Sourced from the mesh node itself, not gossip.
	node.SetLocalMetaExtras(func() mesh.MetaRelayInfo {
		return mesh.MetaRelayInfo{}
	})

	// Peer endpoint resolver — use the mesh session meta exchange
	// (PeerEndpoints), not gossip.
	node.SetPeerEndpointResolver(func(peerKey string) string {
		eps := node.PeerEndpoints(peerKey)
		if len(eps) > 0 {
			return eps[0]
		}
		return ""
	})
}

// startMeshNode starts the core node and logs identity info.
func (a *App) startMeshNode() error {
	if err := a.node.Start(); err != nil {
		return err
	}
	log.Printf("MeshDesk %s started (commit=%s, built=%s)", a.Version, a.Commit, a.BuildTime)
	log.Printf("  Public key: %s", a.node.Identity().PublicKey)
	log.Printf("  Mesh port:  %d", a.cfg.Mesh.Port)
	log.Printf("  Peers:      %d", a.node.RoutingTable().PeerCount())
	return nil
}

// stopMeshNode closes the core node.
func (a *App) stopMeshNode() {
	if a.node != nil {
		a.node.Close()
	}
}

// registerVirtualPortServices registers the node's virtual-port
// services (relay, ping, meta exchange). Called during Start after the
// node is up (order preserved from the original main()).
func (a *App) registerVirtualPortServices() {
	node := a.node

	// Smux stream relay handler — ALWAYS registered: every node may be
	// the relay target for peers that cannot connect directly.
	relayHandler, err := node.RegisterRelayHandler()
	if err != nil {
		log.Printf("Warning: failed to register smux relay handler: %v", err)
	} else {
		relayHandler.OnRelayDial = func(dial *mesh.MeshRelayDial, conn net.Conn) {
			targetPort := int(dial.Port)
			if targetPort == 0 {
				// Legacy peer (pre-port-field): echo to keep the stream alive.
				log.Printf("[mesh-relay] OnRelayDial: port=0 (legacy), echoing stream (tunnel=%s)", dial.TunnelID[:min(len(dial.TunnelID), 16)])
				go func() {
					io.Copy(conn, conn)
					conn.Close()
				}()
				return
			}
			localConn, dErr := node.DialLocalVirtualPort(targetPort, dial.InitiatorKey)
			if dErr != nil {
				log.Printf("[mesh-relay] OnRelayDial: failed to dial local virtual port %d: %v (tunnel=%s)",
					targetPort, dErr, dial.TunnelID[:min(len(dial.TunnelID), 16)])
				conn.Close()
				return
			}
			log.Printf("[mesh-relay] OnRelayDial: bridging relay stream to local port %d (tunnel=%s)",
				targetPort, dial.TunnelID[:min(len(dial.TunnelID), 16)])
			go mesh.RelayStream(conn, localConn)
		}
		log.Printf("  Smux relay: listening on virtual port 0x524C (maxTunnels=%d, OnRelayDial=wired)", mesh.DefaultMaxRelayTunnels)
	}
	a.relayHandler = relayHandler

	// Ping handler (session echo — PeerRTT).
	if err := node.RegisterPingHandler(); err != nil {
		log.Printf("Warning: failed to register ping handler: %v", err)
	}

	// Meta exchange (P1): VirtualIP knowledge floods the smux session
	// graph — works even when memberlist is degraded.
	if me, err := node.RegisterMetaExchanger(); err == nil {
		a.metaExchanger = me
		node.SetSessionEstablishedHandler(func(peerKey string) {
			me.NotifyPeerJoined(peerKey)
			// A new session means the peer graph CHANGED — re-broadcast
			// our full knowledge to every session peer so they learn
			// about this new peer (and its zone/endpoints/collector
			// capability). Without this, meta is only exchanged once
			// per session pair at establishment time: a peer that
			// joins AFTER our session with an intermediary was set up
			// never reaches us (relay-attached AMD was invisible to
			// txcloud — no punch triggered because its zone was
			// unknown). Broadcast is idempotent (peers dedup by VIP)
			// and cheap at mesh scale.
			me.Broadcast()
		})
		// Wire META re-broadcast: collector capability changes (this
		// node became a collector, or learned a new one) must reach
		// peers that already exchanged meta — otherwise relay-attached
		// nodes never learn where to push metrics.
		node.SetMetaBroadcaster(me.Broadcast)
		log.Printf("  Meta:       session meta exchange active (virtual port 0x%x)", mesh.MetaVirtualPort)
	} else {
		log.Printf("Warning: meta exchange failed to start: %v", err)
	}

	// Cluster FileServer (T1.1) — restricted to file_transfer_paths.
	if _, err := node.RegisterFileServer(mesh.FileServerConfig{
		AllowedPaths: a.cfg.Mesh.FileTransferPaths,
	}); err != nil {
		log.Printf("Warning: failed to register cluster file server: %v", err)
	}

	// Remote command executor (T2.1) — one-click node updates.
	if _, err := node.RegisterCommandServer(); err != nil {
		log.Printf("Warning: failed to register command server: %v", err)
	}

	// SOCKS5 exit handler on virtual port 0x5350 (every node by default).
	socks5Cfg := mesh.SOCKS5Config{
		DialTimeout:       time.Duration(a.cfg.Proxy.SOCKS5.DialTimeoutSec) * time.Second,
		IdleTimeout:      time.Duration(a.cfg.Proxy.SOCKS5.IdleTimeoutSec) * time.Second,
		AllowAllPorts:     a.cfg.Proxy.SOCKS5.AllowAllPorts,
		DestinationFilter: a.cfg.Proxy.SOCKS5.DestinationFilter,
		MaxConnections:    a.cfg.Proxy.SOCKS5.MaxConnections,
		AllowedPeers:      a.cfg.Proxy.SOCKS5.AllowedPeers,
		RequireMeshPeer:   a.cfg.Proxy.SOCKS5.RequireMeshPeer,
	}
	if !socks5Cfg.AllowAllPorts && len(a.cfg.Proxy.SOCKS5.AllowedPorts) > 0 {
		socks5Cfg.AllowedPorts = make(map[int]bool, len(a.cfg.Proxy.SOCKS5.AllowedPorts))
		for _, p := range a.cfg.Proxy.SOCKS5.AllowedPorts {
			socks5Cfg.AllowedPorts[p] = true
		}
	}
	if _, err := node.RegisterSOCKS5Handler(socks5Cfg); err != nil {
		log.Printf("Warning: failed to register SOCKS5 handler: %v", err)
	} else {
		log.Printf("  SOCKS5 proxy: listening on virtual port 0x5350 (maxConns=%d)", socks5Cfg.MaxConnections)
	}
}
