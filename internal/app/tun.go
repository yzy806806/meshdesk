package app

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/yzy806806/meshdesk/internal/p2p"
)

// integrateTUN wires the TUN layer with the gossip layer: peer
// VirtualIP route sync, auto-dial on join, subnet proxies, session
// death/reconnect cleanup. Called during Start after gossip is up.
func (a *App) integrateTUN() {
	if a.cfg.Mesh.TunEnabled && a.gossipLayer != nil {
		// Wire gossip join/leave handlers to sync kernel routes
		// for peer VirtualIPs. When a peer joins with a VirtualIP,
		// add a /32 route; when it leaves, remove it.
		// Also detect IPAM conflicts: if a new peer claims the
		// same VirtualIP, trigger re-allocation.
		// IMPORTANT: This handler also calls the NAT traversal join
		// handler if NAT traversal is enabled, because
		// SetJoinHandler overwrites (not appends).
		a.gossipLayer.Events().SetJoinHandler(func(meta *p2p.NodeMeta) {
			// NAT traversal (if enabled).
			if a.natJoinHandler != nil {
				a.natJoinHandler(meta)
			}
			// TUN routing.
			if meta.VirtualIP != "" {
				localVIP := a.node.GetTUNVirtualIP()
				if localVIP != nil && localVIP.String() == meta.VirtualIP {
					peerIPs := make(map[string]net.IP)
					for _, pm := range a.gossipLayer.KnownPeers() {
						if pm.VirtualIP != "" {
							peerIPs[pm.PublicKey] = net.ParseIP(pm.VirtualIP)
						}
					}
					a.node.ReallocateAfterGossip(peerIPs)
				}
				a.node.AddPeerVirtualIPRoute(meta.PublicKey, meta.VirtualIP)
			}
			// Auto-establish a smux session with the new peer.
			// NotifyJoin only adds routing state; without an active
			// session the data plane (TUN, monitor, relay) reports
			// "no session for peer" and traffic dies. Dial the peer's
			// advertised endpoint outbound so the mesh is connected
			// as soon as gossip discovers it — the same
			// "discover → dial" model EasyTier uses.
			//
			// Zone-aware: cross-zone (or unknown-zone) peers are
			// Reality-only. The 0x4D auto-dial below is only for
			// same-zone peers; cross-zone connectivity comes from
			// the peer's own Reality outbound session (or manual
			// AddPeer with Reality config).
			if !a.node.SameZone(meta.PublicKey) {
				return
			}
			if a.node.HasActiveSession(meta.PublicKey) {
				return
			}
			if len(meta.Endpoints) == 0 {
				// No advertised endpoint; the peer may be behind
				// NAT. The NAT traversal layer handles it.
				return
			}
			peerKey := meta.PublicKey
			endpoints := append([]string(nil), meta.Endpoints...)

			// Deduplicate concurrent auto-dials for the same peer
			// (memberlist may re-fire NotifyJoin during flaps).
			a.autoDialMu.Lock()
			if a.autoDialInFlight[peerKey] {
				a.autoDialMu.Unlock()
				return
			}
			a.autoDialInFlight[peerKey] = true
			a.autoDialMu.Unlock()

			go func() {
				defer func() {
					a.autoDialMu.Lock()
					delete(a.autoDialInFlight, peerKey)
					a.autoDialMu.Unlock()
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				for _, ep := range endpoints {
					stream, err := a.node.DialPeerByEndpoint(ctx, ep)
					if err == nil {
						stream.Close() // close port-0 stream; session stays
						log.Printf("[mesh] auto-connected to new peer %s at %s", peerKey[:8], ep)
						return
					}
					log.Printf("[mesh] auto-dial %s at %s failed: %v", peerKey[:8], ep, err)
				}
			}()
		})
		a.gossipLayer.Events().SetLeaveHandler(func(peerKey string) {
			// NAT traversal cleanup (if enabled).
			if a.natLeaveHandler != nil {
				a.natLeaveHandler(peerKey)
			}
			// TUN routes are NOT removed on memberlist NotifyLeave.
			// memberlist flaps on UDP ping timeouts — which are
			// the NORM for NAT'd peers in mixed-family meshes
			// (symmetric NAT: no inbound UDP, so probes always
			// fail even while the peer is fully reachable via
			// relay). Removing the VirtualIP route here breaks the
			// TUN return path permanently: the forwarder's
			// ResolveIP finds no route and drops replies, while
			// the smux session (or relay path) is alive.
			// Real death cleanup is handled by the session death
			// handler (smux Done) — keep routes for flap-prone
			// memberlist leaves.
			log.Printf("[p2p] NotifyLeave: keeping TUN routes for peer %s (memberlist flap != session death)", peerKey[:8])
		})

		// Wire the subnet proxy handler: when a peer advertises
		// subnet proxies, add kernel routes via its VirtualIP.
		a.gossipLayer.SetSubnetProxyHandler(func(pubKey, virtualIP string, subnets []string) {
			if len(subnets) > 0 {
				a.node.AddPeerSubnetProxies(pubKey, virtualIP, subnets)
			} else {
				a.node.RemovePeerSubnetProxies(pubKey)
			}
		})

		// Process already-known peers (in case gossip started
		// before the TUN integration was wired).
		for _, meta := range a.gossipLayer.KnownPeers() {
			if meta.VirtualIP != "" {
				a.node.AddPeerVirtualIPRoute(meta.PublicKey, meta.VirtualIP)
			}
			if len(meta.SubnetProxies) > 0 && meta.VirtualIP != "" {
				a.node.AddPeerSubnetProxies(meta.PublicKey, meta.VirtualIP, meta.SubnetProxies)
			}
		}

		// Re-broadcast the local VirtualIP now that gossip is active.
		// During setupTUN (called inside a.node.Start()), a.gossipLayer was
		// still nil, so the VirtualIP broadcast was deferred. Now that
		// gossip is running, we push it so peers can discover our IP.
		//
		// Also handle IPAM conflict: if a peer has the same VirtualIP,
		// re-allocate to a different IP.
		if ti := a.node.TUNIntegration(); ti != nil {
			// Collect peer VirtualIPs from gossip.
			peerIPs := make(map[string]net.IP)
			for _, meta := range a.gossipLayer.KnownPeers() {
				if meta.VirtualIP != "" {
					peerIPs[meta.PublicKey] = net.ParseIP(meta.VirtualIP)
				}
			}
			// Restore TUN /32 routes from the peer cache BEFORE gossip
			// has propagated VirtualIPs (which can take minutes in
			// mixed IP-family meshes). Without this, a restarted node
			// drops TUN packets for peers whose meta hasn't arrived
			// yet — the forwarder's ResolveIP finds no route.
			if cachedVIPs := a.peerCache.CachedVirtualIPs(); len(cachedVIPs) > 0 {
				restored := 0
				for pk, vip := range cachedVIPs {
					if _, ok := peerIPs[pk]; !ok {
						peerIPs[pk] = net.ParseIP(vip)
					}
					if net.ParseIP(vip) != nil {
						a.node.AddPeerVirtualIPRoute(pk, vip)
						restored++
					}
				}
				log.Printf("[tun] restored %d TUN route(s) from peer cache", restored)
			}
			log.Printf("[tun] re-broadcast: %d known peers", len(peerIPs))
			// Debug: confirm our own VirtualIP is set in the local meta.
			if lm := a.gossipLayer.LocalMeta(); lm != nil {
				log.Printf("[tun] local meta: vip=%q seq=%d", lm.VirtualIP, lm.Seq)
			}
			// Re-allocate if there's a conflict.
			a.node.ReallocateAfterGossip(peerIPs)
			// Re-broadcast (may have changed due to re-allocation).
			if vip := a.node.GetTUNVirtualIP(); vip != nil {
				log.Printf("[tun] re-broadcast: setting local vip=%s", vip)
				a.node.SetTUNLocalVirtualIP(vip.String())
				if len(a.cfg.Mesh.SubnetProxy) > 0 {
					a.node.SetTUNSubnetProxies(a.cfg.Mesh.SubnetProxy)
				}
			}
		}

		// Wire the update handler to detect peer VirtualIP changes
		// (including the initial broadcast from re-joined peers).
		a.gossipLayer.Events().SetUpdateHandler(func(meta *p2p.NodeMeta) {
			if meta.VirtualIP == "" {
				return
			}
			// Check for IPAM conflict with local VirtualIP.
			localVIP := a.node.GetTUNVirtualIP()
			if localVIP != nil && localVIP.String() == meta.VirtualIP {
				// Conflict: peer claims the same VirtualIP.
				// Collect all known peer VirtualIPs and re-allocate.
				peerIPs := make(map[string]net.IP)
				for _, pm := range a.gossipLayer.KnownPeers() {
					if pm.VirtualIP != "" {
						peerIPs[pm.PublicKey] = net.ParseIP(pm.VirtualIP)
					}
				}
				a.node.ReallocateAfterGossip(peerIPs)
			}
			a.node.AddPeerVirtualIPRoute(meta.PublicKey, meta.VirtualIP)
			if len(meta.SubnetProxies) > 0 {
				a.node.AddPeerSubnetProxies(meta.PublicKey, meta.VirtualIP, meta.SubnetProxies)
			}
		})

		// Wire the session death handler: when a smux session truly dies
		// (detected by the reconnect watcher), clean up TUN routes.
		// This is the correct cleanup path, as opposed to memberlist
		// NotifyLeave which may fire on UDP flaps while the session is
		// still alive.
		a.node.SetSessionDeathHandler(func(peerKey string) {
			log.Printf("[mesh] session death: cleaning up TUN routes for peer %s", peerKey[:8])
			a.node.RemoveAllTUNRoutesForPeer(peerKey)
		})

		// Wire the session reconnect handler: after a smux session
		// is successfully re-established, re-add TUN routes that
		// were removed by the sessionDeathHandler. Since the peer
		// stays in memberlist, no new NotifyJoin fires, so the
		// join handler never re-runs. This callback fills that gap
		// by looking up the peer's NodeMeta from the gossip layer
		// and re-adding both the /32 route and subnet proxy routes.
		a.node.SetSessionReconnectHandler(func(peerKey string) {
			for _, meta := range a.gossipLayer.KnownPeers() {
				if meta.PublicKey == peerKey {
					if meta.VirtualIP != "" {
						log.Printf("[mesh] reconnect: restoring TUN routes for peer %s (vip=%s)", peerKey[:8], meta.VirtualIP)
						a.node.AddPeerVirtualIPRoute(meta.PublicKey, meta.VirtualIP)
					}
					if len(meta.SubnetProxies) > 0 && meta.VirtualIP != "" {
						a.node.AddPeerSubnetProxies(meta.PublicKey, meta.VirtualIP, meta.SubnetProxies)
					}
					return
				}
			}
			// Fallback to the peer cache: in degraded memberlist
			// (mixed IP-family meshes) the peer's NodeMeta may not
			// have propagated, but its VirtualIP was persisted when
			// the session last worked. Restoring from cache keeps
			// the TUN route alive across reconnects.
			if vip := a.peerCache.CachedVirtualIP(peerKey); vip != "" {
				log.Printf("[mesh] reconnect: restoring TUN route for peer %s from cache (vip=%s)", peerKey[:8], vip)
				a.node.AddPeerVirtualIPRoute(peerKey, vip)
				return
			}
			log.Printf("[mesh] reconnect: peer %s not found in gossip KnownPeers or cache, skipping TUN route restoration", peerKey[:8])
		})

		log.Printf("  TUN:        gossip integration active (VirtualIP routing + subnet proxy)")
	}
}
