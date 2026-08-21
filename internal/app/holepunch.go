package app

import (
	"context"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/yzy806806/meshdesk/internal/holepunch"
	"github.com/yzy806806/meshdesk/internal/mesh"
)

// startHolePunch wires the memberlist-independent hole-punching engine
// into the app:
//
//  1. STUN discovery of our mapped endpoint + NAT type.
//  2. Register the coordination virtual port (0x504A) so peers can
//     exchange punch params over an existing smux session / relay.
//  3. Trigger punches on session-established peers (meta exchange —
//     memberlist-independent) with their advertised endpoints.
//  4. Feed successful holes into the UDP multipath (DialUDPPeer).
func (a *App) startHolePunch() {
	if a.node == nil {
		return
	}
	hp := holepunch.New(&appHolepunchDialer{node: a.node})
	// Our public key (hex) — carried in the punch coordination frame
	// so the responder can key the hole by identity and establish the
	// data plane on its side too (v1.6.7 deadlock fix).
	hp.IdentityKey = a.node.Identity().PublicKey
	// Punch from the mesh mux UDP socket — the punched NAT mapping is
	// exactly what DialTUNUDP (data plane) uses.
	if mt := a.node.MuxTransport(); mt != nil {
		hp.PunchConnProvider = mt.UDPConnFor
		// Register every kept-alive punch socket with the transport:
		// the punchSocketPoller then starts a reader loop that drains
		// the peer's kx/TUN frames into the UDP mesh manager. Without
		// this the hole "establishes" but the peer's frames arrive
		// into a socket nobody reads → "key exchange ... EOF".
		// Registered under BOTH the peer key (punchUDP) and the
		// remote endpoint string (coordinator pre-answer) so
		// PunchSocket() finds it by either lookup.
		hp.OnPunchSocket = func(key string, conn *net.UDPConn) {
			if mt := a.node.MuxTransport(); mt != nil {
				mt.AddPunchSocket(key, conn)
				// Also register under the IP-only form so a
				// data-plane dial to a different port of the
				// same peer still finds the punch socket.
				if ua, err := net.ResolveUDPAddr("udp", key); err == nil {
					mt.AddPunchSocketAddr(ua.IP.String(), conn)
				}
			}
		}
		hp.OnPunchSocketRemove = func(key string) {
			if mt := a.node.MuxTransport(); mt != nil {
				mt.RemovePunchSocket(key)
				// Also remove the IP-only form.
				if ua, err := net.ResolveUDPAddr("udp", key); err == nil {
					mt.RemovePunchSocket(ua.IP.String())
				}
			}
		}
	}

	// TCP hole-punch port (mesh port + 1): punchTCP opens its own
	// listener here (fixed port = fixed source port = conntrack match).
	// No resident listener — punchTCP owns it during each attempt.
	if a.cfg.Mesh.Port > 0 {
		hp.TcpPort = a.cfg.Mesh.Port + 1
		hp.SrcPort = hp.TcpPort
		log.Printf("  HolePunch: TCP punch port :%d (conntrack punch)", hp.TcpPort)
	}
	a.holepunch = hp

	// Clean up hole-punch state (sockets, per-peer maps) when a
	// session dies so resources don't accumulate across reconnects.
	a.node.SetSessionDeathHandler(func(peerKey string) {
		hp.CleanupPeer(peerKey)
	})

	// 1. STUN discovery (best-effort — punching still works with the
	//    config-advertised endpoints when STUN is unreachable).
	if res, err := holepunch.DiscoverFrom(0, 5*time.Second); err == nil {
		hp.SetLocalInfo(res.MappedEP, res.NatType)
		hp.EasySym = res.EasySym
		if res.Inc > 0 {
			hp.Inc = 1
		} else if res.Inc < 0 {
			hp.Inc = 0xFE
		}
		log.Printf("  HolePunch: STUN mapped %s (nat=%v, easySym=%v inc=%d)", res.MappedEP, res.NatType, res.EasySym, res.Inc)
	} else {
		log.Printf("  HolePunch: STUN discovery failed (%v) — using advertised endpoints", err)
	}

	// Public punch endpoint: prefer the FIRST configured advertise
	// endpoint (config order — admins list reachable endpoints first;
	// forcing IPv6-first here is wrong when the v6 link is down, e.g.
	// txcloud↔Oracle where v6 times out but v4 conntrack-punches).
	// Fall back to STUN.
	if len(a.cfg.P2P.AdvertiseEndpoints) > 0 {
		hp.PublicPunchEP = a.cfg.P2P.AdvertiseEndpoints[0]
		log.Printf("  HolePunch: punch endpoint %s (config)", hp.PublicPunchEP)
	}
	if hp.PublicPunchEP == "" && a.cfg.Mesh.Port > 0 {
		// Fall back to STUN public IP + mesh port.
		if res, err := holepunch.DiscoverFrom(0, 5*time.Second); err == nil {
			if host, _, herr := net.SplitHostPort(res.MappedEP); herr == nil {
				hp.PublicPunchEP = net.JoinHostPort(host, strconv.Itoa(a.cfg.Mesh.Port))
				log.Printf("  HolePunch: punch endpoint %s (STUN)", hp.PublicPunchEP)
			}
		}
	}

	// 2. Register the coordination port.
	ln, err := a.node.ListenVirtualPort(holepunch.HolePunchVirtualPort)
	if err != nil {
		log.Printf("  HolePunch: coordinator port registration failed: %v", err)
	} else {
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go hp.HandleCoordinatorStream(conn)
			}
		}()
		log.Printf("  HolePunch: coordinator on virtual port 0x%X", holepunch.HolePunchVirtualPort)
	}

	// 3. Trigger punches on session-established peers (zone-aware:
	//    same-zone only — cross-zone stays Reality-only).
	a.node.SetSessionEstablishedHandler(func(peerKey string) {
		a.triggerHolePunch(hp, peerKey)
	})

	// 4. Feed holes into the UDP multipath: record the punched
	//    endpoint as a learned endpoint so getUDPStream's resolver
	//    dials the hole (same-zone UDP data plane), then verify with
	//    a quick DialUDPPeer.
	hp.OnHoleEstablished = func(peerKey, punchedEP, holeType string) {
		// Data-plane target: the punched endpoint itself. The old
		// code rebuilt the target as host(punchedEP)+peerObsPort —
		// but the peer's kx/data actually egresses from its MUX
		// socket (the exchanged PublicPunchEP — the mesh port,
		// 52888 by default from cfg.Mesh.Port): DialUDP uses
		// the mux socket as source, so the conntrack-matched target
		// IS the punched endpoint's port, not the ephemeral obsPort.
		// (obsPort is the peer's INDEPENDENT probe socket port —
		// wrong target, and when punchedEP was an unreachable v6 the
		// rebuilt target pointed into the void.)
		target := punchedEP
		log.Printf("  HolePunch: data-plane target %s", target)
		// Record the CONFIRMED hole endpoint in the dedicated hole
		// map (NOT SetLearnedEndpoints — the meta exchange overwrites
		// that with gossip endpoints carrying the TCP port, which is
		// a dead UDP target once ordinary nodes use random UDP ports).
		a.node.SetHoleEndpoint(peerKey, target)
		// The TUN data plane may be stuck in UDP failure cooldown from
		// a previous endpoint (e.g. unreachable v6). A successful hole
		// means the endpoint CHANGED — reset the cooldown so the next
		// TUN packet immediately re-attempts the UDP path instead of
		// staying on relay for up to 10 minutes.
		a.node.ResetPeerUDPCooldown(peerKey)
		if holeType == "tcp" {
			// TCP hole: dial a full mesh session over the punched
			// TCP endpoint — the reliable data plane (EasyTier-style).
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				if stream, err := a.node.DialPeerByEndpoint(ctx, punchedEP); err == nil {
					stream.Close()
					log.Printf("  HolePunch: TCP session live to %s via %s", peerKey[:8], punchedEP)
				} else {
					log.Printf("  HolePunch: TCP session over hole failed: %v", err)
				}
			}()
			return
		}
		go func() {
			// Key-based dial arbitration: smaller public key dials
			// (CLIENT), the other serves (SERVER).
			shouldDial := a.node.Identity().PublicKey < peerKey
			if !shouldDial {
				log.Printf("  HolePunch: %s is SERVER (our key > peer key), waiting for peer to dial", peerKey[:8])
				// Wait for the CLIENT's kx to arrive. If it doesn't
				// within 15s, the CLIENT's UDP kx likely failed (VCN
				// packet filtering). Try TCP fallback: dial the peer's
				// mesh port directly (conntrack from UDP probe may
				// pass TCP SYNs too).
				go func() {
					time.Sleep(15 * time.Second)
					if !a.node.HasUDPHole(peerKey) {
						return // already cleared by CLIENT
					}
					// Try TCP fallback to peer's advertised endpoint.
					if eps := a.node.PeerEndpoints(peerKey); len(eps) > 0 {
						tcpCtx, tcpCancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer tcpCancel()
						if stream, err := a.node.DialPeerByEndpoint(tcpCtx, eps[0]); err == nil {
							stream.Close()
							log.Printf("  HolePunch: %s SERVER TCP fallback live via %s", peerKey[:8], eps[0])
							return // TCP path established, keep hole endpoint
						}
					}
					// Both paths failed — clear for retry.
					a.node.ClearHoleEndpoint(peerKey)
					hp.ResetHoleState(peerKey)
					log.Printf("  HolePunch: %s SERVER timed out — clearing stale hole endpoint", peerKey[:8])
				}()
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if stream, err := a.node.DialUDPPeer(ctx, target); err == nil {
				stream.Close()
				log.Printf("  HolePunch: UDP multipath live to %s via %s", peerKey[:8], target)
			} else {
				log.Printf("  HolePunch: UDP dial over hole failed: %v", err)
				// UDP kx failed (likely VCN packet-length filtering:
				// small probes pass but large kx frames are dropped).
				// Try a direct TCP mesh session to the peer's mesh port
				// (52888) — the conntrack entry from the UDP probe may
				// let TCP SYNs through too (stateful firewall passes
				// RELATED/ESTABLISHED). This is EasyTier's tcp tunnel.
				// Use the peer's advertised endpoint, not the punched
				// endpoint (which has a random UDP port, no TCP listener).
				if eps := a.node.PeerEndpoints(peerKey); len(eps) > 0 {
					tcpTarget := eps[0]
					// Strip port and use mesh port (52888) — PeerEndpoints
					// may carry the TCP mesh port already.
					tcpCtx, tcpCancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer tcpCancel()
					if stream, err := a.node.DialPeerByEndpoint(tcpCtx, tcpTarget); err == nil {
						stream.Close()
						log.Printf("  HolePunch: TCP fallback live to %s via %s", peerKey[:8], tcpTarget)
						return // TCP path established, keep hole endpoint
					} else {
						log.Printf("  HolePunch: TCP fallback also failed: %v", err)
					}
				}
				// Both UDP and TCP failed — clear for retry.
				a.node.ClearHoleEndpoint(peerKey)
				hp.ResetHoleState(peerKey)
				log.Printf("  HolePunch: %s clearing hole endpoint (both UDP+TCP failed)", peerKey[:8])
			}
		}()
	}

	// Lazy scan: meta-learned peers (degraded memberlist — no direct
	// session, so SetSessionEstablishedHandler never fires) still get
	// punched. Scan the routing table every 30s for same-zone peers.
	// ALSO include config peers: after a full restart (both ends) the
	// meta map is empty (meta needs a session, a session needs a hole)
	// — without config peers the punch engine never self-starts and
	// the mesh stays disconnected until manual intervention.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				vips := a.node.PeerVirtualIPs()
				seen := make(map[string]bool, len(vips))
				for peerKey := range vips {
					seen[peerKey] = true
					a.triggerHolePunch(hp, peerKey)
				}
				for _, pc := range a.node.ConfigPeers() {
					if !seen[pc.PublicKey] {
						a.triggerHolePunch(hp, pc.PublicKey)
					}
				}
			case <-a.node.Context().Done():
				return
			}
		}
	}()
}

// triggerHolePunch fires a punch for a same-zone peer when we know its
// advertised endpoints (from gossip meta). Zone-unknown peers are
// still punched (hole failure is harmless — relay fallback covers it).
func (a *App) triggerHolePunch(hp *holepunch.Engine, peerKey string) {	if a.holepunch == nil {
		log.Printf("[holepunch] %s: trigger skipped — holepunch engine nil", peerKey[:8])
		return
	}
	// Fail-closed zone gate.
	peerZone := a.node.PeerZone(peerKey)
	myZone := a.node.LocalZone()
	if peerZone == "" || !a.node.SameZone(peerKey) {
		log.Printf("[holepunch] %s: trigger skipped — zone gate (my=%q peer=%q)", peerKey[:8], myZone, peerZone)
		return
	}
	if a.node.HasUDPHole(peerKey) {
		return
	}
	var endpoints []string
	if eps := a.node.PeerEndpoints(peerKey); len(eps) > 0 {
		endpoints = eps
	}
	log.Printf("[holepunch] %s: trigger fired (endpoints=%d)", peerKey[:8], len(endpoints))
	hp.Trigger(peerKey, endpoints, holepunchNatType(""))
}

// appHolepunchDialer adapts *mesh.MeshNode to holepunch.Dialer.
type appHolepunchDialer struct {
	node *mesh.MeshNode
}

func (d *appHolepunchDialer) DialVirtualPort(ctx context.Context, peerKey string, port int) (net.Conn, error) {
	return d.node.DialVirtualPort(ctx, peerKey, port)
}

// holepunchNatType converts the gossip NodeMeta NAT string to the
// holepunch enum (best-effort mapping; unknown strings → NatUnknown).
func holepunchNatType(s string) holepunch.NatType {
	switch s {
	case "fullcone", "full_cone":
		return holepunch.NatFullCone
	case "restricted", "address_restricted":
		return holepunch.NatRestricted
	case "portrestricted", "port_restricted", "portrestrictedcone":
		return holepunch.NatPortRestricted
	case "symmetric":
		return holepunch.NatSymmetric
	}
	return holepunch.NatUnknown
}
