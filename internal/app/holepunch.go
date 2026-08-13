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
	// Punch from the mesh mux UDP socket — the punched NAT mapping is
	// exactly what DialTUNUDP (data plane) uses.
	if mt := a.node.MuxTransport(); mt != nil {
		hp.PunchConnProvider = mt.UDPConnFor
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

	// 1. STUN discovery (best-effort — punching still works with the
	//    config-advertised endpoints when STUN is unreachable).
	if res, err := holepunch.DiscoverFrom(0, 5*time.Second); err == nil {
		hp.SetLocalInfo(res.MappedEP, res.NatType)
		log.Printf("  HolePunch: STUN mapped %s (nat=%v)", res.MappedEP, res.NatType)
	} else {
		log.Printf("  HolePunch: STUN discovery failed (%v) — using advertised endpoints", err)
	}

	// Public punch endpoint: prefer a public IPv6 advertise endpoint
	// (v6 has no NAT — holes open directly), else the configured v4
	// endpoint, else STUN.
	for _, ep := range a.cfg.P2P.AdvertiseEndpoints {
		if host, _, herr := net.SplitHostPort(ep); herr == nil {
			if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
				hp.PublicPunchEP = ep
				log.Printf("  HolePunch: punch endpoint %s (config v6)", ep)
				break
			}
		}
	}
	if hp.PublicPunchEP == "" && len(a.cfg.P2P.AdvertiseEndpoints) > 0 {
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
		a.node.SetLearnedEndpoints(peerKey, []string{punchedEP})
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
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if stream, err := a.node.DialUDPPeer(ctx, punchedEP); err == nil {
				stream.Close()
				log.Printf("  HolePunch: UDP multipath live to %s via %s", peerKey[:8], punchedEP)
			} else {
				log.Printf("  HolePunch: UDP dial over hole failed: %v", err)
			}
		}()
	}

	// Lazy scan: meta-learned peers (degraded memberlist — no direct
	// session, so SetSessionEstablishedHandler never fires) still get
	// punched. Scan the routing table every 30s for same-zone peers.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				for peerKey := range a.node.PeerVirtualIPs() {
					a.triggerHolePunch(hp, peerKey)
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
func (a *App) triggerHolePunch(hp *holepunch.Engine, peerKey string) {
	if a.holepunch == nil {
		return
	}
	if !a.node.SameZone(peerKey) && a.node.PeerZone(peerKey) != "" {
		// Known different zone — never punch (Reality-only).
		return
	}
	var endpoints []string
	// Meta-exchange learned endpoints first (memberlist-independent —
	// propagated via smux session meta, works when gossip is degraded).
	if eps := a.node.PeerEndpoints(peerKey); len(eps) > 0 {
		endpoints = eps
	} else if a.gossipLayer != nil {
		for _, meta := range a.gossipLayer.KnownPeers() {
			if meta.PublicKey == peerKey && len(meta.Endpoints) > 0 {
				endpoints = meta.Endpoints
				break
			}
		}
	}
	// Always trigger — with no endpoints the engine still coordinates
	// over the mesh (0x504A) to discover the peer's mapped address.
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
