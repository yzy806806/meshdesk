// Package app — SOCKS5 entry/exit + proxy entry node.
package app

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"context"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/proxy"
)

// EntryManager is the interface the web layer uses to manage the SOCKS5
// entry listener dynamically (save-on-Dashboard → restart). The proxy
// subsystem implements it; web.go depends on this interface, not the
// concrete type — breaking the web→proxy reverse dependency.
type EntryManager interface {
	// EntryStatus returns current entry listener config/status.
	EntryStatus() map[string]any
	// ApplyEntry applies a new entry config (listener may restart).
	ApplyEntry(listen, username, password string, exitNodes []string) error
}

// startProxyCircuit starts the legacy SS-based proxy entry node and
// the circuit exit node (deprecated in favor of SOCKS5 0x5350, but kept
// for proxy.ss.enabled configs).
func (a *App) startProxyCircuit() {
	meshDialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		return a.node.Dial(ctx, network, address)
	}
	var proxyEntryNode *proxy.EntryNode
	var proxyExitNode *proxy.ExitNode

	// Create a shared security event sink for all proxy subsystems.
	// When a web server is running, its AlertStore callback is wired
	// after the web server is created (see alert wiring below).
	proxySecSink := proxy.NewSecurityEventSink()
	a.proxySecSink = proxySecSink

	// ── Entry Node (Legacy SS) ──
	// The SS-based entry node accepts Shadowsocks connections and dispatches
	// them through multi-path circuits to the exit a.node.
	//
	// DEPRECATED: SOCKS5 over Reality TLS (virtual port 0x5350) is the
	// default proxy entry. The SS entry node is only started when
	// proxy.ss.enabled is explicitly set to true. The SOCKS5 handler
	// is registered separately via RegisterSOCKS5ForwardHandler/ExitHandler.
	if a.cfg.Proxy.SS.Enabled && a.cfg.Proxy.SS.Port != 0 && a.cfg.Proxy.ExitAddr != "" {
		ssListenAddr := a.cfg.Proxy.SS.ListenAddr
		if ssListenAddr == "" {
			ssListenAddr = fmt.Sprintf(":%d", a.cfg.Proxy.SS.Port)
		}

		// Build circuit config from the YAML config.
		circuitCfg := proxy.CircuitConfig{
			IdleTimeout:         time.Duration(a.cfg.Proxy.Circuit.IdleTimeout) * time.Second,
			KeepaliveInterval:   time.Duration(a.cfg.Proxy.Circuit.KeepaliveInterval) * time.Second,
			NACKTimeout:         time.Duration(a.cfg.Proxy.Circuit.NACKTimeout) * time.Second,
			OrphanTimeout:       time.Duration(a.cfg.Proxy.Circuit.OrphanTimeout) * time.Second,
			MaxReassemblyWindow: a.cfg.Proxy.Circuit.MaxReassemblyWindow,
		}
		if circuitCfg.IdleTimeout == 0 {
			circuitCfg = proxy.DefaultCircuitConfig()
		}

		entryCfg := proxy.EntryNodeConfig{
			SSConfig: proxy.SSConfig{
				Password:   a.cfg.Proxy.SS.Password,
				Cipher:     a.cfg.Proxy.SS.Cipher,
				ListenAddr: ssListenAddr,
			},
			CircuitCfg:       circuitCfg,
			ChunkerStrategy:  a.cfg.Proxy.ChunkerStrategy,
			ChunkerCfg:       proxy.DefaultChunkerConfig(),
			DebugFixedChunks: a.cfg.Proxy.DebugFixedChunks,
			ExitAddr:         a.cfg.Proxy.ExitAddr,
			DialFunc:         meshDialFunc,
			SecSink:          proxySecSink,
		}

		// Configure path selection.
		if a.cfg.Proxy.PathSelection.Mode == "auto" {
			entryCfg.PathSelectionMode = "auto"
			entryCfg.PathSelector = proxy.NewPathSelector(proxy.PathSelectorConfig{
				MaxRelaysPerPath: a.cfg.Proxy.PathSelection.MaxRelaysPerPath,
				ProbeTimeout:     time.Duration(a.cfg.Proxy.PathSelection.ProbeTimeoutSec) * time.Second,
				ProbeConcurrency: a.cfg.Proxy.PathSelection.ProbeConcurrency,
				MaxCandidates:    a.cfg.Proxy.PathSelection.MaxCandidates,
				PathCount:        2,
			})
			// CandidateRelays would be populated from gossip-discovered
			// relay-capable peers. For now, leave empty — auto selection
			// will fail with a clear error if no candidates are provided.
		} else {
			// Manual mode: build Path structs from config.Paths.
			entryCfg.PathSelectionMode = "manual"
			if len(a.cfg.Proxy.Paths) >= 2 {
				entryCfg.Path1 = &proxy.Path{Relays: a.cfg.Proxy.Paths[0]}
				entryCfg.Path2 = &proxy.Path{Relays: a.cfg.Proxy.Paths[1]}
			}
		}

		proxyEntryNode = proxy.NewEntryNode(entryCfg)
		if err := proxyEntryNode.Start(); err != nil {
			log.Printf("Warning: failed to start proxy entry node: %v", err)
			proxyEntryNode = nil
		} else {
			log.Printf("  Proxy:      entry node active (SS listener on %s, exit=%s)",
				ssListenAddr, a.cfg.Proxy.ExitAddr)
		}
	}

	// ── Exit Node ──
	// The exit node receives encrypted chunks from relay paths,
	// reassembles them, and dials the target TCP destination.
	if len(a.cfg.Proxy.Exit.AllowedPorts) > 0 || a.cfg.Proxy.Exit.AllowAllPorts {
		exitCircuitCfg := proxy.DefaultCircuitConfig()
		if a.cfg.Proxy.Circuit.OrphanTimeout > 0 {
			exitCircuitCfg.OrphanTimeout = time.Duration(a.cfg.Proxy.Circuit.OrphanTimeout) * time.Second
		}
		if a.cfg.Proxy.Circuit.NACKTimeout > 0 {
			exitCircuitCfg.NACKTimeout = time.Duration(a.cfg.Proxy.Circuit.NACKTimeout) * time.Second
		}
		if a.cfg.Proxy.Circuit.MaxReassemblyWindow > 0 {
			exitCircuitCfg.MaxReassemblyWindow = a.cfg.Proxy.Circuit.MaxReassemblyWindow
		}

		exitCfg := proxy.ExitConfig{
			CircuitCfg:       exitCircuitCfg,
			AllowedPorts:     a.cfg.Proxy.Exit.AllowedPorts,
			AllowAllPorts:    a.cfg.Proxy.Exit.AllowAllPorts,
			ChunkerStrategy:  a.cfg.Proxy.ChunkerStrategy,
			ChunkerCfg:       proxy.DefaultChunkerConfig(),
			DebugFixedChunks: a.cfg.Proxy.DebugFixedChunks,
			Dialer:           net.Dial,
		}

		proxyExitNode = proxy.NewExitNode(exitCfg)
		proxyExitNode.SetSecurityEventSink(proxySecSink)

		// Start orphan cleanup background goroutine.
		exitCtx, exitCancel := context.WithCancel(context.Background())
		go proxyExitNode.StartOrphanCleanup(exitCtx)

		log.Printf("  Proxy:      exit node active (allowed_ports=%v, allow_all=%v)",
			a.cfg.Proxy.Exit.AllowedPorts, a.cfg.Proxy.Exit.AllowAllPorts)

		a.proxyExitNode = proxyExitNode
		a.proxyExitCancel = exitCancel
	}

	if proxyEntryNode != nil {
		a.proxyEntryNode = proxyEntryNode
	}
}

// startProxy starts the SOCKS5 entry listener (bridges local SOCKS5 to
// mesh exit nodes).
func (a *App) startProxy() {
	cfg, node := a.cfg, a.node
	entryListen := cfg.Proxy.SOCKS5.EntryListen
	if a.socks5Listen != "" {
		entryListen = a.socks5Listen
	}
	entryAuthUser, entryAuthPass := cfg.Proxy.SOCKS5.EntryUsername, cfg.Proxy.SOCKS5.EntryPassword
	if entryListen != "" {
		// Safety: a non-loopback entry listener requires credentials.
		loopback := false
		if host, _, err := net.SplitHostPort(entryListen); err == nil {
			ip := net.ParseIP(host)
			loopback = (host == "127.0.0.1" || host == "::1" || host == "localhost") ||
				(ip != nil && ip.IsLoopback())
		}
		if !loopback && entryAuthUser == "" {
			log.Printf("  SOCKS5 entry: REFUSED to listen on %s without credentials (proxy.socks5.entry_username/password)", entryListen)
			entryListen = ""
		}
	}
	if entryListen != "" && (a.socks5ExitNode != "" || a.socks5ExitNodes != "" || len(cfg.Proxy.SOCKS5.AllowedPeers) > 0 || cfg.Proxy.SOCKS5.ExitNode != "" || len(cfg.Proxy.SOCKS5.ExitNodes) > 0) {
		var nodes []string
		if cfg.Proxy.SOCKS5.ExitNode != "" {
			nodes = append(nodes, cfg.Proxy.SOCKS5.ExitNode)
		}
		nodes = append(nodes, cfg.Proxy.SOCKS5.ExitNodes...)
		if len(nodes) == 0 && a.socks5ExitNode != "" {
			nodes = []string{a.socks5ExitNode}
		}
		if len(nodes) == 0 && a.socks5ExitNodes != "" {
			for _, p := range strings.Split(a.socks5ExitNodes, ",") {
				if p = strings.TrimSpace(p); p != "" {
					nodes = append(nodes, p)
				}
			}
		}
		if len(nodes) == 0 {
			log.Printf("  SOCKS5 entry: listening on %s but no exit nodes configured — traffic has nowhere to go", entryListen)
		}
		go runSOCKS5Client(node, entryListen, nodes, entryAuthUser, entryAuthPass)
		log.Printf("  SOCKS5 entry: %s (auth: %s, exits: %d)", entryListen, map[bool]string{true: "username/password", false: "none"}[entryAuthUser != ""], len(nodes))
	}
}

// EntryStatus reports the entry listener status (EntryManager).
func (a *App) EntryStatus() map[string]any {
	return map[string]any{
		"listen":   a.cfg.Proxy.SOCKS5.EntryListen,
		"username": a.cfg.Proxy.SOCKS5.EntryUsername,
		"exits":    len(a.cfg.Proxy.SOCKS5.ExitNodes),
	}
}

// ApplyEntry applies a new entry config (EntryManager).
func (a *App) ApplyEntry(listen, username, password string, exitNodes []string) error {
	a.cfg.Proxy.SOCKS5.EntryListen = listen
	a.cfg.Proxy.SOCKS5.EntryUsername = username
	a.cfg.Proxy.SOCKS5.EntryPassword = password
	a.cfg.Proxy.SOCKS5.ExitNodes = exitNodes
	return nil
}

type exitHealth struct {
	node  *mesh.MeshNode
	mu    sync.Mutex
	state map[string]bool // exitID → healthy
	order []string
	rr    int
}

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
