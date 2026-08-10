package mesh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yzy806806/meshdesk/internal/tun"
)

// TunVirtualPort is the smux virtual port for TUN packet forwarding.
// 0x5455 = 'T' (0x54) 'U' (0x55) — mnemonic for "TUN".
const TunVirtualPort = 0x5455

// tunPacketHeaderLen is the size of the TUN packet framing header.
// Each TUN packet sent over a smux stream is prefixed with a 4-byte
// big-endian length field so the receiver can frame individual IP
// packets within a single smux stream.
const tunPacketHeaderLen = 4

// maxTunPacketSize is the maximum IP packet size we handle.
// With MTU 1400, the maximum IP packet is 1400 bytes, but we allow
// up to 65535 for safety (the kernel will drop oversized packets).
const maxTunPacketSize = 65535

// TunForwarderConfig holds the configuration for a TunForwarder.
type TunForwarderConfig struct {
	// Device is the open TUN device. The forwarder reads IP packets
	// from it and writes IP packets to it.
	Device *tun.Device

	// Router is the VirtualIP → PublicKey routing table. The forwarder
	// consults it to resolve destination IPs to peer public keys.
	Router *tun.Router

	// MeshNode is used to open smux streams to peers via
	// DialVirtualPort. The forwarder dials the TunVirtualPort on
	// the target peer's smux session.
	MeshNode *MeshNode

	// RouteManager manages subnet proxy routes. When non-nil, the
	// forwarder consults it for packets whose destination IP falls
	// outside the mesh subnet (e.g. 192.168.1.x behind a peer).
	// If nil, non-mesh-subnet packets are dropped.
	RouteManager *tun.RouteManager

	// ACLEngine is the access control list engine for ingress packet
	// filtering. When non-nil, every inbound packet is checked against
	// the ACL rules after anti-spoofing validation and before being
	// written to the TUN device. When nil, all packets are allowed.
	ACLEngine *ACLEngine
}

// TunForwarder implements the TUN data transceive loop:
//
//   - Read loop: reads IP packets from the TUN device, parses the
//     destination IP, looks it up in the routing table, opens a smux
//     stream to the target peer's TUN virtual port, and writes the
//     framed packet.
//
//   - Listen loop: accepts inbound smux streams on the TUN virtual
//     port, reads framed IP packets, and writes them to the TUN device.
//
// The forwarder uses a single long-lived smux stream per peer for
// the outbound direction (lazily created on first packet, reused for
// subsequent packets). Inbound streams are per-connection (each peer
// opens a new stream for each batch, but we keep a read loop alive).
type TunForwarder struct {
	cfg TunForwarderConfig

	// outboundStreams maps peer public key → the smux stream used
	// for outbound TUN packets. Each stream is opened lazily on the
	// first packet to that peer and reused; entries refresh after
	// outboundStreamTTL so session reconnects don't strand packets
	// on dead streams (buffered writes "succeed" without error).
	outboundMu      sync.Mutex
	outboundStreams map[string]outboundStreamEntry

	// udpStreams caches the UDP-preferred TUN stream per peer
	// (multipath D). udpFail records when a UDP dial last failed so
	// we don't hammer unreachable UDP endpoints on every packet.
	udpStreams map[string]outboundStreamEntry
	udpFail    map[string]time.Time
	udpMu      sync.Mutex

	// listener is the virtual port listener for inbound TUN packets.
	listener net.Listener

	// ctx/cancel control the forwarder lifecycle.
	ctx    context.Context
	cancel context.CancelFunc

	// running is atomically set to 1 when Start is called.
	running atomic.Int32

	// wg tracks active goroutines.
	wg sync.WaitGroup

	// stats
	packetsSent     atomic.Uint64
	packetsReceived atomic.Uint64
	packetsDropped  atomic.Uint64
	packetsSpoofed  atomic.Uint64
	bytesSent       atomic.Uint64
	bytesReceived   atomic.Uint64
}

// NewTunForwarder creates a new TUN forwarder from the given config.
// Call Start to begin the read and listen loops.
func NewTunForwarder(cfg TunForwarderConfig) (*TunForwarder, error) {
	if cfg.Device == nil {
		return nil, errors.New("tun-forwarder: Device is required")
	}
	if cfg.Router == nil {
		return nil, errors.New("tun-forwarder: Router is required")
	}
	if cfg.MeshNode == nil {
		return nil, errors.New("tun-forwarder: MeshNode is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &TunForwarder{
		cfg:             cfg,
		outboundStreams: make(map[string]outboundStreamEntry),
		udpStreams:      make(map[string]outboundStreamEntry),
		udpFail:         make(map[string]time.Time),
		ctx:             ctx,
		cancel:          cancel,
	}, nil
}

// Start begins the TUN read loop and the inbound stream listen loop.
// It registers a virtual port listener for TunVirtualPort and spawns
// goroutines for both directions. Call Stop to shut down.
func (f *TunForwarder) Start() error {
	if !f.running.CompareAndSwap(0, 1) {
		return errors.New("tun-forwarder: already running")
	}

	// Register the inbound listener for TUN virtual port.
	ln, err := f.cfg.MeshNode.ListenVirtualPort(int(TunVirtualPort))
	if err != nil {
		f.running.Store(0)
		return fmt.Errorf("tun-forwarder: listen on port 0x%x: %w", TunVirtualPort, err)
	}
	f.listener = ln

	// Start the TUN device read loop (outbound: TUN → mesh).
	f.wg.Add(1)
	go f.tunReadLoop()

	// Start the inbound stream accept loop (mesh → TUN).
	f.wg.Add(1)
	go f.streamAcceptLoop()

	// Start the inbound UDP TUN stream accept loop (multipath D:
	// UDP-preferred data plane).
	if f.cfg.MeshNode != nil && f.cfg.MeshNode.TunUDPListener() != nil {
		f.wg.Add(1)
		go f.udpAcceptLoop()
	}

	log.Printf("[tun-forwarder] started (virtual port 0x%x, MTU=%d, subnet=%s)",
		TunVirtualPort, f.cfg.Device.MTU(), f.cfg.Router.Subnet())

	return nil
}

// Stop shuts down the forwarder: cancels the context, closes the
// listener, closes all outbound streams, and waits for goroutines.
func (f *TunForwarder) Stop() {
	if !f.running.CompareAndSwap(1, 0) {
		return
	}

	f.cancel()

	if f.listener != nil {
		f.listener.Close()
	}

	// Close all outbound streams.
	f.outboundMu.Lock()
	for peerKey, entry := range f.outboundStreams {
		entry.conn.Close()
		delete(f.outboundStreams, peerKey)
	}
	f.outboundMu.Unlock()

	// Close cached UDP TUN streams too (multipath D) — they hold
	// UDP sockets + ARQ goroutines and must not leak on shutdown.
	f.udpMu.Lock()
	for peerKey, entry := range f.udpStreams {
		entry.conn.Close()
		delete(f.udpStreams, peerKey)
	}
	f.udpMu.Unlock()

	f.wg.Wait()
	log.Printf("[tun-forwarder] stopped (sent=%d, recv=%d, dropped=%d, spoofed=%d)",
		f.packetsSent.Load(), f.packetsReceived.Load(), f.packetsDropped.Load(), f.packetsSpoofed.Load())
}

// Stats returns current forwarder statistics.
// TunForwarderStats holds the current forwarder statistics.
type TunForwarderStats struct {
	PacketsSent     uint64
	PacketsReceived uint64
	PacketsDropped  uint64
	PacketsSpoofed  uint64
	BytesSent       uint64
	BytesReceived   uint64
}

func (f *TunForwarder) Stats() TunForwarderStats {
	return TunForwarderStats{
		PacketsSent:     f.packetsSent.Load(),
		PacketsReceived: f.packetsReceived.Load(),
		PacketsDropped:  f.packetsDropped.Load(),
		PacketsSpoofed:  f.packetsSpoofed.Load(),
		BytesSent:       f.bytesSent.Load(),
		BytesReceived:   f.bytesReceived.Load(),
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Outbound: TUN device → smux stream → peer
// ──────────────────────────────────────────────────────────────────────────────

// tunReadLoop reads IP packets from the TUN device and forwards them
// to the appropriate peer over a smux stream.
//
// For each packet:
//  1. Parse the destination IPv4/IPv6 address from the packet header.
//  2. Look up the peer public key in the routing table.
//  3. If the destination is the local node, drop it (kernel handles
//     local delivery via the TUN interface itself).
//  4. If no route is found, drop the packet.
//  5. Get or create an outbound smux stream to the peer.
//  6. Write the framed packet (4-byte length + payload) to the stream.
func (f *TunForwarder) tunReadLoop() {
	defer f.wg.Done()

	mtu := f.cfg.Device.MTU()
	if mtu <= 0 {
		mtu = 1400
	}
	// Read buffer: MTU + some headroom.
	buf := make([]byte, mtu+128)

	for {
		select {
		case <-f.ctx.Done():
			return
		default:
		}

		n, err := f.cfg.Device.File().Read(buf)
		if err != nil {
			if f.ctx.Err() != nil {
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				log.Printf("[tun-forwarder] TUN device closed")
				return
			}
			log.Printf("[tun-forwarder] TUN read error: %v", err)
			continue
		}

		if n == 0 {
			continue
		}

		packet := buf[:n]

		// Parse the destination IP from the packet.
		dstIP, err := parseDstIP(packet)
		if err != nil {
			f.packetsDropped.Add(1)
			if isDebugLogEnabled() {
				log.Printf("[tun-forwarder] dropped packet: cannot parse dst IP: %v", err)
			}
			continue
		}

		// Check if the packet is for self.
		if f.cfg.Router.IsLocalIP(dstIP) {
			// The kernel should handle local delivery, but during
			// IPAM conflict resolution a peer may temporarily share
			// the same VirtualIP. If the Router has a peer route for
			// this IP, forward it (the peer may be using this IP
			// while we are re-allocating).
			peerKey, found := f.cfg.Router.ResolveIP(dstIP)
			if !found || f.cfg.Router.IsSelf(peerKey) {
				f.packetsDropped.Add(1)
				continue
			}
			// IPAM conflict: peer claims this IP too. Skip the
			// IsLocalIP guard and fall through to normal forwarding.
		}

		// Check if the destination is in the TUN subnet.
		if !f.cfg.Router.IsInSubnet(dstIP) {
			// Not in our subnet — try subnet proxy routing.
			// The RouteManager maintains a mapping of advertised
			// subnets (e.g. 192.168.1.0/24) to peer VirtualIPs.
			if f.cfg.RouteManager != nil {
				gwVirtualIP, ok := f.cfg.RouteManager.ResolveSubnetProxy(dstIP)
				if ok {
					// Found a subnet proxy route — resolve the
					// gateway VirtualIP to a peer public key.
					peerKey, found := f.cfg.Router.ResolveIP(net.ParseIP(gwVirtualIP))
					if found && !f.cfg.Router.IsSelf(peerKey) {
						// Forward the packet to the subnet proxy peer.
						conn, err := f.getOutboundStream(peerKey)
						if err != nil {
							f.packetsDropped.Add(1)
							log.Printf("[tun-forwarder] subnet proxy: failed to get stream to peer %s...: %v",
								shortKey(peerKey), err)
							continue
						}
						if err := writeFramedPacket(conn, packet); err != nil {
							f.packetsDropped.Add(1)
							log.Printf("[tun-forwarder] subnet proxy: write to peer %s... failed: %v",
								shortKey(peerKey), err)
							f.closeOutboundStream(peerKey)
							continue
						}
						f.packetsSent.Add(1)
						f.bytesSent.Add(uint64(len(packet)))
						continue
					}
				}
			}
			// No subnet proxy route found — drop.
			f.packetsDropped.Add(1)
			continue
		}

		// Look up the peer public key for this destination IP.
		peerKey, ok := f.cfg.Router.ResolveIP(dstIP)
		if !ok {
			f.packetsDropped.Add(1)
			if isDebugLogEnabled() {
				log.Printf("[tun-forwarder] no route for dst %s, dropping", dstIP)
			}
			continue
		}

		// Skip if the route points to self.
		if f.cfg.Router.IsSelf(peerKey) {
			f.packetsDropped.Add(1)
			continue
		}

		// Get or create the outbound stream to this peer.
		conn, err := f.getOutboundStream(peerKey)
		if err != nil {
			f.packetsDropped.Add(1)
			log.Printf("[tun-forwarder] failed to get stream to peer %s...: %v",
				shortKey(peerKey), err)
			continue
		}

		// Write the framed packet: 4-byte big-endian length + payload.
		if err := writeFramedPacket(conn, packet); err != nil {
			f.packetsDropped.Add(1)
			log.Printf("[tun-forwarder] write to peer %s... failed: %v", shortKey(peerKey), err)
			// Close and remove the broken stream.
			f.closeOutboundStream(peerKey)
			continue
		}

		f.packetsSent.Add(1)
		f.bytesSent.Add(uint64(len(packet)))
	}
}

// getOutboundStream returns the existing outbound smux stream for the
// given peer, or creates a new one if none exists. Streams are cached
// per-peer for the lifetime of the forwarder (or until they break).
// Cached streams are re-established after outboundStreamTTL — a peer's
// session may have reconnected (smux session replaced) while the old
// stream's buffered writes still "succeed" (no immediate error), so
// packets silently vanish on the dead session. TTL forces re-dial.
func (f *TunForwarder) getOutboundStream(peerKey string) (net.Conn, error) {
	// Multipath D: UDP-preferred path first. The UDP ARQ stream is
	// faster on lossy inter-cloud links (no TCP congestion-control
	// collapse); fall back to TCP smux when UDP is unavailable.
	if conn, err := f.getUDPStream(peerKey); err == nil {
		return conn, nil
	}

	f.outboundMu.Lock()
	entry, ok := f.outboundStreams[peerKey]
	f.outboundMu.Unlock()

	if ok && time.Since(entry.createdAt) < outboundStreamTTL {
		return entry.conn, nil
	}
	if ok {
		// Stale — close and re-dial.
		f.closeOutboundStream(peerKey)
	}

	// Open a new smux stream to the peer's TUN virtual port.
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()

	newConn, err := f.cfg.MeshNode.DialVirtualPort(ctx, peerKey, int(TunVirtualPort))
	if err != nil {
		return nil, fmt.Errorf("dial tun port: %w", err)
	}

	f.outboundMu.Lock()
	// Check if another goroutine created a stream in the meantime.
	if existing, ok := f.outboundStreams[peerKey]; ok && time.Since(existing.createdAt) < outboundStreamTTL {
		f.outboundMu.Unlock()
		newConn.Close()
		return existing.conn, nil
	}
	f.outboundStreams[peerKey] = outboundStreamEntry{conn: newConn, createdAt: time.Now()}
	f.outboundMu.Unlock()

	return newConn, nil
}

// udpCooldown is how long a failed UDP TUN dial keeps the UDP path
// disabled for that peer before retrying (fall back to TCP meanwhile).
const udpCooldown = 30 * time.Second

// getUDPStream returns the cached (or freshly dialed) UDP ARQ TUN
// stream for a peer. Returns an error when UDP is unavailable or in
// cooldown — the caller falls back to the TCP smux path.
func (f *TunForwarder) getUDPStream(peerKey string) (net.Conn, error) {
	if f.cfg.MeshNode == nil {
		return nil, errors.New("tun-forwarder: no mesh node for UDP path")
	}
	f.udpMu.Lock()
	entry, ok := f.udpStreams[peerKey]
	lastFail, failed := f.udpFail[peerKey]
	f.udpMu.Unlock()

	if ok && time.Since(entry.createdAt) < outboundStreamTTL {
		return entry.conn, nil
	}
	if failed && time.Since(lastFail) < udpCooldown {
		return nil, errors.New("tun-forwarder: UDP path in cooldown")
	}

	conn, err := f.cfg.MeshNode.DialTUNUDPForPeer(peerKey)
	if err != nil {
		f.udpMu.Lock()
		f.udpFail[peerKey] = time.Now()
		f.udpMu.Unlock()
		return nil, err
	}

	f.udpMu.Lock()
	f.udpStreams[peerKey] = outboundStreamEntry{conn: conn, createdAt: time.Now()}
	delete(f.udpFail, peerKey)
	f.udpMu.Unlock()
	return conn, nil
}

// closeOutboundStream closes and removes the outbound stream for the
// given peer. The next packet to this peer will open a new stream.
// Multipath D: a failing write on either path also invalidates the
// cached UDP stream (otherwise a dead UDP conn keeps being reused
// until its 60s TTL, silently dropping packets) and starts the UDP
// cooldown so we don't immediately re-dial the dead path.
func (f *TunForwarder) closeOutboundStream(peerKey string) {
	f.outboundMu.Lock()
	entry, ok := f.outboundStreams[peerKey]
	if ok {
		delete(f.outboundStreams, peerKey)
	}
	f.outboundMu.Unlock()

	if ok {
		entry.conn.Close()
	}

	f.udpMu.Lock()
	if ue, uok := f.udpStreams[peerKey]; uok {
		delete(f.udpStreams, peerKey)
		ue.conn.Close()
		f.udpFail[peerKey] = time.Now()
	}
	f.udpMu.Unlock()
}

// outboundStreamEntry wraps a cached outbound stream with its creation
// time so stale streams (peer session reconnected) can be re-dialed.
type outboundStreamEntry struct {
	conn      net.Conn
	createdAt time.Time
}

// outboundStreamTTL forces outbound TUN streams to be re-established
// periodically. A peer's smux session may reconnect while the old
// stream's buffered writes still succeed (no immediate error), so
// packets would silently vanish on the dead session forever.
const outboundStreamTTL = 60 * time.Second

// ──────────────────────────────────────────────────────────────────────────────
// Inbound: smux stream → TUN device
// ──────────────────────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// Inbound: UDP ARQ stream → TUN device (multipath D)
// ──────────────────────────────────────────────────────────────────────────────

// udpAcceptLoop accepts inbound UDP TUN streams (each already carries a
// verified peer identity via connWithPeer) and reuses handleInboundStream
// so anti-spoof and ACL checks apply identically to the UDP path.
func (f *TunForwarder) udpAcceptLoop() {
	defer f.wg.Done()

	ln := f.cfg.MeshNode.TunUDPListener()
	if ln == nil {
		return
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if f.ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[tun-forwarder] UDP accept error: %v", err)
			continue
		}
		f.wg.Add(1)
		go f.handleInboundStream(conn)
	}
}

// streamAcceptLoop accepts inbound smux streams on the TUN virtual port
// and spawns a per-stream read loop to forward packets to the TUN device.
func (f *TunForwarder) streamAcceptLoop() {
	defer f.wg.Done()

	for {
		select {
		case <-f.ctx.Done():
			return
		default:
		}

		conn, err := f.listener.Accept()
		if err != nil {
			if f.ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[tun-forwarder] accept error: %v", err)
			continue
		}

		f.wg.Add(1)
		go f.handleInboundStream(conn)
	}
}

// handleInboundStream reads framed IP packets from an inbound smux
// stream and writes them to the TUN device.
//
// The peer identity is extracted from the connWithPeer wrapper (if
// available) for source validation.
func (f *TunForwarder) handleInboundStream(conn net.Conn) {
	defer f.wg.Done()
	defer conn.Close()

	// Extract peer identity if available (for source validation).
	var peerID string
	if cp, ok := conn.(*connWithPeer); ok {
		peerID = cp.PeerID()
	}

	for {
		select {
		case <-f.ctx.Done():
			return
		default:
		}

		packet, err := readFramedPacket(conn)
		if err != nil {
			if f.ctx.Err() != nil {
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[tun-forwarder] inbound read error from peer %s: %v",
				shortKey(peerID), err)
			return
		}

		// Validate source IP matches the peer's VirtualIP (anti-spoofing).
		// Every inbound packet must have its src IP verified against the
		// sending peer's NodeMeta.VirtualIP. Mismatched, unparseable, or
		// unknown-peer packets are dropped. Deny by default when peerID
		// is empty (defense in depth — no unauthenticated TUN writes).
		if peerID == "" {
			f.packetsSpoofed.Add(1)
			if isDebugLogEnabled() {
				log.Printf("[tun-forwarder] anti-spoof: no peer identity, dropping packet")
			}
			continue
		}
		if !f.validateSourceIP(packet, peerID) {
			f.packetsSpoofed.Add(1)
			continue
		}

		// ACL policy check (if engine is configured).
		if f.cfg.ACLEngine != nil {
			if !f.cfg.ACLEngine.Check(packet, peerID) {
				f.packetsDropped.Add(1)
				if isDebugLogEnabled() {
					log.Printf("[tun-forwarder] ACL: packet denied from peer %s",
						shortKey(peerID))
				}
				continue
			}
		}

		// Write the packet to the TUN device.
		_, err = f.cfg.Device.File().Write(packet)
		if err != nil {
			if f.ctx.Err() != nil {
				return
			}
			log.Printf("[tun-forwarder] TUN write error: %v", err)
			f.packetsDropped.Add(1)
			continue
		}

		f.packetsReceived.Add(1)
		f.bytesReceived.Add(uint64(len(packet)))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Source IP anti-spoofing validation
// ──────────────────────────────────────────────────────────────────────────────

// validateSourceIP checks that the source IP address in the given IP packet
// matches the VirtualIP registered for the sending peer in the routing table.
//
// This is the core anti-spoofing check: every IP packet arriving on a TUN
// virtual port must have its source IP verified against the sending peer's
// NodeMeta.VirtualIP. If they don't match, the packet is an attempted spoof
// and must be dropped.
//
// Returns true if the source IP is valid (matches the peer's VirtualIP),
// false if the packet should be dropped.
//
// The method drops (returns false) in three cases:
//  1. Cannot parse the source IP from the packet (malformed packet).
//  2. The sending peer is not in the routing table (unknown peer — cannot
//     verify its VirtualIP).
//  3. The parsed source IP does not match the peer's registered VirtualIP.
func (f *TunForwarder) validateSourceIP(packet []byte, peerID string) bool {
	srcIP, err := parseSrcIP(packet)
	if err != nil {
		if isDebugLogEnabled() {
			log.Printf("[tun-forwarder] anti-spoof: cannot parse src IP from peer %s: %v",
				shortKey(peerID), err)
		}
		return false
	}

	expectedIP, ok := f.cfg.Router.ResolvePeer(peerID)
	if !ok {
		// Empty peer ID = no authenticated chain — always reject.
		if peerID == "" {
			if isDebugLogEnabled() {
				log.Printf("[tun-forwarder] anti-spoof: empty peerID, dropping packet (src=%s)", srcIP)
			}
			return false
		}
		// Peer not in the routing table — cannot verify identity.
		// Fall back: if the source IP is inside the mesh subnet, accept
		// it. In degraded-gossip topologies the peer's VirtualIP may
		// not have propagated (mixed IP families / NAT'd nodes), yet
		// the packet arrived over an authenticated smux chain — a
		// spoofed mesh-subnet source would need the peer's session key.
		if f.cfg.Router.IsInSubnet(srcIP) {
			if isDebugLogEnabled() {
				log.Printf("[tun-forwarder] anti-spoof: peer %s VIP unknown, accepting mesh-subnet src %s", shortKey(peerID), srcIP)
			}
			return true
		}
		if isDebugLogEnabled() {
			log.Printf("[tun-forwarder] anti-spoof: peer %s not in routing table, dropping packet (src=%s)", shortKey(peerID), srcIP)
		}
		return false
	}

	// If the source IP matches the peer's VirtualIP, accept it.
	if expectedIP.Equal(srcIP) {
		return true
	}

	// If the source IP is NOT in the mesh subnet, it may be from a
	// subnet proxy (e.g. the peer is forwarding traffic from its LAN).
	// Only accept it if the RouteManager is configured and the source
	// IP falls within one of the advertised subnet proxies that is
	// routed via this peer's VirtualIP.
	if !f.cfg.Router.IsInSubnet(srcIP) {
		if f.cfg.RouteManager != nil {
			gw, found := f.cfg.RouteManager.ResolveSubnetProxy(srcIP)
			if found {
				// The source IP must be within a subnet that is
				// routed via this peer's VirtualIP. This ensures
				// peer A can't send traffic claiming to be from
				// peer B's LAN.
				if gw == expectedIP.String() {
					return true
				}
			}
		}
		// Either no RouteManager, or the source IP doesn't match
		// any of this peer's advertised subnets — reject.
		log.Printf("[tun-forwarder] anti-spoof: source IP %s outside mesh subnet, not in peer %s's advertised subnets",
			srcIP, shortKey(peerID))
		return false
	}

	// Source is in the mesh subnet but doesn't match — reject.
	log.Printf("[tun-forwarder] anti-spoof: source IP mismatch — expected %s, got %s from peer %s",
		expectedIP, srcIP, shortKey(peerID))
	return false
}

// ──────────────────────────────────────────────────────────────────────────────
// Framing helpers
// ──────────────────────────────────────────────────────────────────────────────

// writeFramedPacket writes a 4-byte big-endian length prefix followed
// by the packet payload to the connection.
func writeFramedPacket(w io.Writer, packet []byte) error {
	// Single Write for atomicity — length prefix + payload in one call.
	buf := make([]byte, tunPacketHeaderLen+len(packet))
	binary.BigEndian.PutUint32(buf[:tunPacketHeaderLen], uint32(len(packet)))
	copy(buf[tunPacketHeaderLen:], packet)
	_, err := w.Write(buf)
	return err
}

// readFramedPacket reads a 4-byte big-endian length prefix, then reads
// that many bytes of payload. Returns the payload as a newly allocated
// slice (safe to retain).
func readFramedPacket(r io.Reader) ([]byte, error) {
	var header [tunPacketHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxTunPacketSize {
		return nil, fmt.Errorf("invalid packet length %d", length)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// IP packet parsing
// ──────────────────────────────────────────────────────────────────────────────

// parseDstIP extracts the destination IP address from an IP packet.
// Supports both IPv4 and IPv6.
func parseDstIP(packet []byte) (net.IP, error) {
	if len(packet) < 1 {
		return nil, errors.New("empty packet")
	}

	// The first nibble (high 4 bits) of the first byte is the IP version.
	version := packet[0] >> 4

	switch version {
	case 4:
		if len(packet) < 20 {
			return nil, errors.New("IPv4 packet too short")
		}
		// Destination IP is at offset 16-19.
		dst := net.IP(packet[16:20])
		return dst.To4(), nil

	case 6:
		if len(packet) < 40 {
			return nil, errors.New("IPv6 packet too short")
		}
		// Destination IP is at offset 24-39.
		dst := make(net.IP, 16)
		copy(dst, packet[24:40])
		return dst, nil

	default:
		return nil, fmt.Errorf("unknown IP version %d", version)
	}
}

// parseSrcIP extracts the source IP address from an IP packet.
// Supports both IPv4 and IPv6.
func parseSrcIP(packet []byte) (net.IP, error) {
	if len(packet) < 1 {
		return nil, errors.New("empty packet")
	}

	version := packet[0] >> 4

	switch version {
	case 4:
		if len(packet) < 20 {
			return nil, errors.New("IPv4 packet too short")
		}
		// Source IP is at offset 12-15.
		src := net.IP(packet[12:16])
		return src.To4(), nil

	case 6:
		if len(packet) < 40 {
			return nil, errors.New("IPv6 packet too short")
		}
		// Source IP is at offset 8-23.
		src := make(net.IP, 16)
		copy(src, packet[8:24])
		return src, nil

	default:
		return nil, fmt.Errorf("unknown IP version %d", version)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Utility
// ──────────────────────────────────────────────────────────────────────────────

// shortKey returns the first 16 characters of a hex public key for
// logging. If the key is shorter, returns it as-is.
func shortKey(key string) string {
	if len(key) <= 16 {
		return key
	}
	return key[:16] + "..."
}

// isDebugLogEnabled returns true if debug-level logging is enabled.
// Currently always false to avoid noise; can be wired to a debug flag.
func isDebugLogEnabled() bool {
	return os.Getenv("MESHDESK_TUN_DEBUG") == "1"
}
