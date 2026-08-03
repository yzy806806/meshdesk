package mesh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
	// first packet to that peer and reused.
	outboundMu      sync.Mutex
	outboundStreams map[string]net.Conn

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
		outboundStreams: make(map[string]net.Conn),
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
	for peerKey, conn := range f.outboundStreams {
		conn.Close()
		delete(f.outboundStreams, peerKey)
	}
	f.outboundMu.Unlock()

	f.wg.Wait()
	log.Printf("[tun-forwarder] stopped (sent=%d, recv=%d, dropped=%d)",
		f.packetsSent.Load(), f.packetsReceived.Load(), f.packetsDropped.Load())
}

// Stats returns current forwarder statistics.
type TunForwarderStats struct {
	PacketsSent     uint64
	PacketsReceived uint64
	PacketsDropped  uint64
	BytesSent       uint64
	BytesReceived   uint64
}

func (f *TunForwarder) Stats() TunForwarderStats {
	return TunForwarderStats{
		PacketsSent:     f.packetsSent.Load(),
		PacketsReceived: f.packetsReceived.Load(),
		PacketsDropped:  f.packetsDropped.Load(),
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
			// Packet is for our own TUN IP — the kernel networking
			// stack handles local delivery. We should not see these
			// on the TUN read side (the kernel delivers locally
			// before sending to the TUN), but if we do, drop them.
			f.packetsDropped.Add(1)
			continue
		}

		// Check if the destination is in the TUN subnet.
		if !f.cfg.Router.IsInSubnet(dstIP) {
			// Not in our subnet — drop. (In the future, this could
			// trigger subnet proxy / NAT functionality.)
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
func (f *TunForwarder) getOutboundStream(peerKey string) (net.Conn, error) {
	f.outboundMu.Lock()
	conn, ok := f.outboundStreams[peerKey]
	f.outboundMu.Unlock()

	if ok {
		return conn, nil
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
	if existing, ok := f.outboundStreams[peerKey]; ok {
		f.outboundMu.Unlock()
		newConn.Close()
		return existing, nil
	}
	f.outboundStreams[peerKey] = newConn
	f.outboundMu.Unlock()

	return newConn, nil
}

// closeOutboundStream closes and removes the outbound stream for the
// given peer. The next packet to this peer will open a new stream.
func (f *TunForwarder) closeOutboundStream(peerKey string) {
	f.outboundMu.Lock()
	conn, ok := f.outboundStreams[peerKey]
	if ok {
		delete(f.outboundStreams, peerKey)
	}
	f.outboundMu.Unlock()

	if ok {
		conn.Close()
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Inbound: smux stream → TUN device
// ──────────────────────────────────────────────────────────────────────────────

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

		// Optional: validate source IP matches the peer's VirtualIP.
		if peerID != "" {
			if srcIP, err := parseSrcIP(packet); err == nil {
				if expectedIP, ok := f.cfg.Router.ResolvePeer(peerID); ok {
					if !expectedIP.Equal(srcIP) {
						// Source IP mismatch — potential spoofing.
						// Drop the packet but keep the stream open
						// (the peer might have multiple IPs or a
						// misconfigured routing table).
						f.packetsDropped.Add(1)
						log.Printf("[tun-forwarder] source IP mismatch: expected %s, got %s from peer %s",
							expectedIP, srcIP, shortKey(peerID))
						continue
					}
				}
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
// Framing helpers
// ──────────────────────────────────────────────────────────────────────────────

// writeFramedPacket writes a 4-byte big-endian length prefix followed
// by the packet payload to the connection.
func writeFramedPacket(w io.Writer, packet []byte) error {
	var header [tunPacketHeaderLen]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(packet)))

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if _, err := w.Write(packet); err != nil {
		return err
	}
	return nil
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
	return false
}
