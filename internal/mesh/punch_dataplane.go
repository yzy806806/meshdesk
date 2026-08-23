// Copyright (c) meshdesk contributors
// SPDX-License-Identifier: MIT

package mesh

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PunchDataplane is a raw-UDP data plane over a hole-punched socket.
// Unlike the ARQ-based punched stream (udpStreamConn), it sends TUN IP
// packets directly as UDP datagrams — no framing, no ACKs, no retransmit.
// Reliability is delegated to the inner transport (TCP retransmits its
// own segments; ICMP/DNS loss is tolerable).
//
// This is the EasyTier model: the punched socket becomes a transport
// directly, and the application (TUN) writes/reads raw IP packets.
// Measured on the txcloud↔Oracle-ARM path (260ms RTT): EasyTier achieves
// 20+ Mbps with 1412B datagrams, while the ARQ layer's 128-frame × 40B
// window capped throughput at ~19KB/s and stalled on single-frame loss.
type PunchDataplane struct {
	conn     *net.UDPConn // the punched UDP socket (from coordination)
	remote   *net.UDPAddr
	peerKey  string
	tunWrite func([]byte) (int, error) // TUN device File().Write
	validate func([]byte, string) bool  // anti-spoof check
	onDead   func()                     // path-death callback

	// Stats
	txPackets atomic.Uint64
	rxPackets atomic.Uint64
	lastRx    atomic.Int64 // unix nano of last received packet

	done   chan struct{}
	close  sync.Once
	closed atomic.Bool
}

// NewPunchDataplane creates a raw-UDP data plane over the given socket.
// The socket must already be punched (conntrack established on both
// sides). The caller retains ownership of the socket; PunchDataplane
// only reads from it. Write uses the same socket.
func NewPunchDataplane(conn *net.UDPConn, remote *net.UDPAddr, peerKey string,
	tunWrite func([]byte) (int, error), validate func([]byte, string) bool,
	onDead func(),
) *PunchDataplane {
	pd := &PunchDataplane{
		conn:     conn,
		remote:   remote,
		peerKey:  peerKey,
		tunWrite: tunWrite,
		validate: validate,
		onDead:   onDead,
		done:     make(chan struct{}),
	}
	pd.lastRx.Store(time.Now().UnixNano())
	return pd
}

// Start launches the receive loop and keepalive goroutines.
func (pd *PunchDataplane) Start() {
		go pd.keepaliveLoop()
	go pd.healthCheckLoop()
}

// Write sends a TUN IP packet as a raw UDP datagram to the peer.
// No framing, no ARQ, no ACK — fire and forget. The caller (TUN
// forwarder) passes raw IP packets; they go out as-is.
func (pd *PunchDataplane) Write(p []byte) (int, error) {
	if pd.closed.Load() {
		return 0, errUDPClosed
	}
	n, err := pd.conn.WriteToUDP(p, pd.remote)
	if err != nil {
		return 0, err
	}
	pd.txPackets.Add(1)
	return n, nil
}

// Close shuts down the data plane. The socket is NOT closed (the
// caller owns it); only the goroutines are stopped.
func (pd *PunchDataplane) Close() error {
	pd.close.Do(func() {
		pd.closed.Store(true)
		close(pd.done)
	})
	return nil
}

// IsAlive returns true if the path has received data recently.
func (pd *PunchDataplane) IsAlive() bool {
	if pd.closed.Load() {
		return false
	}
	ts := pd.lastRx.Load()
	if ts == 0 {
		return false
	}
	return time.Since(time.Unix(0, ts)) < 15*time.Second
}


// keepaliveLoop sends a tiny probe every 2s to keep the NAT/conntrack
// mapping alive on both sides. The probe is a 2-byte payload that
// the receiver's recvLoop will read and discard (it's not a valid IP
// packet, so the TUN write will fail silently or the validate will
// reject it — either way it keeps the socket alive).
func (pd *PunchDataplane) keepaliveLoop() {
	probe := []byte{0x50, 0x4A} // punch probe marker
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-pd.done:
			return
		case <-ticker.C:
			if pd.closed.Load() {
				return
			}
			pd.conn.WriteToUDP(probe, pd.remote)
		}
	}
}

// healthCheckLoop monitors the path. If no data received for 15s
// (7 missed keepalives), the path is considered dead — call onDead
// so the caller can switch to relay and trigger re-punching.
func (pd *PunchDataplane) healthCheckLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-pd.done:
			return
		case <-ticker.C:
			if pd.closed.Load() {
				return
			}
			ts := pd.lastRx.Load()
			if ts == 0 {
				continue
			}
			if time.Since(time.Unix(0, ts)) > 15*time.Second {
				log.Printf("[punch-dataplane] path to %s dead (no RX for %v) — degrading",
					pd.remote, time.Since(time.Unix(0, ts)).Round(time.Second))
				if pd.onDead != nil {
					pd.onDead()
				}
				pd.Close()
				return
			}
		}
	}
}

// reservedProbePacket is the 2-byte keepalive probe. The receiver
// detects it by length (2 bytes is never a valid IP packet) and
// updates lastRx without attempting a TUN write.
var reservedProbePacket = []byte{0x50, 0x4A}

// isProbePacket reports whether the given data is a keepalive probe
// (not a real IP packet).
func isProbePacket(data []byte) bool {
	return len(data) == 2 && data[0] == 0x50 && data[1] == 0x4A
}

// ParsePunchDataplaneKey returns the map key for a PunchDataplane
// (the remote address string). Used by the manager to look up the
// active dataplane for a given peer.
func PunchDataplaneKey(remote *net.UDPAddr) string {
	return remote.String()
}

// PunchDataplaneManager manages active raw-UDP data planes keyed by
// peer public key. It replaces the ARQ-based RegisterPunchedStream
// for the primary TUN data path.
type PunchDataplaneManager struct {
	mu       sync.RWMutex
	planes   map[string]*PunchDataplane // peerKey → dataplane
}

func NewPunchDataplaneManager() *PunchDataplaneManager {
	return &PunchDataplaneManager{planes: make(map[string]*PunchDataplane)}
}

// Register creates (or replaces) a PunchDataplane for the given peer.
// The old dataplane (if any) is closed first.
func (m *PunchDataplaneManager) Register(pd *PunchDataplane, peerKey string) {
	m.mu.Lock()
	if old, ok := m.planes[peerKey]; ok {
		old.Close()
	}
	m.planes[peerKey] = pd
	m.mu.Unlock()
	pd.Start()
	log.Printf("[punch-dataplane] registered raw dataplane for peer %s", peerKey[:min(len(peerKey), 8)])
}

// Get returns the active dataplane for a peer, or nil if none.
// Returns nil if the dataplane is dead (stale path).
func (m *PunchDataplaneManager) Get(peerKey string) *PunchDataplane {
	m.mu.RLock()
	pd := m.planes[peerKey]
	m.mu.RUnlock()
	if pd == nil || !pd.IsAlive() {
		return nil
	}
	return pd
}

// Remove closes and removes the dataplane for a peer.
func (m *PunchDataplaneManager) Remove(peerKey string) {
	m.mu.Lock()
	if pd, ok := m.planes[peerKey]; ok {
		pd.Close()
		delete(m.planes, peerKey)
	}
	m.mu.Unlock()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Ensure unused import doesn't break build

// LocalAddr returns the local socket address.
func (pd *PunchDataplane) LocalAddr() net.Addr { return pd.conn.LocalAddr() }

// RemoteAddr returns the peer's address.
func (pd *PunchDataplane) RemoteAddr() net.Addr { return pd.remote }

// SetDeadline is a no-op (UDP is connectionless).
func (pd *PunchDataplane) SetDeadline(t time.Time) error      { return nil }

// SetReadDeadline is a no-op.
func (pd *PunchDataplane) SetReadDeadline(t time.Time) error  { return nil }

// SetWriteDeadline is a no-op.
func (pd *PunchDataplane) SetWriteDeadline(t time.Time) error { return nil }

// Read is not used — inbound packets go through recvLoop directly
// to the TUN device. This stub satisfies net.Conn.
func (pd *PunchDataplane) Read(p []byte) (int, error) {
	return 0, nil
}

// Feed processes an inbound datagram from the mux's routeUDPPacket.
// This replaces the independent recvLoop (which competed with
// punchSocketPoller for the same socket).
func (pd *PunchDataplane) Feed(data []byte) {
	pd.lastRx.Store(time.Now().UnixNano())
	pd.rxPackets.Add(1)

	// Keepalive probe — not an IP packet.
	if isProbePacket(data) {
		return
	}

	// Anti-spoof validation.
	if pd.validate != nil && !pd.validate(data, pd.peerKey) {
		return
	}

	// Write directly to TUN.
	if _, err := pd.tunWrite(data); err != nil {
		// TUN write error — non-fatal, keep going.
	}
}

// RemoteAddr returns the peer's UDP address (exported).
func (pd *PunchDataplane) RemoteUDPAddr() *net.UDPAddr {
	return pd.remote
}

// Keys returns all peer keys with active dataplanes.
func (m *PunchDataplaneManager) Keys() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.planes))
	for k := range m.planes {
		keys = append(keys, k)
	}
	return keys
}

// SetPunchDataplaneFeed sets the feed callback on the udpMeshManager.
func (m *udpMeshManager) SetPunchDataplaneFeed(f func(*net.UDPAddr, []byte) bool) {
	m.mu.Lock()
	m.punchDataplaneFeed = f
	m.mu.Unlock()
}
