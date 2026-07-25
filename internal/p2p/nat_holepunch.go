package p2p

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

// HolePunchResult holds the outcome of a hole-punching attempt.
type HolePunchResult struct {
	// Success indicates whether the direct WireGuard handshake is
	// expected to succeed via the hole-punched path.
	Success bool

	// LocalEndpoint is our public endpoint used for the punch.
	LocalEndpoint string

	// RemoteEndpoint is the peer's public endpoint we punched to.
	RemoteEndpoint string

	// Error describes why the hole-punch failed (if Success is false).
	Error error

	// Elapsed is how long the hole-punch attempt took.
	Elapsed time.Duration
}

// HolePuncher attempts UDP hole-punching for direct WireGuard connectivity.
//
// Per §3.6 of the spec, hole-punching is not a separate protocol — it's
// simply the normal WireGuard handshake sent to the peer's STUN-discovered
// endpoint. Both peers send packets to each other's mapped addresses
// simultaneously; the first packet creates a NAT mapping that allows the
// response back.
//
// The HolePuncher performs a "pre-punch" by sending a few UDP packets
// to the peer's endpoint to open the NAT mapping before the WireGuard
// device sends its handshake initiation. This improves the success rate
// for restricted and port-restricted NAT types.
type HolePuncher struct {
	// localEndpoint is our STUN-discovered public address.
	localEndpoint string

	// punchPort is the local UDP port used for hole-punching.
	// In production, this should be the same port that WireGuard
	// listens on (mesh port, default 51820) so that the NAT mapping
	// created by the punch is reused by WireGuard.
	punchPort int

	// timeout for each punch attempt.
	timeout time.Duration

	// numPackets is how many probe packets to send.
	numPackets int
}

// NewHolePuncher creates a hole-puncher with the given local endpoint
// and WireGuard listen port.
func NewHolePuncher(localEndpoint string, wgPort int) *HolePuncher {
	return &HolePuncher{
		localEndpoint: localEndpoint,
		punchPort:     wgPort,
		timeout:       5 * time.Second,
		numPackets:    3,
	}
}

// Punch attempts to create a NAT mapping by sending UDP probe packets
// to the peer's discovered endpoint. After the probes are sent, the
// caller (NAT state machine) triggers the WireGuard handshake.
//
// The function sends `numPackets` UDP packets with small delays between
// them, then waits briefly for any response. The actual success is
// determined later by checking if the WireGuard handshake completes.
func (h *HolePuncher) Punch(ctx context.Context, remoteEndpoint string) *HolePunchResult {
	start := time.Now()

	host, port, err := net.SplitHostPort(remoteEndpoint)
	if err != nil {
		return &HolePunchResult{
			Success:        false,
			LocalEndpoint:  h.localEndpoint,
			RemoteEndpoint: remoteEndpoint,
			Error:          fmt.Errorf("invalid remote endpoint: %w", err),
			Elapsed:        time.Since(start),
		}
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return &HolePunchResult{
			Success:        false,
			LocalEndpoint:  h.localEndpoint,
			RemoteEndpoint: remoteEndpoint,
			Error:          fmt.Errorf("resolve remote addr: %w", err),
			Elapsed:        time.Since(start),
		}
	}

	// Open a local UDP socket. We try to bind to the same port as
	// WireGuard to maximize the chance that the NAT mapping is reused.
	// If that fails (port in use by WireGuard itself), we bind to an
	// ephemeral port — the hole-punch still creates a mapping, just on
	// a different port. The WireGuard handshake will then create its own
	// mapping, but the NAT device has already seen outbound traffic to
	// this destination, which can help with some NAT implementations.
	localAddr := &net.UDPAddr{Port: h.punchPort}
	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		// Try ephemeral port if the WG port is in use.
		conn, err = net.DialUDP("udp", nil, remoteAddr)
		if err != nil {
			return &HolePunchResult{
				Success:        false,
				LocalEndpoint:  h.localEndpoint,
				RemoteEndpoint: remoteEndpoint,
				Error:          fmt.Errorf("dial UDP: %w", err),
				Elapsed:        time.Since(start),
			}
		}
	}
	defer conn.Close()

	// Set deadline based on context.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(h.timeout)
	}
	conn.SetDeadline(deadline)

	// Send probe packets. These are small UDP datagrams that create
	// NAT mappings on both sides. The content doesn't matter — it just
	// needs to be a valid UDP packet that the NAT device will forward.
	// We use STUN binding requests as probe packets because they're
	// well-formed and won't be dropped by DPI.
	probeMsg, err := stun.Build(stun.BindingRequest, stun.TransactionID)
	if err != nil {
		return &HolePunchResult{
			Success:        false,
			LocalEndpoint:  h.localEndpoint,
			RemoteEndpoint: remoteEndpoint,
			Error:          fmt.Errorf("build probe: %w", err),
			Elapsed:        time.Since(start),
		}
	}

	sentCount := 0
	for i := 0; i < h.numPackets; i++ {
		select {
		case <-ctx.Done():
			return &HolePunchResult{
				Success:        false,
				LocalEndpoint:  h.localEndpoint,
				RemoteEndpoint: remoteEndpoint,
				Error:          ctx.Err(),
				Elapsed:        time.Since(start),
			}
		default:
		}

		_, err := conn.Write(probeMsg.Raw)
		if err != nil {
			continue
		}
		sentCount++

		// Small delay between packets.
		if i < h.numPackets-1 {
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Wait briefly for any response from the peer. If we receive
	// anything, it means our NAT mapping is working in both directions.
	buf := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = conn.ReadFrom(buf)

	// Read error is expected — the peer may not be sending probes yet,
	// or the NAT may not have forwarded anything. The hole-punch is
	// still considered "sent" because we wrote packets to the peer's
	// endpoint. The actual success is verified by WireGuard handshake.
	_ = err // ignore — success is determined by WG handshake

	return &HolePunchResult{
		Success:        sentCount > 0,
		LocalEndpoint:  h.localEndpoint,
		RemoteEndpoint: remoteEndpoint,
		Error:          nil,
		Elapsed:        time.Since(start),
	}
}

// HolePunchCoordinator coordinates simultaneous hole-punching between
// two peers. Both sides must send probes to each other's endpoints
// at roughly the same time for the NAT mappings to be created.
//
// In the gossip-based architecture, endpoint information is shared via
// NodeMeta. When both peers have each other's STUN-discovered endpoint,
// they each run Punch() independently — the simultaneity is naturally
// achieved because both peers discover the need to connect at roughly
// the same time via gossip.
type HolePunchCoordinator struct {
	mu       sync.Mutex
	punchers map[string]*HolePuncher // peerKey → puncher
}

// NewHolePunchCoordinator creates a new coordinator.
func NewHolePunchCoordinator() *HolePunchCoordinator {
	return &HolePunchCoordinator{
		punchers: make(map[string]*HolePuncher),
	}
}

// RegisterPeer registers a peer for hole-punching with the given local
// endpoint and WireGuard port.
func (hc *HolePunchCoordinator) RegisterPeer(peerKey, localEndpoint string, wgPort int) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.punchers[peerKey] = NewHolePuncher(localEndpoint, wgPort)
}

// UnregisterPeer removes a peer from the coordinator.
func (hc *HolePunchCoordinator) UnregisterPeer(peerKey string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	delete(hc.punchers, peerKey)
}

// AttemptPunch performs a hole-punch to the given peer's endpoint.
// Returns the result of the attempt.
func (hc *HolePunchCoordinator) AttemptPunch(ctx context.Context, peerKey, remoteEndpoint string) *HolePunchResult {
	hc.mu.Lock()
	puncher, ok := hc.punchers[peerKey]
	hc.mu.Unlock()

	if !ok {
		return &HolePunchResult{
			Success:        false,
			RemoteEndpoint: remoteEndpoint,
			Error:          fmt.Errorf("peer %s not registered for hole-punching", safeShortKey(peerKey)),
		}
	}

	return puncher.Punch(ctx, remoteEndpoint)
}

// IsRegistered returns true if the peer is registered for hole-punching.
func (hc *HolePunchCoordinator) IsRegistered(peerKey string) bool {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	_, ok := hc.punchers[peerKey]
	return ok
}
