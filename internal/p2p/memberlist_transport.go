package p2p

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/yzy806806/meshdesk/internal/mesh"
)

// MeshTransport implements the memberlist.Transport interface using the
// gVisor netstack from the existing WireGuard mesh. This means all gossip
// traffic flows through WireGuard encryption — no separate transport needed.
//
// memberlist.Transport requires:
//   - FinalAdvertiseAddr(ip string, port int) (net.IP, int, error)
//   - WriteTo(b []byte, addr string) (time.Time, error)
//   - PacketCh() <-chan *memberlist.Packet
//   - DialTimeout(addr string, timeout time.Duration) (net.Conn, error)
//   - StreamCh() <-chan net.Conn
//   - Shutdown() error
type MeshTransport struct {
	node       *mesh.MeshNode
	meshIP     string
	gossipPort int

	mu       sync.Mutex
	listener net.Listener
	closed   bool

	// Packet channel for incoming UDP-like packets (wrapped TCP)
	packetCh chan *memberlist.Packet
}

// NewMeshTransport creates a new transport that uses the mesh node's gVisor
// netstack for TCP connections.
func NewMeshTransport(node *mesh.MeshNode, meshIP string, gossipPort int) *MeshTransport {
	return &MeshTransport{
		node:       node,
		meshIP:     meshIP,
		gossipPort: gossipPort,
		packetCh:   make(chan *memberlist.Packet, 64),
	}
}

// FinalAdvertiseAddr returns the address to advertise for this transport.
// We always advertise the mesh IP (not a public endpoint) because gossip
// runs inside the WireGuard mesh.
func (t *MeshTransport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
	advertiseIP := net.ParseIP(t.meshIP)
	if advertiseIP == nil {
		return nil, 0, fmt.Errorf("invalid mesh IP: %s", t.meshIP)
	}
	return advertiseIP, t.gossipPort, nil
}

// WriteTo sends a packet to the given address. Memberlist uses this for
// UDP-style packet operations. Since we use TCP transport, we establish
// a short-lived TCP connection, send the packet, and close.
func (t *MeshTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	conn, err := t.DialTimeout(addr, 5*time.Second)
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()

	if _, err := conn.Write(b); err != nil {
		return time.Time{}, err
	}

	return time.Now(), nil
}

// PacketCh returns a channel for receiving incoming packets.
// Since we use TCP, incoming connections are accepted via the listener
// and the initial data is wrapped into a Packet.
func (t *MeshTransport) PacketCh() <-chan *memberlist.Packet {
	return t.packetCh
}

// DialTimeout dials a TCP connection through the gVisor netstack.
func (t *MeshTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return t.node.Dial(ctx, "tcp", addr)
}

// StreamCh returns a channel for incoming TCP/stream connections.
func (t *MeshTransport) StreamCh() <-chan net.Conn {
	ch := make(chan net.Conn, 16)

	go func() {
		defer close(ch)
		for {
			t.mu.Lock()
			ln := t.listener
			closed := t.closed
			t.mu.Unlock()

			if closed || ln == nil {
				return
			}

			conn, err := ln.Accept()
			if err != nil {
				if t.isClosed() {
					return
				}
				continue
			}

			// Try to send to stream channel. If the channel is full,
			// close the connection to avoid blocking.
			select {
			case ch <- conn:
			default:
				conn.Close()
			}
		}
	}()

	return ch
}

// Shutdown closes the transport and releases resources.
func (t *MeshTransport) Shutdown() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}

// Listen starts listening on the mesh IP + gossip port via the gVisor netstack.
// This is called internally during GossipLayer.Start() before creating memberlist.
func (t *MeshTransport) Listen() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	ln, err := t.node.Net().ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP(t.meshIP),
		Port: t.gossipPort,
	})
	if err != nil {
		return fmt.Errorf("listen on %s:%d: %w", t.meshIP, t.gossipPort, err)
	}

	t.listener = ln
	return nil
}

// GetAutoBindPort returns the configured gossip port.
func (t *MeshTransport) GetAutoBindPort() int {
	return t.gossipPort
}

// isClosed returns whether the transport has been shut down.
func (t *MeshTransport) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

// Ensure that MeshTransport satisfies the memberlist.Transport interface.
var _ memberlist.Transport = (*MeshTransport)(nil)
