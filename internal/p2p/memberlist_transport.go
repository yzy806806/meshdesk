package p2p

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/yzy806806/meshdesk/internal/mesh"
)

// MeshTransport implements the memberlist.Transport interface using the
// gVisor netstack from the existing WireGuard mesh. All gossip traffic
// flows through WireGuard encryption — no separate transport needed.
//
// Since we use TCP for everything (gVisor netstack has no UDP), both
// memberlist packet operations (WriteTo) and stream operations
// (DialTimeout) arrive on the same TCP listener. We demultiplex by
// peeking the first byte (msgType): stream-capable types go to StreamCh,
// the rest are wrapped as memberlist.Packet and sent to PacketCh.
type MeshTransport struct {
	node       *mesh.MeshNode
	meshIP     string
	gossipPort int

	mu       sync.Mutex
	listener net.Listener
	closed   bool

	// Packet channel for incoming UDP-like packets (wrapped TCP)
	packetCh chan *memberlist.Packet

	// Stream channel for incoming TCP/stream connections
	streamCh chan net.Conn
}

// memberlist message type constants (from memberlist/net.go)
const (
	mtPingMsg       = 0
	mtIndirectPing  = 1
	mtAckRespMsg    = 2
	mtSuspectMsg    = 3
	mtAliveMsg      = 4
	mtDeadMsg       = 5
	mtPushPullMsg   = 6
	mtCompoundMsg   = 7
	mtUserMsg       = 8
	mtCompressMsg   = 9
	mtEncryptMsg    = 10
	mtNackRespMsg   = 11
	mtHasCrcMsg     = 12
	mtErrMsg        = 13
)

// streamMsgTypes is the set of msgTypes that memberlist's stream handler
// (handleConn) knows how to process. Everything else must go to PacketCh.
var streamMsgTypes = map[byte]bool{
	mtPingMsg:     true,
	mtPushPullMsg: true,
	mtUserMsg:     true,
}

// NewMeshTransport creates a new transport that uses the mesh node's gVisor
// netstack for TCP connections.
func NewMeshTransport(node *mesh.MeshNode, meshIP string, gossipPort int) *MeshTransport {
	return &MeshTransport{
		node:       node,
		meshIP:     meshIP,
		gossipPort: gossipPort,
		packetCh:   make(chan *memberlist.Packet, 64),
		streamCh:   make(chan net.Conn, 16),
	}
}

// FinalAdvertiseAddr returns the address to advertise for this transport.
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
//
// To distinguish packet connections from stream connections on the
// receiver side, we prefix packet data with a 1-byte length-of-prefix
// marker (0xFF) that is NOT a valid memberlist msgType. The receiver
// peeks the first byte: 0xFF = packet, anything else = stream.
func (t *MeshTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	conn, err := t.DialTimeout(addr, 5*time.Second)
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()

	// Write a 1-byte sentinel (0xFF) to indicate this is a packet,
	// followed by a 4-byte big-endian length, then the payload.
	// 0xFF is not a valid memberlist msgType (max is 13).
	header := make([]byte, 5)
	header[0] = 0xFF
	binary.BigEndian.PutUint32(header[1:5], uint32(len(b)))

	if _, err := conn.Write(header); err != nil {
		return time.Time{}, err
	}
	if _, err := conn.Write(b); err != nil {
		return time.Time{}, err
	}

	return time.Now(), nil
}

// PacketCh returns a channel for receiving incoming packets.
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
	return t.streamCh
}

// acceptLoop runs in a goroutine, accepting connections and demultiplexing
// them into packet vs stream based on the first byte.
func (t *MeshTransport) acceptLoop() {
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

		go t.handleConn(conn)
	}
}

// handleConn peeks the first byte to determine if this is a packet
// (sentinel 0xFF) or a stream connection (memberlist msgType).
func (t *MeshTransport) handleConn(conn net.Conn) {
	br := bufio.NewReader(conn)

	// Peek 1 byte — don't consume yet
	first, err := br.Peek(1)
	if err != nil {
		conn.Close()
		return
	}

	if first[0] == 0xFF {
		// Packet: read sentinel + length + payload
		_, _ = br.ReadByte() // consume sentinel
		var lenBuf [4]byte
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			conn.Close()
			return
		}
		payloadLen := binary.BigEndian.Uint32(lenBuf[:])
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(br, payload); err != nil {
			conn.Close()
			return
		}

		// Extract remote address
		fromAddr := conn.RemoteAddr()

		pkt := &memberlist.Packet{
			Buf:       payload,
			From:      fromAddr,
			Timestamp: time.Now(),
		}

		select {
		case t.packetCh <- pkt:
		default:
			// Channel full, drop packet
		}
		conn.Close()
	} else {
		// Stream connection: hand the buffered reader (which has the
		// first byte still buffered) to memberlist via StreamCh.
		// Wrap in a bufferedConn so memberlist can read the first byte.
		wrapped := &bufferedConn{br: br, Conn: conn}

		select {
		case t.streamCh <- wrapped:
		default:
			conn.Close()
		}
	}
}

// bufferedConn wraps a bufio.Reader + net.Conn so that peeked data
// is not lost when memberlist reads from the connection.
type bufferedConn struct {
	br *bufio.Reader
	net.Conn
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.br.Read(p)
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

	// Start the accept loop
	go t.acceptLoop()

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
