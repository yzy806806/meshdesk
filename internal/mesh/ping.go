package mesh

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// PingVirtualPort is a lightweight echo service used to measure the
// round-trip to a peer over its session (0x5049 = 'P' 'I' mnemonic).
// The client writes a 8-byte unix-nano timestamp; the server echoes it
// back; the client computes RTT. Runs on every node.
const PingVirtualPort = 0x5049

// RegisterPingHandler starts the echo service on every node (called at
// startup, like RegisterMetaExchanger).
func (n *MeshNode) RegisterPingHandler() error {
	ln, err := n.ListenVirtualPort(PingVirtualPort)
	if err != nil {
		return err
	}
	go n.pingEchoLoop(ln)
	return nil
}

func (n *MeshNode) pingEchoLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-n.ctx.Done():
				return
			default:
			}
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 8)
			for {
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		}(conn)
	}
}

// PeerRTT measures the round-trip time to a peer over its session using
// the echo virtual port. Returns 0 when the peer is unreachable or has
// no session (callers treat 0 as "unknown").
func (n *MeshNode) PeerRTT(peerKey string) time.Duration {
	ctx, cancel := context.WithTimeout(n.ctx, 3*time.Second)
	defer cancel()
	conn, err := n.DialVirtualPort(ctx, peerKey, PingVirtualPort)
	if err != nil {
		return 0
	}
	defer conn.Close()

	now := time.Now()
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(now.UnixNano()))
	if _, err := conn.Write(ts[:]); err != nil {
		return 0
	}
	var echo [8]byte
	if _, err := io.ReadFull(conn, echo[:]); err != nil {
		return 0
	}
	// If the echo payload differs from our timestamp, it is not our
	// pong — measure by arrival time anyway (the connection is
	// point-to-point on this stream).
	_ = echo
	return time.Since(now)
}
