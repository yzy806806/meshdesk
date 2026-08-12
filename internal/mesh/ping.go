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

// rttCacheTTL bounds how long PeerRTT results are reused.
const rttCacheTTL = 30 * time.Second

// rttCacheEntry is a cached PeerRTT measurement.
type rttCacheEntry struct {
	rtt time.Duration
	at  time.Time
}

// PeerRTT measures the round-trip time to a peer over its session using
// the echo virtual port. Results are cached for rttCacheTTL — topology
// renders and exit selection call this frequently (O(n²) pairs), and
// the echo dial per call would add up on larger meshes. Returns 0 when
// the peer is unreachable or has no session (callers treat 0 as
// "unknown").
func (n *MeshNode) PeerRTT(peerKey string) time.Duration {
	// Cached result within TTL?
	n.sessionsMu.Lock()
	if e, ok := n.rttCache[peerKey]; ok && time.Since(e.at) < rttCacheTTL {
		n.sessionsMu.Unlock()
		return e.rtt
	}
	n.sessionsMu.Unlock()

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
	rtt := time.Since(now)

	// Cache (even 0 is fine to cache — peer unreachable within TTL).
	n.sessionsMu.Lock()
	n.rttCache[peerKey] = rttCacheEntry{rtt: rtt, at: time.Now()}
	n.sessionsMu.Unlock()
	return rtt
}
