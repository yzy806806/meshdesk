package holepunch

import (
	"context"
	"log"
	"net"
	"strconv"
	"time"
)

// TCP hole punch: both sides bind the same local port and connect to
// the peer's mapped endpoint simultaneously. The key trick (from
// EasyTier's analysis) is keeping the socket alive after bind — never
// close+rebind, or the NAT mapping is lost. On Linux we rely on
// SO_REUSEADDR via net.ListenTCP + Dial from the same local address.
func (e *Engine) punchTCP(peerKey string, endpoints []string) string {
	if len(endpoints) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), punchTimeout)
	defer cancel()

	// Exchange params (nonce + mapped endpoint) over the coordination
	// stream, same as UDP. The peer's TCP punch port (if announced)
	// is our dial target — its public IP + TcpPort.
	peerEP, nonce, err := e.exchangePunchParams(ctx, peerKey, endpoints[0])
	if err != nil {
		return ""
	}
	if peerEP == "" {
		return ""
	}
	e.mu.Lock()
	peerTCP := e.peerTCPPort[peerKey]
	peerSrc := e.peerSrcPort[peerKey]
	e.mu.Unlock()
	// Prefer the peer's outbound source port (conntrack punch —
	// stateful security groups pass ESTABLISHED); fall back to its
	// punch listen port.
	port := peerSrc
	if port <= 0 {
		port = peerTCP
	}
	if port <= 0 {
		// The peer didn't announce a TCP punch port — TCP punching
		// cannot work (both sides must listen + connect). Skip fast.
		return ""
	}
	if host, _, herr := net.SplitHostPort(peerEP); herr == nil {
		peerEP = net.JoinHostPort(host, strconv.Itoa(port))
	}
	// Bind the punch port (fixed source port = conntrack match). If
	// the fixed port is taken, fall back to ephemeral — but then the
	// peer cannot blind-connect to the announced SrcPort.
	bindPort := e.TcpPort
	if bindPort <= 0 {
		bindPort = e.PunchPort
	}
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: bindPort})
	if err != nil && bindPort != 0 {
		// Fixed port busy (e.g. another punch in flight) — ephemeral
		// is a degraded mode (no conntrack match).
		ln, err = net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
	}
	if err != nil {
		return ""
	}
	defer ln.Close()

	// Our outbound source port is what the peer must blind-connect to
	// (conntrack punch): the bound listener port.
	if p := ln.Addr().(*net.TCPAddr).Port; p > 0 {
		e.SrcPort = p
	}

	// Concurrently: listen for the peer's inbound connect AND dial out.
	type result struct {
		conn net.Conn
	}
	got := make(chan result, 1)

	go func() {
		ln.SetDeadline(time.Now().Add(punchTimeout))
		conn, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		got <- result{conn: conn}
	}()

	// Dial out to the peer's mapped endpoint, retrying at an interval
	// (EasyTier-style sustained SYN): each attempt refreshes our NAT
	// mapping and, once the peer's own outbound created its conntrack
	// entry, our SYN passes as ESTABLISHED (stateful security groups).
	// We never close an accepted conn until we know the outcome — a
	// close sends RST and breaks the mapping.
	dl := &net.Dialer{LocalAddr: ln.Addr()}
	retry := time.NewTicker(250 * time.Millisecond)
	defer retry.Stop()
	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		for {
			outConn, outErr := dl.DialContext(ctx, "tcp", peerEP)
			if outErr == nil {
				outConn.SetDeadline(time.Now().Add(2 * time.Second))
				if verifyNonce(outConn, nonce) {
					outConn.Close()
					select {
					case got <- result{conn: nil}:
					default:
					}
					return
				}
				outConn.Close()
			}
			select {
			case <-retry.C:
			case <-ctx.Done():
				return
			}
		}
	}()

	// First success wins.
	for {
		select {
		case r := <-got:
			if r.conn != nil {
				r.conn.Close()
			}
			return peerEP
		case <-ctx.Done():
			return ""
		}
	}
}

// verifyNonce writes the nonce and reads it back — cheap proof the
// peer's TCP hole is genuinely wired to us.
func verifyNonce(conn net.Conn, nonce uint32) bool {
	buf := make([]byte, 4)
	if _, err := conn.Write(buf); err != nil {
		return false
	}
	buf2 := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(buf2); err != nil {
		return false
	}
	return true
}

func verifyAndClose(conn net.Conn, nonce uint32) {
	verifyNonce(conn, nonce)
	conn.Close()
}

// tcpBlindConnect is the coordinator-side half of the TCP hole punch:
// after the exchange, connect back to the peer's announced TCP port so
// the hole opens both ways (EasyTier's trick). The connection itself
// is short-lived — its purpose is opening the NAT mapping.
func (e *Engine) tcpBlindConnect(target string, nonce uint32) {
	dl := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dl.Dial("tcp", target)
	if err != nil {
		return
	}
	conn.Close()
	log.Printf("[holepunch] TCP blind-connect to %s done", target)
}
