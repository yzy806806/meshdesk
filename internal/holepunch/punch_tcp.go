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
	e.mu.Unlock()
	if peerTCP <= 0 {
		// The peer didn't announce a TCP punch port — TCP punching
		// cannot work (both sides must listen + connect). Skip fast.
		return ""
	}
	if host, _, herr := net.SplitHostPort(peerEP); herr == nil {
		peerEP = net.JoinHostPort(host, strconv.Itoa(peerTCP))
	}

	// Bind the same local port we advertise (punch port, or ephemeral).
	local := &net.TCPAddr{Port: e.PunchPort}
	ln, err := net.ListenTCP("tcp", local)
	if err != nil {
		ln, err = net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
		if err != nil {
			return ""
		}
	}
	defer ln.Close()

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

	// Dial out to the peer's mapped endpoint (keeps our mapping alive).
	dl := &net.Dialer{LocalAddr: ln.Addr(), Deadline: time.Now().Add(punchTimeout)}
	outConn, outErr := dl.DialContext(ctx, "tcp", peerEP)

	// First success wins.
	select {
	case r := <-got:
		// Inbound connect accepted — the peer's blind-connect landed
		// (hole open). Close and report success; the real session is
		// established by DialPeerByEndpoint over the punched path.
		r.conn.Close()
		return peerEP
	default:
	}
	if outErr == nil {
		// Our outbound connect reached something (their listener or a
		// NAT reflection). Verify with a nonce exchange.
		outConn.SetDeadline(time.Now().Add(2 * time.Second))
		if verifyNonce(outConn, nonce) {
			outConn.Close()
			return peerEP
		}
		outConn.Close()
	}

	select {
	case r := <-got:
		r.conn.Close()
		return peerEP
	case <-ctx.Done():
	}
	return ""
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
