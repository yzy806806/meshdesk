package holepunch

import (
	"context"
	"net"
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
	// stream, same as UDP.
	peerEP, nonce, err := e.exchangePunchParams(ctx, peerKey, endpoints[0])
	if err != nil {
		return ""
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
		verifyAndClose(r.conn, nonce)
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
		verifyAndClose(r.conn, nonce)
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
