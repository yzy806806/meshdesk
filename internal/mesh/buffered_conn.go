package mesh

import (
	"bufio"
	"net"
	"sync"
	"time"
)

// bufferedConn wraps a net.Conn with a bufio.Reader so that peeked bytes
// are retained in the buffer and replayed on Read. This is used by
// MuxTransport to pass connections to memberlist's StreamCh without
// losing the first byte that was peeked for route matching.
//
// Unlike connWithPrefix, bufferedConn does not have a separate prefix
// buffer — the peeked byte lives inside the bufio.Reader's internal
// buffer and is transparently replayed by any subsequent Read, Peek,
// or fill operation. This avoids the double-buffering issue that
// occurs when memberlist's RemoveLabelHeaderFromStream wraps a
// connWithPrefix in another bufio.Reader.
type bufferedConn struct {
	*bufio.Reader
	conn net.Conn
}

// newBufferedConn peeks the first byte of conn, then wraps it in a
// bufio.Reader so the peeked byte is retained. The returned net.Conn
// will replay the peeked byte on the first Read.
func newBufferedConn(conn net.Conn) (net.Conn, byte, error) {
	br := bufio.NewReader(conn)
	peek, err := br.Peek(1)
	if err != nil {
		return nil, 0, err
	}
	return &bufferedConn{Reader: br, conn: conn}, peek[0], nil
}

// Read delegates to the bufio.Reader, which replays buffered bytes first.
func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.Reader.Read(p)
}

// Write delegates to the underlying connection.
func (b *bufferedConn) Write(p []byte) (int, error) {
	return b.conn.Write(p)
}

// Close closes the underlying connection.
func (b *bufferedConn) Close() error {
	return b.conn.Close()
}

// LocalAddr returns the underlying connection's local address.
func (b *bufferedConn) LocalAddr() net.Addr {
	return b.conn.LocalAddr()
}

// RemoteAddr returns the underlying connection's remote address.
func (b *bufferedConn) RemoteAddr() net.Addr {
	return b.conn.RemoteAddr()
}

// SetDeadline sets the deadline on the underlying connection.
func (b *bufferedConn) SetDeadline(t time.Time) error {
	return b.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (b *bufferedConn) SetReadDeadline(t time.Time) error {
	return b.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
func (b *bufferedConn) SetWriteDeadline(t time.Time) error {
	return b.conn.SetWriteDeadline(t)
}

// skipPrefixConn wraps a bufio.Reader and skips the first byte on the
// first Read. Used for mesh-internal connections where the 0x4D marker
// byte was peeked by bufferedConn but should not be replayed to the
// mesh key exchange.
type skipPrefixConn struct {
	*bufio.Reader
	conn  net.Conn
	once  sync.Once
}

func (s *skipPrefixConn) Read(p []byte) (int, error) {
	s.once.Do(func() {
		// Discard the first buffered byte (the 0x4D marker) on first Read.
		if s.Reader.Buffered() > 0 {
			_, _ = s.Reader.ReadByte()
		}
	})
	return s.Reader.Read(p)
}

func (s *skipPrefixConn) Write(p []byte) (int, error)      { return s.conn.Write(p) }
func (s *skipPrefixConn) Close() error                    { return s.conn.Close() }
func (s *skipPrefixConn) LocalAddr() net.Addr              { return s.conn.LocalAddr() }
func (s *skipPrefixConn) RemoteAddr() net.Addr            { return s.conn.RemoteAddr() }
func (s *skipPrefixConn) SetDeadline(t time.Time) error   { return s.conn.SetDeadline(t) }
func (s *skipPrefixConn) SetReadDeadline(t time.Time) error { return s.conn.SetReadDeadline(t) }
func (s *skipPrefixConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

// newSkipPrefixConn creates a skipPrefixConn from a bufferedConn,
// discarding the first byte (marker) on the first Read.
func newSkipPrefixConn(bc *bufferedConn, conn net.Conn) net.Conn {
	return &skipPrefixConn{Reader: bc.Reader, conn: conn}
}
