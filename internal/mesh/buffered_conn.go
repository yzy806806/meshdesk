package mesh

import (
	"bufio"
	"net"
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
