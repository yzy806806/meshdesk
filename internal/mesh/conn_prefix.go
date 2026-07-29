package mesh

import (
	"net"
	"time"
)

// connWithPrefix wraps a net.Conn and replays previously peeked bytes
// before reading from the underlying connection.
//
// In the single-port multiplexing design (Reality TLS + gossip sharing the
// same port), the listener peeks the first N bytes of an incoming connection
// to detect the protocol. Those bytes must then be "given back" so the actual
// protocol handler sees a clean stream starting from byte zero.
//
// connWithPrefix solves this: Read() first drains an in-memory prefix buffer
// (the peeked bytes), then delegates to the underlying conn. All other net.Conn
// methods — Write, Close, SetDeadline, SetReadDeadline, SetWriteDeadline,
// LocalAddr, RemoteAddr — pass through to the underlying conn unchanged.
//
// The prefix is immutable after construction; only the read offset advances.
// This makes the type safe for concurrent use as long as the underlying conn
// is safe for concurrent use (which net.Conn implementations are required to
// be for Read/Write from different goroutines).
type connWithPrefix struct {
	conn      net.Conn // underlying connection
	prefix    []byte   // peeked bytes to replay before reading from conn
	prefixOff int      // current offset into prefix
}

// NewConnWithPrefix creates a connWithPrefix that replays the given prefix
// bytes before reading from conn. The prefix slice is copied so the caller
// may reuse the original buffer.
func NewConnWithPrefix(conn net.Conn, prefix []byte) net.Conn {
	if len(prefix) == 0 {
		// No prefix to replay — return the conn as-is to avoid overhead.
		return conn
	}
	// Copy the prefix so the caller can reuse the original buffer.
	p := make([]byte, len(prefix))
	copy(p, prefix)
	return &connWithPrefix{
		conn:   conn,
		prefix: p,
	}
}

// Read reads data, first draining the prefix buffer (peeked bytes), then
// reading from the underlying connection.
func (c *connWithPrefix) Read(p []byte) (int, error) {
	if c.prefixOff < len(c.prefix) {
		// Still have prefix bytes to replay.
		n := copy(p, c.prefix[c.prefixOff:])
		c.prefixOff += n
		return n, nil
	}
	return c.conn.Read(p)
}

// Write passes through to the underlying connection.
func (c *connWithPrefix) Write(p []byte) (int, error) {
	return c.conn.Write(p)
}

// Close passes through to the underlying connection.
func (c *connWithPrefix) Close() error {
	return c.conn.Close()
}

// LocalAddr passes through to the underlying connection.
func (c *connWithPrefix) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr passes through to the underlying connection.
func (c *connWithPrefix) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline passes through to the underlying connection.
func (c *connWithPrefix) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline passes through to the underlying connection.
//
// Note: the read deadline applies to the underlying conn. While prefix bytes
// are being replayed, reads return immediately from the in-memory buffer and
// are not affected by the deadline. Once the prefix is exhausted, the deadline
// governs reads from the underlying conn as expected.
func (c *connWithPrefix) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline passes through to the underlying connection.
func (c *connWithPrefix) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// CloseWrite delegates to the underlying connection's CloseWrite method.
// This is required by the xtls/reality library, which type-asserts the
// net.Conn to CloseWriteConn (interface { net.Conn; CloseWrite() error }).
// Without this method, the reality server's goroutine panics on the type
// assertion, silently drops the connection (recovered by defer/recover),
// and the REALITY TLS handshake hangs forever.
//
// The underlying conn is always *net.TCPConn when used with the MuxTransport
// (which accepts from a net.TCPListener), so the delegation always succeeds.
type closeWriter interface {
	CloseWrite() error
}

func (c *connWithPrefix) CloseWrite() error {
	if cw, ok := c.conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	// Best-effort: if the underlying conn doesn't implement CloseWrite,
	// a no-op return is safe — the reality library only uses it to signal
	// FIN to the target, and Close() will follow immediately after.
	return nil
}

// Ensure connWithPrefix satisfies net.Conn.
var _ net.Conn = (*connWithPrefix)(nil)
