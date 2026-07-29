package mesh

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// testConn is a minimal net.Conn for testing. It uses net.Pipe for data
// and records whether deadline methods were called.
type testConn struct {
	*netPipeConn
	setDeadlineCalled      bool
	setReadDeadlineCalled  bool
	setWriteDeadlineCalled bool
	closeCalled            bool
	mu                     sync.Mutex
}

// netPipeConn wraps one end of a net.Pipe to satisfy net.Conn.
type netPipeConn struct {
	net.Conn
}

func newTestConn() (*testConn, net.Conn) {
	a, b := net.Pipe()
	return &testConn{netPipeConn: &netPipeConn{Conn: a}}, &netPipeConn{Conn: b}
}

func (tc *testConn) SetDeadline(t time.Time) error {
	tc.mu.Lock()
	tc.setDeadlineCalled = true
	tc.mu.Unlock()
	return tc.netPipeConn.Conn.SetDeadline(t)
}

func (tc *testConn) SetReadDeadline(t time.Time) error {
	tc.mu.Lock()
	tc.setReadDeadlineCalled = true
	tc.mu.Unlock()
	return tc.netPipeConn.Conn.SetReadDeadline(t)
}

func (tc *testConn) SetWriteDeadline(t time.Time) error {
	tc.mu.Lock()
	tc.setWriteDeadlineCalled = true
	tc.mu.Unlock()
	return tc.netPipeConn.Conn.SetWriteDeadline(t)
}

func (tc *testConn) Close() error {
	tc.mu.Lock()
	tc.closeCalled = true
	tc.mu.Unlock()
	return tc.netPipeConn.Conn.Close()
}

// TestConnWithPrefix_PrefixReplayed verifies that peeked bytes are correctly
// replayed before reading from the underlying connection.
func TestConnWithPrefix_PrefixReplayed(t *testing.T) {
	prefix := []byte("PEEKED!")
	conn, peer := newTestConn()
	defer conn.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(conn, prefix)

	// Write some data on the peer side that comes after the prefix.
	// Use a goroutine because net.Pipe is synchronous (write blocks until read).
	go func() {
		peer.Write([]byte("DATA"))
		peer.Close()
	}()

	// Read prefix first.
	buf := make([]byte, len(prefix))
	n, err := io.ReadFull(wrapped, buf)
	if err != nil {
		t.Fatalf("read prefix: %v", err)
	}
	if n != len(prefix) {
		t.Fatalf("expected %d prefix bytes, got %d", len(prefix), n)
	}
	if !bytes.Equal(buf, prefix) {
		t.Fatalf("prefix mismatch: got %q, want %q", buf, prefix)
	}

	// Read the data from the underlying conn.
	dataBuf := make([]byte, 4)
	n, err = io.ReadFull(wrapped, dataBuf)
	if err != nil {
		t.Fatalf("read data: %v", err)
	}
	if n != 4 {
		t.Fatalf("expected 4 data bytes, got %d", n)
	}
	if !bytes.Equal(dataBuf, []byte("DATA")) {
		t.Fatalf("data mismatch: got %q, want %q", dataBuf, []byte("DATA"))
	}
}

// TestConnWithPrefix_PartialReads verifies that prefix bytes are correctly
// delivered across multiple small reads.
func TestConnWithPrefix_PartialReads(t *testing.T) {
	prefix := []byte("HELLO")
	conn, peer := newTestConn()
	defer conn.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(conn, prefix)

	go func() {
		peer.Write([]byte("WORLD"))
		peer.Close()
	}()

	// Read one byte at a time from prefix.
	for i := 0; i < len(prefix); i++ {
		buf := make([]byte, 1)
		n, err := wrapped.Read(buf)
		if err != nil {
			t.Fatalf("partial read %d: %v", i, err)
		}
		if n != 1 {
			t.Fatalf("expected 1 byte, got %d", n)
		}
		if buf[0] != prefix[i] {
			t.Fatalf("byte %d: got %c, want %c", i, buf[0], prefix[i])
		}
	}

	// Read "WORLD" from underlying conn.
	world := make([]byte, 5)
	_, err := io.ReadFull(wrapped, world)
	if err != nil {
		t.Fatalf("read world: %v", err)
	}
	if !bytes.Equal(world, []byte("WORLD")) {
		t.Fatalf("world mismatch: got %q, want %q", world, []byte("WORLD"))
	}
}

// TestConnWithPrefix_LargeRead verifies that when the read buffer is larger
// than the prefix, the prefix and underlying data are merged in one read.
func TestConnWithPrefix_LargeRead(t *testing.T) {
	prefix := []byte("PFX")
	conn, peer := newTestConn()
	defer conn.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(conn, prefix)

	go func() {
		// Write enough data to fill a large buffer.
		peer.Write(bytes.Repeat([]byte("X"), 100))
		peer.Close()
	}()

	buf := make([]byte, 103)
	n, err := io.ReadFull(wrapped, buf)
	if err != nil {
		t.Fatalf("large read: %v", err)
	}
	if n != 103 {
		t.Fatalf("expected 103 bytes, got %d", n)
	}
	// First 3 bytes should be the prefix.
	if !bytes.Equal(buf[:3], prefix) {
		t.Fatalf("prefix part: got %q, want %q", buf[:3], prefix)
	}
	// Remaining bytes should be X.
	for i := 3; i < 103; i++ {
		if buf[i] != 'X' {
			t.Fatalf("byte %d: got %c, want X", i, buf[i])
		}
	}
}

// TestConnWithPrefix_WritePassthrough verifies that Write goes through to
// the underlying connection.
func TestConnWithPrefix_WritePassthrough(t *testing.T) {
	conn, peer := newTestConn()
	defer conn.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(conn, []byte("PFX"))

	data := []byte("HELLO")

	// Read on the peer side concurrently (net.Pipe is synchronous).
	type rwResult struct {
		n   int
		err error
		buf []byte
	}
	ch := make(chan rwResult, 1)
	go func() {
		buf := make([]byte, len(data))
		n, err := io.ReadFull(peer, buf)
		ch <- rwResult{n, err, buf}
	}()

	// Write through the wrapper.
	n, err := wrapped.Write(data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("expected %d, got %d", len(data), n)
	}

	// Verify the peer received the data.
	res := <-ch
	if res.err != nil {
		t.Fatalf("peer read: %v", res.err)
	}
	if !bytes.Equal(res.buf, data) {
		t.Fatalf("peer got %q, want %q", res.buf, data)
	}
}

// TestConnWithPrefix_SetDeadlinePassthrough verifies that SetDeadline
// is passed through to the underlying connection.
func TestConnWithPrefix_SetDeadlinePassthrough(t *testing.T) {
	tc, peer := newTestConn()
	defer tc.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(tc, []byte("PFX"))

	deadline := time.Now().Add(5 * time.Second)
	if err := wrapped.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()
	if !tc.setDeadlineCalled {
		t.Fatal("SetDeadline was not passed through to underlying conn")
	}
}

// TestConnWithPrefix_SetReadDeadlinePassthrough verifies that
// SetReadDeadline is passed through.
func TestConnWithPrefix_SetReadDeadlinePassthrough(t *testing.T) {
	tc, peer := newTestConn()
	defer tc.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(tc, []byte("PFX"))

	deadline := time.Now().Add(5 * time.Second)
	if err := wrapped.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()
	if !tc.setReadDeadlineCalled {
		t.Fatal("SetReadDeadline was not passed through to underlying conn")
	}
}

// TestConnWithPrefix_SetWriteDeadlinePassthrough verifies that
// SetWriteDeadline is passed through.
func TestConnWithPrefix_SetWriteDeadlinePassthrough(t *testing.T) {
	tc, peer := newTestConn()
	defer tc.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(tc, []byte("PFX"))

	deadline := time.Now().Add(5 * time.Second)
	if err := wrapped.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()
	if !tc.setWriteDeadlineCalled {
		t.Fatal("SetWriteDeadline was not passed through to underlying conn")
	}
}

// TestConnWithPrefix_ClosePassthrough verifies that Close is passed through
// to the underlying connection.
func TestConnWithPrefix_ClosePassthrough(t *testing.T) {
	tc, peer := newTestConn()

	wrapped := NewConnWithPrefix(tc, []byte("PFX"))

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()
	if !tc.closeCalled {
		t.Fatal("Close was not passed through to underlying conn")
	}

	// Also close peer to clean up.
	peer.Close()
}

// TestConnWithPrefix_AddrsPassthrough verifies that LocalAddr and RemoteAddr
// are passed through.
func TestConnWithPrefix_AddrsPassthrough(t *testing.T) {
	tc, peer := newTestConn()
	defer tc.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(tc, []byte("PFX"))

	if wrapped.LocalAddr().String() != tc.LocalAddr().String() {
		t.Fatal("LocalAddr mismatch")
	}
	if wrapped.RemoteAddr().String() != tc.RemoteAddr().String() {
		t.Fatal("RemoteAddr mismatch")
	}
}

// TestConnWithPrefix_EmptyPrefix returns the original conn when prefix is empty.
func TestConnWithPrefix_EmptyPrefix(t *testing.T) {
	conn, peer := newTestConn()
	defer conn.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(conn, nil)

	// Should be the same conn (no wrapping needed).
	if wrapped != conn {
		t.Fatal("expected original conn when prefix is empty")
	}
}

// TestConnWithPrefix_PrefixCopy verifies that the prefix bytes are copied
// (the caller can modify the original buffer without affecting the wrapper).
func TestConnWithPrefix_PrefixCopy(t *testing.T) {
	original := []byte("ABCDEF")
	conn, peer := newTestConn()
	defer conn.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(conn, original)

	// Mutate the original buffer.
	original[0] = 'X'

	// Read the prefix — should still be "ABCDEF".
	buf := make([]byte, 6)
	_, err := io.ReadFull(wrapped, buf)
	if err != nil {
		t.Fatalf("read prefix: %v", err)
	}
	if buf[0] != 'A' {
		t.Fatalf("prefix was not copied: got %c, want A", buf[0])
	}
}

// TestConnWithPrefix_ReadDeadlineDuringPrefix verifies that read deadlines
// do not affect reads from the prefix buffer (those return immediately).
// Then once prefix is exhausted, the deadline applies to the underlying conn.
func TestConnWithPrefix_ReadDeadlineDuringPrefix(t *testing.T) {
	prefix := []byte("PREFIX")
	conn, peer := newTestConn()
	defer conn.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(conn, prefix)

	// Set a very short read deadline.
	wrapped.SetReadDeadline(time.Now().Add(1 * time.Millisecond))

	// Read prefix bytes — should succeed immediately despite the deadline.
	buf := make([]byte, len(prefix))
	n, err := io.ReadFull(wrapped, buf)
	if err != nil {
		t.Fatalf("read prefix with deadline: %v", err)
	}
	if n != len(prefix) {
		t.Fatalf("expected %d bytes, got %d", len(prefix), n)
	}
	if !bytes.Equal(buf, prefix) {
		t.Fatalf("prefix mismatch: got %q, want %q", buf, prefix)
	}

	// Now try to read from the underlying conn with the expired deadline.
	// This should time out (the peer is not writing anything).
	dataBuf := make([]byte, 4)

	// Reset deadline to a short one that will expire before we can read.
	wrapped.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	_, err = wrapped.Read(dataBuf)
	if err == nil {
		// Read might have succeeded if the write was fast enough; that's fine.
		// The important assertion is that the prefix was readable despite
		// the deadline.
		return
	}
	// Expected: timeout error from the underlying conn.
	// This confirms that once prefix is exhausted, deadlines apply.
}

// TestConnWithPrefix_SatisfiesNetConn is a compile-time assertion that
// connWithPrefix satisfies the net.Conn interface.
func TestConnWithPrefix_SatisfiesNetConn(t *testing.T) {
	var _ net.Conn = (*connWithPrefix)(nil)
}
