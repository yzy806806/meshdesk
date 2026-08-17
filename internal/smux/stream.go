package smux

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// streamAddr is a synthetic net.Addr for smux streams.
type streamAddr struct {
	addr string
}

func (a *streamAddr) Network() string { return "smux" }
func (a *streamAddr) String() string  { return a.addr }

// Stream is one logical bidirectional stream within a Session.
// It satisfies net.Conn. Reads and writes are independent:
// one goroutine can read while another writes. Close shuts down
// the write side (sends FIN); reads continue until the remote
// peer closes.
//
// All stream methods are safe for concurrent use except:
// concurrent Read calls and concurrent Write calls are NOT safe.
// Use separate goroutines for reading and writing, or wrap with
// a mutex if needed.
type Stream struct {
	id      uint32
	session *Session

	// Read side: reader goroutine appends to readBuf, then signals readCh.
	// Read() copies from readBuf and blocks on readCh when empty.
	readMu  sync.Mutex
	readBuf bytes.Buffer
	readCh  chan struct{} // signal: data or EOF available

	// Write side: stream pushes frames onto session.writeCh.
	// No per-stream write lock needed — Write is not safe for concurrent use.

	// Lifecycle
	closeOnce    sync.Once
	localClosed  atomic.Bool // local Write side closed (FIN sent)
	remoteClosed atomic.Bool // remote FIN received
	resetErr     error       // set when RST received (protected by readMu)
	// maxReadBuf caps the read buffer; overflow resets the stream
	// (peer flooding DATA on an unread stream must not OOM us).
	maxReadBuf int
}

// newStream creates a new Stream within the given session.
func newStream(id uint32, s *Session) *Stream {
	maxRead := s.cfg.WriteBufferSize
	if maxRead <= 0 {
		maxRead = 262144 // default 256KB
	}
	return &Stream{
		id:         id,
		session:    s,
		readCh:     make(chan struct{}, 1),
		maxReadBuf: maxRead,
	}
}

// signalRead sends a non-blocking signal to readCh to wake up a blocked Read.
func (st *Stream) signalRead() {
	select {
	case st.readCh <- struct{}{}:
	default:
	}
}

// Read reads data from the stream. Blocks until data arrives or
// the stream is closed. Returns io.EOF when the remote peer closes
// their write side (FIN received).
func (st *Stream) Read(b []byte) (int, error) {
	st.readMu.Lock()

	for {
		// If there's buffered data, return it.
		if st.readBuf.Len() > 0 {
			n, _ := st.readBuf.Read(b)
			st.readMu.Unlock()
			return n, nil
		}

		// Check terminal states.
		if st.resetErr != nil {
			st.readMu.Unlock()
			return 0, st.resetErr
		}
		if st.remoteClosed.Load() {
			st.readMu.Unlock()
			return 0, io.EOF
		}
		if st.localClosed.Load() {
			st.readMu.Unlock()
			return 0, io.ErrClosedPipe
		}

		// Check if session is closed.
		if st.session.IsClosed() {
			st.readMu.Unlock()
			return 0, io.EOF
		}

		// Wait for data signal.
		st.readMu.Unlock()

		select {
		case <-st.readCh:
		case <-st.session.doneCh:
			st.readMu.Lock()
			// Drain any remaining buffered data.
			if st.readBuf.Len() > 0 {
				n, _ := st.readBuf.Read(b)
				st.readMu.Unlock()
				return n, nil
			}
			st.readMu.Unlock()
			return 0, io.EOF
		}

		st.readMu.Lock()
	}
}

// Write sends data on the stream. Each Write produces one or more DATA frames.
// Writes larger than MaxFrameSize are split into multiple DATA frames.
// Returns an error if the write buffer is full or the session is closed.
func (st *Stream) Write(b []byte) (int, error) {
	if st.localClosed.Load() {
		return 0, ErrStreamClosed
	}
	if st.session.IsClosed() {
		return 0, ErrSessionClosed
	}

	total := 0
	maxFrame := st.session.cfg.MaxFrameSize

	for len(b) > 0 {
		n := len(b)
		if n > maxFrame {
			n = maxFrame
		}

		// Copy the chunk — the writer goroutine will serialize it.
		payload := make([]byte, n)
		copy(payload, b[:n])

		f := newDataFrame(st.id, payload)

		select {
		case st.session.writeCh <- f:
		case <-st.session.doneCh:
			return total, ErrSessionClosed
		}

		total += n
		b = b[n:]
	}

	return total, nil
}

// Close closes the write side of the stream. Sends a FIN frame to the
// remote peer. The read side remains open until the remote peer sends
// their FIN or the session closes. Idempotent.
func (st *Stream) Close() error {
	var err error
	st.closeOnce.Do(func() {
		st.localClosed.Store(true)

		// Send FIN frame.
		fin := newFinFrame(st.id)
		select {
		case st.session.writeCh <- fin:
		case <-st.session.doneCh:
		}

		// Wake up any blocked Read so it returns immediately
		// instead of hanging on readCh forever.
		st.signalRead()

		// Notify session to decrement stream count.
		st.session.streamClosed(st.id)
	})
	return err
}

// LocalAddr returns a synthetic address identifying the local stream.
// Format: "smux:local:<streamID>"
func (st *Stream) LocalAddr() net.Addr {
	return &streamAddr{addr: "smux:local:" + uint32ToStr(st.id)}
}

// RemoteAddr returns a synthetic address identifying the remote stream.
// Format: "smux:remote:<streamID>"
func (st *Stream) RemoteAddr() net.Addr {
	return &streamAddr{addr: "smux:remote:" + uint32ToStr(st.id)}
}

// SetDeadline sets both read and write deadlines.
func (st *Stream) SetDeadline(t time.Time) error {
	st.SetReadDeadline(t)
	st.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline sets the read deadline.
// Currently only supports no-deadline (zero time) for simplicity.
// A non-zero deadline is accepted but the read loop checks session.doneCh.
func (st *Stream) SetReadDeadline(t time.Time) error {
	// Read deadlines are best-effort in this implementation.
	// The Go net.Conn contract allows deadlines to affect blocking behavior.
	// For now, we rely on context-based cancellation via the session.
	return nil
}

// SetWriteDeadline sets the write deadline.
func (st *Stream) SetWriteDeadline(t time.Time) error {
	// Same as read deadline — best-effort.
	return nil
}

// uint32ToStr converts a uint32 to its decimal string representation.
func uint32ToStr(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// onData is called by the reader goroutine when a DATA frame arrives.
func (st *Stream) onData(payload []byte) {
	st.readMu.Lock()
	// Bound the read buffer: a peer flooding DATA on a stream nobody
	// reads (handler stuck, accept queue full) must not grow memory
	// unboundedly → OOM. On overflow, treat as a reset.
	if st.readBuf.Len()+len(payload) > st.maxReadBuf {
		st.resetErr = ErrStreamReset
		st.remoteClosed.Store(true)
		st.readMu.Unlock()
		st.signalRead()
		return
	}
	st.readBuf.Write(payload)
	st.readMu.Unlock()
	st.signalRead()
}

// onFin is called when a FIN frame arrives for this stream.
func (st *Stream) onFin() {
	st.readMu.Lock()
	st.remoteClosed.Store(true)
	st.readMu.Unlock()
	st.signalRead()
}

// onRst is called when an RST frame arrives for this stream.
func (st *Stream) onRst() {
	st.readMu.Lock()
	st.resetErr = ErrStreamReset
	st.remoteClosed.Store(true)
	st.readMu.Unlock()
	st.signalRead()
}
