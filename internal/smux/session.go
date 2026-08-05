package smux

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SessionStats holds traffic counters for a smux session.
type SessionStats struct {
	BytesSent     uint64 // total bytes written to conn (frame headers + payloads)
	BytesReceived uint64 // total bytes read from conn (frame headers + payloads)
}

// Session is a multiplexed session over a single underlying connection.
// It satisfies the multipath.Session interface.
//
// A Session is created by Client() or Server(). Once created, it reads
// from and writes to the underlying conn in background goroutines.
//
// Thread safety: All Session methods are safe for concurrent use.
type Session struct {
	conn       io.ReadWriteCloser
	bufReader  *bufio.Reader // buffered reader over conn
	cfg        Config
	clientMode bool

	// Streams
	streamsMu sync.RWMutex
	streams   map[uint32]*Stream

	// Stream ID allocation
	nextStreamID uint32

	// Stream count (for MaxStreams backpressure)
	streamSlotCh chan struct{} // semaphore for MaxStreams

	// Accept queue
	acceptCh chan *Stream

	// Write channel — all outbound frames go through here
	writeCh chan *frame

	// Lifecycle
	doneCh    chan struct{}
	closeOnce sync.Once
	closed    bool

	// Session handshake
	handshakeDone chan struct{}

	// Traffic counters (atomic, no lock needed)
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
}

// OpenStream creates a new stream and returns it as a net.Conn.
//
// Valid in both client and server mode. Client uses odd stream IDs,
// server uses even stream IDs. This allows both sides to initiate
// streams independently — necessary when one side doesn't listen
// on a public port and can only use the inbound session.
//
// Blocks if the number of active streams has reached MaxStreams.
// Returns an error if the session is closed or the context is cancelled.
func (s *Session) OpenStream(ctx context.Context) (net.Conn, error) {
	if s.IsClosed() {
		return nil, ErrSessionClosed
	}

	// Acquire a stream slot (MaxStreams backpressure).
	if s.cfg.MaxStreams > 0 {
		select {
		case s.streamSlotCh <- struct{}{}:
			// Got a slot.
		case <-ctx.Done():
			if s.IsClosed() {
				return nil, ErrSessionClosed
			}
			return nil, ErrMaxStreams
		case <-s.doneCh:
			return nil, ErrSessionClosed
		}
	}

	// Allocate the next odd stream ID.
	s.streamsMu.Lock()
	if s.nextStreamID >= MaxStreamID {
		s.streamsMu.Unlock()
		// Release the slot.
		if s.cfg.MaxStreams > 0 {
			<-s.streamSlotCh
		}
		return nil, ErrStreamsExhausted
	}
	streamID := s.nextStreamID
	s.nextStreamID += 2 // odd IDs: 1, 3, 5, ...
	st := newStream(streamID, s)
	s.streams[streamID] = st
	s.streamsMu.Unlock()

	// Send SYN frame to the remote peer.
	syn := newSynFrame(streamID, false)
	select {
	case s.writeCh <- syn:
	case <-s.doneCh:
		s.removeStream(streamID)
		return nil, ErrSessionClosed
	}

	// Wait for the remote SYN+ACK (or just proceed — the remote will
	// accept the stream and may send data immediately).
	// For simplicity, we don't wait for an explicit ACK. The stream
	// is usable immediately — the remote will create a stream on
	// receiving our SYN and deliver it via AcceptStream.

	return st, nil
}

// AcceptStream blocks until a remote-initiated stream arrives, then
// returns it as a net.Conn.
//
// Returns an error if the session is closed. Context cancellation
// interrupts the wait.
func (s *Session) AcceptStream(ctx context.Context) (net.Conn, error) {
	if s.IsClosed() {
		return nil, ErrSessionClosed
	}

	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.doneCh:
		return nil, ErrSessionClosed
	}
}

// NumStreams returns the number of currently open streams.
// Includes both locally-opened and remotely-opened streams.
func (s *Session) NumStreams() int {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()
	return len(s.streams)
}

// Stats returns the current traffic counters for this session.
func (s *Session) Stats() SessionStats {
	return SessionStats{
		BytesSent:     s.bytesSent.Load(),
		BytesReceived: s.bytesReceived.Load(),
	}
}

// Close shuts down the session gracefully.
//
// Sends a GO_AWAY frame to the remote peer, closes all open streams
// (each stream receives io.EOF on its next Read), stops background
// goroutines, and closes the underlying conn. Idempotent.
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.streamsMu.Lock()
		s.closed = true
		s.streamsMu.Unlock()

		close(s.doneCh)

		// Send GO_AWAY.
		ga := newGoAwayFrame(GoAwayNormal)
		// Try to send, but don't block if the session is already torn down.
		select {
		case s.writeCh <- ga:
		default:
		}

		// Close all streams.
		s.streamsMu.Lock()
		for _, st := range s.streams {
			st.onFin() // signal EOF to all readers
		}
		s.streams = make(map[uint32]*Stream)
		s.streamsMu.Unlock()

		// Close the underlying conn.
		err = s.conn.Close()
	})
	return err
}

// IsClosed reports whether Close() has been called.
func (s *Session) IsClosed() bool {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()
	return s.closed
}

// Done returns a channel that is closed when the session terminates —
// either via an explicit Close() call, a GO_AWAY frame from the remote
// peer, or an unrecoverable I/O error on the underlying connection
// (which triggers abort).
//
// Callers can use this to detect session loss and trigger reconnection
// logic:
//
//	<-sess.Done()
//	// session is gone — reconnect
//
// The channel is never reassigned; it is safe to select on concurrently
// from multiple goroutines.
func (s *Session) Done() <-chan struct{} {
	return s.doneCh
}

// ── Internal methods ──────────────────────────────────────────────────

// removeStream removes a stream from the session map.
func (s *Session) removeStream(id uint32) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
}

// streamClosed is called by Stream.Close() to decrement the stream count
// and release the MaxStreams slot.
func (s *Session) streamClosed(id uint32) {
	s.removeStream(id)
	if s.cfg.MaxStreams > 0 {
		select {
		case <-s.streamSlotCh:
		default:
		}
	}
}

// writer goroutine: reads frames from writeCh and writes them to conn.
func (s *Session) writer() {
	for {
		select {
		case f := <-s.writeCh:
			if err := writeFrame(s.conn, f); err != nil {
				s.abort(err)
				return
			}
			s.bytesSent.Add(uint64(HeaderSize + len(f.Payload)))
		case <-s.doneCh:
			return
		}
	}
}

// reader goroutine: reads frames from conn and dispatches them.
func (s *Session) reader() {
	for {
		f, err := readFrame(s.bufReader)
		if err != nil {
			s.abort(err)
			return
		}

		// Count received bytes (header + payload).
		s.bytesReceived.Add(uint64(HeaderSize + len(f.Payload)))

		// Validate version.
		if f.Version != ProtocolVersion {
			// Send GO_AWAY with protocol error.
			select {
			case s.writeCh <- newGoAwayFrame(GoAwayProtocolError):
			default:
			}
			s.abort(errors.New("smux: unsupported protocol version"))
			return
		}

		s.dispatch(f)
	}
}

// dispatch routes a frame to the appropriate stream or control handler.
func (s *Session) dispatch(f *frame) {
	// Stream 0 is the control channel — handle session-level frames.
	if f.StreamID == 0 {
		switch f.Type {
		case FrameSyn:
			s.handleHandshakeSyn(f)
		case FramePing:
			resp := newPingFrame(binary.BigEndian.Uint32(f.Payload))
			select {
			case s.writeCh <- resp:
			case <-s.doneCh:
			}
		case FrameGoAway:
			s.Close()
		}
		return
	}

	switch f.Type {
	case FrameData:
		s.handleData(f)
	case FrameSyn:
		s.handleSyn(f)
	case FrameFin:
		s.handleFin(f)
	case FrameRst:
		s.handleRst(f)
	case FramePing:
		// PING on a non-0 stream? Treat as data-less control — ignore.
	case FrameGoAway:
		// GO_AWAY on a non-0 stream — shouldn't happen, ignore.
	default:
		// Unknown frame type — ignore.
	}
}

// handleData delivers a DATA frame's payload to the corresponding stream.
func (s *Session) handleData(f *frame) {
	s.streamsMu.RLock()
	st, ok := s.streams[f.StreamID]
	s.streamsMu.RUnlock()
	if ok {
		st.onData(f.Payload)
	}
}

// handleSyn processes an incoming SYN frame (remote-initiated stream).
func (s *Session) handleSyn(f *frame) {
	// SYN+ACK: this is the response to our own SYN. If the stream already
	// exists (we opened it), it's an ACK — nothing to do.
	if f.Flags&FlagAck != 0 {
		// ACK for a stream we opened — nothing to do.
		return
	}

	// New incoming stream. Check if we already have it (retransmit).
	s.streamsMu.RLock()
	_, exists := s.streams[f.StreamID]
	s.streamsMu.RUnlock()
	if exists {
		return // duplicate SYN
	}

	// Check accept backlog.
	if len(s.acceptCh) >= s.cfg.AcceptBacklog {
		// Reject with RST.
		rst := newRstFrame(f.StreamID, RSTRefused)
		select {
		case s.writeCh <- rst:
		case <-s.doneCh:
		}
		return
	}

	// Acquire a MaxStreams slot BEFORE creating the stream.
	// This prevents zombie streams if MaxStreams is full — the slot
	// acquisition blocks (or returns on doneCh) before the stream is
	// registered in the map.
	if s.cfg.MaxStreams > 0 {
		select {
		case s.streamSlotCh <- struct{}{}:
		case <-s.doneCh:
			return
		}
	}

	// Create the stream.
	st := newStream(f.StreamID, s)
	s.streamsMu.Lock()
	s.streams[f.StreamID] = st
	s.streamsMu.Unlock()

	// Send SYN+ACK back.
	ack := newSynFrame(f.StreamID, true)
	select {
	case s.writeCh <- ack:
	case <-s.doneCh:
		return
	}

	// Deliver to acceptCh.
	select {
	case s.acceptCh <- st:
	case <-s.doneCh:
		return
	}
}

// handleFin processes an incoming FIN frame (remote closed write side).
func (s *Session) handleFin(f *frame) {
	s.streamsMu.RLock()
	st, ok := s.streams[f.StreamID]
	s.streamsMu.RUnlock()
	if ok {
		st.onFin()
		// If the local side is also closed, remove the stream.
		if st.localClosed.Load() {
			s.removeStream(f.StreamID)
		}
	}
}

// handleRst processes an incoming RST frame (stream reset by remote).
func (s *Session) handleRst(f *frame) {
	s.streamsMu.RLock()
	st, ok := s.streams[f.StreamID]
	s.streamsMu.RUnlock()
	if ok {
		st.onRst()
		s.removeStream(f.StreamID)
		// Release the MaxStreams slot.
		if s.cfg.MaxStreams > 0 {
			select {
			case <-s.streamSlotCh:
			default:
			}
		}
	}
}

// abort is called when the underlying conn has an unrecoverable error.
// It tears down the session and all streams.
func (s *Session) abort(err error) {
	s.closeOnce.Do(func() {
		s.streamsMu.Lock()
		s.closed = true
		s.streamsMu.Unlock()

		close(s.doneCh)

		// Signal EOF/error to all stream readers.
		s.streamsMu.Lock()
		for _, st := range s.streams {
			st.onFin()
		}
		s.streams = make(map[uint32]*Stream)
		s.streamsMu.Unlock()

		// Close the underlying conn.
		s.conn.Close()
	})
}

// ── Session handshake ─────────────────────────────────────────────────

// handshake performs the initial SYN/ACK exchange on stream 0.
// Client sends SYN(stream 0), server responds with SYN+ACK(stream 0).
func (s *Session) handshake() error {
	timeout := time.NewTimer(s.cfg.HandshakeTimeout)
	defer timeout.Stop()

	if s.clientMode {
		// Client: send SYN on stream 0.
		syn := &frame{
			Version:  ProtocolVersion,
			Type:     FrameSyn,
			Flags:    FlagSyn,
			StreamID: 0,
			Length:   0,
		}
		select {
		case s.writeCh <- syn:
		case <-timeout.C:
			return errors.New("smux: handshake timeout (send)")
		case <-s.doneCh:
			return ErrSessionClosed
		}
	}

	// Both sides wait for the session handshake to complete.
	// The reader goroutine will see a SYN on stream 0 and signal handshakeDone.
	select {
	case <-s.handshakeDone:
		return nil
	case <-timeout.C:
		return errors.New("smux: handshake timeout (wait)")
	case <-s.doneCh:
		return ErrSessionClosed
	}
}

// handleHandshakeSyn processes a SYN frame on stream 0 (session handshake).
func (s *Session) handleHandshakeSyn(f *frame) {
	if f.StreamID != 0 {
		return
	}

	if !s.clientMode {
		// Server: respond with SYN+ACK on stream 0.
		ack := &frame{
			Version:  ProtocolVersion,
			Type:     FrameSyn,
			Flags:    FlagSyn | FlagAck,
			StreamID: 0,
			Length:   0,
		}
		select {
		case s.writeCh <- ack:
		case <-s.doneCh:
		}
	}

	// Signal handshake complete.
	select {
	case <-s.handshakeDone:
		// Already done.
	default:
		close(s.handshakeDone)
	}
}
