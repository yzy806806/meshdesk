// Package smux provides stream multiplexing over an io.ReadWriteCloser
// for MeshDesk v2 Layer 3.
//
// smux takes a single underlying byte stream (the encrypted SecureConn
// from Layer 2b) and multiplexes many bidirectional net.Conn streams
// over it. Each stream is a full net.Conn: reads and writes are
// independent, ordered, and reliable.
//
// Two roles exist:
//   - Client: calls OpenStream() to create new streams (outbound).
//     Stream IDs are odd: 1, 3, 5, ...
//   - Server: calls AcceptStream() to receive streams created by
//     the remote client (inbound). Stream IDs are even: 2, 4, 6, ...
//
// Every MeshDesk v2 node is both client and server simultaneously.
// The same binary opens streams to peers AND accepts streams from peers.
//
// This package has ZERO external dependencies — only Go stdlib.
// It operates over io.ReadWriteCloser, not net.Conn, for maximum
// testability and transport-agnostic composition.
package smux

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"time"
)

// Config configures an smux session.
type Config struct {
	// MaxStreams is the maximum number of concurrent streams.
	// When reached, OpenStream blocks until a stream is closed.
	// 0 = unlimited. Default: 256.
	MaxStreams int

	// MaxFrameSize is the maximum DATA frame payload in bytes.
	// Larger Writes are split into multiple frames.
	// Must be at least 64 and at most 65535.
	// Default: 16384 (16 KB).
	MaxFrameSize int

	// WriteBufferSize is the per-stream send buffer in bytes.
	// When full, Write blocks. Prevents unbounded memory use.
	// Default: 262144 (256 KB).
	WriteBufferSize int

	// AcceptBacklog is the maximum number of unaccepted streams
	// buffered before AcceptStream must be called. When full,
	// incoming SYN frames are rejected with RST.
	// Default: 64.
	AcceptBacklog int

	// HandshakeTimeout is the max time for the initial SYN/ACK
	// handshake on stream 0 (the session setup).
	// Default: 10s.
	HandshakeTimeout time.Duration

	// StreamIdleTimeout closes streams that have seen no read or write
	// activity for this duration. 0 = disabled.
	// Default: 0 (disabled — smux doesn't close idle streams; upper
	// layers (proxy, WebSSH) manage their own timeouts).
	StreamIdleTimeout time.Duration

	// PingInterval is the keepalive ping frequency on the control
	// channel (stream 0). 0 = no keepalive pings.
	// Default: 0 (disabled — MultiPathSession manages heartbeat
	// at Layer 4 via a dedicated stream).
	PingInterval time.Duration

	// PingTimeout is how long without ANY incoming frame (data or
	// pong) before the session is considered dead and aborted.
	// Only used when PingInterval > 0. Default: 3 × PingInterval.
	PingTimeout time.Duration
}

// DefaultConfig returns a Config with production-tested defaults.
func DefaultConfig() Config {
	return Config{
		MaxStreams:        256,
		MaxFrameSize:      16384,
		WriteBufferSize:   262144,
		AcceptBacklog:     64,
		HandshakeTimeout:  30 * time.Second,
		StreamIdleTimeout: 0,
		PingInterval:      0,
	}
}

// validateConfig validates and fills in defaults for zero-valued fields.
func validateConfig(cfg Config) Config {
	if cfg.MaxFrameSize < 64 {
		cfg.MaxFrameSize = 16384
	}
	if cfg.MaxFrameSize > 65535 {
		cfg.MaxFrameSize = 65535
	}
	if cfg.AcceptBacklog < 1 {
		cfg.AcceptBacklog = 64
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	return cfg
}

// Client creates a new smux session in client mode over the given connection.
//
// Client mode: Stream IDs are odd (1, 3, 5, ...). The caller uses
// OpenStream() to create new streams; remote-initiated streams (even IDs)
// are delivered via AcceptStream().
//
// The underlying conn is owned by smux after this call. Closing the
// returned Session closes the underlying conn. The caller must not
// read from or write to conn after passing it to Client.
func Client(conn io.ReadWriteCloser, cfg Config) (*Session, error) {
	cfg = validateConfig(cfg)

	s := &Session{
		conn:          conn,
		bufReader:     bufio.NewReaderSize(conn, 32*1024),
		cfg:           cfg,
		clientMode:    true,
		streams:       make(map[uint32]*Stream),
		nextStreamID:  1, // odd, starting at 1
		writeCh:       make(chan *frame, 256),
		acceptCh:      make(chan *Stream, cfg.AcceptBacklog),
		doneCh:        make(chan struct{}),
		handshakeDone: make(chan struct{}),
	}

	if cfg.MaxStreams > 0 {
		s.streamSlotCh = make(chan struct{}, cfg.MaxStreams)
	}

	// Start background goroutines.
	go s.reader()
	go s.writer()
	if s.cfg.PingInterval > 0 {
		go s.keepaliveLoop()
	}

	// Perform session handshake.
	if err := s.handshake(); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

// keepaliveLoop sends periodic PING frames on the control channel and
// aborts the session if no frame (data or pong) arrives within
// PingTimeout. This detects TCP half-closes (FIN-WAIT-2/CLOSE-WAIT)
// that would otherwise leave reads blocked forever with IsClosed()
// false — the root cause of zombie sessions.
func (s *Session) keepaliveLoop() {
	interval := s.cfg.PingInterval
	timeout := s.cfg.PingTimeout
	if timeout <= 0 {
		timeout = 3 * interval
	}
	s.lastActivity.Store(time.Now().UnixNano())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.doneCh:
			return
		case <-ticker.C:
			// Send a ping on the control channel. If the writer is
			// stuck (TCP buffer full / half-open peer that keeps
			// ACKing but never reads), writeCh fills up and the send
			// would block forever — which would also freeze the
			// liveness check below. Bound the send: a blocked write
			// means the session is effectively dead.
			select {
			case s.writeCh <- newPingFrame(0):
			case <-s.doneCh:
				return
			case <-time.After(timeout):
				log.Printf("[smux] keepalive write blocked for %s — aborting stuck session", timeout)
				s.abort(errors.New("smux: keepalive write blocked"))
				return
			}
			// Check liveness.
			if time.Since(time.Unix(0, s.lastActivity.Load())) > timeout {
				log.Printf("[smux] keepalive timeout — session dead (no frames for %s), aborting", timeout)
				s.abort(errors.New("smux: keepalive timeout"))
				return
			}
		}
	}
}

// Server creates a new smux session in server mode over the given connection.
//
// Server mode: Stream IDs are even (2, 4, 6, ...). The caller cannot call
// OpenStream() in server mode; all streams are accepted via AcceptStream().
// Remote-initiated streams (odd IDs) are received and delivered through
// AcceptStream().
//
// The underlying conn is owned by smux after this call. Same ownership
// semantics as Client.
func Server(conn io.ReadWriteCloser, cfg Config) (*Session, error) {
	cfg = validateConfig(cfg)

	s := &Session{
		conn:          conn,
		bufReader:     bufio.NewReaderSize(conn, 32*1024),
		cfg:           cfg,
		clientMode:    false,
		streams:       make(map[uint32]*Stream),
		nextStreamID:  2, // even, starting at 2
		writeCh:       make(chan *frame, 256),
		acceptCh:      make(chan *Stream, cfg.AcceptBacklog),
		doneCh:        make(chan struct{}),
		handshakeDone: make(chan struct{}),
	}

	if cfg.MaxStreams > 0 {
		s.streamSlotCh = make(chan struct{}, cfg.MaxStreams)
	}

	// Start background goroutines.
	go s.reader()
	go s.writer()

	// Perform session handshake (wait for client's SYN).
	if err := s.handshake(); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

// multipathSession mirrors the interface expected by internal/multipath.
// (In the actual code, multipath imports smux and uses this check.)
type multipathSession interface {
	OpenStream(ctx context.Context) (net.Conn, error)
	AcceptStream(ctx context.Context) (net.Conn, error)
	NumStreams() int
	Close() error
	IsClosed() bool
}

// Ensure smux.Session satisfies the multipath.Session interface.
var _ multipathSession = (*Session)(nil)

// Ensure Stream satisfies net.Conn.
var _ net.Conn = (*Stream)(nil)

// errClosed is a convenience for internal use.
