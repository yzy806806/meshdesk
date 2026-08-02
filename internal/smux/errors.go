package smux

import "errors"

// Sentinel errors returned by smux operations.
var (
	// ErrSessionClosed is returned by OpenStream, AcceptStream, and Write
	// when the session has been closed.
	ErrSessionClosed = errors.New("smux: session closed")

	// ErrStreamsExhausted is returned by OpenStream when all stream IDs
	// in the client range (odd IDs) have been used.
	ErrStreamsExhausted = errors.New("smux: no more stream IDs available")

	// ErrStreamReset is returned by Read when the remote peer sent RST.
	ErrStreamReset = errors.New("smux: stream reset by peer")

	// ErrStreamClosed is returned by Write when the local side has closed
	// the stream (Close() was called).
	ErrStreamClosed = errors.New("smux: stream closed")

	// ErrMaxStreams is returned by OpenStream when MaxStreams is reached
	// and the context is cancelled before a slot opens.
	ErrMaxStreams = errors.New("smux: max streams reached")
)

// GO_AWAY error codes (4 bytes, big-endian in payload).
const (
	GoAwayNormal           uint32 = 0
	GoAwayProtocolError    uint32 = 1
	GoAwayInternalError    uint32 = 2
	GoAwayStreamsExhausted uint32 = 3
)

// RST error codes (4 bytes, big-endian in payload).
const (
	RSTStreamClosed uint32 = 0
	RSTRefused      uint32 = 1
	RSTCanceled     uint32 = 2
	RSTWriteError   uint32 = 3
)
