# MeshDesk v2 — Layer 3 (smux) Stream Multiplexer Specification

**Status:** FROZEN (Stream multiplexing layer of v2 protocol stack)
**Date:** 2026-07-28
**Author:** architect
**Motion:** motion-856c071ce5a9 (Agora discussion: MeshDesk v2 full rewrite)
**Task:** t_7824afc5 (Action item 5/10 from the motion)
**Depends on:** Layer 2b (SecureConn / AES-256-GCM, FROZEN)
**Freeze order:** Layer 0 → Layer 1 → Layer 2b → Layer 2a → Layer 3 (this spec) → Layer 4 (MultiPathSession)
**Downstream:** Layer 4 (MultiPathSession) depends on smux.Session interface

---

## Overview

smux is the **stream multiplexer** for MeshDesk v2. It takes a single
underlying byte stream (`io.ReadWriteCloser` — in practice the encrypted
`SecureConn` from Layer 2b) and multiplexes many logical bidirectional
streams over it. Each stream is a full `net.Conn`: reads and writes are
independent, ordered, and reliable.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Protocol Stack                                  │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 4         MultiPathSession                                    │
│                 aggregates N smux.Session into one pool             │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 3         smux (stream multiplexing)        ←─── THIS SPEC    │
│                 one underlying conn → many net.Conn streams         │
│                 operates over io.ReadWriteCloser                    │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 2b        SecureConn (AES-256-GCM)                            │
│                 wraps net.Conn into encrypted net.Conn              │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 2a        Session key exchange (X25519 ECDH + Ed25519)        │
│                 not needed for smux operation                       │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 1         Handshake (Reality TLS over TCP)                    │
│                 provides raw encrypted net.Conn                     │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 0         Identity (Ed25519)                                  │
│                 not used by smux                                    │
└─────────────────────────────────────────────────────────────────────┘
```

**Why smux operates over `io.ReadWriteCloser` instead of `net.Conn`:**

The smux layer doesn't need `LocalAddr()`, `RemoteAddr()`, or `SetDeadline()`
from the underlying connection — it only needs to read bytes and write bytes.
Operating over `io.ReadWriteCloser` means:

- smux unit tests don't need real network connections — `bytes.Buffer` or
  `net.Pipe()` work as underlying transports.
- smux is transport-agnostic: the same code works over TCP, Unix sockets,
  in-memory pipes, or a QUIC stream.
- The encryption layer below (SecureConn) satisfies `net.Conn` which itself
  satisfies `io.ReadWriteCloser` — zero impedance mismatch.
- The contract is narrower, therefore simpler to verify and harder to misuse.

**Why smux instead of yamux or a third-party library:**

The MeshDesk v2 policy is **zero external dependencies below Layer 4**.
Commitment to this policy means:

- No `github.com/hashicorp/yamux` import — we own the wire format end-to-end.
- No `quic-go` stream management — smux is the single multiplexer for all v2 transports.
- The wire format is deliberately simple: a fixed 12-byte header with five
  frame types. This is intentionally simpler than yamux (which has 15 frame
  types, window management, and keepalive semantics we don't need), and
  simpler than HTTP/2 frames (which carry HPACK state we actively avoid).

**Two roles, same binary:**

Every MeshDesk v2 node runs both smux.Client and smux.Server simultaneously.
The client role initiates streams; the server role accepts streams. Both
roles share the same underlying encrypted connection. This is symmetric —
either peer can open a stream to the other at any time.

```go
// Entry node connecting to exit node:
conn, _ := handshake.Connect(ctx, "exit.example.com:443")   // Layer 1
sec,  _ := crypto.NewSecureConn(conn, sendKey, recvKey)     // Layer 2b
sess, _ := smux.Client(sec, smux.DefaultConfig())            // Layer 3 client
stream, _ := sess.OpenStream()                                // → net.Conn for WebSSH/proxy

// Exit node accepting from entry:
ln, _   := handshake.Listen(ctx, "0.0.0.0:443")             // Layer 1
conn, _ := ln.Accept()
sec, _  := crypto.NewSecureConn(conn, sendKey, recvKey)     // Layer 2b
sess, _ := smux.Server(sec, smux.DefaultConfig())            // Layer 3 server
stream, _ := sess.AcceptStream()                              // → net.Conn for incoming WebSSH/proxy
```

---

## 1. Core Interface

### 1.1 Constructor Functions

```go
// Package smux provides stream multiplexing over an io.ReadWriteCloser.
//
// smux takes a single underlying byte stream (the encrypted SecureConn
// from Layer 2b) and multiplexes many bidirectional net.Conn streams
// over it. Each stream is independent, ordered, reliable, and flow-controlled.
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
    "context"
    "errors"
    "io"
    "net"
    "sync"
    "time"
)

// Client creates a new smux session in client mode over the given connection.
//
// Client mode: Stream IDs are odd (1, 3, 5, ...). The caller uses
// OpenStream() to create new streams; remote-initiated streams (even IDs)
// are delivered via AcceptStream().
//
// The underlying conn is owned by smux after this call. Closing the
// returned Session closes the underlying conn. The caller must not
// read from or write to conn after passing it to Client.
//
// Context cancellation interrupts only the initial handshake (client sends
// a SYN on stream 0 for session setup). After the handshake, the ctx
// is not used — smux manages its own lifecycle.
func Client(conn io.ReadWriteCloser, cfg Config) (*Session, error)

// Server creates a new smux session in server mode over the given connection.
//
// Server mode: Stream IDs are even (2, 4, 6, ...). The caller cannot call
// OpenStream() in server mode; all streams are accepted via AcceptStream().
// Remote-initiated streams (odd IDs) are received and delivered through
// AcceptStream().
//
// The underlying conn is owned by smux after this call. Same ownership
// semantics as Client.
//
// Context cancellation interrupts only the initial handshake wait (server
// waits for the client's SYN on stream 0). After the handshake, ctx is
// not used.
func Server(conn io.ReadWriteCloser, cfg Config) (*Session, error)
```

### 1.2 Session — Satisfies `multipath.Session`

```go
// Session is a multiplexed session over a single underlying connection.
// It satisfies multipath.Session (defined in internal/multipath/session.go).
//
// A Session is created by Client() or Server(). Once created, it reads
// from and writes to the underlying conn in background goroutines.
//
// Thread safety: All Session methods are safe for concurrent use.
// OpenStream and AcceptStream use independent channels — they do not
// contend on the same mutex.
type Session struct {
    // (unexported fields: conn, streams map, acceptCh, controlCh, ...)
}

// OpenStream creates a new stream and returns it as a net.Conn.
//
// Only valid in client mode. In server mode, returns ErrWrongRole.
// The returned net.Conn is a full-duplex, ordered, reliable byte stream.
// It supports Read, Write, Close, SetDeadline, SetReadDeadline,
// SetWriteDeadline, LocalAddr, and RemoteAddr.
//
// Blocks if the number of active streams has reached MaxStreams.
// Returns an error if the session is closed or the context is cancelled.
func (s *Session) OpenStream(ctx context.Context) (net.Conn, error)

// AcceptStream blocks until a remote-initiated stream arrives, then
// returns it as a net.Conn.
//
// Returns an error if the session is closed. Context cancellation
// interrupts the wait.
func (s *Session) AcceptStream(ctx context.Context) (net.Conn, error)

// NumStreams returns the number of currently open streams.
// Includes both locally-opened and remotely-opened streams.
func (s *Session) NumStreams() int

// Close shuts down the session gracefully.
//
// Sends a GO_AWAY frame to the remote peer, closes all open streams
// (each stream receives io.EOF on its next Read), stops background
// goroutines, and closes the underlying conn. Idempotent.
func (s *Session) Close() error

// IsClosed reports whether Close() has been called.
// True after the first call to Close() — does not wait for remote
// acknowledgment.
func (s *Session) IsClosed() bool
```

### 1.3 Compile-Time Interface Check

```go
// Ensure smux.Session satisfies the multipath.Session interface.
var _ multipathSession = (*Session)(nil)

// multipathSession mirrors the interface expected by internal/multipath.
// (In the actual code, multipath imports smux and uses this check.)
type multipathSession interface {
    OpenStream(ctx context.Context) (net.Conn, error)
    AcceptStream(ctx context.Context) (net.Conn, error)
    NumStreams() int
    Close() error
    IsClosed() bool
}
```

### 1.4 Stream — Satisfies `net.Conn`

```go
// Stream is one logical bidirectional stream within a Session.
//
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
    // (unexported fields: id, session, readBuf, writeCh, ...)
}

// Read reads data from the stream. Blocks until data arrives or
// the stream is closed. Returns io.EOF when the remote peer closes
// their write side (FIN received).
func (st *Stream) Read(b []byte) (int, error)

// Write sends data on the stream. Each Write produces one DATA frame.
// Writes larger than MaxFrameSize are split into multiple DATA frames.
// Returns an error if the write buffer is full or the session is closed.
func (st *Stream) Write(b []byte) (int, error)

// Close closes the write side of the stream. Sends a FIN frame to the
// remote peer. The read side remains open until the remote peer sends
// their FIN or the session closes. Idempotent.
func (st *Stream) Close() error

// LocalAddr returns a synthetic address identifying the local stream.
// Format: "smux:local:<streamID>"
func (st *Stream) LocalAddr() net.Addr

// RemoteAddr returns a synthetic address identifying the remote stream.
// Format: "smux:remote:<streamID>"
func (st *Stream) RemoteAddr() net.Addr

// SetDeadline sets both read and write deadlines.
func (st *Stream) SetDeadline(t time.Time) error

// SetReadDeadline sets the read deadline.
func (st *Stream) SetReadDeadline(t time.Time) error

// SetWriteDeadline sets the write deadline.
func (st *Stream) SetWriteDeadline(t time.Time) error
```

---

## 2. Configuration

```go
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
}

// DefaultConfig returns a Config with production-tested defaults.
func DefaultConfig() Config {
    return Config{
        MaxStreams:        256,
        MaxFrameSize:      16384,
        WriteBufferSize:   262144,
        AcceptBacklog:     64,
        HandshakeTimeout:  10 * time.Second,
        StreamIdleTimeout: 0,
        PingInterval:      0,
    }
}
```

**Design rationale for defaults:**

- **MaxStreams=256:** A single smux session should comfortably handle
  concurrent proxy connections (browser tabs), WebSSH sessions, file
  transfers, and control channels. 256 is generous but bounded — above
  this, open a second smux session (which MultiPathSession already does
  for multipath).
- **MaxFrameSize=16384:** Large enough for efficient bulk transfer
  (WebSSH terminal output, proxy response bodies), small enough to
  interleave smoothly when many streams are active. Same order of
  magnitude as typical TCP MSS.
- **WriteBufferSize=262144:** One MaxFrameSize worth of buffering × 16
  concurrent-yielding streams. Prevents head-of-line blocking when
  one stream is slow to read.
- **AcceptBacklog=64:** Matches `net.Listen`'s default backlog.
  Sufficient for bursty stream creation during proxy startup; above
  this, the remote peer is RST'd and must retry.
- **HandshakeTimeout=10s:** Matches Layer 1's DialTimeout for the
  underlying connection. The smux handshake (SYN on stream 0) should
  never be the bottleneck; if it times out, the connection is dead.
- **No ping, no idle timeout by default:** These are Layer 4
  responsibilities (MultiPathSession heartbeat, proxy-level
  timeouts). smux is a pure multiplexer — it doesn't manage
  session health.

---

## 3. Wire Format

### 3.1 Frame Header (12 bytes, fixed)

```
┌──────────────────────────────────────────────────────────────────┐
│ Byte Offset │ 0     │ 1     │ 2-3   │ 4-7        │ 8-11         │
│ Field       │ Vers  │ Type  │ Flags │ StreamID   │ Length        │
│ Size        │ 1     │ 1     │ 2     │ 4          │ 4            │
│ Endian      │  —    │  —    │ BE    │ BE         │ BE           │
└──────────────────────────────────────────────────────────────────┘
```

All multi-byte integers are **big-endian** (network byte order).

| Field      | Size  | Description                                                  |
|------------|-------|--------------------------------------------------------------|
| Version    | 1     | Protocol version. MUST be 1. Other values → GO_AWAY.         |
| Type       | 1     | Frame type (see §3.2).                                       |
| Flags      | 2     | Type-specific flags. SYN=0x0001, FIN=0x0002, RST=0x0004.    |
| StreamID   | 4     | Stream identifier. 0 = control channel. Max: 2³¹-1.          |
| Length     | 4     | Payload length in bytes. DATA frames only; zero for control. |

**Version field:** Currently 1. If a future version introduces a new frame
type or changes the header layout, the version number is incremented.
Receiving an unsupported version triggers a GO_AWAY frame with the
highest supported version in the payload, then closes the session.

### 3.2 Frame Types

| Type   | Value | Direction   | Payload        | Description                              |
|--------|-------|-------------|----------------|------------------------------------------|
| DATA   | 0x00  | Both        | Stream data    | Application data for a stream.           |
| SYN    | 0x01  | Initiator   | None           | Open a new stream. Has FLAG_SYN set.     |
| FIN    | 0x02  | Both        | None           | Gracefully close a stream's write side.  |
| RST    | 0x03  | Both        | Error code (4B)| Immediately reset a stream.             |
| PING   | 0x04  | Both        | Opaque (4B)   | Session-level keepalive.                 |
| GO_AWAY| 0x05  | Both        | Error code (4B)| Graceful session shutdown.              |

### 3.3 Stream ID Allocation

```
Stream ID 0: Control channel (session setup, PING, GO_AWAY)
Stream ID 1, 3, 5, ...: Client-initiated streams (odd, starting at 1)
Stream ID 2, 4, 6, ...: Server-initiated streams (even, starting at 2)
```

The initiator of a stream is the peer that sends the SYN. The receiver
acknowledges by sending a SYN back (on the same stream ID) with zero
payload — this is the handshake.

Client and server roles are determined at session creation time
(`Client()` vs `Server()`). If both peers call `Client()` on the same
underlying conn, they will collide on stream ID 1 — the first SYN on
stream 1 wins, and the loser must create stream 3 next.

**Stream ID exhaustion:** Stream IDs are monotonically increasing within
each role. When a client's next stream ID exceeds 2³¹-1, no more client-
initiated streams can be opened. Callers receive ErrStreamsExhausted.
In practice, with 256 max streams per session and stream ID recycling
(closed stream IDs are reusable), this limit is unreachable.

### 3.4 Flags (16 bits)

| Flag       | Value  | Set on                          |
|------------|--------|---------------------------------|
| FLAG_SYN   | 0x0001 | SYN frames (opening a stream)   |
| FLAG_FIN   | 0x0002 | FIN frames (closing gracefully) |
| FLAG_RST   | 0x0004 | RST frames (abrupt reset)       |
| FLAG_ACK   | 0x0008 | SYN+ACK (handshake response)    |

### 3.5 Stream Lifecycle

```
                    CLIENT                            SERVER
                      │                                 │
                      │  SYN(FLAG_SYN, StreamID=1)      │
                      │ ──────────────────────────────► │
                      │                                 │
                      │  SYN(FLAG_ACK, StreamID=1)      │
                      │ ◄────────────────────────────── │
                      │                                 │
                      │  DATA(StreamID=1, payload)      │
                      │ ──────────────────────────────► │
                      │                                 │
                      │  DATA(StreamID=1, payload)      │
                      │ ◄────────────────────────────── │
                      │                                 │
                      │  FIN(FLAG_FIN, StreamID=1)      │
                      │ ──────────────────────────────► │   (client done writing)
                      │                                 │
                      │  DATA(StreamID=1, payload)      │
                      │ ◄────────────────────────────── │   (server still writing)
                      │                                 │
                      │  FIN(FLAG_FIN, StreamID=1)      │
                      │ ◄────────────────────────────── │   (server done writing)
                      │                                 │
                      Stream 1 is closed on both sides.   │
```

**Error path:**

```
If either peer encounters an unrecoverable error on a stream
(e.g., write buffer overflow, protocol violation):
→ send RST(StreamID, error_code) → stream immediately deleted
→ Read on remote side returns ErrStreamReset
→ Write on remote side returns ErrStreamReset
```

### 3.6 Session Lifecycle

```
CLIENT                                                    SERVER
  │                                                         │
  │  SYN(FLAG_SYN, StreamID=0) ← Session setup handshake    │
  │ ──────────────────────────────────────────────────────► │
  │                                                         │
  │  SYN(FLAG_ACK, StreamID=0)                              │
  │ ◄────────────────────────────────────────────────────── │
  │                                                         │
  │  ... normal stream activity ...                         │
  │                                                         │
  │  GO_AWAY(StreamID=0, error_code=NORMAL)                 │
  │ ──────────────────────────────────────────────────────► │
  │                                                         │
  │  All streams drain, then underlying conn closes.         │
```

**GO_AWAY error codes (4 bytes, big-endian in payload):**

| Code | Name              | Meaning                               |
|------|-------------------|---------------------------------------|
| 0    | NORMAL            | Graceful shutdown (operator or Close). |
| 1    | PROTOCOL_ERROR    | Unexpected frame type or version.      |
| 2    | INTERNAL_ERROR    | Unrecoverable internal error.          |
| 3    | STREAMS_EXHAUSTED | No more stream IDs available.          |

### 3.7 RST Error Codes (4 bytes, big-endian in payload)

| Code | Name              | Meaning                               |
|------|-------------------|---------------------------------------|
| 0    | STREAM_CLOSED     | Normal stream reset.                   |
| 1    | REFUSED           | Peer rejected the stream (backlog full).|
| 2    | CANCELED          | Application cancelled the stream.      |
| 3    | WRITE_ERROR       | Underlying write failed.               |

### 3.8 Frame Ordering and Reliability

- **Ordered delivery:** DATA frames within a stream are delivered in order.
  smux uses a per-stream sequence counter (not in the wire header — derived
  from position in the byte stream) to detect gaps.
- **No cross-stream ordering:** DATA frames from stream 1 and stream 3 may
  be interleaved arbitrarily on the wire. Each stream's read side
  reassembles its own frames.
- **At-most-once:** RST and FIN are not retransmitted. If the underlying
  conn drops, all streams fail. Upper layers (Layer 4 MultiPathSession)
  handle that case by opening a new smux session on a different path.
- **No flow-control windows:** Unlike HTTP/2 or yamux, smux does not
  advertise per-stream receive windows. Instead, Write() blocks when the
  per-stream WriteBuffer is full, providing natural backpressure through
  the Go channel semaphore. This is simpler, correct for same-machine
  peers, and avoids the complexity of WINDOW_UPDATE frames.

---

## 4. Internal Architecture

### 4.1 Goroutine Model

```
┌──────────────────────────────────────────────┐
│                 smux.Session                  │
│                                               │
│  ┌─────────┐   ┌──────────┐   ┌───────────┐  │
│  │ writer  │   │  reader  │   │  pinger   │  │
│  │ goroutine│   │ goroutine│   │ goroutine │  │
│  │          │   │          │   │ (optional)│  │
│  │ writes   │   │ reads    │   │ periodic  │  │
│  │ frames   │   │ frames   │   │ PING on   │  │
│  │ to conn  │   │ from conn│   │ stream 0  │  │
│  └────┬─────┘   └────┬─────┘   └───────────┘  │
│       │              │                         │
│       │    ┌─────────▼──────────┐              │
│       │    │   frame dispatcher │              │
│       │    │   routes by        │              │
│       │    │   StreamID to      │              │
│       │    │   stream channels  │              │
│       │    └────────┬───────────┘              │
│       │             │                          │
│  ┌────▼─────────────▼──────────────────┐       │
│  │         streams map                 │       │
│  │  StreamID → stream{readCh,writeCh}  │       │
│  └─────────────────────────────────────┘       │
└──────────────────────────────────────────────┘
```

- **writer goroutine (1 per Session):** Reads from a shared write channel
  into which all streams push their outgoing frames. Serializes all writes
  to the underlying conn, holding the write lock. The channel provides
  natural backpressure — when full, stream.Write blocks.
- **reader goroutine (1 per Session):** Reads frames from the underlying
  conn. Dispatches to stream channels by StreamID. Dispatches control
  frames (PING, GO_AWAY) to the control channel.
- **pinger goroutine (0 or 1 per Session):** Only started when
  `PingInterval > 0`. Sends periodic PING frames on stream 0 with a
  monotonic sequence number. Not used in default config.
- **No per-stream goroutines.** Each stream is a pair of channels + a
  read buffer. This minimizes goroutine count: 2–3 goroutines per smux
  session regardless of the number of streams.

### 4.2 Stream Write Path

```
application
    │
    │ stream.Write(data)
    ▼
┌───────────────┐
│  split into   │
│  ≤MaxFrameSize │
│  chunks       │
└───────┬───────┘
        │
        ▼
┌───────────────────┐
│ push each DATA    │
│ frame onto        │
│ session.writeCh   │  ← backpressure: if full, Write blocks
└───────┬───────────┘
        │
        ▼
┌───────────────────┐
│ writer goroutine  │
│ serializes +      │
│ writes to conn    │
└───────────────────┘
```

### 4.3 Stream Read Path

```
underlying conn
    │
    │ read frame
    ▼
┌───────────────────┐
│ reader goroutine  │
│ parse header +    │
│ dispatch          │
└───────┬───────────┘
        │ (StreamID match)
        ▼
┌───────────────────┐
│ stream.readBuf    │  ← append payload
│ stream.readCh     │  ← signal data available
└───────┬───────────┘
        │
        ▼
application
    │
    │ stream.Read(buf)
```

### 4.4 Concurrency Model

```
Write side:          single writer goroutine (no contention)
Read side:           single reader goroutine (no contention)
AcceptStream:        select on acceptCh (no contention on map)
OpenStream:          atomic increment of nextStreamID + channel creation
Close:               sync.Once for idempotency, close all channels
streams map:         sync.RWMutex (read-heavy: dispatcher reads, OpenStream writes)
```

---

## 5. Error Sentinels

```go
var (
    // ErrWrongRole is returned by OpenStream when called on a server-mode Session.
    ErrWrongRole = errors.New("smux: OpenStream not available in server mode")

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

    // ErrBacklogFull is returned internally when the accept backlog is full.
    // The remote peer receives RST(REFUSED).
    ErrBacklogFull = errors.New("smux: accept backlog full")

    // ErrMaxStreams is returned by OpenStream when MaxStreams is reached
    // and the context is cancelled before a slot opens.
    ErrMaxStreams = errors.New("smux: max streams reached")
)
```

---

## 6. Package Layout

```
meshdesk/
├── internal/
│   ├── smux/                         ← NEW (Layer 3, this spec)
│   │   ├── smux.go                   ← Client, Server, Config, DefaultConfig
│   │   ├── session.go                ← Session: OpenStream, AcceptStream, Close, etc.
│   │   ├── stream.go                 ← Stream: net.Conn implementation
│   │   ├── frame.go                  ← Wire format: encode/decode frames
│   │   ├── errors.go                 ← Sentinel errors
│   │   └── smux_test.go              ← Unit + integration tests
│   ├── multipath/                    ← Layer 4 (depends on smux.Session)
│   │   ├── session.go                ← Session interface (smux.Session satisfies)
│   │   └── ...
│   ├── crypto/                       ← Layer 2b (FROZEN)
│   │   └── secure_conn.go
│   └── handshake/                    ← Layer 1 (FROZEN)
│       └── handshake.go
```

**Dependency arrows:**

```
multipath → smux.Session (type assertion, no import if interface is defined in multipath)
smux → io.ReadWriteCloser (stdlib only — zero external deps)
smux ← crypto.SecureConn (SecureConn satisfies io.ReadWriteCloser, smux doesn't import crypto)
```

The multipath package should define the `Session` interface (as currently
spec'd in MULTIPATH_SESSION_SPEC.md) and smux.Session satisfies it via
duck typing. Neither package imports the other.

---

## 7. Heartbeat Reconciliation with MultiPathSession (Layer 4)

The MultiPathSession spec (MULTIPATH_SESSION_SPEC.md §3.2) currently
describes heartbeat as operating on "stream ID 0, reserved." In this
frozen L3 spec, **stream ID 0 is the session control channel** — used
for the initial SYN/ACK handshake, GO_AWAY, and optional PING frames.
It is NOT a `net.Conn` and is not accessible to applications.

**Resolution:** MultiPathSession heartbeat uses a **regular application
stream** opened via `OpenStream()`. This is already described in the
MultiPathSession spec as the fallback:

> If smux does not provide heartbeat (Phase 1 may skip it),
> MultiPathSession falls back to a stream-level ping:
> `OpenStream()` → write 4-byte ping → read 4-byte pong → Close().

This fallback becomes the **primary mechanism** for Phase 1. The
rationale:

1. **smux remains a pure multiplexer** — no health awareness, no RTT
   measurement, no session-liveness tracking.
2. **Heartbeat is an application concern.** MultiPathSession opens a
   stream, sends structured ping/pong messages, computes RTT, and
   closes the stream. This is standard net.Conn usage.
3. **The control channel (stream 0) is for session setup and teardown
   only.** SYN/ACK, GO_AWAY, optional PING keepalive — these are
   protocol-level, not application-level.
4. **No special smux API** is needed for health data. The heartbeat
   is just another stream — tested with the same Read/Write semantics
   as proxy traffic.

**Action for multiPathSession spec:** §3.2 (Heartbeat) and §3.3
(Availability State Machine) should be updated to reflect that:
- Heartbeat uses a regular stream (not stream 0).
- The stream is opened, pinged, and closed per heartbeat cycle.
- Stream 0 is reserved for smux session control (this spec §3.5).

This does not change the MultiPathSession interface, path health
model, or acceptance criteria — only the implementation detail of
how the heartbeat bytes travel.

---

## 8. Integration Points

### 8.1 With Layer 2b (SecureConn)

```go
// smux accepts any io.ReadWriteCloser — SecureConn just works.
conn, _ := handshake.Connect(ctx, "exit:443")
sec, _ := crypto.NewSecureConn(conn, sendKey, recvKey)
sess, _ := smux.Client(sec, smux.DefaultConfig())
```

### 8.2 With Layer 4 (MultiPathSession)

```go
// MultiPathSession constructs smux sessions:
smuxSess, err := smux.Client(secureConn, smux.DefaultConfig())
if err != nil {
    return nil, err
}
// smuxSess satisfies multipath.Session:
path := multipath.Path{
    ID:      0,
    Target:  exitID,
    Session: smuxSess,    // ← duck-typed; no import of smux in multipath
}
```

### 8.3 With WebSSH

```go
// WebSSH handler gets a stream from MultiPathSession:
stream, pathID, err := mps.OpenStream(ctx)
// stream is a *smux.Stream, which is a net.Conn
// Use standard io.Copy for bidirectional proxy:
go io.Copy(stream, wsConn)
go io.Copy(wsConn, stream)
```

### 8.4 With Proxy (circuit/dispatcher)

```go
// Dispatcher gets a stream, tunnels proxy traffic:
stream, pathID, err := mps.OpenStream(ctx)
if err != nil {
    return err
}
defer stream.Close()

// Send proxy header (target address)
binary.Write(stream, binary.BigEndian, uint16(len(target)))
stream.Write([]byte(target))

// Tunnel bidirectional
go io.Copy(stream, clientConn)
io.Copy(clientConn, stream)
```

### 8.5 With File Transfer

```go
// File transfer opens one stream per file:
for _, file := range files {
    stream, _, _ := mps.OpenStream(ctx)
    go func(f File) {
        defer stream.Close()
        io.Copy(stream, f.Reader)
    }(file)
}
```

---

## 9. Acceptance Criteria

All acceptance criteria are written as testable assertions. The implementer
(developer) should be able to verify each one independently.

### AC-1: Client creates a session successfully

```go
// Use net.Pipe() as underlying conn — no network needed.
clientConn, serverConn := net.Pipe()
go func() {
    smux.Server(serverConn, smux.DefaultConfig())
}()

sess, err := smux.Client(clientConn, smux.DefaultConfig())
// err == nil, sess != nil
```

### AC-2: Client opens a stream and writes data; server accepts and reads

```go
clientConn, serverConn := net.Pipe()

var serverSess *smux.Session
go func() {
    serverSess, _ = smux.Server(serverConn, smux.DefaultConfig())
}()

clientSess, _ := smux.Client(clientConn, smux.DefaultConfig())

// Client opens a stream
stream, err := clientSess.OpenStream(context.Background())
// err == nil

// Client writes
n, err := stream.Write([]byte("hello"))
// n == 5, err == nil

// Server accepts
serverStream, err := serverSess.AcceptStream(context.Background())
// err == nil

// Server reads
buf := make([]byte, 1024)
n, err = serverStream.Read(buf)
// n == 5, string(buf[:n]) == "hello"
```

### AC-3: Bidirectional communication works

```go
// Client writes → Server reads
// Server writes → Client reads
// Both directions independent and concurrent
```

### AC-4: Stream Close sends FIN; remote Read returns io.EOF

```go
stream.Close()
// Remote peer's Read returns io.EOF after reading all buffered data
```

### AC-5: Session Close shuts down all streams

```go
sess.Close()
// IsClosed() == true
// All open streams' Read returns io.EOF
// All open streams' Write returns ErrSessionClosed
```

### AC-6: Close is idempotent

```go
err1 := sess.Close()
err2 := sess.Close()
// err1 == nil, err2 == nil (or both are the same)
// No panic
```

### AC-7: MaxStreams limits concurrent streams

```go
cfg := smux.DefaultConfig()
cfg.MaxStreams = 2

sess, _ := smux.Client(conn, cfg)

stream1, _ := sess.OpenStream(ctx) // OK
stream2, _ := sess.OpenStream(ctx) // OK

// Third OpenStream blocks
ctx2, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
defer cancel()
stream3, err := sess.OpenStream(ctx2)
// err == context.DeadlineExceeded, stream3 == nil

// Close stream1 → third OpenStream succeeds
stream1.Close()
stream3, err = sess.OpenStream(ctx)
// err == nil
```

### AC-8: Server-mode session rejects OpenStream

```go
sess, _ := smux.Server(conn, cfg)
stream, err := sess.OpenStream(ctx)
// err == ErrWrongRole, stream == nil
```

### AC-9: Session satisfies multipath.Session interface

```go
var _ multipathSession = (*smux.Session)(nil)
// compiles
```

### AC-10: Stream satisfies net.Conn interface

```go
var _ net.Conn = (*smux.Stream)(nil)
// compiles
```

### AC-11: No external dependencies

```bash
grep -r "github.com\|golang.org/x\|go.uber.org" internal/smux/
# → no results
```

### AC-12: Race detector clean under concurrent use

```bash
go test -race -count=1 ./internal/smux/
# → PASS, no race warnings
```

### AC-13: Large writes split into MaxFrameSize chunks

```go
cfg := smux.DefaultConfig()
cfg.MaxFrameSize = 1024

// Write 3000 bytes → 3 DATA frames
n, err := stream.Write(make([]byte, 3000))
// n == 3000, err == nil
```

### AC-14: Write on closed stream returns error

```go
stream.Close()
n, err := stream.Write([]byte("data"))
// err == ErrStreamClosed, n == 0
```

---

## 10. Trade-offs

### 10.1 Simple Windowless Flow Control vs WINDOW_UPDATE

| Aspect            | smux (windowless)           | yamux (windowed)              |
|-------------------|----------------------------|-------------------------------|
| Complexity        | None — channel backpressure | Per-stream receive window + WINDOW_UPDATE frames |
| Memory bounds     | Per-stream WriteBuffer cap  | Per-stream receive window cap |
| Head-of-line      | Blocked by slow reader on same stream only | Blocked by slow reader on any stream (shared window) |
| Cross-stream      | Independent per-stream buffers | Global connection-level flow control |
| Wire overhead     | No WINDOW_UPDATE frames     | WINDOW_UPDATE every window/2 consumed |

**Decision:** Windowless. MeshDesk v2 streams are used for proxy, WebSSH,
and file transfer — typical patterns where the producer and consumer are
on the same mesh (single-digit ms latency, no WAN buffer bloat). Channel-
based backpressure is simpler, faster, and correct for this environment.
If use cases emerge that require WAN-friendly flow control (e.g., a stream
from a US node to an Asia node), a future draft can add window semantics
as an optional Config flag.

### 10.2 io.ReadWriteCloser vs net.Conn

| Aspect            | io.ReadWriteCloser          | net.Conn                      |
|-------------------|-----------------------------|-------------------------------|
| Testability       | net.Pipe(), bytes.Buffer    | Requires real network or mock |
| Transport coupling | Zero — any byte stream     | TCP, Unix socket only         |
| SetDeadline       | Not available (no clocks)   | Available                     |
| Composition       | Trivial: any wrapper        | Must be net.Conn wrapper      |

**Decision:** `io.ReadWriteCloser`. The smux layer doesn't need deadlines
on the underlying conn — session-level timeouts are managed at Layer 4
(MultiPathSession heartbeat) and stream-level timeouts are on the stream
itself (which IS a `net.Conn`). The underlying conn's deadlines, if any,
are the responsibility of the layer that created it (SecureConn or
net.Pipe in tests).

### 10.3 Built-in Ping vs External Heartbeat

| Aspect            | Built-in Ping               | External Heartbeat            |
|-------------------|-----------------------------|-------------------------------|
| Who manages       | smux (PingInterval config)  | MultiPathSession (dedicated stream) |
| Overhead          | Extra frames on control ch  | One stream per smux session   |
| Coupling          | smux knows about liveness   | smux is a pure multiplexer    |
| Flexibility       | Fixed PingInterval          | MultiPathSession controls freq and timeout |

**Decision:** External heartbeat (MultiPathSession). By default,
`PingInterval=0` — smux doesn't ping. The heartbeat is managed at
Layer 4 via a dedicated stream (stream ID 0 is technically available
but we reserve a real stream for health data so MultiPathSession can
send structured health information). smux remains a pure multiplexer
with no awareness of session health or network conditions.

### 10.4 Stream ID 0: Control Channel

Stream ID 0 is the **session control channel**, used for:
- Initial session handshake (SYN/ACK)
- GO_AWAY frames
- PING frames (if PingInterval > 0)

Stream ID 0 is NOT a `net.Conn`. It's an internal channel that the
session manages. Applications never interact with stream 0 directly.

**Decision:** Reserve stream 0 for control. This is the industry standard
(yamux, HTTP/2) and avoids the problem of "what stream ID does the first
application stream get?".

---

## 11. Downstream Tasks

After this spec is approved and frozen:

1. **developer:** Implement `internal/smux/` per this spec.
   - `frame.go`: Wire format encoding/decoding (12-byte header, 5 frame types).
   - `stream.go`: Stream net.Conn implementation (Read, Write, Close, deadlines).
   - `session.go`: Session with writer/reader goroutines, stream map, dispatch.
   - `smux.go`: Client/Server constructors, Config, DefaultConfig.
   - `errors.go`: Sentinel errors.

2. **tester:** Verify all 14 acceptance criteria.
   - AC-1 through AC-14 must pass with `-race` enabled.
   - Edge cases: rapid OpenStream/Close, concurrent AcceptStreams,
     frame corruption, truncated headers, version mismatch.

3. **architect (next):** Freeze Layer 2a (Session key exchange: X25519 ECDH
   + Ed25519 identity binding). This produces the sendKey/recvKey that
   SecureConn (L2b) expects.

4. **architect (next):** Update MultiPathSession spec to reference this
   frozen smux interface (session.go: ensure the multipath.Session interface
   exactly matches smux.Session's public methods).