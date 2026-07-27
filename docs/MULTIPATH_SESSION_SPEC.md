# MeshDesk v2 — MultiPathSession Layer Specification

**Status:** DRAFT (Layer 3, Gap2)
**Date:** 2026-07-28
**Author:** architect
**Parent task:** t_bd744498
**Depends on:** HandshakeLayer (Layer 1, FROZEN), smux (Layer 2, not yet spec'd)

---

## 1. Background: Why MultiPathSession Exists

### 1.1 The Gap

`smux` is **per-session/per-connection**. One smux session multiplexes many
logical streams over exactly one underlying `net.Conn`. This is correct and
sufficient when there's exactly one physical path to the peer.

The MeshDesk v2 proxy design requires **two paths**: select the fastest 2 exit
nodes, split traffic across both. Opening 2 smux sessions (one per exit) is
trivial. But there's no coordinator that:

1. Knows about both sessions.
2. Decides which session gets the next `OpenStream()` call.
3. Monitors per-path health and removes dead paths from the pool.
4. Provides a single `OpenStream()` API that upper layers can call without
   knowing about path selection — the proxy layer just wants "a stream to
   send this request through."

That coordinator is **MultiPathSession**.

### 1.2 Position in the Protocol Stack

```
┌──────────────────────────────────────────────────┐
│  Proxy Layer (circuit/dispatcher/reassembler)     │
│  "OpenStream() to send this chunk/request"        │
├──────────────────────────────────────────────────┤
│  MultiPathSession (this spec) — Layer 3, Gap2     │
│  ┌──────────────┐  ┌──────────────┐               │
│  │   Path[0]    │  │   Path[1]    │  (≤2 active)│
│  │ smux.Session │  │ smux.Session │               │
│  ├──────────────┤  ├──────────────┤               │
│  │ SecureConn   │  │ SecureConn   │               │
│  ├──────────────┤  ├──────────────┤               │
│  │  net.Conn    │  │  net.Conn    │  (Handshake)  │
│  └──────┬───────┘  └──────┬───────┘               │
│         │                  │                       │
│    ─────┼───────TLS────────┼───────                │
│         │                  │                       │
│    ExitNode_0              ExitNode_1              │
└──────────────────────────────────────────────────┘
```

MultiPathSession **owns** N smux sessions. Each smux session rides on its own
SecureConn → HandshakeLayer → TCP/UDP connection to a different exit node. The
upper layer sees ONE `OpenStream()` call that returns a `smux.Stream` (satisfies
`net.Conn`).

### 1.3 What MultiPathSession Is NOT

- **NOT a chunk splitter.** In v2 Phase 1, flow-level multipath: each stream
  is pinned to one path. Chunk-level splitting (one stream distributed across
  N paths) is deferred to v2.1. This spec defines the extension point (§8).
- **NOT a connection manager.** PeerManager handles transport-level connection
  lifecycle (dial, retry, quarantining, Happy Eyeballs). MultiPathSession
  receives ESTABLISHED smux sessions and manages their pool.
- **NOT a relay coordinator.** It does not build circuits through intermediate
  nodes. It manages direct smux sessions to exit nodes. Relay-based paths
  (entry → relay → exit) are handled by a different component.

---

## 2. Core Interface

### 2.1 MultiPathSession

```go
// Package multipath provides multi-path session management for MeshDesk v2.
//
// MultiPathSession aggregates N smux sessions into one logical session.
// It selects which underlying session handles each OpenStream() call,
// monitors per-path health, and handles path failure/recovery.
//
// Thread safety: all methods are safe for concurrent use.
package multipath

import (
    "context"
    "net"
    "time"
)

// Session is the interface that underlying multiplexed sessions must satisfy.
// smux.Session satisfies this directly.
type Session interface {
    // OpenStream creates a new logical stream within this session.
    OpenStream() (net.Conn, error)

    // AcceptStream receives an incoming stream from the remote peer.
    AcceptStream() (net.Conn, error)

    // NumStreams returns the count of currently open streams.
    NumStreams() int

    // Close shuts down the session. All streams are closed.
    Close() error

    // IsClosed reports whether the session has been closed.
    IsClosed() bool
}

// Path represents one multipath channel: a smux session plus its health state.
type Path struct {
    // ID is a stable, immutable integer [0, N-1] assigned at construction.
    ID int

    // Target is the exit node identifier (e.g., peer public key).
    Target string

    // Session is the underlying smux session.
    Session Session

    // Health tracks latency, failure count, and availability.
    Health PathHealth

    // Stats is a rolling window of recent metrics.
    Stats PathStats
}

// MultiPathSession manages multiple Paths and provides a single
// OpenStream() entry point for upper layers.
type MultiPathSession struct {
    // (unexported fields: paths, selector, monitor, etc.)
}

// New creates a MultiPathSession from the given Paths.
// Returns an error if zero paths are provided.
func New(cfg Config, paths ...Path) (*MultiPathSession, error)

// OpenStream selects a path and opens a new stream on it.
// Returns a smux stream (net.Conn) along with the path ID for observability.
// Returns an error if all paths are down.
func (m *MultiPathSession) OpenStream(ctx context.Context) (net.Conn, int, error)

// OpenStreamOn opens a stream on a specific path. Returns an error if
// that path is not healthy.
func (m *MultiPathSession) OpenStreamOn(ctx context.Context, pathID int) (net.Conn, error)

// AcceptStream accepts an incoming stream from any path.
// It aggregates AcceptStream from all underlying sessions.
// Returns (stream, pathID, error).
func (m *MultiPathSession) AcceptStream(ctx context.Context) (net.Conn, int, error)

// Close shuts down all paths' smux sessions. Idempotent.
func (m *MultiPathSession) Close() error

// NumPaths returns the number of paths in the pool.
func (m *MultiPathSession) NumPaths() int

// ActivePaths returns only healthy, non-closed paths.
func (m *MultiPathSession) ActivePaths() []*Path

// PathStats returns per-path statistics for observability.
func (m *MultiPathSession) PathStats() []PathStat
```

### 2.2 Design Rationale for `OpenStream` returning `(net.Conn, int, error)`

Upper layers (proxy, file transfer, WebSSH) call `OpenStream()` and get back:

1. **`net.Conn`** — the smux stream. Satisfies `io.ReadWriteCloser`, has
   `SetDeadline`, `LocalAddr`, `RemoteAddr`. Upper layers use standard `net`
   APIs — zero coupling to the multipath layer.
2. **`int` (pathID)** — which path was selected. Used for:
   - Logging/metrics: "request X sent via path 1 to exit-Y"
   - Pin-aware upper layers: a chunk dispatcher may call `OpenStreamOn(0)`
     to send a retransmission on a specific path.
   - Observability: the proxy status page shows per-path stream counts.
3. **`error`** — if all paths are unhealthy, PoolExhausted is returned.

The pathID is returned, not hidden. A proxy that wants path-agnostic behavior
ignores it. A proxy that wants path-aware scheduling (retransmit on same path,
or deduplicate across paths) uses it.

---

## 3. Path Health Model

### 3.1 PathHealth

```go
// PathHealth tracks the health state of one path.
type PathHealth struct {
    // Latency is the EWMA-smoothed RTT to the exit node.
    // Updated by heartbeat pings. Zero until first measurement.
    Latency time.Duration

    // ConsecutiveFailures counts successive heartbeat timeouts.
    // Reset to 0 on any successful heartbeat.
    ConsecutiveFailures int

    // Available reports whether this path is in the selection pool.
    // A path becomes unavailable after maxFailures consecutive failures.
    Available bool

    // LastPing is the timestamp of the most recent heartbeat.
    LastPing time.Time
}
```

### 3.2 Heartbeat

Each path's smux session carries a dedicated heartbeat stream (stream ID 0,
reserved). This is an smux-level responsibility — MultiPathSession reads
health data from a channel provided by the smux layer.

```
Entry sends:  ping{timestamp}  every PingInterval (default: 5s)
Exit responds: pong{timestamp}  (echoes entry's timestamp)
Entry computes: RTT = now - echoed_timestamp
```

The heartbeat is per-smux-session, not per-path. The path's `Health.Latency` is
updated from the smux session's RTT measurement. If smux does not provide
heartbeat (Phase 1 may skip it), MultiPathSession falls back to a stream-level
ping: `OpenStream()` → write 4-byte ping → read 4-byte pong → Close().

**Heartbeat timeout:** If a ping is not acknowledged within `PingTimeout`
(default: 2× PingInterval = 10s), `ConsecutiveFailures` increments.

### 3.3 Availability State Machine

```
              ┌──────────┐
    ┌────────►│ available │◄──────────┐
    │         └─────┬─────┘           │
    │               │                 │
    │    [maxFailures heartbeats      │
    │     failed consecutively]       │
    │               │                 │
    │         ┌─────▼──────┐    [probing ping succeeds]
    │         │ unavailable │─────────┘
    │         └─────┬──────┘
    │               │
    │    [probing interval elapsed   OR
    │     all paths unavailable      OR
    │     explicit Reconnect()]
    │               │
    │         ┌─────▼──────┐
    │         │  probing    │
    │         └────────────┘
    │          (single heartbeat
    │           attempt, then:
    │           success → available
    │           failure → unavailable)
    └────────────────────────────────┘
```

**Maximum failures (`maxFailures`):** 3 consecutive heartbeat timeouts.
Configurable per-path.

**Probing interval:** When a path transitions to `unavailable`, MultiPathSession
schedules a probe at exponentially-increasing intervals (30s, 60s, 120s, capped
at 300s). A successful probe restores `available`. This prevents the pool from
permanently removing a path that experienced a transient network blip.

**All-paths-unavailable escape hatch:** When ALL paths are unavailable,
MultiPathSession enters a "blackout" state: `OpenStream()` immediately triggers
a probe on the least-recently-failed path. If it succeeds, the stream is opened
on that path. If it fails, the error is returned to the caller. This ensures
forward progress — the pool does not permanently stall.

### 3.4 PathStats

```go
// PathStat provides point-in-time statistics for one path.
type PathStat struct {
    PathID            int
    Target            string
    Latency           time.Duration
    ActiveStreams     int
    TotalStreamsOpened uint64
    TotalStreamsFailed uint64
    Healthy           bool
    LastError         string  // empty if healthy
    LastErrorTime     time.Time
}
```

---

## 4. Path Selection

### 4.1 PathSelector Interface

```go
// PathSelector picks a path from a pool of candidates.
// Implementations range from simple round-robin to latency-weighted.
type PathSelector interface {
    // Select returns the index of the chosen path, or -1 if none available.
    // It receives only currently-available paths.
    Select(paths []*Path) int
}
```

### 4.2 Built-in Selectors

#### RoundRobinSelector (default for Phase 1)

```go
type RoundRobinSelector struct {
    counter uint64 // atomic
}

func (s *RoundRobinSelector) Select(paths []*Path) int {
    if len(paths) == 0 {
        return -1
    }
    idx := atomic.AddUint64(&s.counter, 1) % uint64(len(paths))
    return int(idx)
}
```

Simple, predictable, zero-allocation. All available paths get equal share of
new streams. Appropriate for Phase 1 where paths have roughly equivalent
capacity.

#### LatencyWeightedSelector (Phase 2)

```go
type LatencyWeightedSelector struct {
    // alpha smooths the weight distribution.
    // 0.0 = strict: only the fastest path gets streams.
    // 1.0 = uniform: all paths get equal share.
    // Default: 0.5 (balanced).
    Alpha float64
}

func (s *LatencyWeightedSelector) Select(paths []*Path) int {
    // 1. Compute per-path latency score (lower = better)
    // 2. Weight = 1 / (latency + epsilon)
    // 3. Weighted random selection
}
```

Not required for Phase 1. Included in the spec so `PathSelector` is designed
as an interface from the start — swapping selectors later requires zero
changes to `MultiPathSession`.

### 4.3 Selection Rules (All Selectors)

1. **Only available paths are candidates.** Paths with `Health.Available == false`
   are excluded from `Select()`.
2. **Empty pool → error.** When zero paths are available, `Select()` returns -1,
   and `OpenStream()` returns `ErrPoolExhausted`.
3. **Single path → use it.** When exactly one path is available, selectors
   MUST return it — no randomness, no weighting.
4. **Backpressure-aware (Phase 2).** When a path has `ActiveStreams >= MaxStreams`,
   it is excluded from selection. `MaxStreams` is configurable per-path
   (default: 0 = no limit).

### 4.4 Stream Capacity

```go
// PathConfig tunes per-path behavior.
type PathConfig struct {
    // MaxStreams caps the number of concurrent streams on this path.
    // 0 = unlimited. When all paths are at capacity, OpenStream blocks
    // until a stream is freed or ctx is cancelled.
    MaxStreams int

    // MaxFailures is the consecutive heartbeat failures before a path
    // is marked unavailable. Default: 3.
    MaxFailures int
}
```

---

## 5. Config

```go
// Config configures a MultiPathSession.
type Config struct {
    // PingInterval is the heartbeat ping frequency. Default: 5s.
    PingInterval time.Duration

    // PingTimeout is the max wait for a pong response. Default: 10s.
    PingTimeout time.Duration

    // MaxPaths is the maximum number of active paths. Default: 2.
    // Only the first MaxPaths paths in the constructor are used;
    // additional paths are kept as warm spares.
    MaxPaths int

    // Selector is the path selection strategy. Default: RoundRobinSelector.
    Selector PathSelector

    // ProbeInterval is the initial interval for probing unavailable paths.
    // Doubles on each consecutive probe, capped at ProbeMaxInterval.
    // Default: 30s.
    ProbeInterval time.Duration

    // ProbeMaxInterval caps the exponential backoff. Default: 300s (5 min).
    ProbeMaxInterval time.Duration

    // OnPathDown is an optional callback invoked when a path transitions
    // to unavailable. Used for logging/metrics/alerting.
    OnPathDown func(pathID int, target string, err error)

    // OnPathUp is an optional callback invoked when a path recovers.
    OnPathUp func(pathID int, target string)
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
    return Config{
        PingInterval:     5 * time.Second,
        PingTimeout:      10 * time.Second,
        MaxPaths:         2,
        Selector:         &RoundRobinSelector{},
        ProbeInterval:    30 * time.Second,
        ProbeMaxInterval: 5 * time.Minute,
    }
}
```

---

## 6. Construction and Teardown

### 6.1 Construction

```go
// Example: constructing a MultiPathSession for a proxy entry node.
func buildMultiPath(ctx context.Context, exits []ExitCandidate) (*multipath.MultiPathSession, error) {
    // exits is pre-sorted by score: fastest first, up to 2 entries.
    var paths []multipath.Path
    for i, exit := range exits[:min(2, len(exits))] {
        // 1. HandshakeLayer.Connect → net.Conn
        conn, err := handshake.Connect(ctx, exit.Addr)
        if err != nil {
            log.Printf("path %d unreachable: %v", i, err)
            continue
        }
        // 2. Session layer: key exchange → SecureConn
        sec, err := session.Handshake(conn, exit.PublicKey)
        if err != nil {
            conn.Close()
            continue
        }
        // 3. smux.Client → smux.Session
        smuxSess, err := smux.Client(sec, smux.DefaultConfig())
        if err != nil {
            sec.Close()
            continue
        }
        paths = append(paths, multipath.Path{
            ID:      i,
            Target:  exit.PublicKey.String(),
            Session: smuxSess,
        })
    }
    if len(paths) == 0 {
        return nil, fmt.Errorf("no exit nodes reachable")
    }
    return multipath.New(multipath.DefaultConfig(), paths...), nil
}
```

### 6.2 Teardown

```go
// Close shuts down all paths. Idempotent.
mps.Close()

// Guarantees:
// 1. All underlying smux sessions are closed.
// 2. All open streams on all paths receive io.EOF on next Read.
// 3. All heartbeat goroutines stop.
// 4. Subsequent OpenStream() returns ErrClosed.
```

---

## 7. Error Model

```go
var (
    // ErrPoolExhausted is returned by OpenStream when ALL paths are
    // unavailable. The caller should back off and retry.
    ErrPoolExhausted = errors.New("multipath: all paths unavailable")

    // ErrPathUnavailable is returned by OpenStreamOn when the specified
    // path is not in the available pool.
    ErrPathUnavailable = errors.New("multipath: path unavailable")

    // ErrClosed is returned by OpenStream after Close().
    ErrClosed = errors.New("multipath: session closed")

    // ErrPathNotFound is returned by OpenStreamOn when pathID >= NumPaths().
    ErrPathNotFound = errors.New("multipath: path not found")
)
```

All errors are sentinel values — callers use `errors.Is()` for comparison.

---

## 8. Extension Point: Stream Multipath (v2.1)

### 8.1 Current Design (Flow-Level Multipath)

Each `OpenStream()` call pins the returned stream to exactly one path. A stream
lives and dies on that path. This matches smux's model: one stream = one
reliable byte stream over one connection. It's correct for:

- **Proxy with per-request routing:** Each HTTP request → `OpenStream()` → one
  exit → one target TCP connection. Browser connections are inherently parallel
  (6+ per host) — multipath at the connection level achieves dispersion.
- **WebSSH:** A terminal session is one stream to one node. MultiPathSession
  selects the best path for the session.
- **File transfer:** Each transfer is one stream. MultiPathSession load-balances
  concurrent transfers across paths.

### 8.2 Future: Chunk-Level Multipath

For use cases where a SINGLE stream's data must be split across paths (large
file download, video stream), the MultiPathSession can be extended with a
`MultiStream` that internally distributes chunks:

```go
// MultiStream (v2.1) is a net.Conn that distributes writes across
// all active paths and reassembles reads from all paths.
type MultiStream struct {
    // ...
}

// OpenMultiStream (v2.1) opens a chunk-level multipath stream.
// func (m *MultiPathSession) OpenMultiStream(ctx context.Context) (net.Conn, error)
```

This requires:
1. A chunk protocol with sequence numbers (already designed in PROXY_DESIGN.md
   §1.2: Chunk Format).
2. A reassembly buffer on the receiving side (already designed in
   PROXY_DESIGN.md §1.3: Reassembly + Retransmission).
3. A per-chunk path selection strategy (uses the same PathSelector interface).

The current design is forward-compatible: `MultiPathSession`, `Path`,
`PathSelector`, and `PathHealth` are unaware of how streams are used. Adding
chunk-level multipath is a new type (`MultiStream`) that consumes the same
pool of paths.

### 8.3 Interaction Between Flow-Level and Chunk-Level

When `MultiStream` is active on a path, that path's `ActiveStreams` count
reflects it (one MultiStream = one active stream count). Other callers using
`OpenStream()` (flow-level) share the remaining capacity. The PathSelector
handles this transparently — paths with `MultiStream` open may receive fewer
(or zero) new flow-level streams depending on capacity config.

---

## 9. Package Layout

```
meshdesk/
├── internal/
│   ├── multipath/                   ← NEW (Layer 3, this spec)
│   │   ├── multipath.go             ← MultiPathSession + Path + Config
│   │   ├── session.go               ← Session interface (smux abstraction)
│   │   ├── selector.go              ← PathSelector + RoundRobin + LatencyWeighted
│   │   ├── health.go                ← PathHealth + heartbeat monitor
│   │   └── errors.go                ← Sentinel errors
│   ├── smux/                        ← Layer 2 (separate task)
│   │   └── ...
│   ├── session/                     ← Layer 2 (separate task)
│   │   └── session.go               ← SecureConn + key exchange
│   └── handshake/                   ← Layer 1 (FROZEN)
│       ├── handshake.go
│       └── reality.go
```

**Dependency arrows:**
```
multipath → smux.Session (via Session interface)
smux → session.SecureConn (for its underlying conn)
session → handshake.HandshakeLayer (for net.Conn)
handshake → net (stdlib)
```

MultiPathSession does NOT import smux directly — it uses the `Session`
interface defined in `multipath/session.go`. This lets smux be tested
or swapped without touching the multipath package.

---

## 10. Integration Points

### 10.1 With Proxy Layer (circuit/dispatcher)

```go
// Dispatcher calls OpenStream for each new proxy request:
stream, pathID, err := mps.OpenStream(ctx)
if err != nil {
    // all exits down; queue request or reject
}
// tunnel proxy request through stream
go proxyTunnel(stream, targetConn)
metrics.RecordStreamOpened(pathID)
```

### 10.2 With WebSSH

```go
// WebSSH handler selects a path for the terminal session:
stream, pathID, err := mps.OpenStream(ctx)
if err != nil {
    http.Error(w, "no exit nodes available", 503)
    return
}
// bridge WebSocket ↔ stream
go bridgeWS(wsConn, stream)
```

### 10.3 With File Transfer

```go
// File transfer opens one stream per file, load-balanced:
for _, file := range files {
    stream, pathID, _ := mps.OpenStream(ctx)
    go transferFile(stream, file)
}
```

### 10.4 With Observability

The `PathStats()` method feeds the proxy status page:

```json
{
  "paths": [
    {"id": 0, "target": "exit-hk", "latency": "15ms", "active_streams": 12, "healthy": true},
    {"id": 1, "target": "exit-tokyo", "latency": "45ms", "active_streams": 8, "healthy": true}
  ]
}
```

---

## 11. Acceptance Criteria

### AC-1: Construction succeeds with 1 or more paths.

```go
mps, err := multipath.New(cfg, path1, path2)
// mps is non-nil, err is nil
// mps.NumPaths() == 2
```

### AC-2: Construction fails with zero paths.

```go
mps, err := multipath.New(cfg)
// err != nil, mps is nil
```

### AC-3: OpenStream distributes across all available paths.

```go
// With 2 healthy paths and RoundRobinSelector:
stream1, pid1, _ := mps.OpenStream(ctx) // pid1 == 0
stream2, pid2, _ := mps.OpenStream(ctx) // pid2 == 1
stream3, pid3, _ := mps.OpenStream(ctx) // pid3 == 0 (wraps)
```

### AC-4: OpenStreamOn routes to a specific path.

```go
stream, err := mps.OpenStreamOn(ctx, 0)
// stream is from path 0, err is nil

stream, err = mps.OpenStreamOn(ctx, 999)
// err is ErrPathNotFound
```

### AC-5: Unavailable path is excluded from selection.

```go
// Mark path 0 as unavailable.
mps.paths[0].Health.Available = false

stream, pid, _ := mps.OpenStream(ctx)
// pid == 1 (only path 1 is available)
```

### AC-6: All paths unavailable → ErrPoolExhausted.

```go
// Mark all paths unavailable.
mps.paths[0].Health.Available = false
mps.paths[1].Health.Available = false

stream, pid, err := mps.OpenStream(ctx)
// err is ErrPoolExhausted, stream is nil
```

### AC-7: Close is idempotent and clean.

```go
mps.Close()
err := mps.Close() // idempotent: no panic
// err is nil

stream, pid, err := mps.OpenStream(ctx)
// err is ErrClosed
```

### AC-8: Close shuts down all underlying sessions.

```go
// After mps.Close():
// - path[0].Session.IsClosed() == true
// - path[1].Session.IsClosed() == true
// - All goroutines (heartbeat monitors) have stopped
```

### AC-9: Session interface is satisfied by smux.Session.

```go
var _ multipath.Session = (*smux.Session)(nil)
// compiles — smux.Session satisfies the interface
```

### AC-10: MultiPathSession does not import smux directly.

```bash
grep -r "smux" internal/multipath/
# → no results
# (Session interface provides the abstraction)
```

### AC-11: PathStats returns observability data.

```go
stats := mps.PathStats()
// len(stats) == NumPaths()
// stats[0].PathID == 0
// stats[0].Healthy is true/false
// stats[0].ActiveStreams >= 0
```

### AC-12: Selector is swappable at runtime.

```go
mps.cfg.Selector = &LatencyWeightedSelector{Alpha: 0.3}
// subsequent OpenStream calls use the new selector
// no restart required
```

---

## 12. Trade-offs

### 12.1 Flow-level vs Chunk-level Multipath

| Aspect | Flow-level (Phase 1) | Chunk-level (v2.1) |
|--------|---------------------|-------------------|
| Complexity | Low — no sequence numbers | High — chunk protocol + reassembly |
| Correctness | Each stream = one TCP connection, standard semantics | Requires exit-side reassembly across 2 TCP connections |
| Throughput | N streams × path bandwidth (good for browser parallelism) | 1 stream × Σ path bandwidth (good for single large transfer) |
| Failure mode | Dead path = streams on that path fail, new streams elsewhere | Dead path = retransmit chunks on surviving path |
| Integration | Drop-in: any io.ReadWriteCloser consumer works | Requires MultiStream consumer awareness |

**Decision:** Ship flow-level in Phase 1. The interface (PathSelector,
Session, PathHealth) is designed to support chunk-level as a new type
without interface changes — the path pool is the same.

### 12.2 Stateless vs Stateful Selection

**Stateless (RoundRobin):** Each `OpenStream()` is independent. No shared
state beyond an atomic counter. O(1), zero contention.

**Stateful (LatencyWeighted):** Selector reads per-path health state.
Requires a read lock on the path array (but contention is low — only
OpenStream and health monitor goroutines touch it).

**Decision:** Start with RoundRobin (AC-3 verifies distribution).
LatencyWeighted is a drop-in via the PathSelector interface — no code
changes in MultiPathSession.

### 12.3 All-Paths-Unavailable Behavior

Three options considered:

1. **Return error immediately.** Clean but requires every caller to handle
   PoolExhausted with retry logic. Pollutes upper-layer code.
2. **Block until a path recovers.** Simple for callers but may block
   indefinitely — a goroutine leak waiting for a dead exit.
3. **Escape hatch: probe LRQ and try it.** Best effort forward progress.
   If probe succeeds, stream goes through. If fails, error returned.

**Decision:** Option 3 — escape hatch. The MultiPathSession tries the
least-recently-unavailable path. If the probe succeeds, the stream is
opened and the path is restored to available. If it fails, ErrPoolExhausted
is returned. One probe attempt, not a loop — no indefinite blocking.

---

## 13. Downstream Tasks

After this spec is approved:

1. **architect (next):** Freeze Layer 2 — smux integration design (smux.go,
   Session interface, stream ID allocation).
2. **architect:** Freeze Layer 2 — Session layer (SecureConn + X25519 key
   exchange + Ed25519 identity binding).
3. **developer:** Implement `internal/multipath/multipath.go` per this spec.
4. **developer:** Implement `internal/multipath/health.go` — heartbeat monitor.
5. **developer:** Implement `internal/multipath/selector.go` — RoundRobinSelector.
6. **tester:** Verify acceptance criteria AC-1 through AC-12.