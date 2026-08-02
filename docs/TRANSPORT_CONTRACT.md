# Transport Layer Interface Contract

**Version:** 1.0
**Status:** Adopted (team motion motion-822f52b56dbe, action item 4/5)
**File:** `internal/mesh/transport.go`
**Tests:** existing mesh tests pass (contract-only file; per-implementation tests TBD)

---

## 1. Overview

This document defines the three-layer Transport interface contract for MeshDesk's
pluggable transport system. The transport layer sits between the mesh protocol
core and the physical network, providing pluggable transport strategies (UDP,
WebSocket, Reality TLS) with per-peer configuration, graceful shutdown, health
monitoring, latency probing, and failover testing support.

The contract was extracted from the existing obfuscation layer
(`internal/mesh/obfuscation.go`) and generalized to support:

- **UDP Transport** — raw UDP (LAN, lowest latency)
- **WebSocket Transport** — WebSocket + uTLS over TCP (existing, fallback)
- **Reality Transport** — Reality TLS natively implemented in Go (new, primary GFW path)

New transports can be added by implementing the interfaces and registering with
`TransportRegistry` — no core changes required.

---

## 2. The Three-Layer Contract

### 2.1 Layer 1: PeerConn — Per-Connection Wrapper

```
interface PeerConn {
    net.Conn                         // Read, Write, Close, LocalAddr, RemoteAddr, SetDeadline, SetReadDeadline, SetWriteDeadline
    Transport() string               // transport name: "udp", "websocket", "reality"
    Latency() time.Duration         // last measured RTT, or 0
    ForceClose() error              // immediate close without graceful drain
}
```

**Contract:**

- `PeerConn` extends `net.Conn` with transport metadata and latency tracking.
- `Transport()` returns the name of the transport that created this connection.
- `Latency()` returns the last measured RTT. Updated internally by `Transport.LatencyProbe`. Returns zero if not yet measured.
- `ForceClose()` immediately closes the underlying socket. Unlike `Close()` (which may perform a graceful TLS `close_notify`), `ForceClose` is a direct socket closure.
- All methods must be safe for concurrent use.
- `NewPeerConn(c net.Conn, transport string)` is the canonical constructor.

### 2.2 Layer 2: Transport — Per-Transport Instance

```
interface Transport {
    Name() string                                                    // transport protocol name
    Connect(ctx context.Context, addr string) (PeerConn, error)      // outbound connection
    Listen(ctx context.Context, addr string) (net.Listener, error)   // inbound listener
    LatencyProbe(ctx context.Context, addr string) (time.Duration, error)  // lightweight RTT probe
    IsHealthy() bool                                                  // point-in-time health check
}
```

**Contract:**

- `Name()` returns the transport protocol name (`"udp"`, `"websocket"`, `"reality"`). Must match the obfuscation mode strings in `config.yaml`.
- `Connect(ctx, addr)` establishes an outbound connection. `addr` is `"host:port"`. Must respect context cancellation.
- `Listen(ctx, addr)` starts an inbound listener. Must respect context cancellation.
- `LatencyProbe(ctx, addr)` measures RTT without establishing a full peer connection. Implementations should use lightweight probes:
  - TCP-based transports: TCP SYN/SYN-ACK timing
  - UDP transports: application-level ping
  - Returns `ErrTransportUnavailable` if the transport is not healthy.
  - Returned errors must be transient-classified (retry may succeed) or permanent (bad address, missing cert).
- `IsHealthy()` is a point-in-time assessment. Must respond quickly (no blocking I/O). A `false` return means the transport should be removed from the active fallback list.
- All methods are safe for concurrent use.

### 2.3 Layer 3: TransportFactory — Lifecycle Management

```
interface TransportFactory {
    Name() string                                           // factory/transport type name
    NewTransport(cfg TransportConfig) (Transport, error)    // create Transport instance
    Shutdown(ctx context.Context) error                     // drain all, block until done
    ConnCount() int                                         // active connection count
    ActiveSince() time.Time                                 // factory creation / last restart
}
```

**Contract:**

- `Name()` must match the `Name()` of `Transport` instances produced.
- `NewTransport(cfg)` creates a new `Transport` instance. Returns an error if the factory has been shut down or the config is invalid.
- `Shutdown(ctx)` blocks until all connections drain or the context expires. **Post-conditions after Shutdown:**
  1. All `Transport` instances are closed.
  2. `NewTransport` returns `ErrTransportShutdown`.
  3. `Connect`/`Listen` on existing transports return `net.ErrClosed`.
  4. `Shutdown` is idempotent — calling it multiple times is safe.
- `ConnCount()` returns the total number of active connections across all `Transport` instances.
- `ActiveSince()` returns the factory creation time or last restart time.

**Lifecycle:**
```
1. NewTransport(cfg)     → create Transport
2. Transport.Connect() / Transport.Listen()  → use
3. Shutdown(ctx)         → drain all connections, release resources
```

### 2.4 TransportRegistry — Registration and Selection

`TransportRegistry` is a concrete struct (not an interface) designed for zero-allocation
embedding in `MeshNode`:

```
struct TransportRegistry {
    // unexported fields: factories map, fallbackOrder slice
}
```

**Contract:**

- `Register(factory)` — registers a `TransportFactory`. Overwrites duplicate names.
- `Get(name)` — returns the factory by name. When `SetFallbackOrder` is configured, returns the first healthy transport in the order regardless of the requested name (automatic failover). Returns `ErrTransportNotFound` if no suitable transport is found.
- `List()` — returns all registered transport names (non-deterministic order).
- `FallbackOrder()` — returns the current failover priority (index 0 = primary). Returns `nil` if no order is set.
- `SetFallbackOrder(order)` — defines the failover priority chain. `index 0` is tried first, then `index 1`, etc. `SetFallbackOrder(nil)` disables automatic failover.
- `ShutdownAll(ctx)` — calls `Shutdown` on every registered factory. Returns the first error encountered.
- All methods are safe for concurrent use.

---

## 3. TransportConfig — Configuration Model

```go
type TransportConfig struct {
    Name           string        // transport type: "udp", "websocket", "reality"
    DialTimeout    time.Duration // max connect wait (0 = default 30s)
    IdleTimeout    time.Duration // max idle before close (0 = no limit)
    MaxConns       int           // max concurrent connections (0 = no limit)
    ListenAddr     string        // inbound listen address

    // TLS
    UseTLS         bool
    CertFile       string
    KeyFile        string
    ServerName     string        // SNI hostname
    TLSFingerprint string        // uTLS ClientHello fingerprint

    // Reality-specific
    RealityDest          string   // camouflage target
    RealityPrivateKey    string   // X25519 private key
    RealityPublicKey     string   // X25519 public key
    RealityShortID       string   // per-client short ID
    RealityServerNames   []string // accepted SNIs

    // Obfuscation
    ObfuscationMode string   // "none", "padded", "websocket"
    ObfuscationPSK  string   // hex-encoded PSK
}
```

**Zero-value semantics:** A zero-valued `TransportConfig` must produce a usable
`Transport` with sensible defaults (UDP on port 0, 30s connect timeout, etc.).
Callers must NOT need to check for nil sub-structs.

**Validation:** `TransportConfig.Validate()` returns an error describing the
first missing or invalid field. Zero config for `"udp"` is valid.

**Defaults:** `DefaultTransportConfig()` returns `{Name: "udp", DialTimeout: 30s, TLSFingerprint: "chrome"}`.

---

## 4. Error Model

### 4.1 TransportError

```go
type TransportError struct {
    Op    string // "connect", "listen", "lookup", "health", "shutdown"
    Name  string // transport name
    Addr  string // target address
    Err   error  // underlying error
    Retry bool   // transient (retry-able) vs permanent
}
```

- `Unwrap()` returns the underlying error for `errors.As`/`errors.Is` compatibility.
- `IsRetryable()` returns whether a retry may succeed.
- `NewTransportError(op, name, addr, err, retryable)` is the constructor.

### 4.2 Error Sentinels

| Sentinel | Kind | Meaning |
|---|---|---|
| `ErrTransportNotFound` | Permanent | No transport matches name or fallback chain |
| `ErrTransportUnavailable` | Transient | Transport registered but currently unhealthy |
| `ErrTransportShutdown` | Permanent | Factory/Transport used after Shutdown |

### 4.3 Config Errors

```go
type TransportConfigError struct {
    Field  string // which field
    Reason string // why it's invalid
}
```

- Always a permanent error — fix the config, retrying won't help.

### 4.4 Shutdown Errors

```go
type TransportShutdownError struct {
    Name string // which factory failed
    Err  error  // underlying error
}
```

- Wraps individual factory shutdown failures from `TransportRegistry.ShutdownAll`.

### 4.5 Error Classification Rules

Implementations must classify errors as:
- **Transient** (`Retry: true`): timeouts, temporary network failures, rate limits, DNS resolution failures, `ErrTransportUnavailable`
- **Permanent** (`Retry: false`): bad addresses, missing TLS certs, `ErrTransportNotFound`, `ErrTransportShutdown`, config validation failures

PeerManager uses this classification for retry/fallback decisions.

---

## 5. Operational Guarantees

### 5.1 Concurrency Safety

All interfaces (`PeerConn`, `Transport`, `TransportFactory`) and the
`TransportRegistry` struct are concurrency-safe. Callers may invoke methods
from multiple goroutines without external synchronization.

### 5.2 Graceful Shutdown

`TransportFactory.Shutdown(ctx)` must:
1. Stop accepting new connections.
2. Close all listeners.
3. Drain existing connections (data may be sent/received until drained).
4. Release all OS resources (file descriptors, sockets).
5. Return when drain is complete or `ctx` is cancelled.

The registry-level `ShutdownAll(ctx)` calls every factory's `Shutdown` sequentially
and collects errors.

### 5.3 Health Monitoring

`Transport.IsHealthy()` is a point-in-time assessment. Implementations should:
- Return quickly (no blocking I/O).
- Cache recent connect/listen success/failure.
- Return `false` after consecutive failures (configurable threshold).
- Return `true` on initial state or after successful operations.

### 5.4 Connection Limits

`TransportConfig.MaxConns` (when > 0) caps the total number of concurrent
connections for a `Transport` instance. Implementations must:
- Reject `Connect` with a backpressure error when at capacity.
- Release capacity when a connection closes.

### 5.5 Idle Timeout

`TransportConfig.IdleTimeout` (when > 0) defines the maximum idle duration
before the transport proactively closes a connection. Implementations must:
- Track last I/O time per connection.
- Close idle connections after the timeout elapses.
- Reset the idle timer on any read or write.

### 5.6 Failover Ordering

`TransportRegistry.SetFallbackOrder` defines a priority chain. When configured:
1. `Get(name)` ignores `name` and returns the first healthy transport in the order.
2. PeerManager iterates through the chain on connection failure.
3. The order is validated lazily — a transport added to the registry after
   `SetFallbackOrder` participates in the chain.

---

## 6. How to Add a New Transport

1. Create a new package or file (e.g., `internal/mesh/transport_reality.go`).
2. Implement the `Transport` interface.
3. Implement the `TransportFactory` interface.
4. Register both in `init()`:
   ```go
   func init() {
       mesh.NewTransportRegistry() // existing registry
       // Or: import from your package and register with the registry
   }
   ```
5. Add configuration defaults and validation in `TransportConfig`.
6. Run contract verification:
   - `go build` — compiles cleanly
   - `go vet` — no warnings
   - `go test ./internal/mesh/` — existing tests pass

**No core code changes required** — the interface indirection is the pluggability point.

---

## 7. Acceptance Criteria

All eight acceptance criteria from `transport.go` header:

| ID | Criterion | Status |
|---|---|---|
| AC-1 | `PeerConn` wraps `net.Conn` and exposes transport metadata | Verified — `peerConn` struct composes `net.Conn` + `transport`/`latency` fields |
| AC-2 | `TransportFactory.Shutdown` blocks until drain or ctx expires | Specified — contract §2.3 |
| AC-3 | `TransportRegistry.SetFallbackOrder` defines failover priority | Verified — `fallbackOrder` slice, index 0 = primary |
| AC-4 | `LatencyProbe` with transient-classified errors | Specified — contract §2.2 |
| AC-5 | Interfaces mockable — `net.Pipe()` compatible | Verified — all interfaces, `TestConnector`/`TestListener` hooks |
| AC-6 | Full godoc doc comments on all public types | Verified — `go doc ./internal/mesh/` covers all public types |
| AC-7 | Zero-value `TransportConfig` safe (`Validate` rejects empty `Name`) | Verified — `Validate()` returns error for empty Name |
| AC-8 | `TransportError` distinguishes transient vs permanent | Verified — `Retry` field + `IsRetryable()` method |

---

## 8. Reviewer Gap Coverage

Six gaps identified by reviewer, all covered:

| Gap | Requirement | Coverage |
|---|---|---|
| RG-1 | Shutdown with context and graceful drain | `TransportFactory.Shutdown(ctx)` — blocks until drain or cancel |
| RG-2 | Health reporting per-transport | `Transport.IsHealthy()` — point-in-time assessment |
| RG-3 | Idle timeout configuration | `TransportConfig.IdleTimeout` — max idle before close |
| RG-4 | Connection limits / backpressure | `TransportConfig.MaxConns` — capacity cap |
| RG-5 | Error classification | `TransportError` — transient vs permanent with `Unwrap()` |
| RG-6 | Operational metrics | `TransportFactory.ConnCount()` + `ActiveSince()` |

---

## 9. Tester Hooks

Two hooks for deterministic failover testing:

- `LatencyProbe(ctx, addr)` — enables injecting controlled latency and errors for path-selection tests.
- `SetFallbackOrder(order)` — enables deterministic failover sequence simulation.
- `TestConnector` / `TestListener` — enable `net.Pipe()`-based in-memory failover tests.

---

## 10. File Manifest

| File | Purpose |
|---|---|
| `internal/mesh/transport.go` | Interface definitions, types, `TransportRegistry`, `TransportConfig`, errors |
| `docs/TRANSPORT_CONTRACT.md` | This document |
| `docs/TRANSPORT_CAPABILITY_MATRIX.md` | Per-implementation feature support matrix |

---

## 11. Related Documents

- `docs/ARCHITECTURE_REFACTOR.md` — architecture decision and implementation plan
- `docs/PROXY_DESIGN.md` — multi-path dispersed anonymous proxy design
- `docs/DESIGN.md` — overall MeshDesk design
- `docs/CHUNKER_CONTRACT.md` — Chunker/Reassembler contract (same contract pattern)
