# MeshDesk v2 — Interface Contract

**Status:** AUTHORITATIVE (freeze order + interface signatures for all layers)
**Date:** 2026-07-28
**Author:** writer
**Motion:** motion-856c071ce5a9 (Agora: MeshDesk v2 full rewrite)
**Task:** t_6d0e90d0 (Action item 9/10)
**Parent:** t_ce22c37c (Layer 0 + Layer 1 freeze)

---

## 1. Freeze Order

MeshDesk v2 protocol stack is frozen bottom-up. Once a layer's interface
is merged, it cannot change without a new motion. Implementation may lag
— an interface freeze means "the contract is settled; code must conform."

| # | Layer | Name | Interface | Status | Frozen in |
|---|-------|------|-----------|--------|-----------|
| **L0** | Identity | Permanent node identity | `identity.Identity`, `Sign()`, `Verify()` | **FROZEN** | t_ce22c37c |
| **L1** | Handshake | Encrypted byte stream | `handshake.HandshakeLayer` | **FROZEN** | t_ce22c37c |
| **L2a** | Session | Authenticated key exchange | `session.SecureConn` | Draft | t_bd744498 |
| **L2b** | smux | Stream multiplexing | `smux.Session` | Draft | Pending |
| **L3** | MultiPathSession | Multi-path stream pool | `multipath.MultiPathSession` | Draft | t_bd744498 |

This document is the single source of truth for what each layer guarantees
to the layer above it. All code references are interface signatures, not
implementation details.

---

## 2. Layer 0 — Identity

**Status:** FROZEN
**Package:** `meshdesk/internal/identity/`
**Key type:** Ed25519 (Go stdlib `crypto/ed25519`)

### 2.1 Interface Signatures

```go
package identity

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/hex"
    "fmt"
)

const KeyLen = ed25519.PublicKeySize // 32 bytes

// Identity is the permanent, immutable identity of a mesh node.
// The PublicKey hex string IS the node's identifier everywhere:
// gossip NodeMeta, PeerManager, session auth, and Dashboard.
type Identity struct {
    PrivateKey string // hex-encoded Ed25519 private key (64 bytes / 128 hex chars)
    PublicKey  string // hex-encoded Ed25519 public key (32 bytes / 64 hex chars)
}

func GenerateIdentity() (*Identity, error)
func IdentityFromHex(privHex string) (*Identity, error)
func (id *Identity) Sign(data []byte) (string, error)       // → hex-encoded signature (128 chars)
func Verify(pubKeyHex string, data []byte, sigHex string) bool
func (id *Identity) ToPEM() (string, error)                  // RFC 8410 PEM (optional)
func IdentityFromPEM(pemData []byte) (*Identity, error)      // PEM → Identity (optional)
func PublicKeyToPEM(pubHex string) (string, error)           // SPKI PEM (optional)
```

### 2.2 Contract Guarantees

1. **Key serialization:** All keys are hex-encoded strings (matching v1 convention).
   Ed25519 private key = 128 hex chars (64 bytes). Public key = 64 hex chars (32 bytes).
   Signature = 128 hex chars (64 bytes).
2. **No external dependencies.** Uses `crypto/ed25519` from stdlib only.
   No `golang.org/x/crypto/curve25519`.
3. **No key clamping required.** Ed25519 has no clamping requirement
   (unlike v1 Curve25519).
4. **Identity file format:** `/etc/meshdesk/identity.json` with `version: 2`.
5. **The public key IS the node ID.** No derivation from IP. No mesh subnet.
   The public key hex is the sole namespace for peer identification in
   gossip, PeerManager, session auth, and Dashboard.

### 2.3 Import Rules

- `internal/identity/` MUST NOT import `internal/handshake/` — zero upward coupling.
- Consumed by: `internal/session/` (for Sign + Verify), gossip (for NodeMeta signing).

---

## 3. Layer 1 — Handshake

**Status:** FROZEN
**Package:** `meshdesk/internal/handshake/`
**Key type:** X25519 (Reality TLS authentication — independent from Layer 0 Ed25519)

### 3.1 Interface Signature

```go
package handshake

import (
    "context"
    "net"
    "time"
)

// HandshakeLayer establishes encrypted connections between mesh nodes.
// It is identity-agnostic: Connect accepts an address, not a peer identity.
// Identity binding is Layer 2's job.
//
// Implementations:
//   - RealityHandshake (TCP): REALITY TLS 1.3 over TCP. Returns *tls.Conn.
//   - QUICHandshake (UDP, deferred): QUIC Short Header over UDP.
type HandshakeLayer interface {
    Connect(ctx context.Context, addr string) (net.Conn, error)
    Listen(ctx context.Context, addr string) (net.Listener, error)
}

// HandshakeConfig configures a HandshakeLayer implementation.
// Only handshake-level fields — no peer management, connection limits,
// or health probes. Those are upper-layer concerns.
type HandshakeConfig struct {
    ListenAddr   string
    DialTimeout  time.Duration

    // Reality-specific
    RealityDest        string
    RealityPrivateKey  string
    RealityPublicKey   string
    RealityShortID     string
    RealityServerNames []string
    TLSFingerprint     string
}

// HandshakeError classifies connect/listen errors.
type HandshakeError struct {
    Op    string // "connect" or "listen"
    Addr  string
    Err   error
    Retry bool   // true = transient
}

func (e *HandshakeError) Error() string
func (e *HandshakeError) Unwrap() error
func (e *HandshakeError) IsRetryable() bool
```

### 3.2 Contract Guarantees

1. **Connect returns `net.Conn`, not `PeerConn`.** No transport metadata,
   no latency cache, no `ForceClose()`. The v1 `PeerConn` abstraction
   (Transport/Latency/ForceClose) is removed — `net.Conn` is the narrowest
   useful contract for a byte stream.
2. **`net.Conn` from Connect is `*tls.Conn` for TCP Reality.**
   It satisfies `net.Conn` and can be wrapped by AES-GCM or passed to smux.
3. **No factory pattern.** One `HandshakeLayer` instance per node.
   v1's `TransportFactory` managed per-peer transport instances because
   WireGuard needed per-peer handshake state. v2 eliminates this — one TCP
   listener on :443, same Reality keys for all peers.
4. **Identity-agnostic.** `Connect` takes an address, not a peer identity.
   The handshake layer never sees an Ed25519 public key.
5. **Error classification:** `HandshakeError.Retry` distinguishes transient
   (timeout, DNS blip) from permanent (bad address, wrong Reality keys).

### 3.3 Import Rules

- `internal/handshake/` MUST NOT import `internal/identity/` — zero upward coupling.
- MUST NOT import `wireguard`, `gVisor`, or `obfuscation` packages.
- Consumed by: `internal/session/` (for `net.Conn`).

---

## 4. Layer 2a — Session (Key Exchange + Identity Binding)

**Status:** DRAFT (interface preview — freeze pending in separate task)
**Package:** `meshdesk/internal/session/`

### 4.1 Interface Signature (Preview)

```go
package session

import (
    "context"
    "net"

    "github.com/yzy806806/meshdesk/internal/identity"
)

// SecureConn is the authenticated, encrypted connection produced by a
// session handshake. It wraps a raw net.Conn (from HandshakeLayer.Connect)
// with X25519 ECDH key exchange + Ed25519 identity verification + AES-GCM.
//
// SecureConn implements net.Conn — upper layers (smux) treat it as a pipe.
type SecureConn struct {
    // net.Conn (Read, Write, Close, LocalAddr, RemoteAddr, SetDeadline, ...)
    net.Conn
    // unexported: aesgcm wrapper, peer identity
}

// Handshake performs the v2 session key exchange over a raw net.Conn:
//
//   1. Generate X25519 ephemeral keypair
//   2. Send: [ephemeralPublicKey:32][ed25519Signature:64]
//      → signature = Ed25519.Sign(self.Identity, ephemeralPublicKey)
//   3. Receive peer's ephemeral + signature
//   4. Verify: ed25519.Verify(peer.PublicKey, peerEphemeral, peerSignature)
//   5. If valid → HKDF-SHA256(ECDH(ourEphemeral, peerEphemeral)) → session key
//   6. Wrap raw conn in AES-256-GCM → SecureConn
//   7. If invalid → close conn (peer doesn't own the claimed identity)
//
// This is the binding point between Layer 0 (Identity) and Layer 1 (Handshake).
func Handshake(
    id *identity.Identity,
    peerPubKey string,   // expected peer Ed25519 public key (hex)
    rawConn net.Conn,     // from HandshakeLayer.Connect
) (*SecureConn, error)

// HandshakeServer is the server-side equivalent — called on connections
// accepted from HandshakeLayer.Listen.
func HandshakeServer(
    id *identity.Identity,
    rawConn net.Conn,
) (*SecureConn, string, error) // returns (SecureConn, peer's verified public key, error)
```

### 4.2 Contract Guarantees (Preview)

1. **Identity binding happens here.** This is the ONLY point where Ed25519
   identity (Layer 0) meets the encrypted channel (Layer 1). Before Session,
   the handshake layer is identity-agnostic. After Session, smux and above
   see an authenticated stream with a verified peer identity.
2. **X25519 and Ed25519 are independent.** Session generates its own X25519
   ephemeral for key exchange. The Ed25519 key signs the ephemeral — no DH
   function on the Ed25519 key.
3. **SecureConn wraps `net.Conn` with AES-256-GCM.** The underlying
   `net.Conn` is transparent to upper layers.
4. **One handshake per connection.** Session handshake runs once when a new
   `net.Conn` is established. No rekeying in Phase 1 (v2.1 will add key
   rotation).

---

## 5. Layer 2b — smux (Stream Multiplexing)

**Status:** DRAFT (interface preview — freeze pending)
**Package:** `meshdesk/internal/smux/`

### 5.1 Interface Signature (Preview)

```go
package smux

import (
    "net"
    "time"
)

// Session multiplexes many logical streams over one underlying connection.
// Each stream is a bidirectional net.Conn. Stream lifetime is independent
// of other streams on the same session.
//
// Design constraint: smux operates over a `net.Conn` (specifically, a
// SecureConn from the session layer). It has no identity awareness, no
// path selection — just stream multiplexing over one pipe.
type Session struct {
    // (unexported)
}

// Client initiates a smux session over an established connection.
func Client(conn net.Conn, cfg Config) (*Session, error)

// Server accepts a smux session from an incoming connection.
func Server(conn net.Conn, cfg Config) (*Session, error)

// OpenStream creates a new logical stream. Returns a net.Conn.
// The stream carries application data — WebSSH, file transfer, proxy relay.
func (s *Session) OpenStream() (net.Conn, error)

// AcceptStream receives a stream opened by the remote peer.
func (s *Session) AcceptStream() (net.Conn, error)

// NumStreams returns the count of currently open streams.
func (s *Session) NumStreams() int

// Close shuts down the session and all streams. Idempotent.
func (s *Session) Close() error

// IsClosed reports whether Close has been called.
func (s *Session) IsClosed() bool

// Config tunes smux behavior.
type Config struct {
    MaxStreams          int           // max concurrent streams (0 = unlimited)
    KeepAliveInterval   time.Duration // idle stream keepalive
    KeepAliveTimeout    time.Duration // close idle streams after timeout
    MaxFrameSize        int           // max frame payload (default: 32768)
}

func DefaultConfig() Config
```

### 5.2 Contract Guarantees (Preview)

1. **One `net.Conn` → many `net.Conn`.** smux is the multiplexer between
   the session layer (one physical connection) and application services
   (many logical streams).
2. **Stream = `net.Conn`.** Every stream is a full `net.Conn` — supports
   `SetDeadline`, `LocalAddr`, `RemoteAddr`. Application code uses standard
   Go APIs.
3. **No identity, no path selection.** smux knows nothing about Ed25519
   identities or multi-path routing. Its sole job: put N streams on 1 pipe.
4. **Stream ID 0 reserved for heartbeat.** Used by MultiPathSession
   (Layer 3) for path health monitoring.

---

## 6. Layer 3 — MultiPathSession (Multi-Path Stream Pool)

**Status:** DRAFT (interface preview — freeze pending in t_bd744498)
**Package:** `meshdesk/internal/multipath/`

### 6.1 Interface Signature (Preview)

```go
package multipath

import (
    "context"
    "net"
    "time"
)

// Session is the interface that underlying multiplexed sessions must satisfy.
// smux.Session implements this directly.
type Session interface {
    OpenStream() (net.Conn, error)
    AcceptStream() (net.Conn, error)
    NumStreams() int
    Close() error
    IsClosed() bool
}

// Path represents one multipath channel: a smux session plus its health state.
type Path struct {
    ID      int
    Target  string    // exit node identifier (peer public key hex)
    Session Session
    Health  PathHealth
    Stats   PathStats
}

// MultiPathSession manages multiple Paths and provides a single
// OpenStream() entry point for upper layers.
type MultiPathSession struct {
    // (unexported)
}

func New(cfg Config, paths ...Path) (*MultiPathSession, error)

// OpenStream selects a path and opens a new stream on it.
// Returns (stream, pathID, error). pathID is for observability.
func (m *MultiPathSession) OpenStream(ctx context.Context) (net.Conn, int, error)

// OpenStreamOn opens a stream on a specific path.
func (m *MultiPathSession) OpenStreamOn(ctx context.Context, pathID int) (net.Conn, error)

// AcceptStream accepts an incoming stream from any path.
func (m *MultiPathSession) AcceptStream(ctx context.Context) (net.Conn, int, error)

func (m *MultiPathSession) Close() error
func (m *MultiPathSession) NumPaths() int
func (m *MultiPathSession) ActivePaths() []*Path
func (m *MultiPathSession) PathStats() []PathStat

// ── Selection ────────────────────────────────────────────────────────

type PathSelector interface {
    Select(paths []*Path) int // returns path index, or -1 if none available
}

type RoundRobinSelector struct { /* atomic counter */ }
type LatencyWeightedSelector struct { Alpha float64 } // Phase 2

// ── Health ───────────────────────────────────────────────────────────

type PathHealth struct {
    Latency             time.Duration
    ConsecutiveFailures int
    Available           bool
    LastPing            time.Time
}

type PathStat struct {
    PathID             int
    Target             string
    Latency            time.Duration
    ActiveStreams      int
    TotalStreamsOpened uint64
    TotalStreamsFailed uint64
    Healthy            bool
    LastError          string
    LastErrorTime      time.Time
}

// ── Config ────────────────────────────────────────────────────────────

type Config struct {
    PingInterval      time.Duration // default: 5s
    PingTimeout       time.Duration // default: 10s
    MaxPaths          int           // default: 2
    Selector          PathSelector  // default: RoundRobinSelector
    ProbeInterval     time.Duration // default: 30s
    ProbeMaxInterval  time.Duration // default: 300s
    OnPathDown        func(pathID int, target string, err error)
    OnPathUp          func(pathID int, target string)
}

type PathConfig struct {
    MaxStreams  int // 0 = unlimited
    MaxFailures int // default: 3
}

func DefaultConfig() Config

// ── Errors ────────────────────────────────────────────────────────────

var (
    ErrPoolExhausted   = errors.New("multipath: all paths unavailable")
    ErrPathUnavailable = errors.New("multipath: path unavailable")
    ErrClosed          = errors.New("multipath: session closed")
    ErrPathNotFound    = errors.New("multipath: path not found")
)
```

### 6.2 Contract Guarantees (Preview)

1. **Single `OpenStream()` entry point.** Upper layers (proxy, WebSSH,
   file transfer) call `OpenStream()` without knowing about path selection.
2. **Flow-level multipath only (Phase 1).** Each stream is pinned to one
   path. Chunk-level splitting (one stream across N paths) deferred to v2.1.
3. **Path health is maintained.** Heartbeat pings detect dead paths.
   Three consecutive failures → path marked unavailable. Exponential backoff
   probing for recovery.
4. **MultiPathSession does not import smux directly.** It uses the `Session`
   interface — smux is testable and swappable without touching multipath.

---

## 7. Cross-Layer Dependency Graph

```
┌─────────────────────────────────────────────────────────┐
│ Application Layer                                       │
│   Proxy (circuit/dispatcher)                            │
│   WebSSH / File Transfer / Dashboard RPC                │
│   Requires: net.Conn (stream)                           │
├─────────────────────────────────────────────────────────┤
│ Layer 3: MultiPathSession                 ^             │
│   OpenStream() → (net.Conn, pathID, err)   │             │
│   Depends on: multipath.Session interface  │             │
├────────────────────────────────────────────┼─────────────┤
│ Layer 2b: smux                            │             │
│   Session.OpenStream() → net.Conn         │             │
│   Session implements multipath.Session ───┘             │
│   Depends on: net.Conn (from session)                   │
├─────────────────────────────────────────────────────────┤
│ Layer 2a: Session                                       │
│   Handshake() → SecureConn (net.Conn + AES-GCM)         │
│   Identity ← Ed25519 Sign/Verify                        │
│   Transport ← HandshakeLayer.Connect (net.Conn)          │
│   THIS is the binding point: Identity meets Transport.  │
├──────────────────────┬──────────────────────────────────┤
│ Layer 1: Handshake   │  Layer 0: Identity               │
│   Connect(addr)      │    Sign(data) → signature        │
│   → net.Conn         │    Verify(pub, data, sig) → bool │
│   (Reality TLS 1.3)  │    Ed25519, stdlib-only          │
│                      │                                  │
│   X25519 keypair     │    Ed25519 keypair               │
│   (REALITY auth)     │    (mesh identity)               │
│                      │                                  │
│   └─ FROZEN ─────────┴── FROZEN ────────────────────────│
└─────────────────────────────────────────────────────────┘
```

### 7.1 Import Rules (Enforced)

| From → To | Allowed? | Reason |
|-----------|----------|--------|
| `identity` → `handshake` | **NO** | Zero upward coupling |
| `handshake` → `identity` | **NO** | Zero upward coupling |
| `session` → `identity` | YES | Signs/verifies during key exchange |
| `session` → `handshake` | YES (interface only) | Receives `net.Conn` from `HandshakeLayer` |
| `smux` → `session` | YES (via `net.Conn`) | Takes `SecureConn` as a `net.Conn` |
| `multipath` → `smux` | NO (via `multipath.Session` interface) | Interface abstraction — no direct import |
| `handshake` → `wireguard/gVisor` | **NO** | All v1 deps removed |

---

## 8. Layer Crossing: What Each Layer Does NOT Know

| Layer | Knows Nothing About |
|-------|--------------------|
| **L0 Identity** | Handshake protocol, transport addresses, peer endpoints, session keys |
| **L1 Handshake** | Mesh identity, Ed25519 keys, peer gossip metadata, stream multiplexing |
| **L2a Session** | Stream multiplexing, path selection, multi-path routing |
| **L2b smux** | Identity, key exchange, path selection, multi-path awareness |
| **L3 MultiPath** | Identity key details, handshake protocol specifics, application protocol |

This is deliberate. Each layer's ignorance is a feature — it means layers
can evolve independently. Reality TCP → QUIC Reality swaps at L1 without
touching L0, L2a, or above. Ed25519 → post-quantum signatures swaps at L0
without touching L1. smux → HTTP/2 swaps at L2b without touching L3.

---

## 9. Configuration Dependencies

| Layer | Config Source | Required Fields |
|-------|--------------|-----------------|
| **L0 Identity** | `/etc/meshdesk/identity.json` | `private_key`, `public_key`, `version: 2` |
| **L1 Handshake** | `config.yaml` → `reality:` block | `dest`, `private_key`, `public_key`, `short_ids`, `server_names` |
| **L2a Session** | Auto-derived | Uses L0 Identity + L1 net.Conn — no separate config |
| **L2b smux** | `config.yaml` → (TBD) | `max_streams`, `keepalive_interval` |
| **L3 MultiPath** | `config.yaml` → (TBD) | `max_paths`, `ping_interval` |

Config files in `/etc/meshdesk/` are read once at startup. The `version: 2`
field in `identity.json` disambiguates v2 Ed25519 keys from v1 Curve25519 keys.

---

## 10. How to Add a New Transport (e.g., QUIC Reality)

1. Implement `handshake.HandshakeLayer` with a new struct (e.g., `QUICHandshake`).
2. `Connect()` returns a `net.Conn` (implemented via `quic.Stream`).
3. `Listen()` returns a `net.Listener`.
4. Zero changes to Layer 0, Layer 2a, or above — `HandshakeLayer` is consumed
   as the interface, not as a concrete `RealityHandshake`.
5. Config: add a `quic:` block to `config.yaml`.

This is the contract's value: the interface is the pluggability point.

---

## 11. Related Documents

| Document | Relationship |
|----------|-------------|
| `docs/LAYER0_LAYER1_SPEC.md` | Detailed Layer 0+1 spec with ACs, rationale, v1 impact |
| `docs/MULTIPATH_SESSION_SPEC.md` | Detailed Layer 3 spec with ACs |
| `docs/MESHDESK_V2_DESIGN.md` | Overall v2 architecture and decisions |
| `docs/V2_MIGRATION_GUIDE.md` | WireGuard → Reality operator migration path |
| `docs/TRANSPORT_CONTRACT.md` | v1 transport contract (superseded by this document) |
| `docs/CHUNKER_CONTRACT.md` | Proxy chunker/dispatcher contract |
| `docs/PROXY_DESIGN.md` | Multi-path dispersed proxy design |

---

## 12. Change History

| Date | Change | Author |
|------|--------|--------|
| 2026-07-28 | Initial: L0+L1 frozen (from t_ce22c37c), L2+L3 preview | writer |
| — | L2a+L2b freeze | (pending) |
| — | L3 freeze | (pending) |