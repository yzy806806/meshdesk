# MeshDesk v2 — Layer 0 (Identity) + Layer 1 (Handshake) Combined Specification

**Status:** FROZEN (Foundation layers of v2 protocol stack)
**Date:** 2026-07-28
**Author:** architect
**Motion:** motion-856c071ce5a9 (Agora discussion: MeshDesk v2 full rewrite)
**Task:** t_ce22c37c (Action item 1/10 from the motion)
**Freeze order:** Layer 0 → Layer 1 → Layer 2 (Session) → Layer 3 (smux)

---

## Overview

This document freezes the bottom two layers of the MeshDesk v2 protocol stack.
Together they form the foundation all higher layers build on:

| Layer | Name | Responsibility | Key type | Freeze status |
|-------|------|---------------|----------|---------------|
| **L0** | Identity | Permanent node identity | Ed25519 (stdlib) | **This spec** |
| **L1** | Handshake | Encrypted byte stream | X25519 (Reality TLS) | **This spec** |

These two key types are **independent**. The Handshake layer uses X25519
for its REALITY TLS authentication. The Identity layer uses Ed25519 for mesh
identity, session signing, and gossip authenticity. Binding between them
happens in Layer 2 (Session), where Ed25519 signs the X25519 ephemeral.

**Why this split matters:** The Handshake layer doesn't need to know about
mesh identity. It's a pure pipe — `Connect` returns a `net.Conn`. Identity
and authentication flow upward through the stack: Identity → Session → smux
→ application. This decoupling means you can swap the handshake transport
(TCP Reality, future QUIC Reality) without touching the identity model.

---

## 1. Layer 0 — Identity

### 1.1 The v1 Legacy (what we're replacing)

```go
// v1 — WireGuard Curve25519, in internal/mesh/peer/identity.go (101 lines)
type Identity struct {
    PrivateKey string // hex-encoded Curve25519 private key
    PublicKey  string // hex-encoded Curve25519 public key
}
```

v1 identity is a **Curve25519** (X25519) keypair, hex-encoded. It served
double duty: both WireGuard Noise_IKpsk2 handshake AND peer identification.
Key clamping (RFC 7748) is required: `priv[0] &= 248; priv[31] &= 127; priv[31] |= 64`.

**What's wrong for v2:**
- Curve25519 is a Diffie-Hellman key; it can't sign. v1 had no mechanism
  to prove ownership of a peer identity — any peer claiming a public key
  could connect (WireGuard's pre-shared key was the only auth).
- No gossip authenticity: gossip messages carry a public key but can't
  prove they're from that peer.
- No session auth: when Layer 2 does X25519 ECDH, we can't prove the other
  side owns the claimed identity.

### 1.2 v2 Identity: Ed25519

Every MeshDesk v2 node has a **permanent Ed25519 keypair**. The public key
**IS** the node's mesh identity. No derivation from IP. No mesh subnet.
No `allowed_ips`. No WireGuard key clamping.

```go
// Package identity provides the permanent node identity for MeshDesk v2.
//
// In v2, identity is an Ed25519 keypair — not a Curve25519/X25519 key.
// Ed25519 supports digital signatures, enabling:
//   - Session auth: signing the Layer 2 X25519 ephemeral proves ownership
//   - Gossip integrity: every NodeMeta update carries an Ed25519 signature
//   - Peer authentication: PeerManager can verify claimed identity
//
// This replaces v1's internal/mesh/peer/ package (Curve25519, ~101 lines).
// Implementation: crypto/ed25519 from Go stdlib. No external dependency.
package identity

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/hex"
    "fmt"
)

// KeyLen is the byte length of an Ed25519 key.
const KeyLen = ed25519.PublicKeySize // 32 bytes

// Identity is the permanent, immutable identity of a mesh node.
// The PublicKey IS the node's identifier throughout the mesh:
// gossip, PeerManager, session auth, and Dashboard all reference
// nodes by their Ed25519 public key (hex-encoded).
//
// There is no mesh IP, no subnet, no allowed_ips. The public key
// is the sole namespace for peer identification.
type Identity struct {
    // PrivateKey is the hex-encoded Ed25519 private key (64 bytes / 128 hex chars).
    // Never transmitted over the network. Used for signing.
    PrivateKey string

    // PublicKey is the hex-encoded Ed25519 public key (32 bytes / 64 hex chars).
    // This IS the node's mesh identity. Shared freely via gossip.
    PublicKey string
}

// GenerateIdentity creates a new random Ed25519 keypair.
// Uses crypto/rand for secure random key generation.
// No key clamping needed — Ed25519 has no clamping requirement.
func GenerateIdentity() (*Identity, error) {
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("generate ed25519 keypair: %w", err)
    }
    return &Identity{
        PrivateKey: hex.EncodeToString(priv),
        PublicKey:  hex.EncodeToString(pub),
    }, nil
}

// IdentityFromHex creates an Identity from a hex-encoded private key.
// The public key is derived from the private key automatically.
func IdentityFromHex(privHex string) (*Identity, error) {
    priv, err := hex.DecodeString(privHex)
    if err != nil {
        return nil, fmt.Errorf("decode private key hex: %w", err)
    }
    if len(priv) != ed25519.PrivateKeySize {
        return nil, fmt.Errorf("invalid key length: got %d, want %d", len(priv), ed25519.PrivateKeySize)
    }
    // Extract the public key from the private key
    privKey := ed25519.PrivateKey(priv)
    pub := privKey.Public().(ed25519.PublicKey)
    return &Identity{
        PrivateKey: privHex,
        PublicKey:  hex.EncodeToString(pub),
    }, nil
}

// Sign signs data with this node's Ed25519 private key.
// The signature is 64 bytes. Returns hex-encoded signature.
// This is the contract that Layer 2 (Session) and Gossip depend on:
//   - Layer 2: Sign(X25519_ephemeral_pub) → sig[32:64] attached to key exchange
//   - Gossip:   Sign(NodeMeta) → sig included in memberlist broadcast
func (id *Identity) Sign(data []byte) (string, error) {
    priv, err := hex.DecodeString(id.PrivateKey)
    if err != nil {
        return "", fmt.Errorf("decode private key: %w", err)
    }
    privKey := ed25519.PrivateKey(priv)
    sig := ed25519.Sign(privKey, data)
    return hex.EncodeToString(sig), nil
}

// Verify checks an Ed25519 signature against a public key.
// Used by PeerManager to verify gossip payloads and session-handshake proofs.
func Verify(pubKeyHex string, data []byte, sigHex string) bool {
    pub, err := hex.DecodeString(pubKeyHex)
    if err != nil {
        return false
    }
    sig, err := hex.DecodeString(sigHex)
    if err != nil {
        return false
    }
    return ed25519.Verify(ed25519.PublicKey(pub), data, sig)
}
```

### 1.3 Key Serialization

All keys are **hex-encoded strings** (matching v1 convention).

| Field | Raw bytes | Hex chars | Example |
|-------|-----------|-----------|---------|
| Ed25519 private key | 64 | 128 | `a1b2c3...` |
| Ed25519 public key | 32 | 64 | `d4e5f6...` |
| Ed25519 signature | 64 | 128 | `7890ab...` |

The public key hex string is used everywhere a node is referenced:
gossip NodeMeta, PeerManager peer IDs, Dashboard node list, session
handshake messages, and config files.

**PEM encoding (optional):** For interop with standard tools and config
files, a `ToPEM()` / `FromPEM()` helper produces RFC 8410 ASN.1 DER
wrapped in PEM. Not required for the mesh protocol — convenience only.

```go
// ToPEM exports the Ed25519 private key as PEM (RFC 8410).
// Suitable for config files that want human-readable key blocks.
func (id *Identity) ToPEM() (string, error)

// IdentityFromPEM loads an Ed25519 keypair from PEM bytes.
func IdentityFromPEM(pemData []byte) (*Identity, error)

// PublicKeyToPEM exports only the public key as PEM (SPKI format).
func PublicKeyToPEM(pubHex string) (string, error)
```

### 1.4 Identity File Layout

Each node stores its identity in a single file (matching v1 convention):

```
/etc/meshdesk/identity.json    (default path)
~/.meshdesk/identity.json      (user-mode fallback)
```

```json
{
  "private_key": "a1b2c3d4... (128 hex chars)",
  "public_key":  "d4e5f6a7... (64 hex chars)",
  "created_at":  "2026-07-28T00:00:00Z",
  "version": 2
}
```

`version: 2` distinguishes v2 Ed25519 identities from v1 Curve25519
identities (which had `version: 1` or were unversioned).

### 1.5 Migration: v1 Curve25519 → v2 Ed25519

Migration is a **one-time key rotation**, not an in-place conversion.

```
v1 identity:  Curve25519 (32B private, 32B public, hex-encoded)
              Used for: WireGuard Noise IK + peer identification
              Cannot sign, cannot authenticate gossip

v2 identity:  Ed25519 (64B private, 32B public, hex-encoded)
              Used for: session signing + gossip integrity + peer ID
              Replaces v1 identity entirely

Migration path:
  1. Generate new Ed25519 keypair with GenerateIdentity()
  2. Write to /etc/meshdesk/identity.json with version: 2
  3. Old v1 identity is discarded — WireGuard/gVisor/meshIP are removed
  4. No backward compatibility bridge (v2 is a clean break)
```

---

## 2. Layer 1 — Handshake

### 2.1 Interface (FROZEN — t_8cbf2bf4)

The HandshakeLayer is the protocol-agnostic transport interface. It
establishes encrypted, authenticated byte streams between mesh nodes.
The returned `net.Conn` carries opaque application data — no transport
metadata, no peer routing info.

```go
// Package handshake provides the Layer 1 transport contract for MeshDesk v2.
//
// The HandshakeLayer interface is frozen — implementations may be added
// (TCP Reality, QUIC Reality) but the interface itself does not change.
package handshake

import (
    "context"
    "net"
)

// HandshakeLayer establishes encrypted connections between mesh nodes.
//
// Implementations:
//   - RealityHandshake (TCP): reuses reality_transport.go from v1, stripped
//     of WireGuard framing. TLS 1.3 + REALITY authentication over TCP.
//     Returns *tls.Conn (a net.Conn) indistinguishable from HTTPS.
//   - QUICHandshake (UDP, deferred): same interface, QUIC Short Header
//     packets with REALITY-style auth over UDP. Drop-in replacement.
//
// The returned net.Conn is the raw encrypted byte stream — the caller
// receives TLS application data (for TCP) or QUIC stream data (for UDP).
// No protocol framing, no transport metadata — just bytes.
type HandshakeLayer interface {
    // Connect establishes an outbound encrypted connection to addr.
    // addr format: "host:port" (e.g., "1.2.3.4:443").
    // The returned net.Conn is a bidirectional encrypted byte stream.
    // Context cancellation aborts the connection attempt.
    Connect(ctx context.Context, addr string) (net.Conn, error)

    // Listen starts an inbound listener on addr.
    // addr format: "host:port" (e.g., "0.0.0.0:443").
    // The returned net.Listener produces net.Conn values from Accept().
    // Context cancellation closes the listener.
    Listen(ctx context.Context, addr string) (net.Listener, error)
}
```

### 2.2 Key Design Decisions

| Decision | v1 | v2 |
|----------|----|----|
| Return type | `PeerConn` (wraps net.Conn + Transport/Latency/ForceClose) | `net.Conn` (standard Go interface) |
| Factory | `TransportFactory` per-transport-type (shutdown, conn tracking) | No factory — single instance per node |
| Latency | `LatencyProbe()` on Transport | PeerManager measures via Session ping |
| Health | `IsHealthy()` on Transport | PeerManager infers from connect success |
| MaxConns | `TransportConfig.MaxConns` semaphore | PeerManager config concern |
| IdleTimeout | `TransportConfig.IdleTimeout` | Session concern (key rotation) |
| Identity in API | `Connect(ctx, addr)` — no peer ID | Same — identity binding is Layer 2's job |
| Context | `Connect` takes context, `Listen` does not (v1) | Both take `context.Context` (v2) |

**Why net.Conn, not PeerConn:**

`PeerConn` was a WireGuard artifact. Its `Transport()` method told
PeerManager which transport protocol was in use. Its `Latency()` cached
RTT. Its `ForceClose()` bypassed TLS close_notify. None of these belong
at the handshake layer in v2:

- PeerManager knows which transport it used because it called it.
- RTT is measured by timing `Connect()` itself or via Session ping.
- `conn.Close()` is the standard way to close a connection — TLS
  close_notify is part of the standard library's `Close()`.

`net.Conn` is the narrowest useful contract. smux works over
`io.ReadWriteCloser`. AES-GCM wraps `net.Conn` into another `net.Conn`.
QUIC's `quic.Stream` satisfies `net.Conn`. No abstraction leak.

### 2.3 Concrete Implementation: RealityHandshake (TCP)

RealityHandshake reuses ~500 lines from v1's `reality_transport.go` (941 lines
total). The REALITY TLS 1.3 handshake core is kept; WireGuard framing,
the factory, peer management, and health probes are stripped.

**KEPT (~500 lines):**
- `dialReality()` — TCP dial + uTLS REALITY client handshake with X25519 ECDH,
  HKDF auth key derivation, AES-GCM tag injection into ClientHello SessionId
- `Listen()` — Reality server-side listener: `realitypkg.Listen` with camouflage
  forwarding to RealityDest
- `realityListener` — `net.Listener` wrapper over `reality.Listener` with
  buffered accept channel
- `buildRealityConfig()` — constructs `reality.Config` (ServerNames, ShortIds,
  DialContext)
- `generateRealityPlaceholderCert()` — throwaway ECDSA cert for
  `reality.Listen`'s non-empty Certificates check
- `getEcdheKey()` — extracts X25519 ephemeral from uTLS handshake state
- `newAESGCM()` / `decodeHexKey()` / `GenerateRealityKeyPair()` — crypto helpers

**STRIPPED (~340 lines):**
- `RealityTransportFactory` (90–249) — multi-instance factory with conn/listener tracking
- `RealityTransportFactory.Shutdown` (151–202) — cross-peer graceful drain
- `Connect()` returning `PeerConn` (303–345) — v1 wraps in `realityPeerConn`
- `realityPeerConn` struct (709–755) — Transport/Latency/ForceClose metadata
- `LatencyProbe()` (621–684) — TLS handshake timing (PeerManager concern)
- `IsHealthy()` (688–693) — health polling (PeerManager concern)
- `semCh` / `initSemaphore` / `releaseSemSlot` (269–290, 458–465) — MaxConns semaphore
- `factory.registerConn/unregisterConn` (216–249) — factory-side tracking
- `IdleTimeout` application (338–340) — moved to Session layer
- `markClosed()` (696–699) — factory shutdown propagation

### 2.4 HandshakeConfig

```go
// HandshakeConfig configures a HandshakeLayer implementation.
// Only fields relevant to the handshake itself — no peer management,
// no connection limits, no health probes.
type HandshakeConfig struct {
    // ListenAddr is the address for Listen(). Default: "0.0.0.0:443".
    ListenAddr string

    // DialTimeout is the max time for Connect to establish. Default: 30s.
    DialTimeout time.Duration

    // ── Reality-specific fields ──────────────────────────────────────

    // RealityDest is the camouflage target (e.g., "www.apple.com:443").
    RealityDest string

    // RealityPrivateKey is the X25519 private key (hex) for server-side.
    RealityPrivateKey string

    // RealityPublicKey is the X25519 public key (hex) for client-side.
    RealityPublicKey string

    // RealityShortID is the per-client short ID (hex, max 8 bytes).
    RealityShortID string

    // RealityServerNames is the list of accepted SNI values for server-side.
    RealityServerNames []string

    // TLSFingerprint is the uTLS ClientHello fingerprint to mimic.
    // Default: "chrome".
    TLSFingerprint string
}
```

### 2.5 Wire Format (Reality TLS over TCP)

**Client → Server (Connect):**
```
TCP SYN → TCP established
ClientHello (TLS 1.3, SNI=target domain) →
  SessionId[0:4]   = version (unused)
  SessionId[4:8]   = unix timestamp
  SessionId[8:16]  = shortId (client identity)
  SessionId[16:32] = padding
  key_share        = X25519(client_ephemeral)
  // authKey = HKDF-SHA256(ECDH(client_ephemeral, server_pub), info="REALITY")
  // SessionId[:16] = AES-GCM-Seal(authKey, RawClientHello, plaintext=SessionId[:16])
← ServerHello (TLS 1.3, real target domain cert) + Finished
→ Client Finished
=== TLS 1.3 application data stream (net.Conn) ===
```

**Server side (Listen):**
```
TCP SYN → ClientHello parsed:
  - Extract key_share = client X25519 ephemeral
  - ECDH(client_ephemeral, server_private) → authKey
  - HKDF-SHA256 → final auth key
  - Verify AES-GCM tag in SessionId[:16] against authKey
  - Valid:   complete TLS handshake → return net.Conn to Accept()
  - Invalid: forward to RealityDest (camouflage) → GFW probe sees real response
```

### 2.6 Error Classification

```go
// HandshakeError classifies connect/listen errors.
// Preserved from v1 TransportError — renamed to avoid confusion.
type HandshakeError struct {
    Op    string // "connect" or "listen"
    Addr  string // target address
    Err   error  // underlying error
    Retry bool   // true = transient, may succeed on retry
}

func (e *HandshakeError) Error() string { ... }
func (e *HandshakeError) Unwrap() error { return e.Err }
func (e *HandshakeError) IsRetryable() bool { return e.Retry }
```

---

## 3. Layer 0 ↔ Layer 1 Integration

### 3.1 Key Types Are Independent

```
┌─────────────────────────────────────────────────────────┐
│ Layer 0: Identity                                       │
│   Ed25519 keypair (64B private, 32B public)             │
│   Purpose: node identity + signing                      │
│   Used by: Session (key exchange auth), Gossip (msgs)   │
│   Stored in: /etc/meshdesk/identity.json                │
│   Lifetime:  permanent (generated once per node)        │
├─────────────────────────────────────────────────────────┤
│ Layer 1: Handshake                                      │
│   X25519 keypair (32B private, 32B public)              │
│   Purpose: REALITY TLS 1.3 handshake authentication     │
│   Used by: RealityHandshake (dialReality client auth)   │
│   Stored in: HandshakeConfig                            │
│   Lifetime:  configurable, rotated with Reality config  │
└─────────────────────────────────────────────────────────┘
```

**Why two keypairs?** The REALITY protocol uses X25519 ECDH for its
authentication tag injection. This is a transport-layer concern — GFW
evasion. The Ed25519 identity signs higher-level protocol messages
(session handshake, gossip). Mixing them would couple transport security
to mesh identity, making it impossible to rotate one without the other.

### 3.2 The Binding Chain (in Layer 2)

The binding between Identity (Layer 0) and Handshake (Layer 1) happens in
Layer 2 (Session), **not** in these foundation layers. This is by design:

```
1. Layer 1 (Handshake):  Reality TLS returns a raw net.Conn
   → No identity awareness at this level

2. Layer 2 (Session):    Over the raw net.Conn:
   a. Generate X25519 ephemeral keypair
   b. Send: [ephemeralPublicKey:32][ed25519Signature:64]
      → signature = Ed25519.Sign(identity.PrivateKey, ephemeralPublicKey)
   c. Receive peer's ephemeral + signature
   d. Verify: ed25519.Verify(peer.PublicKey, peerEphemeral, peerSignature)
   e. If valid → HKDF-SHA256(ECDH(ourEphemeral, peerEphemeral)) → session key
   f. If invalid → close conn (peer doesn't own the claimed identity)

3. Layer 0 (Identity):   Provides Sign() and Verify()
   → Used by Layer 2, never by Layer 1
```

The Handshake layer is identity-agnostic. The Identity layer is
transport-agnostic. Layer 2 is the bridge.

### 3.3 Gossip Identity

Gossip uses Layer 0 identity directly — no Layer 1 involvement:

```go
// NodeMeta (in gossip memberlist) carries the Ed25519 public key
// and a signature proving the node owns it.
type NodeMeta struct {
    PublicKey string   // hex-encoded Ed25519 public key (64 chars)
    Endpoints []string // e.g., ["reality+tcp://1.2.3.4:443"]
    Roles     []string // ["entry", "exit", "relay"]
    Timestamp int64    // unix_ms
    Signature string   // Ed25519.Sign(privateKey, PublicKey||Endpoints||Roles||Timestamp)
}

func (m *NodeMeta) Verify() bool {
    data := m.PublicKey + strings.Join(m.Endpoints, ",") + strings.Join(m.Roles, ",") + fmt.Sprint(m.Timestamp)
    return identity.Verify(m.PublicKey, []byte(data), m.Signature)
}
```

---

## 4. Package Layout

```
meshdesk/
├── internal/
│   ├── identity/                 ← NEW (Layer 0)
│   │   ├── identity.go           ← Identity struct + Generate + FromHex + Sign
│   │   ├── identity_test.go      ← Unit tests (crypto/ed25519)
│   │   └── pem.go                ← PEM encode/decode helpers (optional)
│   ├── handshake/                ← NEW (Layer 1)
│   │   ├── handshake.go          ← HandshakeLayer interface + HandshakeConfig + errors
│   │   └── reality.go            ← RealityHandshake implementation
│   │                              (~500 lines ported from reality_transport.go)
│   ├── session/                  ← NEW (Layer 2, next task)
│   │   └── session.go            ← SecureConn + X25519 key exchange + Ed25519 binding
│   └── mesh/                     ← v1 (being pruned)
│       ├── reality_transport.go  ← DELETED (moved to handshake/reality.go)
│       ├── transport.go          ← PRUNED (Transport/Factory/Registry removed)
│       ├── peer/identity.go      ← DELETED (replaced by internal/identity/)
│       ├── handshake.go          ← DELETED (WireGuard handshake)
│       └── obfuscation.go        ← DELETED (only Reality, no modes)
```

---

## 5. v1 Code Impact

### 5.1 Files to DELETE

| File | Lines | Reason |
|------|-------|--------|
| `internal/mesh/peer/identity.go` | 101 | Curve25519 identity → Ed25519 in `internal/identity/` |
| `internal/mesh/peer/identity_test.go` | ~60 | Tests for deleted code |
| `internal/mesh/transport.go` | 533 | Transport/Factory/Registry → HandshakeLayer |
| `internal/mesh/reality_transport.go` (partial) | ~340 | WireGuard framing, factory, peer management |
| Import of `golang.org/x/crypto/curve25519` | — | No longer needed (Ed25519 in stdlib) |

### 5.2 Dependencies REMOVED

```
golang.org/x/crypto/curve25519  → GONE (stdlib crypto/ed25519 instead)
golang.zx2c4.com/wireguard      → GONE (already removed in Phase 1)
gvisor.dev/gvisor                → GONE (already removed in Phase 1)
```

### 5.3 Files to KEEP (refactored)

| File | What changes |
|------|-------------|
| `internal/mesh/reality_transport.go` | ~500 lines ported to `internal/handshake/reality.go` |
| `internal/mesh/peer_manager.go` | Refactored: `Transport.Dial()` → `handshake.Connect()` |
| Config files referencing peer identity | Updated: `identity` field now Ed25519 hex |

---

## 6. Acceptance Criteria

Tests that MUST pass before Layer 0+1 are considered "frozen and implemented."

### Layer 0 (Identity)

**AC-0.1: GenerateIdentity produces valid Ed25519 keypair.**
```go
id, err := identity.GenerateIdentity()
// err is nil
// len(id.PrivKeyHex()) == 128 (64 bytes hex-encoded)
// len(id.PubKeyHex()) == 64  (32 bytes hex-encoded)
// hex.DecodeString(id.PrivateKey) succeeds
// hex.DecodeString(id.PublicKey) succeeds
```

**AC-0.2: IdentityFromHex round-trips correctly.**
```go
id1, _ := identity.GenerateIdentity()
id2, err := identity.IdentityFromHex(id1.PrivateKey)
// err is nil
// id1.PublicKey == id2.PublicKey
// id1.PrivateKey == id2.PrivateKey
```

**AC-0.3: Sign + Verify round-trips.**
```go
id, _ := identity.GenerateIdentity()
data := []byte("test message")
sig, err := id.Sign(data)
// err is nil
// len(sig) == 128 (64 bytes hex-encoded)

ok := identity.Verify(id.PublicKey, data, sig)
// ok is true
```

**AC-0.4: Verify rejects tampered data or wrong key.**
```go
id, _ := identity.GenerateIdentity()
sig, _ := id.Sign([]byte("original"))

// Tampered data
ok := identity.Verify(id.PublicKey, []byte("tampered"), sig)
// ok is false

// Wrong public key
id2, _ := identity.GenerateIdentity()
ok = identity.Verify(id2.PublicKey, []byte("original"), sig)
// ok is false
```

**AC-0.5: No Curve25519 dependency.**
```bash
grep -r "curve25519\|Curve25519" internal/identity/
# → no results
```

**AC-0.6: Zero external dependencies.**
```bash
go list -deps ./internal/identity/ | grep -v "^\(internal\|errors\|fmt\|crypto\|encoding\|io\|strings\|sync\|time\|runtime\|unicode\|reflect\)"
# → only stdlib packages
```

### Layer 1 (Handshake)

**AC-1.1: HandshakeLayer interface compiles.**
```go
var _ handshake.HandshakeLayer = (*handshake.RealityHandshake)(nil)
// compiles
```

**AC-1.2: Connect returns net.Conn, not PeerConn.**
```go
hs := handshake.NewRealityHandshake(clientCfg)
conn, err := hs.Connect(ctx, "127.0.0.1:10443")
// conn is *tls.Conn (satisfies net.Conn)
// conn does NOT have Transport(), Latency(), or ForceClose() methods
```

**AC-1.3: Listen returns net.Listener producing net.Conn.**
```go
hs := handshake.NewRealityHandshake(serverCfg)
ln, err := hs.Listen(ctx, ":10443")
conn, err := ln.Accept()
// conn is net.Conn, not wrapped
```

**AC-1.4: Client ↔ server handshake succeeds.**
```go
// Server: NewRealityHandshake(serverCfg).Listen(ctx, ":10443")
// Client: NewRealityHandshake(clientCfg).Connect(ctx, "127.0.0.1:10443")
// → client gets net.Conn, server gets net.Conn from Accept()
// → bytes written on one side are readable on the other
```

**AC-1.5: Invalid reality client is rejected with camouflage.**
```go
// Client with wrong RealityPublicKey → Connect returns HandshakeError
// Server's underlying listener forwards to RealityDest (camouflage)
```

**AC-1.6: Context cancellation aborts Connect.**
```go
ctx, cancel := context.WithCancel(context.Background())
cancel()
conn, err := hs.Connect(ctx, "127.0.0.1:10443")
// err is context.Canceled, conn is nil
```

**AC-1.7: Context cancellation closes listener.**
```go
ctx, cancel := context.WithCancel(context.Background())
ln, _ := hs.Listen(ctx, ":10443")
cancel()
// ln.Accept() returns net.ErrClosed or equivalent
```

**AC-1.8: No WireGuard dependencies in handshake package.**
```bash
grep -r "wireguard\|PeerConn\|TransportFactory\|obfuscati" internal/handshake/
# → no results
```

**AC-1.9: Reality keypair generation works standalone.**
```go
priv, pub, err := handshake.GenerateRealityKeyPair()
// priv and pub are hex strings
// len(pub) == 64 (32 bytes hex-encoded X25519 public key)
```

### Integration (L0 ↔ L1)

**AC-I.1: Identity does not import handshake.**
```bash
grep -r "handshake" internal/identity/
# → no results
```

**AC-I.2: Handshake does not import identity.**
```bash
grep -r "identity" internal/handshake/
# → no results
```

**AC-I.3: Ed25519 and X25519 keys are independent.**
```go
// Can generate identity and reality keys independently
id, _ := identity.GenerateIdentity()
priv, pub, _ := handshake.GenerateRealityKeyPair()
// id.PublicKey is Ed25519 (64 hex chars)
// pub is X25519 (64 hex chars)
// They are different key types and cannot be confused
```

---

## 7. Downstream Tasks

After this spec is approved:

| # | Task | Assignee | Depends on |
|---|------|----------|------------|
| 1 | Implement `internal/identity/identity.go` (~30 lines) | developer | This spec |
| 2 | Implement `internal/handshake/handshake.go` + `reality.go` | developer | This spec + reality_transport.go |
| 3 | Freeze Layer 2 — Session (SecureConn + X25519 key exchange + Ed25519 binding) | architect | This spec |
| 4 | Freeze Layer 2 — smux integration (Session interface, stream ID allocation) | architect | Layer 2 Session spec |
| 5 | Freeze Layer 3 — Gossip (redesigned NodeMeta, endpoint propagation) | architect | Layer 0 Identity |
| 6 | Cut old code: delete `internal/mesh/peer/identity.go`, `transport.go` | developer | This spec |

---

## 8. Trade-offs and Rationale

### 8.1 Ed25519 vs Curve25519

| Aspect | Curve25519 (v1) | Ed25519 (v2) |
|--------|----------------|-------------|
| Key type | DH (can't sign) | Signing (can't DH) |
| Stdlib | `golang.org/x/crypto` (external dep) | `crypto/ed25519` (stdlib) |
| Key clamping | Required (3 bitwise ops) | Not required |
| Signature size | N/A | 64 bytes |
| Public key size | 32 bytes | 32 bytes |
| Private key size | 32 bytes | 64 bytes (includes public key) |
| WireGuard compat | Yes (it's what WG uses) | No (not relevant — we're removing WG) |

**Decision:** Ed25519. The ability to sign is required for session auth
and gossip integrity. WireGuard compatibility is irrelevant since we're
removing WireGuard. Stdlib-only is a hard requirement — no `golang.org/x`
dependency for the identity package.

### 8.2 Identity in Connect vs in Session

Two designs considered:

**A) Include identity in HandshakeLayer.Connect:**
`Connect(ctx, peerIdentity, addr) (net.Conn, error)` — the transport layer
verifies identity during or after the TLS handshake.

**B) Identity-agnostic HandshakeLayer (chosen):**
`Connect(ctx, addr) (net.Conn, error)` — Layer 2 (Session) binds identity
to the connection after the encrypted channel is established.

| Aspect | A (Transport identity) | B (Session identity — CHOSEN) |
|--------|----------------------|-------------------------------|
| Transport coupling | Coupled to identity model | Transport is identity-agnostic |
| QUIC future | QUIC transport must also verify identity | QUIC doesn't change |
| Abstraction level | Identity is a transport concern? | Identity is a session concern |
| Testability | Need real keys for transport tests | Transports testable with dummy TLS |
| Change impact | Changing identity model changes transport | Layers evolve independently |

**Decision:** B. Identity is an application/mesh concern, not a transport
concern. Keeping the handshake layer an identity-agnostic pipe means:
- Reality TCP and future QUIC transports share zero identity code.
- Transport tests don't need Ed25519 keys.
- The session layer (Layer 2) is the single point where identity binds
  to transport — all identity logic is in one package.

### 8.3 One HandshakeLayer Per Node (No Factory)

v1's `TransportFactory` managed per-peer Transport instances because
WireGuard needed separate handshake state per peer (different PSKs,
different endpoints, different role config). v2 eliminates this:

- One TCP listener on one port (443) — all peers connect to it.
- No per-peer handshake config — same Reality keys for all peers.
- No per-peer connection tracking at the transport layer — PeerManager tracks.
- Simpler shutdown: close one listener, not N transports.

The factory pattern was WireGuard's shape leaking into our abstraction.
v2's single-instance model is simpler and correct.
