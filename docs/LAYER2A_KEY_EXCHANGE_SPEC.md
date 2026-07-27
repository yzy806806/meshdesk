# MeshDesk v2 — Layer 2a (Session Key Exchange) Specification

**Status:** FROZEN (Key exchange layer of v2 protocol stack)
**Date:** 2026-07-28
**Author:** architect
**Motion:** motion-856c071ce5a9 (Agora discussion: MeshDesk v2 full rewrite)
**Task:** t_7c9f32da (Action item 7/10 from the motion)
**Depends on:** Layer 0 (Identity, FROZEN), Layer 1 (Handshake, FROZEN), Layer 2b (AES-256-GCM SecureConn, FROZEN)
**Freeze order:** Layer 0 → Layer 1 → Layer 2b → Layer 2a (this spec) → Layer 3 (smux)
**Downstream:** L2a implementation (developer), end-to-end integration testing (tester)

---

## Overview

Layer 2a is the **session key exchange** for MeshDesk v2. It performs an
authenticated X25519 Elliptic-Curve Diffie-Hellman (ECDH) exchange over a
Layer 1 `net.Conn`, binding each peer's Ed25519 identity to their ephemeral
key. The output is a pair of AES-256 keys (`sendKey`, `recvKey`) consumed
directly by Layer 2b's `NewSecureConn`.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Protocol Stack                                  │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 3         smux (stream multiplexing)                          │
│                 reads/writes over an encrypted net.Conn             │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 2b        SecureConn (AES-256-GCM)           [FROZEN]         │
│                 wraps net.Conn into encrypted net.Conn               │
│                 Wire: [len:2][nonce:12][ctext+tag]                  │
│                 Takes sendKey(32B) + recvKey(32B) as input          │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 2a        Session Key Exchange               ←─── THIS SPEC   │
│                 X25519 ECDH + Ed25519 identity binding              │
│                 Produces: sendKey, recvKey, peer identity           │
│                 Output type: crypto.SessionKeys                     │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 1         Handshake (Reality TLS over TCP)   [FROZEN]         │
│                 provides raw encrypted net.Conn                     │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 0         Identity (Ed25519)                 [FROZEN]         │
│                 used by Layer 2a to sign key exchange               │
└─────────────────────────────────────────────────────────────────────┘
```

**Why Layer 2a exists separately from 2b:**

L2a (key exchange) and L2b (encryption) are separate because they have
different lifetimes, testability profiles, and failure modes:

- **L2a runs once per session** — one 1-RTT exchange, then done. It uses
  asymmetric crypto (X25519 ECDH, Ed25519 signatures) and is the only
  layer that touches identity keys.
- **L2b runs on every byte** — the hotpath. It uses symmetric crypto
  (AES-256-GCM) and is testable with static 32-byte keys — no key
  exchange needed for unit tests.
- **Separation means independent testing:** L2b can be verified with
  `make([]byte, 32)` keys. L2a can be verified with `net.Pipe()` and
  two Ed25519 keypairs. Neither test needs the other.

**Existing code reused:**

- `internal/crypto/keys.go` already defines `DeriveSessionKeys(sharedSecret, role, identityBinding)`
  and the `SessionKeys` struct with `SendKey`, `RecvKey`, `Nonce` fields. **This
  function is an input to L2a, not a replacement.** L2a's job is to produce the
  `sharedSecret` and `identityBinding` that feed into it.
- `internal/identity/identity.go` provides `Sign(data)` and `Verify(pub, data, sig)`
  — the signing interface L2a calls.
- `golang.org/x/crypto/curve25519` is already in v1's `go.mod` (via
  `reality_transport.go`).

**What this spec defines (not yet implemented):**

Two functions that run the 1-RTT authenticated key exchange over a raw `net.Conn`:

```go
func ClientKeyExchange(conn net.Conn, id *identity.Identity) (*crypto.SessionKeys, string, error)
func ServerKeyExchange(conn net.Conn, id *identity.Identity) (*crypto.SessionKeys, string, error)
```

---

## 1. Interface

### 1.1 Package and Imports

```go
// Package session provides the Layer 2a session key exchange for MeshDesk v2.
//
// It performs an authenticated X25519 ECDH key exchange over a Layer 1
// net.Conn, binding each peer's Ed25519 identity to their ephemeral key
// via signatures. The output is a crypto.SessionKeys (sendKey + recvKey)
// suitable for creating a crypto.SecureConn (Layer 2b).
//
// Two functions cover both roles:
//   - ClientKeyExchange: called by the peer that initiated the L1 connection
//     (the one that called handshake.Connect). Sends first, role=initiator.
//   - ServerKeyExchange: called by the peer that accepted the L1 connection
//     (the one that called ln.Accept after handshake.Listen). Receives first,
//     role=responder.
//
// This package imports identity/ (for Ed25519 signing) and crypto/ (for
// SessionKeys + DeriveSessionKeys). It does NOT import handshake/ — only
// the caller knows the L1 transport.
//
// Dependencies: stdlib crypto/ed25519, crypto/rand, golang.org/x/crypto/curve25519
// (all already vendored in v1 go.sum).
package session

import (
    "crypto/ed25519"
    "crypto/rand"
    "errors"
    "fmt"
    "io"
    "net"
    "sync"
    "time"

    "golang.org/x/crypto/curve25519"

    "github.com/yzy806806/meshdesk/internal/crypto"
    "github.com/yzy806806/meshdesk/internal/identity"
)
```

### 1.2 Constructor Functions

```go
// ClientKeyExchange performs the initiator-side authenticated key exchange
// over the given net.Conn (typically from handshake.Connect).
//
// Protocol:
//   1. Generate X25519 ephemeral keypair + 32-byte random nonce.
//   2. Sign: ed25519.Sign(id.PrivateKey, domain || ephemeralPub || nonce)
//   3. Send msg1: [identityPub:32][ephPub:32][nonce:32][signature:64] = 160 bytes.
//   4. Read msg2: [peerIdentityPub:32][peerEphPub:32][peerSignature:64] = 128 bytes.
//   5. Verify peer signature over domain || ourEphPub || peerEphPub || nonce.
//   6. Compute sharedSecret = X25519(ourEphPriv, peerEphPub).
//   7. identityBinding = sha256(sig_i || sig_r)[:32] (SHA-256 of both signatures, symmetric).
//   8. Return DeriveSessionKeys(sharedSecret, role=true, identityBinding).
//
// Returns:
//   - *crypto.SessionKeys: sendKey, recvKey ready for NewSecureConn.
//   - string: the peer's Ed25519 public key (hex-encoded, 64 chars).
//     This is the verified identity of the remote node.
//   - error: if the exchange fails (signature verification, I/O, timeout).
//
// The conn is NOT closed on error — the caller decides whether to retry.
// After a successful exchange, the conn is still open and ready for
// Layer 2b (SecureConn) wrapping.
func ClientKeyExchange(conn net.Conn, id *identity.Identity) (*crypto.SessionKeys, string, error)

// ServerKeyExchange performs the responder-side authenticated key exchange
// over the given net.Conn (typically from handshake.Listen + Accept).
//
// Protocol:
//   1. Read msg1: [peerIdentityPub:32][peerEphPub:32][nonce:32][peerSignature:64] = 160 bytes.
//   2. Verify peer signature over domain || peerEphPub || nonce.
//   3. Generate X25519 ephemeral keypair.
//   4. Sign: ed25519.Sign(id.PrivateKey, domain || peerEphPub || ourEphPub || nonce).
//   5. Send msg2: [identityPub:32][ephPub:32][signature:64] = 128 bytes.
//   6. Compute sharedSecret = X25519(ourEphPriv, peerEphPub).
//   7. identityBinding = sha256(sig_i || sig_r)[:32] (SHA-256 of both signatures, symmetric).
//   8. Return DeriveSessionKeys(sharedSecret, role=false, identityBinding).
//
// Returns:
//   - *crypto.SessionKeys: sendKey, recvKey ready for NewSecureConn.
//   - string: the peer's Ed25519 public key (hex-encoded, 64 chars).
//     This is the verified identity of the remote node.
//   - error: if the exchange fails.
//
// The conn is NOT closed on error. After success, the conn is ready for
// SecureConn wrapping.
func ServerKeyExchange(conn net.Conn, id *identity.Identity) (*crypto.SessionKeys, string, error)
```

### 1.3 Compile-Time Interface Check

```go
// Verify that ClientKeyExchange and ServerKeyExchange are present and
// have the correct signatures. The compiler enforces this at the call site:
//
//   keys, peerID, err := session.ClientKeyExchange(conn, myIdentity)
//   keys, peerID, err := session.ServerKeyExchange(conn, myIdentity)
//
// There is no interface type to check against — these are plain functions.
// Correctness is verified by the acceptance criteria below.
```

### 1.4 Error Sentinels

```go
var (
    // ErrIdentityMismatch is returned when the peer's signature verifies
    // but the claimed identity does not match the expected peer.
    // The exchange is valid but the peer is not who we expected.
    ErrIdentityMismatch = errors.New("session: peer identity does not match expected")

    // ErrSignatureInvalid is returned when the peer's Ed25519 signature
    // fails verification. The connection should be dropped — the peer
    // cannot prove ownership of the claimed identity.
    ErrSignatureInvalid = errors.New("session: Ed25519 signature verification failed")

    // ErrKeyExchangeTimeout is returned when the exchange does not
    // complete within the configured deadline.
    ErrKeyExchangeTimeout = errors.New("session: key exchange timed out")

    // ErrProtocolViolation is returned when the peer sends a message
    // that doesn't conform to the wire format (wrong length, etc.).
    ErrProtocolViolation = errors.New("session: protocol violation in key exchange")
)
```

---

## 2. Protocol Flow

### 2.1 Message Sequence (1-RTT Mutual Auth)

```
INITIATOR (Connect caller)                     RESPONDER (Accept acceptor)
        │                                              │
        │  ┌─ Generate X25519 ephemeral (priv, pub)    │
        │  │  Generate 32-byte random nonce            │
        │  │  sig_i = Sign(id_i, domain_i || pub_i     │
        │  │          || nonce)                        │
        │  └─ msg1 = [id_pub_i:32][pub_i:32]           │
        │             [nonce:32][sig_i:64]             │
        │                                              │
        │  160 bytes ──────────────────────────────►   │
        │                                              │
        │                              ┌─ Verify sig_i │
        │                              │  Generate X25519 ephemeral (priv_r, pub_r)
        │                              │  sig_r = Sign(id_r, domain_r || pub_i
        │                              │          || pub_r || nonce)
        │                              └─ msg2 = [id_pub_r:32][pub_r:32]
        │                                         [sig_r:64]
        │                                              │
        │  ◄────────────────────────────── 128 bytes   │
        │                                              │
        │  ┌─ Verify sig_r                             │
        │  │  sharedSecret = X25519(priv_i, pub_r)     │
        │  │  binding = sha256(sig_i || sig_r)[:32]             │
        │  └─ keys = DeriveSessionKeys(secret,         │
        │              role=true, binding)              │
        │                                              │
        │  === SECURE CHANNEL ESTABLISHED ===           │
        │                                              │
        │                              ┌─ sharedSecret = X25519(priv_r, pub_i)
        │                              │  binding = sha256(sig_i || sig_r)[:32]
        │                              └─ keys = DeriveSessionKeys(secret,
        │                                       role=false, binding)
        │                                              │
        │                   === BOTH SIDES HAVE KEYS ===│
```

### 2.2 Domain Separation Strings

To prevent cross-protocol signature replay, each signature includes a
domain separation prefix that differs by role:

```go
const (
    // domainInitiator is the signing domain for the initiator's signature.
    // Signed over: domainInitiator || ephemeralPub || nonce
    domainInitiator = "meshdesk-v2-kx-initiator"

    // domainResponder is the signing domain for the responder's signature.
    // Signed over: domainResponder || peerEphemeralPub || ourEphemeralPub || nonce
    domainResponder = "meshdesk-v2-kx-responder"
)
```

**Why different domains:** If both sides used the same domain string,
the initiator's signature could be replayed as a responder's signature
in a different context. Different domains prevent this.

**Signing payload construction:**

```go
// Initiator signs:
payload := append([]byte(domainInitiator), ephemeralPub...)
payload = append(payload, nonce...)
sig, err := id.Sign(payload)

// Responder signs:
payload := append([]byte(domainResponder), peerEphPub...)
payload = append(payload, ourEphPub...)
payload = append(payload, nonce...)
sig, err := id.Sign(payload)
```

### 2.3 Role Determination

The **role** is determined by who initiated the Layer 1 connection:

| Peer | L1 call | L2a role | `role` bool to DeriveSessionKeys |
|------|---------|----------|----------------------------------|
| Initiator | `handshake.Connect(ctx, addr)` | ClientKeyExchange | `true` |
| Responder | `handshake.Listen + Accept` | ServerKeyExchange | `false` |

The role maps directly to `DeriveSessionKeys(sharedSecret, role, identityBinding)`.

**What `role` controls:** In `DeriveSessionKeys` (already implemented in
`internal/crypto/keys.go`), both peers derive `key1` and `key2` from the
same HKDF stream. The role determines which key is assigned to send vs. recv:

```
Initiator (role=true):   SendKey = key1,  RecvKey = key2
Responder (role=false):  SendKey = key2,  RecvKey = key1
```

This ensures `initiator.SendKey == responder.RecvKey` without requiring
the peers to negotiate which key is which.

---

## 3. Wire Format

### 3.1 Message 1 (Initiator → Responder): 160 bytes

```
Byte  0       31 32      63 64      95 96              159
┌───────────────┬──────────┬──────────┬───────────────────┐
│ identity_pub  │ eph_pub  │  nonce   │    signature      │
│   32 bytes    │ 32 bytes │ 32 bytes │    64 bytes       │
│  Ed25519 pub  │ X25519   │ random   │  Ed25519 sig      │
└───────────────┴──────────┴──────────┴───────────────────┘
```

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| `identity_pub` | 32 bytes | raw Ed25519 public key | The initiator's permanent identity. Used by the responder to verify the signature. |
| `eph_pub` | 32 bytes | raw X25519 public key | The initiator's ephemeral DH public key. Used in the ECDH computation. |
| `nonce` | 32 bytes | random bytes from `crypto/rand` | Single-use random value for replay prevention. |
| `signature` | 64 bytes | raw Ed25519 signature | `Sign(identity, domainInitiator \|\| eph_pub \|\| nonce)` |

**Total: 160 bytes.** No length prefix — `io.ReadFull(conn, buf[:160])` reads the entire
message. The fixed size eliminates framing overhead and parsing ambiguity.

### 3.2 Message 2 (Responder → Initiator): 128 bytes

```
Byte  0       31 32      63 64              127
┌───────────────┬──────────┬───────────────────┐
│ identity_pub  │ eph_pub  │    signature      │
│   32 bytes    │ 32 bytes │    64 bytes       │
│  Ed25519 pub  │ X25519   │  Ed25519 sig      │
└───────────────┴──────────┴───────────────────┘
```

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| `identity_pub` | 32 bytes | raw Ed25519 public key | The responder's permanent identity. |
| `eph_pub` | 32 bytes | raw X25519 public key | The responder's ephemeral DH public key. |
| `signature` | 64 bytes | raw Ed25519 signature | `Sign(identity, domainResponder \|\| initiator_eph_pub \|\| responder_eph_pub \|\| nonce)` |

**Total: 128 bytes.** Fixed size — no length prefix. The nonce is NOT included in msg2
because the initiator already generated it in msg1 and the responder echoes it
implicitly by including it in its signature payload.

### 3.3 Why Fixed-Size Messages

| Approach | Pros | Cons |
|----------|------|------|
| Fixed-size (this spec) | Zero framing overhead. Single `io.ReadFull` call. No ambiguity about message boundaries. Trivially testable. | Expands if fields ever change (unlikely — key sizes are standardized). |
| Length-prefixed (TLS-style) | Extensible. Can add optional fields. | Framing code. Variable-length parsing. Duplicates work already done by L2b framing. |

**Decision:** Fixed-size. The key exchange message format is simple and
unlikely to change. Ed25519 and X25519 key sizes are standardized. If
future versions need additional fields, they can define a new message
format with a version byte — no need for preemptive extensibility.

---

## 4. Replay Attack Prevention

### 4.1 Threat Model

An attacker on the same L1 transport path (i.e., between the two mesh
nodes after the Reality TLS handshake) could:

1. **Record msg1** from a legitimate initiator.
2. **Replay msg1** to a responder.
3. The responder verifies the signature (valid), generates a new ephemeral,
   and sends msg2.
4. The attacker cannot decrypt msg2 (they don't know the initiator's private key),
   but they've forced the responder to do work and may cause key confusion.

**Why this is low-risk in practice:** The L1 Reality TLS channel already
provides encryption and authentication between the two endpoints. An
attacker who can inject packets into a TCP stream between two TLS
endpoints has already broken TLS — at that point, they can do far worse
than replay a key exchange message.

**Defense-in-depth nonetheless:** The nonce provides replay protection
as a second layer.

### 4.2 Nonce-Based Replay Protection

The initiator generates a **32-byte cryptographically random nonce**
(`crypto/rand.Read(nonce)`). The responder maintains a bounded cache
of recently seen nonces.

```go
// MaxNonceCache is the maximum number of recent nonces tracked per
// responder. When the cache is full, the oldest entry is evicted.
// At ~10 key exchanges per second, 1024 entries cover ~100 seconds
// of history — far longer than any realistic replay window.
const MaxNonceCache = 1024

// nonceCache is a thread-safe bounded set of recently seen nonces.
type nonceCache struct {
    mu    sync.Mutex
    seen  map[[32]byte]int64 // nonce → unix timestamp
    order []nonceEntry       // FIFO eviction queue
}

// checkAndRecord returns true if the nonce has NOT been seen before
// (and records it). Returns false if the nonce is a replay.
func (c *nonceCache) checkAndRecord(nonce [32]byte) bool
```

**Cache semantics:**
- If the nonce is already in the cache → **replay detected**, return `ErrProtocolViolation`.
- If not in the cache → record it with current timestamp, return OK.
- Cache eviction is FIFO: when full, remove the oldest entry before inserting.

**Why 32-byte random nonce, not timestamp or counter:**
- Timestamps require clock synchronization between peers (fragile in mesh networks).
- Counters require state per peer (the responder would need to track separate counters
  for every initiator).
- 32-byte random nonce has negligible collision probability (~2^-256) and requires
  no per-peer state beyond the shared cache.

### 4.3 Defense via Signature Binding

Even if the nonce cache is bypassed (e.g., cache eviction due to high load),
the responder's signature includes the initiator's ephemeral public key
**and** the nonce. This cryptographically binds the responder's response
to the specific initiator's key exchange:

```
sig_r = Sign(id_r, domainResponder || initiator_eph_pub || responder_eph_pub || nonce)
```

A replayed msg1 would produce a different `responder_eph_pub` each time,
making each msg2 unique. The responder's signature is effectively a
challenge-response — the initiator can verify that the responder
acknowledged its specific nonce.

---

## 5. Key Derivation

### 5.1 How L2a Feeds DeriveSessionKeys

`DeriveSessionKeys` (already implemented, frozen) has this signature:

```go
func DeriveSessionKeys(sharedSecret []byte, role bool, identityBinding []byte) *SessionKeys
```

L2a produces its three arguments as follows:

| Parameter | Source | Notes |
|-----------|--------|-------|
| `sharedSecret` | `curve25519.ScalarMult(ourEphPriv, peerEphPub)` | 32-byte X25519 ECDH output. Both peers compute the same value (DH symmetry). |
| `role` | `true` for ClientKeyExchange, `false` for ServerKeyExchange | Determined by L1 connection direction (see §2.3). |
| `identityBinding` | `sha256(sig_i || sig_r)[:32]` (SHA-256 of both signatures) | Binds session keys to BOTH identities symmetrically. Both peers compute the same value, ensuring complementarity. |

### 5.2 Why SHA-256 of Both Signatures as identityBinding

The `identityBinding` parameter is included in the HKDF `info` string
(see `internal/crypto/keys.go`):

```go
info := []byte("meshdesk-v2-session")
if len(identityBinding) >= 8 {
    info = append(info, identityBinding[:8]...)
}
```

Using `sha256(sig_i || sig_r)[:32]` — the SHA-256 hash of both peers'
Ed25519 signatures concatenated — means:

- **Both peers compute the IDENTICAL identityBinding value.** DeriveSessionKeys
  uses `identityBinding[:8]` in the HKDF info string (keys.go:42). If the
  initiator and responder pass different identityBinding values, they derive
  different `key1`/`key2` from HKDF, which means `initiator.SendKey ≠
  responder.RecvKey` — the SecureConn CANNOT decrypt. Symmetric binding is
  REQUIRED for complementarity.
- **Binds keys to BOTH identities.** Including both signatures in the hash
  means the session keys are cryptographically bound to the verified identity
  of both peers. An attacker who compromises one identity cannot derive the
  same session keys without the other's signature.
- **No extra round-trip.** Both signatures are already exchanged during the
  1-RTT protocol (sig_i in msg1, sig_r in msg2). The SHA-256 hash is computed
  locally after both are received.
- **Deterministic.** Ed25519 signatures are deterministic for the same
  key+message, so both peers always arrive at the same hash value.

### 5.3 Derivation Diagram

```
Initiator:                              Responder:
  eph_priv_i, eph_pub_i                   eph_priv_r, eph_pub_r
  │                                       │
  │  X25519(eph_priv_i, eph_pub_r)        │  X25519(eph_priv_r, eph_pub_i)
  │       │                               │       │
  │       ▼                               │       ▼
  │  sharedSecret (32 bytes)              │  sharedSecret (32 bytes)
  │       │                               │       │
  │       │  sha256(sig_i || sig_r)[:32]   │       │  sha256(sig_i || sig_r)[:32]
  │       │       │                       │       │       │
  │       ▼       ▼                       │       ▼       ▼
  │  DeriveSessionKeys(                   │  DeriveSessionKeys(
  │    sharedSecret,                      │    sharedSecret,
  │    role=true,              ──both──▶  │    role=false,
  │    identityBinding=                   │    identityBinding=
  │    sha256(sig_i || sig_r)[:32])       │    sha256(sig_i || sig_r)[:32])
  │       │                               │       │
  │       ▼                               │       ▼
  │  SessionKeys{                         │  SessionKeys{
  │    SendKey: key1,  ──────same──────▶  │    RecvKey: key1,
  │    RecvKey: key2,  ◀─────same──────   │    SendKey: key2,
  │  }                                    │  }
```

---

## 6. Integration Points

### 6.1 With Layer 1 (Handshake)

```go
// ── Initiator (entry node) ───────────────────────────────────────────

import (
    "github.com/yzy806806/meshdesk/internal/handshake"
    "github.com/yzy806806/meshdesk/internal/session"   // L2a
    "github.com/yzy806806/meshdesk/internal/crypto"    // L2b
    "github.com/yzy806806/meshdesk/internal/identity"  // L0
)

// 1. Establish encrypted channel (L1)
hs := handshake.NewRealityHandshake(cfg)
conn, err := hs.Connect(ctx, "exit.example.com:443")  // → net.Conn

// 2. Authenticated key exchange (L2a — THIS SPEC)
myID, _ := identity.IdentityFromHex(config.IdentityPrivateKey)
keys, peerID, err := session.ClientKeyExchange(conn, myID)
// keys.SendKey, keys.RecvKey are [32]byte
// peerID is the exit node's Ed25519 public key hex

// 3. Encrypt the channel (L2b)
sec, err := crypto.NewSecureConn(conn, keys.SendKey[:], keys.RecvKey[:])
// → encrypted net.Conn ready for smux


// ── Responder (exit node) ───────────────────────────────────────────

hs := handshake.NewRealityHandshake(cfg)
ln, _ := hs.Listen(ctx, "0.0.0.0:443")
conn, _ := ln.Accept()                                   // → net.Conn

myID, _ := identity.IdentityFromHex(config.IdentityPrivateKey)
keys, peerID, err := session.ServerKeyExchange(conn, myID)

sec, err := crypto.NewSecureConn(conn, keys.SendKey[:], keys.RecvKey[:])
// → encrypted net.Conn ready for smux
```

### 6.2 With Layer 2b (SecureConn)

The contract:
1. L2a produces `*crypto.SessionKeys` — exactly the type `NewSecureConn` accepts.
2. After a successful exchange, the caller wraps the same `net.Conn` with `NewSecureConn`.
3. The `net.Conn` is owned by the caller — L2a only reads/writes the key exchange
   messages, then returns. Subsequent reads/writes go through SecureConn.
4. If the key exchange fails, the conn is NOT closed — the caller decides whether
   to retry or close.

### 6.3 With PeerManager

```go
// PeerManager calls ClientKeyExchange with its own identity:
keys, peerID, err := session.ClientKeyExchange(conn, pm.identity)

// peerID is the verified Ed25519 public key of the remote peer.
// PeerManager uses this to:
//   - Look up the peer in its routing table
//   - Verify the peer matches the expected exit node
//   - Store the session keys for key rotation timing

if peerID != expectedExitID {
    conn.Close()
    return fmt.Errorf("%w: expected %s, got %s",
        session.ErrIdentityMismatch, expectedExitID, peerID)
}
```

### 6.4 With Config / Key Rotation

```go
// KeyExchangeConfig configures the L2a key exchange behavior.
type KeyExchangeConfig struct {
    // Timeout is the maximum time for the full 1-RTT exchange.
    // Default: 10s (matches L1 DialTimeout and L2b HandshakeTimeout).
    Timeout time.Duration

    // NonceCacheSize is the number of recent nonces retained for replay
    // detection. 0 = default (MaxNonceCache = 1024).
    NonceCacheSize int
}

func DefaultKeyExchangeConfig() KeyExchangeConfig {
    return KeyExchangeConfig{
        Timeout:        10 * time.Second,
        NonceCacheSize: MaxNonceCache,
    }
}
```

**Key rotation:** The session keys produced by L2a are valid for the lifetime
of the session. To rotate keys, open a new L1 connection and run a new L2a
exchange — this is handled by PeerManager, not by L2a itself.

---

## 7. Package Layout

```
meshdesk/
├── internal/
│   ├── identity/                 ← Layer 0 (FROZEN)
│   │   ├── identity.go           ← Identity, Sign, Verify
│   │   └── identity_test.go
│   ├── handshake/                ← Layer 1 (FROZEN)
│   │   ├── handshake.go          ← HandshakeLayer interface
│   │   └── reality.go            ← Reality TLS implementation
│   ├── crypto/                   ← Layer 2b (FROZEN)
│   │   ├── secure_conn.go        ← SecureConn (AES-256-GCM)
│   │   ├── keys.go               ← SessionKeys, DeriveSessionKeys
│   │   ├── aead.go               ← newAESGCM helper
│   │   └── secure_conn_test.go
│   ├── session/                  ← Layer 2a (NEW — THIS SPEC)
│   │   ├── key_exchange.go       ← ClientKeyExchange, ServerKeyExchange
│   │   ├── nonce.go              ← nonceCache (replay prevention)
│   │   ├── errors.go             ← Sentinel errors
│   │   └── key_exchange_test.go  ← Unit tests
│   └── smux/                     ← Layer 3 (FROZEN)
│       └── ...
```

**Dependency arrows:**

```
session/ → identity/  (Sign, Verify — Ed25519 identity binding)
session/ → crypto/    (SessionKeys, DeriveSessionKeys — key output type)
session/ → golang.org/x/crypto/curve25519  (X25519 ECDH — already vendored)
session/ → stdlib crypto/ed25519, crypto/rand, io, net, sync, time

session/ does NOT import:
  ✗ handshake/   (transport-agnostic — only uses net.Conn)
  ✗ smux/        (below L2a in the stack)
  ✗ multipath/   (below L2a)
```

**Compile-time verification:**

```bash
# session/ must not import handshake/
grep -r '"meshdesk/internal/handshake"' internal/session/
# → no results

# session/ must not add new external dependencies
go list -deps ./internal/session/ | grep -v "^\(internal\|errors\|fmt\|crypto\|encoding\|io\|strings\|sync\|time\|runtime\|unicode\|reflect\|net\|golang.org/x/crypto\)"
# → only stdlib + golang.org/x/crypto (already in v1 go.sum)
```

---

## 8. v1 Code Impact

### 8.1 No Direct v1 Equivalent

v1 had no dedicated session key exchange layer. Session keys were either:

- **WireGuard Noise IK:** the kernel-level WireGuard handshake performed
  key exchange. Removed in Phase 1 (WireGuard excision).
- **Reality TLS:** the TLS 1.3 handshake produces session keys, but those
  are transport-layer keys — not mesh session keys. The L2a exchange runs
  INSIDE the encrypted TLS channel.

The L2a key exchange is entirely new in v2. It provides mesh-level identity
binding that v1 never had.

### 8.2 Dependencies

```
golang.org/x/crypto/curve25519  ← already in v1 go.sum (reality_transport.go imports it)
golang.org/x/crypto/hkdf        ← already in v1 go.sum (used by DeriveSessionKeys)
crypto/ed25519                   ← stdlib (zero new deps)
crypto/rand                      ← stdlib
```

**Zero new external dependencies.** All crypto primitives are already
vendored or in the Go standard library.

### 8.3 New Files

| File | Lines (est.) | Purpose |
|------|-------------|---------|
| `internal/session/key_exchange.go` | ~200 | ClientKeyExchange, ServerKeyExchange, domain constants, wire format read/write |
| `internal/session/nonce.go` | ~60 | Nonce cache with FIFO eviction |
| `internal/session/errors.go` | ~25 | Error sentinels |
| `internal/session/key_exchange_test.go` | ~250 | Unit + integration tests |

**Total: ~535 lines** — small, focused, testable.

---

## 9. Acceptance Criteria

All ACs are written as testable assertions. The developer must verify each
one independently.

### Core — Key Exchange Correctness

**AC-2a.1: ClientKeyExchange + ServerKeyExchange complete successfully over net.Pipe.**

```go
clientConn, serverConn := net.Pipe()

clientID, _ := identity.GenerateIdentity()
serverID, _ := identity.GenerateIdentity()

// Run concurrently (as in real usage)
var clientKeys *crypto.SessionKeys
var serverKeys *crypto.SessionKeys
var clientPeer, serverPeer string
var clientErr, serverErr error

var wg sync.WaitGroup
wg.Add(2)
go func() {
    defer wg.Done()
    clientKeys, clientPeer, clientErr = session.ClientKeyExchange(clientConn, clientID)
}()
go func() {
    defer wg.Done()
    serverKeys, serverPeer, serverErr = session.ServerKeyExchange(serverConn, serverID)
}()
wg.Wait()

// Both sides succeed
// clientErr == nil, serverErr == nil
// clientPeer == serverID.PublicKey
// serverPeer == clientID.PublicKey
```

**AC-2a.2: Derived keys are complementary — initiator SendKey == responder RecvKey.**

```go
// clientKeys.SendKey == serverKeys.RecvKey
// clientKeys.RecvKey == serverKeys.SendKey
```

**AC-2a.3: Data flows correctly through SecureConn after key exchange.**

```go
clientConn, serverConn := net.Pipe()
clientID, _ := identity.GenerateIdentity()
serverID, _ := identity.GenerateIdentity()

var wg sync.WaitGroup
wg.Add(2)

var clientKeys *crypto.SessionKeys
var serverKeys *crypto.SessionKeys

go func() {
    defer wg.Done()
    clientKeys, _, _ = session.ClientKeyExchange(clientConn, clientID)
}()
go func() {
    defer wg.Done()
    serverKeys, _, _ = session.ServerKeyExchange(serverConn, serverID)
}()
wg.Wait()

// Wrap in SecureConn
clientSec, _ := crypto.NewSecureConn(clientConn, clientKeys.SendKey[:], clientKeys.RecvKey[:])
serverSec, _ := crypto.NewSecureConn(serverConn, serverKeys.SendKey[:], serverKeys.RecvKey[:])

// Round-trip
go clientSec.Write([]byte("hello mesh"))
buf := make([]byte, crypto.MaxMessageSize)
n, _ := serverSec.Read(buf)
// n == 10, string(buf[:n]) == "hello mesh"

go serverSec.Write([]byte("hello back"))
n2, _ := clientSec.Read(buf)
// n2 == 10, string(buf[:n2]) == "hello back"
```

### Signature Verification

**AC-2a.4: Invalid initiator signature → ServerKeyExchange returns ErrSignatureInvalid.**

```go
// Set up conn, generate real clientID and serverID
// BUT tamper with the signature bytes in msg1 before the server reads it.
// Use a middleware reader that replaces the last 64 bytes with zeros.

clientConn, serverConn := net.Pipe()
clientID, _ := identity.GenerateIdentity()
serverID, _ := identity.GenerateIdentity()

go func() {
    // Client sends real msg1
    session.ClientKeyExchange(clientConn, clientID)
}()

// Read raw bytes, tamper, pass to ServerKeyExchange via a pipe
raw := make([]byte, 160)
io.ReadFull(serverConn, raw)
// Tamper: zero out the last 64 bytes (signature)
for i := 96; i < 160; i++ {
    raw[i] = 0
}

tamperedReader, tamperedWriter := net.Pipe()
go func() {
    tamperedWriter.Write(raw)
    // Also need to forward server's msg2 back to client — for simplicity,
    // just verify the error on read
}()

_, _, err := session.ServerKeyExchange(tamperedReader, serverID)
// errors.Is(err, session.ErrSignatureInvalid) is true
```

**AC-2a.5: Invalid responder signature → ClientKeyExchange returns ErrSignatureInvalid.**

```go
// Same pattern: server sends tampered signature in msg2.
// ClientKeyExchange detects it.

clientConn, serverConn := net.Pipe()
clientID, _ := identity.GenerateIdentity()
serverID, _ := identity.GenerateIdentity()

go func() {
    // Tampered server: read msg1 (160 bytes), then send msg2 with invalid sig
    raw := make([]byte, 160)
    io.ReadFull(serverConn, raw)
    // Reply with tampered signature
    msg2 := make([]byte, 128)
    // Fill with real data except signature which is zeroed
    // ... implementation detail
    serverConn.Write(msg2)
}()

_, _, err := session.ClientKeyExchange(clientConn, clientID)
// errors.Is(err, session.ErrSignatureInvalid) is true
```

### Replay Protection

**AC-2a.6: Replayed nonce detected on second exchange.**

```go
// Record a complete key exchange, then replay msg1 with the same nonce.
// The responder's nonce cache should detect the replay and return
// ErrProtocolViolation.

clientConn1, serverConn1 := net.Pipe()
clientID, _ := identity.GenerateIdentity()
serverID, _ := identity.GenerateIdentity()

// First exchange (normal)
var wg sync.WaitGroup
wg.Add(2)
go func() {
    defer wg.Done()
    session.ClientKeyExchange(clientConn1, clientID)
}()
go func() {
    defer wg.Done()
    session.ServerKeyExchange(serverConn1, serverID)
}()
wg.Wait()

// Second exchange with replayed msg1
clientConn2, serverConn2 := net.Pipe()

// Capture msg1 from client
var capturedMsg1 [160]byte
// ... capture bytes from clientConn2

go func() {
    session.ClientKeyExchange(clientConn2, clientID)
}()

io.ReadFull(serverConn2, capturedMsg1[:])

// Create a fresh connection and replay msg1
replayConn, replyConn := net.Pipe()
go func() {
    replyConn.Write(capturedMsg1[:])
}()

_, _, err := session.ServerKeyExchange(replayConn, serverID)
// err should indicate replay detection (ErrProtocolViolation)
```

### Error Handling

**AC-2a.7: Timeout returns ErrKeyExchangeTimeout.**

```go
clientConn, serverConn := net.Pipe()
clientID, _ := identity.GenerateIdentity()

// Server never responds
serverConn.Close()

// ClientKeyExchange should time out (uses conn's deadline)
clientConn.SetDeadline(time.Now().Add(100 * time.Millisecond))
_, _, err := session.ClientKeyExchange(clientConn, clientID)
// errors.Is(err, session.ErrKeyExchangeTimeout) or err is os.ErrDeadlineExceeded
```

**AC-2a.8: Protocol violation — wrong message size → ErrProtocolViolation.**

```go
// Server sends 100 bytes instead of 128 in msg2.
// ClientKeyExchange should detect and return ErrProtocolViolation.
```

### Integration

**AC-2a.9: session/ does not import handshake/.**

```bash
grep -r '"meshdesk/internal/handshake"' internal/session/
# → no results
```

**AC-2a.10: Zero new external dependencies.**

```bash
go list -deps ./internal/session/ | grep -v "^\(internal\|errors\|fmt\|crypto\|encoding\|io\|strings\|sync\|time\|runtime\|unicode\|reflect\|net\|golang.org/x/crypto\)"
# → only stdlib + golang.org/x/crypto (already in v1 go.sum)
```

**AC-2a.11: session/ imports identity/ and crypto/ correctly.**

```bash
grep -r '"meshdesk/internal/identity"' internal/session/
# → found in key_exchange.go (correct — needs Sign/Verify)

grep -r '"meshdesk/internal/crypto"' internal/session/
# → found in key_exchange.go (correct — needs SessionKeys)
```

### Concurrency

**AC-2a.12: Race detector clean — 100 concurrent exchanges.**

```bash
go test -race -count=1 -run TestConcurrentExchanges ./internal/session/
# → PASS, no race warnings
```

**AC-2a.13: Nonce cache is thread-safe under concurrent ServerKeyExchange calls.**

```bash
go test -race -count=1 -run TestNonceCache ./internal/session/
# → PASS, no race warnings
```

### Interop

**AC-2a.14: Key exchange with real Ed25519 keys (not test vectors).**

```go
// GenerateIdentity() uses crypto/rand → real keys.
// Verify that ClientKeyExchange + ServerKeyExchange complete successfully
// with real generated keys (i.e., not hardcoded test vectors).
```

---

## 10. Downstream Tasks

After this spec is approved and frozen:

| # | Task | Assignee | Depends on |
|---|------|----------|------------|
| 1 | Implement `internal/session/key_exchange.go` (~200L) | developer | This spec + L0/L1 FROZEN |
| 2 | Implement `internal/session/nonce.go` (~60L) | developer | This spec |
| 3 | Write `internal/session/key_exchange_test.go` (~250L) | developer | This spec |
| 4 | Smoke-test L1→L2a→L2b integration | tester | This spec + developer (completed) |
| 5 | Freeze/implement Layer 4 (MultiPathSession) | architect | This spec + L3 (smux) |
| 6 | PeerManager integration — connect to specific peer by Ed25519 identity | developer | This spec |

---

## 11. Trade-offs and Rationale

### 11.1 1-RTT vs 0-RTT vs 2-RTT

| Aspect | 1-RTT (chosen) | 0-RTT (QUIC-style) | 2-RTT (TLS 1.3 mutual auth) |
|--------|---------------|-------------------|---------------------------|
| Round trips | 1 | 0 (resumption) / 1 (first contact) | 2 |
| Mutual auth | Yes (both sign) | Yes (pre-shared) | Yes (full cert chain) |
| Forward secrecy | Yes (ephemeral ECDH) | Yes (with ephemeral) | Yes |
| Complexity | Minimal: 2 fixed-size messages | Session ticket infrastructure | Certificate verification infrastructure |
| Replay protection | Nonce cache (this spec) | 0-RTT anti-replay tokens | TLS anti-replay |

**Decision:** 1-RTT. MeshDesk sessions are long-lived (minutes to hours) —
the cost of one extra round-trip at session start is negligible compared
to the session duration. 0-RTT would require session ticket infrastructure
that's overkill for a mesh protocol. 2-RTT mutual auth is excessive given
that L1 already provides encrypted transport.

Both peers are authenticated in one round-trip because the initiator
includes its identity and signature in msg1, and the responder includes
its identity and signature in msg2. No extra round-trip for auth.

### 11.2 Fixed-Size vs Length-Prefixed Messages

| Aspect | Fixed-size (chosen) | Length-prefixed |
|--------|-------------------|-----------------|
| Implementation | `io.ReadFull(conn, buf[:160])` — one line | 2-byte length prefix + variable read |
| Extensibility | Add version byte for future formats | Add new fields with new lengths |
| Error detection | Short read = `io.ErrUnexpectedEOF` | Short read on length or payload |
| Wire overhead | 0 bytes | 2 bytes per message |

**Decision:** Fixed-size. The key exchange format is simple and unlikely
to change. Ed25519 and X25519 key sizes are standardized. Future extensions
can define a new message format with a version byte — no need for
variable-length overhead today.

### 11.3 Nonce Cache vs Timestamps vs Sequence Numbers

| Aspect | Nonce cache (chosen) | Timestamps | Per-peer sequence numbers |
|--------|---------------------|------------|--------------------------|
| State required | Bounded cache per responder | Clock sync | Per-peer counter map |
| Clock dependency | None | Requires synchronized clocks | None |
| Replay window | Cache eviction (configurable) | Clock skew tolerance | Infinite (persistent state needed) |
| Memory | ~32KB for 1024 entries | 0 bytes | O(num_peers) bytes |
| Implementation | map + FIFO queue (~60 lines) | time.Since() check | per-peer map with atomic counters |

**Decision:** Nonce cache. It's simple, self-contained, requires no clock
synchronization, and has bounded memory. The cache is per-responder, not
per-peer, so it scales to any number of initiators without extra state.

At the default cache size of 1024 entries and with sessions lasting
minutes to hours, replay windows are effectively impossible to exploit:
an attacker would need to replay within the time it takes for 1024 other
legitimate exchanges to occur — which, at typical mesh connection rates,
is measured in hours.

### 11.4 Session Package Placement (internal/session/ vs internal/crypto/)

| Aspect | internal/session/ (chosen) | internal/crypto/ |
|--------|---------------------------|-----------------|
| Identity dependency | Imports identity/ (ok — needs Sign/Verify) | Would add identity/ to crypto/ (violates L2b AC-L2.I1) |
| Crypto dependency | Imports crypto/ (ok — needs SessionKeys) | Already in crypto/ (no import needed) |
| Test isolation | Can be tested independently of crypto | Coupled to crypto tests |
| Conceptual fit | Session layer — orchestrates identity + crypto | Crypto layer — pure crypto, no identity |

**Decision:** `internal/session/`. The key exchange is an orchestration
layer — it calls identity.Sign/Verify and crypto.DeriveSessionKeys but
doesn't implement either. Placing it in a separate package keeps the
crypto package identity-agnostic (per AC-L2.I1) and the session package
focused on the exchange protocol.

### 11.5 Ed25519 Signature Over What

Three signing payload designs considered:

**A) Sign only the ephemeral public key (v1-style):**
```
Sig_i = Sign(id_i, eph_pub_i)
```
Pro: Simplest. Con: No replay protection. No binding to peer.

**B) Sign ephemeral + nonce (this spec for initiator):**
```
Sig_i = Sign(id_i, domain_i || eph_pub_i || nonce)
Sig_r = Sign(id_r, domain_r || eph_pub_i || eph_pub_r || nonce)
```
Pro: Replay protection via nonce. Responder binds to initiator's ephemeral.
Con: Requires nonce cache.

**C) Sign both ephemerals (mutual binding):**
```
Sig_i = Sign(id_i, eph_pub_i || eph_pub_r)
Sig_r = Sign(id_r, eph_pub_i || eph_pub_r)
```
Pro: Both sides bind to both ephemerals. Con: Initiator doesn't know
responder's ephemeral before signing — requires 1.5-RTT.

**Decision:** B (this spec). The initiator includes a nonce in msg1 and
signs (domain || eph_pub || nonce). The responder echoes the nonce by
including it in its signing payload (domain || init_eph || resp_eph || nonce).
This gives:

1. **Replay protection**: fresh nonce each exchange, verified by nonce cache.
2. **Initiator auth**: signature binds initiator's identity to their ephemeral.
3. **Responder auth**: signature binds responder's identity to BOTH ephemerals
   — proving they saw the initiator's specific key exchange.
4. **1-RTT**: no extra round-trip.

### 11.6 identityBinding = sha256(sig_i || sig_r)[:32] (Symmetric)

#### Why Symmetric? The Complementarity Requirement

DeriveSessionKeys (keys.go:42) uses `identityBinding[:8]` in the HKDF info
string. HKDF(info=...) produces different output for different info values.
Therefore: **different identityBinding → different key1/key2 → SendKey/RecvKey
mismatch → SecureConn cannot decrypt.**

The fix is simple: both peers MUST pass the SAME identityBinding value. Using
`sha256(sig_i || sig_r)[:32]` — the SHA-256 hash of both signatures
concatenated — guarantees both peers compute an identical value. The
concatenation order is fixed: initiator signature first, responder second
(both sides know this order by the end of the exchange).

#### Trade-off Table

| Aspect | sha256(sig_i || sig_r)[:32] (new) | Previous: peerSignature[:32] |
|--------|-----------------------------------|------------------------------|
| Complementarity | YES — both peers compute same value | NO — initiator uses sig_r[:32], responder uses sig_i[:32], different HKDF info = broken keys |
| Identity binding | Binds to BOTH identities | Binds to only ONE identity (the peer) |
| Collision resistance | 256-bit (hash output) | 128-bit (truncation) |
| HKDF info size | 8 bytes (only first 8 used in keys.go) | 8 bytes |
| Extra computation | One SHA-256 hash per peer (negligible) | Zero |
| Deterministic | Yes (Ed25519 is deterministic) | Yes |

**Decision:** `sha256(sig_i || sig_r)[:32]`. The symmetric design is NOT
optional — it is required for correct operation. The original asymmetric
approach (initiator uses sig_r[:32], responder uses sig_i[:32]) was an
architectural bug discovered during implementation review. Both peers
must derive identical HKDF info strings for DeriveSessionKeys to produce
complementary SendKey/RecvKey pairs. The SHA-256 cost is negligible (~1µs)
compared to the ECDH and Ed25519 operations already in the exchange.

---
