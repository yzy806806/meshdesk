# MeshDesk v2 — Layer 2b (AES-GCM Encryption) Specification

**Status:** FROZEN (Data-plane encryption layer of v2 protocol stack)
**Date:** 2026-07-28
**Author:** architect
**Motion:** motion-856c071ce5a9 (Agora discussion: MeshDesk v2 full rewrite)
**Task:** t_bfe2658a (Action item 3/10 from the motion)
**Depends on:** Layer 0 (Identity), Layer 1 (Handshake), Layer 2a (Session key exchange)
**Freeze order:** Layer 0 → Layer 1 → Layer 2b (this spec) → Layer 2a → Layer 3 (smux)

---

## Overview

Layer 2b provides **AES-256-GCM authenticated encryption** over any `net.Conn`.
It wraps the raw byte stream from Layer 1 (Handshake) into a secure channel
where every byte written is encrypted and every byte read is authenticated
before delivery.

```
┌─────────────────────────────────────────────────────────────────┐
│                     Protocol Stack                              │
├─────────────────────────────────────────────────────────────────┤
│ Layer 3         smux (stream multiplexing)                      │
│                 reads/writes over a net.Conn                    │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2b        SecureConn (AES-256-GCM)  ←─── THIS SPEC        │
│                 wraps net.Conn into encrypted net.Conn           │
│                 Wire: [len:2][nonce:12][ctext:plaintext+16B tag]│
├─────────────────────────────────────────────────────────────────┤
│ Layer 2a        Session key exchange (X25519 ECDH + Ed25519)    │
│                 produces: sendKey(32B), recvKey(32B)             │
│                 (separate spec — t_7824afc5)                    │
├─────────────────────────────────────────────────────────────────┤
│ Layer 1         Handshake (Reality TLS over TCP)                │
│                 provides raw encrypted net.Conn                  │
├─────────────────────────────────────────────────────────────────┤
│ Layer 0         Identity (Ed25519)                              │
│                 used by Layer 2a to sign key exchange            │
└─────────────────────────────────────────────────────────────────┘
```

**Why this layer exists separately from the key exchange (2a):**
AES-GCM encryption is the data-plane hotpath — every byte of every
WebSSH session, file transfer, and proxy stream passes through it.
Freezing the encryption contract independently means:
- The key exchange (2a) can be revised without changing the encryption wire format.
- The encryption layer can be tested with static keys (no key exchange needed for
  unit tests — just 32-byte keys from `make([]byte, 32)`).
- The performance profile (zero-copy where possible, no allocations on the hotpath)
  is isolated and optimizable.

---

## 1. Interface — SecureConn

`SecureConn` is a `net.Conn` that transparently encrypts all writes
and decrypts all reads. It satisfies the full `net.Conn` interface
so that any higher layer (smux, PeerManager, applications) sees a
standard Go connection with zero awareness of encryption.

```go
// Package crypto provides the AES-256-GCM encryption layer for MeshDesk v2.
//
// SecureConn wraps a net.Conn with authenticated encryption. Every Write
// produces one framed ciphertext record. Every Read reassembles and decrypts
// one plaintext frame. The caller sees a standard net.Conn — no crypto API,
// no key rotation, no nonce management.
//
// This package is separate from internal/session/ because:
//   - It has no knowledge of mesh identity or key exchange.
//   - It is testable with static 32-byte keys (no Ed25519, no X25519).
//   - It is the single point of encryption for ALL data-plane traffic.
//
// Thread safety: SecureConn is safe for concurrent Read and concurrent Write
// from different goroutines. It is NOT safe for concurrent Read or concurrent
// Write from multiple goroutines — use Layer 3 (smux) for that.
package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/binary"
    "errors"
    "io"
    "net"
    "sync"
    "time"
)

// ──────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────

const (
    // MaxMessageSize is the maximum plaintext size per Write call.
    // Larger writes return an error. This prevents unbounded memory
    // allocation in the receiver.
    //
    // 65535 matches the maximum TLS record payload (2^16 - 1).
    // Each encrypted frame is at most: 2 (len) + 12 (nonce) + 65535 + 16 (tag) = 65565 bytes.
    MaxMessageSize = 65535

    // NonceSize is the AES-GCM nonce length (12 bytes, per NIST SP 800-38D).
    NonceSize = 12

    // TagSize is the AES-GCM authentication tag length (16 bytes).
    TagSize = 16

    // FrameOverhead is the total per-frame overhead: 2 (length) + 12 (nonce) + 16 (tag).
    FrameOverhead = 2 + NonceSize + TagSize // 30 bytes

    // KeySize is the AES-256 key length (32 bytes).
    KeySize = 32
)

// ──────────────────────────────────────────────────────────────────────
// Error sentinels
// ──────────────────────────────────────────────────────────────────────

var (
    // ErrMessageTooLarge is returned by Write when len(p) > MaxMessageSize.
    ErrMessageTooLarge = errors.New("crypto: message exceeds MaxMessageSize")

    // ErrAuthenticationFailed is returned by Read when the GCM tag
    // verification fails. The connection should be considered compromised
    // and closed.
    ErrAuthenticationFailed = errors.New("crypto: AES-GCM authentication failed")

    // ErrInvalidKey is returned by NewSecureConn when a key has the wrong length.
    ErrInvalidKey = errors.New("crypto: key must be 32 bytes (AES-256)")

    // ErrConnClosed is returned when reading from or writing to a closed connection.
    ErrConnClosed = errors.New("crypto: connection closed")
)

// ──────────────────────────────────────────────────────────────────────
// SecureConn
// ──────────────────────────────────────────────────────────────────────

// SecureConn wraps a net.Conn with AES-256-GCM authenticated encryption.
//
// Wire format (per message):
//
//     ┌──────────┬──────────────┬──────────────────────────┐
//     │ 2 bytes  │  12 bytes    │  len(plaintext) + 16 bytes│
//     │  length  │   nonce      │  ciphertext (incl. tag)   │
//     │ (big-end)│ (big-end)    │                           │
//     └──────────┴──────────────┴──────────────────────────┘
//
// The length field encodes the total ciphertext length (plaintext + TagSize).
// The nonce is a big-endian uint96 counter, unique per message per direction.
// The ciphertext includes the 16-byte GCM authentication tag appended by Seal.
//
// Separate keys for send and receive directions prevent reflection attacks:
// data encrypted with sendKey cannot be decrypted with sendKey — only recvKey.
//
// Key rotation: call SetKeys() to swap to new AEADs atomically. This is safe
// to call concurrently with Read and Write. The old AEADs are not zeroed —
// the caller should discard them.
type SecureConn struct {
    conn    net.Conn       // underlying transport (Reality TLS, net.Pipe for tests)

    // ── Encryption ───────────────────────────────────────────────────
    sendAEAD   cipher.AEAD  // encrypts outbound (Write)
    recvAEAD   cipher.AEAD  // decrypts inbound  (Read)
    sendNonce  uint64       // counter for outbound nonces (big-endian, left-padded to 12B)
    recvNonce  uint64       // expected counter for next inbound nonce (checked, not trusted)

    // ── Synchronization ──────────────────────────────────────────────
    writeMu    sync.Mutex   // serialize Write calls
    readMu     sync.Mutex   // serialize Read calls
    closed     bool         // set by Close
    closeMu    sync.RWMutex // protects closed
}

// NewSecureConn creates a SecureConn wrapping the given net.Conn.
//
// Parameters:
//   - conn:    the underlying transport (typically a *tls.Conn from Layer 1)
//   - sendKey: 32-byte AES-256 key for encrypting outbound data (Write calls)
//   - recvKey: 32-byte AES-256 key for decrypting inbound data (Read calls)
//
// Returns ErrInvalidKey if either key is not 32 bytes.
//
// The keys are typically derived from the Layer 2a X25519 ECDH key exchange:
//
//     hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("meshdesk-v2-session"))
//     sendKey := make([]byte, 32)
//     recvKey := make([]byte, 32)
//     io.ReadFull(hkdf, sendKey)
//     io.ReadFull(hkdf, recvKey)
//
// For testing, pass make([]byte, 32) for both keys (all-zero keys are valid AES
// keys — they're just not secret).
func NewSecureConn(conn net.Conn, sendKey, recvKey []byte) (*SecureConn, error) {
    if len(sendKey) != KeySize {
        return nil, fmt.Errorf("%w: send key is %d bytes", ErrInvalidKey, len(sendKey))
    }
    if len(recvKey) != KeySize {
        return nil, fmt.Errorf("%w: recv key is %d bytes", ErrInvalidKey, len(recvKey))
    }

    sendAEAD, err := newAESGCM(sendKey)
    if err != nil {
        return nil, fmt.Errorf("create send AEAD: %w", err)
    }
    recvAEAD, err := newAESGCM(recvKey)
    if err != nil {
        return nil, fmt.Errorf("create recv AEAD: %w", err)
    }

    return &SecureConn{
        conn:      conn,
        sendAEAD:  sendAEAD,
        recvAEAD:  recvAEAD,
        sendNonce: 0,
        recvNonce: 0, // first message MUST have nonce=0
    }, nil
}
```

### 1.1 Read

```go
// Read reads one plaintext message from the underlying conn, decrypts it,
// and copies the plaintext into p. Returns the number of plaintext bytes read.
//
// Read blocks until a full encrypted frame arrives and passes authentication.
// It never returns partial data: either a complete plaintext message is
// returned, or an error.
//
// If the GCM authentication tag fails, Read returns ErrAuthenticationFailed
// and the connection should be closed immediately — the data stream is
// compromised.
//
// Implements io.Reader (satisfies net.Conn.Read contract for single-frame reads).
// This is sufficient because smux (Layer 3) handles stream-level Read semantics.
func (sc *SecureConn) Read(p []byte) (int, error) {
    sc.readMu.Lock()
    defer sc.readMu.Unlock()

    // 1. Read the 2-byte length prefix.
    var lenBuf [2]byte
    if _, err := io.ReadFull(sc.conn, lenBuf[:]); err != nil {
        return 0, err
    }
    ciphertextLen := binary.BigEndian.Uint16(lenBuf[:])

    // 2. Read the nonce (12 bytes).
    var nonceBuf [NonceSize]byte
    if _, err := io.ReadFull(sc.conn, nonceBuf[:]); err != nil {
        return 0, err
    }

    // 3. Validate nonce (replay protection: nonce must be strictly increasing).
    //    The nonce is a big-endian uint96. We only check the first 8 bytes
    //    (the counter portion) for sequential ordering.
    nonce := nonceToUint64(nonceBuf)
    sc.recvNonce++
    if nonce != sc.recvNonce-1 {
        // Nonce out of order — possible replay attack.
        // We still attempt to decrypt (the counter value is in the nonce
        // not in our state), but the tag will almost certainly fail.
        // If it somehow passes, the connection is compromised.
    }

    // 4. Read the ciphertext (including 16-byte GCM tag).
    ciphertext := make([]byte, ciphertextLen)
    if _, err := io.ReadFull(sc.conn, ciphertext); err != nil {
        return 0, err
    }

    // 5. Decrypt and authenticate.
    plaintext, err := sc.recvAEAD.Open(nil, nonceBuf[:], ciphertext, nil)
    if err != nil {
        return 0, ErrAuthenticationFailed
    }

    // 6. Copy to caller's buffer.
    n := copy(p, plaintext)
    if n < len(plaintext) {
        // Caller's buffer is smaller than the message. This is a
        // protocol error on the caller's side — they should have
        // allocated a buffer at least as large as MaxMessageSize.
        return n, io.ErrShortBuffer
    }
    return n, nil
}
```

### 1.2 Write

```go
// Write encrypts p and sends one framed ciphertext record to the
// underlying conn.
//
// Returns ErrMessageTooLarge if len(p) > MaxMessageSize.
// Returns the number of plaintext bytes written on success.
//
// Implements io.Writer (satisfies net.Conn.Write contract).
func (sc *SecureConn) Write(p []byte) (int, error) {
    if len(p) > MaxMessageSize {
        return 0, ErrMessageTooLarge
    }

    sc.writeMu.Lock()
    defer sc.writeMu.Unlock()

    // 1. Encode the nonce.
    nonce := make([]byte, NonceSize)
    nonceFromUint64(nonce, sc.sendNonce)
    sc.sendNonce++

    // 2. Encrypt: Seal appends the ciphertext (including 16-byte tag) to dst.
    //    We pass nil as dst so Seal allocates a fresh buffer for the ciphertext.
    //    Output = p encrypted + 16-byte GCM tag.
    ciphertext := sc.sendAEAD.Seal(nil, nonce, p, nil)

    // 3. Write [length:2][nonce:12][ciphertext].
    //    Use a single Write to minimize syscalls and TCP segment fragmentation.
    headerAndCiphertext := make([]byte, 2+NonceSize+len(ciphertext))
    binary.BigEndian.PutUint16(headerAndCiphertext[0:2], uint16(len(ciphertext)))
    copy(headerAndCiphertext[2:2+NonceSize], nonce)
    copy(headerAndCiphertext[2+NonceSize:], ciphertext)

    if _, err := sc.conn.Write(headerAndCiphertext); err != nil {
        return 0, err
    }
    return len(p), nil
}
```

### 1.3 Lifecycle Methods

```go
// Close closes the underlying connection.
// After Close, Read and Write return ErrConnClosed.
func (sc *SecureConn) Close() error {
    sc.closeMu.Lock()
    defer sc.closeMu.Unlock()
    if sc.closed {
        return nil
    }
    sc.closed = true
    return sc.conn.Close()
}

// LocalAddr returns the local network address of the underlying conn.
func (sc *SecureConn) LocalAddr() net.Addr {
    return sc.conn.LocalAddr()
}

// RemoteAddr returns the remote network address of the underlying conn.
func (sc *SecureConn) RemoteAddr() net.Addr {
    return sc.conn.RemoteAddr()
}

// SetDeadline sets read and write deadlines on the underlying conn.
func (sc *SecureConn) SetDeadline(t time.Time) error {
    return sc.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying conn.
func (sc *SecureConn) SetReadDeadline(t time.Time) error {
    return sc.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying conn.
func (sc *SecureConn) SetWriteDeadline(t time.Time) error {
    return sc.conn.SetWriteDeadline(t)
}
```

### 1.4 Key Rotation

```go
// SetKeys atomically replaces the send and receive AEADs.
//
// Safe to call concurrently with Read and Write. The new keys take
// effect on the next Read/Write call after SetKeys returns.
//
// Nonce counters are NOT reset — they continue from their current
// values. This is correct because the new keys are independent and
// nonce reuse across different keys is safe.
//
// This enables session key rotation without tearing down the connection.
// Typical rotation interval: 1 hour, or after 2^32 messages per direction.
func (sc *SecureConn) SetKeys(sendKey, recvKey []byte) error {
    if len(sendKey) != KeySize || len(recvKey) != KeySize {
        return ErrInvalidKey
    }

    sendAEAD, err := newAESGCM(sendKey)
    if err != nil {
        return fmt.Errorf("create new send AEAD: %w", err)
    }
    recvAEAD, err := newAESGCM(recvKey)
    if err != nil {
        return fmt.Errorf("create new recv AEAD: %w", err)
    }

    sc.writeMu.Lock()
    sc.readMu.Lock()
    sc.sendAEAD = sendAEAD
    sc.recvAEAD = recvAEAD
    // Nonce counters deliberately NOT reset — see doc comment above.
    sc.readMu.Unlock()
    sc.writeMu.Unlock()

    return nil
}
```

---

## 2. Wire Format

Every message sent through a SecureConn is a self-contained frame:

```
Byte 0      1      2             13           14                         N+29
┌──────┬──────┬──────┬─────┬──────┬──────┬─────┬──────────────────────────┐
│ len  │ len  │ nonce│ ... │ nonce│ ctxt │ ... │ ctxt + tag               │
│ (hi) │ (lo) │ [0]  │     │ [11] │ [0]  │     │ [plaintext_len+15]       │
├──────┴──────┼──────┴─────┴──────┼──────┴─────┴──────────────────────────┤
│  2 bytes    │   12 bytes        │   len(plaintext) + 16 bytes           │
│  uint16 BE  │   uint96 BE       │   AES-256-GCM ciphertext (with tag)   │
│  = ct_len   │   = counter       │                                       │
└─────────────┴───────────────────┴───────────────────────────────────────┘

Total frame size = 2 + 12 + len(plaintext) + 16 = 30 + len(plaintext)
```

### 2.1 Field Details

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| `length` | 2 bytes | uint16 big-endian | Total ciphertext length, including the 16-byte GCM tag. Range: [TagSize, MaxMessageSize + TagSize]. |
| `nonce` | 12 bytes | uint96 big-endian counter | Monotonically increasing per direction. Initialized to 0 for the first message on each side. |
| `ciphertext` | variable | AES-256-GCM output | `cipher.Seal` output: plaintext encrypted + 16-byte GCM tag appended. AAD is empty (`nil`). |

### 2.2 Nonce Construction

The nonce is a 12-byte big-endian unsigned 96-bit integer:

```go
func nonceFromUint64(dst []byte, v uint64) {
    // dst must be 12 bytes (filled with zeroed prefix by caller)
    binary.BigEndian.PutUint64(dst[4:], v)
}

func nonceToUint64(nonce [12]byte) uint64 {
    return binary.BigEndian.Uint64(nonce[4:])
}
```

The upper 4 bytes are always zero (the counter is effectively a uint64).
With 2^64 messages per direction, nonce reuse is impossible in practice
even at 1M messages/second (that's ~585,000 years).

**Why counter, not random:** Counter nonces are deterministic, require
no `crypto/rand` syscall per message, and guarantee uniqueness.
Random 96-bit nonces have a 2^-32 collision probability after 2^32
messages. This is good enough for most applications, but for a mesh
protocol that may transport gigabytes over a single long-lived
connection, counter is safer.

**Why no Side-ID in nonce:** Separate send/recv keys eliminate the need
for a side identifier in the nonce. Even if the same counter value
appears on both sides, the keys are different, so nonce reuse is
not a concern.

### 2.3 Nonce Validation on Read

The receiver validates that nonces arrive in monotonic order:

```go
expected := sc.recvNonce // incremented before check
if nonce != expected {
    // Nonce out of order. We still pass the received nonce to AES-GCM Open
    // (since the sender might have legitimately skipped a nonce due to
    // message loss — though this shouldn't happen over TCP).
    // GCM authentication will detect any actual tampering.
}
```

The nonce check is a **best-effort sanity check**, not a security control.
GCM's authentication tag already prevents tampered ciphertext from being
accepted. The nonce check provides defense-in-depth against:
- Replay attacks: identical ciphertext replayed with a nonce that doesn't
  match the expected counter.
- Protocol bugs: a misbehaving sender producing nonces out of order.

---

## 3. Key Derivation (from Layer 2a)

SecureConn needs two 32-byte keys (sendKey, recvKey). These are derived
from the X25519 ECDH shared secret produced by the Layer 2a session
key exchange. The derivation uses HKDF-SHA256 with explicit domain
separation:

```go
// SessionKeys holds the derived AES-256 keys for SecureConn.
type SessionKeys struct {
    SendKey [KeySize]byte // encrypt outbound data
    RecvKey [KeySize]byte // decrypt inbound data
    Nonce   [NonceSize]byte // reserved for future use
}

// DeriveSessionKeys derives AES-256 keys from a shared secret.
//
// sharedSecret: output of X25519 ECDH (32 bytes)
// role: true = initiator, false = responder
// identityBinding: Ed25519 signature of (initiator_pub || responder_pub || sharedSecret)
//                  included in HKDF info string for domain separation.
func DeriveSessionKeys(sharedSecret []byte, role bool, identityBinding []byte) *SessionKeys {
    // HKDF-Extract: salt = nil (all zeros), IKM = sharedSecret
    //   → produces a 32-byte PRK (pseudorandom key)
    // HKDF-Expand: PRK + info = "meshdesk-v2-session" + role + identityBinding prefix
    //   → produces 3 × 32 bytes = 96 bytes of key material

    info := []byte("meshdesk-v2-session")
    if role {
        info = append(info, 'I') // initiator
    } else {
        info = append(info, 'R') // responder
    }
    // Include first 8 bytes of identity binding signature for domain separation.
    // This binds the session keys to the Ed25519 identity verification,
    // preventing cross-identity key confusion.
    if len(identityBinding) >= 8 {
        info = append(info, identityBinding[:8]...)
    }

    reader := hkdf.New(sha256.New, sharedSecret, nil, info)

    var keys SessionKeys
    io.ReadFull(reader, keys.SendKey[:])
    io.ReadFull(reader, keys.RecvKey[:])
    io.ReadFull(reader, keys.Nonce[:]) // reserved

    return &keys
}
```

**Key derivation contract:**
- The caller (Layer 2a) is responsible for running the X25519 ECDH and
  Ed25519 identity verification.
- This package (`crypto`) does NOT perform key exchange. It only consumes
  the derived keys.
- The `info` string includes role (initiator/responder) and identity binding
  to prevent:
  1. Cross-role key confusion: initiator's sendKey ≠ responder's sendKey
  2. Cross-identity attacks: different identities produce different keys
     even if they somehow share the same X25519 ephemeral

**Testing:** For unit tests of SecureConn, use `make([]byte, 32)` for both
keys. All-zero keys are valid AES-256 keys (the key space for AES is 2^256,
and the all-zero key is just one point in that space). Insecure in
production but perfect for verifying encryption/decryption correctness.

---

## 4. Performance and Allocation Budget

This layer is on every byte of mesh traffic. Allocation behavior matters.

| Operation | Allocations | Notes |
|-----------|-------------|-------|
| `NewSecureConn` | 2 AEAD objects (~1KB each, one-time) | Acceptable — once per connection |
| `Write(p)` | 2 allocs: `nonce` + `headerAndCiphertext` | `Seal(nil, ...)` appends to nil → 1 alloc. headerAndCiphertext is 1 alloc. Total: ~len(p) + FrameOverhead bytes |
| `Read(p)` | 1 alloc: `ciphertext` buffer | `ciphertext := make([]byte, ctLen)` → 1 alloc. `Open(nil, ...)` with nil dst → 1 alloc for plaintext |
| `SetKeys` | 2 AEAD objects | Acceptable — infrequent |

**Future optimization (not required for v2.0):**
- Pool Write's `headerAndCiphertext` buffer via `sync.Pool` for repeated
  messages of similar size.
- Pool Read's `ciphertext` buffer via `sync.Pool`.
- Use `Seal(dst[:0], ...)` with pre-allocated buffer to avoid allocation.

Current allocation profile is acceptable for v2.0 launch and can be
optimized later without changing the interface or wire format.

---

## 5. Thread Safety Model

```
┌──────────────────────────────────────────────────┐
│ SecureConn                                        │
│                                                    │
│  Goroutine A (reader):    Goroutine B (writer):    │
│    sc.Read()     ←OK→       sc.Write()             │
│                                                    │
│  Goroutine C (reader):    Goroutine D (writer):    │
│    sc.Read()     ←NO→       sc.Write()             │
│    (concurrent reads corrupt state)                │
│                                                    │
│  Key rotation (any goroutine):                     │
│    sc.SetKeys()  ←OK→  concurrent Read + Write     │
│    (grabs both mutexes, swaps AEADs atomically)    │
└──────────────────────────────────────────────────┘
```

One reader and one writer is the standard Go `net.Conn` concurrency model.
Layer 3 (smux) handles concurrent stream access by multiplexing streams
over a single SecureConn.

---

## 6. Package Layout

```
meshdesk/
├── internal/
│   ├── identity/                 ← Layer 0 (Ed25519 keypair)
│   │   ├── identity.go
│   │   └── identity_test.go
│   ├── handshake/                ← Layer 1 (Reality TLS transport)
│   │   ├── handshake.go
│   │   └── reality.go
│   ├── crypto/                   ← Layer 2b (THIS SPEC) — NEW
│   │   ├── secure_conn.go        ← SecureConn struct + Read/Write/Close
│   │   ├── secure_conn_test.go   ← Unit tests (round-trip, auth fail, key rotation)
│   │   ├── keys.go               ← SessionKeys + DeriveSessionKeys
│   │   └── aead.go               ← newAESGCM helper (shared with handshake)
│   ├── session/                  ← Layer 2a (key exchange + session lifecycle) — separate task
│   │   └── session.go            ← Session interface + X25519 ECDH + Ed25519 binding
│   └── smux/                     ← Layer 3 (stream multiplexing) — separate task
│       └── smux.go
```

**Why `crypto/` not `session/`:**
The `crypto/` package has zero dependencies on `identity/` or `handshake/`.
It only depends on `crypto/aes`, `crypto/cipher`, `crypto/sha256`, and
`golang.org/x/crypto/hkdf` (for key derivation). This makes it:
- Trivially testable with static keys.
- Reusable outside the mesh code path (proxy chunker, for example).
- Separately benchmarkable — performance regressions are isolated.

The `session/` package (Layer 2a) imports both `crypto/` (for SecureConn)
and `identity/` (for Ed25519 signing). It orchestrates the key exchange
and hands derived keys to `NewSecureConn`.

---

## 7. v1 Code Impact

### 7.1 No Direct v1 Equivalent

v1 had no standalone AES-GCM data-plane layer. Encryption was handled by:
- **WireGuard** (ChaCha20-Poly1305 in the kernel/netstack path)
- **Reality TLS** (TLS 1.3 record-layer encryption, which is AES-128-GCM
  per the TLS cipher suite — not our own layer)
- **Protocol header** (AES-CTR for padding in `internal/proxy/protocol.go`)

None of these are a dedicated net.Conn wrapper. The SecureConn in v2 is a
new capability: defense-in-depth encryption between mesh nodes that
operates independently of the transport layer.

### 7.2 Code Reused

| Source | What | Where |
|--------|------|-------|
| `reality_transport.go:861-867` | `newAESGCM()` helper | Extracted to `internal/crypto/aead.go` (used by both handshake and crypto packages) |

The `newAESGCM` function in reality_transport.go is the only AES-GCM
code in v1. It creates a `cipher.AEAD` from a key. Both the handshake
package (REALITY auth tag injection) and the crypto package (SecureConn)
use the same helper. Extract it to a shared location.

### 7.3 Dependencies Added

```
crypto/aes          ← stdlib (already present in v1 via reality_transport.go)
crypto/cipher       ← stdlib (already present in v1 via reality_transport.go)
golang.org/x/crypto/hkdf  ← already present in v1 (reality_transport.go and totp_keymanager.go)
```

Zero new external dependencies. All crypto primitives are in stdlib or
already vendored in v1.

---

## 8. Acceptance Criteria

Tests that MUST pass before this spec is considered "frozen and implemented."

### Core Functionality

**AC-L2.1: SecureConn satisfies net.Conn interface.**
```go
var _ net.Conn = (*crypto.SecureConn)(nil)
// compiles
```

**AC-L2.2: NewSecureConn with valid 32-byte keys succeeds.**
```go
client, server := net.Pipe()
sc, err := crypto.NewSecureConn(client, make([]byte, 32), make([]byte, 32))
// err is nil, sc is not nil
```

**AC-L2.3: NewSecureConn with invalid key length returns ErrInvalidKey.**
```go
_, err := crypto.NewSecureConn(nil, make([]byte, 16), make([]byte, 32))
// errors.Is(err, crypto.ErrInvalidKey) is true
```

**AC-L2.4: Write + Read round-trip preserves data.**
```go
client, server := net.Pipe()
scClient, _ := crypto.NewSecureConn(client, key, key)
scServer, _ := crypto.NewSecureConn(server, key, key)

go func() {
    scClient.Write([]byte("hello world"))
    scClient.Close()
}()

buf := make([]byte, crypto.MaxMessageSize)
n, err := scServer.Read(buf)
// n == 11, string(buf[:n]) == "hello world", err == nil

n, err = scServer.Read(buf)
// n == 0, err == io.EOF
```

**AC-L2.5: Tampered ciphertext detected — Read returns ErrAuthenticationFailed.**
```go
// Write through SecureConn, but tamper with ciphertext on the wire.
client, server := net.Pipe()
scClient, _ := crypto.NewSecureConn(client, key, key)
scServer, _ := crypto.NewSecureConn(server, key, key)

// Instead of using scServer.Read directly, read the raw wire bytes,
// tamper with them, and pass to a raw pipe that scServer reads from.
// (Implementation detail: use a middleware net.Pipe or io.Reader wrapper.)

// Then:
buf := make([]byte, crypto.MaxMessageSize)
_, err := scServer.Read(buf)
// errors.Is(err, crypto.ErrAuthenticationFailed) is true
```

**AC-L2.6: Send/recv key separation — reflection attack prevented.**
```go
// Two SecureConns sharing the SAME key for both directions.
client, server := net.Pipe()
scSameKeyClient, _ := crypto.NewSecureConn(client, key, key) // same key
scSameKeyServer, _ := crypto.NewSecureConn(server, key, key) // same key

go func() {
    scSameKeyClient.Write([]byte("test"))
}()

buf := make([]byte, crypto.MaxMessageSize)
n, _ := scSameKeyServer.Read(buf)
// n == 4, string(buf[:n]) == "test"

// Now swap: write from server, read from client.
go func() {
    scSameKeyServer.Write([]byte("attack"))
}()

n2, err := scSameKeyClient.Read(buf)
// With separate send/recv keys: err should be ErrAuthenticationFailed
// With same keys: n2 == 6, string(buf[:n]) == "attack" (no protection)
```

**AC-L2.7: MaxMessageSize enforcement.**
```go
bigPayload := make([]byte, crypto.MaxMessageSize+1)
_, err := sc.Write(bigPayload)
// errors.Is(err, crypto.ErrMessageTooLarge) is true
```

**AC-L2.8: Close propagates to underlying conn.**
```go
sc.Close()
_, err := sc.Read(buf)
// err indicates connection is closed (io.EOF or net.ErrClosed)
```

**AC-L2.9: Nonce monotonicity — counter increments correctly per message.**
```go
// Write 3 messages, verify on the wire that nonces are 0, 1, 2.
// This is a white-box test: read the raw bytes from the underlying conn
// and verify the nonce bytes at offset 2-13.
client, server := net.Pipe()
sc, _ := crypto.NewSecureConn(client, key, key)

go func() {
    sc.Write([]byte("msg1"))
    sc.Write([]byte("msg2"))
    sc.Write([]byte("msg3"))
}()

// Read raw bytes from server side
for i := 0; i < 3; i++ {
    header := make([]byte, 2+crypto.NonceSize)
    io.ReadFull(server, header)
    nonce := binary.BigEndian.Uint64(header[6:14])
    // nonce == i for each message
}
```

**AC-L2.10: Key rotation — SetKeys swaps AEADs atomically.**
```go
// Write with key1, rotate, read with key2, verify data integrity.
client, server := net.Pipe()
sc, _ := crypto.NewSecureConn(client, key1, key1)

sc.Write([]byte("pre-rotation"))

// Rotate keys
sc.SetKeys(key2, key2)
sc.Write([]byte("post-rotation"))

// Both messages should be decryptable with the correct keys
// at the appropriate points in the stream.
```

### Integration

**AC-L2.I1: crypto/ package does not import identity/ or handshake/.**
```bash
grep -r '"meshdesk/internal/identity"\|"meshdesk/internal/handshake"' internal/crypto/
# → no results
```

**AC-L2.I2: Zero new external dependencies.**
```bash
go list -deps ./internal/crypto/ | grep -v "^\(internal\|errors\|fmt\|crypto\|encoding\|io\|strings\|sync\|time\|runtime\|unicode\|reflect\|net\|golang.org/x/crypto\)"
# → only stdlib + golang.org/x/crypto (already present in v1)
```

**AC-L2.I3: Wire format compliance — external validator.**
```go
// A non-Go tool (or a Go program using only standard AES-GCM) can:
// 1. Read 2-byte length (big-endian uint16)
// 2. Read 12-byte nonce
// 3. Read `length` bytes of ciphertext
// 4. Decrypt with AES-256-GCM (key must be known)
// 5. Recover the original plaintext
//
// This is a manual verification step, not a unit test.
// Implementation: provide a Python or Bash script in tests/ that
// demonstrates wire format parsing.
```

---

## 9. Downstream Tasks

| # | Task | Assignee | Depends on |
|---|------|----------|------------|
| 1 | Implement `internal/crypto/secure_conn.go` + tests | developer (t_0407a960) | This spec |
| 2 | Implement `internal/crypto/keys.go` (DeriveSessionKeys) | developer | This spec + Layer 2a spec |
| 3 | Freeze Layer 2a — Session key exchange (X25519 ECDH + Ed25519) | architect (t_7824afc5) | This spec + L0/L1 |
| 4 | Smoke-test gates: L1→L2 via net.Pipe + local TLS | tester (t_6765e145) | This spec |
| 5 | Extract `newAESGCM` to shared `internal/crypto/aead.go` | developer | This spec |

---

## 10. Trade-offs and Rationale

### 10.1 AES-256-GCM vs ChaCha20-Poly1305

| Aspect | AES-256-GCM (chosen) | ChaCha20-Poly1305 |
|--------|---------------------|-------------------|
| Go stdlib | `crypto/aes` + `crypto/cipher` | Requires `golang.org/x/crypto` |
| Hardware acceleration | AES-NI on x86, ARMv8 Crypto Extensions | Software-only |
| Performance (x86) | ~1-2 GB/s with AES-NI | ~0.5-1 GB/s software |
| Performance (ARM) | ~200-500 MB/s (ARMv8 CE) | ~0.5-1 GB/s (NEON) |
| v1 familiarity | Already used in reality_transport.go | None (WireGuard used it but WG is removed) |
| Nonce handling | 12 bytes, strict uniqueness | 12 bytes, strict uniqueness |

**Decision:** AES-256-GCM. The Go stdlib provides a performant AES-GCM
implementation. AES-NI acceleration is ubiquitous on x86 servers and
ARMv8 Crypto Extensions cover modern ARM devices. No new dependency.
The v1 codebase already uses `newAESGCM` — the pattern is familiar.

### 10.2 Separate Send/Recv Keys

**Why not a single session key with direction byte in the nonce?**

| Aspect | Separate keys (chosen) | Direction byte in nonce |
|--------|----------------------|------------------------|
| Reflection attacks | Prevented by key domain separation | Nonce must encode side (I/R) |
| Nonce space | Full 96-bit per direction | 95-bit per direction (1 bit for side) |
| HKDF output | 64 bytes (2 keys) | 32 bytes (1 key) |
| Implementation | Cleaner API: send ≠ recv | All nonces must carry side bit |
| Wire overhead | 0 bytes (keys are local) | 0 bytes (nonce bit is local convention) |

**Decision:** Separate keys. The cost is 32 extra bytes of HKDF output and
1 extra AEAD object in memory (~1KB). The benefit is that it's impossible
to accidentally reflect a message back to the sender — the key mismatch
guarantees GCM authentication failure.

### 10.3 Length-Prefixed Framing vs Streaming AEAD

Two approaches considered:

**A) Length-prefixed framing (chosen):** Each `Write` produces one frame
with a 2-byte length prefix. `Read` reads and decrypts one complete frame.

**B) Streaming AEAD:** Use a streaming construction like AES-GCM-SIV or
a custom "encrypt-then-MAC each chunk" protocol.

| Aspect | Length-prefixed (chosen) | Streaming AEAD |
|--------|-------------------------|----------------|
| Complexity | Minimal: 2-byte header, read length, read rest | Complex: chunk boundaries, counter sync |
| Error model | Whole-message atom: decrypt or fail | Partial reads, stream state, MAC at end |
| Go compatibility | Standard io.Reader contract | Breaks io.Reader: Read might return partial decrypt |
| Replay protection | Per-message nonce verification | Requires chunk-level counters |
| smux integration | smux sends whole streams as messages | smux would need to handle partial chunks |

**Decision:** Length-prefixed framing. It's the simplest correct approach
and maps naturally to Go's `net.Conn` contract: one `Write` = one message.
smux (Layer 3) batches stream data into messages, so small writes within
a stream get coalesced before hitting SecureConn.

### 10.4 Counter vs Random Nonces

| Aspect | Counter nonce (chosen) | Random nonce |
|--------|----------------------|--------------|
| Uniqueness guarantee | Absolute (monotonic counter) | Probabilistic (birthday bound at 2^32) |
| Per-message syscall | 0 | 1 (`crypto/rand.Read(12)`) |
| Implementation safety | Counter overflow after 2^64 msgs (never) | Collision after ~2^32 msgs (possible) |
| Replay detection | Natural: out-of-order nonce = red flag | No replay detection without external state |

**Decision:** Counter nonces. Deterministic, zero syscall, absolute uniqueness
guarantee. The only downside (no randomness) is irrelevant because the
ciphertext itself is indistinguishable from random (GCM's IND-CCA2 security).

### 10.5 Use of HKDF

```go
// HKDF is already used in:
// - reality_transport.go: HKDF-SHA256 for REALITY auth key derivation
// - totp_keymanager.go:  HKDF-SHA256 for per-user encryption key derivation
//
// Both import golang.org/x/crypto/hkdf (already vendored in v1 go.sum).
```

No new dependency. HKDF-SHA256 is the correct KDF for this use case:
provably secure key derivation with domain separation via the `info`
parameter. The `info` string binds derived keys to the role and
identity binding, preventing cross-context key reuse.