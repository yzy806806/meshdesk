# Code Cleanup Report — meshdesk

**Reviewer:** reviewer  
**Date:** 2026-08-01  
**Task:** t_128e6259  
**Scope:** All Go source files under `internal/` and `cmd/` (52 files)  
**Verification:** `go build ./...` and `go vet ./...` both pass clean  

## Summary

The codebase is in good shape after the prior cleanup (t_d1f8e097). **No dead code, no unused imports, no unused functions/variables/types, and no deprecated API usage** were found in production code. `staticcheck ./...` reports zero U1000 (unused) and zero SA1019 (deprecated) findings in non-test code. Build and vet pass clean.

All findings below are **stale/incorrect comments** that reference the removed v1 WireGuard/gVisor architecture. These are documentation-only issues — no functional impact, but they mislead new readers about the current architecture.

---

## Findings

### FINDING 1 — DELETE: Unnecessary blank identifiers in cmd/meshdesk/main.go

**File:** `cmd/meshdesk/main.go:885-886`  
**Category:** DELETE  
**Severity:** LOW  

```go
_ = gossipLayer  // silence unused warning if P2P disabled
_ = natTraversal // silence unused warning if NAT traversal disabled
```

Both `gossipLayer` and `natTraversal` are already used unconditionally on other code paths (gossipLayer at line 574 for collector discovery wiring, and both in the shutdown sequence at lines 870-871). The Go compiler does not require these blank-identifier assignments — the variables are not "declared and not used." These two lines are vestigial noise.

**Action:** Remove both lines.

---

### FINDING 2 — COMMENT: Stale package-level doc in internal/mesh/node.go

**File:** `internal/mesh/node.go:1-12`  
**Category:** COMMENT  
**Severity:** HIGH  

```go
// Package mesh provides the core mesh node abstraction.
//
// In v2, the MeshNode is being rewritten to use a self-developed protocol
// stack instead of WireGuard/gVisor. This file is a transitional stub:
// the v1 WireGuard/gVisor/obfuscation code has been removed, and the
// methods are stubbed with panic("v2: not implemented") until the new
// protocol layers (HandshakeLayer, AELayer, etc.) are implemented.
```

This comment is dangerously misleading. None of it is true anymore:

- The MeshNode is NOT a "transitional stub" — it is the fully implemented v2 mesh node.
- No method panics with "v2: not implemented" — all ~30 methods are fully implemented (Dial, DialPeerByEndpoint, DialVirtualPort, ListenVirtualPort, Start, Close, AddPeer, RemovePeer, etc.).
- "AELayer" does not exist in the codebase. The authenticated encryption layer is `crypto.NewSecureConn` (AES-256-GCM), not a separate AELayer type.
- WireGuard/gVisor/obfuscation code was removed and replaced by a self-developed protocol stack — exactly what this comment says hasn't happened yet.

**Action:** Rewrite the package comment to describe the current v2 architecture: Ed25519 identity (L0) → Reality TLS or mesh-internal transport (L1) → X25519 ECDH key exchange (L2a) → AES-256-GCM SecureConn (L2b) → smux multiplexed streams (L3) → virtual port dispatch (L4).

Similarly, the type comment at lines 34-42 has the same stale text about being a stub.

---

### FINDING 3 — COMMENT: Stale WireGuard references in internal/mesh/reality_transport.go

**File:** `internal/mesh/reality_transport.go:14`  
**Category:** COMMENT  
**Severity:** MEDIUM  

```go
//   - The resulting connection is a standard net.Conn carrying WireGuard
//     packets inside the encrypted TLS channel.
```

WireGuard is no longer used. The Reality TLS connection carries smux-multiplexed streams (X25519 ECDH → AES-256-GCM SecureConn → smux), not WireGuard packets.

**Action:** Replace "carrying WireGuard packets inside the encrypted TLS channel" with "carrying the v2 protocol stack (X25519 ECDH key exchange → AES-256-GCM SecureConn → smux multiplexed streams)."

---

### FINDING 4 — COMMENT: Stale WireGuard references in internal/mesh/handshake.go

**File:** `internal/mesh/handshake.go:9,46`  
**Category:** COMMENT  
**Severity:** LOW  

```go
// PeerHandshakeInfo holds parsed handshake status for a single peer.
// In v2, this will be populated by the HandshakeLayer, not WireGuard IpcGet.   // line 9

// PersistentKeepalive: not applicable in v2 (no WireGuard keepalive).          // line 46
```

Both comments refer to WireGuard as if it was recently removed. The "v2" framing is stale — this IS v2. The function already reads from the smux session map (as the implementation comment on line 20-22 correctly states).

**Action:** Update line 9 to describe what it actually does: "Populated from the smux session map — session establishment time is the handshake completion time." Remove "in v2" and "WireGuard IpcGet" references.

---

### FINDING 5 — COMMENT: Stale WireGuard references in internal/mesh/peer_manager.go

**File:** `internal/mesh/peer_manager.go:2,357`  
**Category:** COMMENT  
**Severity:** LOW  

```go
// Package mesh provides the PeerManager — a per-peer connection lifecycle
// manager that sits above the Transport layer and below WireGuard.             // line 2

// below WireGuard.                                                             // line 357
```

WireGuard is gone. The PeerManager sits between the transport layer and the smux session layer.

**Action:** Replace "below WireGuard" with "below the smux session layer" or simply "above the Transport layer."

---

### FINDING 6 — COMMENT: Stale WireGuard references in internal/mesh/transport.go

**File:** `internal/mesh/transport.go:3-4`  
**Category:** COMMENT  
**Severity:** LOW  

```go
// The transport layer sits between the WireGuard mesh core and the physical
// network, providing pluggable transport strategies (UDP, WebSocket, Reality TLS)
```

WireGuard mesh core is gone. The transport layer sits between the smux session layer and the physical network.

**Action:** Replace "WireGuard mesh core" with "smux session layer."

---

### FINDING 7 — COMMENT: Stale WireGuard references in cmd/meshdesk/main.go

**File:** `cmd/meshdesk/main.go:57`  
**Category:** COMMENT  
**Severity:** LOW  

```go
flag.BoolVar(&genKey, "gen-key", false, "generate a new WireGuard keypair and exit")
```

The `--gen-key` flag calls `mesh.GenerateIdentity()` which creates an **Ed25519** keypair, not a WireGuard keypair. WireGuard uses Curve25519; meshdesk uses Ed25519.

**Action:** Change help text to "generate a new Ed25519 identity keypair and exit."

---

**File:** `cmd/meshdesk/main.go:1061`  
**Category:** COMMENT  
**Severity:** LOW  

```go
bootstrapKey := fs.String("bootstrap-key", "", "bootstrap node's WireGuard public key (hex, required if not in config peers)")
```

The bootstrap key is an Ed25519 public key.

**Action:** Change help text to say "Ed25519 public key" instead of "WireGuard public key."

---

### FINDING 8 — COMMENT: Stale v1/v2 references in internal/mesh/node.go AddPeer doc

**File:** `internal/mesh/node.go:991-1000`  
**Category:** COMMENT  
**Severity:** LOW  

```go
// When Reality is not configured (the v1 backward-compatible path), the
// peer is registered in the routing table only. This preserves compatibility
// with v1 peers discovered via gossip that lack Reality TLS configuration.
```

There are no "v1 peers" anymore. The codebase no longer supports WireGuard-based peers. When Reality is not configured, the peer is added to the routing table only — this is a valid operational mode (e.g., gossip-discovered peers on the same LAN that don't need Reality TLS), not "backward compatibility with v1."

**Action:** Remove "v1 backward-compatible path" and "v1 peers" references. Describe it as "non-TLS mode" or "routing-table-only mode."

---

## What Was Verified Clean

The following were checked and confirmed clean across all 52 source files:

| Check | Result |
|-------|--------|
| Unused functions/variables/types | 0 findings (staticcheck U1000) |
| Unused imports | 0 findings |
| Dead code paths | 0 findings |
| Deprecated APIs | 0 findings (staticcheck SA1019) |
| Redundant/duplicate code | 0 findings |
| Export visibility issues | 0 findings |
| Inconsistent naming conventions | 0 findings |
| Missing error handling | 0 findings |
| `go build ./...` | PASS |
| `go vet ./...` | PASS |

**Note:** staticcheck reported 10 test-file-only warnings (SA4006, SA4010, S1009, SA4017) in test files. These are pre-existing and low-priority — they come from patterns like unused append results and nil-check-before-len in test helper functions. They do not affect production correctness and were not introduced by recent changes.

---

## Recommended Priority Order

1. **F2** (HIGH) — Rewrite node.go package comment — most misleading, affects onboarding
2. **F7** (LOW) — Fix `--gen-key` and `--bootstrap-key` flag help text — user-facing
3. **F3** (MEDIUM) — Fix reality_transport.go WireGuard comment
4. **F4** (LOW) — Fix handshake.go WireGuard/v2 comments
5. **F8** (LOW) — Fix AddPeer v1/v2 comments
6. **F5** (LOW) — Fix peer_manager.go WireGuard comment
7. **F6** (LOW) — Fix transport.go WireGuard comment
8. **F1** (LOW) — Remove unnecessary blank identifiers from main.go