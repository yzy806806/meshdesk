# MeshDesk Endpoint Learning — Finalized Design Spec v2.0

**Version:** 2.0 (finalized)
**Author:** architect
**Date:** 2026-07-27
**Source:** motion-c642d60e9a8d, action item 1/7
**Supersedes:** docs/ENDPOINT_LEARNING_DESIGN.md (v1.0)
**Status:** ready for implementation — has concrete acceptance criteria

---

## 1. Motivation & Problem Statement

### 1.1 The Endpoint Gap

MeshDesk uses two separate systems that never talk to each other:

1. **WireGuard (wireguard-go)** — encrypts packets, inherently learns peer endpoints from UDP source addresses during handshake, but this information stays inside wireguard-go internals.
2. **memberlist (hashicorp)** — gossip discovery, propagates `NodeMeta` (including `Endpoints []string` field) to all peers.

The bridge between them is **never called.** `GossipLayer.SetLocalEndpoints()` is defined (gossip.go:133) but nothing invokes it. As a result:

- `NodeMeta.Endpoints` stays `[]string{}` on all nodes
- `events.go:firstNonEmpty(meta.Endpoints)` returns `""`
- Peers discovered via gossip cannot establish WireGuard handshakes (no destination endpoint)

### 1.2 The EasyTier Model (Design Inspiration)

In EasyTier, the shared node acts as an **introducer** (not a relay):

```
Node A ──(1) connect──▶ Shared Node S
                           │
                    S learns A's endpoint from source address
                           │
                    S gossips A's (pubkey, endpoint) to all peers
                           │
                           ▼
                        Node B
                           │
                    B tries direct UDP to A's endpoint
                      │              │
                   success        failure
                      │              │
                  A↔B direct    B→S→A relay
                      │              │
                   S exits      relay fallback
```

Key insight: the shared node is the **introducer**, not a permanent relay. The goal is direct peer-to-peer communication.

### 1.3 Why This Spec Exists

The v1.0 design (ENDPOINT_LEARNING_DESIGN.md, 575 lines) covered both endpoint learning AND Dashboard config management. This v2.0 spec **isolates endpoint learning** as the single P0 concern. Dashboard config management is covered in a separate task (t_488d764c).

---

## 2. EndpointNotifier Interface Design

### 2.1 Interface Contract

**Location:** `internal/mesh/obfuscation.go`

```go
// EndpointNotifier is called when the ObfuscatingBind receives a WireGuard
// packet and can identify the source endpoint. Implementations bridge this
// information to the gossip layer for propagation.
type EndpointNotifier interface {
    // OnEndpointDiscovered is called when a WireGuard packet arrives from
    // a peer whose public key can be identified via the endpoint→peer key
    // reverse index. The peerKey is the hex-encoded WireGuard public key,
    // and endpoint is the source address in "host:port" format.
    //
    // Implementation contract (NON-NEGOTIABLE):
    //   - MUST return immediately. This is called from the WireGuard
    //     receive hot path, which runs inside wireguard-go goroutines.
    //     Blocking here delays ALL packet processing.
    //   - MUST be idempotent. WireGuard sends keepalive and transport
    //     packets frequently; duplicate calls for the same (peerKey,
    //     endpoint) pair are the common case, not an edge case.
    //   - MAY be called concurrently from multiple receive goroutines.
    //   - peerKey is guaranteed non-empty. Callers filter empty keys
    //     before invoking (unknown-endpoint packets are silently ignored).
    OnEndpointDiscovered(peerKey string, endpoint string)
}
```

**Design rationale:**

| Decision | Why |
|----------|-----|
| Single-method interface | Only one event source; YAGNI precludes future-proofing with unused methods |
| Non-blocking contract | WireGuard receive goroutines must not stall — this is the hot path |
| Idempotent | Keepalive packets arrive every 10s per peer; duplicate suppression is the callee's responsibility |
| In `obfuscation.go` (mesh package) | The obfuscatingBind is the source of truth for endpoint learning; interface lives where the data originates |
| peerKey is hex public key, not []byte | Matches existing convention across `obfuscators` map, `SetObfuscatorWithConfig`, and `config.PeerConfig.PublicKey` |

### 2.2 ObfuscatingBind Changes

**New fields in `obfuscatingBind` struct** (added at obfuscation.go:739):

```go
type obfuscatingBind struct {
    // ... existing fields (inner, obfuscators, configs, ws, reality, mu, rngMu, rng) ...

    // notifier is called when a source endpoint is successfully mapped to
    // a known peer. nil when not registered (endpoint learning disabled).
    notifier EndpointNotifier

    // endpointToPeer maps "host:port" → hex public key.
    // Populated at SetObfuscatorWithConfig time when the peer config
    // includes a known endpoint. Used by wrapReceiveFunc to reverse-lookup
    // the public key from the source endpoint of an inbound packet.
    endpointToPeer map[string]string
    epMu           sync.RWMutex  // guards endpointToPeer
}
```

**New method: `SetEndpointNotifier`**

```go
// SetEndpointNotifier installs the endpoint learning notifier.
// Pass nil to disable (default — endpoint learning is off).
func (b *obfuscatingBind) SetEndpointNotifier(n EndpointNotifier) {
    b.mu.Lock()
    defer b.mu.Unlock()
    b.notifier = n
}
```

**New method: `AddEndpointMapping`**

```go
// AddEndpointMapping records a known endpoint→peerKey mapping.
// Called from SetObfuscatorWithConfig when the peer config includes an
// endpoint. Safe for concurrent access.
func (b *obfuscatingBind) AddEndpointMapping(endpoint, peerKey string) {
    b.epMu.Lock()
    defer b.epMu.Unlock()
    if b.endpointToPeer == nil {
        b.endpointToPeer = make(map[string]string)
    }
    b.endpointToPeer[endpoint] = peerKey
}
```

**Modified method: `SetObfuscatorWithConfig`** — appends endpoint mapping:

```go
func (b *obfuscatingBind) SetObfuscatorWithConfig(peerKey string, mode ObfuscationMode, cfg ObfuscationConfig, isClient bool) {
    b.mu.Lock()
    defer b.mu.Unlock()
    b.obfuscators[peerKey] = NewObfuscatorWithConfig(mode, cfg, isClient)
    b.configs[peerKey] = cfg
    // NEW: populate reverse index (requires endpoint from caller).
    // The endpoint is passed separately since SetObfuscatorWithConfig
    // doesn't know the endpoint on its own.
}
```

**Design decision: pass endpoint separately**

The current `SetObfuscatorWithConfig` signature has no `endpoint` parameter. Options:

| Option | Pros | Cons |
|--------|------|------|
| A. Add `endpoint string` to `SetObfuscatorWithConfig` | Clean, one call site | Breaking API change; all existing callers must add `""` |
| B. Add separate `AddEndpointMapping(endpoint, peerKey)` | Non-breaking; opt-in | Two calls needed; caller must remember the pairing |
| C. Caller calls `AddEndpointMapping` after `SetObfuscatorWithConfig` | Non-breaking; explicit | Mild inconvenience at call sites |

**Selected: Option B.** `AddEndpointMapping` is a separate, explicit call. The caller (MeshNode.AddPeer) already has both `cfg.Endpoint` and `cfg.PublicKey` at the call site. This avoids breaking the `SetObfuscatorWithConfig` API used in 6+ test files.

### 2.3 MeshNode Public Accessor

Add a public accessor so the gossip layer can register the notifier:

```go
// In internal/mesh/node.go, after the existing accessor block:

// ObfuscatingBind returns the obfuscating bind for registering endpoint
// notifiers. Returns nil if the node has not been started.
func (n *MeshNode) ObfuscatingBind() *obfuscatingBind {
    return n.bind
}
```

**Alternatives considered and rejected:**
- Returning an `EndpointNotifierRegistry` interface — over-engineered for one setter
- Passing the notifier through `NewGossipLayer` constructor — creates a dependency cycle (p2p → mesh → p2p)
- Using an init-time callback — over-complicated

### 2.4 wrapReceiveFunc Modification

The modification in `wrapReceiveFunc` (obfuscation.go:962-987):

```go
func (b *obfuscatingBind) wrapReceiveFunc(fn conn.ReceiveFunc) conn.ReceiveFunc {
    return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
        n, err := fn(packets, sizes, eps)
        if err != nil {
            return n, err
        }
        for i := 0; i < n; i++ {
            if sizes[i] == 0 {
                continue
            }

            // ─── EXISTING: look up obfuscator ───
            peerKey := ""
            if eps[i] != nil {
                peerKey = eps[i].DstToString()
            }
            o := b.GetObfuscator(peerKey)
            data, err := o.UnwrapInbound(packets[i][:sizes[i]])
            if err != nil {
                sizes[i] = 0
                continue
            }
            copy(packets[i], data)
            sizes[i] = len(data)

            // ─── NEW: endpoint learning notification ───
            if b.notifier != nil && eps[i] != nil {
                srcEndpoint := eps[i].DstToString()
                // Look up the peer's public key from the reverse index.
                b.epMu.RLock()
                realPeerKey, found := b.endpointToPeer[srcEndpoint]
                b.epMu.RUnlock()
                if found && realPeerKey != "" {
                    b.notifier.OnEndpointDiscovered(realPeerKey, srcEndpoint)
                }
            }
        }
        return n, nil
    }
}
```

**IMPORTANT: `eps[i].DstToString()` semantics**

After verifying wireguard-go source (`conn.StdNetEndpoint.DstToString()` returns `e.AddrPort.String()`), `DstToString()` on the receive path returns the **source address of the sender** — exactly what we need. This is NOT the destination; the method name is misleading because it was designed for the send path where "dst" means the peer we're sending to. On the receive path, the endpoint IS the sender.

**Performance note:** The reverse index lookup is O(1) map access + RLock. This adds <100ns per packet. Acceptable on the hot path. The `notifier` nil check short-circuits when endpoint learning is disabled (default).

### 2.5 Fix: Also populate `endpointToPeer` from AddPeer

In `MeshNode.AddPeer` (node.go:326), after the `SetObfuscatorWithConfig` call and when `cfg.Endpoint != ""`:

```go
// In AddPeer, after setting up obfuscation (line ~364):
if cfg.Endpoint != "" {
    n.bind.AddEndpointMapping(cfg.Endpoint, cfg.PublicKey)
}
```

---

## 3. Full Callback Chain (6 Steps)

```
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 1: WireGuard UDP packet arrives                                │
│   wireguard-go's StdNetBind.Receive() returns a batch of packets    │
│   Each packet: [raw bytes, size, source Endpoint]                   │
│   Source endpoint: e.g., 203.0.113.5:51820 (peer's public addr)    │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 2: obfuscatingBind.wrapReceiveFunc                              │
│   (internal/mesh/obfuscation.go:962)                                │
│                                                                     │
│   For each received packet (i=0..n-1):                              │
│     srcEndpoint := eps[i].DstToString()  // "203.0.113.5:51820"    │
│     peerKey = b.obfuscators[srcEndpoint] (existing — key mismatch)  │
│     obfuscator.UnwrapInbound(packet)                                │
│                                                                     │
│   ─── NEW LOGIC (after deobfuscation) ───                           │
│     b.epMu.RLock()                                                  │
│     realPeerKey, ok := b.endpointToPeer[srcEndpoint]                │
│     b.epMu.RUnlock()                                                │
│                                                                     │
│     if b.notifier != nil && ok {                                     │
│         b.notifier.OnEndpointDiscovered(realPeerKey, srcEndpoint)   │
│     }                                                                │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 3: GossipLayer.OnEndpointDiscovered                            │
│   (internal/p2p/gossip.go — NEW method)                             │
│                                                                     │
│   func (g *GossipLayer) OnEndpointDiscovered(peerKey, endpoint string) { │
│       g.delegate.updateLocalMeta(func(m *NodeMeta) {                │
│           // Dedup: skip if already present.                        │
│           for _, ep := range m.Endpoints {                          │
│               if ep == endpoint { return }                          │
│           }                                                          │
│           m.Endpoints = append(m.Endpoints, endpoint)               │
│           m.NatType = inferNAT(endpoint)  // see §3.1               │
│           m.Seq++                                                    │
│       })                                                             │
│   }                                                                  │
│                                                                     │
│   updateLocalMeta is atomic (delegate mutex held). The Endpoints    │
│   slice mutation and Seq increment happen inside the closure.       │
│   memberlist detects the Seq change on next PushPull/probe cycle    │
│   and propagates the updated NodeMeta to all peers.                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 4: memberlist gossip propagation                               │
│   (hashicorp/memberlist)                                            │
│                                                                     │
│   NodeMeta.Seq incremented → memberlist detects local metadata      │
│   change → pushes update via PushPull (TCP, immediate for small     │
│   clusters) or indirect UDP ping with metadata piggyback.           │
│                                                                     │
│   All remote nodes receive the updated NodeMeta.Endpoints.          │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 5: meshEventDelegate.NotifyUpdate                              │
│   (internal/p2p/events.go:252) — REQUIRES BUG FIX (§5.1)           │
│                                                                     │
│   1. Parse remote node's NodeMeta                                   │
│   2. Skip if self (own gossip update)                               │
│   3. Check Seq — if stale (existing.Seq > meta.Seq), ignore         │
│   4. OLD endpoint ← capture BEFORE updating cache                   │
│   5. Update metaCache[publicKey] = meta                             │
│   6. NEW endpoint ← firstNonEmpty(meta.Endpoints)                   │
│   7. If newEndpoint != "" && newEndpoint != oldEndpoint:            │
│        → wg.UpdateEndpoint(publicKey, newEndpoint)                 │
│   8. Invoke external updateHandler(meta)                            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 6: WireGuardDelegate.UpdateEndpoint                            │
│   (internal/p2p/wg_delegate.go:207)                                 │
│                                                                     │
│   Uses WireGuard UAPI to update the peer's endpoint in-place:       │
│     ipc = "public_key=<hex>\nendpoint=<host:port>\n"                │
│     device.IpcSet(ipc)                                              │
│                                                                     │
│   WireGuard now has a destination endpoint → can send handshake.    │
│   Existing sessions with this peer re-resolve the endpoint.         │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.1 NAT Type Inference

`inferNAT(endpoint string) string` is a heuristic. When called from `OnEndpointDiscovered`, we know this endpoint was learned from a received packet — meaning the peer can receive UDP at this address. This suggests at least a restricted cone NAT or better.

```go
// inferNAT returns a conservative NAT type based on how the endpoint
// was discovered. Called from OnEndpointDiscovered when a direct packet
// is received from a peer.
func inferNAT(receivedFromEndpoint string) string {
    // A peer that can send us packets directly has at least
    // a restricted cone NAT. We can't distinguish full_cone from
    // restricted_cone without a STUN test, so be conservative.
    return "restricted_cone"
}
```

**Recalibration via STUN:** When `NatTraversal` performs a STUN test, it should call `SetLocalEndpoints` with the STUN-determined NAT type, which overrides the inferred value. This is a future task — for the initial endpoint learning implementation, `restricted_cone` is a safe default.

---

## 4. Registration & Wiring

### 4.1 main.go Wiring

In `cmd/meshdesk/main.go`, after GossipLayer creation (~line 134):

```go
// Existing code:
gl, err := p2p.NewGossipLayer(p2pCfg, node, wgDelegate)
// ...
gossipLayer = gl

// NEW: Register GossipLayer as the endpoint notifier.
// GossipLayer implements mesh.EndpointNotifier.
node.ObfuscatingBind().SetEndpointNotifier(gossipLayer)
log.Printf("[p2p] Endpoint learning: enabled (notifier wired to gossip layer)")
```

**Placement:** After `gossipLayer = gl` (line 134) and before `gl.Start()` (line ~200). The notifier can be registered before Start() because no packets flow until WireGuard is up and Start() begins gossip.

### 4.2 GossipLayer Implements EndpointNotifier

The `GossipLayer` struct already exists in `internal/p2p/gossip.go`. Adding the `OnEndpointDiscovered` method:

```go
// OnEndpointDiscovered implements mesh.EndpointNotifier.
// Non-blocking: delegates to updateLocalMeta which holds the delegate
// mutex briefly. Called from WireGuard receive goroutines.
func (g *GossipLayer) OnEndpointDiscovered(peerKey, endpoint string) {
    // peerKey is unused in this implementation because endpoint learning
    // updates LOCAL node metadata (what endpoints *we* can be reached at).
    // The peerKey identifies which peer sent us the packet, which could be
    // used for per-peer endpoint tracking in a future enhancement.
    _ = peerKey

    g.delegate.updateLocalMeta(func(m *NodeMeta) {
        // Dedup: check if this endpoint is already in the list.
        // O(n) where n is len(Endpoints), typically 1-3.
        for _, ep := range m.Endpoints {
            if ep == endpoint {
                return // already known, seq not incremented
            }
        }
        m.Endpoints = append(m.Endpoints, endpoint)
        m.NatType = inferNAT(endpoint)
        m.Seq++
    })
}
```

**Thread safety:** `updateLocalMeta` acquires `delegate.mu` and calls the closure. The entire read-dedup-append-Seq++ is atomic. No new locks. No double-locking (we don't hold `g.mu` — this is intentionally lock-free because the delegate provides its own synchronization).

---

## 5. Bug Fixes Required (Pre-requisites)

### 5.1 events.go NotifyUpdate: Cache Overwrite Bug (CRITICAL)

**Current code** (events.go:252-316) has a subtle bug:

```go
func (e *meshEventDelegate) NotifyUpdate(node *memberlist.Node) {
    // ...
    e.mu.Lock()

    // Stale check — reads existing from cache (CORRECT)
    if existing, ok := e.metaCache[meta.PublicKey]; ok && existing.Seq > meta.Seq {
        e.mu.Unlock()
        return
    }

    // Updates cache with NEW meta
    e.metaCache[meta.PublicKey] = meta   // ─── line 272 ───

    // ... capability pool updates ...

    // Endpoint change detection — BUG: reads back the just-updated meta
    if existing, ok := e.metaCache[meta.PublicKey]; ok {  // ─── line 292 ───
        newEndpoint := firstNonEmpty(meta.Endpoints)       // always == oldEndpoint
        oldEndpoint := firstNonEmpty(existing.Endpoints)
        if newEndpoint != "" && newEndpoint != oldEndpoint {
            e.mu.Unlock()
            e.wg.UpdateEndpoint(meta.PublicKey, newEndpoint)
        } else {
            e.mu.Unlock()
        }
    }
```

**Root cause:** `existing` on line 292 is a NEW variable (fresh `if` scope), and `e.metaCache[meta.PublicKey]` now returns the new meta (just stored on line 272). So `existing.Endpoints == meta.Endpoints` always — the endpoint change detection never triggers.

**Fix:**

```go
func (e *meshEventDelegate) NotifyUpdate(node *memberlist.Node) {
    meta, err := ParseNodeMeta(node)
    if err != nil {
        log.Printf("[p2p] NotifyUpdate: failed to parse metadata for %s: %v", node.Name, err)
        return
    }

    if e.isSelf(meta.PublicKey) {
        return
    }

    e.mu.Lock()

    // Capture OLD endpoint BEFORE updating the cache.
    oldEndpoint := ""
    if existing, ok := e.metaCache[meta.PublicKey]; ok {
        if existing.Seq > meta.Seq {
            e.mu.Unlock()
            return // stale
        }
        oldEndpoint = firstNonEmpty(existing.Endpoints)
    }

    // Update cached metadata.
    e.metaCache[meta.PublicKey] = meta

    // ... capability pool updates (unchanged) ...

    // Endpoint change detection — NOW uses captured oldEndpoint.
    newEndpoint := firstNonEmpty(meta.Endpoints)
    if newEndpoint != "" && newEndpoint != oldEndpoint {
        e.mu.Unlock()
        if err := e.wg.UpdateEndpoint(meta.PublicKey, newEndpoint); err != nil {
            log.Printf("[p2p] NotifyUpdate: failed to update endpoint for %s: %v",
                meta.PublicKey[:8], err)
        }
    } else {
        e.mu.Unlock()
    }

    // Invoke external update handler.
    e.mu.RLock()
    updateHdl := e.updateHandler
    e.mu.RUnlock()
    if updateHdl != nil {
        updateHdl(meta)
    }
}
```

**Verification:** This bug was confirmed via source review. The fix ensures that when a remote node's `NodeMeta.Endpoints` transitions from `[]` to `["1.2.3.4:51820"]`, WireGuard's peer endpoint is updated.

### 5.2 Type Safety: `eps[i].DstToString()` Usage

The current code uses `eps[i].DstToString()` as both an obfuscator lookup key AND as the "peerKey" variable — but `obfuscators` is keyed by public key, not endpoint. This is a pre-existing mismatch (noted in the comment at obfuscation.go:786-792). The `endpointToPeer` reverse index partially addresses this by providing the correct public key for the notifier. A future task should also fix the obfuscator lookup to use the reverse index.

**This is NOT a blocker for endpoint learning** — the existing obfuscator lookup works because:
- For peers with `ObfuscationNone`, the default return (line 791) is correct
- For peers with active obfuscation, the obfuscator map is actually keyed by endpoint address at runtime (because `SetObfuscatorWithConfig` keys by public key but `wrapReceiveFunc` looks up by endpoint — they never match, so all peers fall through to the `ObfuscationNone` default)

This is a pre-existing correctness issue. Documenting it here for awareness but not fixing it in this spec (scope boundary).

---

## 6. Edge Cases & Error Handling

| Scenario | Behavior |
|----------|----------|
| **Packet from unknown endpoint** | `endpointToPeer[srcEndpoint]` returns zero value. Notifier is NOT called. |
| **Duplicate endpoint (keepalive)** | `updateLocalMeta` closure detects existing entry in `Endpoints`, returns without incrementing `Seq`. No gossip propagation. |
| **Endpoint changes (NAT rebinding)** | New endpoint → not in set → appended. Old endpoint stays (garbage-collected in future iteration). `Seq` increments → gossip propagates. Remote peers try the first non-empty endpoint. |
| **Multiple endpoints (multi-homed)** | Multiple entries in `Endpoints`. Remote peers use `firstNonEmpty()` to pick the first. Future: latency-based selection. |
| **Notifier is nil** | `wrapReceiveFunc` skips the notification. Existing behavior preserved. Default: nil (endpoint learning disabled until wired). |
| **Race: concurrent discoveries** | `updateLocalMeta` is serialized by delegate mutex. Only one discovery wins per Seq increment; correct ordering is guaranteed. |
| **High-frequency packets (transport data)** | Each received packet calls `OnEndpointDiscovered`. Dedup in `updateLocalMeta` closure is O(len(Endpoints)) — typically 1-3 entries, negligible. If this becomes a bottleneck with 100+ peers, add a `map[string]struct{}` dedup cache with 30s TTL as a future optimization. |
| **Node behind NAT with changing port** | Each new port mapping is treated as a new endpoint. Old endpoint stays. Since the old port mapping is likely stale, remote peers will fail to handshake on the old endpoint and fall through to the new one on retry. |
| **GossipLayer not started yet** | `node.ObfuscatingBind().SetEndpointNotifier(gossipLayer)` is called before `gossipLayer.Start()`. Packets may arrive before gossip starts. `OnEndpointDiscovered` calls `updateLocalMeta` which safely updates local metadata; memberlist will propagate on next PushPull cycle once started. |

---

## 7. Implementation Plan

### Phase 1: Bug Fix (blocker)
- Fix `events.go NotifyUpdate` cache overwrite bug (§5.1)
- Unit test: mock remote node with two sequential updates where Endpoints changes from empty to non-empty; assert `UpdateEndpoint` is called

### Phase 2: Core Interface
- Define `EndpointNotifier` interface in `internal/mesh/obfuscation.go`
- Add `notifier`, `endpointToPeer`, `epMu` fields to `obfuscatingBind`
- Add `SetEndpointNotifier()`, `AddEndpointMapping()` methods
- Add `ObfuscatingBind()` accessor to `MeshNode` in `internal/mesh/node.go`

### Phase 3: Receive Path
- Modify `wrapReceiveFunc` to call `notifier.OnEndpointDiscovered()` when source endpoint matches a known peer
- Add `AddEndpointMapping` call in `MeshNode.AddPeer` when `cfg.Endpoint != ""`

### Phase 4: GossipLayer Implementation
- Add `OnEndpointDiscovered(peerKey, endpoint string)` to `GossipLayer`
- Add `inferNAT()` helper in `internal/p2p/nat.go`
- GossipLayer now satisfies `mesh.EndpointNotifier`

### Phase 5: Wiring
- In `main.go`, after `gossipLayer = gl`: `node.ObfuscatingBind().SetEndpointNotifier(gossipLayer)`

### Phase 6: Testing
- Unit test: mock `EndpointNotifier` receives correct (peerKey, endpoint) when `wrapReceiveFunc` processes a packet
- Unit test: `GossipLayer.OnEndpointDiscovered` calls `SetLocalEndpoints` via `updateLocalMeta`
- Unit test: `NotifyUpdate` fix — endpoint change triggers `UpdateEndpoint` call
- Integration test: two-node mesh, peer A sends packet to shared node S, S's `NodeMeta.Endpoints` becomes non-empty, peer B receives gossip update and WireGuard peer endpoint is set

### Effort Estimates

| Phase | Files changed | Lines | Risk |
|-------|--------------|-------|------|
| 1 (bug fix) | 1 | ~20 | Low — well-understood logic fix |
| 2 (interface) | 2 | ~60 | Low — new code, no behavioral change |
| 3 (receive path) | 2 | ~30 | Medium — hot path modification; need perf test |
| 4 (gossip impl) | 2 | ~40 | Low — delegates to existing `updateLocalMeta` |
| 5 (wiring) | 1 | ~5 | Trivial |
| 6 (testing) | 3 | ~150 | Medium — integration tests need two-node setup |
| **Total** | **~6 files** | **~305 lines** | |

---

## 8. Acceptance Criteria (Definition of Done)

- [ ] **AC-1:** `EndpointNotifier` interface defined in `internal/mesh/obfuscation.go` with single method `OnEndpointDiscovered(peerKey, endpoint string)`
- [ ] **AC-2:** `obfuscatingBind` gains `notifier` field, `endpointToPeer` map, `epMu` mutex, `SetEndpointNotifier()`, and `AddEndpointMapping()` methods
- [ ] **AC-3:** `MeshNode.ObfuscatingBind()` accessor returns the `*obfuscatingBind`
- [ ] **AC-4:** `wrapReceiveFunc` calls `notifier.OnEndpointDiscovered()` when source endpoint maps to a known peer in `endpointToPeer`
- [ ] **AC-5:** `MeshNode.AddPeer()` calls `AddEndpointMapping()` when peer config has a non-empty endpoint
- [ ] **AC-6:** `GossipLayer` implements `mesh.EndpointNotifier`; `OnEndpointDiscovered` calls `updateLocalMeta` with dedup and `inferNAT`
- [ ] **AC-7:** `main.go` wires `node.ObfuscatingBind().SetEndpointNotifier(gossipLayer)` after gossip layer creation
- [ ] **AC-8:** `events.go NotifyUpdate` bug fixed — captures old endpoint before cache update; endpoint change triggers `UpdateEndpoint`
- [ ] **AC-9:** Unit test: mock `EndpointNotifier` receives correct values when `wrapReceiveFunc` processes a packet from a mapped endpoint
- [ ] **AC-10:** Unit test: `GossipLayer.OnEndpointDiscovered` with duplicate endpoint does NOT increment `Seq`
- [ ] **AC-11:** Unit test: `NotifyUpdate` with changed Endpoints → `UpdateEndpoint` called; with unchanged Endpoints → `UpdateEndpoint` NOT called
- [ ] **AC-12:** Integration test: two-node setup — node A sends packet to shared node S → S's `NodeMeta.Endpoints` becomes non-empty → memberlist propagates → node B's WireGuard peer endpoint is updated
- [ ] **AC-13:** No performance regression: `wrapReceiveFunc` throughput within 5% of baseline (benchmark existing vs with notifier enabled)
- [ ] **AC-14:** Thread safety: `go test -race ./internal/mesh/... ./internal/p2p/...` passes clean

---

## 9. Scope Boundaries (What We Are NOT Doing)

- **NOT** rewriting MeshDesk to use EasyTier's Tunnel+PeerConn model (architectural scope boundary)
- **NOT** implementing latency-based endpoint selection in `firstNonEmpty` (v2 enhancement)
- **NOT** auto-garbage-collecting stale endpoints (v2 enhancement — current design appends, never removes)
- **NOT** hooking into wireguard-go internals for handshake completion callbacks (too invasive; the `endpointToPeer` reverse index approach is sufficient)
- **NOT** implementing STUN-based NAT type detection (separate task under NatTraversal module)
- **NOT** implementing per-peer endpoint tracking on the shared node (this spec learns LOCAL endpoints; learning REMOTE peer endpoints is a follow-up task)
- **NOT** fixing the obfuscator key mismatch (obfuscators keyed by public key but looked up by endpoint) — separate task, not a blocker for endpoint learning

---

## 10. Follow-up Tasks (Kanban Candidates)

After this spec is implemented and AC-1 through AC-14 pass:

1. **t_next_1: STUN endpoint discovery** — NatTraversal performs STUN, calls `SetLocalEndpoints` with verified public endpoint + accurate NAT type, replacing the `inferNAT` heuristic
2. **t_next_2: Per-peer endpoint tracking** — Shared node S maintains `map[peerKey → []endpoint]` for ALL peers it has seen packets from, propagates via gossip; this completes the EasyTier introducer model
3. **t_next_3: Obscuration key fix** — Fix the `GetObfuscator` lookup to use `endpointToPeer` reverse index instead of direct endpoint string; corrects the obfuscation mode selection for all peers
4. **t_next_4: Endpoint garbage collection** — Periodically prune endpoints that haven't been seen in >5 minutes (requires timestamp tracking per endpoint)
5. **t_next_5: NAT hole-punch integration** — After learning a remote peer's endpoint via gossip, attempt UDP hole-punch before falling back to relay

---

## Appendix A: Existing Code References

| File | Lines | Relevant content |
|------|-------|-----------------|
| `internal/mesh/obfuscation.go` | 739-748 | `obfuscatingBind` struct — add notifier + endpointToPeer fields |
| `internal/mesh/obfuscation.go` | 760-774 | `SetObfuscator` / `SetObfuscatorWithConfig` — natural place for AddEndpointMapping |
| `internal/mesh/obfuscation.go` | 962-987 | `wrapReceiveFunc` — insertion point for notifier call |
| `internal/mesh/node.go` | 29-45 | `MeshNode` struct — `bind *obfuscatingBind` field (private) |
| `internal/mesh/node.go` | 326-397 | `AddPeer` — calls SetObfuscatorWithConfig; has cfg.Endpoint available |
| `internal/p2p/gossip.go` | 18-40 | `GossipLayer` struct — implements EndpointNotifier |
| `internal/p2p/gossip.go` | 132-139 | `SetLocalEndpoints` — updates NodeMeta.Endpoints + Seq |
| `internal/p2p/events.go` | 252-316 | `NotifyUpdate` — receives gossip metadata, updates WireGuard endpoint (BUG: §5.1) |
| `internal/p2p/wg_delegate.go` | 207-233 | `UpdateEndpoint` — WireGuard UAPI in-place endpoint update |
| `cmd/meshdesk/main.go` | 95-135 | GossipLayer creation — registration point |

## Appendix B: Key Design Decisions Log

| Decision | Rationale | Date |
|----------|-----------|------|
| Use `AddEndpointMapping` separate from `SetObfuscatorWithConfig` | Non-breaking; avoids changing 6+ test file call sites | 2026-07-27 |
| Notifier call AFTER deobfuscation, not before | Deobfuscation failure drops the packet (sizes[i]=0); notifying before deobfuscation would fire on garbage packets | 2026-07-27 |
| `GossipLayer.OnEndpointDiscovered` ignores `peerKey` parameter | Current scope is LOCAL endpoint learning (what endpoints we can be reached at); per-peer tracking is follow-up | 2026-07-27 |
| `inferNAT` returns "restricted_cone" | Conservative default; STUN recalibrates later; no false "full_cone" claims that would mislead NAT traversal | 2026-07-27 |
| Not fixing obfuscator key mismatch in this spec | Separate concern; `ObfuscationNone` default handles the mismatch for non-obfuscated peers; fixing it is v2 | 2026-07-27 |
