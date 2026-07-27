# MeshDesk Endpoint Learning + Dashboard Config Management — Design Spec

**Version:** 1.0
**Author:** architect
**Date:** 2026-07-27
**Source:** motion-c642d60e9a8d, action item 1/5
**Status:** draft — pending team review

---

## Table of Contents

1. [Motivation](#motivation)
2. [EndpointNotifier: Interface & Callback Chain](#endpointnotifier-interface--callback-chain)
   - 2.1 [Interface Contract](#21-interface-contract)
   - 2.2 [Callback Chain](#22-callback-chain)
   - 2.3 [Registration Point](#23-registration-point)
   - 2.4 [Thread Safety](#24-thread-safety)
   - 2.5 [Edge Cases](#25-edge-cases)
3. [Dashboard Config Management REST API](#dashboard-config-management-rest-api)
   - 3.1 [API Surface: Per-Section Endpoints](#31-api-surface-per-section-endpoints)
   - 3.2 [Hot-Reload Semantics](#32-hot-reload-semantics)
   - 3.3 [Security Classification](#33-security-classification)
   - 3.4 [Response Schema](#34-response-schema)
   - 3.5 [Validation Rules](#35-validation-rules)
4. [Implementation Order](#implementation-order)
5. [Acceptance Criteria](#acceptance-criteria)

---

## 1. Motivation

### 1.1 The Endpoint Gap

MeshDesk's P2P networking uses two separate systems:

1. **WireGuard (wireguard-go)** — encrypts packets, learns peer endpoints from UDP source addresses
2. **memberlist (hashicorp)** — gossip discovery, propagates `NodeMeta` (including `Endpoints` field)

The bridge between them is **never called.** The code defines `GossipLayer.SetLocalEndpoints()` (line 133 of `gossip.go`) but nothing in the receive path invokes it. As a result:

- `NodeMeta.Endpoints` stays `[]string{}` on all nodes
- `events.go:firstNonEmpty(meta.Endpoints)` returns `""`
- `wgDelegate.AddDynamicPeer()` passes an empty endpoint to WireGuard
- Peers added via gossip cannot establish WireGuard handshakes (no destination endpoint)

EasyTier avoids this problem entirely because its Tunnel + PeerConn model learns endpoints directly from the connection's source address. MeshDesk must bridge this gap within its existing WireGuard + memberlist architecture.

### 1.2 The Dashboard Config Gap

The Dashboard UI has **zero** config editing capability. All 11 config sections (`config.go`, `CONFIG_INVENTORY.md`) are loaded once at startup; changes require manual YAML editing + process restart. `config.Save()` exists but is never wired to an HTTP endpoint. There is no hot-reload mechanism.

---

## 2. EndpointNotifier: Interface & Callback Chain

### 2.1 Interface Contract

A single-method interface in `internal/mesh/obfuscation.go`:

```go
// EndpointNotifier is called when the obfuscatingBind receives a WireGuard
// packet and learns the source endpoint. Implementations bridge this
// information to the gossip layer for propagation.
type EndpointNotifier interface {
    // OnEndpointDiscovered is called when a WireGuard packet arrives from
    // a peer. The peerKey is the hex public key (looked up by endpoint
    // match), and endpoint is the source address (host:port).
    //
    // Implementation contract:
    //   - MUST be non-blocking (spawn a goroutine or use a channel if work
    //     is expensive — this is called from the WireGuard receive hot path).
    //   - MUST be idempotent for repeated calls with the same (peerKey, endpoint).
    //   - MAY be called concurrently from multiple receive goroutines.
    //   - peerKey may be "" if the obfuscatingBind cannot map the source
    //     endpoint to a known peer. Implementations should ignore empty keys.
    OnEndpointDiscovered(peerKey string, endpoint string)
}
```

**Design rationale:**

| Decision | Why |
|----------|-----|
| Single method, not multi-method interface | Only one event source; YAGNI |
| Non-blocking contract | Hot path — WireGuard receive goroutines must not block |
| Idempotent | WireGuard sends keepalive/transport packets frequently; duplicate notifications are expected |
| peerKey may be "" | The obfuscatingBind may receive packets from unknown sources (misconfigured peers, probes); notifier must handle gracefully |
| In obfuscation.go, not p2p package | The obfuscatingBind is the source of truth for endpoint learning; the notifier interface lives where the data originates |

### 2.2 Callback Chain

The complete data flow:

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. WireGuard Receives UDP Packet                                    │
│    wireguard-go's DefaultBind receives a UDP datagram               │
│    Source address: e.g., 203.0.113.5:51820                         │
│    Destination: this node's mesh IP:port                            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 2. obfuscatingBind.wrapReceiveFunc                                  │
│    (internal/mesh/obfuscation.go:962)                               │
│                                                                     │
│    for each received packet:                                        │
│      eps[i] = conn.Endpoint (source addr from UDP)                  │
│      peerKey = eps[i].DstToString()    // "203.0.113.5:51820"      │
│      obfuscator = GetObfuscator(peerKey)                            │
│      unwrapped = obfuscator.UnwrapInbound(packet)                   │
│                                                                     │
│    ─── NEW LOGIC ───                                                │
│    if b.notifier != nil && sizes[i] > 0 {                            │
│        srcEndpoint := eps[i].(conn.StdNetEndpoint).String()         │
│        // Look up the peer's public key from the endpoint.          │
│        // The obfuscatingBind has a reverse index:                  │
│        //   endpointMap: map[string]string  // endpoint → peerKey  │
│        peerKey := b.endpointToPeer(srcEndpoint)                     │
│        if peerKey != "" {                                           │
│            b.notifier.OnEndpointDiscovered(peerKey, srcEndpoint)    │
│        }                                                            │
│    }                                                                │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 3. GossipLayer (implements EndpointNotifier)                        │
│    (internal/p2p/gossip.go)                                        │
│                                                                     │
│    func (g *GossipLayer) OnEndpointDiscovered(peerKey, endpoint string) { │
│        // Build the local endpoint list from all discovered         │
│        // endpoints. Deduplicate against existing set.              │
│        g.mu.Lock()                                                  │
│        current := g.localMeta.Endpoints                             │
│        if !contains(current, endpoint) {                            │
│            newEndpoints := append(current, endpoint)                │
│            g.mu.Unlock()                                            │
│            g.SetLocalEndpoints(newEndpoints, "full_cone")           │
│        } else {                                                     │
│            g.mu.Unlock()                                            │
│        }                                                            │
│    }                                                                │
│                                                                     │
│    SetLocalEndpoints updates NodeMeta.Endpoints and increments Seq. │
│    This triggers memberlist to propagate the updated metadata to    │
│    all peers in the cluster via PushPull + indirect broadcasts.     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 4. memberlist Gossip Propagation                                    │
│    (hashicorp/memberlist library)                                   │
│                                                                     │
│    NodeMeta.Endpoints = ["203.0.113.5:51820", ...]                 │
│    Seq incremented → memberlist detects change → PushPull to peers │
│    Or: periodic PushPullInterval (default 30s) picks up delta      │
│                                                                     │
│    Remote nodes receive the updated NodeMeta.                       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 5. meshEventDelegate.NotifyUpdate                                   │
│    (internal/p2p/events.go:252)                                     │
│                                                                     │
│    Called by memberlist when a remote node's metadata changes.      │
│    Checks:                                                          │
│      - Is this a stale update? (existing.Seq > meta.Seq → ignore)   │
│      - Did the Endpoints field change?                              │
│      - If yes → PeerManager.UpdateEndpoint(publicKey, newEndpoint)  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 6. WireGuardDelegate.UpdateEndpoint                                 │
│    (internal/p2p/wg_delegate.go:207)                                │
│                                                                     │
│    Uses WireGuard UAPI to update the peer's endpoint in-place:      │
│      ipc = "public_key=<hex>\nendpoint=<host:port>\n"               │
│      device.IpcSet(ipc)                                             │
│                                                                     │
│    WireGuard now has a destination endpoint → can send handshake.   │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.3 Registration Point

Two additions to `obfuscatingBind`:

```go
// In obfuscatingBind struct (obfuscation.go:739):
type obfuscatingBind struct {
    // ... existing fields ...

    // notifier is called when a source endpoint is learned.
    // nil when not registered (default — endpoint learning disabled).
    notifier EndpointNotifier

    // endpointToPeer maps "host:port" → hex public key.
    // Populated by SetObfuscator / SetObfuscatorWithConfig when a peer's
    // obfuscator is registered. Used by wrapReceiveFunc to reverse-lookup
    // the public key from the source endpoint.
    endpointToPeer map[string]string
    epMu           sync.RWMutex  // guards endpointToPeer
}

// SetEndpointNotifier installs the endpoint learning notifier.
// Pass nil to disable (default).
func (b *obfuscatingBind) SetEndpointNotifier(n EndpointNotifier) {
    b.mu.Lock()
    defer b.mu.Unlock()
    b.notifier = n
}
```

**The `endpointToPeer` map** is populated when `SetObfuscatorWithConfig` is called — each peer added to the obfuscatingBind has a known endpoint (from static config or from gossip). This reverse index enables the `wrapReceiveFunc` to look up the public key from the source endpoint.

**Alternative considered:** Walking the `obfuscators` map and comparing endpoint strings. Rejected — O(n) per packet vs O(1) map lookup. On a mesh with 50 peers receiving keepalives every 10s, this matters.

**Registration in main.go wiring:**

```go
// In NewGossipLayer, after the obfuscatingBind is created:
gossipLayer := &GossipLayer{...}
node.Bind().SetEndpointNotifier(gossipLayer)
// GossipLayer implements EndpointNotifier
```

### 2.4 Thread Safety

| Component | Concurrency model | Protocol |
|-----------|-------------------|----------|
| `obfuscatingBind.wrapReceiveFunc` | Called by wireguard-go receive goroutines (potentially multiple) | Already holds no locks; reads `notifier` under `b.mu.RLock` |
| `GossipLayer.OnEndpointDiscovered` | Called from receive goroutines | Takes `g.mu.Lock` briefly; calls `SetLocalEndpoints` which takes `g.mu.Lock` again → use a helper that assumes lock is held |
| `meshEventDelegate.NotifyUpdate` | Called by memberlist goroutines | Already holds `e.mu` lock |
| `WireGuardDelegate.UpdateEndpoint` | Called by event delegate | Takes `d.mu.Lock` |

**GossipLayer.OnEndpointDiscovered implementation note:** Must avoid double-locking. The current `SetLocalEndpoints` calls `updateLocalMeta` which locks `delegate.mu`. `OnEndpointDiscovered` should use a non-locking variant or call `SetLocalEndpoints` unlocked:

```go
func (g *GossipLayer) OnEndpointDiscovered(peerKey, endpoint string) {
    // We're called from WireGuard receive path. Do minimal work here.
    // Deduplication: check if this endpoint is already known.
    g.mu.Lock()
    for _, ep := range g.localMeta.Endpoints {
        if ep == endpoint {
            g.mu.Unlock()
            return // already known
        }
    }
    g.mu.Unlock()

    // New endpoint discovered — update gossip metadata.
    g.SetLocalEndpoints(
        append(g.localMeta.Endpoints, endpoint),
        "full_cone",
    )
}
```

But there's a race: `g.localMeta.Endpoints` could change between the read and the `SetLocalEndpoints` call. The fix is to use a `compare-and-update` helper:

```go
func (g *GossipLayer) OnEndpointDiscovered(peerKey, endpoint string) {
    // Acquire delegate lock once.
    g.delegate.updateLocalMeta(func(m *NodeMeta) {
        for _, ep := range m.Endpoints {
            if ep == endpoint {
                return // already known, seq not incremented
            }
        }
        m.Endpoints = append(m.Endpoints, endpoint)
        m.NatType = "full_cone" // learned from direct packet receipt
        m.Seq++
    })
}
```

This is safe: `updateLocalMeta` holds the delegate lock, so the read-modify-write is atomic.

### 2.5 Edge Cases

| Scenario | Behavior |
|----------|----------|
| **Packet from unknown endpoint** | `endpointToPeer[srcEndpoint]` returns `""`. Notifier is not called. |
| **Duplicate endpoint (keepalive)** | `updateLocalMeta` closure detects existing entry, returns without incrementing `Seq`. No gossip propagation. |
| **endpoint changes (roaming node)** | New endpoint → new entry appended. Old endpoint stays until garbage-collected (future enhancement). `Seq` increments → gossip propagates. |
| **Multiple endpoints (NAT, multi-homed)** | Multiple entries in `Endpoints`. Peer nodes use `firstNonEmpty()` to pick the first. Future: latency-based selection. |
| **Notifier is nil** | `wrapReceiveFunc` skips the notification. Existing behavior preserved. |
| **Race: concurrent discoveries** | `updateLocalMeta` is serialized by delegate mutex. Only one discovery wins; Seq ensures correct ordering. |
| **High-frequency packets (transport data)** | Each packet calls `OnEndpointDiscovered`. Dedup in `updateLocalMeta` closure is O(len(Endpoints)) — typically 1-2 entries. Acceptable. If this becomes a bottleneck in large meshes, add a `map[string]struct{}` dedup cache with a 30s TTL. |

---

## 3. Dashboard Config Management REST API

### 3.1 API Surface: Per-Section Endpoints

Based on `CONFIG_INVENTORY.md` analysis of 11 config sections and ~90 leaf fields.

All endpoints require authentication (`requireAuth` middleware). Sensitive operations require step-up auth (`requireStepUp`).

```
# Per-section CRUD
GET    /api/config                    → Full config (secrets masked)
GET    /api/config/{section}          → Single section
PUT    /api/config/{section}          → Update single section (partial merge)
POST   /api/config/peers              → Add a new peer
DELETE /api/config/peers/{public_key} → Remove a peer

# Hot-reload control
POST   /api/config/reload             → Trigger hot-reload of all compatible sections
GET    /api/config/status             → Sections needing restart vs live

# Validation
POST   /api/config/validate           → Dry-run validation without applying
```

**Section keys:** `node`, `mesh`, `peers`, `p2p`, `monitoring`, `webssh`, `auth`, `transfer`, `proxy`, `xray`, `reality`

**Section-specific endpoints (recommended for frontend simplicity):**

```
GET  /api/config/node                 → { identity: "***masked***", hostname: "oracle-1", web: ":8080", position: {...} }
PUT  /api/config/node                 → body: { hostname: "new-name" }  (partial merge; identity is read-only)
GET  /api/config/mesh                 → { port: 51820, gossip_port: 7946 }
PUT  /api/config/mesh                 → body: { port: 51821 }
GET  /api/config/peers               → [{ public_key: "abc...", endpoint: "...", ... }, ...]
POST /api/config/peers               → body: { public_key: "...", endpoint: "...", ... }
DELETE /api/config/peers/{key}        → (requires step-up)
GET  /api/config/p2p                 → { enabled: true, seeds: [...], ... }
PUT  /api/config/p2p                 → body: { seeds: ["10.10.0.1:7946"] }
GET  /api/config/monitoring          → { collectors: [...], interval: 15, port: 4191 }
PUT  /api/config/monitoring          → body: { interval: 30 }
GET  /api/config/webssh             → { port: 2222, max_sessions: 256, ... }
PUT  /api/config/webssh             → body: { max_sessions: 512 }
GET  /api/config/auth               → { web_users: [...], totp_issuer: "MeshDesk", ... }
PUT  /api/config/auth               → body: { totp_issuer: "MyMesh" }  (web_users requires /api/2fa/* for password changes)
GET  /api/config/transfer           → { max_file_size: 1073741824, upload_dir: "/tmp/meshdesk-uploads/" }
PUT  /api/config/transfer           → body: { max_file_size: 2147483648 }
GET  /api/config/proxy              → { chunker_strategy: "bounded-4k-64k", ... }
PUT  /api/config/proxy              → body: { chunker_strategy: "fixed-16k" }
GET  /api/config/xray               → { enabled: false, binary_path: "", ... }
PUT  /api/config/xray               → body: { enabled: true, binary_path: "/usr/bin/xray" }
GET  /api/config/reality            → { enabled: false, dest: "www.apple.com:443", ... }
PUT  /api/config/reality            → body: { dest: "www.cloudflare.com:443" }

# Bulk operations
GET  /api/config                    → All sections, secrets masked
PUT  /api/config                    → Full config replace (step-up required, validates all sections)
```

### 3.2 Hot-Reload Semantics

**Config sections fall into three categories:**

| Category | Sections | Behavior |
|----------|----------|----------|
| **Live-reloadable** | `p2p` (gossip params), `monitoring` (interval), `webssh` (timeouts), `transfer`, `proxy` (tuning), `auth` (non-user fields), `xray` (runtime params), `reality` (non-listen fields) | Applied immediately via `ConfigNotifier` interface |
| **Restart-required** | `mesh` (port), `node` (identity, web addr), `peers` (structural changes), `reality` (listen_addr/port), `xray` (binary_path) | Saved to config.yaml; banner shown in UI: "Restart required for: mesh port, reality config" |
| **Read-only via this API** | `auth.web_users` (password management), `node.identity` (private key), `reality.private_key`, `proxy.ss.password` | Managed via dedicated endpoints (`/api/2fa/*`, `/api/xray/*`); not exposed through config CRUD |

**ConfigNotifier interface:**

```go
// ConfigNotifier is implemented by subsystems that support hot-reload.
// Registered at startup via a registry so the config API can fan out
// section updates to the right subsystems.
type ConfigNotifier interface {
    // NotifyConfigChanged is called when a config section is updated.
    // The section parameter is the YAML key (e.g., "p2p", "monitoring").
    // Returns a list of sections that still require a restart.
    NotifyConfigChanged(section string, newCfg *Config) []string
}
```

**Subsystem implementations:**

| Subsystem | Supports hot-reload | What happens |
|-----------|---------------------|--------------|
| MeshNode | Partial | Port change → restart required. Other fields → no-op. |
| GossipLayer | Yes | `gossip_interval`, `probe_interval`, `max_peers` → reconfigure timers via channel. `seeds` → restart required (join is one-shot). |
| WebServer | No (current) | Tuning params (timeouts, limits) → could be added later. P1. |
| TOTPStore | Yes | `totp_issuer` → regenerates enrollment QR codes. `require_2fa` → updates enforcement. |
| ProxyEntry | Yes | `chunker_strategy`, `circuit.*` timeouts → reconfigure via atomic.Value or channel. |
| XrayManager | Partial | `enabled`, `binary_path` → restart required (subprocess lifecycle). Runtime params → `SIGHUP` reload via xray UAPI. |
| RealityListener | No | All fields → restart required (listener bind is one-shot). |

**`POST /api/config/reload` flow:**

```
1. Read existing config from disk (handle concurrent edits)
2. For each section marked "changed" since last reload:
   a. If live-reloadable: call notifier.NotifyConfigChanged(section, cfg)
   b. If restart-required: skip, add to "restart_needed" list
3. Return JSON: { "applied": ["p2p", "monitoring"], "restart_needed": ["mesh"] }
4. UI shows green checkmarks for applied, orange banner for restart_needed
```

### 3.3 Security Classification

Based on `CONFIG_INVENTORY.md` §4.

**Masking rules for GET responses:**

| Field | GET behavior |
|-------|-------------|
| `node.identity` (private key) | `"***masked (64 chars)***"` — never exposed |
| `reality.private_key` | `"***masked (64 chars)***"` |
| `proxy.ss.password` | `"***masked***"` |
| `peers[].preshared_key` | `"***masked***"` |
| `peers[].obf_config.psk` | `"***masked***"` |
| `reality.short_ids` | `"***masked (N entries)***"` |
| `auth.web_users[].password_hash` | `"***bcrypt_hash***"` |
| All other fields | Return actual value |

**Step-up auth requirements:**

| Operation | Step-up required? |
|-----------|------------------|
| GET any section | No |
| PUT tuning params (p2p intervals, webssh timeouts, etc.) | No |
| PUT peer config (add/remove/change endpoint) | No |
| DELETE peer | **Yes** (OpConfigWrite) |
| PUT full config (`PUT /api/config`) | **Yes** (OpConfigWrite) |
| PUT security-sensitive fields (auth.require_2fa, auth.web_users) | **Yes** (OpConfigWrite) |
| POST /api/config/reload | No |

### 3.4 Response Schema

**Success (200):**
```json
{
  "ok": true,
  "section": "p2p",
  "applied": ["gossip_interval", "probe_interval"],
  "restart_needed": []
}
```

**Partial success (200 with restart_needed):**
```json
{
  "ok": true,
  "section": "mesh",
  "applied": [],
  "restart_needed": ["mesh.port"],
  "message": "Config saved. Restart required for changes to take effect."
}
```

**Validation error (422):**
```json
{
  "ok": false,
  "error": "validation_failed",
  "fields": {
    "mesh.port": "must be between 1024 and 65535",
    "p2p.gossip_interval": "must be at least 5 seconds"
  }
}
```

**Auth error (401/403):**
```json
{
  "ok": false,
  "error": "step_up_required",
  "operation": "OpConfigWrite"
}
```

### 3.5 Validation Rules

Enforced at `PUT` time, before saving:

| Section.Field | Rule |
|---------------|------|
| `mesh.port` | 1024 ≤ port ≤ 65535 |
| `mesh.gossip_port` | 1024 ≤ port ≤ 65535, ≠ mesh.port |
| `p2p.gossip_interval` | ≥ 5 seconds |
| `p2p.gossip_probe_interval` | ≥ 1 second |
| `p2p.max_peers` | 1 ≤ max ≤ 65535 |
| `p2p.relay_mode` | enum: "auto", "manual", "disabled" |
| `p2p.join_approval` | enum: "auto", "manual" |
| `peers[].public_key` | 64-char hex string |
| `peers[].obfuscation` | enum: "none", "padded", "websocket", "reality" |
| `peers[].endpoint` | host:port format or empty |
| `monitoring.interval` | ≥ 5 seconds |
| `webssh.port` | 1024 ≤ port ≤ 65535 |
| `webssh.max_sessions` | 1 ≤ max ≤ 10000 |
| `auth.require_2fa` | Cannot be enabled if no users have TOTP enrolled |
| `transfer.max_file_size` | ≥ 0 (0 = unlimited) |
| `proxy.chunker_strategy` | enum: "fixed-16k", "bounded-4k-64k" |
| `xray.binary_path` | If enabled, must point to existing binary or be empty (auto-detect) |
| `reality.dest` | host:port format |
| `reality.server_names` | Non-empty when enabled |

---

## 4. Implementation Order

| Phase | Component | Dependencies | Effort |
|-------|-----------|-------------|--------|
| **Phase 1** | `EndpointNotifier` interface + `obfuscatingBind` wiring | None (pure interface definition) | Small (2 files, ~80 lines) |
| **Phase 2** | `endpointToPeer` reverse index in `obfuscatingBind` | Phase 1 | Small (1 file, ~30 lines) |
| **Phase 3** | `GossipLayer.OnEndpointDiscovered` implementation | Phase 2 | Small (1 file, ~25 lines) |
| **Phase 4** | Wiring in main.go: `node.Bind().SetEndpointNotifier(gossipLayer)` | Phase 3 | Trivial (1 line) |
| **Phase 5** | Dashboard config GET endpoints (all 11 sections) | None | Medium (2 files, ~200 lines) |
| **Phase 6** | Dashboard config PUT endpoints + validation | Phase 5 | Medium (2 files, ~300 lines) |
| **Phase 7** | `ConfigNotifier` interface + hot-reload plumbing | Phase 6 | Medium (3 files, ~150 lines) |
| **Phase 8** | Subsystem hot-reload implementations (GossipLayer, TOTP, Proxy) | Phase 7 | Medium per subsystem |
| **Phase 9** | `POST /api/config/reload` + `GET /api/config/status` | Phase 8 | Small |
| **Phase 10** | Frontend config page (form-based, section tabs) | Phase 5-9 | Large (frontend task) |

**Recommended parallelization:**
- Phases 1-4 (endpoint learning) can proceed in parallel with Phases 5-6 (config GET/PUT)
- Phases 7-9 build on Phase 6
- Phase 10 is a separate frontend task

---

## 5. Acceptance Criteria

### EndpointNotifier

- [ ] `EndpointNotifier` interface defined in `internal/mesh/obfuscation.go`
- [ ] `obfuscatingBind` gains `notifier` field + `SetEndpointNotifier()` method
- [ ] `wrapReceiveFunc` calls `notifier.OnEndpointDiscovered()` when source endpoint is mapped to a known peer
- [ ] `endpointToPeer` reverse index populated at `SetObfuscatorWithConfig` time
- [ ] `GossipLayer` implements `EndpointNotifier`; `OnEndpointDiscovered` calls `updateLocalMeta` with dedup
- [ ] Registration wired in `NewGossipLayer` → `node.Bind().SetEndpointNotifier(gossipLayer)`
- [ ] Unit test: mock notifier receives correct (peerKey, endpoint) when a WireGuard packet arrives
- [ ] Integration test: shared node receives packet → `SetLocalEndpoints` called → `NodeMeta.Endpoints` non-empty
- [ ] No performance regression: endpoint learning adds <1μs per packet on the receive path
- [ ] Thread safety: concurrent receives from multiple goroutines do not deadlock or corrupt state

### Dashboard Config Management

- [ ] `GET /api/config/{section}` returns correct data for all 11 sections
- [ ] Secrets are masked in responses (identity, private keys, passwords, PSKs, short_ids)
- [ ] `PUT /api/config/{section}` accepts partial merges (only specified fields change)
- [ ] Validation rejects invalid values with specific field-level error messages
- [ ] `POST /api/config/peers` adds a peer; `DELETE /api/config/peers/{key}` removes one
- [ ] `POST /api/config/reload` applies live-reloadable changes and returns restart-needed list
- [ ] `GET /api/config/status` shows which sections are live vs pending restart
- [ ] `config.Save()` is called after every successful PUT (durable persistence)
- [ ] Step-up auth enforced for DELETE peer and PUT full config
- [ ] Validation rejects `auth.require_2fa: true` when no users have TOTP enrolled

---

## Appendix A: Existing Code References

| File | Lines | Relevant content |
|------|-------|-----------------|
| `internal/mesh/obfuscation.go` | 962-987 | `wrapReceiveFunc` — packet receive path; insertion point for notifier call |
| `internal/mesh/obfuscation.go` | 739-748 | `obfuscatingBind` struct — where `notifier` and `endpointToPeer` fields are added |
| `internal/p2p/gossip.go` | 132-139 | `SetLocalEndpoints` — defined but never called; target for `OnEndpointDiscovered` |
| `internal/p2p/events.go` | 252-316 | `NotifyUpdate` — receives gossip metadata changes, calls `PeerManager.UpdateEndpoint` |
| `internal/p2p/wg_delegate.go` | 207-233 | `PeerManager.UpdateEndpoint` — WireGuard UAPI in-place endpoint update |
| `internal/config/config.go` | 883-900 | `config.Save` — YAML marshal + write; unwired |
| `internal/web/server.go` | 297-411 | `registerRoutes` — all existing routes; config endpoints go here |
| `docs/CONFIG_INVENTORY.md` | 1-330 | Full config field inventory, security classification, existing API list |

## Appendix B: What We're NOT Doing (Scope Boundaries)

- **NOT** rewriting MeshDesk to use EasyTier's Tunnel+PeerConn model (too invasive)
- **NOT** adding auto-garbage-collection of stale endpoints (v2 enhancement)
- **NOT** implementing latency-based endpoint selection in `firstNonEmpty` (v2 enhancement)
- **NOT** adding a config file watcher (`inotify`/`fsnotify`) for hot-reload — the API is the single source of truth
- **NOT** building the frontend config page (separate task: t_41862173 or t_da3ca54e)
- **NOT** adding version history or rollback for config changes (v2 enhancement)
