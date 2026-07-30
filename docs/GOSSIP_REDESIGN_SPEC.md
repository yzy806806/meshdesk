# MeshDesk v2 — Gossip Protocol Redesign (Gap3)

**Status:** DRAFT — for team review
**Date:** 2026-07-28
**Author:** architect
**Parent motion:** motion-856c071ce5a9 (MeshDesk v2 full rewrite)
**Action item:** 5/7 — Redesign gossip protocol without meshIP
**Depends on:** HandshakeLayer (Layer 1, FROZEN), Session (Layer 2), MultiPathSession (Layer 3)

---

## 1. Motivation: Why Remove MeshIP

### 1.1 The Problem with MeshIP in v1

v1's mesh IP model (10.10.x.y, deterministically derived from WireGuard public key)
was a convenience that masked a fundamental architectural confusion:

```
mesh IP = virtual address → routed through WireGuard → delivered to gVisor netstack
```

This created a circular dependency:

1. **Gossip used mesh IP for transport**: memberlist bound to the mesh IP,
   dialed other nodes via gVisor TCP. But gVisor TCP requires a working
   WireGuard connection — which requires knowing the peer's endpoint.
2. **Gossip was meant to propagate endpoints**: the same gossip that needed
   WireGuard to function was supposed to tell WireGuard where peers were.
3. **Relay routing depended on mesh IP**: `AddRelayRoute` extended
   AllowedIPs on WireGuard peers — a concept that doesn't exist without
   WireGuard and gVisor netstack.

MESHDESK_V2_DESIGN.md resolves this by eliminating all three:
- Cut WireGuard (wireguard-go)
- Cut gVisor netstack
- Cut mesh IP (deriveMeshIP + routing table)

### 1.2 What Replaces MeshIP

| v1 Concept | v2 Replacement |
|------------|----------------|
| mesh IP (10.10.x.y) | `Endpoints []string` — real `host:port` pairs |
| WireGuard AllowedIPs | PeerManager manages connections, not IP routing |
| gVisor TCP transport for gossip | memberlist standard `NetTransport` (real TCP) |
| `MeshIPToCIDR` / `AllowedIPsForPeer` | Deleted — no subnet routing needed |
| mesh IP derivation from public key | Deleted — identity is Ed25519 public key hex |

### 1.3 Scope of This Spec

This spec covers the gossip layer redesign. It does NOT cover:
- HandshakeLayer implementation (FROZEN, t_8cbf2bf4)
- Session protocol / key exchange (Layer 2, separate task)
- PeerManager redesign for v2 (separate task — P0 after gossip)

What this spec covers:
- New `NodeMeta` schema (without `MeshIP`)
- New gossip transport (standard TCP, no gVisor)
- Endpoint propagation mechanism
- Partition handling and correctness

---

## 2. New NodeMeta Schema

### 2.1 Full Schema (v2)

```go
// NodeMeta carries per-node metadata through the gossip protocol.
// v2 CHANGES:
//   - REMOVED: MeshIP field (no more virtual mesh IPs)
//   - REMOVED: ExitLatency map (moved to PeerManager, §5 addendum)
//   - CHANGED: PublicKey semantic — now Ed25519 hex (64 chars), not Curve25519
//   - KEPT: all capability, load, connectivity, and version fields
//
// Wire format: MessagePack (compact binary). Serialized size is ~150-350
// bytes per node, well within memberlist's 512-byte indirect broadcast
// limit and ~64KB push/pull limit.
type NodeMeta struct {
    // --- Static identity ---

    // PublicKey is the Ed25519 public key (hex-encoded, 64 chars).
    // In v1 this was a WireGuard Curve25519 key. In v2 it is Ed25519.
    PublicKey string `msgpack:"pk"`

    // Hostname is a human-readable name for the node.
    Hostname string `msgpack:"hn"`

    // Role describes the node's primary function:
    // "agent", "web", "relay", "exit", "entry".
    Role string `msgpack:"role"`

    // --- Capabilities ---

    // CapRelay indicates the node can forward relay circuits.
    CapRelay bool `msgpack:"cr"`

    // CapExit indicates the node can serve as a proxy exit.
    CapExit bool `msgpack:"ce"`

    // CapProxyEntry indicates the node can serve as a proxy entry point.
    CapProxyEntry bool `msgpack:"cpe"`

    // --- Connectivity (PRIMARY ADDRESSING in v2) ---

    // Endpoints are the node's reachable addresses. These are REAL IP:port
    // pairs (not mesh IPs). Example: ["203.0.113.10:443", "192.168.1.5:443"].
    // This is the sole source of truth for "how to reach this node."
    Endpoints []string `msgpack:"eps,omitempty"`

    // NatType describes the node's NAT situation:
    // "none", "full_cone", "restricted", "port_restricted", "symmetric", "unknown"
    NatType string `msgpack:"nt"`

    // --- REMOVED fields (v1 only) ---
    //
    // MeshIP       — REMOVED. Nodes are addressed by Endpoints, not virtual IPs.
    //                The 10.10.x.y subnet and deriveMeshIP are no longer used.
    //                See §3 for what replaces mesh IP routing.
    //
    // ExitLatency  — REMOVED from gossip. The map[string]int (region→RTT) is
    //                large (~100-200 bytes) and not needed in every gossip
    //                message. PeerManager maintains exit latency internally
    //                for its own path selection. Forward-looking: if future
    //                requirements demand exit latency in gossip, it can be
    //                re-added as an optional field.

    // --- Load metrics (refreshed every gossip interval) ---

    // LoadCPU is the fraction of CPU used (0.0–1.0).
    LoadCPU float64 `msgpack:"lcpu"`

    // LoadMem is the fraction of memory used (0.0–1.0).
    LoadMem float64 `msgpack:"lmem"`

    // LoadCircuits is the active relay circuit count (only if CapRelay).
    LoadCircuits int `msgpack:"lc,omitempty"`

    // LoadBW is the estimated available bandwidth in Mbps.
    LoadBW uint64 `msgpack:"lbw,omitempty"`

    // MaxCircuits is the maximum circuits this relay will accept.
    MaxCircuits int `msgpack:"mc,omitempty"`

    // --- Version ---

    // Version is the semantic version for compatibility checks.
    Version string `msgpack:"ver"`

    // --- Sequence number ---

    // Seq is a monotonic sequence number for detecting stale metadata.
    Seq uint64 `msgpack:"seq"`
}
```

### 2.2 What Changed and Why

| Field | v1 | v2 | Rationale |
|-------|-----|-----|-----------|
| `PublicKey` | Curve25519 (64 hex chars) | Ed25519 (64 hex chars) | v2 identity model: HandshakeLayer FROZEN spec §4 |
| `MeshIP` | string present | REMOVED | No more virtual IPs |
| `ExitLatency` | `map[string]int` present | REMOVED | Large field, unnecessary in gossip; PeerManager owns exit selection |
| All others | present | present | No change |

### 2.3 Backward Compatibility Warning

v2 NodeMeta is NOT backward compatible with v1. If a v1 node receives v2
NodeMeta, `MeshIP` will be empty string and the v1 node cannot route to the
v2 node. This is acceptable because:

1. The entire protocol stack is being rewritten (v2 = full rewrite).
2. v1 and v2 nodes will never coexist in the same mesh — the identity model
   changed (Ed25519 vs Curve25519), the transport changed (Reality TLS vs
   WireGuard), and the handshake protocol changed.
3. No migration path is needed. The v2 binary is a fresh deployment.

---

## 3. Gossip Transport Redesign

### 3.1 Current (v1): MeshTransport

The v1 `MeshTransport` (350 lines, `memberlist_transport.go`) does:

```
memberlist TCP → MeshTransport → gVisor netstack.ListenTCP(meshIP:port)
                                  → WireGuard encrypt
                                  → obfuscatingBind write
                                  → UDP to peer
```

This requires:
- A functioning WireGuard connection to the peer
- gVisor netstack (netstack.Net)
- A mesh IP derived from the peer's public key
- WireGuard handshake completed before TCP dial succeeds

All of these are removed in v2.

### 3.2 New (v2): Standard TCP Transport

The v2 gossip transport uses **memberlist's built-in `NetTransport`**:

```go
import "github.com/hashicorp/memberlist"

func NewGossipTransport(bindAddr string, bindPort int, advertiseAddr string) (*memberlist.NetTransport, error) {
    nc := &memberlist.NetTransportConfig{
        BindAddrs: []string{bindAddr},     // e.g., "0.0.0.0"
        BindPort:  bindPort,               // e.g., 7946
    }
    return memberlist.NewNetTransport(nc)
}
```

**Key differences from v1:**

| Aspect | v1 MeshTransport | v2 NetTransport |
|--------|------------------|-----------------|
| Underlying transport | gVisor TCP (via TUN) | Real TCP (kernel) |
| Bind address | Mesh IP (10.10.x.y) | Real interface IP |
| Advertise address | Mesh IP | Real endpoint (host:port) |
| Dial mechanism | `node.Dial(ctx, "tcp", addr)` via gVisor | `net.Dial("tcp", addr)` |
| Listener | `netstack.ListenTCP()` | `net.Listen("tcp", addr)` |
| Encryption | WireGuard (below gVisor) | None (gossip is plain TCP) |
| Dependency | mesh.MeshNode, gVisor netstack | stdlib `net` only |
| Lines of code | 350 | ~20 (config struct only) |

### 3.3 Why NOT Encrypted Gossip?

The gossip transport is **plain TCP** — no encryption at the transport level.
Rationale:

1. **Gossip carries only metadata, not user data.** NodeMeta is public information
   (hostname, role, capabilities, load metrics, endpoints). There is no secret in
   gossip traffic.

2. **memberlist supports encryption (shared key).** We can add it later if needed.
   The `memberlist.Config.SecretKey` field enables AES-256-GCM encryption of all
   gossip messages. This is a one-line config change with no code impact.

3. **v1 already had unencrypted gossip inside WireGuard.** The WireGuard encryption
   was at the network layer, not the gossip layer. Same pattern applies here —
   encryption is HandshakeLayer's job for the data plane, not gossip's.

4. **Peer identity is authenticated by Ed25519 signatures in join/handshake.**
   An attacker can't spoof gossip metadata because every node's join is
   authenticated via the JoinProtocol.

**Decision:** Plain TCP for now. Add memberlist shared-key encryption if a threat
model analysis shows it's needed (unlikely for metadata-only gossip).

### 3.4 Bootstrap and Connectivity

Without mesh IP, the bootstrap question changes:

**v1 bootstrap:** `seeds: [10.10.0.5:7946]` — mesh IP of seed node
**v2 bootstrap:** `seeds: [203.0.113.10:7946]` — real IP:port of seed node

The seed's gossip port (default 7946) must be reachable from the joining node.
This means:

1. **Seed nodes must have a reachable gossip port.** This can be:
   - A public IP with the port open (e.g., cloud server)
   - A NAT-mapped port (port forwarding)
   - The same port as the HandshakeLayer listener (e.g., 443 — see §3.5 below)

2. **Non-seed nodes behind NAT** can initiate OUTBOUND gossip connections to
   the seed (TCP outbound works through NAT). They do NOT need an open port
   for gossip inbound — memberlist handles this via its existing TCP reconnect.

3. **The advertise address** for non-seed nodes is set to their STUN-discovered
   endpoint (or empty for nodes that can't be reached directly — they use
   relay for data plane, and gossip connectivity is maintained via outbound
   connections to the seed).

### 3.5 Port Sharing with HandshakeLayer

A seed node could expose both the HandshakeLayer listener (Reality TLS, port 443)
AND the gossip listener (port 7946). Or, to minimize open ports, gossip can
share port 443 using a different protocol prefix:

```
ClientHello → TLS SNI=target → Reality TLS handshake → HandshakeLayer
                                  → data plane connections

first byte != TLS (not 0x16) → gossip TCP → memberlist
```

However, this adds complexity. The simpler approach: **separate ports.**
Seed nodes expose port 443 for HandshakeLayer (Reality TLS) and port 7946
for gossip (plain TCP). This is the standard mesh pattern (Consul, Serf,
Nomad all use separate gossip ports).

**Decision:** Separate gossip port (7946, configurable). No port sharing.

### 3.6 Advertise Address Logic

The memberlist `AdvertiseAddr` is what other nodes use to connect back to
this node for gossip. In v2:

```go
func (g *GossipLayer) resolveAdvertiseAddr() string {
    // Priority 1: explicit config
    if len(g.cfg.AdvertiseEndpoints) > 0 && g.cfg.AdvertiseEndpoints[0] != "" {
        host, _, _ := net.SplitHostPort(g.cfg.AdvertiseEndpoints[0])
        return host
    }

    // Priority 2: first discovered endpoint (STUN)
    eps := g.localMeta.Endpoints
    if len(eps) > 0 && eps[0] != "" {
        host, _, err := net.SplitHostPort(eps[0])
        if err == nil && host != "" {
            return host
        }
    }

    // Priority 3: auto-detect outbound IP (UDP dial trick)
    if ip := detectOutboundIP(); ip != "" {
        return ip
    }

    // Priority 4: bind address (likely 0.0.0.0 — not useful for others)
    // This means the node is behind NAT and can't be reached directly.
    // It will maintain gossip via outbound connections to seeds.
    return ""
}
```

When `AdvertiseAddr` is empty or unreachable, the node functions as a
"client-only" gossip participant — it initiates connections to seeds but
other nodes cannot initiate connections to it. This is the same model as
EasyTier's `--no-listener` nodes.

### 3.7 Updated memberlist Configuration

```go
mlConfig := memberlist.DefaultLocalConfig()
mlConfig.Name = identity.PublicKey[:16]  // first 16 chars of Ed25519 hex
mlConfig.BindAddr = g.cfg.GossipBindAddr  // NEW: real interface address, default "0.0.0.0"
mlConfig.BindPort = g.cfg.GossipPort      // unchanged: 7946
mlConfig.AdvertiseAddr = g.resolveAdvertiseAddr()  // real IP, not mesh IP
mlConfig.AdvertisePort = g.cfg.GossipPort

// Transport: standard NetTransport (not MeshTransport)
nc := &memberlist.NetTransportConfig{
    BindAddrs: []string{g.cfg.GossipBindAddr},
    BindPort:  g.cfg.GossipPort,
}
nt, err := memberlist.NewNetTransport(nc)
mlConfig.Transport = nt
```

### 3.8 What Happens to MeshTransport

`memberlist_transport.go` (350 lines) is **deleted entirely**. Its dependencies
on `mesh.MeshNode`, `gVisor netstack`, `RoutingTable`, `WaitForPeerHandshake`,
and `WireGuard IpcGet` are all removed from the v2 codebase.

`MeshTransport` is replaced by ~20 lines of `NetTransportConfig` in `gossip.go`.

---

## 4. Endpoint Propagation Mechanism

### 4.1 Current (v1) Endpoint Propagation

```
WireGuard receive → ObfuscatingBind.Receive() → source address detected
    → EndpointNotifier.OnEndpointDiscovered(peerKey, endpoint)
    → (never called — the bridge was broken until fixing DEFECT-02)
    → GossipLayer.SetLocalEndpoints(endpoints, natType)
    → memberlist.UpdateNode(time.Second)
    → NodeMeta.Endpoints propagated to all peers
```

The bridge (`EndpointNotifier → GossipLayer`) was designed but the
`SetOnEndpointDiscovered` callback was never wired in v1.

### 4.2 New (v2) Endpoint Propagation

v2 endpoint learning is **simpler** because the HandshakeLayer's `Listen()`
returns raw `net.Conn` values. The PeerManager owns connection state
and learns endpoints naturally:

```
PeerManager receives inbound HandshakeLayer Accept
    → net.Conn.RemoteAddr() gives peer's real IP:port
    → PeerManager calls GossipLayer.SetLocalEndpoints([]string{detectedEndpoint}, natType)
    → memberlist.UpdateNode()
    → NodeMeta.Endpoints propagated to all peers
```

Additionally, STUN discovery (unchanged from v1) provides proactive endpoint
learning:

```
STUN client → discover public endpoint + NAT type
    → GossipLayer.SetLocalEndpoints(discoveredEndpoints, natType)
    → memberlist.UpdateNode()
    → NodeMeta.Endpoints propagated
```

### 4.3 Endpoint Lifecycle

```
Node Start
    │
    ▼
STUN discovery ──→ Endpoints populated with public endpoint(s)
    │
    ▼
memberlist Start ──→ initial NodeMeta broadcast with Endpoints
    │
    ▼
Inbound connection received (HandshakeLayer Accept)
    │
    ▼
Detect source address ──→ dedup against existing Endpoints
    │                       if new → SetLocalEndpoints(append)
    │
    ▼
Every 30s: STUN re-probe (NAT mappings can change)
    │           → if changed → SetLocalEndpoints(update)
    │
    ▼
Node shutdown: Endpoints cleared, LeaveNotice sent
```

### 4.4 Endpoint Selection for Peer Connection

When the PeerManager needs to connect to a peer, it uses the
peer's `NodeMeta.Endpoints` from gossip:

```go
func (pm *PeerManager) ConnectToPeer(meta *NodeMeta) error {
    for _, endpoint := range meta.Endpoints {
        conn, err := pm.handshake.Connect(ctx, endpoint)
        if err == nil {
            return nil  // connected
        }
        // Try next endpoint
    }
    // All endpoints failed — trigger relay fallback
    return pm.connectViaRelay(meta)
}
```

No mesh IP routing. No subnet lookup. Just try each endpoint until one works.

### 4.5 Endpoint Deduplication and Staleness

- **Deduplication:** `SetLocalEndpoints` already deduplicates (gossip.go:247-256).
  No change needed.
- **Staleness:** If a peer's endpoints become stale (e.g., node rebooted, IP
  changed), the connection attempt fails. The PeerManager retries with
  exponential backoff. On the next gossip push/pull (30s), the peer's
  updated Endpoints arrive.
- **Memberlist timeout:** If the peer is unreachable even for gossip, memberlist's
  failure detection (TCP ping → indirect ping → suspicion → dead) handles it.

---

## 5. Partition Handling and Correctness

### 5.1 The v1 Illusion

In v1, mesh IP created an **illusion of connectivity**: every node had a
10.10.x.y IP, and WireGuard's AllowedIPs claimed that subnet was reachable.
But actual connectivity depended on:
- WireGuard handshake success (requires endpoint)
- gVisor netstack forwarding (for relay paths)
- Working routing table entries

Gossip through WireGuard could succeed even when the data plane was broken,
because gossip used the same virtual IP but the WireGuard connection might
have stale endpoints. This made partitions invisible to gossip.

### 5.2 v2: Partitions are Visible

In v2, gossip uses **real TCP connections**. If two groups of nodes can't
reach each other via TCP (gossip port), memberlist detects the partition
immediately:

```
Group A: [N1, N2, N3] — all can gossip to each other via TCP
Group B: [N4, N5]     — all can gossip to each other via TCP

A ↔ B: TCP connection refused/timeout — memberlist sees these nodes as dead
```

memberlist SWIM protocol behavior:
- Each group forms an independent cluster
- Nodes in the other group are eventually declared `dead` (suspicion timeout)
- When connectivity is restored (TCP between groups becomes reachable):
  - memberlist PushPull sync merges the two clusters
  - If the same node appears in both, higher Seq wins
  - Join protocols from group A re-process nodes in group B

This is **standard memberlist behavior** — we don't need to implement
anything. memberlist already handles partition → merge gracefully.

### 5.3 Correctness Guarantees

| Scenario | v1 Behavior | v2 Behavior |
|----------|------------|-------------|
| Seeds unreachable at startup | Join fails, retry loop | Join fails, retry loop (unchanged) |
| One seed goes down | Other seeds available, cluster survives | Same (unchanged) |
| Network partition (A∥B) | A and B each form cluster; node in A can't reach B via WG but gossip might think it can | A and B each form cluster; no false connectivity. Nodes in B are marked dead in A. |
| Partition healing | memberlist PushPull merges clusters | Same (unchanged) |
| Full cluster restart | All nodes re-join seeds | Same (unchanged) |
| Seed is behind NAT (no public port) | Can't happen (seeds needed mesh IP reachable via WG) | Seeds need reachable gossip port. If NAT'd, use port forwarding or a public seed. |
| Node behind NAT, no open ports | Still joins via mesh IP routing (WG) | Joins via outbound TCP to seed. Functions as client-only. |

### 5.4 Client-Only Nodes (--no-listener)

v2 introduces the concept of "client-only" nodes that do not have a reachable
gossip port. These nodes:

1. **Initiate outbound gossip connections** to one or more seeds
2. **Maintain gossip membership** through the outbound TCP connection
   (memberlist TCP transport maintains bidirectional streams)
3. **Propagate their metadata** through the seed to the rest of the mesh
4. **Receive PUSH notifications** from the seed (memberlist PushPull works
   bidirectionally on the established TCP connection)
5. **Do NOT accept inbound gossip connections** — other nodes cannot
   initiate gossip to them directly. This is not a problem because:
   - Gossip data flows through the seed → outbound TCP
   - Relay control messages flow through the seed → outbound TCP
   - Join protocol messages are sent via memberlist SendReliable

The cluster topology for client-only nodes:

```
         ┌──────────────┐
         │   Seed (S)   │ ← public, port 7946 open
         │  Endpoints:  │
         │  [1.2.3.4:7946]│
         └──┬────────┬──┘
    TCP out │        │ TCP out
    ┌───────┘        └───────┐
    ▼                        ▼
┌─────────┐            ┌─────────┐
│ Node A  │            │ Node B  │  ← client-only, NAT'd
│ no open │            │ no open │
│ ports   │            │ ports   │
└─────────┘            └─────────┘
```

A and B can discover each other via gossip metadata propagated through S.
They cannot gossip directly to each other, but they DON'T NEED TO — the
outbound connection to S carries all gossip traffic.

### 5.5 Relay Circuits for Data Plane

Gossip establishes WHO is in the mesh. The data plane (HandshakeLayer
connections, smux sessions) is established separately by the PeerManager.

For NAT'd nodes A and B that need to communicate:
1. Gossip propagates A's and B's metadata (endpoints may be empty or
   private IPs)
2. PeerManager on A sees B has no reachable endpoints → uses relay
3. Relay selection uses the existing `RelayPathBuilder` (unchanged logic)
4. The relay circuit carries the data plane traffic
5. Gossip continues to work through the seed

The relay circuit setup (`circuit_setup` → `circuit_accept`) uses
gossip messages (memberlist SendReliable), which work through the seed's
outbound TCP connection.

---

## 6. Interface Changes

### 6.1 New PeerManager Interface

The v1 `PeerManager` interface (`p2p/wg_delegate.go:17-52`) is **WireGuard-specific**.
v2 replaces it with a transport-agnostic interface:

```go
// PeerManager is the v2 interface for dynamic peer connection management.
// Unlike v1's PeerManager (which was WireGuard-specific), v2 PeerManager
// works with HandshakeLayer connections and is transport-agnostic.
//
// This is the NEW interface. The OLD PeerManager (wg_delegate.go:17-52)
// is deleted along with WireGuardDelegate.
type PeerManager interface {
    // Connect establishes a connection to a peer using the first reachable
    // endpoint from its metadata. Returns an error if all endpoints fail.
    Connect(peerKey string, endpoints []string) error

    // Disconnect closes the connection to a peer and cleans up state.
    Disconnect(peerKey string) error

    // UpdateEndpoints refreshes the known endpoints for a peer.
    // Called when NotifyUpdate detects endpoint changes.
    UpdateEndpoints(peerKey string, endpoints []string) error

    // IsConnected returns whether a connection to the peer is active.
    IsConnected(peerKey string) bool

    // IsStaticPeer returns true if the peer was from static config.
    IsStaticPeer(peerKey string) bool

    // MarkStaticPeer registers a peer key as static.
    MarkStaticPeer(peerKey string)

    // ── Relay operations ──

    // AddRelayTarget adds a remote peer as a relay target on this node.
    // Called on the RELAY node (R) when a circuit_setup is accepted.
    // Unlike v1, this does NOT configure WireGuard — it registers
    // the peer for relay data forwarding via the netstack or relay proxy.
    AddRelayTarget(targetKey string, targetEndpoints []string) error

    // RemoveRelayTarget removes a relay target from this node.
    // Called on the RELAY node when a circuit is torn down.
    RemoveRelayTarget(targetKey string) error
}
```

Key differences from v1 `PeerManager`:
- No `AddDynamicPeer(DynamicPeer)` — replaced by `Connect(peerKey, endpoints)`
- No `RemoveDynamicPeer` — replaced by `Disconnect(peerKey)`
- No `UpdateEndpoint` (singular) — replaced by `UpdateEndpoints` (plural, handles multiple endpoints)
- `AddRelayRoute` → removed (no AllowedIPs in v2)
- `RemoveRelayRoute` → removed
- `IsHealthy` → `IsConnected` (semantics: connection alive, not WG handshake health)
- `UpdateHandshakeTime` → removed (WireGuard-specific)

### 6.2 Simplified DynamicPeer

The v1 `DynamicPeer` struct had WireGuard-specific fields:

```go
// v1 DynamicPeer (DELETED)
type DynamicPeer struct {
    PublicKey    string
    Endpoint     string
    AllowedIPs   []string    // ← DELETED: no WireGuard, no subnet routing
    Capabilities []string
    Obfuscation  string      // ← DELETED: no obfuscation modes
    IsRelay      bool        // ← DELETED: relay state tracked separately
    RelayVia     string      // ← DELETED: relay state tracked separately
}
```

The v2 equivalent is just the `NodeMeta` itself — no separate peer struct needed.
The event delegate passes `NodeMeta` to PeerManager: `Connect(meta.PublicKey, meta.Endpoints)`.

### 6.3 GossipLayer Constructor Changes

```go
// v1 constructor
func NewGossipLayer(cfg P2pConfig, node *mesh.MeshNode, wgDelegate *WireGuardDelegate) (*GossipLayer, error)

// v2 constructor
func NewGossipLayer(cfg P2pConfig, identity []byte, peerManager PeerManager) (*GossipLayer, error)
```

Changes:
- `node *mesh.MeshNode` → removed. No more gVisor dependency.
- `wgDelegate *WireGuardDelegate` → `peerManager PeerManager`. New interface.
- `identity []byte` → the Ed25519 private key (32 bytes raw, not hex).

### 6.4 P2pConfig Additions

```go
type P2pConfig struct {
    // ... existing fields unchanged ...

    // GossipBindAddr is the address for gossip TCP listener.
    // Default: "0.0.0.0" (all interfaces).
    // Set to a specific interface IP to restrict gossip to one network.
    GossipBindAddr string `yaml:"gossip_bind_addr,omitempty"`

    // AdvertiseEndpoints is a list of host:port addresses that this node
    // advertises to peers for gossip connections. When empty, auto-detected
    // from STUN or outbound IP detection. Multiple endpoints are useful for
    // dual-stack IPv4/IPv6 nodes.
    // Example: ["203.0.113.10:7946", "[2001:db8::1]:7946"]
    AdvertiseEndpoints []string `yaml:"advertise_endpoints,omitempty"`

    // AdvertiseEndpoint (legacy, deprecated) — singular form for backward
    // compatibility. If set, migrated to AdvertiseEndpoints[0] during Load().
    AdvertiseEndpoint string `yaml:"advertise_endpoint,omitempty"`

    // GossipEncryption enables AES-256-GCM encryption of gossip messages
    // using a shared secret. Default: false (gossip is plain TCP).
    // Set to true and provide GossipSecretKey to enable.
    GossipEncryption bool `yaml:"gossip_encryption,omitempty"`

    // GossipSecretKey is the 32-byte base64-encoded encryption key for
    // gossip messages. Required when GossipEncryption is true.
    GossipSecretKey string `yaml:"gossip_secret_key,omitempty"`
}
```

### 6.5 Functions Deleted

The following functions are **deleted** as part of this Gap3 work:

| Function | Location | Reason |
|----------|----------|--------|
| `DeriveMeshIPFromHex` | `wg_delegate.go:298` | No more mesh IP derivation |
| `MeshIPToCIDR` | `wg_delegate.go:311` | No more CIDR-based routing |
| `AllowedIPsForPeer` | `events.go:469` | No more AllowedIPs |
| `meshSubnetCIDR` | `events.go:457` | No more mesh subnet |
| `firstNonEmpty` | `events.go:432` | SIMPLIFIED — kept but used differently |

### 6.6 Code Remaining (No Changes)

The following components are **unchanged** or **minimally changed**:

| Component | File | Notes |
|-----------|------|-------|
| `meshDelegate` | `delegate.go` | Changed: NodeMeta parsing (no MeshIP field). Marshal/Unmarshal unchanged. |
| `meshEventDelegate` | `events.go` | Changed: NotifyJoin uses PeerManager.Connect instead of AddDynamicPeer. NotifyLeave uses Disconnect. AllowedIPs logic removed. |
| `GossipLayer` (core) | `gossip.go` | Changed: constructor, transport init, advertise logic. Start/Stop flow unchanged. |
| `RelaySelector` | `relay_selector.go` | Changed: scoring excludes MeshIP. Unchanged otherwise. |
| `RelaySessionManager` | `relay_session.go` | Changed: handleSetup calls PeerManager.AddRelayTarget (new interface). |
| `RelayPathBuilder` | `relay_path.go` | Changed: uses PeerManager interface instead of WireGuardDelegate. |
| `JoinProtocol` | `join.go` | Unchanged. Uses gossip message transport, not mesh IP. |
| `NAT traversal` | `nat.go`, `nat_stun.go` | Unchanged. STUN discovery unchanged. |
| `config.go` | `config.go` | Changed: new fields. P2pConfig default values. |
| Relay protocol | `relay_protocol.go` | Unchanged. Message format independent of transport. |

---

## 7. Implementation Plan

### 7.1 Implementation Sequence

| Phase | Change | Files | Lines Est. | Depends On |
|-------|--------|-------|------------|------------|
| 1 | Remove `MeshIP` from `NodeMeta` | `delegate.go` | -5 lines | — |
| 2 | Remove `DeriveMeshIPFromHex`, `MeshIPToCIDR` | `wg_delegate.go` | -25 lines | Phase 1 |
| 3 | Remove `AllowedIPsForPeer`, `meshSubnetCIDR` | `events.go` | -20 lines | Phase 1 |
| 4 | Rewrite `NotifyJoin` to use `PeerManager.Connect` | `events.go` | ~30 lines | Phase 3 |
| 5 | Rewrite `NotifyLeave` to use `PeerManager.Disconnect` | `events.go` | ~10 lines | Phase 4 |
| 6 | Delete `MeshTransport`, replace with `NetTransport` | `gossip.go` | ~30 lines new, -350 lines deleted | Phases 1-3 |
| 7 | Update `P2pConfig` (new fields, new defaults) | `config.go` | ~25 lines | — |
| 8 | Update `GossipLayer` constructor | `gossip.go` | ~20 lines | Phases 6-7 |
| 9 | Update `RelayPathBuilder` for new PeerManager | `relay_path.go` | ~30 lines | Phase 5 |
| 10 | Update `RelaySessionManager` for new PeerManager | `relay_session.go` | ~15 lines | Phase 5 |
| 11 | Update `PeerManager` interface definition | `wg_delegate.go` → rename | ~30 lines | All |
| 12 | Update tests | `*_test.go` | ~200 lines | All |

**Total estimated:** ~350 lines new, ~450 lines deleted. Net: -100 lines.

### 7.2 Order of Operations (Critical Path)

```
Phase 1-3: Remove MeshIP from data structures (no-op on behavior)
    ↓
Phase 6: Replace transport (MUST be done before any runtime change)
    ↓
Phase 4-5: Rewrite event delegate (now safe — transport works)
    ↓
Phase 9-10: Update relay components
    ↓
Phase 11-12: Finalize interface + tests
```

Phase 1-3 is purely subtractive (remove dead code). Phases 4+ add new behavior.

### 7.3 Test Strategy

1. **Unit tests:** Each Phase has a corresponding test update:
   - Phase 1-3: Tests that construct NodeMeta must remove MeshIP field
   - Phase 4-5: Mock PeerManager (new interface) replaces Mock WireGuardDelegate
   - Phase 6: Transport integration test — two memberlist instances communicating via NetTransport
   - Phase 12: Full relay verification test with new interface

2. **Integration test:** Three-node scenario (seed + 2 NAT'd agents):
   - Seed with public endpoint → gossip transport starts
   - Agent A joins via seed → memberlistMembers() returns 2
   - Agent B joins via seed → memberlistMembers() returns 3
   - A's NodeMeta.Endpoints propagated to B (and vice versa)
   - Relay circuit established between A↔B via relay-capable seed

3. **Partition test:** Two seeds, network partition (iptables DROP):
   - Cluster splits into two groups
   - Each group's memberlist shows only local members
   - When partition heals (iptables rules removed), clusters merge within 30s

---

## 8. Acceptance Criteria

### AC-1: NodeMeta has no MeshIP field
```
WHEN: NodeMeta is marshaled to MessagePack
THEN: The output contains pk, hn, role, cr, ce, cpe, eps, nt, lcpu, lmem, lc, lbw, mc, ver, seq
AND:  The output does NOT contain mip (MeshIP) or el (ExitLatency)
AND:  The output does NOT contain a zero-value stub for mip
```

### AC-2: memberlist NetTransport replaces MeshTransport
```
WHEN: GossipLayer.Start() is called
THEN: memberlist uses a NetTransport (not MeshTransport)
AND:  No gVisor netstack references in the transport layer
AND:  File memberlist_transport.go is deleted
```

### AC-3: Gossip connectivity between seed and NAT'd node
```
GIVEN: Seed S with public endpoint 1.2.3.4:7946
AND:   Node A behind NAT (no open ports)
WHEN:  A starts with seeds=["1.2.3.4:7946"]
THEN:  Within 15 seconds, S and A are in each other's memberlist
AND:   A's metadata (Endpoints, NatType) is visible to S
AND:   S's metadata is visible to A
```

### AC-4: Endpoint propagation through gossip
```
GIVEN: Node A discovers endpoint "5.6.7.8:443" via STUN
WHEN:  A calls SetLocalEndpoints(["5.6.7.8:443"], "full_cone")
THEN:  Within 30 seconds, Node B's NotifyUpdate fires with A's endpoints = ["5.6.7.8:443"]
AND:   A's NodeMeta.NatType = "full_cone"
```

### AC-5: PeerManager.Connect called instead of AddDynamicPeer
```
GIVEN: Node A discovers Node B via gossip (NotifyJoin)
AND:   B has Endpoints = ["5.6.7.8:443"]
WHEN:  NotifyJoin fires for B
THEN:  A calls PeerManager.Connect("B_key", ["5.6.7.8:443"])
AND:   AddDynamicPeer is NOT called
AND:   AllowedIPs is NOT computed
```

### AC-6: NAT peer with empty endpoints triggers relay
```
GIVEN: Node A discovers Node B via gossip
AND:   B has Endpoints = [] (NAT'd, no public endpoint)
WHEN:  NotifyJoin fires for B
THEN:  A calls relayPathBuilder.OnNATPeerDiscovered(meta)
AND:   PeerManager.Connect is NOT called for B
AND:   A's relay circuit setup begins (circuit_setup sent to relay)
```

### AC-7: Partition detection works without mesh IP
```
GIVEN: Cluster of 3 nodes (A, B, C) all gossiping via TCP
WHEN:  iptables rules block TCP port 7946 between A and B
THEN:  memberlist marks B as dead in A's view
AND:   memberlist marks A as dead in B's view
AND:   C (connected to both) sees both A and B as alive
AND:   When iptables rules are removed, A and B rejoin within 60s
```

### AC-8: Client-only node functions correctly
```
GIVEN: Seed S with gossip_port=7946 open
AND:   Node A with no open ports, seeds=["S:7946"]
WHEN:  A starts
THEN:  A appears in S's memberlist
AND:   A's metadata is propagated to other nodes via S
AND:   S's metadata is visible to A
AND:   A receives relay messages via outbound TCP connection to S
```

### AC-9: No MeshIP references in codebase
```
WHEN: grep -r "MeshIP" internal/p2p/
THEN: No matches (except in comments documenting the removal)
AND:  grep -r "deriveMeshIP\|MeshIPToCIDR\|AllowedIPsForPeer\|meshSubnetCIDR" internal/p2p/ returns empty
```

### AC-10: Tests pass with updated interfaces
```
GIVEN: All phases of implementation complete
WHEN:  go test ./internal/p2p/... runs
THEN:  All tests pass (with updated mocks using new PeerManager interface)
AND:   No test references MeshIP, AllowedIPs, DynamicPeer, or WireGuardDelegate
```

---

## 9. Migration Impact

### 9.1 Files Deleted

| File | Lines | Reason |
|------|-------|--------|
| `memberlist_transport.go` | 350 | Replaced by memberlist NetTransport |
| `wg_delegate.go` (WireGuardDelegate portion) | ~300 | WireGuard-specific, no longer needed |
| `DeriveMeshIPFromHex` + `MeshIPToCIDR` | ~30 | Mesh IP functions |
| `AllowedIPsForPeer` + `meshSubnetCIDR` | ~20 | AllowedIPs routing |

Total: ~700 lines deleted.

### 9.2 Files Modified

| File | Lines Changed | Type of Change |
|------|--------------|----------------|
| `delegate.go` | -5 (remove MeshIP field) | Subtractive |
| `events.go` | ~40 (rewrite NotifyJoin/Leave) | Behavioral |
| `gossip.go` | ~50 (transport + constructor) | Behavioral |
| `config.go` | ~25 (new fields) | Additive |
| `relay_path.go` | ~30 (new interface) | Behavioral |
| `relay_session.go` | ~15 (new interface) | Behavioral |
| `*_test.go` files | ~200 (mock updates) | Behavioral |

### 9.3 Dependencies Removed

From `go.mod`:
- `golang.zx2c4.com/wireguard/tun/netstack` — only used by MeshTransport
- `golang.zx2c4.com/wireguard` — only used by WireGuardDelegate

These are removed when the full v2 rewrite completes (not just Gap3).

### 9.4 No Breaking Changes for Config Users

The `config.yaml` p2p section is backward compatible:
- `mesh_ip` field is removed (no longer generated/used)
- `gossip_bind_addr` is new but optional (defaults to "0.0.0.0")
- `advertise_endpoint` already exists (repurposed for real address)
- `seeds` format changes from "10.10.x.y:7946" to "1.2.3.4:7946"

Since v2 is a fresh deployment (no upgrade from v1), these changes are
documentation-only for users.

---

## 10. Open Questions for Team Discussion

### Q1: Gossip Encryption — Now or Later?

memberlist supports `SecretKey` (shared key, AES-256-GCM). Should we enable it?

**Pro:** Defends against passive eavesdropping on gossip traffic (endpoints,
capabilities, load metrics visible on the wire).

**Con:** Adds a shared-secret management problem. Every node needs the same key.
Key rotation requires cluster-wide restart. For metadata-only gossip, the
benefit is marginal.

**Recommendation:** Defer. Add in v2.1 if a threat model justifies it. Default
to plain TCP for simplicity.

### Q2: Relay Data Plane — How Does Relay Forwarding Work Without WireGuard?

v1 relays used WireGuard's netstack forwarding: decrypt → route through netstack
→ re-encrypt → deliver. v2 has no WireGuard and no gVisor.

**Options:**
a. **Relay proxy:** `io.Copy` between two HandshakeLayer connections.
   Simple, works, but doubles CPU cost (encrypt/decrypt at relay).
b. **Relay as introducer:** Relay only introduces peers (like EasyTier
   shared node). After introduction, A and B attempt direct connection.
   Falls back to data-plane relay only if direct fails.
c. **smux relay:** The relay opens a smux session to each peer. A's smux
   stream is connected to B's smux stream via `io.Copy` at the relay.

**Recommendation:** Option (c) — smux relay. This is the natural v2 equivalent
of v1's netstack forwarding. The relay `io.Copy`s between two smux streams.
No WireGuard, no netstack forwarding. This is OUT OF SCOPE for this spec
(relay data plane is a separate task), but the gossip metadata design
supports it.

### Q3: Should we require seeds to have public endpoints?

v2 gossip seeds need a reachable TCP port (7946). This means seeds must have
a public IP or port-forwarded NAT mapping.

**Impact:** Users deploying in home NAT environments need at least one
node with port forwarding (or use a cloud VPS as seed). This is the same
constraint as EasyTier, Consul, and most mesh networks.

**Alternative:** Use UPnP/NAT-PMP to automatically forward the gossip port.
This adds complexity but improves UX. Defer to v2.1.

**Recommendation:** Document the requirement clearly. Seeds need reachable
gossip port. Use a cloud VPS or port forwarding.

### Q4: memberlist LAN vs WAN configuration?

memberlist has two configuration presets: `DefaultLANConfig()` and
`DefaultWANConfig()`. The main difference: WAN has longer timeouts and
fewer indirect pings, optimized for higher-latency paths.

**Which should v2 use?** LAN for walled-garden deployments (all nodes in
same datacenter). WAN for cross-region deployments (nodes across different
networks).

**Recommendation:** Default to LAN with overridable config. Most MeshDesk
deployments are < 20 nodes, and LAN config works fine for WAN at that scale.
Add a `gossip_network: "lan" | "wan"` config option for advanced users.

---

## Appendix A: Full GossipLayer.Start() (v2, Pseudocode)

```go
func (g *GossipLayer) Start() error {
    // 1. Create memberlist config
    mlConfig := memberlist.DefaultLocalConfig()
    mlConfig.Name = shortKey(g.identity.PublicKey())  // first 16 chars
    mlConfig.BindAddr = g.cfg.GossipBindAddr           // "0.0.0.0" or specific IP
    mlConfig.BindPort = g.cfg.GossipPort               // 7946
    mlConfig.AdvertiseAddr = g.resolveAdvertiseAddr()  // real IP, not mesh IP
    mlConfig.AdvertisePort = g.cfg.GossipPort

    // Standard timeouts (unchanged from v1)
    mlConfig.TCPTimeout = 10 * time.Second
    mlConfig.IndirectChecks = 3
    mlConfig.PushPullInterval = time.Duration(g.cfg.GossipInterval) * time.Second
    mlConfig.ProbeInterval = time.Duration(g.cfg.GossipProbeInterval) * time.Second
    mlConfig.ProbeTimeout = 500 * time.Millisecond

    // Delegates (unchanged from v1)
    mlConfig.Delegate = g.delegate
    mlConfig.Events = g.events

    // Optional encryption
    if g.cfg.GossipEncryption && g.cfg.GossipSecretKey != "" {
        key, _ := base64.StdEncoding.DecodeString(g.cfg.GossipSecretKey)
        mlConfig.SecretKey = key
    }

    // 2. Create NetTransport (NEW — replaces MeshTransport)
    nc := &memberlist.NetTransportConfig{
        BindAddrs: []string{g.cfg.GossipBindAddr},
        BindPort:  g.cfg.GossipPort,
    }
    nt, err := memberlist.NewNetTransport(nc)
    if err != nil {
        return fmt.Errorf("create net transport: %w", err)
    }
    mlConfig.Transport = nt

    // 3. Create memberlist
    ml, err := memberlist.Create(mlConfig)
    if err != nil {
        return fmt.Errorf("create memberlist: %w", err)
    }
    g.memberlist = ml

    // 4. Announce endpoint (unchanged from v1)
    g.announceLocalEndpoint()

    // 5. Join seeds (unchanged from v1, except seeds are real IPs)
    if g.cfg.HasSeed() {
        go func() { g.retryJoinSeeds() }()
    }

    // 6. Wire join protocol (unchanged from v1)
    g.wireJoinProtocol()

    return nil
}
```

## Appendix B: Changed NodeMeta — Before/After Diff

```diff
 type NodeMeta struct {
     PublicKey    string           `msgpack:"pk"`
     Hostname     string           `msgpack:"hn"`
     Role         string           `msgpack:"role"`
     CapRelay     bool             `msgpack:"cr"`
     CapExit      bool             `msgpack:"ce"`
     CapProxyEntry bool            `msgpack:"cpe"`
     Endpoints    []string         `msgpack:"eps,omitempty"`
     NatType      string           `msgpack:"nt"`
-    MeshIP       string           `msgpack:"mip"`           ← REMOVED
     LoadCPU      float64          `msgpack:"lcpu"`
     LoadMem      float64          `msgpack:"lmem"`
     LoadCircuits int              `msgpack:"lc,omitempty"`
     LoadBW       uint64           `msgpack:"lbw,omitempty"`
     MaxCircuits  int              `msgpack:"mc,omitempty"`
-    ExitLatency  map[string]int   `msgpack:"el,omitempty"`  ← REMOVED
     Version      string           `msgpack:"ver"`
     Seq          uint64           `msgpack:"seq"`
 }
```

## Appendix C: Test Mock Update Pattern

```go
// v1: Mock WireGuardDelegate
type mockPeerManager struct {
    peers map[string]*DynamicPeer
}
func (m *mockPeerManager) AddDynamicPeer(p DynamicPeer) error { ... }

// v2: Mock v2 PeerManager
type mockPeerManagerV2 struct {
    connections map[string][]string  // publicKey → endpoints
}
func (m *mockPeerManagerV2) Connect(peerKey string, endpoints []string) error { ... }
func (m *mockPeerManagerV2) Disconnect(peerKey string) error { ... }
func (m *mockPeerManagerV2) UpdateEndpoints(peerKey string, endpoints []string) error { ... }
func (m *mockPeerManagerV2) IsConnected(peerKey string) bool { ... }
```
