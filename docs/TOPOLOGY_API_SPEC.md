# Topology API Contract

**Version:** 2.0
**Status:** Spec (architecture contract)
**Source:** motion-4921c5640c27 action 1/4, evolved from v1 (t_2aa5ffd7)
**Scope:** GET /api/topology, SSE /api/topology/events

---

## 1. Overview

This document defines the topology API contract between the MeshDesk backend
and the 3D topology visualization frontend. The contract is **stable** —
frontend and backend evolve independently as long as both sides conform to
this spec.

Data sources may change (static WireGuard config → memberlist gossip), but
the API shape is the compatibility boundary. The backend is responsible for
normalizing whichever data source is active into this contract.

### 1.1 Design Principles

- **JSON only.** All responses are `Content-Type: application/json`.
- **Snake case fields.** Consistent with the existing dashboard API conventions.
- **Optional fields.** The frontend treats every field as optional — nodes
  appear with whatever data the backend has at the moment.
- **Deterministic ordering.** Node and edge arrays are sorted (`id` for
  nodes, `source` then `target` for edges).
- **Auth.** Both endpoints require a valid session cookie (same as `/api/events`).

---

## 2. Endpoints

### 2.1 GET /api/topology

Returns a complete topology snapshot.

**Request:** `GET /api/topology`  
**Auth:** Session cookie  
**Query params:** none (production). `?mock=true` for development.

**Response 200:**

```json
{
  "nodes": [
    {
      "id": "a1b2c3d4...",
      "public_key": "mPmTi...=",
      "mesh_ip": "10.144.144.3",
      "role": "entry+relay",
      "hostname": "node-east-1",
      "status": "online",
      "cpu": 23.5,
      "mem": 10.2,
      "x": -120.5,
      "y": 340.0,
      "z": 15.3
    }
  ],
  "edges": [
    {
      "source": "a1b2c3d4...",
      "target": "e5f6g7h8...",
      "latency_ms": 4.2,
      "bandwidth_mbps": 1000,
      "link_status": "direct"
    }
  ],
  "circuits": [
    {
      "id": "c-0001",
      "entry": "a1b2c3d4...",
      "exit": "i9j0k1l2...",
      "paths": [
        {"hops": ["a1b2c3d4...", "e5f6g7h8...", "i9j0k1l2..."], "latency_ms": 45.0},
        {"hops": ["a1b2c3d4...", "m3n4o5p6...", "i9j0k1l2..."], "latency_ms": 62.0}
      ]
    }
  ]
}
```

**Response 200 (empty — no data sources configured):**

```json
{"nodes": [], "edges": [], "circuits": []}
```

**Response 401:** `{"error": "unauthorized"}`
**Response 500:** `{"error": "internal server error"}`

#### 2.1.1 Node Fields

| Field        | Type    | Required | Semantics                                              |
|-------------|---------|----------|--------------------------------------------------------|
| `id`        | string  | yes      | Hex-encoded WireGuard public key. Stable identifier.   |
| `public_key` | string  | no       | Base64 WireGuard public key (UI-displayable form).     |
| `mesh_ip`   | string  | no       | Primary mesh IP (first /32 AllowedIP).                 |
| `role`      | string  | no       | `"entry"`, `"relay"`, `"exit"`, `"dashboard"`, or `+`-delimited. |
| `hostname`  | string  | no       | Hostname from monitor, or `""`.                       |
| `status`    | string  | no       | `"online"` or `"offline"`.                            |
| `cpu`       | number  | no       | CPU usage percent (0–100), present only when `online`. |
| `mem`       | number  | no       | Memory usage percent (0–100), present only when `online`. |
| `x`         | number  | no       | 3D display X coordinate. Defaults to 0.               |
| `y`         | number  | no       | 3D display Y coordinate. Defaults to 0.               |
| `z`         | number  | no       | 3D display Z coordinate. Defaults to 0.               |

- `id` is the canonical node identifier. The backend must preserve it across
  restarts, re-configures, and data-source transitions.
- `mesh_ip` is the first `/32` AllowedIP. Empty string when no mesh IP is
  assigned (e.g., pure relay with no local subnet).
- `public_key` is the base64 WireGuard key, suitable for display in UIs
  (e.g., `wg show` format).
- `role` uses `+` as the delimiter for multi-role nodes (e.g.,
  `"entry+relay"`). The frontend may split on `+` for display.

#### 2.1.2 Edge Fields

| Field           | Type   | Required | Semantics                                                    |
|----------------|--------|----------|--------------------------------------------------------------|
| `source`       | string | yes      | Node ID of the edge origin.                                    |
| `target`       | string | yes      | Node ID of the edge destination.                               |
| `latency_ms`   | number | no       | Latest measured RTT in milliseconds. `-1` = unknown.          |
| `bandwidth_mbps`| number | no       | Estimated available bandwidth in Mbps. `-1` = unknown.         |
| `link_status`  | string | no       | `"direct"`, `"relayed"`, or `"unreachable"`.               |

- `link_status` reflects the connectivity type:
  - `direct` — the two nodes have a direct WireGuard tunnel (static or
    NAT-hole-punched).
  - `relayed` — traffic between the nodes is relayed through a third party.
  - `unreachable` — no path exists; the edge is shown as a dashed line.
  - Absent/`""` — backend cannot determine link type (treat as `direct`).

#### 2.1.3 Circuit Fields (optional top-level array)

| Field   | Type            | Required | Semantics                                                    |
|---------|-----------------|----------|--------------------------------------------------------------|
| `id`    | string          | yes      | Short circuit identifier (e.g., `"c-0001"`).                 |
| `entry` | string          | yes      | Node ID of the circuit entry (ingress).                        |
| `exit`  | string          | yes      | Node ID of the circuit exit (egress).                          |
| `paths` | array of paths  | yes      | Ordered list of hop-arrays for this circuit.                   |

Each path object: `{"hops": ["nodeA", "nodeB", ...], "latency_ms": 45.0}`.

- The `circuits` array is **optional**. It is present only when the proxy
  subsystem is running and has active circuits. Frontends must handle its
  absence gracefully (treat as `[]`).
- Circuits may change rapidly. The frontend should replace the array on each
  snapshot rather than diffing.

---

### 2.2 GET /api/topology/events (SSE)

Streams real-time topology updates via Server-Sent Events.

**Request:** `GET /api/topology/events`  
**Auth:** Session cookie  
**Content-Type:** `text/event-stream`

**Event types:**

| Event          | Payload                          | Semantics                                         |
|---------------|----------------------------------|---------------------------------------------------|
| `topology`    | Full `TopologySnapshot` (2.1)   | Sent on connect (cold start) and on full refresh. |
| `node_update`  | Single `TopologyNode` (2.1.1)    | A node's metrics, role, or position changed.      |
| `node_online`  | `{"id": "...", "hostname": "..."}` | Node started reporting fresh metrics.               |
| `node_offline` | `{"id": "...", "hostname": "..."}` | Node's metrics went stale (>60s).                  |
| `edge_update`  | Single `TopologyEdge` (2.1.2)    | An edge's latency or link status changed.          |

- Keepalive: `": keepalive\n\n"` comment line every 15 seconds.
- Clients should reconnect on connection loss with exponential backoff
  (starting at 1s, max 30s).
- `topology` events carry the full snapshot; all other events are deltas.

---

## 3. Data Source Transition (WireGuard → Gossip)

### 3.1 Current: Static WireGuard Config

Data flows:
```
config(.yaml/.json) → RoutingTable → meshTopologyPeers adapter → /api/topology
```

- `id` = `PeerEntry.ID` (hex public key).
- `mesh_ip` = first `AllowedIP` from the peer's static config.
- `public_key` = base64 of the hex ID.
- `role` = derived from local config flags + static path config for remotes.
- Edges come from the path probe cache (`latency_ms`, `bandwidth_mbps`).
  `link_status` is `"direct"` for probed pairs, `""` otherwise.

### 3.2 Future: Memberlist Gossip

Data flows:
```
memberlist (SWIM) → gossip delegate → TopologyPeers adapter → /api/topology
```

- `id` = node's public key (same stable identifier).
- `mesh_ip` = node's primary mesh address from gossip metadata.
- `public_key` = base64 of the public key (same).
- `role` = propagated via gossip node metadata (`NodeRole` tag).
- Edges come from the path probe cache (the probe layer does not change).
  `link_status` = `"direct"` for probed pairs, `"relayed"` when the
  path goes through a relay node, `"unreachable"` when no path exists.

### 3.3 Migration Path

1. Backend first adds the new fields (`mesh_ip`, `public_key`, `link_status`)
   to the Go types and populates them from `PeerEntry`.
2. Frontend updates to consume the new fields (they're all optional).
3. Later, when the gossip delegate is deployed, the data source switches,
   but the API shape does not change.
4. `"relayed"` and `"unreachable"` edge states become meaningful only after
   the gossip transition.

---

## 4. Acceptance Criteria

### AC-TO-01: Response shape
GET /api/topology returns `{"nodes": [...], "edges": [...], "circuits": [...]}`.
All three keys are always present; arrays may be empty.

### AC-TO-02: Node identity
Every node has `id` (hex public key). This field is required, non-empty, and
stable across restarts.

### AC-TO-03: New fields (v2)
Nodes carry `mesh_ip` (string) and `public_key` (string, base64).
Edges carry `link_status` (string: `"direct"` | `"relayed"` | `"unreachable"`).

### AC-TO-04: Edges from probe data
Edges are derived from the path probe cache (latency measurements).
`len(edges) ≤ len(nodes) * (len(nodes) - 1) / 2`.

### AC-TO-05: SSE cold start
On connect, GET /api/topology/events sends one `topology` event with the
full snapshot, then streams deltas.

### AC-TO-06: SSE event types
The SSE stream emits `topology`, `node_update`, `node_online`, `node_offline`,
and `edge_update` events with payloads matching the REST shapes.

### AC-TO-07: Auth
Both endpoints reject unauthenticated requests with 401.

### AC-TO-08: Empty state
When no data sources are configured (no mesh node, no monitor, no proxy),
GET /api/topology returns `{"nodes": [], "edges": [], "circuits": []}`
(200 OK, not 500).

### AC-TO-09: Sorting
Node arrays are sorted by `id` ascending. Edge arrays are sorted by
`source` ascending, then `target` ascending.

### AC-TO-10: Gossip-ready
The contract does not reference WireGuard-specific concepts (no `endpoint`,
no `allowed_ips` arrays). All fields are named so they map naturally to
memberlist gossip metadata.

### AC-TO-11: Base64 public_key
`public_key` is standard base64 (no padding variants). Matches `wg show` output.

### AC-TO-12: Link status semantics
`link_status` is an edge field with three valid values (`"direct"`, `"relayed"`,
`"unreachable"`). Absent/`""` is treated as `"direct"` by the frontend
(backward compatibility). The backend SHOULD populate it when the link type
can be determined; the frontend MUST NOT assume it is present.

### AC-TO-13: Circuit array
`circuits` is present when the proxy subsystem is active, absent or `[]`
otherwise. Each circuit carries `id`, `entry`, `exit`, and `paths`.

---

## 5. Backend Implementation Notes

### 5.1 Go Type Reference

```go
// TopologyNode — matches §2.1.1
type TopologyNode struct {
    ID        string  `json:"id"`
    PublicKey string  `json:"public_key"`
    MeshIP    string  `json:"mesh_ip"`
    Role      string  `json:"role"`
    X         float64 `json:"x"`
    Y         float64 `json:"y"`
    Z         float64 `json:"z"`
    CPU       float64 `json:"cpu"`
    Mem       float64 `json:"mem"`
    Hostname  string  `json:"hostname"`
    Status    string  `json:"status"`
}

// TopologyEdge — matches §2.1.2
type TopologyEdge struct {
    Source        string  `json:"source"`
    Target        string  `json:"target"`
    LatencyMs     float64 `json:"latency_ms"`
    BandwidthMbps float64 `json:"bandwidth_mbps"`
    LinkStatus    string  `json:"link_status"`
}

// TopologyCircuit — matches §2.1.3
type TopologyCircuit struct {
    ID    string           `json:"id"`
    Entry string           `json:"entry"`
    Exit  string           `json:"exit"`
    Paths []CircuitPath    `json:"paths"`
}

type CircuitPath struct {
    Hops      []string `json:"hops"`
    LatencyMs float64  `json:"latency_ms"`
}

// TopologySnapshot — matches §2.1
type TopologySnapshot struct {
    Nodes    []TopologyNode    `json:"nodes"`
    Edges    []TopologyEdge    `json:"edges"`
    Circuits []TopologyCircuit `json:"circuits"`
}
```

### 5.2 Interface Changes (from v1)

| Interface / Method | Change |
|---|---|
| `TopologyPeers` | Add `MeshIP(peerID string) string` |
| `TopologyPeers` | Add `PublicKey(peerID string) string` |
| `TopologyPeers.Position` | Unchanged |
| `TopologyMetrics` | Unchanged (CPU/mem/hostname come from monitor) |
| `TopologyPathInfo` | Unchanged |
| `CircuitManager.ListCircuits()` | Already returns circuits; wire into snapshot |

### 5.3 meshTopologyPeers Adapter Changes

```go
func (m *meshTopologyPeers) MeshIP(peerID string) string {
    if m.localNodeID != "" && peerID == m.localNodeID {
        return firstAllowedIP(m.cfg)  // from config
    }
    peer, ok := m.rt.GetPeer(peerID)
    if !ok || len(peer.AllowedIPs) == 0 {
        return ""
    }
    return stripCIDR(peer.AllowedIPs[0])
}

func (m *meshTopologyPeers) PublicKey(peerID string) string {
    // hex ID → base64
    b64, _ := peer.Base64Key(peerID)
    return b64
}
```

### 5.4 Edge link_status Populating

```go
func linkStatus(paths TopologyPathInfo, src, dst string) string {
    if paths.PeerLatency(src, dst) >= 0 {
        return "direct"  // probed successfully
    }
    if paths.PeerLatency(dst, src) >= 0 {
        return "direct"  // reverse direction works
    }
    return "unreachable"
}
```

When gossip propagates relay topology, the adapter can set `"relayed"` for
pairs that are reachable only through an intermediate node.

---

## 6. Frontend Contract

### 6.1 Field Presence

The frontend must not assume any field is present except `id` on nodes and
`source`/`target` on edges.

- Missing `mesh_ip` → display `"-"` or hide the field.
- Missing `public_key` → hide the key icon.
- Missing `cpu`/`mem` → hide the meter/gauge.
- `link_status` missing/`""` → same as `"direct"` (solid line, no indicator).

### 6.2 SSE Consumption

```
const es = new EventSource("/api/topology/events");
es.addEventListener("topology",  e => replaceSnapshot(JSON.parse(e.data)));
es.addEventListener("node_update", e => patchNode(JSON.parse(e.data)));
es.addEventListener("node_online", e => markOnline(JSON.parse(e.data)));
es.addEventListener("node_offline", e => markOffline(JSON.parse(e.data)));
es.addEventListener("edge_update", e => patchedge(JSON.parse(e.data)));
```

Reconnect on error/close with exponential backoff (1s → 30s max).

### 6.3 Rendering Rules

- `link_status === "unreachable"` → dashed/stippled line.
- `link_status === "relayed"` → solid line with relay indicator (e.g.,
  different color or icon overlay).
- `link_status === "direct"` or `""`/absent → default solid line.

---

## 7. Versioning

| Version | Changes |
|---------|---------|
| 1.0     | Initial contract: nodes with id/role/x/y/z/cpu/mem, edges with source/target/latency/bandwidth |
| 2.0     | Added node mesh_ip & public_key, edge link_status, circuits array. Gossip-ready. |

## 8. Implementation Gap Analysis (2026-07-26)

This section documents the delta between the API contract (this spec) and the
current codebase. The developer task t_3e9ed39e should close these gaps.

### 8.1 Go Types (internal/topology/types.go)

Current code is missing three fields and one top-level array:

| Field | Struct | Status |
|-------|--------|--------|
| `PublicKey` | `TopologyNode` | MISSING — add `PublicKey string \`json:"public_key"\`` |
| `MeshIP` | `TopologyNode` | MISSING — add `MeshIP string \`json:"mesh_ip"\`` |
| `LinkStatus` | `TopologyEdge` | MISSING — add `LinkStatus string \`json:"link_status"\`` |
| `Circuits` | `TopologySnapshot` | MISSING — add `Circuits []TopologyCircuit \`json:"circuits"\`` |

The `TopologyCircuit` and `CircuitPath` structs from §5.1 must also be added
to types.go.

### 8.2 Interfaces (internal/topology/interfaces.go)

`TopologyPeers` is missing two methods:

```go
// MeshIP returns the node's primary mesh IP address (first /32 AllowedIP).
// Returns "" when no mesh IP is assigned.
MeshIP(peerID string) string

// PublicKey returns the node's WireGuard public key in base64 format.
// Returns "" when unknown.
PublicKey(peerID string) string
```

### 8.3 Adapter (internal/web/handlers_topology.go)

`meshTopologyPeers` must implement the two new `TopologyPeers` methods:

- `MeshIP(peerID string)`: For the local node, derive from config's first
  AllowedIP. For remote peers, read from RoutingTable's `PeerEntry.AllowedIPs[0]`
  (strip CIDR suffix). Return `""` if no mesh IP is configured.
- `PublicKey(peerID string)`: Convert the hex public key to base64 (standard
  WireGuard format). Implement `peer.Base64Key()` or equivalent conversion.

The `buildTopologySnapshot` function must populate the new fields:

- Set `node.PublicKey` and `node.MeshIP` from the peers adapter.
- Set `edge.LinkStatus` from the link type determination logic (§5.4).
  During the WireGuard-only phase, all edges default to `"direct"` unless
  the path probe cache reports no latency (→ `"unreachable"`).
- Propagate `snapshot.Circuits` from the CircuitManager when available.
  If `s.circuitManager` is nil, set to `nil` (omitempty in JSON serialization).

### 8.4 Mock Data (internal/topology/mock/mock.go)

`mock.Snapshot()` does not populate `PublicKey`, `MeshIP`, or `LinkStatus`.
After the types are updated, the mock builder must:

- Set `PublicKey` to a deterministic base64 encoding of the hex node ID.
- Set `MeshIP` to a deterministic fake IP (e.g., `10.144.144.N`).
- Set `LinkStatus` to `"direct"` for all mock edges.

### 8.5 SSE Delta Events (internal/web/handlers_topology.go)

`BroadcastTopologyNodeUpdate` and `BroadcastTopologyEdgeUpdate` must include
the new fields in their payloads so that SSE delta events carry the same
shape as the REST snapshot.

### 8.6 Frontend (web/static/js/topology.js)

No urgent changes required — all new fields are optional per §6.1. However,
the frontend SHOULD eventually:

- Display `mesh_ip` in the node hover tooltip (replacing `node.id.substring(0,8)`).
- Display `public_key` in a detail panel or copyable field.
- Use `link_status` for edge rendering: dashed line for `"unreachable"`,
  different color/indicator for `"relayed"`.
- Handle `circuits` array if present (highlight active circuit paths).

### 8.7 Order of Work

1. Update `internal/topology/types.go` — add the four missing fields/structs.
2. Update `internal/topology/interfaces.go` — add `MeshIP` and `PublicKey`.
3. Implement the two new methods on `meshTopologyPeers`.
4. Update `buildTopologySnapshot` to populate new fields.
5. Update `mock.Snapshot()` to populate new fields.
6. Update SSE broadcast helpers to include new fields.
7. Verify all existing tests pass after changes.
8. (Optional) Update frontend to consume new fields.

This order respects compile-time dependencies: types → interfaces → adapters
→ builder → mock → SSE broadcasts. The entire change is backward-compatible
because all new fields are optional in the contract.