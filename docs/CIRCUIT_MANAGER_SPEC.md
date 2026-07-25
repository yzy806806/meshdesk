# MeshDesk CircuitManager Design Specification

**Version:** 1.0
**Status:** Proposed
**Created:** 2026-07-26
**Source:** Agora motion motion-ab7dcffe52e8, action item 2/6

---

## Overview

The CircuitManager is the central orchestrator for circuit lifecycle management in
the MeshDesk multi-path dispersed proxy. It owns:

1. **Path selection** — finds two node-disjoint paths from entry to exit using the
   mesh latency matrix (BFS k-shortest, k=2) with probe-based fallback.
2. **Chunk-to-path assignment** — distributes chunks across the two paths using a
   pluggable strategy (round-robin, weighted by path quality).
3. **Circuit lifecycle** — manages the full FSM: creation, active tracking
   (keepalive RTT, path health), teardown (flush in-flight chunks, send
   ChunkStreamEnd markers), and resource cleanup (zero keys, free buffers).

This spec defines the data model, interfaces, algorithm, state machine, and
acceptance criteria. It does not prescribe implementation details (concrete
Go types, synchronization primitives) — those are for the developer task.

---

## 1. Data Model

### 1.1 MeshLatencyMatrix

The latency matrix represents the mesh as a weighted undirected graph. Nodes are
mesh peers; edges are peer-to-peer connections with measured RTT.

```
MeshLatencyMatrix {
    nodes: map[NodeID]NodeInfo       // all known mesh nodes
    edges: map[(NodeID, NodeID)]LatencyEdge  // peer connections
    updated_at: timestamp
}

NodeInfo {
    id: NodeID                // hex public key
    hostname: string
    mesh_addr: string         // mesh IP:port
    role: NodeRole            // entry | relay | exit | standard
    capabilities: [Capability] // relay, exit
    status: NodeStatus        // online | offline | degraded
}

LatencyEdge {
    source: NodeID
    target: NodeID
    rtt_ms: float64           // measured RTT in milliseconds
    bandwidth_bps: int64      // measured bandwidth (0 = unknown)
    measured_at: timestamp
    source: EdgeSource        // probe | gossip | keepalive
}

NodeID = string               // hex-encoded public key
Capability = "relay" | "exit"
NodeRole = "entry" | "relay" | "exit" | "standard"
NodeStatus = "online" | "offline" | "degraded"
EdgeSource = "probe" | "gossip" | "keepalive"
```

**Data sources:**

| Source | What it provides | Frequency |
|--------|-----------------|-----------|
| P2P gossip | Peer list, capabilities, advertised RTT | On change / periodic |
| Keepalive pings | Measured RTT between connected peers | Every 30s |
| Active probing | On-demand RTT to relay candidates | Per circuit setup |
| Topology API | Full snapshot for dashboard | On request |

**Invariants:**
- Edges exist only between nodes with an established peer connection.
- A node's `capabilities` set determines whether it can appear in a circuit:
  - `relay` → can be a relay hop
  - `exit` → can be a circuit exit node
- Latency values are never negative. Zero means "unmeasured" — the BFS algorithm
  applies a penalty weight for unmeasured edges.

### 1.2 Circuit

```
Circuit {
    id: CircuitID                   // 16 bytes, random
    state: CircuitState             // FSM state
    created_at: timestamp
    last_activity: timestamp

    // Endpoints
    entry: NodeID
    exit: NodeID
    target_addr: string             // host:port

    // E2E encryption
    e2e_key: [32]byte               // ChaCha20-Poly1305, zeroed on teardown
    padding_seed: [32]byte          // per-circuit padding CSPRNG seed, zeroed on teardown

    // Paths (always exactly 2)
    paths: [2]CircuitPath
    assignment_strategy: ChunkAssignmentStrategy

    // Health
    keepalive_interval: duration    // 30s default
    idle_timeout: duration          // 5 min default
    created_at: timestamp
}

CircuitPath {
    index: int                      // 0 or 1
    hops: [NodeID]                  // relay nodes in order (entry→relay₁→...→exit)
                                    // empty list = direct entry→exit
    relay_keys: [[32]byte]          // per-hop onion header keys, one per relay

    // Runtime state
    total_chunks: uint64            // chunks dispatched on this path
    total_bytes: uint64             // bytes dispatched on this path
    last_rtt: duration              // last measured RTT from keepalive
    healthy: bool                   // path is currently usable
    established_at: timestamp
}

CircuitID = [16]byte

CircuitState = enum {
    CREATING    // setup in progress, ECDH handshake not yet complete
    ACTIVE      // ECDH complete, data flowing on both paths
    TEARDOWN    // teardown initiated, flushing remaining data
    CLOSED      // circuit fully closed, resources freed
}
```

### 1.3 ChunkAssignmentStrategy

```
ChunkAssignmentStrategy = interface {
    // AssignPath returns which path index (0 or 1) should carry the next chunk.
    // The circuit provides path health and latency data for weighted decisions.
    AssignPath(circuit: *Circuit) int

    // Name returns a human-readable strategy name for config/logging.
    Name() string
}
```

**Concrete strategies:**

| Strategy | Description | AssignPath behavior |
|----------|------------|---------------------|
| `round-robin` | Alternates between paths | `toggle % 2` |
| `weighted` | Proportional to path quality | Path with lower RTT gets more chunks. Ratio = `pathB_RTT / (pathA_RTT + pathB_RTT)` |
| `fastest-only` | Only uses the fastest path (failover) | Returns healthiest path index; falls back to other if primary unhealthy |

---

## 2. Path Selection Algorithm

### 2.1 BFS k-Shortest Node-Disjoint Paths

The algorithm finds `k=2` paths from entry node to exit node that minimize total
latency and share no relay nodes.

**Preconditions:**
- The mesh latency matrix is populated (at minimum: entry and exit are vertices,
  relay candidates have edges to both entry and exit or to each other).
- Edge weights are RTT values (milliseconds). Unmeasured edges get a default
  penalty weight of 500ms.

**Algorithm (single shortest path):**

```
ShortestPath(graph, source, target, blocked_nodes):
    // Dijkstra's algorithm on the latency-weighted graph.
    // blocked_nodes: set of nodes to exclude (for disjointness).

    dist = map[node]infinity
    prev = map[node]nil
    dist[source] = 0
    pq = min-heap of (dist, node)

    while pq not empty:
        u = pq.pop()
        if u == target: break
        for each neighbor v of u where v not in blocked_nodes:
            weight = graph.edge(u, v).rtt_ms
            if weight == 0: weight = 500  // penalty for unmeasured
            alt = dist[u] + weight
            if alt < dist[v]:
                dist[v] = alt
                prev[v] = u
                pq.push(v)

    if dist[target] == infinity: return nil
    return reconstructPath(prev, target)
```

**Algorithm (k-disjoint paths):**

```
KShortestDisjointPaths(graph, source, target, k=2):
    paths = []
    blocked = {}

    for i in 1..k:
        path = ShortestPath(graph, source, target, blocked)
        if path == nil: break
        paths.append(path)
        // Block all relay nodes on this path (excluding source/target).
        for each node in path[1..len-2]:  // skip entry and exit
            blocked.add(node)

    if len(paths) < k:
        return error("insufficient disjoint paths")
    return paths
```

**Relay node extraction:**
Each returned path is a sequence `[entry, relay₁, ..., relayₙ, exit]`. The
relay set is `path[1:len-1]`. These become the `CircuitPath.hops` array.

**Disjointness guarantee:**
By adding intermediate nodes to `blocked` after each path is found, the second
shortest path cannot use any relay from the first path. Entry and exit nodes
are never blocked — they are the circuit endpoints.

### 2.2 Fallback: Probe-Based Selection

When the mesh latency matrix is insufficient (fewer than `MinCandidates` relay
nodes have known RTTs), CircuitManager falls back to the existing
`PathSelector.SelectPaths` probe-based approach:

1. Query mesh for all `relay`-capable nodes.
2. Filter by advertised RTT (top `MaxCandidates`).
3. Actively probe each candidate in parallel.
4. Select two candidates with the lowest RTT that are disjoint (different
   NodeIDs for single-hop paths).
5. Build paths: `[entry, relay₁, exit]`, `[entry, relay₂, exit]`.

**Selection strategy decision matrix:**

| Condition | Strategy | Rationale |
|-----------|----------|-----------|
| Mesh latency matrix has ≥2 relay candidates with known RTTs | BFS k-shortest | Optimal path through mesh graph |
| Latency matrix has <2 candidates | Probe-based fallback | On-demand probing for bootstrap |
| Both strategies fail | Error: no paths available | Cannot establish circuit |

### 2.3 Path Overlap Detection

The hard requirement from PROXY_DESIGN.md §1.5: **reject any circuit where two
candidate paths share a relay node.**

This is enforced by the `blocked` set in the BFS algorithm and by the disjoint
check in the probe-based fallback. The CircuitManager also validates at creation
time that `path1.RelayNodes ∩ path2.RelayNodes == ∅`.

### 2.4 On-Demand Probing

Path probing scales O(K), not O(N²) (PROXY_DESIGN.md §1.5):

1. CircuitManager queries the mesh for relay-capable nodes.
2. If the latency matrix has recent (<30s) RTT data for enough candidates,
   use BFS directly — zero probes.
3. If stale or insufficient, probe the top K candidates (K ≤ 10) in parallel.
4. Update the latency matrix with probe results for future circuits.

---

## 3. Chunk-to-Path Assignment

### 3.1 Assignment Strategies

The assignment strategy is selected per-circuit via config:

```yaml
proxy:
  circuit:
    chunk_assignment: "round-robin"   # round-robin | weighted | fastest-only
```

### 3.2 Round-Robin (v1 default)

```
RoundRobin.AssignPath(circuit):
    return circuit._next_path_index % 2
    circuit._next_path_index += 1
```

Simple, evenly distributes chunks across both paths. Already implemented in
`Dispatcher.Run()`. No per-path quality awareness.

### 3.3 Weighted Assignment (v2)

```
Weighted.AssignPath(circuit):
    rtt_a = circuit.paths[0].last_rtt
    rtt_b = circuit.paths[1].last_rtt

    // If both unmeasured, fall back to round-robin.
    if rtt_a == 0 and rtt_b == 0: return round_robin

    // Handle single-path failure.
    if !circuit.paths[0].healthy: return 1
    if !circuit.paths[1].healthy: return 0

    // Weight by inverse latency: faster path gets more chunks.
    // p(path_0) = rtt_1 / (rtt_0 + rtt_1)
    // Example: path0=20ms, path1=80ms → 80% of chunks go to path0.
    if rtt_a == 0: weight_a = 1.0   // unmeasured path gets equal share
    if rtt_b == 0: weight_b = 1.0

    weight_a = rtt_b / (rtt_a + rtt_b)  // faster = larger weight
    // Random selection weighted by quality.
    return random([0→weight_a, 1→(1-weight_a)])
```

Weighted assignment requires RTT measurements from keepalives. Until the first
keepalive round-trip completes, the strategy falls back to round-robin.

### 3.4 Integration with Dispatcher

The Dispatcher calls `AssignPath` once per chunk before encryption:

```
Dispatcher.Run():
    for each chunk in chunker.Split(data):
        path_idx = circuit.assignment_strategy.AssignPath(circuit)
        path = circuit.paths[path_idx]
        next_hop = path.first_hop()
        wc = EncodeChunk(chunk, circuit.e2e_key, path.relay_keys[0], next_hop, circuit.id)
        sendChunk(path_idx, wc)
        circuit.paths[path_idx].total_chunks++
        circuit.paths[path_idx].total_bytes += len(chunk.Payload)
```

---

## 4. Circuit Lifecycle FSM

### 4.1 State Machine

```
    ┌──────────┐
    │  (start) │
    └────┬─────┘
         │ ecdh_setup()
         ▼
    ┌──────────┐   ack received   ┌──────────┐
    │ CREATING │─────────────────▶│  ACTIVE  │
    └────┬─────┘                  └────┬─────┘
         │ ack timeout                  │ teardown trigger:
         │ ack rejected                 │   - TCP close (EOF)
         │                              │   - idle timeout
         ▼                              │   - path failure on both
    ┌──────────┐                        │   - exit sends teardown
    │  CLOSED  │◀───────────────────────┘
    └──────────┘   teardown complete
         ▲
         │ teardown timeout
    ┌────┴─────┐
    │ TEARDOWN │──────────flush complete──▶ CLOSED
    └──────────┘
```

### 4.2 State Transitions

#### CREATING → ACTIVE

**Trigger:** CircuitAck received from exit with `Accepted=true`.
**Action:**
- Derive E2E shared key from ECDH.
- Initialize path health (mark both as healthy).
- Start keepalive goroutine.
- Start idle timeout timer.

#### CREATING → CLOSED (rejected)

**Trigger:** CircuitAck with `Accepted=false` OR setup timeout (10s).
**Action:**
- Zero any partial key material.
- Release circuit ID.
- Log rejection reason.

#### ACTIVE → TEARDOWN

**Triggers (any one):**
1. **TCP close:** Entry-side SS connection returns EOF.
2. **Idle timeout:** No data for `IdleTimeout` (default 5 min).
3. **Path failure:** Both paths report unhealthy (keepalive timeout on both).
4. **Exit-initiated:** Exit sends `MsgCircuitTeardown` (target TCP closed, NACK
   retries exhausted, or stream reassembly timeout).
5. **Explicit:** Operator/admin action.

**Action on teardown initiation:**
- Set `CircuitState = TEARDOWN`.
- **FLUSH:** Send `ChunkStreamEnd` markers on both paths so the exit knows the
  stream is complete (if not already sent by the Dispatcher).
- Stop accepting new data from the SS connection.
- Cancel keepalive goroutine.
- Wait for in-flight chunks to be acknowledged or timeout.

#### TEARDOWN → CLOSED

**Trigger:** Flush complete (all ChunkStreamEnd markers acknowledged) OR teardown
timeout (10s).

**Action:**
- Zero E2E key and padding seed in memory.
- Close path connections.
- Close SS connection.
- Remove circuit from tracking table.
- Emit `circuit_close` SSE event for topology UI.
- Release circuit ID.

### 4.3 Circuit Tracking

CircuitManager maintains an in-memory circuit table:

```
CircuitManager {
    circuits: map[CircuitID]*Circuit     // active + tearing-down circuits
    circuits_by_exit: map[NodeID][]CircuitID  // for exit-node health tracking
    stats: CircuitStats                   // aggregate metrics
}

CircuitStats {
    total_created: uint64
    total_closed: uint64
    active: int                           // len(circuits) where state == ACTIVE
    tearing_down: int
    total_chunks_dispatched: uint64
    total_bytes_dispatched: uint64
    avg_circuit_lifetime: duration
}
```

Circuit data is exposed to the topology API via `GET /api/topology` (see
3D_TOPOLOGY_DESIGN.md):

```json
{
  "circuits": [
    {
      "id": "c-abc123",
      "state": "active",
      "entry": "entry-tokyo",
      "exit": "exit-uswest",
      "target": "example.com:443",
      "paths": [
        {"hops": ["entry-tokyo", "relay-b", "exit-uswest"], "latency_ms": 45, "chunks": 1234},
        {"hops": ["entry-tokyo", "relay-c", "relay-d", "exit-uswest"], "latency_ms": 62, "chunks": 1180}
      ],
      "age_seconds": 127,
      "bytes_dispatched": 52428800
    }
  ]
}
```

### 4.4 Keepalive + Path Health

Every `KeepaliveInterval` (30s), the entry sends a `MsgKeepalive` on each path.
The exit echoes the timestamp back. The entry computes `RTT = now - timestamp`.

```
Path Health State Machine:
    HEALTHY ──(keepalive_response)──▶ HEALTHY, update RTT
    HEALTHY ──(keepalive_timeout × 2)──▶ DEGRADED
    DEGRADED ──(keepalive_response)──▶ HEALTHY
    DEGRADED ──(keepalive_timeout × 4)──▶ UNHEALTHY
    UNHEALTHY ──(keepalive_response)──▶ HEALTHY
```

- `healthy=false` means the path is not used for new chunk dispatch.
- If both paths are unhealthy, the circuit transitions to TEARDOWN.
- The fastest healthy path is used for teardown messages (circuit_teardown) and
  NACK responses.

### 4.5 Teardown with Flush

When tearing down, the CircuitManager must ensure the exit receives the
ChunkStreamEnd marker so its reassembler completes the stream. The flush
sequence:

```
1. Entry: stop reading from SS connection.
2. Entry: send ChunkStreamEnd on BOTH paths (redundancy — one may be unhealthy).
3. Entry: track which paths' stream-end markers were acknowledged
   (ack from exit's MsgACK or implicit via circuit_teardown_ack).
4. Wait up to FlushTimeout (10s) for acks.
5. Entry: send MsgCircuitTeardown on fastest healthy path.
6. Entry: zero keys, close connections, remove from table.
7. Exit: on receiving MsgCircuitTeardown, flush reassembly buffer to target TCP,
   close target TCP, purge circuit state.
```

**Edge case: path dead during teardown.**
If only one path is healthy during teardown, send ChunkStreamEnd + teardown on
the healthy path. The exit's reassembler has an OrphanTimeout (30s) — it will
clean up the dead path's stream buffer independently.

### 4.6 Cleanup

On CLOSED:
- Zero all key material: `e2e_key`, `padding_seed`, per-path `relay_keys`.
- Close all mesh connections for this circuit.
- Remove from `CircuitManager.circuits`.
- Emit `circuit_close` event.
- Update stats.

---

## 5. CircuitManager Interface

### 5.1 Core API

```
CircuitManager {
    // CreateCircuit initiates a new circuit to the given target.
    // Returns immediately with the circuit in CREATING state.
    // The caller receives circuit events via the event callback.
    CreateCircuit(target_addr: string) → (CircuitID, error)

    // TeardownCircuit gracefully tears down a circuit with flush.
    TeardownCircuit(circuit_id: CircuitID, reason: string) → error

    // GetCircuit returns the current circuit state.
    GetCircuit(circuit_id: CircuitID) → (*Circuit, error)

    // ListCircuits returns all active and tearing-down circuits.
    ListCircuits() → [CircuitInfo]

    // GetLatencyMatrix returns the current mesh latency graph.
    GetLatencyMatrix() → MeshLatencyMatrix

    // UpdateLatencyMatrix merges new latency data from gossip/probes.
    UpdateLatencyMatrix(edges: [LatencyEdge])

    // HandleCircuitAck processes the exit's response to a circuit setup.
    HandleCircuitAck(circuit_id: CircuitID, ack: CircuitAck)

    // HandleTeardown processes an exit-initiated teardown.
    HandleTeardown(circuit_id: CircuitID, msg: TeardownMsg)

    // HandleKeepaliveResponse processes a keepalive echo to measure RTT.
    HandleKeepaliveResponse(circuit_id: CircuitID, path_idx: int, timestamp: int64)

    // GetCircuitStats returns aggregate circuit metrics.
    GetCircuitStats() → CircuitStats

    // OnCircuitEvent registers a callback for circuit lifecycle events.
    OnCircuitEvent(callback: func(event: CircuitEvent))

    // Shutdown gracefully tears down all circuits and stops the manager.
    Shutdown()
}
```

### 5.2 CircuitEvent

```
CircuitEvent = {
    type: CircuitEventType
    circuit_id: CircuitID
    timestamp: timestamp
    data: any   // type-specific payload
}

CircuitEventType = enum {
    CIRCUIT_CREATED
    CIRCUIT_ESTABLISHED
    CIRCUIT_TEARDOWN_INITIATED
    CIRCUIT_CLOSED
    PATH_DEGRADED
    PATH_RESTORED
    PATH_UNHEALTHY
    KEEPALIVE_TIMEOUT
    NACK_RECEIVED
}
```

### 5.3 Configuration

```yaml
proxy:
  circuit:
    # Path selection
    path_count: 2                         # always 2 for v1
    selection_strategy: "bfs"             # bfs | probe | auto
    max_candidates: 10                    # K for on-demand probing
    probe_timeout: 3s
    min_candidates: 2

    # Chunk assignment
    chunk_assignment: "round-robin"       # round-robin | weighted | fastest-only

    # Lifecycle
    setup_timeout: 10s                    # max time for CREATING → ACTIVE
    idle_timeout: 5m                      # ACTIVE → TEARDOWN if no data
    keepalive_interval: 30s               # periodic ping interval
    flush_timeout: 10s                    # max wait during TEARDOWN → CLOSED
    orphan_timeout: 30s                   # exit-side incomplete buffer cleanup
    stream_reassembly_timeout: 60s        # max per-stream reassembly time
    nack_timeout: 5s                      # gap detection → NACK send
    max_nack_retries: 3                   # max NACKs before circuit teardown

    # Path health
    keepalive_timeout: 10s                # no response → DEGRADED
    keepalive_dead_timeout: 40s           # DEGRADED → UNHEALTHY

    # DoS protection
    max_reassembly_window: 256            # max chunks ahead of ackBase
    max_circuits_per_exit: 1024           # per exit node limit
    max_circuits_total: 4096              # total circuits on this entry
```

### 5.4 Integration Points

```
EntryNode
  │
  ├── SS Listener (accepts user traffic)
  │     │
  │     └── handleConnection(conn)
  │           │
  │           ├── CircuitManager.CreateCircuit(target)
  │           │     │ selects paths (BFS or probe)
  │           │     │ sends CircuitSetup to exit
  │           │     │ returns circuit in CREATING state
  │           │     │
  │           │     └── on CircuitAck:
  │           │           CircuitManager.HandleCircuitAck(id, ack)
  │           │           → state = ACTIVE
  │           │           → emit CIRCUIT_ESTABLISHED
  │           │
  │           ├── NewDispatcher(circuit) ──→ Dispatcher.Run()
  │           │     │ reads from SS conn
  │           │     │ chunker.Split(data)
  │           │     │ circuit.assignment_strategy.AssignPath(circuit)
  │           │     │ EncodeChunk(...)
  │           │     │ sendChunk(path_idx, wire_chunk)
  │           │
  │           └── on conn EOF:
  │                 CircuitManager.TeardownCircuit(id, "tcp close")
  │
  ├── Keepalive goroutines (one per circuit)
  │     │ sends MsgKeepalive every 30s on each path
  │     │ on response: CircuitManager.HandleKeepaliveResponse(...)
  │
  └── CircuitManager.Shutdown() (on EntryNode.Close())

ExitNode
  │
  ├── CircuitSetup handler
  │     │ validates port, ECDH key agreement
  │     │ returns CircuitAck
  │     │ registers circuit locally
  │
  ├── HandleWireChunk (per incoming chunk)
  │     │ DecodeChunk, feed to reassembler
  │     │ detect gaps → NACK
  │     │ reassembled data → target TCP
  │
  └── CircuitTeardown handler
        │ flush reassembly buffer
        │ close target TCP
        │ purge circuit
```

---

## 6. Data Flow Diagrams

### 6.1 Circuit Creation (Happy Path)

```
User App      Entry Node         CircuitManager        Exit Node        Target
  │               │                    │                    │              │
  │──TCP SYN───▶  │                    │                    │              │
  │               │──CreateCircuit──▶  │                    │              │
  │               │                    │──select paths──    │              │
  │               │                    │  (BFS or probe)    │              │
  │               │                    │──store CREATING──  │              │
  │               │                    │──CircuitSetup─────▶│              │
  │               │                    │                    │──ECDH key──  │
  │               │                    │                    │──validate──  │
  │               │                    │                    │──dial TCP───▶│
  │               │                    │◀───CircuitAck──────│              │
  │               │                    │──derive E2E key──  │              │
  │               │                    │──state=ACTIVE────  │              │
  │               │◀──circuit ready──  │                    │              │
  │               │──Dispatcher.Run──▶ │                    │              │
  │◀──TCP ack───  │                    │                    │              │
  │──data───────▶│                    │                    │              │
  │               │──chunk+encrypt──▶  │──WireChunk────────▶│──decrypt────▶│
  │               │                    │                    │──reassemble─▶│
```

### 6.2 Chunk Dispatch (Active)

```
Entry Node                        CircuitManager
  │                                     │
  │ read data from SS conn              │
  │ chunker.Split(data) → chunks        │
  │                                     │
  │ for each chunk:                     │
  │   path_idx = circuit.assignment_strategy.AssignPath(circuit)
  │   path = circuit.paths[path_idx]    │
  │   wc = EncodeChunk(chunk, key, ...) │
  │   sendChunk(path_idx, wc)           │
  │                                     │
  │   circuit.paths[path_idx].total_chunks++
  │   circuit.paths[path_idx].total_bytes += len(chunk.Payload)
  │                                     │
  │   circuit.last_activity = now       │
```

### 6.3 Teardown with Flush

```
Entry Node              CircuitManager               Exit Node
  │                          │                           │
  │ conn.EOF detected        │                           │
  │──TeardownCircuit(id)──▶  │                           │
  │                          │ state = TEARDOWN          │
  │                          │ stop reading SS           │
  │                          │                           │
  │                          │──ChunkStreamEnd(path0)──▶ │
  │                          │──ChunkStreamEnd(path1)──▶ │
  │                          │                           │──reassembler
  │                          │                           │  completes stream
  │                          │                           │──flush to target
  │                          │                           │──close target TCP
  │                          │                           │
  │                          │──MsgCircuitTeardown─────▶│
  │                          │                           │──purge circuit
  │                          │                           │
  │                          │ state = CLOSED            │
  │                          │ zero keys                 │
  │                          │ close connections         │
  │                          │ emit CIRCUIT_CLOSED       │
```

---

## 7. Error Handling

| Scenario | Detection | Response |
|----------|-----------|----------|
| No relay candidates | `KShortestDisjointPaths` returns < 2 paths | Circuit creation fails with `ErrNoPaths` |
| Path overlap detected | Validation at circuit creation | Circuit creation fails with `ErrPathOverlap` |
| Circuit setup timeout | `CREATING` state exceeds `setup_timeout` | Transition to CLOSED; report `ErrSetupTimeout` |
| Exit rejects circuit | `CircuitAck.Accepted=false` | Transition to CLOSED; report reason |
| Single path failure | Keepalive timeout on one path | Mark path unhealthy; continue on healthy path |
| Both paths fail | Keepalive timeout on both paths | Transition to TEARDOWN |
| Idle timeout | `last_activity + idle_timeout < now` | Transition to TEARDOWN |
| Chunk decode failure | AEAD verification fails at exit | Report `SecEventExitDecodeFail`; discard chunk |
| NACK retries exhausted | `nack_retry_count[seq] >= MaxNACKRetries` | Exit sends teardown; entry transitions to CLOSED |
| Reassembly window exceeded | Chunk seq ≥ ackBase + MaxReassemblyWindow | Discard chunk; report security event |
| Teardown flush timeout | No ack after `flush_timeout` | Force CLOSED; exit's orphan timeout cleans up |

---

## 8. Concurrency Model

CircuitManager is the single writer for circuit state transitions. All mutations
go through its methods, which internalize synchronization.

- **Circuit creation/teardown:** Serialized by CircuitManager's mutex per
  circuit.
- **Chunk dispatch:** Dispatcher reads circuit state (paths, assignment
  strategy) under read lock. Path stats are updated atomically.
- **Keepalive:** Runs in separate goroutines; updates path RTT via
  `HandleKeepaliveResponse` which mutates only `CircuitPath.last_rtt` and
  `CircuitPath.healthy`.
- **Latency matrix:** Updated asynchronously by gossip/probe threads.
  CircuitManager reads the matrix under a read lock during path selection.

---

## 9. Integration with Existing Code

### 9.1 What CircuitManager Replaces

| Existing Component | CircuitManager Role |
|-------------------|---------------------|
| `EntryNode.setupCircuit()` | `CircuitManager.CreateCircuit()` — centralized ECDH, path selection, state tracking |
| `EntryNode.teardownCircuit()` | `CircuitManager.TeardownCircuit()` — flush, cleanup, key zeroing |
| `SelectPaths()` in dispatcher.go | `CircuitManager.selectPaths()` — BFS k-shortest + probe fallback |
| Path toggle in `Dispatcher.Run()` | `ChunkAssignmentStrategy.AssignPath()` |
| `EntryNode.sessions` map | `CircuitManager.circuits` map |
| Scattered keepalive logic | Centralized in `CircuitManager` |

### 9.2 What CircuitManager Delegates

| Responsibility | Delegated To | Why |
|---------------|-------------|-----|
| Chunk splitting | `Chunker.Split()` | Pluggable chunking strategies |
| Chunk reassembly | `ExitReassembler` on exit node | Already implemented and tested |
| Wire encryption | `EncodeChunk()` / `DecodeChunk()` | CircuitManager is key management, not wire crypto |
| Relay forwarding | `Relay.ForwardChunk()` | Relay is a separate component |
| Onion header encryption | `ForwardingHeader.Encode()` | Already in protocol.go |
| Exit-side target TCP | `ExitNode` | Exit is a separate component |

### 9.3 Migration Path

1. Implement `CircuitManager` in `internal/proxy/circuit_manager.go`.
2. Wire `EntryNode` to use `CircuitManager` instead of its internal
   `setupCircuit`/`teardownCircuit`.
3. Update `Dispatcher` to use `ChunkAssignmentStrategy` instead of the inline
   `pathToggle`.
4. Add `GET /api/topology` circuits array from `CircuitManager.ListCircuits()`.
5. Remove old scattered circuit state from `EntryNode` (deprecate, not delete,
   until tests pass).

---

## 10. Acceptance Criteria

### A. Path Selection

- [ ] **AC-PS-01:** `KShortestDisjointPaths` returns 2 node-disjoint paths when
  the mesh graph has ≥2 relay nodes connected to both entry and exit.
- [ ] **AC-PS-02:** `KShortestDisjointPaths` returns the lowest-total-latency
  pair among all disjoint pairs (verified by exhaustive enumeration in tests).
- [ ] **AC-PS-03:** Path overlap detection rejects any pair where
  `path_a.relays ∩ path_b.relays ≠ ∅`.
- [ ] **AC-PS-04:** When a relay node has an unmeasured edge (RTT=0), BFS
  applies the 500ms penalty weight.
- [ ] **AC-PS-05:** Probe fallback is used when fewer than `MinCandidates`
  relays have known RTTs in the matrix.
- [ ] **AC-PS-06:** On-demand probing scales O(K) — only `MaxCandidates` (≤10)
  nodes are probed per circuit setup.

### B. Chunk Assignment

- [ ] **AC-CA-01:** Round-robin strategy alternates path 0 → 1 → 0 → 1
  consistently.
- [ ] **AC-CA-02:** Weighted strategy assigns chunks proportionally to inverse
  latency (faster path ~80% when 20ms vs 80ms).
- [ ] **AC-CA-03:** Weighted strategy falls back to round-robin when no RTT data
  is available.
- [ ] **AC-CA-04:** When one path is unhealthy, both strategies route all chunks
  to the healthy path.

### C. Circuit Lifecycle

- [ ] **AC-CL-01:** Circuit transitions CREATING → ACTIVE on successful
  CircuitAck.
- [ ] **AC-CL-02:** Circuit transitions CREATING → CLOSED on rejected
  CircuitAck or setup timeout (10s).
- [ ] **AC-CL-03:** Circuit transitions ACTIVE → TEARDOWN on TCP close, idle
  timeout (5m), or both-path failure.
- [ ] **AC-CL-04:** Circuit transitions ACTIVE → TEARDOWN on exit-initiated
  teardown (MsgCircuitTeardown received).
- [ ] **AC-CL-05:** Teardown sends ChunkStreamEnd markers on all healthy paths
  before closing.
- [ ] **AC-CL-06:** Flush timeout (10s) forces CLOSED even if stream-end acks
  are pending.
- [ ] **AC-CL-07:** On CLOSED, E2E key and padding seed are zeroed in memory
  (verified by reading the memory region after close).
- [ ] **AC-CL-08:** Circuit state is exposed via `ListCircuits()` for the
  topology API.
- [ ] **AC-CL-09:** Keepalive pings are sent every `KeepaliveInterval` (30s) on
  each active path.
- [ ] **AC-CL-10:** Path health transitions HEALTHY → DEGRADED after 2 missed
  keepalives (20s), DEGRADED → UNHEALTHY after 2 more (total 40s).

### D. Tracking and Observability

- [ ] **AC-TO-01:** `CircuitManager.GetCircuitStats()` returns accurate
  aggregate metrics (total created, closed, active, bytes dispatched).
- [ ] **AC-TO-02:** `CircuitManager.OnCircuitEvent()` fires lifecycle events
  (CREATED, ESTABLISHED, CLOSED, PATH_DEGRADED, PATH_RESTORED).
- [ ] **AC-TO-03:** `GET /api/topology` includes circuits array with paths,
  latency, and chunk counts.

### E. Error Handling

- [ ] **AC-EH-01:** Circuit creation fails with `ErrNoPaths` when fewer than 2
  disjoint paths can be found.
- [ ] **AC-EH-02:** Circuit creation fails with `ErrPathOverlap` when manually
  provided paths share relay nodes.
- [ ] **AC-EH-03:** NACK retries exhausted → circuit teardown initiated.
- [ ] **AC-EH-04:** Reassembly window exceeded → chunk discarded, security event
  emitted.

### F. Integration

- [ ] **AC-IN-01:** CircuitManager integrates with existing `EntryNode` without
  breaking existing SS listener flow.
- [ ] **AC-IN-02:** CircuitManager integrates with existing `Dispatcher` (chunk
  assignment via strategy interface).
- [ ] **AC-IN-03:** CircuitManager integrates with existing mesh transport
  (`DialFunc`).
- [ ] **AC-IN-04:** CircuitManager works with existing `CircuitConfig` for all
  timeout parameters.

### G. Security

- [ ] **AC-SE-01:** E2E keys never leave the CircuitManager's memory (not
  logged, not serialized, not exposed via API).
- [ ] **AC-SE-02:** Circuit IDs are generated with `crypto/rand` (16 bytes, 128
  bits of entropy).
- [ ] **AC-SE-03:** Path relay keys are unique per circuit per relay (not reused
  across circuits).
- [ ] **AC-SE-04:** Key zeroing on CLOSED is verifiable (unit test reads key
  buffer after close).

---

## 11. Test Strategy

### Unit Tests

| Test | Scope | Target |
|------|-------|--------|
| BFS shortest path on 5-node graph | Pure algorithm | AC-PS-01, AC-PS-02 |
| BFS k-shortest with blocked nodes | Pure algorithm | AC-PS-03 |
| BFS with unmeasured edges | Pure algorithm | AC-PS-04 |
| Empty graph → probe fallback | Integration | AC-PS-05 |
| Round-robin assignment | Unit | AC-CA-01 |
| Weighted assignment with known RTTs | Unit | AC-CA-02, AC-CA-03 |
| Circuit FSM all transitions | Unit | AC-CL-01 through AC-CL-04 |
| Teardown flush sequence | Unit | AC-CL-05, AC-CL-06 |
| Key zeroing verification | Unit | AC-CL-07, AC-SE-04 |
| Keepalive path health FSM | Unit | AC-CL-10 |
| Circuit stats aggregation | Unit | AC-TO-01 |
| Error scenarios | Unit | AC-EH-01 through AC-EH-04 |

### Integration Tests

| Test | Scope | Target |
|------|-------|--------|
| EntryNode → CircuitManager → Dispatcher flow | Integration | AC-IN-01, AC-IN-02 |
| CircuitManager with real mesh transport | Integration | AC-IN-03 |
| Topology API circuits array | Integration | AC-TO-03 |
| End-to-end: SS → chunk → two paths → exit reassembly | Integration | AC-IN-01 through AC-IN-03 |

### Security Tests

| Test | Scope | Target |
|------|-------|--------|
| E2E key not exposed in API | Security | AC-SE-01 |
| Circuit ID entropy | Security | AC-SE-02 |
| Per-circuit relay key uniqueness | Security | AC-SE-03 |

---

## 12. Design Decisions Log

### Decision 1: BFS vs Dijkstra

**Chosen:** Dijkstra's algorithm (referred to as "BFS" in the task description
for simplicity).

**Rationale:** The mesh graph has weighted edges (RTT in ms). Classic BFS finds
shortest paths in unweighted graphs. Since we need latency-minimized paths
through the mesh, Dijkstra is the correct algorithm. The spec uses "BFS
k-shortest" as the feature name but implements Dijkstra under the hood.

### Decision 2: Single-hop vs Multi-hop Paths (v1)

**Chosen:** Support single-hop paths only for v1 (entry → relay → exit).

**Rationale:** The current `PathSelector` builds single-hop paths. Multi-hop
paths (entry → relay₁ → relay₂ → exit) require the relay-to-relay onion
encryption layer which is specified but not yet implemented in `Relay.ForwardChunk`
(the current relay passes the header through unmodified). The `KShortestDisjointPaths`
algorithm supports multi-hop paths — when the mesh graph has relay-to-relay
edges, it will naturally produce multi-hop paths.

### Decision 3: CircuitManager as a New Package

**Chosen:** Keep CircuitManager in `internal/proxy/` alongside existing code.

**Alternative:** New `internal/circuit/` package.

**Rationale:** PROXY_DESIGN.md §7 scoped `internal/circuit/` as a new package,
but the current implementation has co-located all proxy components under
`internal/proxy/`. Moving circuit management to a separate package would create
a circular dependency (circuit depends on proxy protocol types). Keeping it in
`proxy` avoids this while still offering clean separation via the file
boundary.

### Decision 4: CircuitManager Owns Key Lifecycle

**Chosen:** CircuitManager generates, stores, and zeros all circuit keys.

**Rationale:** Currently, keys are scattered: ECDH in `EntryNode.setupCircuit`,
E2E in DispatcherConfig, relay keys in Path. Centralizing key management in
CircuitManager gives a single place to enforce the "zero on CLOSED" contract
(AC-CL-07, AC-SE-04) and reduces the risk of key leakage through scattered
references.

---

## 13. Open Questions

1. **Multi-hop relay forwarding:** The current `Relay.ForwardChunk` passes the
   original header through. True onion routing (each relay re-encrypts the
   header) is specified but not yet implemented. Should CircuitManager support
   multi-hop paths with the current relay behavior, or wait for true onion
   relay support? **Recommendation:** Support the graph structure now (the BFS
   algorithm handles it), but validate at circuit creation that all paths are
   single-hop until onion relay is done.

2. **Exit-initiated teardown transport:** When the exit node needs to tear down
   a circuit (NACK retries exhausted, target TCP closes), how does it signal
   the entry? Currently there's no reverse circuit. **Recommendation:** Send
   the teardown message on the same mesh connection used for CircuitAck. The
   entry listens on that connection for reverse control messages.

3. **Latency matrix freshness:** At what age should an edge be considered
   stale? **Recommendation:** 60 seconds. After 60s without a new measurement,
   the edge RTT is considered stale and ignored by the BFS selector. This
   forces a probe refresh if the matrix is too old.

---

## 14. References

- PROXY_DESIGN.md §1.5 (Path Selection), §1.6 (Exit Latency Matrix),
  §1.8 (Circuit Lifecycle), §1.9 (Forwarding Header Obfuscation)
- 3D_TOPOLOGY_DESIGN.md (Circuit visualization in topology API)
- NETWORKING_GAP_ANALYSIS.md (Gossip protocol, P2P latency data)
- `internal/proxy/path_selector.go` (Existing probe-based selection)
- `internal/proxy/dispatcher.go` (Existing round-robin dispatch)
- `internal/proxy/entry_node.go` (Existing circuit lifecycle)
- `internal/proxy/protocol.go` (CircuitConfig, CircuitState, circuit messages)