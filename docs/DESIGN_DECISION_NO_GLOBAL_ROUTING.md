# Design Decision: No Global Routing Table — Per-Pair Reactive Fallback

**Status:** Adopted (motion-fb0fdd61c936, 2026-08-07)
**Phase:** Node Auto-Interconnect (post-v1.2.1)
**Author:** architect
**Supersedes:** None. Clarifies scope of AGENTS.md goal item #4 (全局路由表).

---

## 1. Decision

**This phase does NOT implement a global Peer-Center routing table.**

The four-node stop condition ("any two nodes TUN-ping reachable, direct-first,
relay on failure") is satisfied by the existing per-pair `NatSession` state
machine and `tryRelayFallback` relay selection. Multi-hop transit
(A→relay1→relay2→B where intermediate nodes forward traffic they did not
originate) is **explicitly out of scope** for this phase.

## 2. Rationale

### 2.1 The stop condition demands at most one relay hop

The four-node topology has two shared (relay-capable) nodes and two ordinary
nodes. Every unreachable pair (e.g., 阿里云↔N1 across IPv4/IPv6, or
txcloud↔Oracle ARM across IPv6) shares at least one relay-capable node that
has active sessions to both endpoints. The maximum useful path is therefore
**one relay hop** (A→relay→B), which the existing code already handles.

A Peer-Center global routing table solves a different problem: large-scale
multi-hop transit (A→B→C→D) where intermediate nodes forward traffic they
did not originate. That problem does not exist at four nodes.

### 2.2 The existing data path already implements "direct-first, relay-fallback"

The full connection lifecycle, traced in code:

```
NotifyJoin (gossip event)
  → NatTraversal.InitiateConnection
    → runStateMachine (per-peer goroutine)
      → STUN_DISCOVERY (handleStunDiscovery, nat.go:486)
        → if both sides symmetric NAT → transitionToRelay (nat.go:603)
        → else → DIRECT_PROBE (handleDirectProbe, nat.go:537)
          → if hole-punch succeeds → DIRECT → ACTIVE (nat.go:463)
          → if hole-punch fails → RELAY_FALLBACK
            → transitionToRelay → SelectBestRelay → circuit_setup via gossip

When data needs to flow (DialVirtualPort, node.go:1225):
  → if no direct session → tryRelayFallback (relay_dialer.go:316)
    → collect CapRelay candidates from gossip (GetRelayCandidates, events.go:542)
    → filter: exclude self, target, at-capacity, symmetric-NAT, dead-session
    → sort by RTT ascending
    → DialViaRelay (relay_dialer.go:258) iterates each candidate on port 0x524C
      until one succeeds
```

This is a reactive, per-pair state machine — not a globally computed routing
table. It produces exactly the behavior the stop condition requires:

- **Direct-first:** `handleDirectProbe` attempts hole-punching on advertised
  endpoints before any relay is considered.
- **Relay on failure:** `transitionToRelay` + `tryRelayFallback` select the
  best relay from gossip-known `CapRelay` peers, filtered by health and
  sorted by RTT.
- **Automatic:** No manual configuration of relay paths is needed — the
  state machine transitions autonomously based on probe results.

### 2.3 Gossip metadata already provides the necessary topology information

The `NodeMeta` struct (delegate.go:19) propagates everything needed for
relay selection via gossip:

| Field | Purpose |
|---|---|
| `Endpoints` | All reachable IP:port pairs (IPv4/IPv6/mesh IP) |
| `CapRelay` | Whether the node can forward relay circuits |
| `NatType` | NAT classification (filters symmetric NAT relays) |
| `RTT` | Self-measured RTT to gossip seed (relay selection sort key) |
| `LoadCircuits` / `MaxCircuits` | Capacity filtering |

`GetRelayCandidates()` (events.go:542) returns all `CapRelay=true` peers
from the gossip pool. `tryRelayFallback` (relay_dialer.go:316) further
filters these by health and session availability. No additional topology
broadcast mechanism is needed — the gossip layer already propagates the
information that drives routing decisions.

### 2.4 Over-engineering risk

Building a Peer-Center global routing table would require:
- A new gossip message type for peer-map reporting (topology broadcast)
- A central peer-map aggregation service (on the lowest-ID node)
- A path computation algorithm (Dijkstra/BFS over the global topology graph)
- Path invalidation and convergence logic

This is substantial new complexity for a problem that does not exist at the
four-node scale. The YAGNI principle applies: if future testing proves
per-pair fallback insufficient, a routing table can be added then — but
preemptively building it would violate the project's "don't over-engineer"
constraint.

## 3. Scope Boundaries

### In scope (already implemented, no new code needed)

1. **Gossip advertise endpoints** — `NodeMeta.Endpoints`, `detectOutboundIPs`,
   `resolveAdvertiseAddr`, `OnEndpointDiscovered` reactive append.
2. **NotifyJoin auto-connect** — `InitiateConnection`, `DialPeerByEndpoint`
   direct + relay fallback.
3. **Single-hop relay (0x524C)** — `RelayHandler`, `DialViaRelay`,
   `RelayPathBuilder`, `RelaySelector` top-K, `circuit_setup`/`pong` health
   monitoring + failover.

### Out of scope (deferred to future phase if needed)

1. **Global Peer-Center routing table** — No topology broadcast, no central
   peer-map aggregation, no global path computation.
2. **Multi-hop transit relay** — A→relay1→relay2→B where intermediate nodes
   forward traffic they did not originate. The existing `MaxRelayHops`
   config (default: 2, nat.go:137) refers to the NAT traversal probe depth,
   not transit-hop forwarding.
3. **Explicit multi-hop path selection** — No Dijkstra/BFS path computation
   over a global topology graph.

### Trigger for revisiting this decision

If real-device testing proves per-pair fallback insufficient (e.g., a
relay-required pair cannot establish connectivity because no single relay
has sessions to both endpoints), then a global routing table becomes
necessary. The diagnostic signal is: `tryRelayFallback` logs "no relay
candidates" for a pair that should be reachable, and the SIGUSR1 state
dump shows no `CapRelay=true` peer with an active session to both
endpoints.

## 4. Operational Prerequisites

No code changes are required before real-device deployment. The only
prerequisite is **operational**:

- `proxy.relay.enabled: true` on all four nodes (config default is `false`,
  config.go:379). The relay pairs are cross-cutting — ordinary nodes relay
  for shared-node pairs and vice versa — so partial enablement silently
  breaks relay-required pairs.
- Pre-deployment gate: send `SIGUSR1` to each node and confirm `CapRelay=true`
  in the state dump before proceeding to TUN-ping tests.

## 5. Acceptance Criteria

This design decision is considered correctly recorded when:

1. ✅ This document exists at `docs/DESIGN_DECISION_NO_GLOBAL_ROUTING.md`
2. ✅ AGENTS.md "Recent Decisions" section references this decision
3. ✅ The decision is traceable to motion-fb0fdd61c936
4. ✅ Code references (file:line) are accurate and verifiable
5. ✅ Out-of-scope items are explicitly listed, not implied

## 6. References

- **Motion:** motion-fb0fdd61c936 (adopted, unanimous)
- **AGENTS.md:** Stop condition §1-3, goal item #4
- **Code:**
  - `internal/p2p/nat.go:72` — `NatSession` struct
  - `internal/p2p/nat.go:442` — `runStateMachine` (STUN→DirectProbe→RelayFallback)
  - `internal/p2p/nat.go:603` — `transitionToRelay`
  - `internal/p2p/events.go:542` — `GetRelayCandidates`
  - `internal/p2p/delegate.go:19` — `NodeMeta` struct
  - `internal/mesh/relay_dialer.go:316` — `tryRelayFallback`
  - `internal/mesh/relay_dialer.go:258` — `DialViaRelay` (MeshNode convenience)
  - `internal/mesh/node.go:1225` — `DialVirtualPort` relay fallback entry point
  - `internal/config/config.go:379` — `RelayNodeConfig.Enabled` (default false)
  - `cmd/meshdesk/main.go:404` — relay mode initialization
- **Discussion participants:** architect, researcher, developer, tester,
  reviewer, leader — all converged on this decision.
