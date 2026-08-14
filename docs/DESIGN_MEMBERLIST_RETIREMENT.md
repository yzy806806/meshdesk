# Memberlist Retirement — Design Memo

**Status:** Phase 1 in progress (v1.6.x)
**Decision context:** reality-discipline refactor (zone boundary = Reality boundary)

## Why retire memberlist

Two independent pressures converge on the same conclusion:

1. **Anti-DPI discipline.** The architecture invariant is: *every packet
   crossing a zone boundary must ride Reality TLS.* Memberlist gossip
   (push/pull, probes) is raw, identifiable protocol traffic on the mesh
   port. Cross-zone gossip violates the invariant — the data plane is
   disguised, but the discovery plane is not.

2. **It does not reach the nodes that need it.** Memberlist requires
   bidirectional reachability; relay-attached / NAT nodes run degraded
   memberlist and never receive full membership. Every v1.6.x feature
   was built to work around this: META-based collector discovery,
   memberlist-independent hole punching, meta-learned endpoints, config
   peer scans. META has been eating memberlist's responsibilities one by
   one.

Running two discovery planes doubles the surface area and the bugs. The
mesh is small (≤10 nodes); META flooding is entirely sufficient.

## Capability mapping

| Memberlist provides            | Replacement                                              | Status |
| ------------------------------ | -------------------------------------------------------- | ------ |
| Membership (who exists)        | META peer-list flood (session-based)                     | ✅ live |
| Endpoints                      | META `Endpoints` + hole endpoints                        | ✅ live |
| Zone tags                      | META `Zone`                                              | ✅ live |
| Capabilities (relay/collector) | META `Collector` (live) + relay fields (phase 1)         | ✅ live |
| VirtualIP propagation          | META `VIP`                                               | ✅ live |
| Failure detection (SWIM)       | Session death + reconnect watcher                        | ✅ live |
| RTT / latency matrix           | Session echo ping (0x5049) + `rttCache`                  | ✅ live |
| NAT type advertisement         | META `NatType` (phase 1)                                 | ✅ phase 1 |
| Relay load (circuits)          | META `MaxCircuits`/`LoadCircuits` (phase 1)              | ✅ phase 1 |

## Phases

### Phase 1 (this branch) — demote, do not delete

- Relay/NAT fields (`Role`, `NatType`, `CapRelay`, `MaxCircuits`,
  `LoadCircuits`) added to the META `PeerMeta` payload; flooded through
  relay hops like `Collector`.
- `relayMetaProvider` merges three sources: META-learned first, gossip
  overlay (fresher load/RTT where available), static config peers last.
  Relay selection now works for relay-attached nodes with degraded
  memberlist.
- Local node's relay knowledge advertised in META via
  `SetLocalMetaExtras` (sourced from the gossip layer's local meta while
  gossip exists).

### Phase 2 — gate cross-zone gossip

- Memberlist events/probes involving a peer in a DIFFERENT zone are
  suppressed: cross-zone membership knowledge flows exclusively through
  META-over-Reality sessions.
- Same-zone gossip may remain (it does not cross the anti-DPI boundary).

### Phase 3 — delete

- Remove `internal/p2p` memberlist wiring, `wg_delegate`, gossip
  assembly glue in `internal/app`. Prerequisites:
  - Periodic META re-broadcast replaces the "learn on join" model (a
    node joining mid-flight must receive full membership without waiting
    for a session event).
  - Bootstrapping is fully seed-driven: config seed → Reality session →
    META gives everything else. Document the bootstrap order.
- Keep STUN-free mapped-address learning via the shared node's observed
  source (0x50 0x4C observation probes) — no external STUN dependency.

## Invariant enforced after retirement

> Discovery, coordination, and data — every plane rides the session
> transport. Cross-zone means Reality TLS. There is no independent
> discovery traffic.
