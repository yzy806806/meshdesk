# v1.6.0 Design — main.go Split + Independent Hole-Punching Engine

**Status:** Draft for discussion
**Target:** v1.6.0

## 1. Motivation

`cmd/meshdesk/main.go` is ~2900 lines with a ~1700-line `main()` — all
cross-layer glue (dozens of `SetXxxProvider`/`Broadcaster`/`Handler`
callbacks, gossip/mesh/TUN/web assembly) is stacked in one function.
Every new feature (hole-punching, QUIC transport, multi-hop routing)
requires threading through this monolith. The NAT hole-punching logic
is embedded in `internal/p2p` and depends on memberlist/gossip for
triggering — with degraded memberlist it never runs ("约等于没有").

v1.6.0 does two things:
1. **Split main.go into small functional modules** (architecture-clean,
   compiles green, behavior identical).
2. **A standalone hole-punching engine** (memberlist-independent,
   EasyTier-style multi-strategy), built on the new architecture.

## 2. Phase 1 — Split main.go

### 2.1 Target structure

```
internal/app/                    // NEW package — assembly + lifecycle
├── app.go                       // App struct, Build(cfg) (*App, error), Start/Stop
├── mesh_node.go                 // Mesh node assembly: TUN callbacks, virtual-port services
├── p2p.go                       // Gossip layer + seeds + NAT traversal wiring
├── tun.go                       // TUN integration, routing, subnet proxy
├── services.go                  // DNS, WebSSH, transfer, command executor, remote services
├── proxy.go                     // SOCKS5 entry/exit + proxy entry node
├── web.go                       // Dashboard server + monitor reporter/store
└── signals.go                   // Signal handling, graceful shutdown

cmd/meshdesk/main.go             // shrinks to: parse flags → config → app.Build → app.Start → wait
```

### 2.2 Principles

- **Pure refactor**: move code, do not change behavior. All existing
  tests must stay green; the binary's flags/config/behavior are
  identical.
- **Assembly via Build(cfg)**: the monolith's initialization sequence
  becomes `app.Build(cfg)` — testable (construct an App without
  running it), reusable (embedding, testing).
- **Callback injection converges**: `SetXxxProvider`/`Broadcaster`
  registrations live with the component that owns them (each file
  wires its own mesh callbacks), instead of all in main().
- **Explicit dependency order**: `mesh_node.go` first (node.Start),
  then virtual-port services, then p2p/tun (they attach to the node),
  then web/monitor (read-only consumers).
- **Shared state via App fields**: `node`, `gossipLayer`, `natTraversal`,
  `tunForwarder`, `reporter`, `webServer`, ... are App struct fields —
  no globals, no closure soup across files.

### 2.3 Acceptance (Phase 1)

- `go build ./...` + full test suite green (25 packages, no behavior change)
- `main.go` < 500 lines (flags, subcommands, app.Build/Start glue)
- Binary behavior identical (four-node mesh still works after deploy)
- `-race` clean

## 3. Phase 2 — Standalone Hole-Punching Engine

### 3.1 Why the current one fails

| Break | Cause |
|-------|-------|
| Trigger | `InitiateConnection` only called by gossip NotifyJoin — memberlist degraded → never runs |
| Prerequisite | peer endpoint + NAT type must come from gossip NodeMeta |
| Strategy | single v4 UDP one-way probes (fixed port) |
| Usage | success judged by wgDelegate.IsConnected; the punched hole is not wired into the mesh transport |

### 3.2 New engine

```
internal/holepunch/              // NEW package — memberlist-independent
├── engine.go                    // HolePunchEngine: per-peer state machine, triggers
├── coordinator.go               // shared-node coordination: RPC exchange of mapped addrs
├── punch_udp.go                 // two-way synchronized UDP hole punching
├── punch_tcp.go                 // TCP hole punching (socket reuse, SO_REUSEADDR, no RST)
├── sym_predict.go               // symmetric-NAT port prediction (birthday scan)
└── trigger.go                   // triggers: meta-exchange learned peer, lazy (on TUN traffic)
```

### 3.3 Key designs (EasyTier-informed)

- **Trigger independence**: the engine subscribes to the **meta
  exchange** (0x4D45 — already memberlist-independent) for new
  peers + endpoints; also a **lazy trigger** (first TUN packet to a
  relayed peer fires a punch attempt — `--lazy-p2p` style).
- **Coordinator**: shared nodes (public reachable, Reality-enabled)
  act as punch coordinators — peers exchange STUN-mapped addresses via
  the existing smux/Reality channel (no new protocol transport needed;
  reuse the meta exchange or a small RPC virtual port).
- **Multi-strategy**: UDP two-way synchronized first; TCP punch
  (bind same port, non-blocking connect, keep socket alive to preserve
  NAT mapping); symmetric prediction when both sides are NAT4; IPv6
  direct attempt (no NAT).
- **Result wiring**: a successful hole yields the punched endpoint →
  feed it to the mesh UDP multipath (`getUDPStream`) and/or establish
  a session over the hole (Reality over the punched UDP path).
- **Backoff/health**: reuse the exponential backoff pattern from the
  relay fix; probe results cached (30s) like PeerRTT.

### 3.4 Acceptance (Phase 2)

- txcloud ↔ Oracle ARM: direct P2P (no relay) — target <300ms stable
  (EasyTier achieved 256ms; meshdesk must be comparable)
- Works with degraded memberlist (meta-triggered)
- Multi-strategy fallback chain (UDP → TCP → predict → relay)
- All tests green + `-race` clean

## 4. Sequencing & Release

1. **Phase 1** (split) — pure refactor, v1.6.0-alpha: compile + tests green, deploy to 4 nodes, verify no regression.
2. **Phase 2** (holepunch engine) — v1.6.0-beta: engine + coordinator + strategies; real-machine verification txcloud↔Oracle ARM.
3. **v1.6.0** — both phases verified; release.

## 5. Risks

- Phase 1 regression risk mitigated by pure-move discipline + full test
  suite + real-machine verification.
- Phase 2 hole-punching success depends on network (NAT types); fallback
  chain guarantees relay still works (current behavior preserved).
- main.go subcommands (`join`, `join-token`, `version`) stay in main.go
  (CLI surface unchanged).

## 6. Open questions

- Hole-punch coordinator: reuse meta exchange vs dedicated RPC virtual
  port?
- UDP multipath integration: punched hole feeds `getUDPStream` directly,
  or a new dedicated UDP session layer?
- Should the engine replace `internal/p2p`'s nat.go entirely, or coexist
  during transition?

## 8. Implementation Status (2026-08-13)

- **Phase 1 (split)**: DONE — internal/app modules, three-phase Build,
  explicit reverse-order Stop, smoke test, 27/27 packages green.
- **Phase 2 (holepunch)**: DONE (engine) — internal/holepunch with
  coordination (0x504A), multi-strategy punches, mux-socket reuse,
  0x504A-prefixed probe echo. Real-machine verified: STUN, v4+v6
  endpoint exchange, coordination over degraded memberlist.
  Remaining: per-network probe tuning (symmetric NAT / v6 links).
