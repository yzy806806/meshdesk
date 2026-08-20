# MeshDesk Dependency Tree

> Last updated: 2026-08-20 (v1.8.3). Covers external Go modules,
> internal package structure, and runtime (OS-level) dependencies.

---

## 1. External Dependencies (go.mod)

MeshDesk keeps its external surface small and security-focused. Every
direct dependency exists for a specific protocol or crypto primitive —
there is no web framework, no ORM, no generic utility kitchen sink.

### 1.1 Direct dependencies

| Module | Version | Purpose | Used in |
|--------|---------|---------|---------|
| `github.com/xtls/reality` | 0.0.0-20260322 | Reality TLS server/client — anti-DPI HTTPS disguise | `internal/handshake` |
| `github.com/refraction-networking/utls` | v1.8.2 | ClientHello fingerprint mimicry (Chrome etc.) | `internal/handshake` |
| `github.com/pion/stun/v3` | v3.1.6 | STUN binding requests — NAT discovery | `internal/holepunch` |
| `github.com/miekg/dns` | v1.1.72 | Mesh DNS server (custom TLD resolution) | `internal/dns` |
| `github.com/gorilla/websocket` | v1.5.3 | Dashboard WebSocket channel | `internal/web` |
| `github.com/creack/pty` | v1.1.24 | Pseudo-terminal for WebSSH sessions | `internal/webssh` |
| `github.com/hashicorp/go-sockaddr` | v1.0.7 | Interface/socket address helpers | `internal/config`, `internal/mesh` |
| `github.com/vmihailenco/msgpack/v5` | v5.4.1 | Relay request/response serialization (0x524C) | `internal/mesh` |
| `gopkg.in/yaml.v3` | v3.0.1 | Config file parsing | `internal/config` |
| `golang.org/x/crypto` | v0.54.0 | X25519, Ed25519, AES-GCM primitives | `internal/crypto`, `internal/session` |

### 1.2 Notable indirect dependencies

| Module | Why it exists |
|--------|---------------|
| `pion/dtls/v3`, `pion/transport/v4`, `wlynxg/anet` | Pion STUN's transport stack |
| `pion/logging` | Pion STUN logging |
| `andybalholm/brotli`, `klauspost/compress` | HTTP compression in `x/net`/websocket paths |
| `cloudflare/circl` | x/crypto's post-quantum/elliptic helpers |
| `pires/go-proxyproto` | PROXY protocol support in smux listeners |
| `golang.org/x/net`, `golang.org/x/mod` | x/crypto & utls shared deps |

> The dependency graph is intentionally stable: **no new module has been
> added since v1.5.x** — hole punching, NAT discovery and relay caching
> are all built on the existing `pion/stun` + stdlib `net`.

---

## 2. Internal Package Dependency Tree

### 2.1 Layered overview

```
cmd/ (entrypoints)
 └── meshdesk          flags, subcommands, config load → app.Build/Start/Run
     meshdesk-socks5   standalone SOCKS5 entry
     meshfsput         file transfer helper

internal/
 ├── app               APPLICATION LAYER — assembly, wiring, lifecycle
 │    ├── app.go           three-phase Build → wire → Start/Stop (explicit reverse order)
 │    ├── mesh_node.go     MeshNode adapter (meta exchange, routes)
 │    ├── p2p.go           static peer connection (auto-reconnect with backoff)
 │    ├── tun.go           TUN integration, routes
 │    ├── proxy.go         SOCKS5 entry/exit wiring
 │    ├── services.go      DNS / transfer / WebSSH services
 │    ├── monitor.go       reporter + aggregator + alerts
 │    ├── join.go          /api/join onboarding
 │    ├── web.go           dashboard + reloaders
 │    ├── reload.go        cross-subsystem hot reload
 │    ├── signals.go       signal loop (SIGINT/TERM/HUP/USR1)
 │    ├── holepunch.go     hole-punch engine wiring
 │    └── topology_paths.go
 │
 ├── holepunch          HOLE-PUNCH ENGINE (standalone, memberlist-independent)
 │    ├── engine.go         per-peer state machine (Trigger/backoff/Forget)
 │    ├── punch_udp.go      UDP punch + coordination protocol (0x504A) + NAT4E window scan
 │    ├── punch_tcp.go      TCP punch (conntrack source-port, sustained SYN)
 │    ├── stun_discovery.go STUN probes → mapped endpoint + NAT class + EasySym/Inc
 │    └── (tests)
 │
 │ ├── mesh               NETWORK LAYER — the core node
 │    ├── node.go          MeshNode: sessions, virtual ports, relay fallback,
 │    │                     holeEndpoints map (punched endpoint survives meta overwrites)
 │    ├── mux_transport.go single-port multiplexer (Reality/mesh/SOCKS5);
 │    │                     dual-family UDP binds (ordinary: random distinct ports;
 │    │                     shared: single [::] dual-stack)
 │    ├── mux_udp.go       UDP ARQ streams (mesh |in/|out, TUN data plane)
 │    ├── udp_conn.go      ARQ sliding-window conn — adaptive RTO (RFC 6298
 │    │                     SRTT/RTTVAR), per-frame retransmit
 │    ├── relay_dialer.go  relay tunnel client + working-path cache
 │    ├── tun_forwarder.go TUN device forwarding (0x54 independent stream
 │    │                     disabled — TUN rides the 0x4D session stream)
 │    ├── meta_exchange.go session meta (endpoints/VIP propagation)
 │    └── ...
 │
 ├── session            SECURITY LAYER — key exchange
 │    └── key_exchange.go  X25519 ECDH + Ed25519 signatures (initiator/responder)
 │
 ├── crypto             AES-256-GCM SecureConn wrapping
 ├── handshake          Reality TLS server/client
 ├── identity           Ed25519 identity (pubkey = peer ID)
 │
 ├── config             YAML config model + validation
 ├── ipam               deterministic VirtualIP allocation
 ├── p2p                (deleted in v1.7.0 — memberlist retired, meta exchange replaces gossip)
 ├── smux               multiplexer (fork)
 ├── tun                raw /dev/net/tun (syscall-only, ~150 lines)
 ├── dns / proxy / web / webssh / monitor / join / service / transfer
 │                      feature subsystems (thin, app-wired)
 └── topology           path/topology views for the dashboard
```

### 2.2 Key dependency edges (who imports whom)

| Edge | Why |
|------|-----|
| `app → mesh` | application wires the node, registers virtual ports |
| `app → holepunch` | engine wiring (dialer adapter over `mesh.MeshNode`) |
| `holepunch → (Dialer interface)` | **no mesh import** — the engine is testable in isolation; mesh adapts via `appHolepunchDialer` |
| `mesh → session` | key exchange over inbound/outbound streams |
| `mesh → crypto` | SecureConn wrap after key exchange |
| `mesh → smux` | session multiplexing |
| `mesh → identity` | peer identification |
| `mesh → tun` | TUN device read/write |
| `mesh → app` | meta exchange for relay candidates (via callback — no import cycle) |
| `session → crypto, identity` | signing + symmetric wrapping |
| `handshake → utls, reality` | Reality TLS |
| `config → yaml.v3` | config parsing |

### 2.3 Anti-import-cycle discipline

- **`holepunch` never imports `mesh`** — it depends only on a `Dialer`
  interface (`DialVirtualPort(ctx, peerKey, port)`); the app layer
  adapts `*mesh.MeshNode`.
- **`mesh` never imports `p2p`** — relay metadata is injected as a
  callback (`relayMetaProvider func() []RelayPeerInfo`) to avoid the
  meta ↔ network cycle.
- **`mesh` never imports `app`** — app is the composition root.

---

## 3. Runtime (OS-Level) Dependencies

| Dependency | Used for | Notes |
|------------|----------|-------|
| `/dev/net/tun` | TUN device creation | raw syscalls (`open`, `ioctl TUNSETIFF`) — no external tools |
| `CAP_NET_ADMIN` | TUN creation, route/addr management | required for mesh0 setup |
| `SO_REUSEADDR` | TCP hole punching (bind + dial same port) | Linux-only behavior relied on by `punch_tcp.go` |
| **Distinct UDP ports** | Ordinary nodes: `udp4:random` + `udp6:random` (`UDPPort=-1`) — never share a port with TCP or the other family | dodges a Go runtime bug: shared-port UDP sockets silently fail public sends; shared nodes keep one `[::]` dual-stack socket on the mesh port |
| System clock | key-exchange timestamp anti-replay window | skew > window fails auth |
| `ip` binary | optional: route/addr display helpers | meshdesk prefers raw netlink where possible |
| systemd (optional) | `TimeoutStopSec=15` + `ExecStopPost` cleanup | see `docs/SYSTEMD_DEPLOY_GUIDE_v1.1.md` |

---

## 4. Versioned dependency facts

- Go toolchain: **1.25** (`go 1.25.0` in go.mod)
- `pion/stun/v3` added in v1.6.0 (STUN discovery) — the only new
  direct dep since v1.5.12; everything else is pre-existing.
- CGO disabled for release builds (`CGO_ENABLED=0`); `-trimpath` +
  `-ldflags "-s -w"` — no runtime C library dependencies.
