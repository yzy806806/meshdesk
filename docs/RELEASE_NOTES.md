# MeshDesk v1.0.0-beta.1 — Initial Public Beta

**Release date: 2026-07-26**
**Tag: `v1.0.0`**
**Status: Beta — real-machine acceptance testing pending**

MeshDesk v1.0.0-beta.1 is the first public release. It combines mesh VPN, server
monitoring, web terminal, file transfer, service management, multi-path anonymous
proxy, dashboard security (TOTP 2FA), dashboard config management, x-ui panel
integration, and 3D topology visualization into a single binary.

**Important:** This release is functionally complete and all unit tests pass, but
it has NOT been validated on physical multi-node hardware. See [Validation
Status](#validation-status) below for what has and hasn't been tested.

---

## Feature Maturity

Features carry an explicit maturity label so you know what to expect:

| Feature | Maturity | Notes |
|---|---|---|
| Mesh VPN & P2P Dynamic Networking | **Stable** | WireGuard mesh, gossip discovery, NAT traversal, dynamic join — all unit-tested |
| Transport Layer | **Beta** | Pluggable transports: UDP, Reality (xray-core embedded), WebSocket; automatic fallback |
| PeerManager | **Beta** | Auto-reconnect, multi-transport fallback, EWMA latency probing, optimal path selection |
| Monitoring | **Stable** | Real-time metrics, push collectors, SSE dashboard updates |
| Web Terminal | **Stable** | xterm.js + WebSocket, multi-tab, SIGWINCH support |
| File Transfer | **Stable** | Upload/download via web UI, capability-scoped paths |
| Service Management | **Stable** | Start/stop/restart systemd services, per-peer authorization |
| Dashboard Security (TOTP 2FA) | **Stable** | TOTP enrollment, step-up auth, encrypted key storage, webhook alerts |
| Multi-path Anonymous Proxy | **Beta** | Circuit routing functional; chunker/reassembly needs real-hardware validation |
| Endpoint Learning & Shared Relay | **Beta** | Endpoint learning + NAT-type inference + relay circuits with failover; gossip integration tested |
| Dashboard Config Management | **Beta** | Tiered config API, PATCH merge-patch, hot reload, diff viewer — integration tested |
| x-ui Panel Integration | **Beta** | Inbound/outbound configuration, user management, Reality config generation via Dashboard |
| 3D Topology Visualization | **Beta** | Node graph + latency edges complete; circuit particles use mock data |

**Maturity definitions:**
- **Stable** — Feature is implemented, unit-tested, and verified by the team.
  Suitable for production use with standard safeguards.
- **Beta** — Feature is functionally complete and passes all unit tests, but has
  NOT been validated on physical multi-node hardware. Use with caution; report
  issues on GitHub.

Maturity labels graduate from Beta to Stable when acceptance tests pass on real
hardware — not when a commit lands.

---

## Major Features

### Mesh VPN & P2P Dynamic Networking

- **WireGuard mesh** via wireguard-go + gVisor netstack — every node gets a mesh
  IP derived from its public key
- **Gossip discovery** (hashicorp/memberlist) — automatic peer discovery with
  epidemic-style propagation; no manual peer config needed
- **NAT traversal** — STUN-based public endpoint discovery + UDP hole-punching
  with automatic relay fallback through mesh peers
- **Dynamic join protocol** — `meshdesk join <bootstrap-addr>` subcommand;
  bootstrap authenticates via authorized_keys, then gossips the new member to
  the cluster
- **Transport obfuscation** — AmneziaWG-style padded mode (H1-H4 headers, S1-S4
  padding, junk train, anti-probe PSK), WebSocket+TLS mode with uTLS
  fingerprint mimicry (Chrome, Firefox, Safari, Edge, iOS, Android), or
  Reality TLS mode with xray-core handshake hijack (embedded, no subprocess)
- **Endpoint learning** — when a NAT node connects to a seed, the seed reflects
  its public endpoint and gossips it cluster-wide, enabling direct connections
  to NAT nodes without manual endpoint configuration (EasyTier-style)
- **Shared node relay** — when direct connection fails (e.g. symmetric NAT),
  traffic routes through mesh peers via relay circuits with automatic failover:
  top-2 relay candidates, 30s health checks, 3-missed-pong failover
- **Fine-grained peer capabilities** — per-peer capability scoping for monitor,
  SSH, file transfer, and service management

**Mesh routing model:** The `RoutingTable` is a local, gossip-populated
mesh-IP-to-peer mapping — a simple in-memory hash-map lookup, not an OSPF
link-state protocol. It is populated by static peer config at startup and by
gossip events (memberlist join/leave) at runtime. `ResolveRoute(meshIP)` does
a direct lookup to find the owning peer; there is no next-hop computation, no
SPF calculation, and no latency-aware route selection. The original design
docs referenced EasyTier's OSPF-based `PeerRoute` as inspiration for a future
"Phase 4" feature, but the full link-state algorithm was explicitly deferred
in favor of a simpler gossip-populated table. Multi-transport path selection
is handled separately by PeerManager at the connection level.

### Transport Layer

The transport layer abstracts how MeshDesk nodes communicate, with PeerManager
handling automatic fallback between transports:

- **UDP Transport** — raw WireGuard UDP for LAN peers and direct connections
- **Reality Transport** — xray-core Reality TLS handshake hijack, embedded
  directly in MeshDesk (no subprocess). uTLS ClientHello fingerprint mimicry
  makes connections indistinguishable from a real browser visiting a major
  website (e.g. apple.com). The strongest GFW-resistant transport available.
- **WebSocket Transport** — WebSocket + TLS with uTLS fingerprint mimicry,
  retained as a fallback
- **Automatic Fallback** — transports tried in priority order (UDP → Reality →
  WS → Relay). If the primary transport is unresponsive after 5s, the next is
  raced in parallel (Happy Eyeballs hedging)

### PeerManager

PeerManager is the connection lifecycle manager for every mesh peer:

- **Auto-reconnect with exponential backoff** (30s → 60s → 120s → 240s → 300s cap)
- **Multi-transport fallback** with per-transport quarantine and exponential
  cooldown. A blackout escape hatch prevents permanent disconnect when all
  transports are unavailable.
- **EWMA-based latency probing** — split-alpha EWMA (α_rise=0.7, α_fall=0.3)
  tracks per-transport latency with fast rise / slow fall to detect degradation
  without path flapping
- **Optimal path selection with hysteresis** — composite additive score with
  10% hysteresis discount on the active transport to prevent flapping

### Monitoring

- Real-time CPU / memory / disk / network / load average metrics
- Metric push to collector nodes with configurable interval
- Ring buffer storage per node (survives collector outages)
- Live dashboard updates via Server-Sent Events (SSE)
- Process list per server

### Web Terminal

- Browser-based terminal (xterm.js + WebSocket)
- Agent runs as root — no SSH keys or passwords needed
- Multi-tab, multi-server terminal sessions
- SIGWINCH resize support, clipboard integration, status bar

### File Transfer

- Upload / download files via web UI
- Mesh-internal transfers (files route through VPN, not exposed to internet)
- Capability-based access control with per-path restrictions

### Service Management

- Start / stop / restart systemd services
- View service logs
- Per-peer authorization via `service_manage` capability

### Multi-path Anonymous Proxy

- **Shadowsocks entry** — SS AEAD (chacha20-ietf-poly1305) over WebSocket
- **Cloudflare Tunnel camouflage** — entry listener exposed via `cloudflared`,
  appears as HTTPS traffic
- **ECDH circuit setup** — per-connection end-to-end encryption between entry
  and exit
- **Two disjoint relay paths** — traffic split across node-disjoint paths to
  disperse traffic
- **Blind relay forwarding** — onion-style headers; relays never decrypt payload
- **Anti-timing-analysis jitter** — 5-50ms random forwarding delay per chunk
- **Pluggable chunker** — fixed 16KB or bounded random 4KB-64KB with TLS 1.3
  record padding for protocol mimicry
- **Exit reassembly** — sliding window with out-of-order, dedup, NACK
  retransmission, orphan cleanup
- **Dynamic path selection** — RTT-based Dijkstra k-shortest path selection
- **Audit logging** — circuit→destination mappings (no payload data)

### Dashboard Security

- **TOTP 2FA** (RFC 6238) — QR code enrollment, 6-digit codes, ±1 window
  tolerance
- **Encrypted secret storage** — AES-256-GCM with node-local master key
- **Step-up authentication** — terminal, service management, file upload,
  settings require recent 2FA verification
- **Security alerting** — real-time alerts for auth denials, node joins/leaves,
  and suspicious proxy activity
- **Webhook dispatch** — async alert delivery to external endpoints with 3-retry
  exponential backoff
- **TOTP key rotation** — zero-downtime rotation with old-key grace period
- **Recovery codes** — 10 single-use codes
- **Lockout protection** — 5 failed attempts → 30-second lockout

### Dashboard Config Management

Full configuration management via the `/config` page, eliminating the need to
SSH in and edit YAML by hand:

- **All 11 config sections** rendered on a single dashboard page (node, mesh,
  peers, p2p, monitoring, webssh, auth, transfer, proxy, xray, reality)
- **Tiered field display** — four access tiers control visibility and writability:
  T0 (read-only), T1 (masked secrets), T2 (step-up 2FA required), T3 (normal)
- **PATCH /api/config** — partial save via JSON merge-patch (RFC 7396). Only
  changed fields are sent; server merges into current config and writes atomically
- **Hot reload** — `POST /api/config/reload` applies hot-reloadable changes
  without restarting the daemon. Rate-limited to once per 5 seconds.
- **Restart button** — `POST /api/config/restart` triggers a daemon restart for
  restart-required fields. Step-up auth required. Rate-limited to once per 30s.
- **Diff viewer** — `GET /api/config/diff` compares running in-memory config
  against on-disk saved config, showing pending changes

### x-ui Panel Integration

A MeshDesk-native equivalent of the x-ui panel, accessible at `/xui`:

- **Inbound/outbound configuration** — manage xray-core inbounds (VLESS, VMess,
  Trojan, Shadowsocks) and outbounds via the Dashboard
- **Traffic statistics** — per-inbound traffic counters and uptime
- **Client management** — add/remove clients with per-client traffic limits
- **Share links** — generate shareable `vless://` / `vmess://` URIs
- **Reality config generation** — generate Reality server/client keys and
  short IDs from the Dashboard UI

### 3D Topology Visualization

- Three.js 3D scene with force-directed node layout
- Animated particles flowing along proxy circuit paths
- Real-time SSE topology updates
- Color-coded nodes by role (entry, relay, exit, dashboard)
- OrbitControls for pan/zoom/rotate
- Performance-adaptive particle reduction
- Mock-data fallback for standalone testing

---

## Bugs Found and Fixed During Pre-Release Validation

Three non-trivial bugs were discovered during the pre-release audit and have been
fixed at HEAD. They are documented here because they illustrate gaps that
automated testing alone cannot close — all three were missed by `go test ./...`:

### 1. Working Tree Corruption — main.go Truncated to Zero Bytes

`cmd/meshdesk/main.go` was truncated to zero bytes in the working tree. `go test
./...` passed because it operates on compiled packages, not working tree file
integrity. A `git checkout` restored the 652-line entrypoint.

**Root cause:** Environment-level corruption, not a code defect. The Go compiler
reads from the working tree at build time, so a truncated file produces a
buildable-but-broken binary with no test failure.

**Lesson:** Always run `go build ./...` before declaring a release buildable.
Tests alone are not sufficient.

### 2. Duplicate StreamEnd After Completion

When a `ChunkStreamEnd` arrived for an already-completed stream,
`AddStreaming` created a brand-new stream state because the old one had been
cleaned up. This caused the reassembler to re-process a stream it had already
delivered.

**Fix:** A `completedStreams` map tracks recently-completed stream IDs so that
duplicate completions are silently ignored rather than re-processed.

### 3. StreamEnd Payload Injection at Delivered Sequence

The deduplication check in `processChunk` used `st.chunks[sequence]` existence to
detect duplicates, but delivered chunks are removed from that map. A StreamEnd
arriving at an already-delivered sequence bypassed the check and stored
replacement payload.

**Fix:** A `sequence < st.nextExpected` guard rejects payloads at
already-delivered positions.

---

## Validation Status

### What passed

| Test category | Method | Result |
|---|---|---|
| Unit tests (all 14+ packages) | `go test ./...` | **PASS** |
| Go vet (static analysis) | `go vet ./...` | **Clean** |
| Build | `go build ./...` | **Clean** |
| gofmt compliance | `gofmt -s -w .` | **Applied** |
| Chunker/Reassembler boundary tests | 18 table-driven cases | **PASS** |
| Circuit manager lifecycle | Unit + integration | **PASS** |
| Exit node reassembly stress | Concurrent stream test | **PASS** |
| NAT traversal state machine | Table-driven transitions | **PASS** |
| Gossip discovery integration | Multi-node simulation | **PASS** |
| Dynamic join protocol | Unit + mock cluster | **PASS** |
| TOTP 2FA integration | Enrollment + verify + lockout | **PASS** |
| Security alerting + webhook | End-to-end dispatch | **PASS** |
| Topology backend + frontend | API + SSE + Three.js render | **PASS** |
| Endpoint learning chain | Unit + gossip integration test | **PASS** |
| Config hot-reload | Integration test (PATCH, reload, diff) | **PASS** |
| 3-node cluster integration harness | Automated test | **PASS** |

### What remains

| Validation | Status | Notes |
|---|---|---|
| Real-hardware multi-node deployment | **Pending** | Has not been run on physical machines with heterogeneous network conditions. This is the single most important validation step. |
| WireGuard handshake over real NAT/firewall | **Pending** | Unit tests simulate interfaces; actual NAT traversal (UDP hole-punching, relay fallback) must be verified in the wild. |
| Multi-path proxy with 3+ physical nodes | **Pending** | Circuit setup, chunk dispersion, reassembly, and path failover have only been tested in simulated environments. |
| WebSocket+TLS obfuscation against real DPI | **Pending** | uTLS fingerprint mimicry is implemented but not tested against live GFW. |
| High-load stress testing | **Pending** | No sustained throughput benchmarks or memory-leak profiling under prolonged load. |
| Cross-platform builds | **Pending** | Only tested on Linux/amd64. |

**Bottom line:** This release passes every automated test in the suite, but
automated tests cannot replace real-hardware validation for a distributed
networking product. Treat this as a beta. We encourage early adopters to test on
their own infrastructure and report issues on GitHub.

---

## Known Limitations

### IPv6 support

MeshDesk uses IPv4 addressing for the mesh network. IPv6 is not yet supported.
Tunnels may still work over IPv6 underlay networks, but mesh-internal addressing
is IPv4-only.

### Windows support

No Windows binary is provided. The codebase uses Linux-specific APIs (TUN
interface, systemd integration). Windows is planned but not scheduled.

### No bandwidth accounting or rate limiting

Relay nodes forward traffic without bandwidth caps. A busy relay could saturate
its network link. Administrators should monitor relay node bandwidth and
configure firewall rules if needed.

### YAML config only

The config format is YAML only. No environment-variable overrides or CLI config
flags beyond `--config`. The config file must be readable by the meshdesk
process.

### High-throughput proxy not yet tuned

The proxy chunker/reassembler pipeline is functional but has not been
benchmarked or tuned for high-throughput (>100 Mbps) streams. Expect
performance improvements in future releases.

---

## CLI

```
meshdesk --config /etc/meshdesk/config.yaml --web          # agent + dashboard
meshdesk --config /etc/meshdesk/config.yaml --relay        # agent + relay mode
meshdesk --gen-key                                          # generate WireGuard keypair
meshdesk join <bootstrap-addr> --bootstrap-key <hex>        # join existing mesh
```

---

## Build

```bash
git clone https://github.com/yzy806806/meshdesk.git
cd meshdesk
go build -o meshdesk ./cmd/meshdesk/
```

---

## Documentation

- [README.md](./README.md) — Project overview and getting started
- [README_CN.md](./README_CN.md) — 中文项目概述
- [ARCHITECTURE.md](./docs/ARCHITECTURE.md) — System architecture overview
- [ARCHITECTURE_REFACTOR.md](./docs/ARCHITECTURE_REFACTOR.md) — Transport layer abstraction, Reality, PeerManager refactor
- [PEERMANAGER_DESIGN.md](./docs/PEERMANAGER_DESIGN.md) — PeerManager state machine, quarantine, latency probing, path selection
- [TRANSPORT_CONTRACT.md](./docs/TRANSPORT_CONTRACT.md) — Transport layer interface contract (PeerConn, Transport, TransportRegistry)
- [TRANSPORT_CAPABILITY_MATRIX.md](./docs/TRANSPORT_CAPABILITY_MATRIX.md) — Transport feature comparison matrix
- [OBFUSCATION_RESEARCH.md](./docs/OBFUSCATION_RESEARCH.md) — GFW obfuscation research and Reality integration design
- [ENDPOINT_LEARNING_DESIGN.md](./docs/ENDPOINT_LEARNING_DESIGN.md) — Endpoint learning mechanism (EasyTier-style)
- [ENDPOINT_LEARNING_DESIGN_v2.md](./docs/ENDPOINT_LEARNING_DESIGN_v2.md) — Endpoint learning v2 (gossip integration + NAT-type inference)
- [CONFIG_INVENTORY.md](./docs/CONFIG_INVENTORY.md) — Full inventory of all config fields across 11 sections
- [CONFIG_SECURITY_MODEL.md](./docs/CONFIG_SECURITY_MODEL.md) — Tiered config access model (T0–T3) and security rationale
- [PROXY_DESIGN.md](./docs/PROXY_DESIGN.md) — Multi-path anonymous proxy design
- [CIRCUIT_MANAGER_SPEC.md](./docs/CIRCUIT_MANAGER_SPEC.md) — Circuit lifecycle
- [CHUNKER_CONTRACT.md](./docs/CHUNKER_CONTRACT.md) — Chunker/Reassembler interface
- [TOTP_KEY_ENCRYPTION_SPEC.md](./docs/TOTP_KEY_ENCRYPTION_SPEC.md) — TOTP secret encryption
- [3D_TOPOLOGY_DESIGN.md](./docs/3D_TOPOLOGY_DESIGN.md) — 3D topology visualization
- [DESIGN.md](./docs/DESIGN.md) — Frontend design system (color, typography, spacing tokens)
- [FRONTEND.md](./docs/FRONTEND.md) — Frontend architecture, JS/CSS inventory, and conventions
- [RELEASE_CHECKLIST.md](./docs/RELEASE_CHECKLIST.md) — Release SOP
- [THREAT_MODEL.md](./THREAT_MODEL.md) — Security threat model

---

## License

MIT
