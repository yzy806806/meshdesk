# Release Notes

## v1.5.11 — 2026-08-12

**Multi-hop relay + config-pinned exits + exit path selection.**

### Relay
- **Multi-hop relay** (A→R1→R2→B): recursive forwarding with
  `MeshRelayRequest.Path` loop prevention, bounded by `max_relay_hops`.
  Fix: accept response now sent to the initiator before bridging (was:
  initiator timed out with EOF despite a live tunnel). Multi-hop
  data-plane test passes (bidirectional echo).
- **Slow-path relay preference**: `DialVirtualPort` tries a relay path
  when the direct session RTT exceeds 300ms (typically cross-zone
  Reality) — a same-zone relay hop can beat the direct path. Ping port
  excluded (recursion guard).

### Exit selection (socks5)
- `proxy.socks5.exit_node` / `exit_nodes`: config-pinned fixed exit for
  the entry listener (Dashboard-managed; CLI flags remain fallback).
- Per-connection selection picks the healthy exit with the lowest live
  RTT (`pickBestExits`); failures fall back to the next-best exit
  (was: hard reject).
- **PeerRTT caching** (30s TTL): topology renders (O(n²) pairs) and
  exit selection reuse cached measurements instead of hammering the
  session echo port.

### Verified
- 25/25 test packages green; multi-hop echo test
- 4-node real machines: exit selection (aliyun auto-picked at 174ms vs
  Oracle ARM 212ms), fixed exit via relay (Oracle ARM IP), data plane OK

---

## v1.5.10 — 2026-08-12

**Security hardening + full-connectivity topology.**

### Security (external review driven)
- **Join bundle signing**: ConfigBundle is Ed25519-signed by the server;
  the joiner pins it against the token's ServerFP — MITM tampering over
  plain HTTP is detected and refused (`AllowUnsignedBundle` for legacy
  tokens).
- **Install checksums**: install.sh + join install script verify the
  binary sha256 against the release checksums.txt (fail closed).
- **Login rate limit**: web login POST limited to 5 failures/minute/IP
  (429) — brute-force protection.
- **Join token POST**: `/join` accepts the token in a POST body (no URL
  / proxy-log leakage); GET query still works for `curl | sh`.

### Topology
- **Full-connectivity edges**: every node pair gets an edge (was:
  only measured probe pairs — empty graph with degraded memberlist).
- **Latency-sized layout**: edge spring length maps real path RTT
  (new session echo ping, virtual port 0x5049) — low latency = short
  edge, high latency = long edge.
- **Meta exchange propagates endpoints**: same-zone peers learn
  reachable endpoints even with degraded memberlist → direct UDP/TCP
  dials work (resolvePeerEndpoint fallback).

### Fixes / cleanup
- DNS test helper readiness probe sleeps (deterministic under load)
- Stale WireGuard-era comments + Agora motion annotations removed;
  puppeteer dep dropped
- THREAT_MODEL documents the join trust boundary

---

## v1.5.9 — 2026-08-12

**SOCKS5 entry management + zone fixes.** Zone-aware transport
(v1.5.8) continued; every node is a SOCKS5 exit by default; Dashboard
Proxy page manages the entry listener (listen address + RFC 1929
credentials), save auto-restarts the daemon; relay fallback with
degraded gossip; peers/topology pages show meta-learned peers.

---

## v1.5.8 — 2026-08-11

**Zone-aware transport + 3D topology.** Completion commits: `69f0f74` → `e9a5061`

### Features
- **Zone tags** (`mesh.zone` + `peer.zone`, free-form strings like `cn`/`us`):
  same zone → **UDP P2P** (multipath + hole-punching + 0x4D); cross zone /
  unknown → **Reality TLS only** (conservative). Zone broadcast via gossip
  (NodeMeta.Zone) + meta exchange.
- **3D Topology Dashboard**: node ring color = zone; edge color = transport
  (Reality green / UDP blue / 0x4D amber / relay grey); edge hover shows
  transport / ping / bandwidth. Backend `/api/topology` exposes
  `zone` + `transport` + `latency_ms` + `bandwidth_mbps`.
- Guide: [docs/ZONE_AWARE_TRANSPORT.md](ZONE_AWARE_TRANSPORT.md)

### Fixes
- `peerTransport` map init (nil-map panic on 0x4D dial)
- Earlier Reality-only experiment reverted (UDP/0x4D/NAT code restored —
  kept in git history)

### Verified
- 25/25 test packages green; SameZone unit tests
- Real machines (txcloud ↔ aliyun, both zone: cn): session (Reality),
  data plane (TCP), ping, same-zone UDP multipath (0x54 auth frames)
- ⚠️ All nodes MUST run the same binary version (mixed versions break
  the data plane)

---

## v1.2.1 — 2026-08-06

Single-port HTTP multiplexing and programmatic join endpoint. Completion commit: `a83c9f8`

> **Commit chain:** `de1fe7a` (e2e wiring test) → `db96ae1` (release notes) → `a83c9f8` (join URL port derivation fix)
>
> **Post-release patch:** `fef481a` — race condition fix in `mockExitServer.handleConn` (see v1.2.1-patch below)

### Features

- **Single-Port HTTP Demux** — Dashboard Web UI and join server now share the mesh port (52888) via MuxTransport. HTTP traffic (GET/POST/HEAD, first byte `0x47`/`0x50`/`0x48`) is demuxed onto a dedicated channel, enabling single-port deployment behind restrictive NAT — only one public port required for all mesh traffic plus web access.
- **`/api/join` Onboarding Endpoint** — Programmatic challenge-response onboarding via `POST /api/join` on port 52888. The join server handler is attached to the Dashboard's HTTP mux, so `/api/join` rides the same port as the web UI. Exempt from web session auth; authenticated via token + Ed25519 challenge signature instead.
- **Join URL Port Derivation** — On shared nodes with `reality.enabled: true`, the join install URL (printed on Dashboard join page) now derives its port from the Reality listener (`mesh.port`) instead of hardcoding the web port. This ensures one-click join commands work correctly when Reality TLS is active on the default mesh port. Commit `a83c9f8`.

### Verified

- HTTP demux parseability tests confirm all HTTP methods (GET/POST/HEAD) are correctly routed (`de1fe7a`)
- E2E wiring test verifies `POST /api/join` is served through the demux port (`de1fe7a`)
- Mux demux regression fixed (HTTP channel consumer added to test harness, `db96ae1`)
- Join URL port derivation tested on shared-node topology (`a83c9f8`)
- Motion `motion-454cda95e956` adopted: worktree clean, HEAD=a83c9f8=origin/main, all 22 packages pass

### Post-Release Patch: v1.2.1-patch

Date: 2026-08-07. Commit: `fef481a`

**Store-after-ack race in mockExitServer.handleConn** (`internal/proxy/entry_node_test.go`):

- **Root cause:** `mockExitServer.handleConn` wrote `CircuitAck` and closed the connection BEFORE storing `e2eKeys`/`circuits` in the mock map. The test (`TestEntryNodeCircuitSetup`) reads `e2eKeys` immediately after decoding the ack — triggering a store-after-ack race under `-race`.
- **Reproduction:** `go test -race -run TestEntryNodeCircuitSetup -count=50` → 7/50 failures pre-fix.
- **Fix:** Moved `e2eKeys`/`circuits` store before the `CircuitAck` write, with undo-on-failure cleanup.
- **Verification:** `-race -count=200` PASS; full `internal/proxy -race` 391/391 PASS; full repo test suite 24/24 PASS. Verified by tester at HEAD `8051e88`.

## v1.2.0 — 2026-08-06

Second feature release. Commit: `4dc3f7a`

### Features

- **Systemd Integration + Auto-Reconnect** — systemd unit file with `Type=notify` + `WatchdogSec` support; smux session auto-reconnect with exponential backoff; SIGTERM graceful shutdown (save `peers.cache`, close sessions, delete TUN device)
- **Version Command** — `meshdesk version` outputs version, commit hash, build time, Go version, and platform architecture. Build info injected at compile time via `-ldflags`
- **Log Rotation** — Configurable log rotation: `log_file` / `log_max_size` (default 100MB) / `log_max_backups` (default 3). Defaults to stdout for systemd journald capture
- **Config Validation** — `meshdesk validate <config.yaml>` checks syntax, field types, required fields, and port conflicts with specific error locations and fix suggestions. Runs automatically at startup
- **Mesh DNS** — Embedded lightweight DNS server (Go stdlib). `<hostname>.mesh` resolution via gossip-synced hostname→VirtualIP mapping. Optional `dns_enabled` + `dns_port` config
- **Traffic Statistics** — Per-node metrics: smux bytes/streams, relay forwards, TUN rx/tx packets. Gossip-propagated and displayed on Dashboard node cards
- **Alert UI** — Dashboard alert notification bar + alerts history page. Node offline alerts auto-generated when threshold exceeded
- **Signal Handling** — SIGTERM/SIGINT: graceful shutdown. SIGHUP: config hot-reload. SIGUSR1: dump current state (peers, sessions, routes) to log
- **Config Hot-Reload** — `meshdesk reload` command or SIGHUP triggers reload of ACL rules, monitoring interval, proxy config, and log level. Non-reloadable fields (port, identity) produce clear restart guidance
- **CI Pipeline** — GitHub Actions CI workflow; test identity PEMs use temp directories for non-root CI environments

### Verified

- All unit tests pass across 10 feature packages
- Three-node join end-to-end verified (txcloud → aliyun → N1)
- Version command outputs complete build metadata
- Alert UI renders offline/online events correctly
- Config hot-reload applies ACL and log level without restart

### Known Issues

- **#1 — N1-join /api/monitor metrics gap (cpu=0/mem=0)**: Reporter.pushToCollectors silently fails when collector list is empty on freshly joined nodes. Collector discovery via gossip propagation lags behind first push cycles. Root cause traced to 6 code locations (reporter.go, aggregator.go, gossip.go, events.go). Tracked at [yzy806806/meshdesk#1](https://github.com/yzy806806/meshdesk/issues/1).

## v1.1.0 — 2026-08-05

First feature update. Commit: `e56b22c`

### Features

- **ACL Guide** — Access control list documentation and configuration
- **Systemd Deploy Guide** — Production deployment with systemd
- **Multi-Path Optimization** — Proxy relay path selection improvements

## v1.0.0 — 2026-08-04

First stable release.

### Features

- **Mesh VPN** — P2P decentralized networking via memberlist gossip + Reality TLS + smux
- **TUN Virtual Network** — Transparent Layer 3 IP routing between mesh nodes
  - Deterministic IPAM (VirtualIP = cidr_base + pubkey_hash % host_count)
  - Kernel route auto-sync via gossip NodeMeta
  - Subnet proxy (share local LAN with mesh peers)
  - Source IP anti-spoofing (deny-by-default)
  - Zero-dependency TUN device via raw `/dev/net/tun` syscall
- **Server Monitoring** — CPU, memory, disk, network, services
  - Push-based collection over mesh (no exposed port)
  - Auto-discovery of collector nodes via gossip
  - Metric dedup (SourceID + Sequence)
- **WebSSH** — SSH directly from browser, proxied over mesh
- **SOCKS5 Proxy** — Reality TLS disguised, multi-path relay, exit node controls
  - Standard SOCKS5 client support (no VLESS/xray needed)
  - Entry (0x5350) → relay (0x524C) → exit (0x4558) over single port
- **Dashboard** — Full web UI for node management
  - 3D topology graph, real-time monitoring
  - One-click node join (curl | sh)
  - 4-tier config access control
  - File transfer, service management
- **Reality TLS** — All traffic disguised as HTTPS to a real website (e.g. apple.com)
  - DPI cannot distinguish from legitimate HTTPS
  - No WireGuard, no KCP, no recognizable UDP patterns
- **Single Port** — All protocols multiplexed on port 52888 via MuxTransport
- **One-Click Join** — Generate install command from Dashboard, paste on new machine

### Architecture

- Layer 0: Ed25519 identity (PEM file)
- Layer 1: Reality TLS handshake (REALITY hijack)
- Layer 2a: X25519 ECDH key exchange
- Layer 2b: AES-256-GCM encryption (per-session keys, nonce replay protection)
- Layer 3: smux stream multiplexer
- Layer 4: MeshNode (gossip, WebSSH, file transfer, SOCKS5, TUN, monitoring)

### Node Types

- **Shared node** — Public TCP+UDP port, Reality TLS server, MuxTransport
- **Ordinary node** — No public port, UDP-only gossip, connects outbound

### Verified

- 22/22 unit test packages pass
- TUN ping verified: 0% packet loss, ~184ms cross-network RTT
- VirtualIP gossip broadcast + kernel route injection
- Subnet proxy route injection
- smux sessions across NAT
