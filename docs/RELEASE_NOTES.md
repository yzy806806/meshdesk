# Release Notes

## v1.2.1 — 2026-08-06

Single-port HTTP multiplexing and programmatic join endpoint. Commit: `89e4081`

### Features

- **Single-Port HTTP Demux** — Dashboard Web UI and join server now share the mesh port (52888) via MuxTransport. HTTP traffic (GET/POST/HEAD, first byte `0x47`/`0x50`/`0x48`) is demuxed onto a dedicated channel, enabling single-port deployment behind restrictive NAT — only one public port required for all mesh traffic plus web access.
- **`/api/join` Onboarding Endpoint** — Programmatic challenge-response onboarding via `POST /api/join` on port 52888. The join server handler is attached to the Dashboard's HTTP mux, so `/api/join` rides the same port as the web UI. Exempt from web session auth; authenticated via token + Ed25519 challenge signature instead.

### Verified

- HTTP demux parseability tests confirm all HTTP methods (GET/POST/HEAD) are correctly routed
- E2E wiring test verifies `POST /api/join` is served through the demux port
- Mux demux regression fixed (HTTP channel consumer added to test harness)

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
