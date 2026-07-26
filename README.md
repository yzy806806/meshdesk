# MeshDesk

**Decentralized server mesh network + monitoring + WebSSH + anonymous proxy — in a single binary.**

[中文文档](./README_CN.md)

---

## What is MeshDesk?

MeshDesk combines five tools into one:

1. **Mesh VPN** — P2P decentralized networking between all your servers (replaces EasyTier)
2. **Server Monitoring** — CPU, memory, disk, network, services (replaces Nezha)
3. **Web Terminal** — SSH directly from the browser, no separate client needed
4. **Multi-path Anonymous Proxy** — dispersed traffic across relay nodes with GFW-resistant transport
5. **3D Topology Visualization** — interactive 3D mesh topology in the browser

Every node runs the same binary. Any node can become the control panel with `--web`.

### Why not just use Nezha + EasyTier?

| | Nezha | EasyTier | MeshDesk |
|---|---|---|---|
| Server monitoring | ✅ | ❌ | ✅ |
| Mesh VPN | ❌ | ✅ | ✅ |
| WebSSH | ✅ (via agent) | ❌ | ✅ (via agent) |
| Architecture | Centralized (agent→dashboard) | Decentralized P2P | Decentralized P2P |
| Single binary | ❌ (dashboard + agent) | ✅ | ✅ |
| File transfer | ❌ | ❌ | ✅ |
| Network topology view | ❌ | ✅ (CLI only) | ✅ (3D Web UI) |
| Anonymous proxy | ❌ | ❌ | ✅ |
| Dashboard 2FA | ❌ | ❌ | ✅ |

Nezha has monitoring and WebSSH but no mesh networking — if the dashboard is down, you lose everything. EasyTier has mesh VPN but no monitoring or web terminal. MeshDesk does it all in one binary.

## Features

### Mesh VPN & P2P Dynamic Networking

- Decentralized P2P networking via **WireGuard** (wireguard-go + gVisor netstack)
- **Gossip discovery** — automatic peer discovery via hashicorp/memberlist; no manual peer config needed
- **NAT traversal** — STUN-based public endpoint discovery + UDP hole-punching with relay fallback
- **Dynamic join protocol** — new nodes join via `meshdesk join <bootstrap-addr>`, authenticated by authorized_keys
- **Relay fallback** — when direct connection fails, traffic is relayed through mesh peers
- Transport obfuscation: padded mode (AmneziaWG-style) or WebSocket+TLS mode (with uTLS fingerprint mimicry)
- Fine-grained peer capabilities — restrict what each peer can access (monitor, SSH, file transfer, service management)
- Pluggable transport layer with Reality TLS handshake hijack (embedded, no subprocess) — see [Transport Layer](#transport-layer)

### Transport Layer

The transport layer abstracts how MeshDesk nodes communicate. Every peer can use a different transport, and [PeerManager](#peermanager) handles automatic fallback between them. The transport layer implements a three-layer interface contract: `PeerConn` (per-connection wrapper), `Transport` (per-transport instance), and `TransportRegistry` (named registry). See [docs/TRANSPORT_CONTRACT.md](./docs/TRANSPORT_CONTRACT.md) for the full spec.

- **Transport Interface** — a common `Transport` interface (`Connect`, `Listen`, `LatencyProbe`, `IsHealthy`) decouples WireGuard from the underlying network. Any transport implementing this interface can carry mesh traffic — add new transports without touching WireGuard code.
- **UDP Transport** — raw WireGuard UDP. Used for LAN peers and direct connections. Lowest latency, zero overhead.
- **Reality Transport** — xray-core Reality TLS handshake hijack, **embedded directly in MeshDesk** (no subprocess, no external binary). uTLS ClientHello fingerprint mimicry (Chrome, Firefox, Safari) makes the connection indistinguishable from a real browser visiting a major website (e.g., apple.com). Passive DPI sees legitimate TLS 1.3. Active probing hits the real website's response. The strongest GFW-resistant transport available.
- **WebSocket Transport** — WebSocket + TLS with uTLS fingerprint mimicry, retained as a fallback for environments where Reality is unnecessary or unavailable.
- **Automatic Fallback** — PeerManager tries transports in priority order (UDP → Reality → WS → Relay). If the primary transport is unresponsive after 5s, the next transport is raced in parallel (Happy Eyeballs hedging). See [docs/ARCHITECTURE_REFACTOR.md](./docs/ARCHITECTURE_REFACTOR.md) for the full refactor design.

### PeerManager

PeerManager is the connection lifecycle manager for every mesh peer. Each peer gets a dedicated goroutine that monitors connectivity across all transports, handles failure recovery, and selects the best available path.

- **Auto-reconnect with exponential backoff** — dropped connections are retried automatically with exponential backoff (30s → 60s → 120s → 240s → 300s cap). Successful connection resets the timer.
- **Multi-transport fallback** — when the primary transport fails, PeerManager falls through the fallback chain (UDP → Reality → WS → Relay) automatically. Quarantined transports are cooled off with exponential cooldown before retry. A **blackout escape hatch** (try the least-recently-quarantined transport) prevents permanent disconnect when all transports are unavailable.
- **EWMA-based latency probing** — split-alpha EWMA (α_rise=0.7, α_fall=0.3) tracks per-transport latency. Fast rise detects degradation within 2 samples (~60s); slow fall prevents path flapping. Samples come from both passive sources (WireGuard handshake timing, TCP RTT via `getsockopt`) and active probes (scheduled `LatencyProbe` calls).
- **Optimal path selection with hysteresis** — a composite additive score (EWMA latency + stability penalty − hysteresis bonus) selects the best transport. A 10% hysteresis discount on the currently-active transport prevents path flapping when two transports have similar latency.
- **Per-transport quarantine** — repeated failures quarantine a transport with exponential cooldown (up to 300s cap). Failure thresholds vary by transport type (UDP: 3, WebSocket: 2, Reality: 2, Relay: 3) reflecting real-world reliability characteristics.

See [docs/PEERMANAGER_DESIGN.md](./docs/PEERMANAGER_DESIGN.md) for the full state machine, quarantine logic, Happy Eyeballs hedging, and path selection scoring spec.

### Monitoring

- Real-time CPU / memory / disk / network / load average metrics
- Metric push to collector nodes with configurable interval
- Ring buffer storage per node (buffers during collector outage)
- Live dashboard updates via Server-Sent Events (SSE)
- Process list per server

### Web Terminal

- Browser-based terminal (xterm.js + WebSocket)
- No SSH keys or passwords needed — agent runs as root
- Multi-tab, multi-server terminal
- Connection proxied over the mesh VPN

### File Transfer

- Upload / download files via web UI
- Mesh-internal transfers (files route through the VPN, not exposed to the internet)
- Capability-based access control — restrict which peers can send files and which paths they can touch
- Configurable per-file size limit and upload directory

### Service Management

- Start / stop / restart systemd services
- View service logs
- Authorized per-peer — only peers with `service_manage` capability can control services

### Multi-path Anonymous Proxy

A built-in multi-path dispersed transport proxy for censorship-resistant internet access:

- **Shadowsocks entry** — accepts user traffic via SS AEAD (chacha20-ietf-poly1305) over WebSocket
- **Cloudflare Tunnel camouflage** — entry listener exposed via `cloudflared` for TLS camouflage (appears as HTTPS)
- **ECDH circuit setup** — per-connection end-to-end encryption between entry and exit nodes
- **Two disjoint relay paths** — traffic is split across two node-disjoint paths to disperse traffic patterns
- **Blind relay forwarding** — relay nodes never decrypt payload; they only process the onion-style forwarding header
- **Anti-timing-analysis jitter** — relays introduce random 5–50ms delays to disrupt traffic correlation
- **Pluggable chunker** — fixed 16KB or bounded random 4KB–64KB chunk sizes with padding
- **Exit reassembly** — sliding-window reassembly with out-of-order handling, deduplication, NACK retransmission, and orphan cleanup
- **Dynamic path selection** — automatic RTT-based path probing and selection (Dijkstra k-shortest paths)
- **Audit logging** — exit nodes log circuit→destination mappings (no payload data)

### Dashboard Security

- **TOTP 2FA** — RFC 6238 time-based one-time passwords with QR code enrollment
- **Encrypted secret storage** — TOTP secrets encrypted at rest with node-local master key (AES-256-GCM)
- **Step-up authentication** — sensitive operations (terminal, service management, file upload, settings) require recent 2FA verification
- **Security alerting** — real-time alerts for auth denials, node joins/leaves, and suspicious proxy activity
- **Webhook dispatch** — async alert delivery to external endpoints (Slack, Discord, custom) with 3-retry exponential backoff
- **TOTP key rotation** — zero-downtime key rotation with old-key grace period
- **Recovery codes** — 10 single-use recovery codes generated during enrollment
- **Lockout protection** — 5 failed TOTP attempts triggers 30-second lockout

### 3D Topology Visualization

- Interactive **Three.js** 3D scene with force-directed node layout
- **Animated particles** flowing along proxy circuit paths (edges)
- **Real-time SSE updates** — topology changes reflected live in the browser
- **Color-coded nodes** by role (entry=blue, relay=orange, exit=green, dashboard=purple)
- **Node hover labels** with role, CPU, memory, hostname
- **Edge thickness** modulated by latency (lower latency = brighter)
- **OrbitControls** for pan / zoom / rotate
- **Performance-adaptive** — reduces particle count on low FPS
- Mock-data fallback when no real mesh nodes exist

### Feature Maturity

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
| Multi-path Anonymous Proxy | **Beta** | Circuit routing functional; chunker/reassembly needs real-machine validation |
| 3D Topology Visualization | **Beta** | Node graph + latency edges complete; circuit particles use mock data |
| x-ui Panel Integration | **Beta** | Inbound/outbound configuration, user management, Reality config generation via Dashboard |

**Maturity definitions:**
- **Stable** — Feature is implemented, unit-tested, and has been verified by the team. Suitable for production use with standard safeguards.
- **Beta** — Feature is functionally complete and passes all unit tests, but has NOT been validated on physical multi-node hardware. Use with caution; report issues on GitHub.

Maturity labels graduate from Beta to Stable when acceptance tests pass on real hardware — not when a commit lands.

## Known Caveats

The following issues were discovered during pre-release validation and have been fixed at HEAD. They are documented here because they illustrate gaps that automated testing alone cannot close:

1. **Working tree corruption (fixed).** `cmd/meshdesk/main.go` was truncated to zero bytes in the working tree. `go test ./...` passed because it operates on compiled packages, not working tree file integrity. A `git checkout` restored the 652-line entrypoint. **Lesson:** always run `go build ./...` before declaring a release buildable — tests alone are not sufficient.

2. **Duplicate StreamEnd after completion (fixed).** When a `ChunkStreamEnd` arrived for an already-completed stream, `AddStreaming` created a brand-new stream state because the old one had been cleaned up. The fix tracks recently-completed stream IDs in a `completedStreams` map so that duplicate completions are silently ignored rather than re-processed.

3. **StreamEnd payload injection at delivered sequence (fixed).** The deduplication check in `processChunk` used `st.chunks[sequence]` existence to detect duplicates, but delivered chunks are removed from that map. A StreamEnd arriving at an already-delivered sequence bypassed the check and stored replacement payload. The fix adds a `sequence < st.nextExpected` guard to reject payloads at already-delivered positions.

All three were missed by `go test ./...` because the test suite operates on committed, tracked Go packages — it cannot detect working tree corruption, missing deduplication in edge cases that were not yet tested, or race conditions between stream lifecycle and chunk arrival. Real-machine deployment remains the only reliable way to surface these categories of issues.

## Installation

**Requires root.** The agent needs root to:

- Create TUN interface for the WireGuard VPN
- Execute commands for Web Terminal
- Read system metrics (disk, network, processes)
- Manage systemd services

### Build from source

```bash
git clone https://github.com/yzy806806/meshdesk.git
cd meshdesk
go build -o meshdesk ./cmd/meshdesk/
sudo cp meshdesk /usr/local/bin/
```

### Run

```bash
# Agent only (mesh transport + monitoring reporter)
meshdesk --config /etc/meshdesk/config.yaml

# Agent + Web UI (dashboard, WebSSH, file transfer, service management, topology)
meshdesk --config /etc/meshdesk/config.yaml --web

# Agent + relay mode (accept proxy relay circuits from peers)
meshdesk --config /etc/meshdesk/config.yaml --relay

# Generate a WireGuard keypair (prints private and public key)
meshdesk --gen-key

# Join an existing mesh via a bootstrap node (dynamic join protocol)
meshdesk join 203.0.113.5:51820 --bootstrap-key <hex-pubkey>
```

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--config` | `/etc/meshdesk/config.yaml` | Path to config file |
| `--web` | `false` | Enable web UI mode (serves dashboard, WebSSH, file transfer, service management, topology) |
| `--relay` | `false` | Enable relay mode (accept proxy relay circuits from peers) |
| `--gen-key` | `false` | Generate a new WireGuard keypair and exit |

**Subcommand: `join`**

```
meshdesk join <bootstrap-addr> [--bootstrap-key <hex>] [--config <path>]
```

Joins an existing mesh via a bootstrap node. The bootstrap authenticates the joiner (authorized_keys check), then gossips the new member to the cluster.

When `--web` is set and `node.web` is not configured, the web UI listens on `:8080`.

## Configuration

```yaml
# /etc/meshdesk/config.yaml
node:
  identity: ""           # WireGuard private key (hex); auto-generated if empty
  hostname: ""           # display name (auto-detected if empty)
  web: ":8080"           # web UI listen address; empty = agent-only mode
  position:              # optional manual 3D position for topology view
    x: 0
    y: 0
    z: 0

mesh:
  port: 51820            # WireGuard listen port
  gossip_port: 7946      # memberlist gossip port (TCP, on mesh IP)

# P2P dynamic networking (gossip discovery + NAT traversal + dynamic join)
# When disabled, only static peers are used (backward compatible).
p2p:
  enabled: false
  seeds:                 # bootstrap peers (mesh_ip:gossip_port)
    - "10.0.0.1:7946"
  nat_traversal: true    # STUN discovery + UDP hole-punching
  stun_servers:          # defaults to Google + Cloudflare STUN
    - "stun.l.google.com:19302"
  relay_mode: "auto"     # auto | manual | disabled
  max_relay_hops: 2
  join_approval: "auto"  # auto (authorized_keys) | manual (dashboard)
  authorized_keys: []    # WireGuard public keys (hex) pre-authorized to join
  gossip_interval: 30    # push/pull state sync interval (seconds)
  gossip_probe_interval: 1  # health check interval (seconds)
  direct_reprobe_interval: 120  # re-probe direct connection while relayed
  max_peers: 256

peers:
  - public_key: "abc123..."         # peer's WireGuard public key
    endpoint: "relay.example.com:51820"  # host:port; empty for roaming peers
    allowed_ips:                     # mesh IPs routed to this peer
      - "10.0.0.2/32"
    capabilities:                    # what this peer is allowed to do on us
      - monitor_write               # push metrics to us
      - file_transfer               # send/receive files
      - ssh                         # open terminal sessions
      - service_manage              # manage systemd services
    service_manage:                  # restrict service_manage to specific unit names
      - nginx
      - docker
    file_transfer_paths:             # restrict file_transfer to specific directories
      - /var/www/
    obfuscation: "padded"            # none | padded | websocket
    obf_config:                        # per-peer obfuscation parameters (AmneziaWG-style)
      jc: 5                            # junk train: 5 junk packets before handshake initiation
      jmin: 64                         # min junk packet size (bytes)
      jmax: 256                        # max junk packet size (bytes)
      jitter_max_ms: 20                # timing jitter to disrupt traffic analysis
      psk: ""                          # hex-encoded 32-byte anti-probe PSK (empty = disabled)
      # For websocket mode:
      # ws_use_tls: true               # use wss:// (TLS) for the WebSocket transport
      # tls_sni: "example.com"         # SNI to send in TLS ClientHello
      # tls_fingerprint: "chrome"      # chrome | firefox | safari | edge | ios | android

monitoring:
  collectors: []         # peer IDs of collector nodes that receive metric pushes
  interval: 15           # push interval in seconds
  port: 4191             # mesh-internal port for metric pushes

webssh:
  port: 2222             # mesh-internal port for SSH server on target nodes
  shell: ""              # default shell (auto-detected if empty)
  host_key: ""           # SSH host private key (auto-generated if empty)
  dial_timeout: 10       # seconds to wait when dialing the target node
  read_deadline: 300     # WebSocket read deadline for idle sessions (seconds)
  write_deadline: 10     # WebSocket write deadline (seconds)
  max_sessions: 256      # max concurrent terminal sessions per node

auth:
  web_users:             # web UI login accounts (leave empty for first-run open access)
    - username: admin
      password_hash: "$2a$10$..."  # bcrypt hash of the password
  totp_issuer: "MeshDesk"     # issuer name in QR code otpauth:// URI
  require_2fa: false          # mandate TOTP enrollment before dashboard access
  totp_window: 1              # ±skew tolerance (each step = 30s)
  totp_store_dir: ""          # dir for encrypted TOTP state (e.g. /var/lib/meshdesk/totp)
  step_up_timeout: 300        # step-up auth token lifetime (seconds)
  alert_webhook_url: ""      # external webhook for security alert delivery

transfer:
  max_file_size: 1073741824   # max file size in bytes (default 1 GB, 0 = unlimited)
  upload_dir: "/tmp/meshdesk-uploads/"  # where incoming transfers are written

# Multi-path anonymous proxy (see docs/PROXY_DESIGN.md)
proxy:
  ss:                         # Shadowsocks entry listener (entry nodes only)
    password: "your-ss-password"
    cipher: "chacha20-ietf-poly1305"
    listen_addr: "127.0.0.1:8388"
  circuit:                    # circuit lifecycle parameters
    idle_timeout: 300         # auto-teardown after N seconds idle
    keepalive_interval: 30    # ping interval (seconds)
    nack_timeout: 5           # exit waits N seconds before NACK
    orphan_timeout: 30        # incomplete reassembly buffer cleanup
    max_reassembly_window: 256
  chunker_strategy: "bounded-4k-64k"  # or "fixed-16k"
  path_selection:             # dynamic path selection (Phase 2)
    mode: "manual"            # manual | auto
    strategy: "latency"       # latency | random | round-robin
    max_relays_per_path: 2
    probe_timeout_sec: 3
    probe_concurrency: 8
    max_candidates: 10
    probe_cache_ttl_sec: 30
  cf_tunnel:                  # Cloudflare Tunnel (entry nodes only)
    enabled: false
    tunnel_id: ""
    credentials_file: ""
    hostname: "proxy.example.com"
    origin_server: "127.0.0.1:8388"
    binary_path: ""           # path to cloudflared binary
  relay:                      # relay node config (relay nodes only)
    enabled: false
    jitter_min_ms: 5
    jitter_max_ms: 50
    max_circuits: 1024
    max_queue_depth: 256
  exit:                       # exit node config (exit nodes only)
    allowed_ports: [80, 443]
    allow_all_ports: false    # WARNING: full legal exposure
    destination_filter: []    # CIDR or FQDN patterns
    audit_log_dir: ""
    audit_retention_days: 7
```

All fields are optional. Omitted fields get sensible defaults. If the config file doesn't exist at startup, the node runs with defaults and auto-generates a WireGuard identity.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  MeshDesk Node                       │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌───────┐  ┌────────┐ │
│  │   Mesh   │  │ Monitor  │  │WebSSH │  │ Proxy  │ │
│  │ WireGuard│  │ Collect  │  │ Hub   │  │ Entry/ │ │
│  │ + netstk │  │ + Push   │  │(SSH   │  │ Relay/ │ │
│  │ + gossip │  │          │  │ proxy)│  │ Exit   │ │
│  └────┬─────┘  └────┬─────┘  └───┬───┘  └───┬────┘ │
│       │             │            │           │       │
│  ┌────┴─────────────┴────────────┴───────────┴────┐ │
│  │              PeerManager                       │ │
│  │   auto-reconnect • multi-transport fallback    │ │
│  │   EWMA latency probing • optimal path select   │ │
│  └────┬───────────────────────────────────────────┘ │
│       │                                             │
│  ┌────┴──────────────────────────────────────────┐  │
│  │              Transport Layer                   │  │
│  │   UDP • Reality (embedded) • WebSocket        │  │
│  └────┬──────────────────────────────────────────┘  │
│       │                                             │
│  ┌────┴──────────────────────────────────────────┐  │
│  │           HTTP Server                          │  │
│  │  (--web only)                                 │  │
│  │                                               │  │
│  │  • Dashboard (htmx + SSE)                    │  │
│  │  • WebSSH Terminal                            │  │
│  │  • File Transfer UI                           │  │
│  │  • Service Management UI                      │  │
│  │  • 3D Topology (Three.js + SSE)              │  │
│  │  • TOTP 2FA + Step-up Auth                   │  │
│  │  • Security Alerts + Webhook                 │  │
│  │  • x-ui Panel Integration                    │  │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Documentation

Detailed design documents are in [`docs/`](./docs/):

- [ARCHITECTURE.md](./docs/ARCHITECTURE.md) — System architecture overview
- [ARCHITECTURE_REFACTOR.md](./docs/ARCHITECTURE_REFACTOR.md) — Transport layer abstraction, Reality, and PeerManager refactor
- [PEERMANAGER_DESIGN.md](./docs/PEERMANAGER_DESIGN.md) — PeerManager state machine, quarantine, latency probing, path selection
- [OBFUSCATION_RESEARCH.md](./docs/OBFUSCATION_RESEARCH.md) — GFW obfuscation research and Reality integration design
- [TRANSPORT_CONTRACT.md](./docs/TRANSPORT_CONTRACT.md) — Transport layer interface contract (PeerConn, Transport, TransportRegistry)
- [PROXY_DESIGN.md](./docs/PROXY_DESIGN.md) — Multi-path anonymous proxy design
- [CIRCUIT_MANAGER_SPEC.md](./docs/CIRCUIT_MANAGER_SPEC.md) — Circuit lifecycle management
- [CHUNKER_CONTRACT.md](./docs/CHUNKER_CONTRACT.md) — Chunker/Reassembler interface
- [TOTP_KEY_ENCRYPTION_SPEC.md](./docs/TOTP_KEY_ENCRYPTION_SPEC.md) — TOTP secret encryption
- [3D_TOPOLOGY_DESIGN.md](./docs/3D_TOPOLOGY_DESIGN.md) — 3D topology visualization
- [THREAT_MODEL.md](./THREAT_MODEL.md) — Security threat model

## License

MIT
