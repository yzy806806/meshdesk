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

- Custom mesh protocol stack replacing WireGuard: **Layer 0–4 protocol architecture** with Ed25519 identity, Reality TLS handshake, X25519 ECDH key exchange, AES-256-GCM encryption, and smux stream multiplexing
- **Gossip v2 discovery** — automatic peer discovery via hashicorp/memberlist using standard `NetTransport` (real TCP), no custom MeshTransport; no manual peer config needed
- **NAT traversal** — STUN-based public endpoint discovery + UDP hole-punching with relay fallback
- **Dynamic join protocol** — new nodes join via `meshdesk join <bootstrap-addr>`, authenticated by Ed25519 identity signatures
- **Endpoint learning** — when a node connects to a seed, the seed detects its real endpoint and gossips it cluster-wide. Other nodes can then reach the NAT node directly, modeled on EasyTier's endpoint learning mechanism (see [Endpoint Learning and Shared Node Relay](#endpoint-learning-and-shared-node-relay))
- **Shared node relay** — when direct connection fails (e.g., symmetric NAT), traffic is routed through mesh peers via relay circuits with automatic failover: top-2 relay candidates, 30s health checks (PING/PONG), and 3-missed-pong failover to secondary relay (see [Endpoint Learning and Shared Node Relay](#endpoint-learning-and-shared-node-relay))
- **Reality TLS transport** — all mesh traffic over port 443 with REALITY TLS handshake hijack, indistinguishable from HTTPS traffic to a major website (e.g., apple.com). Passive DPI sees legitimate TLS 1.3. Active probing hits the real website's response
- Fine-grained peer capabilities — restrict what each peer can access (monitor, SSH, file transfer, service management)

### How It Works: Protocol Stack

MeshDesk v2 uses a layered protocol stack. Each layer builds on the one below, with clean interfaces between them:

```
┌─────────────────────────────────────────────┐
│ Layer 4 — MeshNode                          │
│   Wires everything together: PeerManager,   │
│   gossip, WebSSH, file transfer, proxy      │
├─────────────────────────────────────────────┤
│ Layer 3 — smux Multiplexer                  │
│   Stream multiplexing over a single conn.   │
│   WebSSH, file transfer, RPC, and proxy     │
│   traffic all share one encrypted link      │
├─────────────────────────────────────────────┤
│ Layer 2b — AES-256-GCM Encryption           │
│   Session-key encryption of all traffic.    │
│   nonce(8B) + ciphertext + tag(16B)         │
├─────────────────────────────────────────────┤
│ Layer 2a — X25519 ECDH Key Exchange         │
│   Ephemeral key exchange + Ed25519 signing. │
│   Binding: Ed25519 identity proves ownership│
│   of the X25519 ephemeral for session auth  │
├─────────────────────────────────────────────┤
│ Layer 1 — Reality TLS Handshake             │
│   Encrypted byte stream. ClientHello with   │
│   SNI=target domain, REALITY auth via       │
│   X25519 ECDH + HKDF. Returns net.Conn      │
├─────────────────────────────────────────────┤
│ Layer 0 — Ed25519 Identity                  │
│   Permanent node identity. Public key IS    │
│   the node ID. Used for signing and gossip  │
│   authenticity. crypto/ed25519 (stdlib)     │
└─────────────────────────────────────────────┘
```

**Key design principles:**

- **Identity-agnostic transport:** Layer 1 (Reality TLS) produces a raw `net.Conn` — it knows nothing about mesh identity. Layer 2 binds identity to the connection via Ed25519 signatures on the X25519 ephemeral.
- **No virtual IPs:** v1 used mesh IPs (10.10.x.y) derived from WireGuard keys. v2 addresses peers by their Ed25519 public key and real endpoints. No TUN interface, no gVisor netstack, no subnet routing.
- **smux multiplexing:** All services (WebSSH, file transfer, RPC, proxy) share a single encrypted connection via smux streams. No per-service port configuration needed.

### Gossip v2

The gossip layer discovers peers and propagates metadata cluster-wide:

- Uses hashicorp/memberlist with standard `NetTransport` — real TCP on the gossip port (default 7946), not the v1 custom `MeshTransport` that tunneled through gVisor
- Separate gossip port from the Reality TLS handshake port (443) — same pattern as Consul, Serf, and Nomad
- `NodeMeta` carries: Ed25519 public key, real endpoints (host:port), NAT type, capabilities (relay/exit/entry), load metrics (CPU, memory, circuits, bandwidth), and a monotonic sequence number
- **No mesh IP** — nodes are addressed by their real endpoints. The 10.10.x.y subnet and `deriveMeshIP` are removed
- Endpoint propagation: STUN discovery and HandshakeLayer inbound connections feed endpoints into gossip, which broadcasts them cluster-wide
- Bootstrap via real addresses: `seeds: ["115.29.235.24:7946"]` instead of v1's `seeds: ["10.10.0.1:7946"]`

### PeerManager

PeerManager is the connection lifecycle manager for every mesh peer. Each peer gets a dedicated goroutine that monitors connectivity, handles failure recovery, and selects the best available path.

- **Auto-reconnect with exponential backoff** — dropped connections are retried automatically with exponential backoff (30s → 60s → 120s → 240s → 300s cap). Successful connection resets the timer
- **Multi-path fallback** — PeerManager tries TCP Reality first, then attempts UDP (QUIC-masqueraded) for direct connections. When direct paths fail, relay fallback routes traffic through a shared peer
- **Quarantine and escape** — repeatedly failing transports are quarantined with exponential cooldown. A blackout escape hatch (try the least-recently-quarantined path) prevents permanent disconnect
- **EWMA-based latency tracking** — split-alpha EWMA (α_rise=0.7, α_fall=0.3) tracks per-path latency for optimal path selection

### Endpoint Learning and Shared Node Relay

When nodes sit behind NAT, direct connectivity depends on discovering each other's public endpoints. MeshDesk implements two complementary mechanisms:

**Endpoint Learning (EasyTier-style)**

- When a NAT node connects to a seed, the seed's HandshakeLayer detects the source endpoint of incoming TCP connections
- The gossip layer receives the notification, updates the local node's metadata (`Endpoints` list + inferred NAT type), and increments the sequence number — triggering automatic re-broadcast to all cluster members
- Other nodes receive the updated metadata via gossip and can now attempt direct connections to the NAT node's public endpoint
- Deduplication is built-in: duplicate endpoint discoveries don't increment the sequence number, preventing gossip storms
- Off by default — the notifier must be explicitly registered. When no notifier is set, endpoint discovery has zero overhead

**Shared Node Relay (multi-hop)**

- When direct connection is impossible (e.g., symmetric NAT on both sides), the entry node selects the top-K=2 relay candidates via RTT-weighted scoring and sends `circuit_setup` messages
- The relay node accepts the circuit (capacity check), adds the target peer's identity to its forwarding table, and begins forwarding traffic
- Health monitoring: PING every 30s; 3 consecutive missed PONGs trigger automatic failover to the secondary relay
- Circuit lifecycle: `circuit_setup` → `circuit_accept` → traffic flows → `circuit_teardown` (on peer leave) or failover
- Reconciliation loop: runs every 30s to detect NAT peers without circuits

**Per-relay quarantine and retry**

- Failed relays are quarantined for 60s with exponential cooldown
- Reconciliation re-probes quarantined relays after expiry

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
- Connection routed over the mesh via smux streams — no virtual IP needed

### File Transfer

- Upload / download files via web UI
- Mesh-internal transfers via smux streams — files route through the encrypted mesh, not exposed to the internet
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

### Dashboard Config Management

The `/config` page provides full configuration management via a tiered access API, eliminating the need to SSH in and edit YAML by hand.

- **All config sections** — renders every field from `node`, `mesh`, `reality`, `peers`, `p2p`, `monitoring`, `webssh`, `auth`, `transfer`, `proxy`, `exit`, and `web` in a single dashboard page
- **Tiered field display** — fields are classified into four access tiers controlling visibility and writability:
  - **T0 (read-only)**: displayed but rejected on write (e.g., `node.hostname`, `peers[N].public_key`, `auth.totp_store_dir`)
  - **T1 (masked)**: displayed as `***` in GET responses, accepted on write (no-op if `***` sent) — for secrets (e.g., `node.identity`, `reality.private_key`)
  - **T2 (step-up)**: displayed normally, requires step-up 2FA token to write — for security-sensitive fields (e.g., `peers[N].capabilities`, `auth.web_users`, `exit.allowed_ports`)
  - **T3 (normal)**: displayed and writable with standard session auth — all other fields
- **Dirty field tracking** — modified fields are tracked as either hot-reloadable or restart-required. The `_meta.tier_map` in the API response tells the client exactly which fields need a restart
- **PATCH /api/config** — partial save via JSON merge-patch (RFC 7396). Only changed fields are sent; the server merges them into the current config, writes atomically to disk, and marks dirty fields
- **Hot reload button** — `POST /api/config/reload` applies all hot-reloadable changes without restarting the daemon. Rate-limited to once per 5 seconds
- **Restart button** — `POST /api/config/restart` triggers a daemon restart for restart-required fields. Step-up auth required. Rate-limited to once per 30 seconds
- **Diff viewer** — `GET /api/config/diff` compares the running in-memory config against the on-disk saved config

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
| v2 Protocol Stack (L0–L4) | **Beta** | Ed25519 Identity, Reality TLS handshake, X25519 ECDH, AES-256-GCM, smux — functionally complete |
| Gossip v2 (NetTransport) | **Beta** | Standard memberlist TCP transport; no mesh IP dependency |
| PeerManager | **Beta** | Auto-reconnect, multi-path fallback, EWMA latency tracking |
| Monitoring | **Stable** | Real-time metrics, push collectors, SSE dashboard updates |
| Web Terminal | **Stable** | xterm.js + WebSocket, multi-tab, SIGWINCH support |
| File Transfer | **Stable** | Upload/download via web UI, capability-scoped paths |
| Service Management | **Stable** | Start/stop/restart systemd services, per-peer authorization |
| Dashboard Security (TOTP 2FA) | **Stable** | TOTP enrollment, step-up auth, encrypted key storage, webhook alerts |
| Multi-path Anonymous Proxy | **Beta** | Circuit routing functional; chunker/reassembly needs real-machine validation |
| Endpoint Learning & Shared Relay | **Beta** | Endpoint learning + NAT-type inference + relay circuits with failover; gossip integration tested |
| Dashboard Config Management | **Beta** | Tiered config API, PATCH merge-patch, hot reload, diff viewer — integration tested |
| 3D Topology Visualization | **Beta** | Node graph + latency edges complete; circuit particles use mock data |

**Maturity definitions:**
- **Stable** — Feature is implemented, unit-tested, and has been verified by the team. Suitable for production use with standard safeguards.
- **Beta** — Feature is functionally complete and passes all unit tests, but has NOT been validated on physical multi-node hardware. Use with caution; report issues on GitHub.

Maturity labels graduate from Beta to Stable when acceptance tests pass on real hardware — not when a commit lands.

## Installation

**Requires root.** The agent needs root to:

- Listen on privileged ports (443 for Reality TLS, 80 for web if needed)
- Execute commands for Web Terminal
- Read system metrics (disk, network, processes)
- Manage systemd services

**No TUN interface required.** MeshDesk v2 does not use WireGuard or gVisor netstack — there is no virtual network device to create.

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

# Generate an Ed25519 identity keypair (prints private and public key)
meshdesk --gen-key

# Join an existing mesh via a bootstrap node (dynamic join protocol)
meshdesk join 203.0.113.5:443 --bootstrap-key <hex-pubkey>
```

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--config` | `/etc/meshdesk/config.yaml` | Path to config file |
| `--web` | `false` | Enable web UI mode (serves dashboard, WebSSH, file transfer, service management, topology) |
| `--relay` | `false` | Enable relay mode (accept proxy relay circuits from peers) |
| `--gen-key` | `false` | Generate a new Ed25519 identity keypair and exit |

**Subcommand: `join`**

```
meshdesk join <bootstrap-addr> [--bootstrap-key <hex>] [--config <path>]
```

Joins an existing mesh via a bootstrap node's Reality TLS endpoint (default port 443). The bootstrap authenticates the joiner (Ed25519 signature verification), then gossips the new member to the cluster.

When `--web` is set and `node.web` is not configured, the web UI listens on `:8080`.

## Configuration

```yaml
# /etc/meshdesk/config.yaml
node:
  identity: ""           # Ed25519 private key (hex, 128 chars); auto-generated if empty
  hostname: ""           # display name (auto-detected if empty)
  web: ":8080"           # web UI listen address; empty = agent-only mode
  listen: ":443"         # Reality TLS listen address (seed nodes with public IP)
  position:              # optional manual 3D position for topology view
    x: 0
    y: 0
    z: 0

mesh:
  listen_port: 443       # Reality TLS handshake listen port
  gossip_port: 7946      # memberlist gossip port (TCP, real interface)

# Reality TLS server config (seed nodes with public IP)
reality:
  enabled: false         # start the Reality TLS listener
  dest: "www.apple.com:443"   # camouflage target — real website for non-auth traffic
  server_names:               # accepted SNI values in ClientHello
    - "www.apple.com"
  private_key: ""             # X25519 private key (hex) for REALITY ECDH auth
  short_ids: []               # accepted short IDs (hex, up to 8 bytes each)
  tls_fingerprint: "chrome"   # browser ClientHello fingerprint to mimic

# P2P dynamic networking (gossip discovery + NAT traversal + dynamic join)
p2p:
  enabled: false
  seeds:                 # bootstrap peers (real_ip:gossip_port)
    - "115.29.235.24:7946"
  nat_traversal: true    # STUN discovery + UDP hole-punching
  stun_servers:          # defaults to Google + Cloudflare STUN
    - "stun.l.google.com:19302"
  relay_mode: "auto"     # auto | manual | disabled
  max_relay_hops: 2
  join_approval: "auto"  # auto (Ed25519 signature) | manual (dashboard)
  authorized_keys: []    # Ed25519 public keys (hex) pre-authorized to join
  gossip_interval: 30    # push/pull state sync interval (seconds)
  gossip_probe_interval: 1  # health check interval (seconds)
  direct_reprobe_interval: 120  # re-probe direct connection while relayed
  max_peers: 256

peers:
  - public_key: "abc123..."         # peer's Ed25519 public key (64 hex chars)
    endpoint: "relay.example.com:443"  # host:port of Reality TLS listener; empty for NAT peers
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
    # Reality TLS client config (per-peer):
    reality:
      server_name: "www.apple.com"   # SNI in ClientHello, must match server's server_names
      public_key: ""                 # server's X25519 public key (hex) for ECDH auth
      short_id: ""                   # per-client short ID (hex, up to 8 bytes)

monitoring:
  collectors: []         # peer IDs of collector nodes that receive metric pushes
  interval: 15           # push interval in seconds
  port: 4191             # mesh-internal port for metric pushes (over smux)

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
  path_selection:             # dynamic path selection
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

All fields are optional. Omitted fields get sensible defaults. If the config file doesn't exist at startup, the node runs with defaults and auto-generates an Ed25519 identity keypair.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  MeshDesk Node                       │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌───────┐  ┌────────┐ │
│  │   Mesh   │  │ Monitor  │  │WebSSH │  │ Proxy  │ │
│  │ Protocol │  │ Collect  │  │ Hub   │  │ Entry/ │ │
│  │ L0–L4    │  │ + Push   │  │(SSH   │  │ Relay/ │ │
│  │+ gossip  │  │          │  │ proxy)│  │ Exit   │ │
│  └────┬─────┘  └────┬─────┘  └───┬───┘  └───┬────┘ │
│       │             │            │           │       │
│  ┌────┴─────────────┴────────────┴───────────┴────┐ │
│  │              PeerManager                       │ │
│  │   auto-reconnect • multi-path fallback         │ │
│  │   EWMA latency tracking • optimal path select  │ │
│  └────┬───────────────────────────────────────────┘ │
│       │                                             │
│  ┌────┴──────────────────────────────────────────┐  │
│  │              smux Multiplexer                  │  │
│  │   WebSSH │ file transfer │ RPC │ proxy        │  │
│  └────┬──────────────────────────────────────────┘  │
│       │                                             │
│  ┌────┴──────────────────────────────────────────┐  │
│  │           Protocol Stack (L0–L4)               │  │
│  │   L4 MeshNode │ L3 smux │ L2 AES-GCM          │  │
│  │   L2a X25519 ECDH │ L1 Reality TLS │ L0 ID    │  │
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
│  │  • Config Management (tiered API)            │  │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Documentation

Detailed design documents are in [`docs/`](./docs/):

- [ARCHITECTURE.md](./docs/ARCHITECTURE.md) — System architecture overview
- [MESHDESK_V2_DESIGN.md](./docs/MESHDESK_V2_DESIGN.md) — v2 design document: custom protocol stack, role model, smart routing
- [V2_INTERFACE_CONTRACT.md](./docs/V2_INTERFACE_CONTRACT.md) — v2 interface contracts for all layers (L0–L4)
- [LAYER0_LAYER1_SPEC.md](./docs/LAYER0_LAYER1_SPEC.md) — Layer 0 (Ed25519 Identity) + Layer 1 (Reality TLS Handshake) specification
- [LAYER2A_KEY_EXCHANGE_SPEC.md](./docs/LAYER2A_KEY_EXCHANGE_SPEC.md) — Layer 2a X25519 ECDH key exchange specification
- [LAYER2_ENCRYPTION_SPEC.md](./docs/LAYER2_ENCRYPTION_SPEC.md) — Layer 2b AES-256-GCM encryption specification
- [LAYER3_SMUX_SPEC.md](./docs/LAYER3_SMUX_SPEC.md) — Layer 3 smux stream multiplexer specification
- [GOSSIP_REDESIGN_SPEC.md](./docs/GOSSIP_REDESIGN_SPEC.md) — Gossip v2 redesign (NetTransport, no mesh IP)
- [PEERMANAGER_DESIGN.md](./docs/PEERMANAGER_DESIGN.md) — PeerManager state machine, quarantine, latency probing, path selection
- [ENDPOINT_LEARNING_DESIGN.md](./docs/ENDPOINT_LEARNING_DESIGN.md) — Endpoint learning mechanism (EasyTier-style)
- [ENDPOINT_LEARNING_DESIGN_v2.md](./docs/ENDPOINT_LEARNING_DESIGN_v2.md) — Endpoint learning v2 (gossip integration + NAT-type inference)
- [OBFUSCATION_RESEARCH.md](./docs/OBFUSCATION_RESEARCH.md) — GFW obfuscation research and Reality integration design
- [TRANSPORT_CONTRACT.md](./docs/TRANSPORT_CONTRACT.md) — Transport layer interface contract
- [PROXY_DESIGN.md](./docs/PROXY_DESIGN.md) — Multi-path anonymous proxy design
- [CIRCUIT_MANAGER_SPEC.md](./docs/CIRCUIT_MANAGER_SPEC.md) — Circuit lifecycle management
- [CHUNKER_CONTRACT.md](./docs/CHUNKER_CONTRACT.md) — Chunker/Reassembler interface
- [CONFIG_INVENTORY.md](./docs/CONFIG_INVENTORY.md) — Full inventory of all config fields
- [CONFIG_SECURITY_MODEL.md](./docs/CONFIG_SECURITY_MODEL.md) — Tiered config access model (T0–T3) and security rationale
- [TOTP_KEY_ENCRYPTION_SPEC.md](./docs/TOTP_KEY_ENCRYPTION_SPEC.md) — TOTP secret encryption
- [3D_TOPOLOGY_DESIGN.md](./docs/3D_TOPOLOGY_DESIGN.md) — 3D topology visualization
- [DESIGN.md](./docs/DESIGN.md) — Frontend design system (color, typography, spacing tokens)
- [FRONTEND.md](./docs/FRONTEND.md) — Frontend architecture, JS/CSS inventory, and conventions
- [SMOKE_TEST_GATES.md](./docs/SMOKE_TEST_GATES.md) — Smoke test definitions and pass gates
- [V2_MIGRATION_GUIDE.md](./docs/V2_MIGRATION_GUIDE.md) — v1 to v2 migration guide
- [RELEASE_NOTES.md](./docs/RELEASE_NOTES.md) — Release notes and validation status
- [RELEASE_CHECKLIST.md](./docs/RELEASE_CHECKLIST.md) — Release SOP checklist
- [THREAT_MODEL.md](./THREAT_MODEL.md) — Security threat model

## License

MIT
