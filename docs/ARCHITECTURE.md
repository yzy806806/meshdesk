# MeshDesk Architecture

**Version:** 3.0 (2026-08-23)

## Overview

### PunchDataplane (v2.0, 2026-08-23)

The punched UDP data plane uses raw datagrams — no ARQ, no framing, no ACKs.
TUN IP packets go out as bare UDP datagrams (up to ~1400B); inbound datagrams
are anti-spoof validated and written directly to the TUN device. Reliability is
delegated to the inner transport (TCP retransmits its own segments).

Key parameters (aligned with Tailscale magicsock):
- Keepalive: 2s (disco ping equivalent)
- Health check: 15s no-RX → auto-degrade to relay
- MTU: 1400 (TUN) → 1411B UDP payload (fits one Ethernet frame)

Inbound routing: mux's `routeUDPPacket` → `punchDataplaneFeed` callback →
`PunchDataplane.Feed()` (anti-spoof + TUN write). The mux's single read loop
owns the socket; PunchDataplane does not compete for reads.

Outbound routing: `getOutboundStream` checks PunchDataplane first (alive →
raw path), then ARQ fallback (if enabled), then smux relay.

MeshDesk is a single-binary decentralized server mesh network combining:
- P2P mesh VPN with custom protocol stack
- Server monitoring (CPU/memory/disk/services)
- WebSSH terminal
- File transfer
- Anonymous proxy (SOCKS5 + Reality)
- 3D topology visualization

Every node runs the same binary. Any node can become the Dashboard with `--web`.

## Protocol Stack

```
┌─────────────────────────────────────────────┐
│           Application Layer                  │
│  Monitor  WebSSH  FileTransfer  Proxy  RPC  │
├─────────────────────────────────────────────┤
│  L4: MeshNode (smux sessions, virtual ports) │
│  MuxTransport (single port: 0x16/0x4D/other) │
├─────────────────────────────────────────────┤
│  L3: smux stream multiplexing               │
├─────────────────────────────────────────────┤
│  L2b: AES-256-GCM SecureConn                │
├─────────────────────────────────────────────┤
│  L2a: X25519 ECDH + Ed25519 key exchange    │
├─────────────────────────────────────────────┤
│  L1: Reality TLS 1.3 (GFW evasion)          │
├─────────────────────────────────────────────┤
│  L0: Ed25519 identity                        │
└─────────────────────────────────────────────┘
```

### L0 — Identity

Each node has an Ed25519 keypair (32-byte private + 32-byte public key).
Identity is auto-generated on first run and stored in config. The public key
serves as the node's unique identifier in the mesh.

### L1 — Reality TLS

REALITY TLS handshake hijack: the server impersonates a major website
(e.g., `www.apple.com:443`). DPI sees legitimate TLS 1.3. Active probing
hits the real website. Only clients with the correct Reality public key
and short ID can access the mesh; others get proxied to the real site.

### L2a — Key Exchange

X25519 ECDH ephemeral key exchange with Ed25519 signature authentication.
Client sends: ephemeral pubkey + nonce + Ed25519 signature.
Server verifies, responds with its ephemeral pubkey + signature.
Both derive shared session keys. Replay protection via nonce cache.

### L2b — Encryption

AES-256-GCM with per-direction session keys derived from ECDH.
Each direction uses independent send/recv keys. Nonce counter prevents reuse.

### L3 — smux Multiplexing

Multiple logical streams over one encrypted connection.
Each stream carries a 2-byte virtual port prefix for dispatching.
Virtual ports: 0 (generic), 2222 (WebSSH), 4191 (monitor), 4192 (RPC), 4193 (file transfer).

### L4 — MeshNode & MuxTransport

**MuxTransport** shares a single TCP port (default 52888) between four protocols:

| First Byte | Protocol | Routing |
|-----------|----------|---------|
| `0x16` | TLS ClientHello | Reality TLS → acceptLoop |
| `0x47`/`0x50`/`0x48` | HTTP | GET/POST/HEAD → HTTP listener (v1.2.1+) |
| `0x4D` | Mesh-internal marker | Key exchange → acceptMeshLoop |
| Other | Meta exchange | Meta StreamCh |

UDP on the same port goes directly to the UDP mesh manager for hole-punch keepalives and data-plane frames.

**MeshNode** manages peer sessions:
- `Dial()` — full Reality TLS path (requires peer config with public key + short ID)
- `DialPeerByEndpoint()` — mesh-internal path via 0x4D marker (for meta-discovered peers)
- `DialVirtualPort()` — opens a stream on an existing session, with fallback to dialing
- `ListenVirtualPort()` — registers a handler for inbound streams on a port

## Peer Discovery (META Exchange)

Uses META exchange over smux sessions for peer discovery, endpoint propagation, and liveness (memberlist retired in v1.7.0).

- **Seeds**: nodes connect to configured seed addresses to join the cluster
- **Endpoint broadcast**: each node advertises multiple endpoints (IPv6, mesh IP, public IPv4)
- **Push/pull sync**: every 30s, nodes exchange state via TCP
- **UDP probes**: fast health checks every 1s
- **NotifyJoin/NotifyLeave**: peer events trigger session establishment or cleanup

## Multi-Endpoint

Nodes advertise multiple addresses via `advertise_endpoints` in config:

```yaml
p2p:
  advertise_endpoints:
    - "[2001:db8::1]:52888"    # Public IPv6
    - "10.0.0.1:52888"         # Mesh VPN IP
    - "203.0.113.1:52888"      # Public IPv4
```

When dialing a peer, the connector tries each endpoint in order and uses
the first that succeeds. This enables IPv4-only nodes to reach IPv6-only
nodes via a shared mesh VPN IP.

## Monitoring

- **Reporter** (every node): collects CPU/memory/load/disk metrics every 15s,
  pushes to configured collectors via `DialMesh(peerID, 4191)`
- **Aggregator** (Dashboard node): receives metric pushes on virtual port 4191,
  stores in `monitor.Store`, exposes via `/api/monitor` and `/api/topology`
- **Config**: `monitoring.collectors` lists peer IDs that should receive metrics

```yaml
monitoring:
  interval: 15
  port: 4191
  collectors:
    - "<dashboard-node-public-key-hex>"
```

## Dashboard

Web UI on port 8080 (configurable via `node.web: ":8080"`).
Enable with `--web` flag.

Features:
- Real-time topology (SSE updates, 3D force-directed graph)
- Node monitoring (CPU/memory/load charts)
- Service management (list/start/stop/restart systemd services)
- File upload to remote nodes
- WebSSH terminal (WebSocket)
- Proxy status (SOCKS5/Reality inbound)
- Configuration management (view/reload/restart with step-up auth)
- 2FA (TOTP) support

Access control: `auth.web_users` with bcrypt password hashes.
Step-up authentication for sensitive operations (service management, file upload, config restart).

## Single-Port Deployment

Shared node exposes only one port (TCP + UDP):

```
Port 52888/TCP → MuxTransport
  ├── 0x16 → Reality TLS (mesh data, GFW evasion)
  ├── 0x47/0x50/0x48 → HTTP (Dashboard Web UI, join server) (v1.2.1+)
  ├── 0x4D → Mesh-internal (key exchange + smux, no Reality needed)
  └── other → Meta exchange (peer discovery, endpoint propagation)

Port 52888/UDP → UDP mesh manager (hole-punch keepalives, data-plane frames)
```

No additional ports needed. Router/firewall only opens one port.

## Code Structure

```
cmd/meshdesk/main.go          — Entry point, wiring
internal/mesh/                 — MeshNode, MuxTransport, routing, peer manager
internal/p2p/                  — (deleted in v1.7.0, memberlist retired)
internal/handshake/            — Reality TLS handshake
internal/session/              — X25519 ECDH key exchange
internal/crypto/               — AES-256-GCM SecureConn
internal/smux/                 — Stream multiplexer
internal/identity/             — Ed25519 identity
internal/join/                 — Auto-join protocol (HMAC+Ed25519 challenge-response)
internal/monitor/              — Reporter, Aggregator, Store
internal/web/                  — Dashboard web server
internal/webssh/               — WebSocket terminal
internal/transfer/             — File transfer
internal/proxy/                — Exit/entry node, multi-path proxy
internal/service/              — Systemd service management
internal/config/               — Config parsing/validation
internal/auth/                 — Capability engine, TOTP
internal/topology/             — 3D graph layout
```

## Key Design Decisions

1. **Single binary, no agent/dashboard split** — every node can be dashboard
2. **Reality TLS for GFW evasion** — not for mesh identity (Ed25519 handles that)
3. **Mesh-internal path (0x4D)** — meta-discovered peers connect without Reality config
4. **Virtual ports over smux** — multiplex monitor/WebSSH/file/RPC on one session
5. **Multi-endpoint broadcast** — solve IPv4/IPv6 network fragmentation
6. **No WireGuard dependency** — custom protocol stack, pure Go
