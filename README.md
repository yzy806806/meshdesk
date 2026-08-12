# MeshDesk

**Decentralized server mesh — VPN + monitoring + WebSSH + SOCKS5 proxy + TUN virtual network, in a single Go binary.**

[中文文档](./README_CN.md) | [Release Notes](docs/RELEASE_NOTES.md)

> **Current release: v1.2.1** (`a83c9f8`, 2026-08-06) + patch `fef481a` (2026-08-07) — 12 features: systemd, version, log rotation, config validation, Mesh DNS, traffic stats, alert UI, signal handling, hot-reload, CI, plus v1.2.1's single-port HTTP multiplexing and `/api/join` onboarding on port 52888. See [release notes](docs/RELEASE_NOTES.md) and [known issues](https://github.com/yzy806806/meshdesk/issues/1).

---

## Why MeshDesk?

If you manage multiple servers, you probably run Nezha for monitoring, EasyTier or WireGuard for networking, and maybe a proxy tool for circumventing firewalls. That's three or more processes, three configs, three things to update.

MeshDesk does all of it in one binary:

| Feature | Nezha | EasyTier | WireGuard | MeshDesk |
|---------|:-----:|:--------:|:---------:|:--------:|
| Server monitoring | ✅ | — | — | ✅ |
| Mesh VPN / TUN | — | ✅ | ✅ | ✅ |
| WebSSH | ✅ | — | — | ✅ |
| SOCKS5 proxy | — | — | — | ✅ |
| One-click join | — | — | — | ✅ |
| Anti-DPI (Reality TLS) | — | — | — | ✅ |
| Single binary | — | ✅ | — | ✅ |
| Dashboard config | — | — | — | ✅ |

### Key Design Choices

- **Reality TLS** — All mesh traffic is disguised as HTTPS to a real website (e.g. `www.apple.com:443`). DPI cannot distinguish it from legitimate traffic. No WireGuard, no KCP, no recognizable UDP patterns.
- **Single port** — Everything runs on one TCP+UDP port (default 52888). MuxTransport sniffs the first byte to route Reality TLS, mesh-internal smux, SOCKS5, and memberlist gossip.
- **Zero third-party TUN** — The TUN device is created via raw `/dev/net/tun` syscalls (~150 lines). No wireguard-go, no gVisor, no external dependencies.
- **Deterministic IPAM** — Virtual IP = `cidr_base + (pubkey_hash % host_count)`. No DHCP server, no coordination, zero conflicts.
- **Reactive Relay Fallback** — When nodes cannot establish a direct connection, the per-pair `NatSession` state machine automatically probes alternatives (STUN→DirectProbe→RelayFallback), selecting the best relay from gossip-advertised `CapRelay` metadata by RTT. No global routing table, no manual path configuration. Single-hop relay (A→relay→B) covers the four-node topology; multi-hop transit (A→R1→R2→B) is deferred to a future phase. See [design decision](docs/DESIGN_DECISION_NO_GLOBAL_ROUTING.md).
- **Self-evolving** — Built with the Agora multi-agent framework. AI teams implement features, write tests, review code, and deploy autonomously.

---

## Quick Start

### 1. Build

```bash
go build -o meshdesk ./cmd/meshdesk/

# Cross-compile for ARM64 (e.g. ARM SBCs)
GOOS=linux GOARCH=arm64 go build -o meshdesk-arm64 ./cmd/meshdesk/
```

### 2. Shared Node (has a public port)

```bash
meshdesk gen-identity    # → identity.pem
meshdesk gen-reality      # → reality keys

meshdesk --web --config /etc/meshdesk/config.yaml
```

Config:
```yaml
node:
  hostname: "gateway"
  web: ":8080"
  identity_file: "/etc/meshdesk/identity.pem"
mesh:
  port: 52888
  tun_enabled: true
  mesh_cidr: "10.100.0.0/24"
p2p:
  enabled: true
  advertise_endpoints: ["YOUR_PUBLIC_IP:52888"]
  gossip_probe_interval: 5
reality:
  enabled: true
  dest: "www.apple.com:443"
  server_names: ["www.apple.com"]
  private_key: "..."
  short_ids: ["aabbccdd"]
auth:
  web_users:
    - username: admin
      password_hash: "$2b$10$..."  # bcrypt
```

### 3. Ordinary Node (no exposed port)

```yaml
p2p:
  enabled: true
  seeds: ["SHARED_NODE_IP:52888"]
  gossip_probe_interval: 5
reality:
  enabled: false
mesh:
  tun_enabled: true
  mesh_cidr: "10.100.0.0/24"
```

### 4. One-Click Join

Open the Dashboard → **Join** page, click "Generate Install Command", paste on the new machine:

```bash
# Legacy web port (8080)
curl -sSL http://gateway:8080/join?token=xxx | sudo sh

# Single-port path (52888) — v1.2.1+
curl -sSL http://gateway:52888/join?token=xxx | sudo sh
```

For programmatic onboarding, the `/api/join` endpoint (POST) supports challenge-response authentication over either port:

```bash
curl -X POST http://gateway:52888/api/join \
  -H "Content-Type: application/json" \
  -d '{"token":"xxx","joiner_pubkey":"..."}'
```

The new node auto-downloads the binary, generates identity, writes config, and joins the cluster.

---

## Architecture

### Protocol Stack

```
┌──────────────────────────────────────────────┐
│ Application Layer                            │
│   Monitoring · WebSSH · File Transfer        │
│   SOCKS5 Proxy · TUN Forwarding · Dashboard  │
├──────────────────────────────────────────────┤
│ Layer 3 — smux Stream Multiplexer            │
│   Many virtual streams over one connection   │
├──────────────────────────────────────────────┤
│ Layer 2b — AES-256-GCM Encryption           │
│   Per-session keys, nonce-based replay       │
│   protection, authenticated encryption       │
├──────────────────────────────────────────────┤
│ Layer 2a — X25519 ECDH Key Exchange          │
│   Ephemeral DH + Ed25519 identity signing    │
├──────────────────────────────────────────────┤
│ Layer 1 — Reality TLS                        │
│   REALITY hijack on port 52888               │
│   Indistinguishable from HTTPS to apple.com  │
├──────────────────────────────────────────────┤
│ Layer 0 — Ed25519 Identity                   │
│   Permanent node identity (PEM file)         │
└──────────────────────────────────────────────┘
```

### Single-Port Multiplexing (MuxTransport)

Port 52888 handles all protocols via first-byte sniffing:

| First Byte | Protocol | Target | Description |
|:----------:|----------|--------|-------------|
| `0x16` | Reality TLS | `realityCh` | TLS ClientHello — encrypted mesh traffic |
| `0x47`/`0x50`/`0x48` | HTTP | `httpCh` | GET/POST/HEAD — Dashboard, join server (v1.2.1+) |
| `0x4D` | mesh-internal | `meshCh` | smux session establishment (key exchange) |
| `0x53` | SOCKS5 entry | — | Phone/client SOCKS5 proxy entry (`0x5350`) |
| `0x45` | SOCKS5 exit | — | Exit node handler (`0x4558`) |
| `0x52` | smux relay | — | Cross-network stream relay (`0x524C`) |
| other | gossip | `streamCh` | memberlist TCP push/pull sync |

UDP 52888 handles memberlist gossip (ping/pong, anti-entropy).

### Zone-Aware Transport (v1.5.8+)

Nodes carry a free-form zone tag (`mesh.zone` + `peer.zone`, e.g. `cn`/`us`).
Transport selection:

| Peer zone | Data plane | Sessions |
|-----------|-----------|----------|
| **Same zone** (equal, non-empty) | UDP multipath (fast) | UDP direct / 0x4D / hole-punching |
| **Cross zone** (different) | Reality TLS only | Reality (no 0x4D, no punching) |
| **Unknown** (empty) | Reality TLS only (conservative) | Reality / relay |

**Rationale**: same zone = same side of the network → UDP P2P is fast and
safe; cross zone = crossing the GFW boundary → **Reality TLS only** (UDP
across the wall is QoS-throttled and fingerprintable). Unknown zone is
conservative (Reality works everywhere, UDP across the wall is the real
risk).

```yaml
mesh:
  zone: cn

peers:
  - public_key: 0d4bf4b1...
    endpoint: 203.0.113.10:52888
    zone: cn    # same zone → UDP P2P
  - public_key: 7eb1844e...
    endpoint: 161.118.141.101:52888
    zone: us    # cross zone → Reality only
```

Zone is broadcast via gossip (NodeMeta.Zone) — new nodes are auto-learned.
The Dashboard 3D topology shows zone rings + transport-colored edges
(Reality green / UDP blue / 0x4D amber / relay grey), with ping & bandwidth
on edge hover. Full guide: [docs/ZONE_AWARE_TRANSPORT.md](docs/ZONE_AWARE_TRANSPORT.md)

### SOCKS5 Entry & Exit (v1.5.9+)

Every node is a SOCKS5 **exit** by default (virtual port `0x5350`,
destination ports 80/443). The **entry** listener is managed from the
Dashboard Proxy page (or `--socks5-listen`):

```yaml
proxy:
  socks5:
    entry_listen: 0.0.0.0:10811   # LAN clients connect here
    entry_username: mesh          # RFC 1929 auth (required for
    entry_password: secret        #   non-loopback listeners)
    exit_node: fc709e08...        # pin this entry to ONE fixed exit
    # exit_nodes: [a..., b...]    # or a list — lowest live RTT picked
```

- **Exit selection (v1.5.11)**: per connection the healthy exit with the
  lowest live RTT wins (`pickBestExits`); failures fall back to the next.
- **Multi-hop relay (v1.5.11)**: `DialVirtualPort` tries a relay path when
  the direct RTT is slow (>300ms, typical cross-zone Reality) — a
  same-zone relay hop can beat the direct path; multi-hop chains
  (A→R1→R2→B) are loop-protected and bounded by `p2p.max_relay_hops`.
- Save on the Proxy page auto-restarts the daemon (supervisor required).

### Node Types

| | Shared Node | Ordinary Node |
|---|---|---|
| Public port | ✅ TCP+UDP 52888 | — |
| Reality TLS | ✅ (server) | — |
| MuxTransport | ✅ TCP listener | UDP-only |
| Gossip | ✅ | ✅ |
| Monitoring | ✅ | ✅ |
| Dashboard | ✅ (`--web`) | ✅ (`--web`) |
| TUN | ✅ | ✅ |

---

## TUN Virtual Network

Transparent Layer 3 IP routing across the mesh. With TUN enabled, nodes can `ping`, `ssh`, and run any IP application over the virtual network.

```yaml
mesh:
  tun_enabled: true
  mesh_cidr: "10.100.0.0/24"
  subnet_proxy: ["172.26.0.0/18"]   # share local LAN
  tun_name: "mesh0"
  tun_mtu: 1400
```

**How it works:**

1. **IPAM** — Each node deterministically allocates a Virtual IP from `mesh_cidr` based on its public key hash. No central allocator, no conflicts.
2. **Route sync** — When a peer joins, its VirtualIP propagates via gossip. All nodes install `/32` kernel routes via the TUN interface.
3. **Forwarding** — IP packets read from TUN → destination IP resolved to peer public key → sent over smux stream → remote TUN → kernel → target app.
4. **Subnet proxy** — Nodes with `subnet_proxy` advertise local subnets. Peers install kernel routes, enabling cross-network LAN access.
5. **Anti-spoofing** — Every inbound TUN packet is validated: source IP must match the sender's gossip-advertised VirtualIP.

```
$ ping 10.100.0.10
PING 10.100.0.10: 56 data bytes
64 bytes from 10.100.0.10: icmp_seq=0 ttl=64 time=184ms

$ ssh user@10.100.0.10
user@10.100.0.10's password:
```

---

## SOCKS5 Proxy

Phone → Shared node:52888 → Reality TLS → SOCKS5 (0x5350) → mesh relay (0x524C) → exit node (0x4558) → Internet

- Use any standard SOCKS5 client (no VLESS/xray needed)
- Multi-path relay with automatic failover
- Exit node controls allowed ports (default: 80, 443)
- Traffic appears as normal HTTPS to DPI

---

## Dashboard

| Page | Path | Description |
|------|------|-------------|
| Topology | `/topology` | 3D mesh topology graph, real-time node status |
| Monitor | `/` | CPU / memory / disk / load / network for all nodes |
| Config | `/config` | Edit all node settings (4-tier access control) |
| Join | `/join` | Generate one-click install command |
| Proxy | `/proxy` | SOCKS5 proxy status, entry/exit configuration |
| Nodes | `/nodes` | Node list with details and capabilities |
| Peers | `/peers` | Known peers management |
| Files | `/files` | File transfer between nodes |
| Terminal | `/terminal` | WebSSH — SSH directly from browser |
| Services | `/services` | Remote systemd service management |

---

## Monitoring

- Push-based metrics collection over the mesh (no exposed port needed)
- Auto-discovery: nodes with `CapCollector` capability are discovered via gossip
- Deduplication: `SourceID + Sequence` prevents metric loops
- Persistence: `peers.cache` saves discovered endpoints across restarts
- Identity stability: `identity.pem` keeps Ed25519 public key constant

---

## Project Stats

| Metric | Value |
|--------|-------|
| Language | Go |
| Source files | ~310 |
| Lines of Go | ~138,000 |
| Dependencies | memberlist, go-msgpack, Reality TLS library |
| Platforms | Linux (amd64, arm64) |
| License | MIT |

---

## Build & Deploy

```bash
# Build
go build -o meshdesk ./cmd/meshdesk/

# Cross-compile
GOOS=linux GOARCH=arm64 go build -o meshdesk-arm64 ./cmd/meshdesk/

# Run (needs root for TUN)
sudo meshdesk --web --config /etc/meshdesk/config.yaml

# Agent-only mode (no dashboard, no TUN)
meshdesk --config /etc/meshdesk/config.yaml
```

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Join Guide](docs/JOIN_GUIDE.md)
- [SOCKS5 Proxy Guide](docs/SOCKS5_PROXY_GUIDE.md)
- [Config Inventory](docs/CONFIG_INVENTORY.md)
- [Proxy Design](docs/PROXY_DESIGN.md)
- [Frontend](docs/FRONTEND.md)
- [Threat Model](THREAT_MODEL.md)
- [Design Decision: No Global Routing Table](docs/DESIGN_DECISION_NO_GLOBAL_ROUTING.md)
- [Relay Deployment](docs/RELAY_DEPLOYMENT.md)

## License

MIT
