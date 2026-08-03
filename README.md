# MeshDesk

**Decentralized server mesh network + monitoring + WebSSH + SOCKS5 proxy — in a single binary.**

[中文文档](./README_CN.md)

---

## What is MeshDesk?

MeshDesk combines five tools into one:

1. **Mesh VPN** — P2P decentralized networking between all your servers (no EasyTier needed)
2. **Server Monitoring** — CPU, memory, disk, network, services (no Nezha needed)
3. **Web Terminal** — SSH directly from the browser
4. **SOCKS5 Proxy** — Reality TLS + smux relay to exit nodes, standard SOCKS5 client
5. **Dashboard** — Full node management, one-click join, config editing, proxy control

Every node runs the same binary. Any node can become the control panel with `--web`.

### Why not just use Nezha + EasyTier?

| | Nezha | EasyTier | MeshDesk |
|---|---|---|---|
| Server monitoring | ✅ | ❌ | ✅ |
| Mesh VPN | ❌ | ✅ | ✅ |
| WebSSH | ✅ (via agent) | ❌ | ✅ |
| Single binary | ❌ (dashboard + agent) | ✅ | ✅ |
| One-click join | ❌ | ❌ | ✅ |
| Dashboard config | ❌ | ❌ | ✅ |
| SOCKS5 proxy | ❌ | ❌ | ✅ |

## Quick Start

### Shared Node (has public port)

```bash
# Generate identity and reality keys
meshdesk gen-identity > /etc/meshdesk/identity.pem
meshdesk gen-reality > keys.txt

# Config
cat > /etc/meshdesk/config.yaml << 'EOF'
node:
  hostname: "my-node"
  web: ":8080"
  identity_file: "/etc/meshdesk/identity.pem"
mesh:
  port: 52888
  gossip_port: 52888
p2p:
  enabled: true
  advertise_endpoints:
    - "YOUR_PUBLIC_IP:52888"
  gossip_probe_interval: 5
reality:
  enabled: true
  listen_addr: "0.0.0.0"
  listen_port: 52888
  dest: "www.apple.com:443"
  server_names: ["www.apple.com"]
  private_key: "YOUR_REALITY_PRIVATE_KEY"
  short_ids: ["aabbccdd"]
monitoring:
  interval: 15
  port: 4191
auth:
  web_users:
    - username: admin
      password_hash: "$2b$10$..."  # bcrypt
EOF

# Run
meshdesk --web --config /etc/meshdesk/config.yaml
```

### Ordinary Node (no exposed ports)

Just point the seed at a shared node:

```yaml
p2p:
  enabled: true
  seeds:
    - "SHARED_NODE_IP:52888"
  gossip_probe_interval: 5
reality:
  enabled: false
```

### One-Click Join (from Dashboard)

1. Open Dashboard → **Join** page
2. Click "Generate Install Command"
3. Copy the command, SSH to the new machine, paste and run:

```bash
curl -sSL http://dashboard:8080/join?token=xxx | sudo sh
```

The new node auto-downloads the binary, generates identity, writes config, and joins the cluster.

## Architecture

### Protocol Stack

```
┌─────────────────────────────────────────────┐
│ Layer 4 — MeshNode                          │
│   Wires everything together: gossip,        │
│   WebSSH, file transfer, SOCKS5, proxy      │
├─────────────────────────────────────────────┤
│ Layer 3 — smux Multiplexer                  │
│   Stream multiplexing over a single conn.   │
│   WebSSH, file transfer, RPC, SOCKS5, and   │
│   proxy traffic share one encrypted link    │
├─────────────────────────────────────────────┤
│ Layer 2b — AES-256-GCM Encryption           │
│   Session-key encryption of all traffic.    │
├─────────────────────────────────────────────┤
│ Layer 2a — X25519 ECDH Key Exchange         │
│   Ephemeral key exchange + Ed25519 signing. │
├─────────────────────────────────────────────┤
│ Layer 1 — Reality TLS Handshake             │
│   REALITY TLS hijack on port 52888.         │
│   Indistinguishable from HTTPS traffic.     │
├─────────────────────────────────────────────┤
│ Layer 0 — Ed25519 Identity                 │
│   Permanent node identity (PEM file).       │
└─────────────────────────────────────────────┘
```

### MuxTransport — Single Port Multiplexing

Port 52888 handles all protocols via first-byte sniffing:

| First Byte | Protocol | Virtual Port | Description |
|------------|----------|-------------|-------------|
| 0x16 | Reality TLS | — | TLS ClientHello, encrypted mesh traffic |
| 0x4D | mesh-internal | — | smux session establishment |
| 0x53 | SOCKS5 entry | 0x5350 | Phone/client SOCKS5 proxy entry |
| 0x45 | SOCKS5 exit | 0x4558 | Exit node handler for SOCKS5 |
| 0x52 | smux relay | 0x524C | Stream relay for cross-network routing |
| other | gossip | — | memberlist TCP push/pull sync |

UDP 52888 handles gossip ping/pong and anti-entropy.

### Node Types

- **Shared node** (`reality.enabled: true`): listens on 52888 TCP+UDP, Reality TLS + MuxTransport. The only node type that exposes a public port.
- **Ordinary node** (`reality.enabled: false`): no TCP listener, UDP-only gossip. Connects outbound to shared nodes. Never exposes a port.

### Monitoring Auto-Routing

- Dashboard nodes broadcast `CapCollector` via gossip NodeMeta
- Other nodes auto-discover collectors and push metrics
- Aggregators forward metrics to each other (`Forwarded` flag + `SourceID+Sequence` dedup prevents loops)
- `peers.cache` persists discovered endpoints + collector info across restarts
- `identity.pem` persists Ed25519 identity (public key stable across restarts)

## Dashboard

| Page | Path | Description |
|------|------|-------------|
| Topology | `/topology` | 3D mesh topology, node status |
| Monitor | `/` | CPU/memory/load for all nodes |
| Config | `/config` | Edit all node settings (4-tier access) |
| Join | `/join` | Generate one-click install command |
| Proxy | `/proxy` | SOCKS5 proxy status, entry/exit config |
| Nodes | `/nodes` | Node list with details |
| Peers | `/peers` | Known peers management |
| Files | `/files` | File transfer |
| Terminal | `/terminal` | WebSSH |
| Services | `/services` | Remote service management |

## SOCKS5 Proxy

Phone → Shared node:52888 → Reality TLS → SOCKS5 (0x5350) → mesh relay (0x524C) → exit node (0x4558) → Internet

- Use any standard SOCKS5 client (no VLESS/xray needed)
- Multi-path relay with automatic failover
- Exit node controls allowed ports (default: 80, 443)

## Build

```bash
# AMD64
go build -o meshdesk ./cmd/meshdesk/

# ARM64
GOOS=linux GOARCH=arm64 go build -o meshdesk-arm64 ./cmd/meshdesk/
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Release Notes](docs/RELEASE_NOTES.md)
- [Join Guide](docs/JOIN_GUIDE.md)
- [SOCKS5 Proxy Guide](docs/SOCKS5_PROXY_GUIDE.md)
- [Config Inventory](docs/CONFIG_INVENTORY.md)
- [Proxy Design](docs/PROXY_DESIGN.md)
- [Frontend](docs/FRONTEND.md)
- [Threat Model](THREAT_MODEL.md)

## License

MIT
