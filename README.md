# MeshDesk

**Decentralized server mesh network + monitoring + WebSSH — in a single binary.**

[中文文档](./README_CN.md)

---

## What is MeshDesk?

MeshDesk combines three tools into one:

1. **Mesh VPN** — P2P decentralized networking between all your servers (replaces EasyTier)
2. **Server Monitoring** — CPU, memory, disk, network, services (replaces Nezha)
3. **Web Terminal** — SSH directly from the browser, no separate client needed

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
| Network topology view | ❌ | ✅ (CLI only) | ✅ (Web UI) |

Nezha has monitoring and WebSSH but no mesh networking — if the dashboard is down, you lose everything. EasyTier has mesh VPN but no monitoring or web terminal. MeshDesk does it all in one binary.

## Architecture

```
┌──────────────────────────────────────────┐
│            Single Binary (Go)            │
│                                          │
│  ┌──────────┐   ┌─────────────────────┐  │
│  │  Agent   │   │   WebUI (--web)     │  │
│  │          │   │                     │  │
│  │ • System │   │ • Server overview   │  │
│  │   stats  │   │ • Network topology  │  │
│  │ • Cmd    │   │ • Web terminal      │  │
│  │   exec   │   │ • File transfer     │  │
│  │ • Mesh   │   │ • Service mgmt      │  │
│  │   node   │   │                     │  │
│  └────┬─────┘   └─────────┬───────────┘  │
│       │                    │              │
│       └─── mesh layer ────┘              │
│           P2P / relay auto-select         │
└──────────────────────────────────────────┘
```

- **Every node** runs the same binary as root
- **Agent mode** (default): collects metrics, accepts commands, participates in mesh
- **Web mode** (`--web`): serves the web UI on a configurable port
- **Mesh layer**: P2P direct connection when possible, relay fallback when behind NAT
- **No central server**: any node can be the panel, any node can go down without affecting others

## Features

### Mesh VPN
- Decentralized P2P networking (KCP/QUIC/TCP)
- NAT traversal with shared relay nodes
- Automatic peer discovery
- Encrypted tunnel (ChaCha20-Poly1305)
- Network topology visualization in Web UI

### Monitoring
- Real-time CPU / memory / disk / network metrics
- Process list per server
- Service status (systemd units)
- Historical charts
- Alerting (threshold-based, via webhook/Telegram)

### Web Terminal
- Browser-based terminal (xterm.js + WebSocket)
- No SSH keys or passwords needed — agent runs as root
- Multi-tab, multi-server
- Session recording (optional)

### File Management
- Upload / download files via web UI
- Drag-and-drop support
- File browser with permissions

### Service Management
- Start / stop / restart systemd services
- View service logs
- Enable / disable services

## Installation

```bash
# Install as root
curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/install.sh | bash

# Or manually:
# 1. Download the binary for your platform
# 2. Place it in /usr/local/bin/meshdesk
# 3. Create the systemd service
# 4. Start it

# Agent only (default)
meshdesk --network mynet --secret mysecret

# Agent + Web UI
meshdesk --network mynet --secret mysecret --web :8080
```

**Requires root.** The agent needs root to:
- Create TUN interface for VPN
- Execute commands for Web Terminal
- Read system metrics (disk, network, processes)
- Manage systemd services

## Configuration

```yaml
# /etc/meshdesk/config.yaml
network: mynet          # mesh network name
secret: mysecret        # shared secret for mesh auth
web: ":8080"            # web UI port (empty = no web UI)
peers:                  # bootstrap peers (shared relay nodes)
  - relay1.example.com:11010
  - relay2.example.com:11010
hostname: ""            # display name (auto-detected if empty)
tun: true               # enable TUN interface for VPN
tun_ip: ""              # auto-assigned if empty
```

## Tech Stack

- **Language:** Go (single binary, cross-platform)
- **Frontend:** React + TypeScript (embedded in binary via `embed.FS`)
- **Terminal:** xterm.js + WebSocket
- **VPN:** TUN device + ChaCha20-Poly1305
- **Transport:** KCP / QUIC / TCP (auto-negotiated)
- **Database:** SQLite (embedded, for metrics history)
- **Protocol:** gRPC / Protobuf (mesh communication)

## License

MIT
