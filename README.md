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

## Features

### Mesh VPN

- Decentralized P2P networking via **WireGuard** (wireguard-go + gVisor netstack)
- NAT traversal with shared relay nodes
- Automatic peer discovery
- Transport obfuscation: padded mode (AmneziaWG-style) or WebSocket mode
- Fine-grained peer capabilities — restrict what each peer can access (monitor, SSH, file transfer, service management)

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

# Generate a WireGuard keypair (prints private and public key)
meshdesk --gen-key

# Agent + Web UI (dashboard, WebSSH, file transfer, service management)
meshdesk --config /etc/meshdesk/config.yaml --web
```

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--config` | `/etc/meshdesk/config.yaml` | Path to config file |
| `--web` | `false` | Enable web UI mode (serves dashboard, WebSSH, file transfer, service management) |
| `--gen-key` | `false` | Generate a new WireGuard keypair and exit |

When `--web` is set and `node.web` is not configured, the web UI listens on `:8080`.

## Configuration

```yaml
# /etc/meshdesk/config.yaml
node:
  identity: ""           # WireGuard private key (hex); auto-generated if empty
  hostname: ""           # display name (auto-detected if empty)
  web: ":8080"           # web UI listen address; empty = agent-only mode

mesh:
  port: 51820            # WireGuard listen port

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

transfer:
  max_file_size: 1073741824   # max file size in bytes (default 1 GB, 0 = unlimited)
  upload_dir: "/tmp/meshdesk-uploads/"  # where incoming transfers are written
```

All fields are optional. Omitted fields get sensible defaults. If the config file doesn't exist at startup, the node runs with defaults and auto-generates a WireGuard identity.

## Architecture

```
┌─────────────────────────────────────────┐
│              MeshDesk Node               │
│                                          │
│  ┌──────────┐  ┌──────────┐  ┌───────┐  │
│  │   Mesh   │  │ Monitor  │  │WebSSH │  │
│  │ WireGuard│  │ Collect  │  │ Hub   │  │
│  │ + netstk│  │ + Push   │  │ (SSH  │  │
│  │          │  │          │  │ proxy)│  │
│  └────┬─────┘  └────┬─────┘  └───┬───┘  │
│       │             │            │       │
│       └──────┬──────┴────────────┘       │
│              │                           │
│  ┌───────────┴───────────────┐           │
│  │       HTTP Server          │           │
│  │  (--web only)             │           │
│  │                            │           │
│  │  • Dashboard (htmx + SSE) │           │
│  │  • WebSSH Terminal         │           │
│  │  • File Transfer UI        │           │
│  │  • Service Management UI   │           │
│  └────────────────────────────┘           │
└─────────────────────────────────────────┘
```

## License

MIT
