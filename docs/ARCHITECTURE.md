# MeshDesk Architecture Design

**Version:** 1.0
**Status:** Adopted (via motion-f46363097b43, 2026-07-24)
**Team:** architect, developer, researcher, reviewer, writer, tester

---

## Overview

MeshDesk is a single Go binary that combines three tools into one:

1. **Decentralized Mesh VPN** (replaces EasyTier) — P2P encrypted networking between all servers
2. **Server Monitoring** (replaces Nezha) — CPU, memory, disk, network, process, and service metrics
3. **Web Terminal** — browser-based SSH access via WebSocket + xterm.js

Every node runs the same binary. Any node can serve the Web UI with `--web`. The binary requires root (TUN device, PTY allocation, system metrics, service management). Every architectural decision is scoped to these constraints: single binary, userspace networking, GFW resilience, production-grade security.

---

## Decision A: Mesh VPN — WireGuard + wireguard-go + gVisor Netstack

### Chosen Stack

| Layer | Component | Rationale |
|-------|-----------|-----------|
| **Cryptographic transport** | WireGuard via `golang.zx2c4.com/wireguard` (wireguard-go) | Battle-tested — same implementation as Tailscale, Headscale, Netbird. Noise_IKpsk2 handshake: authenticated encryption, PFS, replay protection, DoS resistance. |
| **Userspace TUN** | gVisor netstack (`gvisor.dev/gvisor/pkg/tcpip`) | Pure userspace — no kernel module, no `--privileged` for containers. Same pattern as Tailscale's tsnet. Eliminates the `water` library dependency (which requires kernel TUN). |
| **Obfuscation shim** | Custom pluggable transport layer *above* WireGuard | Mandatory for GFW resilience. Sits between the wireguard-go device and the network. Three modes. |

### Obfuscation Modes

The shim is per-peer configurable (LAN peers skip it, internet peers use it):

| Mode | Description | Use Case |
|------|-------------|----------|
| `none` | WireGuard packets sent directly | Trusted LAN, internal networks |
| `padded` | Per-packet random padding + timing randomization + handshake obfuscation | Default for internet peers. Based on AmneziaWG design (proven in Russia/Iran). |
| `websocket` | Wrap ciphertext in WebSocket frames over TCP | Environments where UDP is throttled/blocked |

### Evidence

- **Researcher:** WireGuard handshake is trivially fingerprintable by DPI (148-byte init, 92-byte response). Chinese GFW has been deep-inspecting UDP since ~2020. The shim is not optional — it's a hard requirement given the stop condition of "公网生产环境可用."
- **Researcher:** AmneziaWG (fork of wireguard-go) uses per-packet random padding + encrypted size metadata + timing randomization — deployed successfully in Russia and Iran where DPI is comparable to China's.
- **Reviewer:** Domain fronting is dead since 2022 (major CDNs block it). Protocol mimicry (NaiveProxy/Hysteria2) adds C++ dependencies that contradict the single-binary constraint. The padded+timing shim is the right trade-off.

### Integration Surface

```
┌──────────────────────────────────────┐
│            Mesh Routing Layer        │  ← Our code: peer discovery, routing table
├──────────────────────────────────────┤
│  wireguard-go device.Device          │  ← Encryption/decryption of IP packets
├──────────────────────────────────────┤
│  gVisor netstack (userspace TUN)     │  ← Packet processing, no kernel module
├──────────────────────────────────────┤
│  Obfuscation Shim                    │  ← Per-peer transform before network I/O
├──────────────────────────────────────┤
│  UDP / WebSocket socket              │  ← Actual network transmission
└──────────────────────────────────────┘
```

- `device.Device` reads/writes to the gVisor netstack endpoint
- Each peer maps to a `device.Peer` with its own WireGuard keypair
- The mesh routing layer decides which peer to send a packet to; WireGuard handles encryption transparently

---

## Decision B: Monitoring — Push-Gossip with Collector Subset

### Topology

```
                          ┌──────────────┐
                          │  Collector A  │  ← --web node (receives metrics)
                          │  (--web)      │
                          └──────┬───────┘
                                 │ push
              ┌──────────────────┼──────────────────┐
              │ push             │ push             │ push
         ┌────┴────┐       ┌────┴────┐       ┌────┴────┐
         │ Node 1  │       │ Node 2  │       │ Node 3  │
         │ (agent) │       │ (agent) │       │ (agent) │
         └─────────┘       └─────────┘       └─────────┘
```

### Design

| Aspect | Decision |
|--------|----------|
| **Collection** | Each node collects its own metrics locally (CPU, memory, disk, network, custom health checks) at configurable interval (default: 15s) |
| **Distribution** | Push to a small, configurable set of collector nodes (--web nodes + 1-2 designated aggregators for redundancy). O(N×C) where C is collector count (typically 1-3). |
| **Discovery** | Gossip protocol used ONLY for discovering which nodes are collectors — not for shipping metrics data |
| **Storage** | Local ring buffer per node: 1-minute resolution for 24h, 5-minute resolution for 7 days |
| **Dashboard** | --web node reads from its local replica. No on-demand pull across the mesh needed. |

### Rationale

- **Reviewer:** Gossip-everywhere (researcher's original proposal) is O(N²) — 100 nodes = 9,900 push streams. Single elected aggregator (architect's original proposal) is a SPOF. Push-to-subset with collector discovery via gossip is the correct middle ground.
- **Developer:** Push is more resilient than pull in a mesh with NAT traversal — nodes may not be directly reachable for scraping. Metrics arrive when the peer is healthy; the collector always has recent data.
- **Nezha precedent:** Nezha uses a push model (agent → dashboard). Adapting it to a mesh means the dashboard moves to whichever node has `--web`.

### Acceptance Criteria
- [ ] Monitoring data reaches the collector within 2× the push interval under normal network conditions
- [ ] When the collector node goes down, agents buffer locally and re-target when a new collector is discovered
- [ ] Collector failover completes within 30 seconds of detection
- [ ] Historical data preserved from local ring buffer during collector absence

---

## Decision C: WebSSH Bridge — WebSocket + xterm.js + creack/pty + x/crypto/ssh

### Architecture

```
Browser                    Web Server Node               Target Node
┌──────────┐              ┌────────────────┐            ┌──────────────┐
│ xterm.js │──WebSocket──│  WebSocket Hub  │──SSH over──│  SSH Server   │
│  (+addons)│             │  (goroutine-    │  mesh VPN │  (x/crypto/ssh)│
│          │              │   per-session)  │           │       │       │
└──────────┘              └────────────────┘           │  creack/pty   │
                                                       │       │       │
                                                       │   /bin/bash   │
                                                       └───────────────┘
```

### Components

| Component | Library | Purpose |
|-----------|---------|---------|
| Frontend terminal | xterm.js + addons (fit, web-links, search) | Browser-based terminal emulator |
| Transport | WebSocket (gorilla/websocket or nhooyr.io/websocket) | Bidirectional streaming between browser and server |
| PTY allocation | `github.com/creack/pty` | Allocate pseudo-terminal on target node |
| SSH client | `golang.org/x/crypto/ssh` | Connect from web server to target node over mesh VPN |
| SSH server | `golang.org/x/crypto/ssh` | Accept connections on target node (mesh IP only) |

### Flow

1. Browser opens WebSocket to web server node's `/ws/terminal?node=<peer-id>`
2. Web server resolves peer-id to mesh IP via routing table
3. Web server opens SSH connection to target node over the mesh VPN (gVisor netstack)
4. Web server allocates a PTY on the target, bridges WebSocket ↔ SSH channel ↔ PTY
5. One goroutine per session — no tmux-style multiplexing needed for v1
6. On WebSocket disconnect: SIGHUP → close PTY → close SSH channel (automatic cleanup)

### UX Requirements (from Writer)

- **Connection state visibility:** Status bar showing "connected to node-3 via mesh" that turns red on disconnect — not a silent frozen terminal
- **Clipboard integration:** xterm.js `navigator.clipboard` APIs + visible paste button for browsers with inconsistent clipboard permissions
- **SIGWINCH propagation:** Browser window resize event → WebSocket → SSH channel → remote PTY. Without this, `vim`, `htop`, and `less` render broken layouts.

### Test Requirements (from Tester)

1. **PTY leak test:** Open 100 concurrent sessions, kill them all with TCP RST (browser-tab-close equivalent), verify zero zombie PTYs via `lsof`
2. **SIGWINCH propagation test:** Open vim, resize browser window 50× rapidly, verify `stty size` matches
3. **Network partition recovery:** Yank mesh link via `iptables DROP`, wait 30s, restore, verify clean reconnect or unambiguous "connection lost" status
4. **Key rotation during active session:** Rotate target SSH host key mid-session, verify connection fails closed (terminates, does not silently accept new key)

### Acceptance Criteria
- [ ] PTY leak test passes (zero zombie PTYs after 100 concurrent abrupt disconnects)
- [ ] SIGWINCH propagates correctly within 500ms of browser resize
- [ ] Terminal renders correctly at 80×24, 120×40, and 200×60 dimensions
- [ ] Connection state indicator updates within 2 seconds of network state change

---

## Decision D: Frontend — Go Templates + htmx + Embedded Assets

### Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| **Server-side rendering** | Go `html/template` | No JS build pipeline, templates compiled into binary |
| **Interactivity** | htmx (≈14KB) | Navigation, form submissions, partial page updates without SPA complexity |
| **Live data** | Server-Sent Events (SSE) for dashboard, WebSocket for terminal | Dashboard live metrics push via `/api/events` SSE stream. Terminal uses the WebSocket hub built for WebSSH. |
| **CSS framework** | Pico.css (≈25KB, class-light) | Professional look, no build step, semantic HTML |
| **Terminal** | xterm.js + addons (≈500KB gzipped) | De facto standard for browser terminals |
| **Asset embedding** | Go `embed.FS` | All static assets (CSS, JS, images) compiled into the binary at build time |

### Dashboard Architecture

```
┌─────────────────────────────────────────────┐
│  Go Template (server-rendered shell)         │
│  ├── Navigation (htmx: page swaps)           │
│  ├── Node List (htmx: partial refresh)       │
│  ├── Charts / Metrics (SSE: live data)       │
│  ├── Terminal Pane (xterm.js + WebSocket)    │
│  └── File Manager (htmx: upload/download)    │
└─────────────────────────────────────────────┘
```

### What We Avoid

- **No npm, no webpack, no node_modules** — everything is embedded in the binary
- **No SPA framework** (React/Vue/Svelte) — contradicts the single-binary constraint
- **No CDN dependencies** — the binary is self-contained, works offline

### Writer's Constraint

htmx alone won't give us real-time monitoring — the dashboard needs an SSE stream for live metrics push. The WebSocket hub from the WebSSH subsystem is reused for the terminal, while SSE handles dashboard updates independently.

### Acceptance Criteria
- [ ] Binary contains all frontend assets (zero external HTTP requests at runtime)
- [ ] Dashboard loads and renders within 2 seconds on first visit
- [ ] Live metrics update via SSE within 1 second of arrival
- [ ] Terminal pane opens within 1 second of user clicking "Connect"

---

## Decision E: Security Model — Capability-Scoped Peer Authorization (Default-Deny)

### Core Principle

WireGuard provides network-layer encryption and peer identity. We layer authorization on top. **Mesh membership ≠ trust.** Each service access requires explicit, revocable authorization.

### Model

```
┌────────────────────────────────────────────────────┐
│                   WireGuard Layer                  │
│  Peer identity = WireGuard public key              │
│  Encryption = Noise_IKpsk2 (always on)             │
│  Mesh admission = config.yaml peer list + PSK      │
├────────────────────────────────────────────────────┤
│              Capability Authorization Layer        │
│  Per-peer whitelist in config.yaml                 │
│  Capabilities: ssh_proxy, file_transfer,           │
│    monitor_read, monitor_write, service_manage     │
│  Optional service-name scoping:                    │
│    service_manage: [nginx, meshdesk]               │
├────────────────────────────────────────────────────┤
│                   Service Handlers                 │
│  WebSSH, File Transfer, Monitoring, Service Mgmt   │
│  Each handler receives pre-authorized requests     │
│  only — unauthorized requests dropped at auth layer│
└────────────────────────────────────────────────────┘
```

### Authorization Flow

1. Request arrives over the mesh (WebSSH proxy, file transfer, monitoring push, service command)
2. Receiving node inspects source WireGuard peer identity (public key)
3. Checks local `config.yaml` capability whitelist for that peer
4. Unauthorized → dropped before touching any service handler (early rejection)
5. Authorized → forwarded to service handler

### Web UI Auth

- Web server node manages its own local user accounts: bcrypt-hashed credentials, session cookies
- When a web UI user requests action on a remote node (e.g., "SSH into node-03"):
  1. Is this user authenticated? (session check)
  2. Does the web server node's own config authorize it to proxy SSH to node-03? (capability check)
- Both must pass. The web server node is a trusted proxy — it needs explicit capability grants from every node it can act on.

### Default Configuration

**Zero-trust.** A fresh node accepts no incoming service requests from any peer until the admin explicitly grants capabilities. WireGuard connectivity (ping, handshake) is always allowed; everything above that requires explicit authorization.

### Capabilities

| Capability | Scope | Description |
|------------|-------|-------------|
| `ssh_proxy` | Per peer | Allow this peer to proxy SSH sessions to this node |
| `file_transfer` | Per peer (bidirectional v1) | Allow push and pull of files |
| `monitor_read` | Per peer | Allow this peer to read monitoring data |
| `monitor_write` | Per peer | Allow this peer to push monitoring data (for aggregator relationships) |
| `service_manage` | Per peer, per service name | Allow start/stop/restart of named services |

### Hardening Requirements (from Reviewer)

#### 1. Key Revocation

`meshdesk revoke <peer-id>` must:
- Remove the peer's key from local WireGuard config
- Drop all active connections to that peer
- Gossip a signed revocation notice to all other mesh nodes
- Revocation notice must be signed with the revoking node's WireGuard key (prevent malicious revocation)

#### 2. Audit Logging

Every cross-node service request must produce a structured log entry:
```
{
  "timestamp": "ISO8601",
  "source_peer": "<WireGuard public key>",
  "requested_capability": "ssh_proxy",
  "target_resource": "node-03:/bin/bash",
  "result": "allow" | "deny",
  "reason": "explicit_allow" | "no_capability" | "revoked"
}
```

#### 3. Binary Upgrade Confirmation Challenge

- `service_manage` capability authorizes stop/start/restart of named services
- Binary upgrades (uploading and executing a new binary) require additional confirmation:
  1. Requesting node sends upgrade request
  2. Target node responds with a cryptographic nonce
  3. Requesting node signs the nonce with its service key
  4. Target verifies signature before accepting the binary
- This prevents a compromised but authorized node from pushing a backdoored binary to every peer in one sweep

### Test Requirements (from Tester)

**Capability enforcement test suite:** Stand up a 3-node mesh with distinct capability profiles:
- Node-A: web server, SSH to all
- Node-B: monitoring only, no SSH
- Node-C: file transfer only, no SSH, no monitoring access

Automated probe:
1. Node-B attempting SSH to Node-A → rejected at SSH auth layer (early rejection)
2. Node-C attempting to pull monitoring data from Node-A → rejected
3. Node-A WebSSH proxy to Node-B → succeeds (authorized)
4. Each rejection produces an auditable log entry with timestamp, source IP, attempted service, reason

### Acceptance Criteria
- [ ] Default config denies all service requests (zero-trust)
- [ ] Capability enforcement test suite passes on 3-node mesh
- [ ] Audit log contains structured entries for every denied request
- [ ] Key revocation propagates to all mesh nodes within 30 seconds
- [ ] Binary upgrade without nonce signature is rejected
- [ ] Compromised node can only access services on peers that explicitly authorized it

---

## Decision F: Package Structure

### Tree

```
meshdesk/
├── cmd/meshdesk/main.go          — Single entrypoint, --web flag routing
├── internal/
│   ├── mesh/                     — WireGuard integration, gVisor netstack, peer discovery, routing table
│   ├── monitor/                  — Metric collection, push reporter, ring buffer, optional aggregator
│   ├── webssh/                   — PTY allocation, WebSocket handler, remote node SSH proxy
│   ├── transfer/                 — File transfer protocol (4-byte header + JSON metadata + raw bytes)
│   ├── service/                  — ServiceManager interface (systemd backend via D-Bus)
│   ├── web/                      — HTTP server, API routes, auth middleware, WebSocket hub (integration layer)
│   ├── auth/                     — Capability whitelist engine, audit logger, revocation protocol, nonce challenge
│   └── config/                   — Unified config struct, YAML load/save, capability parsing
├── web/                          — go:embed target (no Go code, assets only)
│   ├── static/                   — css/ (Pico.css), js/ (htmx, xterm.js), img/
│   └── templates/                — Go html/template files
├── docs/
│   └── ARCHITECTURE.md           — This document
├── go.mod / go.sum
├── Makefile
├── README.md
└── README_CN.md
```

### Design Rules

1. `internal/` enforces Go's compiler-level visibility — no external project can import our packages. Correct for a binary, not a library.
2. No `pkg/` directory — we're a single binary, not a library.
3. `internal/web/` is the integration layer: it imports from mesh, monitor, webssh, transfer, service, and auth to wire the HTTP API.
4. `web/` sits outside `internal/` because `go:embed` patterns are cleaner with a top-level directory. Contains no Go code — just assets consumed at build time.
5. `cmd/meshdesk/main.go` is the sole entrypoint. Without `--web`, the node runs in agent-only mode (mesh transport + monitoring reporter).

### Key Interfaces

```go
// internal/mesh: Node identity and routing
type MeshNode interface {
    Identity() peer.Identity          // WireGuard public key
    RoutingTable() []peer.Route       // known peers + mesh IPs
    Dial(ctx context.Context, peerID string) (net.Conn, error)  // mesh-internal connection
}

// internal/monitor: Metric collection and reporting
type Collector interface {
    Collect() (*Metrics, error)
    Push(ctx context.Context, target peer.Identity) error
}

// internal/webssh: Terminal session management
type TerminalSession interface {
    Start(ctx context.Context, peerID string, cols, rows int) error
    Resize(cols, rows int) error
    Read(p []byte) (n int, err error)
    Write(p []byte) (n int, err error)
    Close() error
}

// internal/auth: Capability authorization
type CapabilityEngine interface {
    Authorize(source peer.Identity, capability string, resource string) (bool, error)
    Revoke(target peer.Identity) error
    AuditLog() <-chan AuditEntry
}

// internal/service: Service management
type ServiceManager interface {
    Start(name string) error
    Stop(name string) error
    Restart(name string) error
    Status(name string) (*ServiceStatus, error)
    Logs(name string, follow bool) (io.ReadCloser, error)
    List() ([]ServiceStatus, error)
}
```

---

## Cross-Cutting Concerns

### Data Flow: Web UI Request to Remote Node

```
Browser ──HTTPS──▶ Web Server Node ──mesh TCP──▶ Target Node
                      │                              │
                  1. Session check              4. Capability check
                  2. Resolve peer ID            5. Service handler
                  3. Capability check           6. Response
                     (can I proxy to target?)
```

### Data Flow: Monitoring

```
Agent Node                    Collector Node (--web)          Browser
    │                              │                            │
    ├─ Collect() @ 15s interval    │                            │
    ├─ Push() to collector ──────▶ │ Store in ring buffer       │
    │                              ├─ SSE push ───────────────▶ │ Live update
    │                              │                            │
    │                              ├─ HTTP API ───────────────▶ │ Historical query
```

### Binary Distribution

- Single statically-linked Go binary (CGO_ENABLED=0)
- All assets (templates, CSS, JS, images) compiled in via `go:embed`
- No runtime dependencies beyond a Linux kernel
- Requires root for: TUN device (gVisor netstack avoids kernel module), PTY allocation, system metrics, service management

### Configuration

```yaml
# /etc/meshdesk/config.yaml
node:
  identity: ""                # auto-generated WireGuard keypair on first run
  hostname: ""                # auto-detected if empty
  web: ":8080"                # empty = agent-only mode

mesh:
  port: 51820                 # WireGuard listen port

peers:
  - public_key: "..."         # bootstrap peer
    endpoint: "1.2.3.4:51820"
    capabilities: []          # what this peer can do on US (default: empty = zero-trust)
    obfuscation: padded       # none | padded | websocket

monitoring:
  collectors: []              # peer IDs of collector nodes (empty = no reporting)
  interval: 15                # seconds

auth:
  web_users:                  # only relevant on --web nodes
    - username: admin
      password_hash: "$2b$..."
```

---

## Decision Log

| Decision | Outcome | Rationale |
|----------|---------|-----------|
| A: Mesh VPN | WireGuard + wireguard-go + gVisor netstack | Battle-tested crypto, userspace only, Tailscale-proven pattern |
| A: Obfuscation | Pluggable shim (none/padded/websocket), per-peer | Mandatory for GFW; AmneziaWG pattern proven in Russia/Iran |
| B: Monitoring | Push to collector subset, gossip for discovery | O(N×C) scaling, resilient to NAT, Nezha-proven push model |
| C: WebSSH | WebSocket + xterm.js + creack/pty + x/crypto/ssh | Goroutine-per-session, mesh-internal SSH, no external client |
| D: Frontend | Go templates + htmx + Pico.css + embedded assets | No JS build pipeline, single binary, professional look |
| D: Live data | SSE for dashboard metrics, WebSocket for terminal | Dual transport: EventSource for metrics stream, WebSocket hub for terminal sessions |
| E: Security | Capability-scoped peer authorization, default-deny | Zero-trust, lateral movement containment, defense in depth |
| E: Revocation | `meshdesk revoke <peer-id>` with signed gossip | Manual for v1, automated rotation v2 |
| E: Audit | Structured JSON log for every cross-node request | Breach investigation trail, tester's executable security spec |
| E: Binary upgrade | Nonce-sign confirmation challenge | Prevents backdoor propagation from compromised authorized node |
| F: Package structure | `cmd/` entrypoint, `internal/` subsystems, `web/` assets | Compiler-enforced visibility, no `pkg/`, single binary |

---

## Anti-Goals (What We Explicitly Chose NOT to Build)

- **No custom crypto protocol.** WireGuard is the only defensible choice for production-grade mesh security.
- **No SPA framework.** React/Vue/Svelte add build complexity that contradicts the single-binary promise.
- **No pull-based monitoring.** Prometheus-style scraping fails in NAT-traversed meshes where nodes aren't directly reachable.
- **No blanket mesh trust.** "If you're in the mesh, you're trusted" is a lateral-movement dream. Capability-scoped authorization from day one.
- **No kernel module dependency.** gVisor netstack avoids the `wireguard` kernel module and container `--privileged` requirements.
- **No domain fronting.** Dead since 2022 — major CDNs actively block it.
- **No protocol mimicry.** NaiveProxy/Hysteria2 complexity (C++ dependencies) contradicts the single-binary constraint.

---

## Next Steps

This document reflects the team's consensus from motion-f46363097b43. The following implementation tasks are spawned as kanban cards:

1. `t_2f9210a5` — Implement WireGuard + gVisor netstack integration (developer)
2. `t_8591e271` — Implement obfuscation shim (developer)
3. Remaining tasks: monitoring push-gossip, WebSSH bridge, frontend scaffolding, auth/capability engine, service management

Each subsystem must be implemented against the interfaces defined in Decision F. Acceptance criteria from each decision section are binding — they constitute the definition of done.