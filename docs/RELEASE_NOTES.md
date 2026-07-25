# MeshDesk v1.0.0 — Production Release

**Release date: 2026-07-26**

MeshDesk v1.0.0 is the first production release. It combines mesh VPN, server monitoring, web terminal, file transfer, service management, multi-path anonymous proxy, dashboard security (TOTP 2FA), and 3D topology visualization into a single binary.

## Major Features

### Mesh VPN & P2P Dynamic Networking

- **WireGuard mesh** via wireguard-go + gVisor netstack — every node gets a mesh IP derived from its public key
- **Gossip discovery** (hashicorp/memberlist) — automatic peer discovery with epidemic-style propagation; no manual peer config needed
- **NAT traversal** — STUN-based public endpoint discovery + UDP hole-punching with automatic relay fallback through mesh peers
- **Dynamic join protocol** — `meshdesk join <bootstrap-addr>` subcommand; bootstrap authenticates via authorized_keys, then gossips the new member to the cluster
- **Transport obfuscation** — AmneziaWG-style padded mode (H1-H4 headers, S1-S4 padding, junk train, anti-probe PSK) or WebSocket+TLS mode with uTLS fingerprint mimicry (Chrome, Firefox, Safari, Edge, iOS, Android)
- **Fine-grained peer capabilities** — per-peer capability scoping for monitor, SSH, file transfer, and service management

### Monitoring

- Real-time CPU / memory / disk / network / load average metrics
- Metric push to collector nodes with configurable interval
- Ring buffer storage per node (survives collector outages)
- Live dashboard updates via Server-Sent Events (SSE)
- Process list per server

### Web Terminal

- Browser-based terminal (xterm.js + WebSocket)
- Agent runs as root — no SSH keys or passwords needed
- Multi-tab, multi-server terminal sessions
- SIGWINCH resize support, clipboard integration, status bar

### File Transfer

- Upload / download files via web UI
- Mesh-internal transfers (files route through VPN, not exposed to internet)
- Capability-based access control with per-path restrictions

### Service Management

- Start / stop / restart systemd services
- View service logs
- Per-peer authorization via `service_manage` capability

### Multi-path Anonymous Proxy

- **Shadowsocks entry** — SS AEAD (chacha20-ietf-poly1305) over WebSocket
- **Cloudflare Tunnel camouflage** — entry listener exposed via `cloudflared`, appears as HTTPS traffic
- **ECDH circuit setup** — per-connection end-to-end encryption between entry and exit
- **Two disjoint relay paths** — traffic split across node-disjoint paths to disperse traffic
- **Blind relay forwarding** — onion-style headers; relays never decrypt payload
- **Anti-timing-analysis jitter** — 5-50ms random forwarding delay per chunk
- **Pluggable chunker** — fixed 16KB or bounded random 4KB-64KB with padding
- **Exit reassembly** — sliding window with out-of-order, dedup, NACK retransmission, orphan cleanup
- **Dynamic path selection** — RTT-based Dijkstra k-shortest path selection
- **Audit logging** — circuit→destination mappings (no payload data)

### Dashboard Security

- **TOTP 2FA** (RFC 6238) — QR code enrollment, 6-digit codes, ±1 window tolerance
- **Encrypted secret storage** — AES-256-GCM with node-local master key
- **Step-up authentication** — terminal, service management, file upload, settings require recent 2FA
- **Security alerting** — real-time alerts for auth denials, node joins/leaves, suspicious proxy activity
- **Webhook dispatch** — async alert delivery to external endpoints with 3-retry exponential backoff
- **TOTP key rotation** — zero-downtime rotation with old-key grace period
- **Recovery codes** — 10 single-use codes
- **Lockout protection** — 5 failed attempts → 30-second lockout

### 3D Topology Visualization

- Three.js 3D scene with force-directed node layout
- Animated particles flowing along proxy circuit paths
- Real-time SSE topology updates
- Color-coded nodes by role (entry, relay, exit, dashboard)
- OrbitControls for pan/zoom/rotate
- Performance-adaptive particle reduction
- Mock-data fallback for standalone testing

## CLI

```
meshdesk --config /etc/meshdesk/config.yaml --web          # agent + dashboard
meshdesk --config /etc/meshdesk/config.yaml --relay        # agent + relay mode
meshdesk --gen-key                                          # generate WireGuard keypair
meshdesk join <bootstrap-addr> --bootstrap-key <hex>        # join existing mesh
```

## Build

```bash
git clone https://github.com/yzy806806/meshdesk.git
cd meshdesk
go build -o meshdesk ./cmd/meshdesk/
```

## Testing

All packages pass `go test ./...` and `go vet ./...` is clean. The test suite includes:

- Chunker/Reassembler boundary tests (18 cases)
- Circuit manager lifecycle tests
- Exit node reassembly stress tests
- NAT traversal state machine tests
- Gossip discovery integration tests
- Dynamic join protocol tests
- TOTP 2FA integration tests
- Security alerting tests
- Webhook dispatcher tests
- Topology handler tests
- Integration harness (3-node cluster test)

## License

MIT
