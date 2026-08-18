# MeshDesk

**Decentralized server mesh — VPN + monitoring + WebSSH + SOCKS5 proxy + TUN virtual network, in a single Go binary.**

[中文文档](./README_CN.md) | [Release Notes](docs/RELEASE_NOTES.md) | [Dependency Tree](docs/DEPENDENCY_TREE.md)

> **Current release: v1.7.4** — multi-path relay routing (Dijkstra path planning via shared nodes), MESHDESK_DEBUG log fix, STUN MappedEP fix, smux goroutine leak fix, config 12 lines, memberlist retired.

---

## Why MeshDesk?

If you manage multiple servers, you probably run Nezha for monitoring, EasyTier or WireGuard for networking, and maybe a proxy tool for circumventing firewalls. That's three or more processes, three configs, three things to update.

MeshDesk does all of it in one binary:

| Feature | Nezha | EasyTier | WireGuard | MeshDesk |
|---------|:-----:|:--------:|:---------:|:--------:|
| Server monitoring | ✅ | — | — | ✅ |
| Mesh VPN / TUN | — | ✅ | ✅ | ✅ |
| **NAT hole punching** | — | ✅ | — | ✅ |
| WebSSH | ✅ | — | — | ✅ |
| SOCKS5 proxy | — | — | — | ✅ |
| One-click join | — | — | — | ✅ |
| Anti-DPI (Reality TLS) | — | — | — | ✅ |
| Single binary | — | ✅ | — | ✅ |
| Dashboard config | — | — | — | ✅ |

### Key Design Choices

- **Reality TLS** — All mesh traffic is disguised as HTTPS to a real website (e.g. `www.apple.com:443`). DPI cannot distinguish it from legitimate traffic. No WireGuard, no KCP, no recognizable UDP patterns.
- **Single port** — All mesh traffic runs on one TCP+UDP port (default 52888). MuxTransport sniffs the first byte to route Reality TLS, mesh-internal smux, SOCKS5, and memberlist gossip. The Dashboard is deliberately NOT served on this port (anti-fingerprinting): HTTP probes hitting the mesh port are proxied to the Reality camouflage site. The Dashboard listens on the dedicated web port (`node.web`, default `:8080`).
- **Standalone hole-punching engine** (`internal/holepunch`, v1.6) — memberlist-independent, EasyTier-parity:
  - Coordination over a dedicated virtual port (`0x504A`) through existing smux/relay sessions — no central punch server needed
  - UDP two-way punching with nonce-verified holes (v4 + v6)
  - TCP punching with conntrack source-port exchange + sustained SYN (stateful security groups pass ESTABLISHED)
  - **Symmetric NAT port prediction** (NAT4E): STUN third-probe detects predictable mapped-port increments; the cone side fires a 50-port window scan (birthday-attack, EasyTier-style)
  - Fragmented UDP ARQ frames (<60B) survive links that drop large datagrams; stream isolation (`|in`/`|out`) keeps two-way key exchanges clean
  - **Adaptive RTO** (RFC 6298 SRTT/RTTVAR) keeps retransmits honest on jittery WAN links — no retransmit storms, stable sessions across idle periods
  - Holes feed straight into the TUN UDP multipath; relay fallback stays as the safety net
  - **Verified production-stable** (v1.6.3): txcloud↔Oracle both directions 0% loss @ ~270ms, 100+ minutes idle without session loss
- **Port strategy split** (v1.6.3): ordinary nodes (NAT-traversed, no public inbound) bind UDP on **random distinct ports** per family (`UDPPort=-1`) — this dodges a Go runtime bug where a socket sharing its port with the TCP listener or the other family silently fails public sends. Shared nodes keep **single-port multiplexing** (one `[::]` dual-stack socket on the mesh port) — one firewall rule, Reality disguise preserved. Punch coordination exchanges the real ports, so no fixed UDP port is needed.
- **Zero third-party TUN** — The TUN device is created via raw `/dev/net/tun` syscalls (~150 lines). No wireguard-go, no gVisor, no external dependencies.
- **Deterministic IPAM** — Virtual IP = `cidr_base + (pubkey_hash % host_count)`. No DHCP server, no coordination, zero conflicts.
- **Reactive Relay Fallback** — When nodes cannot establish a direct connection (or the link drops large UDP), the per-pair state machine automatically falls back through gossip-advertised relay candidates sorted by RTT. The working relay path is cached (60s) so monitor ticks don't re-scan (v1.6 CPU fix). See [design decision](docs/DESIGN_DECISION_NO_GLOBAL_ROUTING.md).
- **Self-evolving** — Built with the Agora multi-agent framework. AI teams implement features, write tests, review code, and deploy autonomously.

---

## Quick Start

### 1. Build

```bash
go build -trimpath -ldflags "-s -w" -o meshdesk ./cmd/meshdesk
```

### 2. Shared node (public, accepts inbound, `reality.enabled: true`)

```yaml
# /etc/meshdesk/config.yaml
p2p:
    enabled: true
    advertise_endpoints:
        - 1.2.3.4:52888          # public IPv4
        - '[2409:...]:52888'      # public IPv6 (optional)
mesh:
    port: 52888
reality:
    enabled: true
    listen_port: 52888
    dest: www.microsoft.com:443
    server_names: [www.microsoft.com]
    private_key: <generated>
```

### 3. Ordinary node (outbound only, `reality.enabled: false`)

```yaml
p2p:
    enabled: true
    seeds:
        - 1.2.3.4:52888
    advertise_endpoints:          # helps hole punching
        - 6.7.8.9:52888
peers:
    - public_key: <shared-node-pubkey>
      endpoint: 1.2.3.4:52888
      zone: cn
      reality:
        server_name: www.microsoft.com
        public_key: <shared-node-reality-pubkey>
        short_id: 0123456789abcdef
        tls_fingerprint: chrome
mesh:
    port: 52888
    virtual_ip: 10.100.0.3
```

### 4. Run

```bash
sudo ./meshdesk --web --config /etc/meshdesk/config.yaml
# dashboard: http://localhost:8080  (node.web port — NOT the mesh port)
```

Nodes that share a zone and can reach each other **auto-punch to a
direct UDP/TCP hole**; everything else flows through relay — no manual
path configuration.

---

## Documentation

| Doc | Contents |
|-----|----------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Overall design, layers, data plane |
| [DEPENDENCY_TREE.md](docs/DEPENDENCY_TREE.md) | External + internal + runtime dependency tree |
| [DESIGN_V16_SPLIT_AND_HOLEPUNCH.md](docs/DESIGN_V16_SPLIT_AND_HOLEPUNCH.md) | v1.6 split + hole-punch engine design & implementation status |
| [RELAY_DEPLOYMENT_GUIDE.md](docs/RELAY_DEPLOYMENT_GUIDE.md) | Relay node setup |
| [ZONE_AWARE_TRANSPORT.md](docs/ZONE_AWARE_TRANSPORT.md) | Zone-aware routing rules |
| [JOIN_GUIDE.md](docs/JOIN_GUIDE.md) | One-click join onboarding |
| [SOCKS5_PROXY_GUIDE.md](docs/SOCKS5_PROXY_GUIDE.md) | Proxy entry/exit setup |
| [ACL_GUIDE_v1.1.md](docs/ACL_GUIDE_v1.1.md) | Access control between nodes |
| [SYSTEMD_DEPLOY_GUIDE_v1.1.md](docs/SYSTEMD_DEPLOY_GUIDE_v1.1.md) | systemd service setup |
| [RELEASE_NOTES.md](docs/RELEASE_NOTES.md) | Version history |

---

## Architecture at a glance (v1.6)

```
┌─ cmd/meshdesk (flags/subcommands)
├─ internal/app        composition root — three-phase Build → wire → Start/Stop
├─ internal/holepunch  NAT punch engine (Dialer interface — no mesh import)
├─ internal/mesh       MeshNode: single-port mux, UDP ARQ, relay, TUN data plane
├─ internal/session    X25519 + Ed25519 key exchange
├─ internal/crypto     AES-256-GCM SecureConn
├─ internal/handshake  Reality TLS
└─ internal/...        config / identity / p2p / tun / web / webssh / dns / proxy / monitor / join
```

See [DEPENDENCY_TREE.md](docs/DEPENDENCY_TREE.md) for the full tree.

---

## License & Governance

Open source under [your license]. Built with the Agora multi-agent framework — AI teams implement, test, review, and deploy features autonomously.
