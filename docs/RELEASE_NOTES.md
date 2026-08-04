# Release Notes

## v1.0.0 — 2026-08-04

First stable release.

### Features

- **Mesh VPN** — P2P decentralized networking via memberlist gossip + Reality TLS + smux
- **TUN Virtual Network** — Transparent Layer 3 IP routing between mesh nodes
  - Deterministic IPAM (VirtualIP = cidr_base + pubkey_hash % host_count)
  - Kernel route auto-sync via gossip NodeMeta
  - Subnet proxy (share local LAN with mesh peers)
  - Source IP anti-spoofing (deny-by-default)
  - Zero-dependency TUN device via raw `/dev/net/tun` syscall
- **Server Monitoring** — CPU, memory, disk, network, services
  - Push-based collection over mesh (no exposed port)
  - Auto-discovery of collector nodes via gossip
  - Metric dedup (SourceID + Sequence)
- **WebSSH** — SSH directly from browser, proxied over mesh
- **SOCKS5 Proxy** — Reality TLS disguised, multi-path relay, exit node controls
  - Standard SOCKS5 client support (no VLESS/xray needed)
  - Entry (0x5350) → relay (0x524C) → exit (0x4558) over single port
- **Dashboard** — Full web UI for node management
  - 3D topology graph, real-time monitoring
  - One-click node join (curl | sh)
  - 4-tier config access control
  - File transfer, service management
- **Reality TLS** — All traffic disguised as HTTPS to a real website (e.g. apple.com)
  - DPI cannot distinguish from legitimate HTTPS
  - No WireGuard, no KCP, no recognizable UDP patterns
- **Single Port** — All protocols multiplexed on port 52888 via MuxTransport
- **One-Click Join** — Generate install command from Dashboard, paste on new machine

### Architecture

- Layer 0: Ed25519 identity (PEM file)
- Layer 1: Reality TLS handshake (REALITY hijack)
- Layer 2a: X25519 ECDH key exchange
- Layer 2b: AES-256-GCM encryption (per-session keys, nonce replay protection)
- Layer 3: smux stream multiplexer
- Layer 4: MeshNode (gossip, WebSSH, file transfer, SOCKS5, TUN, monitoring)

### Node Types

- **Shared node** — Public TCP+UDP port, Reality TLS server, MuxTransport
- **Ordinary node** — No public port, UDP-only gossip, connects outbound

### Verified

- 22/22 unit test packages pass
- TUN ping verified: 0% packet loss, ~184ms cross-network RTT
- VirtualIP gossip broadcast + kernel route injection
- Subnet proxy route injection
- smux sessions across NAT
