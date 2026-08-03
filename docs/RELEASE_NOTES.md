# Release Notes

## v3.0.0 — 2026-08-03

### Major Changes

- **Removed xray-core** — meshdesk now uses its own Reality TLS + smux protocol stack exclusively. No external binary dependency.
- **SOCKS5 proxy** — phone/client connects to shared node port 52888, Reality TLS handshake → SOCKS5 stream (virtual port 0x5350) → mesh relay → exit node (virtual port 0x4558) → Internet. Uses standard SOCKS5 client, no VLESS needed.
- **One-click join** — Dashboard `/join` page generates `curl -sSL http://dashboard:8080/join?token=xxx | sudo sh`. New node auto-downloads binary, generates identity, writes config, joins cluster.
- **Dashboard full management** — all node config editable from Dashboard (`/config` page, 4-tier access). No SSH needed for routine operations.
- **Smux stream relay** — virtual port 0x524C. Ordinary nodes (no public port) can relay streams between peers that can't connect directly (e.g., IPv4-only ↔ IPv6-only).

### MuxTransport Multiplexing

Port 52888 handles all protocols via first-byte sniffing:

| First Byte | Protocol | Virtual Port |
|------------|----------|-------------|
| 0x16 | Reality TLS | — |
| 0x4D | mesh-internal | — |
| 0x53 | SOCKS5 entry | 0x5350 |
| 0x45 | SOCKS5 exit | 0x4558 |
| 0x52 | smux relay | 0x524C |
| other | gossip (TCP/UDP) | — |

### Node Types

- **Shared node** (`reality.enabled: true`): listens on 52888, Reality TLS + MuxTransport
- **Ordinary node** (`reality.enabled: false`): no TCP listener, UDP-only gossip, connects outbound

### Monitoring Auto-Routing

- Dashboard nodes broadcast `CapCollector` via gossip
- Other nodes auto-discover collectors and push metrics
- Aggregator forwarding with `Forwarded` flag + `SourceID+Sequence` dedup (loop prevention)
- `peers.cache` persists endpoints + collector info across restarts
- `identity.pem` persists Ed25519 identity (stable public key)

### Code Review Fixes

**Critical:**
- Aggregator dedup map periodic cleanup (prevents unbounded growth)
- Store buffers stale node cleanup (`RemoveStaleNodes`)
- MuxTransport `packetChIn` buffered (4096) to prevent UDP listen blocking

**High:**
- smux `handleSyn` acquires MaxStreams slot before stream creation (prevents zombie streams)
- Aggregator `handlePush` WaitGroup tracking (prevents goroutine leak on Stop)
- metaCache 24h expiry cleanup (NotifyLeave retains for fallback but cleans stale)
- MuxTransport `streamCh` buffered (64)
- UDP-only MuxTransport advertises correct port from `udpConn.LocalAddr`

**Low:**
- Removed dead code: `ErrWrongRole`, `ErrBacklogFull`, `detectOutboundIPFromInterfaces`
- Fixed smux `OpenStream` comment for bidirectional streams

### Verification

- 22/22 unit test packages pass
- 3-node real-device test: txcloud (ordinary + Dashboard) + aliyun (shared, IPv4) + N1 (ordinary, IPv6)
- All nodes visible in topology with correct hostnames
- 3-node monitoring data with aggregator forwarding
- 0 UDP sendto errors
- identity.pem persistence verified across restarts

### Build

```bash
go build -o meshdesk ./cmd/meshdesk/
GOOS=linux GOARCH=arm64 go build -o meshdesk-arm64 ./cmd/meshdesk/
```

### Documentation

- [Architecture](ARCHITECTURE.md)
- [Join Guide](JOIN_GUIDE.md)
- [SOCKS5 Proxy Guide](SOCKS5_PROXY_GUIDE.md)
- [Config Inventory](CONFIG_INVENTORY.md)
- [Proxy Design](PROXY_DESIGN.md)
- [Frontend](FRONTEND.md)
- [Config Security Model](CONFIG_SECURITY_MODEL.md)
- [Transport Contract](TRANSPORT_CONTRACT.md)
- [Transport Capability Matrix](TRANSPORT_CAPABILITY_MATRIX.md)
