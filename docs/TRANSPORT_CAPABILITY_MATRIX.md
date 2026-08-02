# Transport Layer Capability Matrix

**Version:** 1.0
**Status:** Current as of 2026-07-26
**Contract:** `docs/TRANSPORT_CONTRACT.md`
**Interface:** `internal/mesh/transport.go`

---

## 1. Quick Reference

| Feature | UDP | WebSocket | Reality |
|---|---|---|---|
| **Status** | Existing (v1) | Existing (v1) | Stable (native Go) |
| **Transport** | UDP | TCP + WebSocket | TCP + TLS 1.3 |
| **TLS** | None | uTLS (optional) | Reality TLS |
| **GFW Resistance** | Low | Medium | High |
| **NAT Traversal** | Native (WireGuard) | TCP-based | TCP-based |
| **Latency** | Lowest | Medium | Medium-High |
| **Obfuscation** | Header rand + padding | WebSocket framing | SNI camouflage + Auth |
| **Connection Model** | Connectionless | Stream-oriented | Stream-oriented |
| **WiFi/LAN** | Ideal | Overkill | Overkill |
| **Cellular/4G/5G** | Good | Good | Good |
| **Cross-GFW** | Blocked | May work | Primary path |
| **Fallback Role** | Primary (LAN) | Secondary | Primary (WAN/GFW) |

---

## 2. Feature Detail

### 2.1 Connectivity

| Capability | UDP | WebSocket | Reality |
|---|---|---|---|
| Outbound Connect | ✓ | ✓ | ✓ (native Go) |
| Inbound Listen | ✓ | ✓ | ✓ (native Go) |
| Multi-peer support | ✓ (per-endpoint) | ✓ (connection pool) | ✓ (MuxTransport) |
| Connection pooling | N/A (connectionless) | ✓ (wsBind pool) | ✓ (MuxTransport) |
| Idle timeout | N/A | Configurable | Configurable |
| Connection limits | N/A | Configurable | Configurable |
| Context-aware dial | ✓ | ✓ | ✓ (delegated) |

### 2.2 Security

| Capability | UDP | WebSocket | Reality |
|---|---|---|---|
| TLS encryption | None | uTLS (optional) | TLS 1.3 (always) |
| TLS fingerprint mimic | N/A | ✓ (6 profiles) | ✓ (native uTLS) |
| SNI camouflage | N/A | ✓ (custom SNI) | ✓ (camouflage target) |
| Anti-probe (server) | None | None | Full (Reality auth gate) |
| Anti-probe (client) | None | None | Full (shortId + key) |
| Certificate auth | N/A | Optional (TLS cert) | X25519 + shortId |
| fallback (camouflage) | N/A | N/A | ✓ (forward to real site) |

### 2.3 Obfuscation

| Capability | UDP | WebSocket | Reality |
|---|---|---|---|
| Header randomization | ✓ (AmneziaWG H1-H4) | Via WS frame | TLS 1.3 native |
| Message-type hiding | ✓ (H-ranges) | Via WS opcode | TLS record type |
| Per-message padding | ✓ (S1-S4) | Via WS frame | Via TLS record |
| Junk train (Jc) | ✓ | N/A | N/A |
| Anti-probe PSK | ✓ (HMAC tag) | N/A | ✓ (Reality auth) |
| Timing jitter | ✓ (JitterMaxMs) | N/A | N/A |
| WireGuard type hiding | ✓ | ✓ (via WS framing) | ✓ (via TLS stream) |
| DPI fingerprint diversity | Medium | High (uTLS profiles) | Maximum (uTLS + Reality) |

### 2.4 Operational

| Capability | UDP | WebSocket | Reality |
|---|---|---|---|
| Graceful shutdown | ✓ (close UDP socket) | ✓ (drain WS pool) | ✓ (close TLS listener) |
| Health check | ✓ (ICMP/TCP) | ✓ (connection alive) | ✓ (Reality session alive) |
| Latency probing | ✓ (ICMP/timing) | ✓ (SYN-ACK timing) | ✓ (Reality conn probe) |
| Auto-restart | N/A | N/A | ✓ (circuit breaker) |
| Log capture | Via stderr | Via stderr | ✓ (ring buffer) |
| Config hot-reload | N/A | N/A | ✓ (SIGHUP) |
| Metrics (ConnCount) | ✓ | ✓ | ✓ |
| Metrics (ActiveSince) | ✓ | ✓ | ✓ |

### 2.5 Mockability / Testing

| Capability | UDP | WebSocket | Reality |
|---|---|---|---|
| net.Pipe() compatible | ✓ | ✓ | ✓ (interface) |
| Latency injection | ✓ | ✓ | ✓ |
| Failover simulation | ✓ | ✓ | ✓ |
| Error classification | ✓ | ✓ | ✓ |
| Zero-config test mode | ✓ (port 0) | ✓ (port 0) | ✓ (Go interface) |
| In-memory testing | ✓ | ✓ | ✓ (pure Go) |

---

## 3. Configuration Surface

### 3.1 UDP Transport

```yaml
peers:
  - public_key: "..."
    endpoint: "10.0.0.26:51820"
    obfuscation: "none"   # or "padded" for AmneziaWG
```

**Relevant `TransportConfig` fields:**
- `Name: "udp"`
- `DialTimeout`
- `ObfuscationMode: "none"` or `"padded"`
- `ObfuscationPSK` (for anti-probe)

### 3.2 WebSocket Transport

```yaml
peers:
  - public_key: "..."
    endpoint: "203.0.113.10:8443"
    obfuscation: "websocket"
    obf_config:
      ws_use_tls: true
      tls_sni: "www.microsoft.com"
      tls_fingerprint: "chrome"
```

**Relevant `TransportConfig` fields:**
- `Name: "websocket"`
- `UseTLS`
- `CertFile`, `KeyFile`
- `ServerName` (SNI)
- `TLSFingerprint` (chrome, firefox, safari, edge, ios, android)
- `ListenAddr`

### 3.3 Reality Transport

```yaml
# Server-side (this node as shared node)
reality:
  enabled: true
  listen_port: 443
  target: "www.apple.com:443"
  server_names: ["www.apple.com"]
  private_key: "..."       # X25519 key (hex)
  short_ids: ["0123456789abcdef"]

# Client-side (connect to shared node)
peers:
  - public_key: "..."
    endpoint: "203.0.113.10:443"
    obfuscation: "reality"
    reality:
      server_name: "www.apple.com"
      public_key: "..."      # server's X25519 public key
      short_id: "0123456789abcdef"
```

**Relevant `TransportConfig` fields:**
- `Name: "reality"`
- `RealityDest` (camouflage target)
- `RealityPrivateKey` (server-side)
- `RealityPublicKey` (client-side)
- `RealityShortID` (client-side)
- `RealityServerNames` (server-side accepted SNIs)
- `ServerName` (SNI sent in ClientHello)

---

## 4. Implementation Details

### 4.1 UDP Transport

**Package:** `internal/mesh/obfuscation.go`
**Key types:** `obfuscatingBind`, `paddedObfuscator`, `noneObfuscator`
**WireGuard integration:** Via `conn.Bind` interface — wraps the default UDP bind with per-peer obfuscation transforms.

**Architecture:**
```
WireGuard Device
  └── obfuscatingBind (conn.Bind wrapper)
       └── DefaultBind (raw UDP)
            └── OS UDP socket
```

**Strengths:**
- Lowest latency (direct UDP, no extra framing)
- AmneziaWG 2.0-style header randomization and padding
- Anti-probe HMAC challenge
- Junk train (Jc) for handshake camouflage

**Limitations:**
- No TCP fallback — blocked on networks that throttle/block UDP
- No TLS layer — bare WireGuard handshake fingerprints detectable
- No SNI camouflage

### 4.2 WebSocket Transport

**Package:** `internal/mesh/obfuscation.go`
**Key types:** `wsBind`, `websocketTransport`, `websocketObfuscator`
**WireGuard integration:** Via `conn.Bind` — `wsBind` extends `obfuscatingBind` to route websocket-mode peers over TCP+TLS.

**Architecture:**
```
WireGuard Device
  └── obfuscatingBind
       ├── DefaultBind (UDP peers)
       └── wsBind (websocket peers)
            ├── wsListener (inbound, TCP/TLS accept)
            └── wsConn pool (outbound, per-peer dial)
```

**Strengths:**
- TCP-based — works on networks that throttle UDP
- uTLS fingerprint mimicry (6 browser profiles)
- Optional TLS encryption with custom SNI
- HTTP upgrade handshake looks like normal web traffic

**Limitations:**
- Higher latency than UDP (TCP + WS + TLS overhead)
- Connection-oriented — per-peer connection pool management
- WebSocket framing adds ~2-10 bytes per packet
- TLS handshake adds connection setup latency

### 4.3 Reality Transport

**Package:** `internal/mesh/` (`reality_transport.go`)
**Key types:** `RealityTransportFactory`, `RealityConn`
**Integration:** Native Go implementation — no external binary dependency.

**Architecture:**
```
MeshDesk Go Binary
  ├── MuxTransport (single TCP port)
  ├── RealityTransportFactory
  │   ├── Connect() → uTLS ClientHello → Reality TLS handshake
  │   ├── Listen() → reality.Server() → accept authenticated connections
  │   └── Non-mesh traffic → forward to camouflage destination
  │
  └── Pure Go Reality (github.com/xtls/reality + utls)
      └── TLS 1.3 + REALITY + uTLS fingerprint mimicry
```

**Strengths:**
- Maximum GFW resistance — Reality TLS 1.3 with SNI camouflage
- Native Go, single binary — no xray-core subprocess or external dependency
- Server-side: authenticates mesh peers silently, forwards non-mesh to real site
- Client-side: mimics real browser TLS fingerprint, valid SNI to real domain
- Zero subprocess boundary — lower latency than subprocess-based approaches
- Full Go testability — in-memory testing with net.Pipe(), no binary dependency

**Limitations:**
- TLS handshake adds connection setup latency (~100ms)
- Higher CPU cost than raw UDP (TLS 1.3 encryption)
- Requires valid camouflage destination (e.g., apple.com:443)

---

## 5. Deployment Scenarios

### Scenario A: LAN Mesh (Home/Office)

**Primary:** UDP (lowest latency, no firewall)
**Fallback:** None needed
```
Peer A ← UDP → Peer B
```

### Scenario B: Cross-GFW (Client in China → Server Abroad)

**Primary:** Reality (highest GFW resistance)
**Fallback:** WebSocket+TLS
```
Client (CN) ← Reality TLS → Server (US)
              ↕ (fallback)
Client (CN) ← WS+uTLS   → Server (US)
```

### Scenario C: Mixed Topology

| Path | Transport | Rationale |
|---|---|---|
| LAN peer → LAN peer | UDP | Lowest latency |
| LAN peer → Remote peer | Reality | Cross-GFW |
| NAT'd peer → Shared node | Reality | Behind CGNAT |
| Shared node → Shared node | Reality | Inter-datacenter |
| All peers → Failover | WebSocket+TLS | When Reality unavailable |

---

## 6. Acceptance Criteria Compliance

Per-contract AC-6 (godoc comments), each transport implementation must document:

| AC | UDP | WebSocket | Reality |
|---|---|---|---|
| Interface compliance | ✓ (conn.Bind wrapper) | ✓ (conn.Bind wrapper) | TBD (TransportFactory) |
| godoc comments | ✓ (obfuscation.go) | ✓ (obfuscation.go) | ✓ (reality_transport.go) |
| Error classification | Implicit | Implicit | Explicit (CircuitState) |
| Health reporting | ICMP-based | Connection-alive | Process status |

---

## 7. Future Considerations

| Feature | Priority | Notes |
|---|---|---|
| Reality native Go (no xray dep) | ✅ DONE | Native Go Reality TLS in `internal/mesh/reality_transport.go` |
| gRPC transport | P3 | HTTP/2-based, multiplexed streams |
| QUIC transport | P3 | Lower latency than TCP, resistant to head-of-line blocking |
| QUIC+Reality | P3 | Combine QUIC performance with Reality GFW resistance |
| Multipath aggregation | P3 | Bond multiple transports for throughput |