# MeshDesk Anonymous Proxy Design

**Version:** 2.0
**Status:** Adopted (team motion motion-3024854615df, 2026-07-25)
**Created:** 2026-07-25
**Updated:** 2026-07-25

---

## Overview

MeshDesk 已实现 mesh VPN（WireGuard + gVisor + 混淆 shim）。本设计在现有 mesh 基础上新增**多路径分散匿名代理**功能，同时强化 Dashboard 安全。

核心价值：**节点越多，路径选择越多，速度越快，抗检测越强。**

---

## Architecture Decision Record: Chunk Sizing

### Decision

Adopt **bounded random chunking**: each chunk payload is 4KB–64KB, sampled from a Pareto distribution that mirrors real HTTP/2 frame sizes. External wire format uses TLS 1.3 record padding for protocol mimicry.

### Alternatives Considered

| Approach | Proposer | Strengths | Weaknesses |
|---|---|---|---|
| Fixed 16KB + random padding | Developer | Simplest reassembly; deterministic buffer sizing | Fixed-size fingerprint observable at relay; statistical correlation across chunks |
| Tor-style 512-byte cells | (benchmark) | Maximum anonymity at cell level | ~500ms circuit latency; unacceptable fragmentation overhead for throughput-oriented proxy |
| Fully adaptive sizing | (strawman) | Optimal per-path throughput | Requires real-time per-path measurement feedback loop; months of tuning; complex reassembly |
| **Bounded random 4KB–64KB + TLS 1.3 padding** | **Researcher** | **Anti-fingerprinting via realistic distribution; bounded reassembly buffer; debug flag for fixed-size testing** | **Moderate implementation complexity (one `crypto/rand` call per chunk)** |

### Evidence

- **Tor** uses fixed 512-byte cells — proves uniform sizing works for anonymity, but at unacceptable bandwidth cost for MeshDesk's use case.
- **Shadowsocks** uses stream-based transport with no artificial chunking — proves stream-based resists fingerprinting but loses multi-path parallelism.
- **V2Ray/Xray** (most deployed GFW circumvention tool in China) adopts TLS 1.3 record framing — proves protocol mimicry defeats Chinese DPI.
- **Academic consensus** (WTF-PAD, Front, Walkie-Talkie): uniform packet sizes make traffic analysis *easier*, not harder. Effective padding must sample from a realistic distribution.
- **AmneziaWG** proves random padding defeats DPI without protocol-level changes.

### Verification

Tester's four failure-mode tests (out-of-order reassembly, path death recovery, reassembly buffer DoS, duplicate deduplication) must pass on 3+ physical nodes before the decision is considered verified. A debug flag forces uniform 16KB chunks for deterministic testing in CI; production mode requires random sizing.

---

## 1. Multi-Path Dispersed Transport

### Principle

入口节点收到用户流量后，拆成 chunk，端到端加密（入口↔exit 共享密钥），随机分配到多条 mesh 路径并行传输。中间节点只做转发，无密钥，无法还原。exit 节点重组 chunk → 解密 → 发起 TCP 连接到目标。

```
用户设备          CF边缘        入口节点              mesh中段              exit节点
┌────────┐      ┌────────┐    ┌──────────┐    ┌──────────────────┐    ┌──────────┐
│ SS/SOCKS5│─TLS─→│ CF IP  │──→│ mesh节点 │    │ 多路径分散传输    │    │ mesh节点 │──→ 目标
│ client │      │ (不可封)│   │ 终结代理 │───→│ path1: A→B→exit   │───→│ 重组+发起 │    网站
│        │      └────────┘    │ 协议     │    │ path2: A→C→D→exit │    │ TCP连接   │
└────────┘                    └──────────┘    └──────────────────┘    └──────────┘
                                  ↑动态选择入口          ↑动态选择exit
                                  (多个入口通过          (根据exit→目标
                                   不同CF Tunnel暴露)     延迟选最优)
```

### Security Model

| Observer | What They See | Can Decrypt |
|---|---|---|
| Relay node B/C/D | AEAD ciphertext fragment + per-hop encrypted forwarding header | No — no decryption key |
| GFW (single path) | WireGuard-encrypted traffic + obfuscation | No — double encryption |
| GFW (multi-path correlation) | Two incomplete ciphertext streams | No — randomly allocated chunks prevent stream reconstruction; timing uncorrelated via relay jitter |
| Exit node | Decrypted plaintext | Yes — endpoint of end-to-end encryption; unavoidable (same as Tor) |

### 1.1 TCP Termination + Chunk Dispersion

浏览器发 TCP 流，入口节点必须终结 TCP 连接（接收 TCP、提取 payload），把 payload 拆成 chunk 分散到不同路径。exit 端重建 TCP 连接到目标。

这本质上是在传输层之上实现一个**可靠的多路径传输协议**（类似 QUIC multipath）。

### 1.2 Chunk Format

```
┌──────────────────────────────────────────────────────────────┐
│ Per-Hop Encrypted Forwarding Header (fixed 64 bytes)         │
│  Routed via onion-style: each relay decrypts and re-encrypts │
│  with next relay's key. No relay sees the full path.         │
├──────────────────────────────────────────────────────────────┤
│ E2E Encrypted Payload (4KB–64KB, bounded random)             │
│  Sampled from Pareto distribution matching HTTP/2 frames     │
│  Wire format: TLS 1.3 record framing for protocol mimicry    │
│  Cipher: ChaCha20-Poly1305 AEAD                              │
├──────────────────────────────────────────────────────────────┤
│ TLS 1.3 Record Padding (variable, to next record boundary)   │
└──────────────────────────────────────────────────────────────┘
```

Key properties:
- **Payload size**: 4KB–64KB per chunk, randomly sampled per chunk (not per stream). Distribution follows Pareto (heavy-tailed, matching real HTTP/2 frame sizes).
- **Forwarding header**: Fixed 64-byte encrypted blob. Each relay decrypts with its own key, reads next-hop address, re-encrypts with the next relay's key. This is onion-style per-hop encryption, not a single plaintext header. No relay can reconstruct the full path.
- **Wire format**: Chunks are encapsulated in TLS 1.3 record frames. To any DPI observer at a relay, the traffic looks like a normal TLS session with variable-length records — no fixed-size fingerprint.
- **Payload**: End-to-end AEAD encrypted (ChaCha20-Poly1305). Relay nodes never possess the decryption key.
- **Debug mode**: A `--debug-fixed-chunks` flag forces uniform 16KB chunks for deterministic testing. Must be off in production.

### 1.3 Reassembly + Retransmission

- Exit node maintains a per-circuit reassembly buffer with sequence-number-based sliding window.
- Chunks arrive out of order across multiple paths; exit sorts by sequence number before decrypting.
- **Retransmission model**: Exit-side NACK. When the exit detects a gap in the sequence window beyond a configurable timeout (suggested: 5 seconds), it sends a NACK back to the entry via the fastest available path. The entry retransmits the missing chunk, potentially on a different path.
- **Deduplication**: Exit deduplicates by sequence number. Retransmitted chunks with the same sequence number are silently discarded.
- **DoS protection**: Hard limit on reassembly window size (256 chunks ahead of the highest contiguous byte). Chunks beyond this window are rejected — prevents an attacker from exhausting exit memory with sparse sequence numbers.
- **Path death**: If one path fails mid-transfer, the exit detects the gap, requests retransmission on the surviving path. Orphaned reassembly buffers time out after a configurable period (suggested: 30 seconds) and are cleaned up.

### 1.4 End-to-End Encryption: ECDH Key Agreement

入口选定 exit 后，通过 mesh 控制信道做一次 ECDH 密钥交换：

```
1. 入口 → exit: circuit_setup (ECDH pubkey + target addr)
2. exit → 入口: circuit_ack (ECDH pubkey + accept/reject)
3. 双方派生共享密钥 (ChaCha20-Poly1305)
4. 数据传输开始
```

支持动态 exit 选择。密钥只存在于入口和 exit 两端。中间 relay 节点从接触不到密钥材料。

### 1.5 Path Selection

**Phase 1 (Manual config):** User specifies two paths in config file.

**Phase 2 (Auto selection):** RTT probing, automatically select two lowest-latency paths.

**Phase 3 (Adaptive):** Latency-proportional allocation + load-aware + dynamic switching.

Path selection = entry→exit path latency + exit→target latency. Select the two paths with the lowest combined latency.

**Path probing scalability:** On-demand probing, not O(N²). Entry queries mesh for relay-capable nodes, picks K candidates via advertised latency estimates, probes only those K, and builds the circuit. Scales O(K) instead of O(N²).

**Path overlap detection (hard requirement):** The path selection algorithm must reject any circuit where two candidate paths share a relay node. A relay appearing on both paths can correlate entry↔exit via timing even with ciphertext-only access. Implementation: tag each path with its relay node set; reject pairs where `path_A_nodes ∩ path_B_nodes` is non-empty.

### 1.6 Exit Latency Matrix

Each exit node periodically probes target regions for latency, propagated via mesh gossip protocol:

```
exit-tokyo:  { "jp": 5ms, "us-west": 120ms, "eu": 200ms }
exit-uswest: { "jp": 110ms, "us-west": 8ms, "eu": 150ms }
exit-fra:    { "jp": 250ms, "us-west": 180ms, "eu": 12ms }
```

Entry node receives target URL → DNS resolution → GeoIP region → lookup latency matrix → select optimal exit.

### 1.7 Identity Trust Boundary: Entry ↔ Exit

The three-layer trust model creates explicit identity boundaries:

```
Entry Node                Relay Nodes                Exit Node
┌──────────────┐     ┌──────────────┐          ┌──────────────┐
│ Knows:       │     │ Knows:       │          │ Knows:       │
│ - User IP    │     │ - Previous   │          │ - Previous   │
│ - Target     │     │   hop ID     │          │   relay ID   │
│   address    │     │ - Next hop   │          │ - Target     │
│ - Full path  │     │   address    │          │   address    │
│              │     │ Knows NOT:   │          │ Knows NOT:   │
│              │     │ - Entry ID   │          │ - Entry ID   │
│              │     │ - Exit ID    │          │ - User IP    │
│              │     │ - Payload    │          │              │
└──────────────┘     └──────────────┘          └──────────────┘
```

**Critical design property:** The exit node does NOT know which entry node originated the traffic. The last relay before the exit strips the entry's identity from the forwarding header — onion-style layering. The exit only knows "this circuit came from relay-X," not "this circuit came from entry-A." This prevents a compromised exit from correlating users to destinations.

**Corollary:** The entry node knows the exit node's identity (because it builds the circuit), and knows the target address. The entry is the most sensitive node in the system — it holds both user identity and destination. Entry node operators must be trusted, or users must run their own entry nodes.

### 1.8 Circuit Lifecycle

A circuit is **per-session**: one circuit per TCP connection (not per user). This matches Tor's model and is the only defensible choice against long-term correlation attacks. A per-user circuit that persists across connections would allow an observer to link all of a user's traffic to a single circuit ID.

```
CREATION:
  1. Entry selects exit based on target region
  2. Entry selects two disjoint paths through relay-capable nodes
  3. Entry → Exit: circuit_setup (ECDH pubkey + target addr)
     - Routed through path 1, onion-encrypted per hop
  4. Exit → Entry: circuit_ack (ECDH pubkey + accept/reject)
     - Routed through path 2
  5. Both sides derive shared ChaCha20-Poly1305 key
  6. Data transfer begins

ACTIVE:
  - Chunks flow on both paths simultaneously
  - Exit sends periodic ACKs (not per-chunk, window-based)
  - Entry sends keepalive pings every 30s to prevent timeout
  - Path health monitored via RTT on keepalives

TEARDOWN:
  - Triggered by: TCP connection close, idle timeout (configurable, default 5 min),
    path failure on both paths, or explicit circuit_teardown message
  - Entry → Exit: circuit_teardown (routed on fastest available path)
  - Exit: flushes reassembly buffer, closes target TCP connection
  - Both sides: purge shared key, free circuit state

IDLE TIMEOUT:
  - If no data flows for `circuit_idle_timeout` (default 5 min), entry sends
    circuit_teardown
  - Prevents resource leaks from abandoned circuits
  - Exit independently enforces timeout as defense against orphaned circuits
```

### 1.9 Forwarding Header Obfuscation

The forwarding header is the weakest link in the relay trust boundary — it sits outside the E2E ciphertext by definition. A plaintext header containing a circuit ID allows any relay to trivially correlate all chunks belonging to the same session.

**Mechanism: Onion-style per-hop encryption.**

```
Sender (Entry/Relay) constructs header:
  [next_hop_addr] encrypted with next_relay_pubkey

On receipt, Relay:
  1. Decrypt header with own private key → read next_hop_addr
  2. Construct new header for downstream relay:
     [next_next_hop_addr] encrypted with next_relay_pubkey
  3. Forward chunk with new header

This is how Tor's relay cells work.
```

**Additional protections:**
- Header is fixed 64 bytes regardless of content. Variable-length headers create their own fingerprint.
- If onion routing adds unacceptable latency for v1, the minimum viable alternative is rotating ephemeral circuit IDs that change every N chunks, so an observer cannot link chunks across time.
- Relay nodes MUST introduce random jitter (5–50ms) on chunk forwarding. Without jitter, timing side-channels between chunk arrival and departure at a relay reveal entry↔exit path correlation.

---

## 2. User Entry: CF Tunnel + Shadowsocks

### Protocol Selection

User device → CF Tunnel → Entry node, using **Shadowsocks over WebSocket**.

Rationale:
- CF's TLS provides protocol camouflage layer (GFW sees access to CF website), no Reality needed
- SS is lightweight, good performance
- CF IP space is vast; GFW cannot block all CF IPs

### Implementation

Use existing **shadowsocks-go** library (github.com/shadowsocks/shadowsocks-go or equivalent Go port). Do not reimplement the SS protocol — it is a minefield of edge cases (AEAD cipher modes, salt handling, replay protection).

### Entry Dynamic Selection

Multiple mesh nodes expose themselves as entry candidates through their respective CF Tunnels. User device (SS client) switches based on connection quality. This is client-side configuration — MeshDesk does not manage it.

MeshDesk ensures only that every node willing to serve as an entry runs an SS listener exposed via cloudflared.

### CF Tunnel Limitations

- No bandwidth cap (CF has not published a limit)
- Idle timeout: connections dropped when idle; proxy scenario has continuous traffic, not a concern
- TCP only: no UDP; UDP applications must be encapsulated in TCP
- CF ToS gray area: proxy traffic strictly violates ToS, but enforcement is lax in practice

---

## 3. Port Model

### Single-Port Design

MeshDesk shared nodes expose **1 TCP port** (vs EasyTier's 3 TCP + 3 UDP = 6):

```
Shared node:
  Public: 1 TCP (51820) — WebSocket WireGuard + relay + intra-mesh communication
  Optional: 1 UDP (51820) — LAN direct UDP WireGuard (better performance)
  CF Tunnel: Optional (if this node also serves as proxy entry)

Standard node:
  Public: 0 (outbound-only to shared node)
  Intra-mesh: automatic (gVisor netstack)

Dashboard node:
  Public: 0 (default)
  CF Tunnel: 1 → Web UI
  Intra-mesh: not listening (127.0.0.1 only)

Proxy entry node:
  CF Tunnel: 1 → SS listener
  Public: 0
```

All intra-mesh communication multiplexed over the same TCP connection (inside WireGuard encryption):
- WireGuard handshake (WebSocket encapsulated)
- Intra-mesh TCP streams (gVisor netstack virtual TCP)
  - Metrics push
  - File transfer
  - WebSSH SSH connections
  - Service management RPC
  - Circuit relay forwarding packets

### Comparison: EasyTier

| | EasyTier Shared Node | MeshDesk Shared Node |
|---|---|---|
| Public ports | 3 TCP + 3 UDP = 6 | 1 TCP (+ optional 1 UDP) |
| UFW rules | 6 | 1–2 |
| Attack surface | Large | Small |

---

## 4. Dashboard Security Hardening

Dashboard compromise = full-mesh SSH compromise. Multi-layer defense required.

### Attack Surface

1. CF Tunnel → Web UI (CF account compromise / ToS ban)
2. Direct port exposure (port scan → brute force)
3. Intra-mesh node compromise → access Dashboard via mesh IP
4. WebSSH vulnerability (WebSocket → SSH → root)

### Layered Defense

#### Layer 1: Entry Tightening

```yaml
node:
  web:
    listen: "127.0.0.1:8080"    # loopback only
    expose: "cf-tunnel"          # CF Tunnel only

auth:
  web_users:
    - username: admin
      password_hash: "$2a$12$..."  # bcrypt cost=12
      totp_secret: "JBSWY3DPEHPK3PXP"  # TOTP 2FA
  allow_open_mode: false
  session:
    max_age: 3600                # 1-hour expiry
    csrf: true
  rate_limit:
    login: 5/min
    login_lockout: 15min         # lockout after 5 failures
```

#### Layer 2: Mesh Network Zero Trust

Dashboard listens on loopback only. Mesh network does not expose Dashboard port. Operators accessing from within the mesh use SSH port forwarding.

#### Layer 3: Privileged Action Re-Authentication

WebSSH terminal access = root access. Should not share the same authentication level as Dashboard login:

```yaml
auth:
  privileged_actions:            # require re-authentication
    - webssh_connect             # terminal: re-enter password/TOTP
    - file_transfer
    - service_manage
    - binary_upgrade
```

#### Layer 4: Audit + Alerting

Existing audit log (hash chain + rotation). Added real-time alerting:

```
Anomalous login → Telegram webhook notification
New SSH session → Telegram webhook notification
File transfer → Telegram webhook notification
Service change → Telegram webhook notification
Consecutive auth failure → immediate alert
```

MeshDesk pushes security events via webhook to Hermes → Telegram.

---

## 5. Capabilities

```yaml
peers:
  - public_key: "B..."
    capabilities:
      - relay              # allow forwarding transit circuit packets
  - public_key: "exit_node..."
    capabilities:
      - exit              # allow serving as exit node
      - relay
  - public_key: "entrance_node..."
    capabilities:
      - relay
      - exit
```

| Capability | Scope | Description |
|---|---|---|
| `relay` | Per peer | Allow forwarding transit circuit packets |
| `exit` | Per peer | Allow serving as exit node (initiating outbound TCP connections) |

Default: off (zero-trust).

---

## 6. Exit Node: Legal Responsibility

### The Problem

Exit nodes initiate TCP connections to arbitrary destinations on behalf of users. This is the same legal exposure that Tor exit node operators face — the exit IP appears in target server logs, and the exit operator may receive abuse complaints, DMCA notices, or legal requests.

### Design Response

**1. Default destination filtering.** Exit nodes default to allowing only ports 80 and 443. Operators can expand the allowlist via configuration, with an explicit warning about increased legal exposure:

```yaml
exit:
  allowed_ports: [80, 443]       # default
  # allowed_ports: [80, 443, 22] # expand at operator's discretion
  allow_all_ports: false         # WARNING: full legal exposure
```

This is a per-node config flag, not a hard protocol limit — some operators will want unrestricted exits for legitimate use cases. The configuration file must display a warning when ports beyond 80/443 are enabled.

**2. Audit logging for operator defense.** Exit nodes maintain a minimal audit log recording `circuit_id → destination_ip:port → timestamp` (NOT payload content). This allows operators to demonstrate relay-only behavior if subpoenaed — the log proves the exit did not initiate the connection and had no knowledge of the content:

```json
{"time": "2026-07-25T07:30:00Z", "circuit": "0xCAFE...", "dest": "93.184.216.34:443", "bytes_in": 4096, "bytes_out": 12288}
```

Logs rotate daily; retention is operator-configurable (default: 7 days). No payload is ever logged.

**3. Operator narrative.** The design provides a verifiable defense: "I forwarded encrypted bytes. I never saw plaintext. I never saw the user's IP. My logs prove I was a passive relay." This narrative — trust through verifiability — is documented in the operator-facing documentation (not this design doc).

**4. CONNECT-style proxy command.** Because exit nodes default to port-restricted operation, the circuit setup message must specify the target address in a CONNECT-style format (host:port), not a raw TCP stream. The exit validates the port against its allowlist before establishing the connection.

---

## 7. Package Structure

```
meshdesk/
├── internal/
│   ├── circuit/                   — new
│   │   ├── circuit.go            — circuit setup/teardown/keepalive, ECDH key agreement
│   │   ├── relay.go              — relay node forwarding logic
│   │   ├── dispatcher.go         — entry-side chunk dispatch + path selection
│   │   ├── reassembler.go        — exit-side reassembly + NACK retransmission
│   │   └── protocol.go           — forwarding header, chunk format, onion encryption
│   ├── proxy/                    — new
│   │   ├── socks5.go             — SOCKS5 entry (optional)
│   │   ├── shadowsocks.go        — SS protocol entry
│   │   └── tunnel.go             — CF Tunnel adapter
│   ├── mesh/
│   │   ├── latency.go            — new: latency probing + path discovery
│   │   └── loadbalance.go        — new: load-aware path selection
│   ├── auth/
│   │   ├── totp.go               — new: TOTP 2FA
│   │   ├── reauth.go             — new: privileged action re-authentication
│   │   └── alert.go              — new: security event webhook alerting
│   └── config/
│       └── config.go             — extended: proxy/circuit/totp config sections
```

---

## 8. Implementation Phases

### Phase 1 — Core Proxy (P0)

- [ ] Circuit protocol definition (forwarding header with onion encryption, chunk format with bounded random sizing, ECDH handshake)
- [ ] Relay node forwarding logic (header decrypt/re-encrypt, relay jitter 5–50ms)
- [ ] Entry-side dispatcher (chunk dispatch, bounded random 4KB–64KB sizing, two disjoint paths)
- [ ] Exit-side reassembler (sliding window, NACK retransmission, sequence deduplication, DOS window limit, orphan timeout)
- [ ] SS listener (shadowsocks-go library, Shadowsocks protocol entry)
- [ ] CF Tunnel integration docs
- [ ] `relay` + `exit` capability enforcement
- [ ] End-to-end encryption (ChaCha20-Poly1305 AEAD)
- [ ] Path overlap detection (reject circuits with shared relay nodes)
- [ ] Basic test (2-node relay + 1 circuit)

### Phase 2 — Dynamic Path Selection (P1)

- [ ] Latency probing (intra-mesh RTT measurement via existing heartbeats)
- [ ] Exit latency matrix (gossip propagation)
- [ ] Auto path selection (select two lowest-latency disjoint paths)
- [ ] Load awareness (downgrade paths under high load)
- [ ] Path failover (auto-switch when a path degrades)
- [ ] On-demand path probing (O(K) scaling, not O(N²))
- [ ] Multi-path file transfer extension

### Phase 3 — Dashboard Security Hardening (P0, parallel with Phase 1)

- [ ] Web UI loopback-only binding
- [ ] bcrypt cost=12
- [ ] TOTP 2FA
- [ ] Privileged action re-authentication (webssh, file_transfer, service_manage)
- [ ] Login rate limiting + lockout
- [ ] CSRF token
- [ ] Security event webhook (→ Telegram)
- [ ] Mesh network isolation of Dashboard

### Phase 4 — Frontend (P2)

- [ ] Circuit visualization (path topology graph)
- [ ] Proxy configuration UI
- [ ] Exit latency matrix display
- [ ] Security event real-time panel

---

## 9. Network Effects

```
N = relay node count
Available path count ≈ N×(N-1)/2

| Relay Nodes | Available Path Pairs | Effect |
|---|---|---|
| 3 | 3 | 2 paths selectable |
| 10 | 45 | 2 optimal from 45 |
| 50 | 1225 | near-infinite path selection |
```

Each new node joining the network expands the path selection space. Prerequisites:
1. Relay nodes must have bandwidth headroom
2. Paths must be node-disjoint (enforced by overlap detection)
3. Load awareness required (prevent all traffic converging on fastest path)

---

## 10. Resolved Design Questions

These questions were in the v1.0 "Open Questions" section; team discussion (motion-3024854615df) resolved them:

| # | Question | Resolution |
|---|---|---|
| 1 | Chunk sizing granularity | **Bounded random 4KB–64KB + TLS 1.3 padding.** Sampled from Pareto distribution matching HTTP/2 frames. Debug flag for fixed 16KB in testing. |
| 2 | Retransmission mechanism | **Exit-side NACK.** Exit detects gaps in sequence window, requests retransmission via fastest available path. Entry does not track which paths delivered successfully. |
| 3 | Circuit lifecycle | **Per-session** (one circuit per TCP connection). Per-user circuits enable long-term correlation; per-session follows Tor's model. |
| 4 | Path count | **Fixed 2 paths for v1.** Configurable later. Two disjoint paths balance dispersion gain against reassembly complexity. |
| 5 | Forwarding header obfuscation | **Onion-style per-hop encryption.** Fixed 64-byte encrypted header. Each relay decrypts, reads next hop, re-encrypts with next relay's key. Ephemeral circuit IDs as fallback if onion routing adds unacceptable latency. |
| 6 | SS implementation | **Use existing shadowsocks-go library.** Do not reimplement — SS protocol has too many edge cases. |
| 7 | Path overlap detection | **Hard requirement.** Path selection rejects any circuit where two candidate paths share a relay node. Tag each path with relay node set; reject if intersection is non-empty. |
| 8 | Exit node legal risk | **Default allowlist (80/443 only).** Per-node config flag with warning. Audit log records circuit_id→dest_ip:port→timestamp (no payload). CONNECT-style proxy command for port validation. |