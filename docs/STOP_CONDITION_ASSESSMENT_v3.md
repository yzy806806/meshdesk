# MeshDesk Stop Condition Assessment v3

Date: 2026-07-25 | Commit: a9b1ab5 | Assessor: architect

## Stop Condition (from AGENTS.md)

> 项目文件精简无冗余，代码风格统一，前端页面美观，实现优雅，VPN性能好，抗网络波动和GFW干扰能力强，代理功能实现多路径分散传输+动态选路+SS入口，Dashboard安全加固完成(TOTP+二次认证+告警)，实机测试通过。

## What Changed Since v2 (commit f435567)

The v2 assessment (commit f435567) found two critical wiring gaps:
1. Proxy package (26 files) not wired in main.go
2. Dashboard security (452 lines) not wired into HTTP routes

Since then:
- **76e0d7f**: TOTP 2FA + step-up auth + security alerting LANDED and WIRED in server.go
- **a9b1ab5**: Harness fix for WebSSH capability enforcement
- **t_4155ba9c**: TOTP key management security spec produced (24 acceptance criteria)
- Four blocked parent tasks resolved (config fields, chunker, WebSSH auth, TOTP wiring)

## Codebase Snapshot (HEAD a9b1ab5)

| Metric | Value |
|--------|-------|
| Go source files (non-test) | 50 |
| Go test files | 51 |
| Internal packages | 11 |
| go vet | clean |
| Proxy module files | 26 |
| Frontend files (templates + CSS + JS) | 21 |
| Documentation files | 10 .md |
| TODO | 2 (ssh known-hosts store x2) |

## Package Test Results (HEAD a9b1ab5)

| Package | Result | Notes |
|---------|--------|-------|
| internal/auth | PASS | |
| internal/config | PASS | |
| internal/mesh | PASS | |
| internal/mesh/peer | PASS | |
| internal/monitor | PASS | |
| internal/service | PASS | |
| internal/transfer | PASS | |
| internal/web | PASS | |
| internal/webssh | PASS | |
| internal/proxy (unit tests) | MOSTLY PASS | TestRelayMaxCircuits DEADLOCKS |
| test/harness | PASS | Full 8/8 integration suite |

---

## Criterion-by-Criterion Assessment

### 1. 项目文件精简无冗余 (Lean files, no redundancy) — ✅ PASS

Evidence:
- 50 production Go files across 11 packages
- 51 test files in complementary structure
- go vet clean, go build passes
- README has stale references (KCP/QUIC) documented but not code-redundant

**Verdict:** PASS. No change from v2.

### 2. 代码风格统一 (Consistent code style) — ✅ PASS

Evidence:
- go vet clean
- All packages follow Go conventions
- One cosmetic gofmt alignment in cftunnel.go

**Verdict:** PASS. No change from v2.

### 3. 前端页面美观 (Beautiful frontend pages) — ✅ PASS

Evidence:
- 8 HTML templates: dashboard, node_detail, terminal, files, services, peers, login, login_2fa, error
- Pico.css dark theme + 1,244-line app.css
- xterm.js terminal with fit/search/web-links
- htmx for partial updates, dashboard.js for SSE metrics
- All assets compiled into binary via go:embed

**Verdict:** PASS. No change from v2.

### 4. 实现优雅 (Elegant implementation) — ⚠️ PARTIAL

Evidence of elegance:
- Pluggable obfuscation shim with clean interface contract
- Capability-based authorization engine with composable middleware
- Proxy module with well-defined interfaces (Chunker, Reassembler, Relay, Exit, PathSelector)
- Dashboard security now wired with composable middleware: sessionAuth -> stepUp -> requireAuth
- Audit logging with hash chaining, rotation, sequence numbers
- NullBackend pattern for systemd-unavailable environments (Gap 5 resolved)
- TransferConfig.MaxFileSize for file transfer bounds (Gap 4 resolved)

Gaps:
- **Proxy not wired in main.go** — cmd/meshdesk/main.go (293 lines) has ZERO proxy imports
- **Relay deadlock** — TestRelayMaxCircuits hangs on RWMutex.RLock in relay.go:162 secReport()
- **No unified capability enforcement** (Structural Gap 2): only service management calls CapabilityEngine.Authorize(). WebSSH handler, monitor aggregator, and file transfer have no authorization checks at the mesh-internal listener layer.
- 2 TODOs for SSH known-hosts store

**Verdict:** PARTIAL. Proxy wiring + relay fix + capability enforcement remain. Gap 4 and Gap 5 from structural analysis are resolved.

### 5. VPN性能好 (VPN performance) — ❓ UNKNOWN

Evidence:
- Zero benchmarks for VPN throughput or latency
- WireGuard-go + gVisor netstack has ~30-50% throughput penalty vs kernel WireGuard (documented architecture limitation)
- Obfuscation benchmarks exist but only measure CPU overhead

**Verdict:** UNKNOWN. No change from v2. Still unmeasurable.

### 6. 抗网络波动和GFW干扰能力强 (GFW resistance) — ⚠️ PARTIAL

Evidence:
- Pluggable obfuscation shim with three strategies: uTLS, Junk-over-WebSocket, handshake masking
- uTLS integration for ClientHello randomization
- Obfuscation registry + per-peer capability-based configuration

Gaps:
- Never tested against real GFW or DPI equipment
- No empirical traffic-capture analysis
- No real-world deployment data

**Verdict:** PARTIAL. Implementation is thoughtfully designed but lacks empirical validation. No change from v2.

### 7. 代理功能实现多路径分散传输+动态选路+SS入口 (Proxy multi-path + SS entry) — ⚠️ PARTIAL

Evidence of completion:
- 26 files in internal/proxy/ — fully implemented and tested
- Chunker: fixed 16KB + bounded variable with DebugFixedSizes
- Reassembler: exit-side streaming with sequence/total keying
- Relay: forwarding with anti-timing jitter
- ExitNode: AEAD decrypt + reassembly buffer + NACK protocol
- Shadowsocks: SS entry listener + chunking pipeline + circuit protocol
- CF Tunnel: Cloudflare Tunnel integration
- Path Selector: dynamic path selection + overlap detection
- Dispatcher: multi-path scheduling
- Wire format: AEAD-encrypted chunks with metadata-in-ciphertext

Gaps:
- **NOT wired in main.go** — the entire proxy package is a library, never instantiated
- **Relay deadlock** — TestRelayMaxCircuits hangs on RWMutex contention
- Chunker contract gaps resolved (t_90dc41ea verified)

**Verdict:** PARTIAL. All 26 files are implemented and individually tested. The relay has a deadlock bug. The primary gap remains the ~20-line wiring block in main.go.

### 8. Dashboard安全加固完成(TOTP+二次认证+告警) (Dashboard security) — ⚠️ PARTIAL (IMPROVED since v2)

Evidence of completion (NEW since v2):
- **TOTP 2FA** wired: /api/2fa/enroll, /api/2fa/verify, /api/2fa/disable, /api/2fa/status
- **Step-up auth** wired: /api/stepup/challenge, /api/stepup/verify, middleware gating on terminal, file upload, service management
- **Security alerts** wired: /api/alerts, /api/alerts/dismiss
- **Login flow**: password -> 2FA pending cookie -> TOTP verify -> full session
- **Middleware chain**: sessionAuth -> stepUp -> RequireCapability on WebSSH terminal
- AlertStore bridge methods: HandleAuthDenial, HandlePeerJoin, HandlePeerLeave, HandleProxySecurityEvent

Gaps:
- **TOTP secrets stored in plaintext** (in-memory, no at-rest encryption). Per t_4155ba9c spec: should use node-local master secret + HKDF-SHA256 key derivation + AES-256-GCM per-user encryption
- **TOTP enrollment state is binary** (enrolled/not-enrolled), not the 5-state model from the spec (DISABLED, PENDING, VERIFIED, ROTATING, DISABLED_BY_ADMIN)
- t_4bfd784b (TOTP key management hardening) is READY but not yet dispatched

**Verdict:** PARTIAL. Major improvement — dashboard security went from "not wired" to "wired with TOTP/step-up/alerts." The remaining gap is TOTP key management hardening (encryption at rest, 5-state enrollment).

### 9. 实机测试通过 (Real-device testing) — ✅ PASS (IMPROVED since v2)

Evidence:
- Full Integration Suite (TestSuiteRealDevice): 8/8 PASS (confirmed by t_6126c4bf)
- test/harness package passes at HEAD a9b1ab5
- Previous WebSSH individual test failures resolved by commit a9b1ab5 (harness fix)

**Verdict:** PASS. v2 had "MIXED" with WebSSH edge-case failures. Those are now resolved.

---

## Summary

| # | Criterion | v2 Status | v3 Status | Key Gap |
|---|-----------|-----------|-----------|---------|
| 1 | Lean files | ✅ PASS | ✅ PASS | — |
| 2 | Code style | ✅ PASS | ✅ PASS | — |
| 3 | Frontend | ✅ PASS | ✅ PASS | — |
| 4 | Elegant implementation | ⚠️ PARTIAL | ⚠️ PARTIAL | Proxy not wired + relay deadlock + capability enforcement |
| 5 | VPN performance | ❓ UNKNOWN | ❓ UNKNOWN | Zero benchmarks |
| 6 | GFW resistance | ⚠️ PARTIAL | ⚠️ PARTIAL | No empirical validation |
| 7 | Proxy multi-path + SS | ⚠️ PARTIAL | ⚠️ PARTIAL | Not wired in main.go + relay deadlock |
| 8 | Dashboard security | ⚠️ PARTIAL | ⚠️ PARTIAL | TOTP key management hardening pending |
| 9 | Real-device testing | ⚠️ MIXED | ✅ PASS | — |

### Verdict: STOP CONDITION IS NOT MET

**How we got here:** v1 had 3 PASS / 2 PARTIAL / 3 FAIL / 1 UNKNOWN. v2 had 3 PASS / 4 PARTIAL / 1 UNKNOWN / 1 MIXED. v3 has 4 PASS / 4 PARTIAL / 1 UNKNOWN. Progress: 2 criteria improved (dashboard security wiring, real-device testing).

## Remaining Work (Priority Order)

### Critical (blocks stop condition):

1. **Wire proxy into main.go** — ~20-30 lines to instantiate proxy components and start listeners
2. **Fix relay deadlock** — TestRelayMaxCircuits RWMutex contention in secReport()
3. **Implement TOTP key management spec** — t_4bfd784b: node-local master secret, HKDF key derivation, AES-256-GCM encryption, 5-state enrollment

### Important (quality / security):

4. **Add unified capability enforcement** (Structural Gap 2): interceptor for mesh-internal listeners
5. **Add VPN throughput benchmarks** — iperf3-equivalent over mesh

### Nice to have:

6. **GFW empirical validation** — traffic-capture analysis against DPI
7. **SSH known-hosts store** — 2 TODOs in codebase