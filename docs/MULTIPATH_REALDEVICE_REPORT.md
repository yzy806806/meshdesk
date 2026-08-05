# MeshDesk Multi-Path Failover + Performance Test Report
## 3-Node Topology Real-Device Test (v2.0)

**Version:** 2.0  
**Date:** 2026-08-05  
**Author:** tester  
**Status:** PARTIAL — unit tests pass (391 total, 44 multipath-specific), both nodes operational with P2P/relay/proxy, cross-node gossip blocked by Alibaba Cloud security group

---

## Executive Summary

All proxy unit tests pass with **391 PASS, 0 FAIL, 0 data races**. Both aliyun (203.0.113.10) and N1 (fn.example.com:22000) are reachable via SSH and successfully run meshdesk with P2P gossip, relay, exit node, and proxy subsystems active. N1's previously broken P2P configuration (dangling `advertise_endpoint` causing MuxTransport DNS parse failure) has been fixed and verified.

**Cross-node gossip remains BLOCKED**: The Alibaba Cloud security group on aliyun allows only ports 22, 80, 443, and 7000 (all occupied by other services). UFW has been opened for meshdesk ports (52888/tcp+udp, 7946/tcp+udp, 8080/tcp, 18800/tcp+udp), but the upstream security group overrides UFW. N1→aliyun TCP dials to ports 7946 and 18800 timeout consistently.

Multi-path real-device throughput/latency/packet-loss tests require ≥2 nodes with mutual gossip connectivity to establish 2 disjoint relay paths. With the current security group configuration, only 0 relay paths are available.

---

## 1. Unit Test Baseline

### Full Proxy Suite
```
Package: github.com/yzy806806/meshdesk/internal/proxy
Command: go test ./internal/proxy/ -count=1 -timeout 120s
Result:  PASS (391 tests, 0 failures, 2.2s)
Race:    PASS (go test -race, 0 data races, 4.6s)
```

### Multipath-Specific Tests (44 tests, all PASS)

| Category | Tests | Key Metrics |
|----------|-------|-------------|
| PathSelectorScaling | 4 | 10→250 candidates: 110µs–400µs (budget 50ms–2s) |
| DispatcherThroughput (single vs multi) | 3 | 395–433 MB/s (RoundRobin/Weighted/FastestOnly) |
| MultiPathFairDistribution | 3 | RR: 50/50 split; Weighted(10ms/100ms): 91/9 split |
| FailoverLatency | 3 | Instant failover, 0% chunk loss |
| PathSelectorProbeCacheHitRate | 1 | 100% warm-cache hit; precise invalidation |
| MultiPathPacketLossResilience | 2 | Survives one path dead with round-robin |
| AssignmentStrategyThroughput | 2 | RR 411 MB/s, Weighted 376 MB/s |
| DispatcherStatsAccuracy | 1 | Chunk/byte tracking correct |
| PathSelectorPerCandidateOverhead | 4 | ~2–7 µs per candidate |
| PathSelector health tests | 5 | ExcludeUnhealthy, FailoverOnDegraded, SelectReplacement, etc. |
| PathSelector core tests | 6 | SelectPaths, InsufficientCandidates, AllProbesFail, ProbeCache, etc. |
| Dispatcher tests | 6 | Padding, RoundTrip, Stats, RejectOverlap, etc. |
| **TOTAL** | **44** | **ALL PASS, 0 failures, 0 races** |

---

## 2. Real-Device Deployment

### Node Inventory

| Node | Status | Public IP | SSH | meshdesk | P2P Gossip | Relay | Exit |
|------|--------|-----------|-----|----------|------------|-------|------|
| aliyun | **ONLINE** | 203.0.113.10 | root@203.0.113.10 (deploy_key) | Running (PID 726142) | Active (port 7946, 2 seeds) | Active (maxCircuits=1024) | Active (ports 80,443,5201) |
| N1 | **ONLINE** | fn.example.com:22000 | yzy806806@fn.example.com:22000 | Running (PID 263198) | Active (port 7946, 1 seed) | Active (NAT+STUN+relay fallback) | Active (ports 80,443) |
| txcloud | **UNREACHABLE** | 10.144.144.20 | Connection timed out | Unknown | Unknown | Unknown | Unknown |

### aliyun (203.0.113.10)
- **Binary**: `/etc/meshdesk/meshdesk` (ELF x86_64, go build, meshdesk dev)
- **Config**: `/etc/meshdesk/config.yaml`
  - P2P: enabled, seeds=[10.144.144.20:7946, 10.144.144.11:7946]
  - Advertise: 203.0.113.10:52888
  - Reality: enabled (port 18800, dest=www.microsoft.com:443)
  - Proxy: path_selection.mode=manual, exit allowed_ports=[80,443,5201]
  - Relay: maxCircuits=1024
  - TUN: enabled, mesh0, 10.100.0.1/24
  - ACL: 0 rules, default=allow
- **Startup flags**: `--web`
- **Auth**: bcrypt (rounds=4), password NOT admin/123456
- **UFW**: Ports 52888, 7946, 8080, 18800 now open (was blocked)
- **Smux relay**: listening on virtual port 0x524C

### N1 (fn.example.com:22000)
- **Binary**: `/usr/local/bin/meshdesk` (ELF aarch64, go build, meshdesk dev)
- **Config**: `/home/yzy806806/meshdesk-config/config.yaml` (fixed from dangling advertise_endpoint)
  - P2P: enabled, seeds=[203.0.113.10:7946]
  - Advertise: auto-detected (192.168.1.206:52888 + IPv6)
  - Reality: enabled (port 18800, dest=www.apple.com:443)
  - Proxy: path_selection.mode=auto, exit allowed_ports=[80,443]
  - NAT: symmetric (STUN endpoint 120.243.147.66)
- **Startup flags**: `--web`
- **Auth**: web_users=[] (open access)
- **Proxy API**: `/api/proxy/status` returns `{"running":false,"session_count":0,"cf_tunnel_ready":false}`
- **SOCKS5 status**: path_mode=auto, socks5_enabled=false

### Startup Verification (aliyun log excerpts)
```
MeshDesk dev started
  Public key: f2bdccf548a029dc1ce8f2876f036b5860160c495160174ae8f3d2b17e61588b
  Mesh port:  52888
  Peers:      0
  Smux relay: listening on virtual port 0x524C (maxTunnels=64)
  P2P: gossip active (port 7946, 2 seeds)
  P2P: relay mode active (maxCircuits=1024)
  Proxy: exit node active (allowed_ports=[80 443 5201], allow_all=false)
  TUN: 10.100.0.1/24 on mesh0
```

### Startup Verification (N1 log excerpts)
```
MeshDesk dev started
  Public key: 4a37810012002a05c2055d4fb37b8c2c394579ac0a10f79a2d6ffd2696efb0fb
  Mesh port:  52888
  P2P: gossip active (port 7946, 1 seeds)
  P2P: NAT traversal active (STUN + hole-punch + relay fallback)
  Proxy: exit node active (allowed_ports=[80 443], allow_all=false)
  TUN: gossip integration active (VirtualIP routing + subnet proxy)
```

---

## 3. Blocker Analysis

### Root Cause: Alibaba Cloud Security Group

The Alibaba Cloud security group on aliyun (ECS iZbp10emrt4l28g3ohkq59Z) allows ONLY:
- Port 22 (SSH) — in use
- Port 80 (HTTP) — nginx
- Port 443 (HTTPS) — nginx
- Port 7000 — frps

All other ports are blocked at the security group level, overriding UFW rules.

### Port Reachability Matrix

| Port | Service | SG | UFW | Status | Occupied By |
|------|---------|-----|-----|--------|-------------|
| 22 | SSH | OPEN | ALLOW | Reachable | sshd |
| 80 | HTTP | OPEN | ALLOW | Reachable | nginx |
| 443 | HTTPS | OPEN | ALLOW | Reachable | nginx |
| 7000 | - | OPEN | ALLOW | Reachable | frps |
| 52888 | MuxTransport | BLOCKED | ALLOW | Timeout | - |
| 7946 | Gossip | BLOCKED | ALLOW | Timeout | - |
| 8080 | Web UI | BLOCKED | ALLOW | Timeout | - |
| 18800 | Reality/Mux | BLOCKED | ALLOW | Timeout | - |

### Attempted Mitigations

1. **UFW rules added**: Opened TCP+UDP for 52888, 7946, 8080, 18800 — SG still blocks
2. **N1 config fix**: Removed dangling `advertise_endpoint` → P2P gossip now starts successfully
3. **SSH tunnel (N1→aliyun)**: Established SSH tunnel N1:17946→aliyun:7946 via port 22. Tunnel verified working (TCP connection succeeds). However, memberlist requires bidirectional UDP+TCP and correct peer identity exchange; SSH TCP-only tunnel is insufficient for full memberlist operation
4. **SG modification**: No Alibaba Cloud CLI available on aliyun; manual console access required
5. **Port reuse**: All open ports (80, 443, 7000) occupied by other services

### Cross-Node Gossip Status
```
                 aliyun ───X─── N1        (aliyun→N1: 10.144.144.11:7946 unreachable — internal IP)
                 N1    ───X─── aliyun     (N1→aliyun: 203.0.113.10:7946 timeout — SG blocked)
                 aliyun ───X─── txcloud   (10.144.144.20:7946 unreachable)
                 
Multi-path requires ≥2 nodes with mutual gossip connectivity.
With only intra-node communication: 0 relay paths available.
Minimum viable: aliyun + N1 with mutual gossip (requires opening SG for UDP 7946 or TCP 18800).
```

---

## 4. What Was Verified

1. ✅ **Unit test suite** — All 391 proxy tests pass; 44 multipath-specific tests pass; 0 data races
2. ✅ **N1 config fix** — Removed dangling advertise_endpoint; P2P gossip now starts without "failed to parse advertise address" error
3. ✅ **Binary deployment** — Both aliyun (x86_64) and N1 (aarch64) meshdesk binaries operational
4. ✅ **P2P gossip** — Both nodes start gossip layer independently (aliyun: port 7946, 2 seeds; N1: port 7946, 1 seed)
5. ✅ **Relay subsystem** — aliyun: Smux relay on 0x524C + relay session manager (maxCircuits=1024); N1: NAT relay fallback active
6. ✅ **Exit node** — Both nodes: exit node active with allowed ports
7. ✅ **NAT traversal** — N1: STUN discovery (symmetric NAT, endpoint 120.243.147.66)
8. ✅ **TUN** — aliyun: mesh0 up with 10.100.0.1/24
9. ✅ **SOCKS5 API** — N1: `/api/proxy/socks5/status` returns full topology + config (path_mode=auto)
10. ✅ **Multipath perf benchmarks** — Throughput (395–433 MB/s), scaling (O(K) verified), failover (instant, 0% loss), fairness (91/9 weighted split)

---

## 5. What Is Blocked (Requires SG Change)

1. ❌ **Multi-path throughput** — Real-device throughput comparison (single vs multi-path) over actual relay circuits
2. ❌ **Failover latency** — End-to-end failover timing when one relay path fails mid-stream
3. ❌ **Chunk distribution** — Real relay path fairness (round-robin, weighted) with actual network jitter
4. ❌ **Path health tracking** — Real relay health degradation and recovery over actual network conditions
5. ❌ **Circuit lifecycle** — Circuit establishment, keepalive, orphan detection between real nodes
6. ❌ **Reality TLS proxy path** — End-to-end phone→entry→relays→exit flow

---

## 6. Resolution Required

To unblock cross-node multipath testing, the Alibaba Cloud security group for ECS instance `iZbp10emrt4l28g3ohkq59Z` (203.0.113.10) must be modified to allow:

| Port | Protocol | Purpose |
|------|----------|---------|
| 7946 | TCP+UDP | P2P gossip (memberlist) |
| 52888 | TCP+UDP | MuxTransport (mesh + gossip multiplexing) |
| 18800 | TCP+UDP | Reality TLS + MuxTransport (shared node mode) |
| 8080 | TCP | Web UI (optional, for Dashboard) |

This can be done via:
- Alibaba Cloud Console → ECS → Security Groups → Add rules
- OR `aliyun` CLI tool (if installed): `aliyun ecs AuthorizeSecurityGroup ...`

Once SG rules are added and nodes can mutually gossip, the full multipath test suite can proceed:
1. Configure at least 2 nodes as relay candidates
2. Enable `path_selection.mode: auto` on the entry node
3. Establish SOCKS5 proxy session
4. Measure throughput, latency, packet loss for single-path vs multi-path
5. Test failover by killing one relay node mid-stream

---

## 7. Test Inventory

### Commands Used
```bash
# Unit tests
cd /root/meshdesk
go test ./internal/proxy/ -count=1 -timeout 120s -v
go test ./internal/proxy/ -count=1 -race

# Multipath-specific tests
go test ./internal/proxy/ -count=1 -timeout 120s \
  -run "TestPathSelector|TestDispatcher|TestFailover|TestAssignment|TestMultiPath" -v

# Proxy API (N1 — open access)
curl -s http://127.0.0.1:8080/api/proxy/status
curl -s http://127.0.0.1:8080/api/proxy/socks5/status

# Deploy to aliyun
scp meshdesk root@203.0.113.10:/etc/meshdesk/meshdesk
# Deploy to N1
sshpass -p '...' scp -P 22000 meshdesk-arm64 yzy806806@fn.example.com:/usr/local/bin/meshdesk

# Start meshdesk
nohup /etc/meshdesk/meshdesk --web -config /etc/meshdesk/config.yaml > /etc/meshdesk/meshdesk.log 2>&1 &

# UFW rules (aliyun)
ufw allow 7946/tcp && ufw allow 7946/udp
ufw allow 52888/tcp && ufw allow 52888/udp
ufw allow 18800/tcp && ufw allow 18800/udp
ufw allow 8080/tcp
```

### Files Modified
- `/home/yzy806806/meshdesk-config/config.yaml` on N1: Fixed dangling `advertise_endpoint`, set `path_selection.mode: auto`, added `tun_enabled: true`
- `/etc/meshdesk/config.yaml` on aliyun: No changes (binary redeployed)
- UFW rules on aliyun: Added ports 52888, 7946, 8080, 18800

### Test Results Summary
| Metric | Value |
|--------|-------|
| Total proxy tests | 391 |
| Failures | 0 |
| Data races | 0 |
| Multipath-specific tests | 44 |
| Nodes reachable | 2/3 (aliyun + N1) |
| Nodes with P2P gossip | 2/2 |
| Nodes with relay active | 2/2 |
| Nodes with exit active | 2/2 |
| Cross-node gossip | BLOCKED (SG) |
| Available relay paths | 0 |
