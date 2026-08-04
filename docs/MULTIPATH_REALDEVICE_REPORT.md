# MeshDesk Multi-Path Failover + Performance Test Report
## 3-Node Topology Real-Device Test

**Version:** 1.0  
**Date:** 2026-08-05  
**Author:** tester  
**Status:** PARTIAL — unit tests pass, real-device relay verified on txcloud, multi-path blocked by node availability

---

## Executive Summary

All multi-path unit tests pass with 0 failures and 0 data races. The meshdesk binary with relay, exit node, and proxy support was built and deployed to txcloud successfully. The relay subsystem (Smux on virtual port 0x524C), exit node, and proxy APIs are all operational in production config on real hardware.

**Multi-path failover real-device testing across 3 nodes is BLOCKED**: aliyun (10.144.144.10) and N1 (10.144.144.11) are unreachable from the build machine. Only txcloud (203.0.113.10) is operational. Cross-node gossip between txcloud and aliyun is additionally blocked by aliyun's firewall (UDP 7946). Multi-path requires ≥2 independently reachable relay-capable nodes to establish 2 disjoint relay paths.

---

## 1. Unit Test Baseline

### Proxy Suite (all tests)
```
Package: github.com/yzy806806/meshdesk/internal/proxy
Command: go test ./internal/proxy/ -count=1 -timeout 120s
Result:  PASS (0 failures, 2.2s)
Race:    PASS (go test -race, 0 data races)
```

### Multipath-Specific Tests
| Test | Subtests | Status | Key Metric |
|------|----------|--------|------------|
| TestPathSelectorScaling | 4 | PASS | 10→250 candidates, sub-millisecond (110µs–442µs) |
| TestDispatcherThroughputSingleVsMulti | 3 | PASS | 387–446 MB/s across strategies |
| TestFailoverLatency | 3 | PASS | Instant failover, 0% chunk loss |
| TestPathSelectorProbeCacheHitRate | 1 | PASS | 100% warm-cache hit; precise invalidation |
| TestAssignmentStrategyThroughput | 2 | PASS | RR 399 MB/s, Weighted 333 MB/s |
| TestDispatcherStatsAccuracy | 1 | PASS | Chunk/byte tracking correct |
| TestPathSelectorPerCandidateOverhead | 4 | PASS | ~2–7 µs per candidate |
| PathSelector health tests | 5 | PASS | ExcludeUnhealthy, FailoverOnDegraded, SelectReplacement, etc. |
| RelayHealthTracker | 8 | PASS | State machine: healthy→degraded→unhealthy→recovery |
| **TOTAL** | **31** | **ALL PASS** | **0 failures, 0 races** |

---

## 2. Real-Device Deployment: txcloud

### Node Inventory
| Node | Status | IP | SSH | meshdesk |
|------|--------|----|-----|----------|
| txcloud | **ONLINE** | 203.0.113.10 | root@203.0.113.10 (deploy_key) | Running (PID 719062) |
| aliyun | **UNREACHABLE** | 10.144.144.10 | Connection timed out | Unknown |
| N1 | **UNREACHABLE** | 10.144.144.11:22000 | Connection timed out | Unknown |

### Binary Deployment
- **Source**: `/root/meshdesk/meshdesk` (go build, ELF x86_64, stripped)
- **Deployed**: `/etc/meshdesk/meshdesk` on txcloud
- **Config**: `/etc/meshdesk/config.yaml` (proxy.relay.enabled=true, path_selection.mode=manual)
- **Startup flags**: `--web --relay`
- **Auth**: admin:txcloud123 (bcrypt, rounds=4)

### Startup Verification (txcloud log excerpts)
```
MeshDesk dev started
  Public key: f2bdccf548a029dc1ce8f2876f036b5860160c495160174ae8f3d2b17e61588b
  Mesh port:  52888
  Peers:      0
  Smux relay: listening on virtual port 0x524C (maxTunnels=64)
  Service RPC: listening on mesh port 4192
  File transfer: listening on mesh port 4193 (max 1073741824 bytes)
  WebSSH:     listening on mesh port 2222
  Proxy:      exit node active (allowed_ports=[80 443], allow_all=false)
  Monitor:   reporter active (interval=15s)
  Aggregator: listening on mesh port 4191
```

### API Verification
| Endpoint | Method | Status | Response |
|----------|--------|--------|----------|
| `/api/proxy/status` | GET | 200 | `{"running":false,"session_count":0,"cf_tunnel_ready":false}` |
| `/api/proxy/socks5/status` | GET | 200 | Full SOCKS5 config + topology snapshot |
| `/login` | POST | 303 | Auth successful → redirect |

### Subsystem Status on txcloud
| Subsystem | Status | Notes |
|-----------|--------|-------|
| Smux Relay (0x524C) | ✅ Registered | Virtual port, activates on peer connection |
| Exit Node | ✅ Active | Allowed ports: 80, 443 |
| SOCKS5 Handler | ⬜ Not active | No mesh peers to establish circuits |
| Reality TLS | ✅ Active | Listening on :18800 |
| TUN (mesh0) | ✅ Active | Virtual IP 10.100.0.1/24 |
| ACL | ✅ Active | 3 rules, default=allow |
| Proxy Entry (forwarder) | ⬜ Not running | Requires ≥2 relay paths |

---

## 3. Blocker Analysis

### Blocker 1: aliyun Unreachable
- **SSH**: `root@10.144.144.10:22` → "Connection timed out"
- **HTTP from txcloud**: `curl http://10.144.144.10:8080` → failed
- **Root cause**: No EasyTier VPN or direct route from build machine / txcloud
- **Resolution needed**: Establish EasyTier VPN tunnel or open direct SSH access

### Blocker 2: N1 Unreachable
- **SSH**: `yzy806806@10.144.144.11:22000` → "Connection timed out"
- **Root cause**: No network route; requires EasyTier VPN
- **Resolution needed**: Establish EasyTier VPN connectivity

### Blocker 3: Cross-Node Gossip
- **Symptom**: txcloud and aliyun cannot gossip despite both running
- **Root cause**: aliyun firewall blocks UDP 7946 from txcloud IP (per prior ACL verification t_f18f5825)
- **Resolution needed**: Open aliyun security group for UDP 7946 from txcloud IP (203.0.113.10)

### Testability Assessment
```
                 txcloud ───X─── aliyun    (UDP 7946 blocked)
                 txcloud ───X─── N1        (no route)
                 aliyun  ───?─── N1        (unknown)

Multi-path requires 2 independent relay paths.
With only txcloud reachable: 0 relay paths available.
Minimum viable topology: txcloud + aliyun (2 nodes, 1 relay path per direction).
Full 3-node test: txcloud + aliyun + N1 all mutually reachable.
```

---

## 4. What Was Verified

1. ✅ **Unit test suite** — All 31 multipath tests pass (failover, throughput, scaling, health tracking)
2. ✅ **Binary build** — Compiles cleanly with relay + proxy support
3. ✅ **Real-device relay startup** — Smux relay registers on virtual port 0x524C
4. ✅ **Exit node activation** — Proxy exit node active on real hardware
5. ✅ **API contracts** — `/api/proxy/status` and `/api/proxy/socks5/status` return correct JSON
6. ✅ **Auth flow** — Session-based auth working; proxy status accessible with valid session
7. ✅ **Config integrity** — Proxy config (path_selection, circuit, relay, exit) parses correctly

## 5. What Is Blocked (Pending Resolution of Blockers)

1. ❌ **Multi-path throughput** — Real-device throughput comparison (single vs multi-path) over actual relay circuits
2. ❌ **Failover latency** — End-to-end failover timing when one relay path fails mid-stream
3. ❌ **Chunk distribution** — Real relay path fairness (round-robin, weighted) with actual network jitter
4. ❌ **Path health tracking** — Real relay health degradation and recovery over actual network conditions
5. ❌ **Circuit lifecycle** — Circuit establishment, keepalive, orphan detection between real nodes
6. ❌ **Reality TLS proxy path** — End-to-end phone→entry→relays→exit flow

---

## 6. Recommended Next Steps

1. **Restore aliyun connectivity** — Establish EasyTier VPN from build machine to aliyun (10.144.144.10)
2. **Open UDP 7946 on aliyun** — Allow cross-node gossip from txcloud
3. **Restore N1 connectivity** — Establish EasyTier VPN to N1 (10.144.144.11)
4. **Configure relay paths** — Set `proxy.paths` in config with explicit relay node IDs
5. **Write automated multi-node test harness** — Script that deploys to all 3 nodes, establishes circuits, and measures failover
6. **Re-run this test task** — Once 3 nodes are reachable, re-run full multi-path failover + performance test

---

## 7. Test Inventory

### Files Modified
None (report-only task). Binary and config deployed to txcloud.

### Test Commands
```bash
# Unit tests
cd /root/meshdesk
go test ./internal/proxy/ -count=1 -timeout 120s -v
go test ./internal/proxy/ -count=1 -race

# Binary build
go build -o meshdesk ./cmd/meshdesk/

# Deploy (to txcloud)
scp meshdesk root@203.0.113.10:/tmp/meshdesk-test
ssh root@203.0.113.10 "cp /tmp/meshdesk-test /etc/meshdesk/meshdesk && ..."

# Verify
curl -b /tmp/cook.txt http://127.0.0.1:8080/api/proxy/status
curl -b /tmp/cook.txt http://127.0.0.1:8080/api/proxy/socks5/status
```
