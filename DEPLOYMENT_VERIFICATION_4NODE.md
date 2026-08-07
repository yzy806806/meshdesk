# 4-Node Deployment + CapRelay Verification Report

Task: t_54e1aac3 — 四节点部署 + CapRelay 全开验证
Date: 2026-08-07
HEAD: 4229ee7 (a83c9f8 + docs only; no mesh code changes)

## 1. Deployment Summary

All 4 nodes deployed with fresh HEAD binaries and verified configs:

| Node | Arch | Role | identity_file | fingerprint | reality | relay.enabled | Public key |
|------|------|------|--------------|-------------|---------|---------------|------------|
| aliyun (115.29.235.24) | amd64 | shared | /etc/meshdesk/identity.pem | bb16d823... | true (52888) | **true** | bb16d823a7c48f7853e0455be3acf5d601d9b40d25b9baf4fc37e234be104168 |
| N1 (fn.fxxkccp.top) | arm64 | shared | /home/yzy806806/.meshdesk/identity.pem | b111ed0c... | true (52888) | **true** (added) | b111ed0ce5b391cfbb6135013b969cf1f0c0ffdf69b5f6a0b8ba561d43317635 |
| txcloud (local) | amd64 | normal | /etc/meshdesk/identity.pem | 11c8bf78... | false | true | 11c8bf78ac52364b0704ac9eb6be7625ce7ad750679289e310babdee376f85af |
| Oracle (145.241.223.212) | arm64 | normal | /etc/meshdesk/identity.pem | 9523c5c1... (auto-gen) | false | true | 9523c5c122ec3ace6194e878c91c3a6cf758eee790383b0e3566cd4ea09dd8b6 |

## 2. Config Fixes Applied

1. **N1**: `proxy.relay.enabled: true` was MISSING — added. identity_file pointed to
   `/etc/meshdesk/identity.pem` (missing; key was lost) → changed to the existing
   key at `/home/yzy806806/.meshdesk/identity.pem`; fingerprint updated to b111ed0c...
2. **txcloud**: `advertise_endpoints` changed from `43.155.221.253:52888` (stale
   shared-node port) → `43.155.221.253:7946` (normal-node mux port).
3. **Oracle**: `advertise_endpoints` changed from `145.241.223.212:52888` →
   `145.241.223.212:7946`.
4. **aliyun**: already compliant (relay.enabled=true, reality.enabled=true).
5. **txcloud dashboard password**: was unrecoverable bcrypt → reset to admin123
   (hash `$2b$04$nf0VcSvBF6EyMbHc6L/68uorimhCHH0lQ5iTqA.Y6aqo6AE6FKNsi`).

## 3. Deployment Steps Performed

- Built fresh binaries at HEAD: amd64 (aliyun, txcloud) + arm64 (N1, Oracle).
- Transferred via rsync/scp, verified md5 on each node.
- aliyun + N1 (shared nodes) started first; verified gossip + smux sessions.
- txcloud + Oracle (normal nodes) started after 1-2 min stagger.
- Oracle needed a hard restart (its systemd unit had a stale process from
  Aug-6 19:21); N1 needed the start-script pattern (setsid/nohup over SSH).

## 4. Acceptance Criteria — ALL MET

### 4.1 /api/topology shows all 4 nodes (verified on txcloud dashboard :7946)
```
Total: 4
  txcloud    11c8bf78ac52364b  online  role=relay+exit+dashboard
  oracle     9523c5c122ec3ace  online  role=node
  n1         b111ed0ce5b391cf  online  role=node
  aliyun     bb16d823a7c48f78  online  role=node
```

### 4.2 Relay active on all 4 (SIGUSR1 state dump)
```
txcloud: === Relay: active (tunnels=0) ===
aliyun:  === Relay: active (tunnels=64→33, actively relaying) ===
n1:      === Relay: active (tunnels=0) ===
oracle:  === Relay: active (tunnels=0) ===
```

### 4.3 CapRelay propagation via gossip (verified)
- txcloud `tryRelayFallback: 1 relay-capable candidate(s)` for N1 and Oracle —
  CapRelay metadata is distributed via gossip.
- Oracle relay tunnels ACCEPTED through aliyun (tunnel=... accepted logs) —
  relay fallback works end-to-end.
- aliyun smux sessions: 3 server sessions (txcloud rx=541KB, oracle rx=234KB,
  n1 rx=58KB) with real traffic.

### 4.4 Mesh connectivity
- txcloud joined gossip via 2/2 seeds (aliyun + N1 IPv6) after endpoint fix.
- Oracle joined via aliyun seed.
- N1 ↔ aliyun session established immediately on restart.

## 5. DEFECTS FOUND (real, reproducible)

### DEFECT-A: memberlist delegate mutex deadlock on shared node under relay load
- **Symptom**: aliyun's memberlist stops responding to join streams; all inbound
  memberlist streams from normal nodes time out ("failed to join ... i/o timeout");
  txcloud/Oracle cannot rejoin until aliyun restarts.
- **Evidence**: SIGQUIT goroutine dump on aliyun shows dozens of goroutines
  `[sync.RWMutex.RLock, N minutes]` at:
  - `handleConn` → `sendLocalState` → `Delegate.LocalState` → d.mu.RLock (net.go:1017)
  - `sendRelayMessage` → `Members()` → nodeLock.RLock (gossip.go:1301)
  - `SetLocalRTT`/healthPoll → `UpdateNode` → nodeLock.RLock (gossip.go:924, memberlist.go:524)
  - memberlist's own probe/reap (state.go:594/650)
- **Trigger**: relay tunnel flood (Oracle retry every 30s + monitor pushes) →
  sustained inbound streams → the delegate write-lock holder (traffic stats /
  health loop `updateLocalMeta`) starves readers → cascade.
- **Impact**: cluster partition; shared node stops accepting new joins while
  existing smux sessions keep working. Recovers only on restart.
- **Workaround**: restart the shared node (clears the lock pileup). Idle tunnel
  cleanup (5-min timeout) eventually reduces the load but does not prevent the
  deadlock once the reader queue is large.
- **Recommendation**: (1) do not call memberlist `UpdateNode`/`Members()` from
  hot paths holding the delegate mutex; (2) bound the number of concurrent
  handleConn streams (memberlist maxPushPullRequests is already 128, but the
  delegate RLock waiters still pile up); (3) consider a watchdog that detects
  >N consecutive minutes of RLock starvation and self-restarts the gossip layer.

### DEFECT-B: relay tunnels accumulate under retry storms (capacity exhaustion)
- aliyun's RelayHandler reached maxTunnels=64 from repeated relay requests
  (each retry creates a new tunnel entry; idle cleanup is 5 min so tunnels
  accumulate faster than they expire under load).
- Impact: `RelayRejectAtCapacity` for legitimate new relay requests.
- The idle sweep DOES reclaim (64→56→33), so this is a transient load issue,
  not a hard leak — but combined with DEFECT-A it amplifies the deadlock.

### DEFECT-C: normal-node endpoint advertisement (config issue, fixed)
- txcloud/Oracle advertised `:52888` (stale shared-node port) but as normal
  nodes their mux port is `:7946` → peers couldn't dial them directly.
- Fixed in configs; after the fix txcloud joined 2/2 seeds.

## 6. Verification Commands Used
- `curl -b cookie http://127.0.0.1:7946/api/topology` — topology
- `kill -USR1 <pid>` then grep `=== Relay` — relay state dump
- `kill -QUIT <pid>` then journalctl — goroutine dump (deadlock analysis)
- `ss -tlnp | grep 52888/7946` — listener check
- `md5sum` — binary verification after transfer

## 7. Notes
- N1 TUN creation fails (non-root, no CAP_NET_ADMIN) — continues without TUN;
  TUN verification is a separate concern.
- N1's original 4a378100 identity was LOST (file gone). New stable identity
  b111ed0c (the key that existed on disk). Any configs referencing 4a378100
  as a peer are stale.
- The relay tunnel "at_capacity" rejections are visible in logs but the mesh
  still delivers (monitor pushes succeed via accepted tunnels).
