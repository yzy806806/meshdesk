# Aliyun Multi-Endpoint Interconnection Test Plan

**Version:** 1.0
**Author:** tester
**Date:** 2026-07-30
**References:**
- `docs/MESHDESK_V2_DESIGN.md` §Testing Requirements (lines 305-327)
- `docs/TESTING_REPORT_V2.md` (prior 4-node test, gossip join partial success)
- `docs/NETWORKING_GAP_ANALYSIS.md` (shared-node + relaying architecture)
- `docs/GOSSIP_REDESIGN_SPEC.md` §8 Acceptance Criteria
- `internal/p2p/config.go` (P2pConfig, AdvertiseEndpoints)
- `internal/p2p/gossip.go` (resolveAdvertiseAddr:382, announceLocalEndpoint, handleDirectProbe)
- `internal/p2p/events.go` (NotifyJoin, NotifyUpdate, endpoint propagation)

---

## 1. Test Objective

Verify that the **Aliyun meshdesk node (pure IPv4)** can join the gossip cluster with **txcloud** and **N1** (both dual-stack IPv4+IPv6) using the **multi-endpoint advertisement** feature, so that:

1. Aliyun advertises its sole IPv4 endpoint (`203.0.113.10:52888`) via gossip.
2. txcloud and N1 each advertise multiple endpoints (public IPv6 + mesh IPv4).
3. All nodes complete memberlist PushPull state sync and propagate endpoints bidirectionally.
4. Aliyun appears in the `/api/topology` response on txcloud with correct endpoints and non-zero metrics.

Per MESHDESK_V2_DESIGN.md §Testing Requirements: **unit tests alone are insufficient** — this test must run on real machines with log evidence.

---

## 2. Test Environment

### 2.1 Node Inventory

| Node    | Hostname                  | Architecture | EasyTier Mesh IP | Public IP              | MuxTransport Port | Dashboard | IPv4/IPv6 |
|---------|---------------------------|-------------|------------------|------------------------|-------------------|-----------|-----------|
| aliyun  | iZbp10emrt4l28g3ohkq59Z  | amd64       | 10.144.144.10    | 203.0.113.10          | 52888             | :8080     | IPv4 only |
| txcloud | VM-0-4-ubuntu             | amd64       | 10.144.144.20    | `<txcloud-public-ipv6>` | 52888             | :8080     | Dual-stack|
| N1      | N1                        | arm64       | 10.144.144.11    | `<n1-public-ipv6>`      | 52888             | :8080     | Dual-stack|

**N1 access:** `ssh -p 22000 yzy806806@10.144.144.11`

### 2.2 Network Topology

```
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│     aliyun       │        │     txcloud      │        │       N1         │
│  iZbp10emrt4l... │        │  VM-0-4-ubuntu   │        │  (arm64)          │
│                  │        │                  │        │                  │
│ Public:          │        │ Public:          │        │ Public:          │
│  203.0.113.10   │        │  <ipv6-addr>     │        │  <ipv6-addr>     │
│ Mesh: 10.144.144.10      │ Mesh: 10.144.144.20      │ Mesh: 10.144.144.11
│ MuxTransport:52888│       │ MuxTransport:52888│       │ MuxTransport:52888│
│                  │        │ Dashboard:8080    │        │ Dashboard:8080    │
│   IPv4 ONLY      │        │   DUAL-STACK      │        │   DUAL-STACK      │
└────────┬─────────┘        └────────┬─────────┘        └────────┬─────────┘
         │                           │                           │
         │     EasyTier Mesh VPN     │                           │
         │       10.144.144.0/24     │                           │
         └───────────────────────────┴───────────────────────────┘
```

**Key network characteristics:**

- **EasyTier mesh VPN** provides full-mesh L3 IPv4 connectivity between all 3 nodes on the `10.144.144.0/24` subnet. All mesh IPs are mutually reachable.
- **Aliyun is IPv4-only** — it has NO IPv6 address. This means it cannot reach IPv6-only endpoints on txcloud or N1. Multi-endpoint is essential here: txcloud and N1 must advertise at least one IPv4 endpoint (their mesh IP) so Aliyun has a reachable address.
- **MuxTransport** on port 52888 multiplexes Reality TLS (byte `0x16`) and memberlist gossip (all other first bytes) over a single TCP/UDP listener. Both protocols share the same port.
- **No Aliyun security group changes are needed** for inter-node traffic when using EasyTier mesh — all gossip traffic routes through the VPN tunnel.

### 2.3 Public IP Reachability (Beyond EasyTier)

If the test extends to direct public-IP connectivity (bypassing EasyTier):

| Direction          | Protocol | Port  | Source        | Purpose                        |
|--------------------|----------|-------|---------------|--------------------------------|
| Inbound to aliyun  | TCP      | 52888 | txcloud/N1    | MuxTransport (gossip + Reality)|
| Inbound to aliyun  | UDP      | 52888 | txcloud/N1    | memberlist UDP ping            |
| Inbound to aliyun  | TCP      | 8080  | trusted       | Dashboard (if externally needed)|

---

## 3. Prerequisites

### 3.1 Binary Build

Build meshdesk for each target architecture:

```bash
cd /root/meshdesk

# txcloud + aliyun: amd64
GOOS=linux GOARCH=amd64 go build -o build/meshdesk-amd64 .

# N1: arm64
GOOS=linux GOARCH=arm64 go build -o build/meshdesk-arm64 .
```

**Verify:** `file build/meshdesk-amd64` → `ELF 64-bit LSB executable, x86-64`
**Verify:** `file build/meshdesk-arm64` → `ELF 64-bit LSB executable, ARM aarch64`

### 3.2 Pre-Deployment Checks

Run the full test suite before deploying:

```bash
cd /root/meshdesk
go build ./...          # Must pass with zero errors
go vet ./...            # Must pass with zero warnings
go test ./... -count=1  # All packages must PASS
```

Critical tests for multi-endpoint feature:

```bash
go test ./internal/p2p/ -run "AdvertiseEndpoints|ResolveAdvertiseAddr|AnnounceLocalEndpoint" -v
go test ./internal/mesh/ -run "MuxDemux|MuxTransport" -v
```

### 3.3 Reality Key Generation

Generate Reality X25519 keypairs for each node that will serve as Reality TLS entry points:

```bash
cd /root/meshdesk && go run ./tools/gen_reality_key.go
```

Copy the generated keys into each node's config under `reality.private_key` and `reality.public_key`.

### 3.4 Node-Specific Requirements

**All nodes:**
- EasyTier mesh VPN must be running and healthy: `systemctl status easytier` or `easytier-cli peer`
- MuxTransport port 52888 must be free (no stale meshdesk processes): `kill $(pgrep meshdesk) 2>/dev/null`
- Config directory must exist: `mkdir -p /etc/meshdesk`

**Aliyun (IPv4-only):**
- Verify public IP is reachable: `curl -s https://ifconfig.me` → shows `203.0.113.10`
- Verify NO IPv6 connectivity: `ping6 -c 1 google.com` should fail

**N1 (arm64, SSH-only):**
- Access via: `ssh -p 22000 yzy806806@10.144.144.11`
- Verify arm64 architecture: `uname -m` → `aarch64`

---

## 4. Config Examples

### 4.1 Aliyun (`/etc/meshdesk/config.yaml`)

Aliyun is **pure IPv4**. It advertises exactly one endpoint — its public IPv4 address. All other nodes reach it via this address (either directly or through EasyTier mesh routing to the mesh IP if `10.144.144.10` is also advertised).

```yaml
node:
  web: ":8080"
  hostname: "iZbp10emrt4l28g3ohkq59Z"

mesh:
  port: 52888
  gossip_port: 52888

p2p:
  enabled: true
  seeds:
    - "10.144.144.20:52888"   # txcloud mesh IP
    - "10.144.144.11:52888"   # N1 mesh IP
  gossip_bind_addr: "0.0.0.0"
  gossip_port: 52888
  nat_traversal: false        # Public IP node, no NAT traversal needed
  advertise_endpoints:
    - "203.0.113.10:52888"   # Public IPv4 (reachable by all)

reality:
  enabled: true
  listen_port: 52888
  short_ids:
    - "<hex-short-id>"
  private_key: "<reality-private-key>"
  server_names:
    - "www.apple.com"

auth:
  web_users:
    - username: admin
      password_hash: "<bcrypt-hash>"

monitoring:
  interval: 15
```

### 4.2 txcloud (`/etc/meshdesk/config.yaml`)

txcloud is **dual-stack**. It advertises TWO endpoints: its public IPv6 and its EasyTier mesh IPv4. Aliyun (IPv4-only) can reach it via the mesh IP; IPv6-capable nodes can reach it via the public IPv6.

```yaml
node:
  web: ":8080"
  hostname: "VM-0-4-ubuntu"

mesh:
  port: 52888
  gossip_port: 52888

p2p:
  enabled: true
  seeds:
    - "10.144.144.10:52888"   # aliyun mesh IP
  gossip_bind_addr: "0.0.0.0"
  gossip_port: 52888
  nat_traversal: false
  advertise_endpoints:
    - "[<txcloud-public-ipv6>]:52888"  # Public IPv6
    - "10.144.144.20:52888"            # EasyTier mesh IPv4

reality:
  enabled: true
  listen_port: 52888
  short_ids:
    - "<hex-short-id>"
  private_key: "<reality-private-key>"
  server_names:
    - "www.apple.com"

auth:
  web_users:
    - username: admin
      password_hash: "<bcrypt-hash>"

monitoring:
  interval: 15
```

### 4.3 N1 (`/etc/meshdesk/config.yaml`)

N1 is **dual-stack** (arm64). Same dual-endpoint pattern as txcloud.

```yaml
node:
  web: ":8080"
  hostname: "N1"

mesh:
  port: 52888
  gossip_port: 52888

p2p:
  enabled: true
  seeds:
    - "10.144.144.10:52888"   # aliyun mesh IP
  gossip_bind_addr: "0.0.0.0"
  gossip_port: 52888
  nat_traversal: false
  advertise_endpoints:
    - "[<n1-public-ipv6>]:52888"   # Public IPv6
    - "10.144.144.11:52888"        # EasyTier mesh IPv4

reality:
  enabled: true
  listen_port: 52888
  short_ids:
    - "<hex-short-id>"
  private_key: "<reality-private-key>"
  server_names:
    - "www.apple.com"

auth:
  web_users:
    - username: admin
      password_hash: "<bcrypt-hash>"

monitoring:
  interval: 15
```

### 4.4 Multi-Endpoint Mechanism (Code Reference)

The multi-endpoint feature works as follows:

1. **`config.go:87-91`** — `P2pConfig.AdvertiseEndpoints []string` holds the list of endpoints from config.
2. **`gossip.go:197-225`** — `announceLocalEndpoint()` uses `cfg.AdvertiseEndpoints` directly when set, then calls `mergeEndpoints()` to deduplicate with reactively-learned addresses.
3. **`gossip.go:370-403`** — `resolveAdvertiseAddr()` selects the first IPv4 endpoint from `AdvertiseEndpoints` for memberlist's own `AdvertiseAddr` field (hashicorp memberlist uses a TCP transport that is IPv4-native).
4. **`events.go:105-172`** — `NotifyJoin()` propagates all `meta.Endpoints` to the PeerManager via `wg.Connect(publicKey, endpoints)`.
5. **`events.go:234-297`** — `NotifyUpdate()` detects endpoint changes and calls `wg.UpdateEndpoints()` when the endpoint list changes.

This means:
- **Aliyun** advertises `["203.0.113.10:52888"]` — one endpoint, IPv4.
- **txcloud** advertises `["[<ipv6>]:52888", "10.144.144.20:52888"]` — two endpoints (IPv6 + IPv4).
- **N1** advertises `["[<ipv6>]:52888", "10.144.144.11:52888"]` — two endpoints (IPv6 + IPv4).

Aliyun's `resolveAdvertiseAddr()` picks `203.0.113.10` (the first and only IPv4 endpoint). txcloud's picks `10.144.144.20` (the first IPv4 endpoint in its list). N1's picks `10.144.144.11`.

---

## 5. Test Steps

### Phase 1: Build and Deploy

#### Step 1.1 — Build binaries

```bash
cd /root/meshdesk
GOOS=linux GOARCH=amd64 go build -o build/meshdesk-amd64 .
GOOS=linux GOARCH=arm64 go build -o build/meshdesk-arm64 .
```

#### Step 1.2 — Deploy to txcloud (local)

txcloud is the machine running this test session. Deploy directly:

```bash
cp build/meshdesk-amd64 /usr/local/bin/meshdesk
mkdir -p /etc/meshdesk
cp /path/to/txcloud-config.yaml /etc/meshdesk/config.yaml
```

#### Step 1.3 — Deploy to Aliyun (via EasyTier mesh)

```bash
scp build/meshdesk-amd64 root@10.144.144.10:/usr/local/bin/meshdesk
scp /path/to/aliyun-config.yaml root@10.144.144.10:/etc/meshdesk/config.yaml
```

#### Step 1.4 — Deploy to N1 (via SSH over EasyTier)

```bash
scp -P 22000 build/meshdesk-arm64 yzy806806@10.144.144.11:/tmp/meshdesk
ssh -p 22000 yzy806806@10.144.144.11 'sudo cp /tmp/meshdesk /usr/local/bin/meshdesk && sudo chmod +x /usr/local/bin/meshdesk'
scp -P 22000 /path/to/n1-config.yaml yzy806806@10.144.144.11:/tmp/config.yaml
ssh -p 22000 yzy806806@10.144.144.11 'sudo mkdir -p /etc/meshdesk && sudo cp /tmp/config.yaml /etc/meshdesk/config.yaml'
```

### Phase 2: Startup

#### Step 2.1 — Start meshdesk on txcloud

```bash
# Stop any stale process
kill $(pgrep meshdesk) 2>/dev/null; sleep 1

# Start with output to log file
/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml 2>&1 | tee /tmp/meshdesk-txcloud.log &
```

**Expected logs (within 10s):**
```
[p2p] endpoint learning: announced 2 local endpoint(s): [[<ipv6>]:52888 10.144.144.20:52888] (merged 0 existing)
[p2p] gossip layer started (bind 0.0.0.0:52888, advertise 10.144.144.20)
```

#### Step 2.2 — Start meshdesk on Aliyun

```bash
ssh root@10.144.144.10 'kill $(pgrep meshdesk) 2>/dev/null; sleep 1'
ssh root@10.144.144.10 '/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml 2>&1 | tee /tmp/meshdesk-aliyun.log &'
```

**Expected logs:**
```
[p2p] endpoint learning: announced 1 local endpoint(s): [203.0.113.10:52888] (merged 0 existing)
[p2p] gossip layer started (bind 0.0.0.0:52888, advertise 203.0.113.10)
[p2p/memberlist] Initiating push/pull sync with: 10.144.144.20:52888
```

#### Step 2.3 — Start meshdesk on N1

```bash
ssh -p 22000 yzy806806@10.144.144.11 'sudo kill $(pgrep meshdesk) 2>/dev/null; sleep 1'
ssh -p 22000 yzy806806@10.144.144.11 'sudo /usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml 2>&1 | tee /tmp/meshdesk-n1.log &'
```

**Expected logs:**
```
[p2p] endpoint learning: announced 2 local endpoint(s): [[<n1-ipv6>]:52888 10.144.144.11:52888] (merged 0 existing)
[p2p] gossip layer started (bind 0.0.0.0:52888, advertise 10.144.144.11)
```

### Phase 3: Gossip Discovery Verification

#### Step 3.1 — Allow gossip to converge (wait 30s)

```bash
sleep 30
```

#### Step 3.2 — Verify memberlist membership on txcloud

```bash
# Check topology API — all 3 nodes should appear
curl -s http://localhost:8080/api/topology | python3 -m json.tool
```

**Expected response structure:**
```json
{
  "nodes": [
    {
      "public_key": "0bfeda34...",
      "hostname": "VM-0-4-ubuntu",
      "endpoints": ["<ipv6>:52888", "10.144.144.20:52888"],
      "status": "online",
      "cpu": 0.5,
      "mem": 45.2
    },
    {
      "public_key": "de52c6da...",
      "hostname": "iZbp10emrt4l28g3ohkq59Z",
      "endpoints": ["203.0.113.10:52888"],
      "status": "online",
      "cpu": 4.4,
      "mem": 56.1
    },
    {
      "public_key": "61ac6321...",
      "hostname": "N1",
      "endpoints": ["<n1-ipv6>:52888", "10.144.144.11:52888"],
      "status": "online",
      "cpu": 1.2,
      "mem": 30.5
    }
  ],
  "edges": [...]
}
```

**Node count check:**
```bash
curl -s http://localhost:8080/api/topology | jq '.nodes | length'
# Expected: 3
```

#### Step 3.3 — Verify Aliyun's endpoints on txcloud

```bash
curl -s http://localhost:8080/api/topology | jq '.nodes[] | select(.hostname | contains("iZbp")) | .endpoints'
# Expected: ["203.0.113.10:52888"]
```

#### Step 3.4 — Verify txcloud shows multi-endpoint for both remote nodes

```bash
# Both remote nodes should have correct endpoint counts
curl -s http://localhost:8080/api/topology | jq '.nodes[] | select(.hostname | contains("iZbp") or contains("N1")) | {hostname, endpoint_count: (.endpoints | length)}'
# Expected: aliyun endpoint_count=1, N1 endpoint_count=2
```

### Phase 4: Multi-Endpoint Propagation

#### Step 4.1 — Verify Aliyun log: endpoint announcement

```bash
ssh root@10.144.144.10 'grep "endpoint learning" /tmp/meshdesk-aliyun.log'
```

**Expected:**
```
[p2p] endpoint learning: announced 1 local endpoint(s): [203.0.113.10:52888] (merged 0 existing)
```

#### Step 4.2 — Verify Aliyun log: push/pull sync with all seeds

```bash
ssh root@10.144.144.10 'grep -E "push/pull sync|JoinSeeds" /tmp/meshdesk-aliyun.log'
```

**Expected:** At least two successful sync attempts — one to txcloud (`10.144.144.20:52888`) and one to N1 (`10.144.144.11:52888`).

#### Step 4.3 — Verify txcloud log: NotifyJoin for aliyun

```bash
grep "NotifyJoin" /tmp/meshdesk-txcloud.log | grep "de52c6da"
```

**Expected:**
```
[p2p] NotifyJoin: connected peer de52c6da (role agent, 1 endpoints)
```

#### Step 4.4 — Verify txcloud log: NotifyJoin for N1

```bash
grep "NotifyJoin" /tmp/meshdesk-txcloud.log | grep "61ac6321"
```

**Expected:**
```
[p2p] NotifyJoin: connected peer 61ac6321 (role agent, 2 endpoints)
```

#### Step 4.5 — Verify N1 log: sees aliyun endpoints

```bash
ssh -p 22000 yzy806806@10.144.144.11 'sudo grep "NotifyJoin" /tmp/meshdesk-n1.log | grep "de52c6da"'
```

**Expected:** Similar NotifyJoin entry showing aliyun with 1 endpoint.

### Phase 5: Log-Evidence Collection

Run the evidence collection script from txcloud:

```bash
#!/bin/bash
# evidence-collect.sh — run on txcloud (collector node)
EVIDENCE_DIR="/tmp/meshdesk-aliyun-evidence-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

# 1. Topology snapshot
curl -s http://localhost:8080/api/topology > "$EVIDENCE_DIR/topology.json"
echo "Node count: $(jq '.nodes | length' "$EVIDENCE_DIR/topology.json")" > "$EVIDENCE_DIR/summary.txt"

# 2. Node-specific endpoint details
jq '[.nodes[] | {hostname, endpoints, status}]' "$EVIDENCE_DIR/topology.json" > "$EVIDENCE_DIR/endpoints.json"

# 3. txcloud log excerpts
grep -E 'gossip layer started|endpoint learning|NotifyJoin|NotifyUpdate|push/pull sync' \
  /tmp/meshdesk-txcloud.log > "$EVIDENCE_DIR/txcloud-gossip.log"

# 4. Aliyun log excerpts (via mesh)
ssh root@10.144.144.10 "grep -E 'gossip layer started|endpoint learning|NotifyJoin|push/pull sync|invalid msgType' \
  /tmp/meshdesk-aliyun.log" > "$EVIDENCE_DIR/aliyun-gossip.log" 2>/dev/null

# 5. N1 log excerpts (via SSH)
ssh -p 22000 yzy806806@10.144.144.11 "sudo grep -E 'gossip layer started|endpoint learning|NotifyJoin|push/pull sync|invalid msgType' \
  /tmp/meshdesk-n1.log" > "$EVIDENCE_DIR/n1-gossip.log" 2>/dev/null

# 6. Dashboard health check
curl -s http://localhost:8080/api/proxy/status > "$EVIDENCE_DIR/proxy-status.json" 2>/dev/null || echo "proxy/status unavailable" > "$EVIDENCE_DIR/proxy-status.json"

# 7. MuxTransport port check on each node
ss -tlnp | grep 52888 > "$EVIDENCE_DIR/txcloud-port-check.txt"
ssh root@10.144.144.10 'ss -tlnp | grep 52888' > "$EVIDENCE_DIR/aliyun-port-check.txt" 2>/dev/null
ssh -p 22000 yzy806806@10.144.144.11 'sudo ss -tlnp | grep 52888' > "$EVIDENCE_DIR/n1-port-check.txt" 2>/dev/null

echo "Evidence collected at: $EVIDENCE_DIR"
ls -la "$EVIDENCE_DIR/"
```

---

## 6. Pass/Fail Criteria

### 6.1 Multi-Endpoint Interconnection Checks

| ID   | Check | Pass Condition | Fail Condition |
|------|-------|---------------|----------------|
| **ME-1** | All nodes appear in topology | `/api/topology` returns exactly 3 nodes within 60s of all nodes starting | Fewer than 3 nodes after 60s |
| **ME-2** | Aliyun endpoints propagated | Aliyun node in topology has `endpoints: ["203.0.113.10:52888"]` (non-empty, correct count) | Aliyun endpoints empty or wrong count |
| **ME-3** | txcloud multi-endpoint count | txcloud node has exactly 2 endpoints in its own announcement log | txcloud announces fewer or more than 2 |
| **ME-4** | N1 multi-endpoint count | N1 node has exactly 2 endpoints in its own announcement log | N1 announces fewer or more than 2 |
| **ME-5** | Aliyun → txcloud gossip sync | Aliyun log shows successful push/pull sync to `10.144.144.20:52888` without `i/o timeout` | `i/o timeout` or no sync attempt logged |
| **ME-6** | Aliyun → N1 gossip sync | Aliyun log shows successful push/pull sync to `10.144.144.11:52888` without `i/o timeout` | `i/o timeout` or no sync attempt logged |
| **ME-7** | txcloud → aliyun NotifyJoin | txcloud log shows `NotifyJoin: connected peer de52c6da...` with `1 endpoints` | No NotifyJoin for de52c6da, or wrong endpoint count |
| **ME-8** | N1 → aliyun NotifyJoin | N1 log shows `NotifyJoin: connected peer de52c6da...` with `1 endpoints` | No NotifyJoin for de52c6da on N1 |
| **ME-9** | No protocol interference errors | Zero `invalid msgType` lines in any node log | Any `invalid msgType` line appears |
| **ME-10** | Aliyun metrics flowing | Aliyun CPU > 0 AND memory > 0 in topology API within 60s | CPU=0 or memory=0 for aliyun |

### 6.2 Final Acceptance

**Stop condition:** All checks ME-1 through ME-10 must PASS. Any FAIL blocks the stop condition per MESHDESK_V2_DESIGN.md §Testing Requirements.

**The stop condition is met when:**
> "阿里云（纯 IPv4）通过多 endpoint 与 txcloud + N1 互联发现成功"

This is satisfied when:
- All 3 nodes mutually discover each other (ME-1, ME-5, ME-6)
- Endpoints are correctly propagated for all nodes (ME-2, ME-3, ME-4)
- Aliyun's single IPv4 endpoint and txcloud/N1's dual endpoints are all visible (ME-7, ME-8)
- No protocol interference errors (ME-9)
- Monitoring data flows from all nodes (ME-10)

---

## 7. Known Limitations

### 7.1 IPv4-Only to IPv6-Only Endpoint Mismatch

Aliyun is pure IPv4. If txcloud or N1 were to advertise ONLY their public IPv6 addresses (without the mesh IPv4 endpoint), Aliyun would be unable to reach them:

```
[WARN] memberlist: Was able to connect to <peer> over TCP but UDP probes failed
[INFO] memberlist: Suspect <peer> has failed, no acks received
```

**Mitigation:** Each dual-stack node MUST advertise at least one IPv4 endpoint alongside its IPv6 endpoint. In this test plan, both txcloud and N1 include their EasyTier mesh IPv4 as the second `advertise_endpoints` entry. This ensures Aliyun can reach them via IPv4.

This is a **network environment limitation**, not a code bug. memberlist's TCP transport is IPv4-native, and `resolveAdvertiseAddr()` (gossip.go:382) explicitly prefers the first IPv4 endpoint for the memberlist AdvertiseAddr.

### 7.2 memberlist UDP Ping Over EasyTier

EasyTier mesh VPN may not reliably forward UDP between nodes. If memberlist UDP pings fail through the mesh tunnel, memberlist falls back to TCP-only probing. This is expected behavior — TCP push/pull sync still works. The symptom is:

```
[WARN] memberlist: Was able to connect to <peer> over TCP but UDP probes failed
```

This does NOT block gossip state synchronization. It only means health checks use TCP fallback instead of UDP.

### 7.3 Architecture Cross-Compatibility

The N1 node runs `arm64` (aarch64) while txcloud and aliyun run `amd64` (x86_64). memberlist uses MessagePack serialization for NodeMeta. MessagePack is architecture-independent, so this should not cause issues, but it is a variable worth monitoring. If unexpected parse errors occur on N1, verify the binary was built with `GOARCH=arm64`.

### 7.4 MuxTransport Replay Buffer

The MuxTransport 1-byte peek (`peckByteCount = 1` in `internal/mesh/mux_transport.go:29`) reads one byte to classify the connection (0x16 → Reality TLS, otherwise → memberlist). The byte is replayed via `connWithPrefix`. If the replay path corrupts the stream, memberlist may receive garbled data. The `TestMuxDemux_HighVolumeRapidConnections` test in `internal/mesh/sniffing_edge_test.go` covers this on localhost, but real-network behavior with cross-region latency (Aliyun Hangzhou ↔ txcloud) is unverified.

### 7.5 Seed Connectivity Dependency

Aliyun relies on EasyTier mesh VPN for initial seed connectivity. If EasyTier is down on any node, that node cannot join the gossip cluster. Always verify EasyTier is healthy before starting the test:

```bash
# On each node:
ping -c 3 10.144.144.20   # txcloud mesh IP
ping -c 3 10.144.144.11   # N1 mesh IP
ping -c 3 10.144.144.10   # aliyun mesh IP
```

---

## 8. Appendix: Quick Reference

### 8.1 Node Access Summary

| Node    | Access Command                                          | Config Path              | Log Path                  |
|---------|--------------------------------------------------------|--------------------------|---------------------------|
| txcloud | local                                                  | `/etc/meshdesk/config.yaml` | `/tmp/meshdesk-txcloud.log` |
| aliyun  | `ssh root@10.144.144.10`                               | `/etc/meshdesk/config.yaml` | `/tmp/meshdesk-aliyun.log` |
| N1      | `ssh -p 22000 yzy806806@10.144.144.11`                 | `/etc/meshdesk/config.yaml` | `/tmp/meshdesk-n1.log`    |

### 8.2 Key Log Patterns

| Pattern | Meaning | Source |
|---------|---------|--------|
| `endpoint learning: announced N local endpoint(s): [...]` | Endpoints published to gossip | `gossip.go:224` |
| `gossip layer started (bind ..., advertise ...)` | memberlist transport ready | `gossip.go:531` |
| `Initiating push/pull sync with: ...` | Outbound sync attempt | memberlist |
| `NotifyJoin: connected peer XXXXXXXX (role ..., N endpoints)` | New peer joined + endpoints received | `events.go:163` |
| `NotifyUpdate: failed to update endpoints` | Endpoint propagation failure | `events.go:282` |
| `invalid msgType(N)` | MuxTransport protocol interference | memberlist |
| `i/o timeout` | Seed unreachable | memberlist |

### 8.3 Key Code References

| File | Lines | Content |
|------|-------|---------|
| `internal/p2p/config.go` | 87-91 | `AdvertiseEndpoints []string` field definition |
| `internal/p2p/gossip.go` | 197-225 | `announceLocalEndpoint()` — publishes endpoints |
| `internal/p2p/gossip.go` | 256-295 | `detectOutboundIPs()` — auto-detects IPv4+IPv6 |
| `internal/p2p/gossip.go` | 370-403 | `resolveAdvertiseAddr()` — picks IPv4 for memberlist |
| `internal/p2p/events.go` | 105-172 | `NotifyJoin()` — receives peer endpoints |
| `internal/p2p/events.go` | 234-297 | `NotifyUpdate()` — endpoint change detection |
| `internal/mesh/mux_transport.go` | 29 | `peekByteCount = 1` — 1-byte MuxTransport demux |