# Real-Device Verification: TUN Virtual Network (Round 12)

**Version:** 1.0
**Date:** 2026-08-03
**Commit:** `c4b0519` (Fix: re-add TUN routes after smux reconnect)
**Motion:** `motion-8c9b0a82a47f` — meshdesk project completion vote, round 12
**Status:** All five stop conditions verified — project complete

## Test Environment

| Parameter | Value |
|-----------|-------|
| Binary | `meshdesk` cross-compiled at `c4b0519` (amd64 for aliyun, arm64 for N1) |
| Node 1 (aliyun) | `root@203.0.113.10`, amd64, Ubuntu |
| Node 2 (N1) | `yzy806806@10.144.144.11:22000`, arm64, Armbian |
| mesh_cidr | `10.100.0.0/24` |
| Commit verified | `c4b0519` = `origin/main`, working tree clean |

## Stop Condition 1: Build, Vet, Test

**Requirement:** `go build/vet/test` must pass clean.

**Result: PASS.**

```
22 packages, 0 FAIL
New packages: internal/ipam (0.007s), internal/tun (0.046s)
HEAD=c4b0519=origin/main
```

All packages compile without error. New TUN-related packages (`internal/tun`, `internal/ipam`) pass
their unit tests on first integration.

## Stop Condition 2: TUN Device Creation

**Requirement:** TUN virtual network interface created on both nodes with IPAM-assigned
Virtual IPs.

**Result: PASS.**

**aliyun:**
```
$ ip addr show mesh0
mesh0: inet 10.100.0.10/24 scope global mesh0
```

**N1:**
```
$ ip addr show mesh0
mesh0: inet 10.100.0.30/24 scope global mesh0
```

**Log confirmation (both nodes):**
```
created TUN device mesh0 (subnet=10.100.0.0/24, mtu=1400)
tun-forwarder started (virtual port 0x5455, MTU=1400)
TUN integration complete
```

IPAM deterministically assigned `.10` to aliyun and `.30` to N1 from the `10.100.0.0/24`
CIDR. The TUN forwarder listens on virtual port `0x5455`, reusing the existing
smux+MuxTransport infrastructure without adding new network ports.

## Stop Condition 3: Bidirectional Ping over Virtual IP

**Requirement:** Nodes must ping each other by Virtual IP with no packet loss.

**Result: PASS — bidirectional, 0% loss.**

### aliyun → N1

```
$ ping -c 4 10.100.0.30
PING 10.100.0.30 (10.100.0.30) 56(84) bytes of data.
64 bytes from 10.100.0.30: icmp_seq=1 ttl=64 time=35.6 ms
64 bytes from 10.100.0.30: icmp_seq=2 ttl=64 time=25.0 ms
64 bytes from 10.100.0.30: icmp_seq=3 ttl=64 time=29.0 ms
64 bytes from 10.100.0.30: icmp_seq=4 ttl=64 time=27.7 ms

--- 10.100.0.30 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss
rtt min/avg/max = 25.0/29.3/35.6 ms
```

### N1 → aliyun

```
$ ping -c 4 10.100.0.10
PING 10.100.0.10 (10.100.0.10) 56(84) bytes of data.
64 bytes from 10.100.0.10: icmp_seq=1 ttl=64 time=27.7 ms
64 bytes from 10.100.0.10: icmp_seq=2 ttl=64 time=23.9 ms
64 bytes from 10.100.0.10: icmp_seq=3 ttl=64 time=25.7 ms
64 bytes from 10.100.0.10: icmp_seq=4 ttl=64 time=26.1 ms

--- 10.100.0.10 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss
rtt min/avg/max = 23.9/25.9/27.7 ms
```

ICMP packets traverse the full chain: kernel → TUN fd → IP header parse → route lookup →
DialVirtualPort(0x5455) → smux stream → peer's ListenVirtualPort(0x5455) → write to TUN fd →
kernel. Latency of 24–36ms is consistent with the aliyun–N1 network path over the mesh
(Reality TLS + smux encapsulation overhead).

## Stop Condition 4: SSH over Virtual IP

**Requirement:** TCP connections to peer's Virtual IP must traverse the TUN successfully,
confirmed by receiving the SSH banner.

**Result: PASS.**

```
$ nc 10.100.0.30 22000
SSH-2.0-OpenSSH_9.2p1
```

The SSH banner confirms that a TCP SYN → SYN/ACK → data exchange completed over the
TUN virtual network. The full protocol path is:

```
nc → kernel TCP stack → TUN mesh0 → meshdesk TUN forwarder (parse dst IP)
→ route lookup (pubkey for 10.100.0.30) → DialVirtualPort(0x5455)
→ smux stream → MuxTransport → Reality TLS → network → N1
→ MuxTransport → smux stream → ListenVirtualPort(0x5455)
→ write to TUN fd → kernel → SSH daemon on port 22000
```

This validates that the TUN virtual network supports arbitrary TCP traffic, not just ICMP.

## Stop Condition 5: Subnet Proxy

**Requirement:** When aliyun is configured with `subnet_proxy`, its advertised subnets must
propagate via gossip to N1, and N1 must install kernel routes for those subnets via aliyun's
Virtual IP.

**Result: PASS.**

N1 kernel routing table after aliyun's subnet_proxy gossip propagation:

```
$ ip route show | grep mesh0
172.26.0.0/18 via 10.100.0.10 dev mesh0
```

aliyun advertised its local Docker subnet (`172.26.0.0/18`) via the `SubnetProxies` field in
`NodeMeta` (msgpack tag `spx`). N1 received the gossip update via `NotifyMsg` and its
`route_manager.go` installed the kernel route automatically. Traffic to `172.26.0.0/18`
on N1 is now routed through `mesh0` to aliyun, which forwards it onto its local network.

## Bug Fixes Verified During Testing

### Bug 1: mesh_cidr Routing Conflict with EasyTier tun0

**Commit:** `136f899` — `fix(tun): resolve mesh_cidr routing conflict with EasyTier tun0`

**Problem:** EasyTier's `tun0` interface (10.144.144.0/24) conflicted with the original
mesh_cidr, causing kernel route collisions.

**Fix (three layers):**
1. Changed mesh_cidr to `10.100.0.0/24` to avoid the EasyTier subnet entirely
2. `ip route replace` with metric 0 to override any conflicting routes (defense-in-depth)
3. `detectSubnetConflict()` warns at startup if another interface claims the mesh CIDR

**Verification:** 19 new tests in `tun_route_conflict_test.go` (389 lines). Both nodes
created `mesh0` without routing errors.

### Bug 2: smux Reconnect Route Loss

**Commit:** `c4b0519` — `Fix: re-add TUN routes after smux reconnect`

**Problem:** When a smux session died, `sessionDeathHandler` removed the peer's `/32` kernel
route and subnet proxy routes. Since the peer remained in memberlist, no `NotifyJoin` fired
on reconnect — routes were never re-added, causing silent 100% packet loss.

**Fix:** Added `sessionReconnectHandler` callback to `MeshNode` (`session_reconnect.go`).
After `tryReconnect` succeeds, it looks up the peer's `NodeMeta` from
`gossipLayer.KnownPeers()` and re-executes `AddPeerVirtualIPRoute` +
`AddPeerSubnetProxies`. Routes are idempotent (`ip route replace`), so re-adding is
safe.

**Wiring:** `main.go` sets the callback on the MeshNode:
```
meshNode.SetSessionReconnectHandler(func(peerPubKey string) {
    meta := gossipLayer.KnownPeers()[peerPubKey]
    routeMgr.AddPeerVirtualIPRoute(meta.VirtualIP)
    routeMgr.AddPeerSubnetProxies(meta.SubnetProxies, meta.VirtualIP)
})
```

**Verification:** Logs confirmed `NotifyReconnect` events triggered route re-addition
on both nodes during the verification run.

## Architecture Implemented

The four project goals verified above are implemented in these source files:

| Component | Source File | Description |
|-----------|------------|-------------|
| TUN device | `internal/tun/tun.go` | Zero-dependency Linux TUN via syscall (no wireguard library) |
| IPAM | `internal/ipam/ipam.go` | Deterministic allocation: `IP = mesh_cidr_base + (pubkey_hash % host_count)`, salt-based collision resolution |
| TUN forwarder | `internal/mesh/tun_forwarder.go` | 4-byte length-prefix framing on virtual port `0x5455` |
| Route manager | `internal/tun/route_manager.go` | Kernel route add/replace/delete via `netlink` |
| TUN integration | `internal/mesh/tun_integration.go` | MeshNode lifecycle: create TUN, start forwarder, manage routes |
| Gossip metadata | `internal/mesh/delegate.go` | `NodeMeta` with `VirtualIP` (msgpack: `vip`) and `SubnetProxies` (msgpack: `spx`) |

**Data flow for a forwarded packet:**

```
App (ping/SSH) → kernel TCP/IP stack
→ TUN device (mesh0) → meshdesk reads IP packet
→ parse dst IP header → router: which peer owns this IP?
→ DialVirtualPort(0x5455, peerPubKey) → smux stream
→ MuxTransport → Reality TLS (port 52888) → network
→ peer's MuxTransport → smux stream → ListenVirtualPort(0x5455)
→ write IP packet to TUN fd → kernel → target application
```

## Verifying Participants

All four technical roles independently confirmed the five stop conditions:

| Role | Vote | Key Findings |
|------|------|-------------|
| **tester** | ADOPT | Executed all five verification steps on real hardware at `c4b0519` |
| **architect** | ADOPT | Verified code matches design spec; IPAM allocation, NodeMeta fields, TUN forwarder pattern |
| **developer** | ADOPT | Confirmed build/vet/test; reviewed both bug fixes; verified TUN data path wiring |
| **reviewer** | ADOPT | Confirmed both bug fixes resolve earlier blind spots; no residual concerns |

The writer (documentation) and researcher also confirmed the project completion.

## Related Documentation

- `README.md` § TUN Virtual Network — user-facing configuration guide
- `AGENTS.md` — project goals and stop conditions (line 12)
- `docs/RELEASE_NOTES.md` — v3.0.0 release notes
- `docs/ARCHITECTURE.md` — protocol stack and component diagram
- Test harness: `test/results/real_device_report.json`
