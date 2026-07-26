# MeshDesk Multi-Machine GFW Real-Machine Testing Schedule

**Document Version:** 1.0
**Status:** Post-Release Milestone — Scheduled
**Release Context:** v1.0.0-rc1 (tagged 2026-07-26, commit afcdbfd)
**Motion Reference:** motion-deeb2e0a9735 (adopted, 5-1-0)
**Author:** tester

---

## 1. Purpose

This document schedules the multi-machine real-world testing of MeshDesk
in GFW-affected and heterogeneous network environments. It is a
post-release validation milestone, not a release-blocking gate. The
v1.0.0-rc1 release exists so the user can deploy and test on their own
hardware; this schedule defines the structured validation plan to
progressively confirm production readiness and promote the release
candidate to v1.0.0 stable.

## 2. Context: What Has Been Validated

| Validation Surface | Status | Coverage |
|---|---|---|
| Unit tests (all packages) | 610/614 pass, 0 data races | 74.3% coverage |
| Integration tests (multi-node gossip, NAT traversal, relay, WireGuard) | All pass (39KB integration_test.go + 28KB join_test.go) | In-process, simulated network |
| Harness tests (real-device) | 8/8 pass | Single-machine multi-process |
| Obfuscation unit tests | All pass (3 modes, anti-probe, junk train, uTLS) | CPU-only, no real DPI |
| Proxy adversarial tests (reassembly, DoS, fingerprinting) | 43 tests, all pass | In-memory/loopback only |
| Topology API contract + 3D rendering | 29 tests, all pass | httptest + headless browser |
| TOTP 2FA integration | 30 tests, all pass | In-memory test doubles |
| Docker cluster (3-node, GFW sim via iptables) | Not yet run against v1.0.0-rc1 | Docker-local, approximate GFW |

**What has NOT been validated:**
- Any test against a real GFW/DPI deployment
- Multi-machine deployment on physically separate hosts
- Real NAT traversal through carrier-grade NAT
- WireGuard tunnel throughput over real WAN links
- Obfuscation effectiveness against live packet inspection
- Proxy multi-path reassembly under real packet loss and reordering
- Long-running stability (hours to days)
- Cross-region latency tolerance (100ms+ real RTT)

## 3. Testing Phases

### Phase 1: Single-Machine Multi-Instance Network Namespace Test

**Goal:** Validate P2P networking core against real NAT code paths with zero
additional infrastructure. Exercises gossip discovery, STUN resolution,
UDP hole punching, relay fallback, and WireGuard peer sync across Linux
network namespaces.

**Infrastructure:** Single Linux host with root access (any cloud VM or
bare-metal). No additional machines required.

**Estimated Duration:** 30 minutes

**Test Procedure:**
1. Create two isolated network namespaces (ns-a, ns-b)
2. Configure `iptables` MASQUERADE on ns-b to simulate restrictive NAT
3. Deploy meshdesk binary in both namespaces with STUN server
   (`stun.l.google.com:19302`)
4. Run gossip discovery — verify both instances discover each other
5. Verify WireGuard tunnel establishment through simulated NAT
6. Exchange data through the tunnel (ping, iperf3-style throughput)
7. Kill namespace A and verify namespace B detects leave event

**Acceptance Criteria (Phase 1):**
- [ ] `meshdesk status` shows peer as connected within 30s of startup
- [ ] WireGuard handshake completes successfully (confirmed in logs)
- [ ] Bidirectional data transfer works through the tunnel
- [ ] NAT hole-punch succeeds or relay fallback engages cleanly
- [ ] Graceful leave detection works (peer removed within 60s)

**Caveats:**
- Does not test multi-hop routing (only 2 instances)
- Network namespace NAT is Linux netfilter, not carrier-grade NAT
- No real latency or packet loss simulation
- STUN server is public (requires internet access)

### Phase 2: Two-Node Real Deployment Smoke Test

**Goal:** Validate that MeshDesk deploys, forms a mesh, and provides core
services (Web UI, WebSSH, monitoring) on real hardware with real IPv4
addressing. This is the minimum viable real-machine test.

**Infrastructure:** Two Linux VMs (any cloud provider, Ubuntu 24.04, minimum
1 vCPU / 512MB RAM each). One node acts as collector+web (public IP), the
other as agent.

**Estimated Duration:** 2 hours (including provisioning)

**Test Procedure:**
1. Provision both VMs with Ubuntu 24.04
2. Build meshdesk from source on both (`go build -o meshdesk ./cmd/meshdesk/`)
3. Deploy per `test/provision.sh` (role=public-vps on node1,
   role=behind-nat on node2)
4. Configure peer entries: node1 knows node2's public key, node2 knows
   node1's public key
5. Start meshdesk on both nodes
6. Verify: `meshdesk status` shows the peer as connected
7. Verify: `--web` dashboard loads on node1, shows both nodes with live
   CPU/memory/disk metrics
8. Verify: WebSSH terminal from node1's dashboard to node2 works (type
   `uptime`, see output)
9. Run `go test -race -count=1 ./...` on both machines in the deployed
   environment
10. Transfer a 10MB test file over the mesh, verify SHA256 checksum

**Acceptance Criteria (Phase 2):**
- [ ] `meshdesk status` shows peer connected within 60s (both directions)
- [ ] Web dashboard loads and displays both nodes with live metrics
- [ ] WebSSH terminal session establishes and responds to input
- [ ] `go test -race -count=1 ./...` passes on both machines
- [ ] File transfer completes with matching SHA256 checksum
- [ ] Zero panics or crashes in logs after 15 minutes of idle operation

**Caveats:**
- Both VMs are from the same cloud provider (homogeneous network)
- No carrier-grade NAT between nodes
- No GFW DPI in the path
- No cross-region latency
- Short duration (not a soak test)

### Phase 3: Three-Node Multi-Machine Full Mesh Test

**Goal:** Validate the full 3-node topology: public VPS collector, NAT'd
agent, cross-region agent with real latency. Exercises all P2P networking
paths, relay selection, WireGuard key rotation, and multi-hop routing.

**Infrastructure:** Three Linux VMs:
- Node A: Public VPS with open ports (collector + Web UI)
- Node B: VPS behind restrictive firewall or NAT (agent only)
- Node C: Cross-region VPS with 100ms+ RTT to Node A (agent only)

**Estimated Duration:** 4 hours (including provisioning and config)

**Test Procedure:**
1. Provision all three VMs with Ubuntu 24.04
2. Configure latency simulation on Node C (tc netem, 150ms)
3. Deploy meshdesk using `provision.sh` with appropriate roles
4. Configure full mesh peer entries (each node knows the other two)
5. Start all three nodes
6. Verify: 3-node gossip convergence within 60s
7. Verify: NAT traversal from Node B to Node A (STUN + hole punch)
8. Verify: Node C → Node A communication at real 150ms latency
9. Verify: Relay fallback when direct hole-punch fails (simulate by
   blocking UDP on Node B's firewall temporarily)
10. Run full scenario matrix (`test/scenario-matrix.sh`) from Node A
11. Obfuscation test: capture traffic with tcpdump on Node A, verify
    WireGuard packets are obfuscated (no plaintext "WireGuard" magic bytes,
    randomized message types, variable padding)
12. Long-running stability: leave mesh running for 1 hour, monitor for
    crashes, memory leaks, or gossip partition
13. Dynamic join/leave: add a 4th temporary node, verify it discovers the
    mesh, then remove it and verify clean teardown

**Acceptance Criteria (Phase 3):**
- [ ] All 3 nodes discover each other via gossip within 60s
- [ ] `meshdesk status` on each node shows 2 peers connected
- [ ] WireGuard handshakes complete for all peer pairs
- [ ] WebSSH from Node A to Node B and Node C both work
- [ ] File transfer across the mesh (Node A → Node C) completes with
      correct checksum despite 150ms latency
- [ ] NAT hole-punch succeeds (Node B → Node A), or relay fallback
      engages with <5s failover time
- [ ] Obfuscation verified: tcpdump shows no plaintext WireGuard protocol
      identifiers
- [ ] Scenario matrix: ≥90% of applicable scenarios pass
- [ ] 1-hour stability: zero crashes, zero goroutine leaks (≤5% memory
      growth acceptable)
- [ ] Dynamic join/leave: new node converges within 60s, removal
      propagates within 30s

**Caveats:**
- Three nodes is still a small mesh (real deployments may have 10+)
- Cloud VPS NAT is not carrier-grade NAT
- No actual GFW DPI equipment in the path
- 1-hour stability is not a multi-day soak test

### Phase 4: GFW Real-Environment Validation

**Goal:** Validate obfuscation shim effectiveness against live GFW DPI,
traffic analysis resistance, and connection stability in real GFW-affected
environments.

**Infrastructure:**
- At least one node physically located behind GFW (mainland China)
- At least one node outside GFW (international VPS: Singapore, Tokyo, or
  US West Coast)
- Optionally: a relay node in Hong Kong for the common GFW-bypass topology

**Estimated Duration:** Ongoing (initial validation: 1 day; long-term
monitoring: 1+ weeks)

**Test Procedure:**

1. **Pre-flight (outside GFW first):**
   - Provision international node, verify all three obfuscation modes
     (none, padded, WebSocket) work correctly in a non-filtered
     environment
   - Capture baseline traffic with tcpdump for later comparison

2. **GFW-internal node deployment:**
   - Deploy meshdesk on the China-based node
   - Configure obfuscation mode = "padded" with strong H1-H4 ranges
   - Optionally enable WebSocket+TLS mode with CDN-friendly SNI

3. **Connectivity test:**
   - Attempt WireGuard tunnel establishment from GFW node to
     international node
   - Measure: time to first handshake, handshake completion rate,
     connection drop frequency
   - Test all three obfuscation modes: none (expected to fail/be blocked),
     padded, WebSocket+TLS

4. **DPI resistance test:**
   - Capture traffic on both sides (tcpdump)
   - Run Wireshark/tshark analysis: does the traffic pattern match known
     WireGuard signatures?
   - Verify: randomized message types defeat DPI fingerprinting
   - Verify: variable padding defeats packet-size correlation
   - Verify: WebSocket+TLS mode traffic is indistinguishable from HTTPS
     (entropy analysis)

5. **Connection stability under GFW:**
   - Leave the mesh running for 24 hours
   - Log every connection drop and reconnection
   - Measure: mean time between disconnections (MTBD), reconnection
     success rate
   - Test: does GFW active probing trigger connection resets? (periodic
     RST injection by GFW)
   - Test: anti-probe PSK challenge effectiveness — do PSK-enabled peers
     survive active probing longer than non-PSK peers?

6. **Multi-path proxy validation (if wired in main.go):**
   - Create a circuit from GFW node → relay (international) → exit node
     → target
   - Measure end-to-end latency and throughput
   - Test path switching under connection loss
   - Verify chunk reassembly correctness under real packet loss

7. **Long-term monitoring (1+ weeks):**
   - Run meshdesk as a systemd service on both GFW and international nodes
   - Log connection events, reconnections, and data throughput
   - Weekly report: uptime percentage, connection stability, obfuscation
     effectiveness

**Acceptance Criteria (Phase 4):**
- [ ] Padded obfuscation mode: WireGuard tunnel establishes and survives
      ≥2 hours without disconnection from GFW DPI
- [ ] WebSocket+TLS mode: WireGuard tunnel establishes and survives ≥24
      hours without disconnection
- [ ] "None" mode (control): tunnel is blocked or unstable within 30
      minutes (confirms GFW is active and the test is valid)
- [ ] Traffic capture analysis: no plaintext WireGuard identifiers
      visible in padded or WebSocket modes
- [ ] WebSocket+TLS entropy: traffic is indistinguishable from normal
      HTTPS to automated DPI analysis
- [ ] Anti-probe PSK: PSK-enabled peers resist GFW active probing
      (connection survives ≥4 hours vs non-PSK baseline)
- [ ] 1-week stability: ≥95% uptime for WebSocket+TLS mode, ≥80% for
      padded mode
- [ ] Reconnection: ≥90% of disconnections result in successful
      reconnection within 120s

**Caveats:**
- GFW behavior is adversarial and changes over time — test results are a
  snapshot, not a permanent guarantee
- Real GFW testing requires maintaining a node inside China, which
  carries operational overhead (server payment, network access, legal
  considerations)
- CDN-dependent modes (Cloudflare Tunnel) depend on CDN availability
  inside China, which varies by region and ISP
- Entropy analysis is best-effort — GFW may use ML-based classification
  that a static analysis tool cannot simulate
- Long-term stability depends on the specific ISP, region, and time of
  day (GFW filtering intensity varies)

## 4. Infrastructure Requirements Summary

| Phase | Nodes | Locations | Special Requirements |
|---|---|---|---|
| 1 | 1 (2 ns) | Any | Root access, kernel 5.4+, internet |
| 2 | 2 VMs | Any cloud (same region OK) | Ubuntu 24.04, 1vCPU/512MB min |
| 3 | 3 VMs | Public + NAT'd + cross-region | One node with 100ms+ RTT |
| 4 | 2-3 VMs | 1 GFW-internal + 1 international + opt. HK relay | GFW node: mainland China VPS |

## 5. Schedule

| Phase | Prerequisite | Target Start | Est. Duration | Blocks |
|---|---|---|---|---|
| Phase 1 | v1.0.0-rc1 released (done) | Immediately | 30 min | Phase 2 |
| Phase 2 | Phase 1 passes | Within 48h of Phase 1 | 2 hours | RC promotion |
| Phase 3 | Phase 2 passes | Within 1 week of Phase 2 | 4 hours | v1.0.0 stable |
| Phase 4 | Phase 3 passes | Within 2 weeks of Phase 3 | 1 day + 1 week monitoring | v1.0.1+ |

**Promotion gates:**
- v1.0.0-rc1 → v1.0.0: Phase 2 smoke test passes
- v1.0.0 stable: Phase 3 full mesh test passes
- v1.0.1 GFW-validated: Phase 4 GFW test passes with ≥80% criteria met

## 6. Reporting

Each phase produces a structured report in `test/results/`:

```
test/results/
├── phase1-namespace-test.json       # Phase 1 results
├── phase2-smoke-test.json           # Phase 2 results
├── phase3-full-mesh-test.json       # Phase 3 results
├── phase4-gfw-test-initial.json     # Phase 4 initial results
└── phase4-gfw-test-weekly.json      # Phase 4 long-term results
```

Report format (JSON):

```json
{
  "phase": "2",
  "title": "Two-Node Real Deployment Smoke Test",
  "timestamp": "2026-07-28T12:00:00Z",
  "meshdesk_version": "v1.0.0-rc1",
  "nodes": [
    {"hostname": "node1", "role": "public-vps", "ip": "203.0.113.1"},
    {"hostname": "node2", "role": "behind-nat", "ip": "198.51.100.1"}
  ],
  "results": [
    {
      "id": "P2-smoke-01",
      "description": "meshdesk status shows peer connected",
      "result": "PASS",
      "duration_s": 45,
      "details": "Peer discovered via gossip, WireGuard handshake complete"
    }
  ],
  "summary": {
    "total": 5,
    "passed": 5,
    "failed": 0,
    "skipped": 0,
    "duration_s": 7200
  },
  "caveats": [
    "Both VMs on same cloud provider — homogeneous network",
    "No cross-region latency",
    "No GFW DPI in path"
  ]
}
```

## 7. Documented Caveats — What This Testing Does and Does Not Prove

### What is validated:
- P2P networking: gossip discovery converges on real network interfaces
- NAT traversal: STUN resolution and UDP hole-punching through real NAT
- WireGuard tunnel: handshake negotiation and data transport between
  physically separate hosts
- WebSSH: terminal session establishment and interactivity over mesh VPN
- Service management: systemd integration on real Linux hosts
- Dashboard security: TOTP 2FA endpoints work with real sessions
- Obfuscation: traffic pattern randomization and DPI evasion (Phase 4)

### What is NOT validated (and may never be):
- **Scale:** 3-4 node tests do not validate behavior at 50+ nodes.
  Gossip message overhead, WireGuard key distribution, and relay
  selection algorithms have not been tested at scale.
- **Heterogeneous topologies:** All test nodes are Linux/amd64. ARM,
  Windows, and macOS nodes are untested.
- **Production traffic load:** Tests use artificial workloads (iperf3,
  test files). Real-world traffic patterns (bursty HTTP, long-lived SSH
  sessions, streaming media) may expose different bottlenecks.
- **Long-term stability beyond 1 week:** Memory leaks, goroutine buildup,
  and WireGuard key rotation edge cases may only manifest after weeks or
  months of continuous operation.
- **GFW rule evolution:** Phase 4 results are a snapshot. GFW DPI rules
  change. An obfuscation mode that works today may be fingerprinted
  tomorrow.
- **Adversarial conditions:** No testing under active attack (targeted
  DPI, packet injection, RST spoofing by state actors).
- **Legal/operational:** Running encrypted tunnels through GFW carries
  operational risk. This testing plan documents technical acceptance
  criteria only.

## 8. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| GFW node not available | Medium | Blocks Phase 4 | Phase 4 is explicitly deferred; Phases 1-3 do not require GFW access |
| Obfuscation fails against real GFW | Medium | v1.0.x must be patched | WebSocket+TLS mode is fallback; CF Tunnel mode is tertiary fallback |
| Multi-machine config drift causes false failures | High | Delays Phase 2/3 | Use identical provision.sh on all nodes; version-pin all dependencies |
| User blocks on GFW testing before team | Low | Stalls promotion | User's own hardware testing counts as Phase 2 validation; report format is self-serve |
| Docker unavailable for Phase 1 fallback | Low (on arm64 host) | Blocks Phase 1 | Phase 1 uses network namespaces, not Docker; no dependency on container runtime |

## 9. Follow-Up Tasks

After Phase 2 passes:
- Promote v1.0.0-rc1 to v1.0.0 stable with `gh release edit --draft=false`
- Update RELEASE_NOTES.md with smoke test results

After Phase 3 passes:
- Add multi-machine test results to release notes
- Create v1.0.1 milestone for any issues found

After Phase 4 passes:
- Add GFW validation status to README maturity labels
- Publish traffic capture comparison (sanitized) as documentation
- Create GFW-specific configuration guide for end users

## 10. Version History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-07-26 | tester | Initial schedule from motion-deeb2e0a9735 action item 6/6 |
