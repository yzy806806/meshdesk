# MeshDesk v2 Smoke-Test Gates — Protocol Layer Boundaries

**Version:** 1.0
**Author:** reviewer
**Date:** 2026-07-28
**Source:** Motion motion-856c071ce5a9, action item 6/7
**Upstream docs:** docs/MESHDESK_V2_DESIGN.md, docs/QUIC_FEASIBILITY.md
**Status:** pending implementation

---

## 0. Purpose and Non-Purpose

### Purpose
This document defines **gate tests** at each protocol layer boundary in the
MeshDesk v2 stack. A gate test is a fast, deterministic, dependency-free
assertion that a layer's **contract** is satisfied — if a gate test fails,
the layer is broken and no higher-layer testing is meaningful.

Every gate test meets these criteria:
- **In-process**: uses `net.Pipe()`, local TLS servers, or `go test` only;
  no real network, no remote machines, no subprocesses.
- **Deterministic**: same result every run; no timing races, no entropy-dependent
  branching.
- **Fast**: each gate completes in under 1 second; the full suite runs in under
  10 seconds.
- **Contract-assertive**: tests the layer's public API contract, not its
  implementation details.

### Layer stack (bottom-up)
```
Layer 1  — Handshake (Reality TLS, net.Conn after TLS 1.3)
Layer 2  — AES-GCM Encryption (aeadConn wrapping net.Conn)
Layer 3  — smux Multiplexing (stream open/close/data over encrypted conn)
Layer 4  — Services (WebSSH, RPC, file transfer — consuming smux streams)
Layer 5+ — Gossip, Smart Routing, PeerManager (consumer of above contracts)
```

### Non-purpose
These are NOT integration tests, NOT real-machine tests, and NOT end-to-end
scenarios. They do NOT test Reality protocol correctness (that's in
`reality_transport_test.go`), do NOT test PeerManager failover logic (that's
in `peer_manager_test.go`), and do NOT replace any existing test. They sit
**before** all other tests in the test pyramid and are intended to run as a
CI pre-flight: `go test -short ./internal/mesh/ -run 'Smoke'`.

---

## 1. Layer 1-2 Gate: Handshake → AES-GCM Encryption

### 1.1 Contract Under Test

```
HandshakeLayer.Connect(ctx, addr) → net.Conn      (TLS 1.3, authenticated)
AES-GCM Encrypt(outConn) → aeadConn wraps net.Conn (application-layer AEAD)

Stack: plaintext ↔ aeadConn ↔ TLS net.Conn ↔ wire
```

The gate tests verify:
1. A `net.Pipe()` pair can carry plaintext through **both** a local TLS
   handshake (Layer 1) and an AES-GCM wrapper (Layer 2).
2. Wire traffic is ciphertext (indistinguishable from random).
3. Tampering with ciphertext is detected by AES-GCM authentication.
4. Key material flows from handshake to encryption without leaking across
   sessions.

### 1.2 Test Harness Primitives

The following primitives are provided in `internal/mesh/smoke_layer12_test.go`
and tagged `//go:build smoke` so they compile only when explicitly requested.

```
// newLocalTLSPipe creates an in-process TLS client+server pair using
// net.Pipe() and a self-signed certificate. Returns (clientConn, serverConn)
// where both ends are *tls.Conn instances that have completed the handshake.
func newLocalTLSPipe(t *testing.T) (client, server net.Conn)

// newAEADPipe wraps a net.Conn pair with AES-GCM encryption using a
// pre-shared 32-byte key. Returns (clientAEAD, serverAEAD) where both
// satisfy io.ReadWriter and encrypt/decrypt transparently.
func newAEADPipe(t *testing.T, key []byte) (client, server net.Conn)

// newTLSThenAEADPipe chains the two: TLS handshake → AES-GCM wrapping.
// Returns a plaintext client io.ReadWriter and a plaintext server
// io.ReadWriter. All traffic between them is TLS+AES-GCM encrypted.
func newTLSThenAEADPipe(t *testing.T, aesKey []byte) (client, server net.Conn)
```

### 1.3 Gate Tests

#### Gate L12-01: Plaintext round-trip through TLS+AES-GCM (REQUIRED)

**Test:** `TestSmoke_L12_PlaintextRoundTrip`
**Assertions:**
1. Write `"hello meshdesk v2"` to client → read same bytes from server.
2. Write `"acknowledged"` to server → read same bytes from client.
3. Repeat with 64 KiB payload.
4. No errors, no timeouts, no goroutine leaks.

**Why this gates the stack:** If plaintext can't round-trip, every higher
layer is broken. This single assertion covers TLS handshake completion,
AES-GCM encrypt/decrypt, and correct data framing.

#### Gate L12-02: Wire traffic is ciphertext (REQUIRED)

**Test:** `TestSmoke_L12_WireIsCiphertext`
**Assertions:**
1. Capture the raw bytes flowing over the underlying `net.Pipe()` BETWEEN
   the TLS layer and the AES-GCM layer using an intercepting `io.Reader`.
2. Assert that the captured bytes contain **zero** occurrences of the
   plaintext sent (search for the plaintext string in captured bytes).
3. Assert that the captured bytes fail a chi-squared randomness test with
   p < 0.01 (i.e., cannot be distinguished from random). Use a 1 KiB
   sliding window.

**Why this gates the stack:** Layer 2's contract is "the wire sees ciphertext."
If plaintext leaks through the AES-GCM layer, the encryption is not working.

#### Gate L12-03: Tamper detection (REQUIRED)

**Test:** `TestSmoke_L12_TamperDetection`
**Assertions:**
1. Establish a TLS+AES-GCM pipe.
2. Client writes 1 KiB of data.
3. On the server-side AES-GCM reader, flip one byte of the AEAD tag
   (the last 16 bytes of the frame) before decryption.
4. Assert that `server.Read()` returns an error (authentication failure).
5. Repeat with a flipped byte in the ciphertext body (not the tag).
6. Assert that both produce errors, not silent corruption.

**Why this gates the stack:** AES-GCM's AEAD property is the core security
guarantee of Layer 2. If tampering is not detected, the encryption is
cryptographically broken.

#### Gate L12-04: Key isolation — separate sessions use separate keys (REQUIRED)

**Test:** `TestSmoke_L12_KeyIsolation`
**Assertions:**
1. Create two independent TLS+AES-GCM pipes with different AES keys (K1, K2).
2. Encrypt `"data-for-session-1"` with K1 → ciphertext C1.
3. Attempt to decrypt C1 with K2 → must fail (authentication error).
4. Encrypt `"data-for-session-2"` with K2 → ciphertext C2.
5. Assert C1 != C2 (different keys produce different ciphertexts for
   different plaintexts).

**Why this gates the stack:** Cross-session key leakage means a compromise
of one session compromises all sessions. This is the line between "encryption
exists" and "encryption is correctly implemented."

#### Gate L12-05: Concurrent read/write safety (RECOMMENDED)

**Test:** `TestSmoke_L12_ConcurrentReadWrite`
**Assertions:**
1. Establish a TLS+AES-GCM pipe.
2. Spawn 10 goroutines on the client, each writing 100 messages of 4 KiB.
3. Spawn 10 goroutines on the server, each reading and echoing back.
4. Assert total bytes read = total bytes written.
5. Assert no data races detected by `-race`.

**Why this gates the stack:** The encryption layer is shared by all smux
streams in Layer 3. If reads/writes are not concurrent-safe, smux corrupts
data under load.

#### Gate L12-06: Close propagates through both layers (RECOMMENDED)

**Test:** `TestSmoke_L12_ClosePropagation`
**Assertions:**
1. Establish a TLS+AES-GCM pipe.
2. Client calls `Close()`.
3. Server's next `Read()` returns `io.EOF`.
4. Server's next `Write()` returns an error (broken pipe).
5. Client's next `Read()` returns an error.

---

## 2. Layer 3 Gate: smux Stream Multiplexing

### 2.1 Contract Under Test

```
smux.Session wraps a net.Conn (the encrypted Layer 1-2 transport)
smux.Session.OpenStream() → smux.Stream (io.ReadWriteCloser)
smux.Session.AcceptStream() → smux.Stream (server-side accept)

Stack: stream ↔ smux framing ↔ aeadConn ↔ TLS net.Conn ↔ wire
```

The gate tests verify:
1. A single stream can open, exchange data, and close cleanly.
2. Multiple concurrent streams can share one underlying connection.
3. Stream lifecycle (open→data→close) is correct on both sides.
4. The underlying connection close tears down all streams.

### 2.2 Test Harness Primitives

Provided in `internal/mesh/smoke_layer3_test.go`.

```
// newSMuxPair creates two smux Sessions over a net.Pipe() connection.
// Returns (clientSession, serverSession) — the client opens streams,
// the server accepts them.
func newSMuxPair(t *testing.T) (client, server *smux.Session)

// newSMuxOverTLSAndAEAD creates the full v2 stack in-process:
//   net.Pipe → TLS → AES-GCM → smux
// Returns (clientSession, serverSession).
func newSMuxOverTLSAndAEAD(t *testing.T, aesKey []byte) (client, server *smux.Session)
```

### 2.3 Gate Tests

#### Gate L3-01: Stream open, data, close (REQUIRED)

**Test:** `TestSmoke_L3_StreamOpenDataClose`
**Assertions:**
1. Create smux pair over a `net.Pipe()`.
2. Client opens a stream → `clientStream`.
3. Server accepts a stream → `serverStream`.
4. Client writes `"hello over smux stream 1"` to `clientStream`.
5. Server reads from `serverStream` → same bytes.
6. Server writes `"response over smux"` to `serverStream`.
7. Client reads from `clientStream` → same bytes.
8. Client calls `clientStream.Close()`.
9. Server's next `serverStream.Read()` returns `io.EOF`.
10. Verify no goroutine leaks with `runtime.NumGoroutine()` before/after.

**Why this gates the stack:** This is the fundamental smux operation. If a
single stream can't open/close/deliver data, WebSSH and file transfer cannot
work.

#### Gate L3-02: Multiple concurrent streams (REQUIRED)

**Test:** `TestSmoke_L3_MultipleConcurrentStreams`
**Assertions:**
1. Create smux pair.
2. Client opens 5 streams concurrently (goroutines).
3. Server accepts and processes all 5 streams concurrently.
4. Each stream sends a unique payload (e.g., `"stream-N-data"`).
5. Server echoes back `"stream-N-ack"`.
6. Assert each client stream receives the correct echoed response
   (no cross-stream data contamination).
7. Close all streams.
8. Assert all goroutines exit.

**Why this gates the stack:** smux's entire purpose is multiplexing multiple
logical streams over one physical connection. If streams contaminate each
other, the multiplexing is broken.

#### Gate L3-03: Stream capacity — open 100 streams (REQUIRED)

**Test:** `TestSmoke_L3_StreamCapacity`
**Assertions:**
1. Create smux pair.
2. Client opens 100 streams sequentially, each sending 1 KiB and closing.
3. Server accepts all 100 streams, reads 1 KiB from each, and closes.
4. Assert all 100 streams completed without error.
5. Assert no stream ID exhaustion errors.

**Why this gates the stack:** smux uses 32-bit stream IDs. If the
implementation leaks IDs or can't handle the default concurrency, it crashes
at scale. 100 is a smoke threshold, not a stress test.

#### Gate L3-04: Half-close semantics (RECOMMENDED)

**Test:** `TestSmoke_L3_HalfClose`
**Assertions:**
1. Create smux pair.
2. Client opens a stream, writes `"request"`, then closes the write side
   (if smux supports half-close; otherwise skip).
3. Server reads `"request"`, then writes `"response"`.
4. Client reads `"response"`, then reads → `io.EOF`.
5. If half-close is NOT supported, this test documents that fact and is
   skipped.

#### Gate L3-05: Underlying connection close tears down all streams (REQUIRED)

**Test:** `TestSmoke_L3_ConnCloseTearsDownStreams`
**Assertions:**
1. Create smux pair over `net.Pipe()`.
2. Client opens 3 streams.
3. Server accepts 3 streams.
4. Close the underlying `net.Pipe()` connection directly.
5. Assert that within 1 second, ALL 6 streams' `Read()` calls return an
   error (not hang indefinitely).
6. Assert `clientSession.IsClosed()` and `serverSession.IsClosed()` return
   true.

#### Gate L3-06: Full stack smoke — TLS + AES-GCM + smux (REQUIRED)

**Test:** `TestSmoke_L3_FullStack`
**Assertions:**
1. Create the full v2 stack: `net.Pipe → TLS → AES-GCM → smux`.
2. Client opens a stream → writes `"meshdesk v2 full stack"`.
3. Server accepts → reads same bytes → writes back `"v2 ack"`.
4. Client reads `"v2 ack"`.
5. Close the stream.
6. Assert the underlying TLS+AES-GCM transport is still healthy
   (open another stream and repeat).

**Why this gates the stack:** This is the minimum integration assertion that
all three layers compose correctly. If this fails, the stack is broken
regardless of individual layer correctness.

---

## 3. Real-Machine Coverage Plan

Per the task spec and the user's explicit testing requirements in
docs/MESHDESK_V2_DESIGN.md ("所有功能必须实测通过，不能只看单元测试"), the
following novel components require real-machine (multi-node, real network)
coverage.

### 3.1 Hardware Requirements

| Role | Machine | OS | Network | Purpose |
|------|---------|-----|---------|---------|
| Shared/Relay | Alibaba Cloud ECS | Ubuntu 22.04+ | Public IP, port 443 open | Gossip seed, relay, Reality listener |
| Node A | ARM SBC (e.g. RPi 5) | Ubuntu 24.04 | NAT behind home router | Leaf node, WebSSH target |
| Node B | AMD x86 (e.g. mini PC) | Ubuntu 22.04+ | NAT behind home router | Leaf node, Dashboard runner |
| Observer | Any | Any | Any | Run test scripts, collect logs |

### 3.2 Novel Component 1: Gossip Partition Testing

**Component**: Custom gossip replacing memberlist (Phase 4 in v2 plan, ~300
lines of simplification from ~800 lines of v1 gossip).

**Risks identified in discussion** (researcher, motion-856c071ce5a9):
- Distributed correctness under partition
- Endpoint propagation races
- Split-brain recovery

**Coverage gates:**

| ID | Gate | Setup | Assertion | Min Duration |
|----|------|-------|-----------|-------------|
| RM-G1 | **3-node consensus after fresh join** | All 3 nodes start, Node A joins → Node B joins → Node C joins | Within 30s, all 3 nodes see all 3 peers in `gossip.AllNodes()`, each with correct `Endpoints`. | 60s |
| RM-G2 | **Endpoint propagation under churn** | Node A restarts with new port | Within 15s, Node B and C update Node A's endpoint in their local view. Node A's old endpoint is no longer present. | 30s |
| RM-G3 | **Partition: Node B isolated** | iptables DROP all traffic from B to A and C | B's local view shows A and C as unreachable. A and C's view shows B as unreachable. B does NOT form a split-brain (it does not declare itself the only healthy node). | 120s |
| RM-G4 | **Partition heal: Node B reconnected** | Remove iptables rule | Within 30s, all 3 nodes converge to the same membership view. No duplicate entries. No stale endpoints. | 60s |
| RM-G5 | **Relay election after partition heal** | After G4 heals | The shared node (Alibaba ECS) is re-elected as relay. `relay.GetRelay()` returns the shared node's ID. | 60s |

**Evidence required per gate**: Timestamped logs from all 3 nodes showing
gossip message send/receive, membership view snapshots before/after.

### 3.3 Novel Component 2: QUIC Disguise Verification

**Component**: UDP transport disguised as QUIC Short Header packets (Phase 2,
~500 lines: ~285 wire format + ~200 CRYPTO frame bridge).

**Risks identified in research** (docs/QUIC_FEASIBILITY.md):
- quic-go wire package is internal (must copy ~100 lines)
- Initial packet SNI leak
- DPI rejection of malformed QUIC headers

**Coverage gates:**

| ID | Gate | Setup | Assertion | Min Duration |
|----|------|-------|-----------|-------------|
| RM-Q1 | **QUIC packet wire format validation** | Node A sends QUIC-disguised UDP to Node B. Capture with `tcpdump -i any udp port 51820 -w /tmp/quic.pcap`. | Replay pcap through Wireshark QUIC dissector (`tshark -r /tmp/quic.pcap -Y quic`). Assert: every captured UDP packet is dissected as valid QUIC (not "Malformed Packet" or "UDP"). Zero dissection errors. | 30s |
| RM-Q2 | **QUIC Short Header structure compliance (RFC 9000)** | Same capture as Q1. | Extract Short Header packets: (a) Header Form bit = 0, (b) Fixed Bit = 1, (c) Spin Bit present, (d) Destination Connection ID length 1-20 bytes, (e) Packet Number length 1-4 bytes. All fields within RFC 9000 ranges. | 30s |
| RM-Q3 | **TCP fallback when UDP blocked** | iptables DROP udp port 51820 on Node B | Node A detects UDP unreachable within 5s. Traffic switches to TCP (Reality TLS). No data loss. `meshdesk status` shows transport="reality" not "quic". | 60s |
| RM-Q4 | **TCP→UDP upgrade when UDP restored** | Remove iptables rule from Q3 | Node A detects UDP reachable within 15s. Traffic upgrades to QUIC-disguised UDP. `meshdesk status` shows transport="quic". | 60s |
| RM-Q5 | **UDP data plane integrity** | Send 10 MiB over QUIC-disguised UDP | SHA256 of sent data = SHA256 of received data. Throughput ≥ 80% of TCP throughput for the same payload. | 120s |

**Evidence required per gate**: tcpdump pcap files, tshark dissection output,
meshdesk status output, SHA256 checksums.

**Important caveat from research**: If QUIC disguise is deferred to v2.1
(per docs/QUIC_FEASIBILITY.md recommendation), gates RM-Q1 through RM-Q5
are gated on `transport.quic.enabled=true`. Without QUIC, the UDP transport
uses a plain AES-GCM-encrypted datagram format (no QUIC header). In that
case, replace RM-Q1/Q2 with:
> **RM-U1 (QUIC not implemented)**: UDP datagrams carry AES-GCM ciphertext
> only (no recognizable protocol header). Verify with tcpdump that UDP
> payloads fail ALL known protocol dissectors (DNS, QUIC, HTTP/3, WireGuard,
> KCP). This is the anti-fingerprinting assertion.

### 3.4 Novel Component 3: Smart Routing Validation

**Component**: Multi-path selection with latency+bandwidth+connectivity scoring
(Phase 6, ~300 lines, built on PeerManager).

**Risks identified in review** (PeerManager review t_b96f5e99):
- Score formula correctness (EWMA vs median confirmed fixed)
- Hysteresis stability under flapping
- Transport fallback ordering

**Coverage gates:**

| ID | Gate | Setup | Assertion | Min Duration |
|----|------|-------|-----------|-------------|
| RM-R1 | **Correct exit selection by latency** | Node A is the entry. Node B (1ms LAN) and Node C (50ms WAN) are exits to target T. | `selectExit(T)` returns [B, C] where B is first (lower latency). Score(B) < Score(C). | 60s |
| RM-R2 | **Multi-path: traffic split across 2 paths** | Same setup as R1. Generate 20 connections to T. | ≥ 80% of connections go through B (primary). Remaining through C (secondary). No single path carries 100%. | 120s |
| RM-R3 | **Failover on primary path failure** | iptables DROP traffic from A to B | Within 5s, all traffic to T routes exclusively through C. `meshdesk status` shows B's transport as degraded/failed. Zero connection failures (graceful failover). | 60s |
| RM-R4 | **Primary path recovery and re-balancing** | Remove iptables rule from R3 | Within 30s, B is probed and marked healthy. Traffic distribution returns to B-primary, C-secondary. `meshdesk status` shows B as active. | 120s |
| RM-R5 | **Bandwidth-aware scoring** | Saturate Node B's uplink (e.g., `iperf3` to a 4th node) | B's available bandwidth drops below C's. `selectExit(T)` promotes C to primary. After `iperf3` stops, B returns to primary within 30s. | 180s |
| RM-R6 | **Relay fallback when no direct path** | iptables DROP all direct traffic between A and T's exit node. Only relay path available. | `selectExit(T)` includes relay path. Traffic flows A → relay → exit → T. Latency is measurably higher (relay hop). | 120s |
| RM-R7 | **Hysteresis: no flap on brief degradation** | Inject 2s of 100ms artificial latency on B (using `tc netem`) | B is NOT demoted to secondary (hysteresis bonus prevents flap for spikes shorter than `TriggerConsecutive` probes × `ProbeInterval`). | 60s |
| RM-R8 | **Hysteresis: degradation sustained triggers switch** | Inject 60s of 100ms artificial latency on B | B IS demoted to secondary. C becomes primary. After `tc netem` is removed, B returns to primary within 30s. | 180s |

**Evidence required per gate**: `selectExit()` output, transport state
transitions logged by PeerManager, traffic distribution histograms.

---

## 4. Implementation Notes

### 4.1 Where to Put the Tests

```
internal/mesh/
├── smoke_layer12_test.go   ← Layer 1-2 gate tests (new, build tag: smoke)
├── smoke_layer3_test.go    ← Layer 3 gate tests (new, build tag: smoke)
├── smoke_helpers_test.go   ← Shared harness (newLocalTLSPipe, etc.)
├── transport_test.go       ← Existing PeerConn tests (reference pattern)
└── reality_transport_test.go ← Existing Reality tests (do not modify)

test/
├── real_machine/
│   ├── gossip_partition_test.sh       ← RM-G1 through RM-G5
│   ├── quic_disguise_test.sh          ← RM-Q1 through RM-Q5 (or RM-U1)
│   ├── smart_routing_test.sh          ← RM-R1 through RM-R8
│   └── run_all_real_machine.sh        ← Orchestrator
```

### 4.2 Build Tags

```
//go:build smoke
// +build smoke
```

Gate tests use `//go:build smoke` so they do NOT run in normal `go test`.
They require explicit opt-in: `go test -tags=smoke -short ./internal/mesh/`.

This prevents slow TLS handshakes from impacting normal test iteration speed.

### 4.3 Dependencies

Layer 1-2 gates (TLS+AES-GCM): `crypto/tls`, `crypto/aes`, `crypto/cipher`
— all in Go stdlib. No external dependencies.

Layer 3 gates (smux): require a smux library. The v2 design specifies
smux but does not yet name a specific Go package. Candidates:
- `github.com/xtaci/smux` (1.3k stars, pure Go, net.Conn based, MIT license)
- `github.com/hashicorp/yamux` (1.5k stars, maintained by HashiCorp, MPL-2.0)
- `github.com/xtls/smux` (XTLS fork, optimized for proxy use, MPL-2.0)

**Decision deferred**: The smoke test uses a `smuxInterface` abstraction
with `OpenStream()/AcceptStream()` so the concrete implementation can be
swapped without changing the gate assertions. The initial implementation
targets `xtaci/smux` as it is the simplest pure-Go, MIT-licensed option.

### 4.4 CI Integration

```
# .github/workflows/smoke.yml or CI equivalent
- name: Layer smoke gates
  run: go test -tags=smoke -short -count=1 ./internal/mesh/ -run 'Smoke'

- name: Gate check
  run: |
    if go test -tags=smoke -short -json ./internal/mesh/ -run 'Smoke' | \
       jq -e 'select(.Action=="fail" and (.Test//"")|startswith("TestSmoke"))' ; then
      echo "SMOKE GATE FAILED — blocking merge"
      exit 1
    fi
```

Gate tests are **blocking** for any PR that modifies `internal/mesh/`.
A failing gate means the protocol layer contract is broken.

---

## 5. Acceptance Criteria

This document satisfies action item 6/7 when:

1. All 12 unit-level gate tests (6 × L1-2 + 6 × L3) are defined with exact
   assertion text (this document §1.3, §2.3).
2. All 18 real-machine coverage gates are defined with exact setup, assertion,
   and evidence requirements (§3.2–§3.4).
3. The test harness primitives (§1.2, §2.2) specify function signatures and
   semantics sufficient for a developer to implement them without ambiguity.
4. File layout (§4.1) is explicit about which files to create and where.
5. Build tags (§4.2) and CI integration (§4.4) are specified.

**Out of scope for this document** (these are follow-up tasks):
- Implementing the gate tests in Go (→ developer)
- Implementing the real-machine test scripts (→ developer)
- Running the gate tests (→ CI)
- Running the real-machine coverage (→ tester, Phase 10)