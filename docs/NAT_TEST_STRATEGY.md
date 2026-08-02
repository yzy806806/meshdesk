# NAT Traversal Testing Strategy

## Overview

This document defines the testing strategy for the meshdesk NAT traversal subsystem
(`internal/p2p/nat.go`, `nat_stun.go`, `nat_holepunch.go`). The strategy ensures
complete coverage of the NAT traversal state machine, STUN discovery, hole-punching,
relay fallback, and re-probe mechanisms.

Test file: `internal/p2p/nat_test.go`

## Test Categories

### 1. Unit Tests — Pure Functions

| Function | Tests | What's Covered |
|----------|-------|----------------|
| `classifyNat` | 3 | Same address, symmetric (same IP diff port), symmetric (different IP) |
| `CanHolePunch` | 2 | Table-driven (9 combos) + full matrix (36 combos: 6x6 NatType) |
| `isPublicIP` | 1 | Table-driven (11 cases): public, RFC1918, CGNAT, loopback, link-local |
| `NatState.String()` | 1 | All 9 states: INIT through FAILED |
| `generateCircuitID` | 1 | Format (hex, 32 chars), uniqueness (100 iterations) |
| `inferNAT` | 1 | Returns "restricted_cone" for valid and empty endpoints |
| `safeShortKey` | 1 | 6 boundary cases: empty, 1-char, 7-char, 8-char, 9-char, long |
| `NatType` constants | 1 | 6 string values: none, full_cone, restricted, port_restricted, symmetric, unknown |
| `NatType.Classify` | 1 | All 6 NatType string representations |

### 2. STUN Client Tests

| Test | Type | What's Covered |
|------|------|----------------|
| Default servers | Unit | Zero-value constructor gives 2 default STUN servers, 5s timeout |
| Custom servers | Unit | Custom server list and timeout propagated correctly |
| Empty servers (error) | Unit | `servers=[]` after construction → Discover returns error |
| Bad server address | Unit | Unresolvable server → error (not panic) |
| Real server | Integration | Queries Google STUN, verifies non-empty mapped address |
| Server failover | Integration | First server unreachable → falls back to second |

### 3. Hole-Puncher Tests

| Test | What's Covered |
|------|----------------|
| Invalid endpoint | Malformed address → `Punch()` returns error, no panic |
| Unreachable endpoint | TEST-NET-1 address → returns result without hanging |
| Register/Unregister | Peer added then removed, registration tracking correct |
| Attempt punch unregistered | Unregistered peer → error |
| Concurrent register | 20 goroutines register+unregister → thread-safe |

### 4. NAT Traversal State Machine Tests

#### Acceptance Criteria Tests (from P2P_NETWORKING_SPEC.md)

| AC | Test | What's Verified |
|----|------|-----------------|
| AC-5 | `TestNatTraversal_AC5_DirectConnection` | Full-cone + full-cone → INIT → STUN_DISCOVERY → DIRECT_PROBE → DIRECT → ACTIVE |
| AC-6 | `TestNatTraversal_AC6_RelayFallback` | Symmetric + symmetric → forced relay → RELAY_FALLBACK, WG endpoint updated to relay IP |
| AC-7 | `TestNatTraversal_AC7_DirectReprobe` | RELAY_FALLBACK → DIRECT_REPROBE → DIRECT on success, endpoint switched from relay to direct |

#### State Machine Path Coverage

| Path | Test | States Traversed |
|------|------|-----------------|
| Direct connection | AC-5 | INIT → STUN_DISCOVERY → DIRECT_PROBE → DIRECT → ACTIVE |
| Both symmetric → relay | AC-6, BothSymmetric_ForcedRelay | INIT → STUN_DISCOVERY → RELAY_FALLBACK |
| Re-probe to direct | AC-7 | RELAY_FALLBACK → DIRECT_REPROBE → DIRECT |
| Re-probe fails → relay | ReprobeFailed_BackToRelay | RELAY_FALLBACK → DIRECT_REPROBE → RELAY_FALLBACK |
| No endpoints → relay | DirectProbe_NoEndpoints_ToRelay | DIRECT_PROBE (empty eps) → RELAY_FALLBACK |
| No endpoints + relay=disabled → RETRY | DirectProbe_NoEndpoints_RelayDisabled | DIRECT_PROBE (empty eps) → RETRY |
| Relay disabled | RelayDisabled | DIRECT_PROBE → RETRY → FAILED |
| RETRY → FAILED | HandleRetry_TransitionsToFailed | RETRY (retries >= max) → FAILED |
| Backoff active | Retry_BackoffActive | RETRY stays RETRY during backoff (10s) |
| FAILED terminal | Failed_TerminalState | FAILED state never transitions further |
| Nil relay → FAILED | TransitionToRelay_NilRelay | RELAY_FALLBACK (nil relay) → FAILED |
| No relay candidates → RETRY | NoRelayCandidates_Retry | RELAY_FALLBACK (no candidates) → RETRY |
| Re-probe no endpoints | Reprobe_NoEndpoints_BackToRelay | DIRECT_REPROBE (empty eps) → RELAY_FALLBACK |
| Re-probe multiple cycles | Reprobe_MultipleCycles | Multiple re-probe cycles, state stays RELAY_FALLBACK |

### 5. Session Management Tests

| Test | What's Covered |
|------|----------------|
| Session creation | `InitiateConnection` creates session, state advances past INIT |
| Session state for unknown peer | Returns NatInit |
| Session deduplication | Second `InitiateConnection` for same peer is no-op |
| Session removal | `RemoveConnection` cleans session + puncher registration |
| All sessions snapshot | Multiple sessions returned correctly |
| All sessions concurrent modification | AllSessions() during concurrent RemoveConnection — thread-safe |
| Snapshot immutability | Modifying original doesn't affect snapshot |

### 6. Config & Lifecycle Tests

| Test | What's Covered |
|------|----------------|
| Default config | All defaults: STUN servers, reprobe 120s, MaxRetries=10, RelayMode=auto, MaxRelayHops=2 |
| From P2pConfig | Custom values propagate correctly |
| Double start | Second Start() returns error |
| Stop not started | No-op, no panic |
| Local discovery | SetLocalDiscovery + accessors |
| SetGossipLayer | Wires gossip layer + localKey |

### 7. Relay Messaging Tests (Nil Gossip Safety)

| Test | What's Covered |
|------|----------------|
| sendRelaySetup nil gossip | Returns empty circuit ID (no crash) |
| sendRelayTeardown nil gossip | No-op (no crash) |

### 8. Concurrent Safety Tests

| Test | What's Covered |
|------|----------------|
| Concurrent access | 10 goroutines: InitiateConnection + GetSession + SessionState + AllSessions |
| Concurrent initiate+remove | 5 peers concurrently initialized and removed — session map ends empty |
| HolePunchCoordinator concurrent | 20 goroutines concurrent register/unregister |
| AllSessions under mutation | 100 reads concurrent with 20 removes |

### 9. Session Field Verification

| Test | What's Covered |
|------|----------------|
| Fields after relay fallback | State, Endpoints, RemoteNatType, RelayVia correct after transition |

## Coverage Gap Analysis

### Covered
- All 9 NatState values and their String() representations
- All 6 NatType values and their string constants
- classifyNat: same address, symmetric (IP:port), different IP
- CanHolePunch: full 6x6 matrix (36 combinations)
- isPublicIP: RFC1918 (10/8, 172.16/12, 192.168/16), CGNAT (100.64/10), loopback, link-local, unspecified
- STUN: construction, bad server, empty servers, real server, failover
- Hole-punch: invalid endpoint, unreachable, register/unregister, concurrent
- State machine: all 9 states in various transition paths
- Re-probe: success, failure, multiple cycles, no endpoints
- Relay: forced (both symmetric), nil relay, no candidates, setup/teardown with nil gossip
- Lifecycle: start, double start, stop, stop when not started
- Config: defaults, custom, conversion from P2pConfig
- Concurrency: access, init+remove, register/unregister, AllSessions under mutation

### Not Covered (Noted for Future)

1. **Real network integration tests** — hole-punching between two actual NAT'd nodes. Requires test infrastructure with two hosts behind different NAT types.
2. **WireGuard handshake integration** — verifying WireGuard key exchange after hole-punch. Requires WireGuard kernel module.
3. **STUN NAT classification accuracy** — verifying classifyNat correctly identifies real NAT types (full_cone vs restricted vs symmetric). Requires controlled NAT environment.
4. **Relay circuit setup with real gossip** — end-to-end relay circuit creation through memberlist.SendReliable. Requires running memberlist cluster.
5. **Reprobe timing accuracy** — verifying the 120-second reprobe interval is honored precisely. Test uses shortened interval.
6. **Retry exponential backoff with MaxRetries > 0** — the full backoff cycle with 10s first retry. Test verifies backoff is active but can't wait full 10s.

## Running the Tests

```bash
# All NAT-related tests
go test ./internal/p2p/ -run "TestNat|TestStun|TestHolepunch|TestClassify|TestSafe|TestCircuit|TestInfer|TestDefault|TestCanHole|TestGenerate|TestIsPublic|TestNatType" -v

# With race detector
go test -race ./internal/p2p/ -run "TestNat|TestStun|TestHole|TestClassify"

# Full p2p test suite
go test ./internal/p2p/
```

## Test Count Summary

| Category | Count |
|----------|-------|
| Pure function unit tests | 10 |
| STUN client tests | 6 |
| Hole-punch tests | 5 |
| Acceptance criteria tests | 3 |
| State machine path tests | 15 |
| Session management tests | 6 |
| Config & lifecycle tests | 5 |
| Relay messaging tests | 2 |
| Concurrent safety tests | 4 |
| Session field tests | 1 |
| **Total** | **57** |
