# Integration Test Strategy: Proxy + TOTP + Circuit Lifecycle

**Author:** reviewer  
**Date:** 2026-07-26  
**Target:** MeshDesk HEAD (commit 6748888)  

---

## 1. Executive Summary

This strategy covers three integration test tracks identified in the Agora heartbeat motion-5a213c739526:

1. **Track A — Proxy management endpoints behind TOTP auth**: REST API endpoints for circuit CRUD, path selection, and proxy configuration that sit behind session auth + TOTP 2FA enforcement.
2. **Track B — Config validation for combined TOTP+proxy fields**: Validation rules that ensure TOTP auth and proxy subsystem configs are consistent and mutually compatible.
3. **Track C — End-to-end circuit lifecycle tests**: Full lifecycle from HTTP request → circuit creation → chunk dispatch → relay forwarding → exit reassembly → HTTP response, exercising the complete proxy pipeline.

All three tracks use the existing test infrastructure patterns: `internal/web/proxy_status_2fa_test.go`, `internal/web/auth_2fa_integration_test.go`, and `internal/proxy/circuit_manager_test.go`.

---

## 2. Existing Coverage (Baseline)

| Area | Coverage | Gaps |
|------|----------|------|
| Proxy HTTP endpoint | `/api/proxy/status` (GET, read-only, 2FA-exempt) | No management endpoints (CRUD) |
| 2FA enforcement | Middleware: exempt endpoints, enrolled/unenrolled, alert generation | No tests for combined proxy-endpoint + 2FA flow through full middleware chain |
| TOTP integration | Full flow: enroll → login → verify → step-up → lockout → recovery (1,427 lines) | No proxy-specific TOTP interaction |
| Circuit lifecycle | 37 AC-* unit tests: path selection, chunk assignment, FSM, teardown, NACK, key zeroing | All unit-level with in-memory stubs; no end-to-end |
| Config validation | Defaults, save/load round-trip, per-field defaults, relay Enabled flag | No cross-field validation (TOTP+proxy interactions) |

---

## 3. Track A: Proxy Management Endpoints Behind TOTP Auth

### 3.1 Problem

The proxy subsystem currently exposes only one HTTP endpoint: `/api/proxy/status` (GET, read-only, 2FA-exempt). As the proxy system matures, management endpoints are needed:

- Circuit CRUD (create, list, teardown)
- Path selection (list available paths, switch strategy)
- Entry/exit node status

These endpoints must be behind session auth AND TOTP enforcement (when `Require2FA=true`), except for read-only status endpoints that monitoring tools need.

### 3.2 Test File

`internal/web/proxy_management_test.go`

### 3.3 Test Infrastructure

Reuse `new2FAEnforcementTestServer()` from `proxy_status_2fa_test.go`, which creates a server with:
- A bcrypt-hashed web user ("admin" / "testpassword")
- A mock `ProxyStatusProvider` (extend to mock `CircuitManager` methods)
- Full middleware chain: `recoverMiddleware → authMiddleware → require2FAEnforcement`

### 3.4 Test Scenarios

#### PM-01: Circuit list requires session auth
```
GIVEN a server with WebUsers configured, Require2FA=false
WHEN  GET /api/proxy/circuits without session cookie
THEN  HTTP 303 redirect to /login
```

#### PM-02: Circuit list requires TOTP enrollment
```
GIVEN Require2FA=true, admin NOT enrolled in TOTP
WHEN  GET /api/proxy/circuits with valid session cookie
THEN  HTTP 403 (JSON: "2FA enrollment required")
```

#### PM-03: Circuit list succeeds when enrolled
```
GIVEN Require2FA=true, admin IS enrolled in TOTP
WHEN  GET /api/proxy/circuits with valid session cookie
THEN  HTTP 200 + JSON array of circuits
```

#### PM-04: Circuit create (POST) requires TOTP + step-up
```
GIVEN Require2FA=true, admin enrolled but NO step-up token
WHEN  POST /api/proxy/circuits {target: "example.com:443"}
THEN  HTTP 403 "step-up authentication required"
```

#### PM-05: Circuit create succeeds with step-up
```
GIVEN Require2FA=true, admin enrolled AND valid step-up token for "proxy_manage"
WHEN  POST /api/proxy/circuits {target: "example.com:443"}
THEN  HTTP 201 + circuit ID in response
```

#### PM-06: Circuit teardown (DELETE) requires session + TOTP + step-up
```
GIVEN Require2FA=true, admin enrolled AND valid step-up for "proxy_manage"
WHEN  DELETE /api/proxy/circuits/{id}
THEN  HTTP 200 + teardown confirmation
ALSO: circuit is removed from CircuitManager's active list
```

#### PM-07: Proxy status (GET) remains exempt from TOTP
```
(Covered by existing TestRequire2FAEnforcement_ProxyStatusExemptWhenNotEnrolled)
VERIFY: regression test — this behavior must not change
```

#### PM-08: Unauthorized circuit teardown by different user
```
GIVEN Require2FA=true, user "operator" (not "admin") enrolled in TOTP
WHEN  DELETE /api/proxy/circuits/{id} (circuit created by admin's session)
THEN  HTTP 403 (must match the circuit owner's username or be an admin role)
```

### 3.5 Implementation Notes

- Use `httptest.Server` with the full middleware chain (same pattern as `proxy_status_2fa_test.go:fullMiddlewareChain()`)
- Mock `CircuitManager` methods (`ListCircuits`, `TeardownCircuit`) using a test double that implements the existing `CircuitManager` interface
- Register new routes in `server.go:registerRoutes()`:
  - `GET /api/proxy/circuits` → `handleCircuitList` (session auth only)
  - `POST /api/proxy/circuits` → `handleCircuitCreate` (session + TOTP + step-up)
  - `DELETE /api/proxy/circuits/{id}` → `handleCircuitTeardown` (session + TOTP + step-up)
  - `GET /api/proxy/paths` → `handlePathList` (session + TOTP)

---

## 4. Track B: Config Validation for Combined TOTP+Proxy Fields

### 4.1 Problem

`config.go` validates fields within `AuthConfig` and `ProxyConfig` independently but never checks their interaction. Several dangerous combinations exist:

- `Require2FA=true` without `WebUsers` configured → users can never log in (catch-22)
- `Require2FA=true` with proxy exposed publicly → proxy health endpoints work but management is blocked (correct behavior, but needs documentation)
- SS listener port conflicts with web server port
- Exit node `AllowAllPorts=true` without audit logging → legal risk
- Circuit idle timeout < keepalive interval → pathological behavior
- `DebugFixedChunks=true` in production config → fingerprintable

### 4.2 Test File

`internal/config/config_combined_validation_test.go`

### 4.3 Test Scenarios

#### CV-01: Require2FA with no WebUsers is a validation error
```
GIVEN config with auth.require_2fa=true and auth.web_users=[]
WHEN  Validate() is called
THEN  error: "require_2fa requires at least one web user configured"
```

#### CV-02: Require2FA with proxy management endpoints — info-level warning
```
GIVEN config with auth.require_2fa=true, web_users=[admin], proxy.ss.port=8388
WHEN  Validate() is called
THEN  warning (not error): "proxy management endpoints will require TOTP authentication"
```

#### CV-03: SS port conflicts with web port
```
GIVEN config with node.web=":8080" and proxy.ss.listen_addr="0.0.0.0:8080"
WHEN  Validate() is called
THEN  error: "SS listen address conflicts with web server address"
```

#### CV-04: Exit AllowAllPorts requires audit logging
```
GIVEN config with proxy.exit.allow_all_ports=true and proxy.exit.audit_log_dir=""
WHEN  Validate() is called
THEN  error: "allow_all_ports requires audit_log_dir to be configured"
```

#### CV-05: Circuit idle timeout >= keepalive interval
```
GIVEN config with proxy.circuit.idle_timeout=30, proxy.circuit.keepalive_interval=60
WHEN  Validate() is called
THEN  error: "idle_timeout must be greater than keepalive_interval"
```

#### CV-06: DebugFixedChunks in production
```
GIVEN config with proxy.debug_fixed_chunks=true (no debug flag set)
WHEN  Validate() is called
THEN  error: "debug_fixed_chunks must not be enabled in production"
VERIFY: not triggered when MESHDESK_DEBUG=true env var is set
```

#### CV-07: ChunkerStrategy validation
```
GIVEN config with proxy.chunker_strategy="invalid-strategy"
WHEN  Validate() is called
THEN  error: "unsupported chunker strategy: invalid-strategy (valid: fixed-16k, bounded-4k-64k)"
```

#### CV-08: PathSelection mode validation
```
GIVEN config with proxy.path_selection.mode="manual", paths=[] (empty)
WHEN  Validate() is called
THEN  error: "manual path selection requires at least one configured path"
```

#### CV-09: PathSelection mode="auto" with insufficient relay candidates
```
GIVEN config with proxy.path_selection.mode="auto", no P2P enabled, no static peers
WHEN  Validate() is called
THEN  warning: "auto path selection may fail without P2P or static peers"
```

#### CV-10: TOTPStoreDir is writable
```
GIVEN config with auth.totp_store_dir="/nonexistent/readonly/dir"
WHEN  Validate() is called
THEN  error: "totp_store_dir is not accessible: <os error>"
```

### 4.4 Implementation Notes

- Add a `Validate() error` method to `config.Config` that returns `*ConfigErrors` (multiple errors/warnings)
- Use `ConfigErrors` type with `.Errors() []string` and `.Warnings() []string` methods
- Call `Validate()` from `Load()` after defaults are applied, log warnings but return errors as actual errors
- Distinguish between "production" mode (no `MESHDESK_DEBUG` env) and "development" mode using `os.Getenv("MESHDESK_DEBUG")`

---

## 5. Track C: End-to-End Circuit Lifecycle Tests

### 5.1 Problem

The circuit lifecycle tests in `circuit_manager_test.go` are unit-level: in-memory latency matrices, stub TCP listeners (`listenStub()`), and direct `CircuitManager` method calls. No test exercises the full proxy pipeline:

```
Client → SS Listener → Chunker → Encrypt → Relay (via mesh/net.Pipe) → Exit Reassembler → Target
```

### 5.2 Test File

`internal/proxy/e2e_circuit_lifecycle_test.go`

### 5.3 Test Infrastructure: In-Process Mesh Simulator

Build an in-process mesh simulator that connects the entry node, relay, and exit node through `net.Pipe` connections:

```go
type meshSimulator struct {
    entry  *EntryNode       // SS listener + chunker
    relay  *RelayHandler    // Forwarding relay
    exit   *ExitNode        // Reassembler + target dialer
    cm     *CircuitManager  // Circuit lifecycle
    
    // net.Pipe connections:
    // entry → relay → exit
    
    connER  net.Conn  // entry → relay
    connRE  net.Conn  // relay → entry
    connRX  net.Conn  // relay → exit
    connXR  net.Conn  // exit → relay
}
```

### 5.4 Test Scenarios

#### E2E-01: Full happy path — small payload
```
GIVEN in-process mesh with entry → relay → exit topology
WHEN  EntryNode receives 256 bytes from a simulated client over the SS listener
THEN  CircuitManager creates a circuit (state: ACTIVE)
AND   Chunks are dispatched on both paths (round-robin)
AND   Relay forwards encrypted chunks to exit
AND   Exit reassembles and delivers payload to target
AND   Target response flows back through exit → relay → entry → client
AND   Circuit transitions from ACTIVE to CLOSED on teardown
AND   Keys are zeroed after close
```

#### E2E-02: Large payload — multi-chunk dispatch
```
GIVEN EntryNode configured with chunker_strategy="fixed-16k"
WHEN  Client sends 64KB payload over SS
THEN  Payload is split into 4 chunks (16KB each)
AND   Chunks 0,2 dispatched on path 0; chunks 1,3 on path 1 (round-robin)
AND   Exit reassembles in order: 0,1,2,3
AND   Final delivered payload matches original
```

#### E2E-03: Circuit setup timeout
```
GIVEN relay is unreachable (net.Pipe never responds)
WHEN  Client connects to SS listener and sends data
THEN  CircuitManager transitions CREATING → CLOSED after SetupTimeout (10s)
AND   EventCircuitClosed is emitted with reason="setup timeout"
AND   EntryNode returns error to client
```

#### E2E-04: Single path failure — chunks reroute
```
GIVEN in-process mesh with 2 paths (relayA, relayB)
WHEN  relayA's TCP connection is severed mid-stream
THEN  CircuitPath[0].MissKeepalive is called repeatedly
AFTER 4 missed keepalives (40s at 10s timeout): PathHealth transitions to UNHEALTHY
AND   All subsequent chunks route to path 1 (healthy path)
AND   Circuit remains ACTIVE on the surviving path
```

#### E2E-05: Both paths fail — circuit teardown
```
GIVEN both relayA and relayB connections are severed
WHEN  4 keepalive intervals pass on both paths
THEN  BothCircuitPaths become UNHEALTHY
AND   CircuitManager auto-tears down: ACTIVE → TEARDOWN → CLOSED
AND   EventPathUnhealthy emitted for each path
AND   EventCircuitClosed emitted
AND   Keys are zeroed
```

#### E2E-06: Keepalive restores path health
```
GIVEN path 0 in DEGRADED state (2 missed keepalives)
WHEN  path 0 receives a keepalive response
THEN  PathHealth transitions DEGRADED → HEALTHY
AND   Chunk assignment resumes using both paths
```

#### E2E-07: NACK retry and recovery
```
GIVEN chunk 5 is lost (exit never receives it)
WHEN  NACKTimeout expires (5s default)
THEN  Exit sends NACK for chunk 5
AND   Entry re-dispatches chunk 5 on the healthier path
AND   Exit receives and reassembles
AFTER MaxNACKRetries (3) without receipt: circuit is closed
```

#### E2E-08: Idle teardown
```
GIVEN active circuit with IdleTimeout=5s
WHEN  no data flows for 5+ seconds
THEN  CircuitManager sweeps idle circuits
AND   Circuit transitions ACTIVE → TEARDOWN (flush in-flight) → CLOSED
AND   ChunkStreamEnd markers sent on both paths
```

#### E2E-09: DoS protection — MaxCircuitsPerExit
```
GIVEN MaxCircuitsPerExit=1
WHEN  second circuit is created with the same exit node
THEN  CreateCircuit returns ErrTooManyCircuits
AND   first circuit remains ACTIVE
```

#### E2E-10: End-to-end latency measurement
```
GIVEN EntryNode with path_selection.mode="latency"
WHEN  1000 chunks are dispatched on 2 paths with 20ms and 80ms RTT
THEN  WeightedStrategy assigns ~80% of chunks to the faster path
AND   Measured end-to-end latency is within 2x of the faster path's RTT
```

### 5.5 CircuitManager Interface Extraction

To make the CircuitManager testable from the web handler layer and e2e tests, extract the following interface:

```go
type CircuitManagerAPI interface {
    CreateCircuit(targetAddr, entryID, exitID string, candidates []CandidateRelay) (CircuitIDType, error)
    HandleCircuitAck(cid CircuitIDType, ack *CircuitAck) error
    TeardownCircuit(cid CircuitIDType, reason string, sendChunkEnd func(pathIdx int) error) error
    ListCircuits() []CircuitInfo
    GetCircuit(id CircuitIDType) (*Circuit, bool)
    GetStats() CircuitStats
    OnCircuitEvent(cb CircuitEventCallback)
    UpdateLatencyMatrix(edges []LatencyEdge)
}
```

This allows:
- `proxy_management_test.go` to inject a mock `CircuitManagerAPI`
- `e2e_circuit_lifecycle_test.go` to use the real implementation
- `server.go` to accept `CircuitManagerAPI` in `Deps` for test injection

---

## 6. Implementation Order and Dependencies

```
Phase 1 (Foundational):
  1. Extract CircuitManagerAPI interface              (unblocks Track A + C)
  2. Add Validate() to config.Config                  (unblocks Track B)
  3. Add test helpers: meshSimulator, fullMiddlewareChain export

Phase 2 (Independent — can parallelize):
  A. Track B: config_combined_validation_test.go      (no deps beyond Phase 1.2)
  B. Track A: proxy_management_test.go                (depends on Phase 1.1)
  C. Track C: e2e_circuit_lifecycle_test.go           (depends on Phase 1.1 + 1.3)

Phase 3 (Integration):
  Run all three tracks together, verify no regressions
```

---

## 7. Acceptance Criteria

| Criterion | Verification |
|-----------|-------------|
| All Track A scenarios pass (PM-01 through PM-08) | `go test -v -run "^TestPM_" ./internal/web/` |
| All Track B scenarios pass (CV-01 through CV-10) | `go test -v -run "^TestCV_" ./internal/config/` |
| All Track C scenarios pass (E2E-01 through E2E-10) | `go test -v -run "^TestE2E_" ./internal/proxy/` |
| No regressions on existing tests | `go test ./...` with zero failures |
| Test infrastructure is reusable | `new2FAEnforcementTestServer`, `meshSimulator`, `CircuitManagerAPI` interface |
| Config validation integrated into Load() | `config.Load()` calls `Validate()` and returns errors/warnings |

---

## 8. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| CircuitManagerAPI breaks when methods change | Medium | Low | Interface extraction is mechanical; compiler enforces compliance |
| meshSimulator flaky due to net.Pipe timing | Medium | Medium | Use generous timeouts (50ms+); avoid race-prone patterns |
| Config validation too strict and breaks existing configs | Low | High | Warnings are logged only; errors require explicit opt-in (new settings) |
| 2FA enforcement on proxy endpoints disrupts existing monitoring | Low | High | `/api/proxy/status` remains permanently exempt; management endpoints are opt-in |