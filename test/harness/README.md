# MeshDesk Real-Device Integration Test Harness

Real-device integration tests for MeshDesk that spawn actual `meshdesk`
subprocesses, configure them with WireGuard identities and full-mesh peer
relationships, and run end-to-end scenarios against the live cluster.

## What it tests

The harness covers all 7 MeshDesk stop-condition criteria:

| ID | Category | Description |
|----|----------|-------------|
| C1 | Mesh VPN | P2P mesh connectivity — all nodes healthy with listening ports |
| C2 | NAT Traversal | Node reachability through full-mesh peer configuration |
| C3 | Resilience | Process lifecycle resilience (survives startup/health checks) |
| C4 | WebSSH | WebSocket terminal session lifecycle, error paths, cleanup, max-sessions enforcement |
| C5 | File Transfer | File upload API endpoint availability |
| C6 | Service Mgmt | Service management API endpoint availability |
| C7 | Monitoring | Dashboard rendered with expected content and live metrics |

## Quick Start

```bash
# 1. Build the binary
cd /root/meshdesk
go build -o meshdesk ./cmd/meshdesk/

# 2. Run the full suite (3-node cluster, ~0.5s)
go test -v -timeout 60s ./test/harness/ -run TestSuiteRealDevice

# 3. Run individual tests
go test -v -timeout 30s ./test/harness/ -run TestQuickSanity
go test -v -timeout 30s ./test/harness/ -run TestDashboardAccess
go test -v -timeout 30s ./test/harness/ -run TestPeerConnectivity
go test -v -timeout 30s ./test/harness/ -run TestWebSSHLifecycle
go test -v -timeout 30s ./test/harness/ -run TestWebSSHSessionCleanup

# 4. Run all harness tests
go test -v -count=1 ./test/harness/

# 5. Run with race detector (recommended for regression testing)
go test -v -race -count=1 ./test/harness/
```

## Test Structure

```
test/harness/
├── harness.go         # Core framework: process lifecycle, health checks, scenarios
├── harness_test.go    # Test functions covering all 7 stop-condition criteria
└── README.md          # This file
```

## How It Works

Unlike existing in-process mock tests (`net.Pipe`, `inProcMesh`), the harness:

1. **Spawns real `meshdesk` subprocesses** — exercising the full production code path
2. **Generates unique WireGuard keypairs** per node (same crypto as `internal/mesh/peer`)
3. **Creates YAML configs** with full-mesh peer relationships
4. **Health-checks nodes** via `/proc` liveness, UDP port scanning, and HTTP probing
5. **Runs test scenarios** against the live cluster via HTTP/WebSocket API calls
6. **Collects structured JSON results** with pass/fail/skip status and duration

## Test Functions

| Test | Nodes | Duration | Description |
|------|-------|----------|-------------|
| `TestSuiteRealDevice` | 3 | ~0.5s | Complete 9-phase suite across all 7 criteria |
| `TestQuickSanity` | 1 | ~0.5s | Fast smoke test — web UI reachable |
| `TestBinaryBuildAndSmoke` | 0 | ~1s | Builds binary from source, verifies `--gen-key` |
| `TestNodeLifecycle` | 1 | ~0.5s | Full lifecycle: start, health check, stop |
| `TestFileUploadAPI` | 1 | ~0.5s | File upload endpoint availability |
| `TestServiceAPI` | 1 | ~0.5s | Service management API |
| `TestDashboardAccess` | 1 | ~0.5s | Dashboard renders with expected content |
| `TestPeerConnectivity` | 3 | ~0.5s | All mesh ports reachable, peer activity in logs |
| `TestGracefulShutdown` | 1 | ~1.5s | SIGINT clean shutdown |
| `TestWebSSHLifecycle` | 1 | ~0.5s | WebSSH WS connect → status → close lifecycle |
| `TestWebSSHErrorPath` | 1 | ~0.5s | WebSSH error handling: unresolvable peer |
| `TestWebSSHSessionCleanup` | 1 | ~1.0s | Session cleanup after disconnect, reconnect test |
| `TestWebSSHMaxSessions` | 1 | ~0.5s | Max sessions enforcement via real WS connections |
| `TestWebSSHDataRaceRegression` | 3 | ~1.0s | Full race regression: 4 WebSSH scenarios on 3-node cluster with `-race` |

## WebSSH Lifecycle Coverage

The harness verifies the complete WebSSH session lifecycle against a real
meshdesk collector node:

- **Connect**: WebSocket upgrade at `/ws/terminal?node=<peerID>&cols=80&rows=24`
- **Status flow**: `connecting` → `connected` or `error` messages received
- **Error paths**: Unresolvable peer returns proper error, hub stays alive
- **Cleanup**: Disconnect → session removed → reconnect succeeds (no zombies)
- **Max sessions**: Multiple concurrent WS connections exercise hub limits
- **Data-race**: All scenarios run under `-race` detector against 3-node cluster

## Thread Safety

The harness uses a `safeBuffer` (mutex-protected `bytes.Buffer`) for subprocess
log capture, preventing data races between the subprocess's stdout/stderr
goroutines and the test goroutine's health-check reads. All tests pass with
`go test -race` — zero races detected.

## Skipping Tests

Set `MESHDESK_SKIP_REAL=1` to skip tests that require a pre-built binary:

```bash
MESHDESK_SKIP_REAL=1 go test ./test/harness/
```

`TestBinaryBuildAndSmoke` always runs — it builds the binary itself.

## Extending

To add a new scenario:

```go
func (h *Harness) ScenarioNewFeature() (result, details string) {
    // Your test logic here...
    return "PASS", "feature verified"
}

// In your test:
h.RunScenario("C8-new-feature", "category", "Description", h.ScenarioNewFeature)
```
