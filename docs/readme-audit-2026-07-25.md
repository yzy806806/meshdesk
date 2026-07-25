# README Accuracy Audit — MeshDesk

Date: 2026-07-25 | Commit: b9e99bc

## Summary

The README.md (and README_CN.md) contain substantial inaccuracies. Of the ~15 feature claims examined, 9 are false or misleading, 3 are partially true (backend code exists but no frontend or HTTP wiring), and only 3 are accurate.

## Detailed Findings

### 1. Protocol/Encryption Claims — FALSE

**README claims:** "KCP/QUIC/TCP" transport and "ChaCha20-Poly1305" encryption.

**Reality:** The project uses WireGuard (wireguard-go) with gVisor netstack, not KCP/QUIC/TCP. WireGuard uses ChaCha20-Poly1305 internally so the cipher name is not wrong, but the transport protocol claim is completely inaccurate.

**Evidence:** `go.mod` imports `golang.zx2c4.com/wireguard/*`, internal/mesh/node.go uses wireguard-go device/netstack.

### 2. Web UI Claims — FALSE (Critical)

**README claims:** "Web UI", "Network topology visualization in Web UI", "Web UI" for file management and service management.

**Reality:** `web/templates/` and `web/static/` directories exist but are COMPLETELY EMPTY. `cmd/meshdesk/main.go` has the `--web` flag but does NOT start any HTTP server — it only logs a message. No `http.ListenAndServe`, no router, no template rendering.

**Evidence:** `main.go` imports only `config` and `mesh` packages. Zero HTTP server code.

### 3. CLI Flag Claims — FALSE

**README claims:** `meshdesk --network mynet --secret mysecret --web :8080`

**Reality:** Actual flags are `--config`, `--web` (boolean), `--gen-key`. No `--network` or `--secret` flags exist.

**Evidence:** `go run ./cmd/meshdesk/ --help` output.

### 4. Config Example — FALSE

**README claims:** Flat YAML with keys like `network`, `secret`, `web`, `peers` (as host:port strings), `tun`, `tun_ip`.

**Reality:** Actual config uses nested structs: `node.identity`, `node.hostname`, `node.web`, `mesh.port`, `peers[].public_key`, `peers[].endpoint`, `peers[].allowed_ips`, `peers[].capabilities`, `monitoring.*`, `webssh.*`, `auth.web_users`.

**Evidence:** `internal/config/config.go` — Config, NodeConfig, MeshConfig, PeerConfig structs.

### 5. File Management Claims — PARTIALLY FALSE

**README claims:** "Upload/download files via web UI", "Drag-and-drop support", "File browser with permissions"

**Reality:** Backend transfer protocol (`internal/transfer/protocol.go`) exists with Send/Receive functions. But there is NO HTTP endpoint, NO web UI, NO drag-and-drop, NO file browser. Just the low-level protocol library.

### 6. Service Management Claims — PARTIALLY FALSE

**README claims:** "Start/stop/restart systemd services", "View service logs", "Enable/disable services"

**Reality:** Backend `internal/service/manager.go` has ExecBackend with Start/Stop/Restart/Status/Logs/List. But NO HTTP endpoint, NO web UI. "Enable/disable" is NOT implemented even in backend (only start/stop/restart).

### 7. Monitoring "Historical Charts" and "Alerting" — FALSE

**README claims:** "Historical charts" and "Alerting (threshold-based, via webhook/Telegram)"

**Reality:** `internal/monitor/` has metric collection, aggregation, ring buffer, and store. But there is ZERO alerting code (no webhook, no Telegram, no threshold checks) and ZERO charting code (no frontend exists anyway).

**Evidence:** Grep for "alert", "webhook", "telegram", "chart", "recording" across all Go files returned zero results.

### 8. "Session Recording" — FALSE

**README claims:** "Session recording (optional)" for Web Terminal

**Reality:** `internal/webssh/` handles WebSocket-to-SSH bridging but contains no session recording logic.

### 9. xterm.js — FALSE

**README claims:** "Browser-based terminal (xterm.js + WebSocket)"

**Reality:** `web/static/` is empty. No xterm.js files. Backend WebSSH handler exists but no frontend to use it.

### 10. install.sh — FALSE

**README claims:** `curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/install.sh | bash`

**Reality:** No `install.sh` file exists in the repository.

### 11. Comparison Table — MISLEADING

The table claims MeshDesk has "✅ (Web UI)" for Network topology view when no Web UI exists. It claims "File transfer: ✅" without noting this is backend-only with no frontend.

### 12. CLI Example — WRONG

The `--web :8080` syntax is wrong. `--web` is a boolean flag; the web address must be set in config YAML as `node.web: ":8080"`.

## What IS Accurate

| Claim | Status |
|-------|--------|
| Decentralized P2P architecture | ✅ |
| WireGuard-based mesh VPN | ✅ (though README says KCP/QUIC) |
| Server monitoring (CPU/memory/disk/network) | ✅ Backend exists |
| WebSSH handler | ✅ Backend exists |
| Service status (systemd units) | ✅ Backend exists |
| NAT traversal with relay nodes | ✅ |
| Automatic peer discovery | ✅ |
| Single binary | ✅ |
| Requires root | ✅ |
| MIT License | ✅ |

## Recommendation

The README should be rewritten to accurately reflect what currently EXISTS in the codebase:
- Backend: Mesh VPN (WireGuard), Monitoring collection, WebSSH bridge, File transfer protocol, Service management via systemctl
- Frontend: NOT YET IMPLEMENTED (under construction — card t_dbac3ce3)
- Remove all feature claims that don't exist yet
- Fix config/YAML example to match actual config.go structure
- Fix CLI examples to use actual flags
- Remove install.sh reference until created