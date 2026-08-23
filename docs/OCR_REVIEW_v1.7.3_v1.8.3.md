# OCR Code Review — v1.7.3 → v1.8.3

> Review date: 2026-08-20  
> Range: v1.7.3..v1.8.3 (9 files, +470/-195)  
> Reviewer: host agent (OCR delegation mode)

## Summary

No critical or high severity issues found. The changeset covers UDP hole-punch restoration (5 root-cause fixes), hole-punch engine hardening (7 bugs + 5 review fixes), UDP stream leak fix, auto-reconnect, meta replay, and config zone/p2p.enabled additions.

## Findings

### Medium

#### M1: `triggerHolePunch` function signature formatting
- **File**: `internal/app/holepunch.go`, `triggerHolePunch` function
- **Issue**: Function body opening brace `{` is followed by a tab and `if a.holepunch == nil {` on the same line — the `if` is not on its own line. This passes `gofmt` (Go allows it) but is unconventional and likely an artifact of the patch tool.
- **Severity**: medium (maintainability)
- **Fix**: Run `gofmt -w internal/app/holepunch.go`

#### M2: `DialUDPStream` ACK confirmation uses 50ms sleep polling
- **File**: `internal/mesh/mux_udp.go`, `DialUDPStream` confirmation loop
- **Issue**: The ACK confirmation loop polls `len(sc.inflight)` every 50ms via `time.Sleep(50 * time.Millisecond)`, for up to `udpDialConfirmTimeout` (1s). This is not a strict busy-wait (has sleep), but produces ~20 polling iterations per dial. Under high-concurrency punch scenarios, this adds unnecessary CPU overhead.
- **Severity**: medium (performance)
- **Fix**: Use a channel signal from `advanceBase` (when inflight drains) instead of polling. Larger refactor — acceptable as-is for now.

### Low

#### L1: SERVER timeout checks `HasPeerSession` (smux) not UDP session
- **File**: `internal/app/holepunch.go`, SERVER timeout goroutine
- **Issue**: After 15s SERVER timeout, checks `!a.node.HasPeerSession(peerKey)` to decide whether to clear the hole endpoint. `HasPeerSession` checks for a smux session (which may exist via TCP relay), not a UDP data-plane session. If a relay session exists but UDP session does not, the hole endpoint is not cleared.
- **Severity**: low — CLIENT-side `ClearHoleEndpoint` on dial failure covers the main case. SERVER edge case is unlikely to permanently block (next punch cycle will retry after CLIENT clears its side).
- **Fix**: Use a dedicated `HasUDPSession` check, or unconditionally clear on SERVER timeout.

#### L2: `peerKey[:8]` assumes minimum 8-character key
- **File**: `internal/app/holepunch.go`, multiple locations
- **Issue**: `peerKey[:8]` in log statements assumes peerKey is at least 8 characters. Public keys are 64-char hex, so this is always safe in practice. An empty or short key would panic.
- **Severity**: low — cannot trigger with valid public keys

#### L3: `goto reconnect` label in `p2p.go`
- **File**: `internal/app/p2p.go`, `startP2P` goroutine
- **Issue**: Uses `goto reconnect` to jump back to the outer `AddPeer` loop after detecting session loss. Go allows `goto` but it is uncommon. Logic is correct — the goto breaks out of the inner `select` loop and re-enters the outer `for` loop.
- **Severity**: low (style) — functional, could be replaced with a labeled break for readability


---

## OCR Code Review — v2.0.0 (PunchDataplane)

> Review date: 2026-08-23
> Range: 8251368..05d4835 (3 commits, +479/-64 lines)

### Findings

**No critical or high issues found.**

#### Medium

**M1: PunchDataplane.Write strips 4B length prefix heuristically**
- File: `punch_dataplane.go` Write()
- The heuristic checks `framedLen > 0 && framedLen <= len(p)-4 && framedLen <= 1500`.
  A malformed IP packet whose first 4 bytes happen to look like a valid length
  would be incorrectly stripped. Risk: low (TUN packets always start with a
  valid IP version nibble, not a length).

**M2: punchDataplaneFeed iterates all dataplanes per packet**
- File: `mesh_node.go` feed callback
- O(N) scan over all active dataplanes for every inbound packet. With ≤5 peers
  this is fine; at scale (100+ peers) an addr→peerKey index would be better.
- Severity: low (current scale is 5 nodes).

#### Low

**L1: PunchDataplane.Read returns (0, nil) — satisfies net.Conn but unused**
- Unused stub; harmless but could confuse callers if they ever call Read.
- Severity: low (cosmetic)

**L2: isProbePacket checks exactly 2 bytes — probe could be padded**
- If a future implementation pads the probe, the check would fail.
- Severity: low (current probes are always exactly 2 bytes)
