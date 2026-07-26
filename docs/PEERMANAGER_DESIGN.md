# PeerManager Design Spec

**Version:** 2.1
**Status:** Adopted (team motion motion-3911ff2db1df, race-condition audit: motion-9a4b680ec39a)
**File:** `internal/mesh/peer_manager.go` (implementation target)
**Implementer:** developer (t_72aaf915)
**Prerequisites:** Transport interface contract (`docs/TRANSPORT_CONTRACT.md`, `internal/mesh/transport.go`)

---

## Change Log

### v2.0 → v2.1

| Section | Change | Rationale |
|---|---|---|
| §15 | New section: "Race-Condition Audit & Concurrency Correctness" documents verified thread-safety guarantees (G1–G11) and the known TransportRegistry mutex gap | Formalize audit findings from motion-9a4b680ec39a for future maintainers |

### v1.0 → v2.0

| Section | Change | Rationale |
|---|---|---|
| §2.2 | Per-transport sub-states expanded from 3 → 5: add `connecting` and `failed` | Full lifecycle coverage; `connecting` tracks in-flight dials, `failed` marks permanent errors |
| §2.3 | State invariant #2 clarified: blackout means ALL transports quarantined (not 5-cycle threshold) | Aligns with test contract (§Test 2) |
| §3.3 | Blackout escape hatch redefined: bypass quarantine entirely when ALL transports are quarantined, try LRQ | Matches TDD test TestBlackoutEscapeAllQuarantinedBypass |
| §5 | Latency smoothing: median of sliding window → EWMA with split alpha (α_rise=0.7, α_fall=0.3) | Faster degradation detection, hysteresis on recovery; see §14.1 |
| §6 | Path scoring: single-term multiplicative → additive weighted: `score = e_lat + s_pen - h_bonus` | Three explicit decision components; see §14.1 |
| §10 | `PeerManager` naming collision resolved | Per-peer struct is `PeerConnection`; `p2p.PeerManager` stays as WG peer lifecycle interface; see §14.2 |
| §14 | New section: "Open Design Decisions" documents resolved EWMA alpha and naming collision | Permanent record for future readers |

---

## 1. Overview

PeerManager is the connection lifecycle manager for every mesh peer. Each
configured peer gets a dedicated goroutine running a select-loop that manages
multi-transport connectivity, health monitoring, latency probing, and optimal
path selection. PeerManager sits above the Transport layer and below the
WireGuard mesh core.

### 1.1 Design principles

- **One goroutine per peer.** Each PeerConnection's lifecycle is event-driven
  via a single select-loop. No shared locks between peer goroutines —
  communication happens through channels and atomic state transitions.
- **Transport-agnostic.** PeerManager operates on the `mesh.Transport` and
  `mesh.TransportRegistry` interfaces. Adding a new transport type requires zero
  PeerManager changes.
- **Graceful degradation.** When the primary transport fails, PeerManager
  falls through the fallback chain without dropping the peer — the connection
  stays in `connecting` state, probing each transport until one succeeds.
- **Bias toward connectivity.** Quarantined transports are eventually retried;
  blackout is a last-resort escape hatch that tries the least-recently-quarantined
  transport, not a permanent state.

### 1.2 Architecture position

```
┌─────────────────────────────────────────┐
│  WireGuard device (wg-go + gVisor)       │
├─────────────────────────────────────────┤
│  PeerManager (this spec)                 │  ← per-peer goroutines
│   ├── State machine (disconnected→...)   │
│   ├── Latency probing (passive+active)   │
│   ├── Quarantine (exponential cooldown)  │
│   ├── Happy Eyeballs (race fallbacks)    │
│   └── Path selection (score-based)       │
├─────────────────────────────────────────┤
│  Transport layer (mesh.Transport)        │  ← existing contract
│   ├── UDP Transport                      │
│   ├── WebSocket Transport                │
│   └── Reality Transport                  │
└─────────────────────────────────────────┘
```

---

## 2. State Machine

### 2.1 Peer-level states

A peer has exactly one of three top-level states:

```
                    ┌──────────────┐
          ┌────────►│ disconnected │◄─────────┐
          │         └──────┬───────┘          │
          │                │                  │
          │         [connect called]          │
          │                │                  │
          │         ┌──────▼───────┐          │
          │         │  connecting  │          │
          │         └──────┬───────┘          │
          │                │                  │
          │    ┌───────────┼───────────┐      │
          │    │           │           │      │
          │  [success] [all transports  │      │
          │    │       failed (blackout)]│     │
          │    │           │           │      │
          │ ┌──▼──────┐    │    ┌──────┴──┐   │
          │ │connected│    │    │try LRQ   │   │
          │ └──┬──────┘    │    │(blackout  │  │
          │    │           │    │ escape)   │  │
          │  [connection  │    └────┬─────┘  │
          │   lost]       │         │        │
          └────┘          └─────────┘        │
                                             │
                    [Reconnect() API         │
                     resets quarantine]      │
                    └────────────────────────┘
```

| State | Meaning |
|---|---|
| `disconnected` | No connection attempt in progress. Initial state and terminal state after deliberate disconnect. |
| `connecting` | Actively trying transports in fallback order. Happy Eyeballs may race multiple transports. |
| `connected` | At least one transport has an active PeerConn. Latency probes are passive (piggyback on data). |

### 2.2 Per-transport sub-states

Within the `connecting` and `connected` peer-level states, each transport
maintains its own sub-state. There are **five** sub-states (expanded from the
original three in v1.0 to cover the full lifecycle):

```
                      ┌───────────────────┐
                      │      active       │◄──────────────────────┐
                      └──┬──┬──┬────┬─────┘                      │
                         │  │  │    │                            │
             [dial start]│  │  │    │[threshold failures]        │
                         │  │  │    │                            │
              ┌──────────▼┐ │  │  ┌─▼──────────────┐             │
         ┌───►│connecting │ │  │  │  quarantined   │             │
         │    └─────┬─────┘ │  │  └──┬─────────────┘             │
         │          │       │  │     │                            │
         │ [success]│       │  │     │[cooldown expires]          │
         │          │       │  │     │        OR                  │
         │          └───────┘  │     │[blackout escape (LRQ)]     │
         │                     │     │                            │
         │ [permanent error]   │     └────────────────────────────┘
         │                     │
    ┌────▼────┐          ┌─────▼─────┐
    │ failed  │          │  probing  │
    └─────────┘          └───────────┘
                         (latency probe
                          in progress)
```

| Sub-state | Peer-level context | Meaning |
|---|---|---|
| `active` | `connected` | This transport currently carries traffic for the peer. |
| `connecting` | `connecting` | A dial (Connect) is in progress for this transport. |
| `probing` | `connecting` or `connected` | A latency probe (LatencyProbe) is in flight for this transport. |
| `quarantined` | `connecting` or `connected` | Transport hit failure threshold. Waiting out exponential cooldown before next probe. |
| `failed` | `connecting` | Transport encountered a permanent error (bad config, blackout exhausted). Will not be retried without manual intervention. |

### 2.3 State invariants

1. **At most one active transport per peer.** When a new transport becomes
   active, the previous active transport's connection is closed.
2. **Blackout = ALL transports quarantined.** When every transport for a peer
   is in `quarantined` sub-state, the peer enters a "blackout" condition.
   PeerManager bypasses quarantine and tries the least-recently-quarantined
   (LRQ) transport. This is an escape hatch, not a permanent state.
3. **Quarantined transports are never probed until cooldown expires.** The
   cooldown timer fires and transitions `quarantined` → `connecting` (for a
   dial retry) or `quarantined` → `probing` (for a latency-only probe,
   Reality-specific for GFW considerations).
4. **A transport in `failed` sub-state requires explicit Reconnect().** It
   will never be probed automatically.
5. **A peer in `disconnected` state has no goroutine.** The goroutine is spawned
   on the first `Connect()` call and cleaned up on deliberate `Disconnect()`.
6. **State transitions are atomic.** All state changes happen inside the
   per-peer goroutine's select-loop; external callers send commands via a
   channel (`chan peerCommand`).

### 2.4 Sub-state transition table

| From | To | Trigger |
|---|---|---|
| `active` | `connecting` | New dial attempt started |
| `active` | `probing` | Idle: latency probe triggered |
| `active` | `quarantined` | Consecutive failures >= threshold |
| `connecting` | `active` | Dial succeeded |
| `connecting` | `quarantined` | Consecutive failures >= threshold during dial |
| `connecting` | `failed` | Permanent error (bad config, cert expired) |
| `probing` | `active` | Probe completed successfully |
| `probing` | `quarantined` | Probe failed, threshold reached |
| `quarantined` | `connecting` | Cooldown expired (dial retry) |
| `quarantined` | `connecting` | Blackout escape: LRQ selected while all quarantined |
| `quarantined` | `failed` | Permanent: repeated quarantine without success |
| `failed` | `connecting` | `Reconnect()` called (manual intervention) |

---

## 3. Per-Transport Quarantine

### 3.1 Failure counting and thresholds

Track consecutive failures per transport, per peer. Success resets the counter.

| Transport | Threshold | Rationale |
|---|---|---|
| UDP | 3 consecutive failures | UDP is unreliable by nature in some environments; tolerate transient loss. |
| WebSocket | 2 consecutive failures | WS/TCP failures usually indicate a real connectivity problem. |
| Reality | 2 consecutive failures | Reality failure means either GFW interference or server-side config mismatch; fail faster than UDP to avoid detection patterns. |
| Relay | 3 consecutive failures | Relay is a last-resort path; tolerate transient failures. |

Thresholds are configurable per-peer via `QuarantineThreshold` in
`PeerManagerConfig`. If not set, the defaults above apply.

### 3.2 Exponential cooldown

When a transport hits its failure threshold, it enters `quarantined` sub-state
with an exponential backoff:

```
cooldown = min(30s × 2^n, 300s)
```
where `n` is the quarantine cycle count (0-indexed: first quarantine = n=0).

| Quarantine count (n) | Cooldown |
|---|---|
| 0 (first) | 30s |
| 1 | 60s |
| 2 | 120s |
| 3 | 240s |
| 4+ | 300s (capped) |

The quarantine count increments each time the transport transitions to
`quarantined`. A successful connection resets the count to 0.

### 3.3 Blackout escape hatch

When **ALL** transports for a peer are in `quarantined` sub-state, PeerManager
enters a "blackout" condition. Rather than waiting for cooldowns to expire
sequentially (which could take minutes), PeerManager immediately bypasses
quarantine and tries the **least-recently-quarantined (LRQ)** transport.

The LRQ selection logic:

```
1. Find the transport with the oldest quarantine timestamp.
2. Transition that transport from quarantined → connecting.
3. Attempt Connect(). If it succeeds, the transport returns to active.
4. If it fails, the transport re-enters quarantine with incremented cycle count.
   The next LRQ is selected (the next-oldest).
```

Rationale: the LRQ is the most likely to have recovered — its cooldown has been
running the longest. This is better than waiting for cooldowns to expire
naturally, which would leave the peer disconnected for up to 300s.

The `Reconnect()` API provides an external escape hatch: it resets all
quarantine state for a peer and forces an immediate dial on the primary
transport.

### 3.4 Quarantine timers

Instead of `time.AfterFunc` (which allocates), use the per-peer select-loop with
a `time.Timer` that is reset on each quarantine entry:

```go
select {
case <-quarantineTimer.C:
    // cooldown expired → probe
case <-peerCmdCh:
    // handle command
case <-probeResultCh:
    // handle probe result
}
```

---

## 4. Happy Eyeballs Hedging

When entering `connecting` state, PeerManager tries transports in fallback
order. If the primary transport is slow (no response within 5s), race the
next fallback — but do NOT cancel the primary attempt.

### 4.1 Algorithm

```
1. Start primary transport Connect (timeout derived from DialTimeout config).
2. If primary succeeds within 5s:
     → Promote to active. Done.
3. If 5s elapses without success:
     → Start fallback transport Connect concurrently.
     → First transport to succeed wins.
     → Close the loser's connection.
4. If all transports fail:
     → Transition to disconnected (quarantine applies for next attempt).
```

### 4.2 Why 5s

- UDP on LAN typically connects in <100ms. A 5s delay strongly suggests the
  transport is blocked or the peer is unreachable on that path.
- 5s is long enough to avoid false-positive fallback races on high-latency
  links, but not so long that the user notices a multi-second delay.
- Configurable via `PeerManagerConfig.HedgeDelay`.

### 4.3 Interaction with quarantine

Happy Eyeballs races only non-quarantined transports. If the primary is
healthy and the fallback is quarantined, don't race — wait for the primary.

If a raced transport fails, it increments its failure counter normally.
A transport that "wins" the race does NOT reset the loser's counter.

### 4.4 Slow transport classification

Hedging is only triggered for transports classified as "slow":

| Transport | Slow? | Rationale |
|---|---|---|
| UDP | No | Typically <100ms on LAN, racing would be wasteful |
| Reality | Yes | TLS handshake + potential GFW delays |
| WebSocket | Yes | TCP+TLS+upgrade: multi-RTT setup |
| Relay | No | Relay is inherently slow; racing it alongside faster transports is expected, but racing TO it from a slow Reality is not useful |

---

## 5. Hybrid Latency Probing

PeerManager maintains an EWMA-smoothed latency estimate for each transport on
each peer. Latency samples come from two sources: passive (I/O piggyback) and
active (scheduled probing).

### 5.1 EWMA smoothing (revised from v1.0 median)

**Decision:** Split-alpha EWMA with `α_rise = 0.7`, `α_fall = 0.3`.

```
if new_sample > smoothed:
    smoothed = 0.7 * new_sample + 0.3 * smoothed   // fast rise
else:
    smoothed = 0.3 * new_sample + 0.7 * smoothed   // slow fall
```

Rationale (detailed in §14.1):
- Fast rise (α=0.7): When latency spikes, PeerManager needs to detect
  degradation quickly to trigger failover. A 2x increase in RTT is reflected
  in the estimate within 2 samples.
- Slow fall (α=0.3): When latency drops, PeerManager is conservative — it
  waits for sustained improvement before declaring a transport healthy again.
  This prevents flapping between paths.
- Average convergence time to 90% of new value:
  - On rise: ~2 samples (~60s at 30s probe interval)
  - On fall: ~6 samples (~180s at 30s probe interval)

The EWMA `smoothed` value is what feeds into path selection scoring (§6).

### 5.2 Passive probing (data path)

When a transport is `active` and carrying traffic, latency is measured
passively:

- **UDP:** Track WireGuard handshake initiation → handshake response time
  (available from wg-go's internal handshake tracking). No extra packets.
- **TCP-based (WS/Reality):** Record TCP RTT from the kernel
  (`TCP_INFO` via `getsockopt`). Polled every 5s while active.

Passive samples are fed into the EWMA. A sample is only recorded if
the transport has been active for at least 2s (to avoid counting the initial
TLS handshake as "latency").

### 5.3 Active probing (idle path)

When a transport is idle (not currently `active` for a peer) and is not
quarantined:

| Transport status | Probe interval | Method |
|---|---|---|
| Healthy, idle | 30s | `Transport.LatencyProbe(ctx, addr)` |
| Quarantined Reality | 5min | `Transport.LatencyProbe(ctx, addr)` |
| Quarantined UDP/WS | Follows cooldown schedule (§3.2) | `Transport.LatencyProbe(ctx, addr)` |

The 5min interval for quarantined Reality is motivated by GFW considerations:
Reality's camouflage depends on looking like normal HTTPS traffic. Probing a
blocked Reality endpoint too frequently creates a distinguishable pattern.

### 5.4 EWMA implementation

```go
type latencyEWMA struct {
    smoothed time.Duration // current EWMA estimate
    alphaRise float64      // 0.7: weight for new sample when rising
    alphaFall float64      // 0.3: weight for new sample when falling
    initialized bool       // false until first sample
}

func (e *latencyEWMA) update(sample time.Duration) {
    if !e.initialized {
        e.smoothed = sample
        e.initialized = true
        return
    }
    if sample > e.smoothed {
        // Fast rise: detect degradation quickly
        e.smoothed = time.Duration(
            e.alphaRise*float64(sample) + (1-e.alphaRise)*float64(e.smoothed),
        )
    } else {
        // Slow fall: prevent flapping
        e.smoothed = time.Duration(
            e.alphaFall*float64(sample) + (1-e.alphaFall)*float64(e.smoothed),
        )
    }
}

func (e *latencyEWMA) get() time.Duration {
    return e.smoothed
}
```

---

## 6. Path Selection

When multiple transports are healthy for a peer, PeerManager selects the best
path based on a composite additive score.

### 6.1 Score formula (revised from v1.0 multiplicative)

```
score = e_lat + s_pen - h_bonus
```

where:

| Component | Symbol | Meaning | Unit |
|---|---|---|---|
| EWMA latency | `e_lat` | EWMA-smoothed RTT (§5.1) | milliseconds |
| Stability penalty | `s_pen` | Penalty for recent failures: `e_lat × (recent_failures / max(attempts, 10))` | milliseconds |
| Hysteresis bonus | `h_bonus` | 10% discount for the currently-active transport: `0.10 × e_lat` if active, else 0 | milliseconds |

**Lower score = better path.**

### 6.2 Worked examples

**Example 1: Fast but flaky vs slow but stable**
```
Transport A (UDP):        e_lat=5ms,  recent_failures=5, attempts=10
  s_pen = 5 × (5/10) = 2.5ms
  h_bonus = 0 (not active)
  score = 5 + 2.5 - 0 = 7.5

Transport B (Reality):    e_lat=15ms, recent_failures=0, attempts=10
  s_pen = 15 × (0/10) = 0ms
  h_bonus = 1.5 (active)
  score = 15 + 0 - 1.5 = 13.5

→ A wins (7.5 < 13.5). A fast-but-flaky transport beats a slow-but-stable one
  because the absolute penalty is small relative to the latency gap.
```

**Example 2: Similar latency, different stability**
```
Transport A (UDP):        e_lat=10ms, recent_failures=0, attempts=10
  score = 10 + 0 - 0 = 10.0

Transport B (Reality):    e_lat=12ms, recent_failures=8, attempts=10
  s_pen = 12 × (8/10) = 9.6ms
  score = 12 + 9.6 - 0 = 21.6

→ A wins decisively (10.0 vs 21.6). The stability penalty dominates when
  failure rate is high.
```

**Example 3: Hysteresis prevents flapping**
```
Transport A (UDP, active):    e_lat=10ms, recent_failures=0
  score = 10 + 0 - 1.0 = 9.0

Transport B (Reality, idle):  e_lat=9ms, recent_failures=0
  score = 9 + 0 - 0 = 9.0

→ Tie (9.0 vs 9.0). Without hysteresis, B would win (9 < 10) and we'd flap.
  With hysteresis, the tie is broken by fallback order — A stays active.
```

### 6.3 Selection rules

1. Only non-quarantined transports with an initialized EWMA (at least one
   sample) are eligible.
2. If only one transport is eligible, select it regardless of score.
3. If multiple are eligible, select the one with the lowest score.
4. If scores are within 10% of each other, prefer the lower-index transport
   in the fallback order (stable tie-breaking).
5. A newly-active transport's EWMA is initialized from the first latency
   sample and becomes eligible immediately.

### 6.4 Switching

PeerManager switches the active transport when:

- The current active transport's score exceeds the best alternative's score by
  >25% **AND** the alternative has maintained its better score for 3
  consecutive probe cycles (prevents flapping).
- The current active transport enters quarantine.
- The current active connection drops (Read/Write error).

### 6.5 Relationship to degradation detection

Path selection (§6) and degradation detection (§5) are independent mechanisms:

- **Degradation detection** (EWMA with 2x threshold, 3 consecutive probes)
  triggers a proactive failover: it marks the active transport as
  "degraded" and forces a path re-selection even if the connection is still
  alive.
- **Path selection** runs continuously and may switch even if the active
  transport is not degraded — e.g., a new transport becomes available with
  better score, or the active transport's stability penalty grows.

---

## 7. Per-Peer Goroutine Architecture

### 7.1 Naming: PeerConnection (resolved from v1.0)

The per-peer struct is named `PeerConnection` (not `PeerManager`). This
resolves the collision with `p2p.PeerManager` (the WireGuard peer lifecycle
interface in `internal/p2p/wg_delegate.go`). See §14.2 for full rationale.

### 7.2 Goroutine lifecycle

```go
type PeerConnection struct {
    peerKey    string
    transports []mesh.Transport     // ordered by fallback priority
    config     PeerManagerConfig
    state      peerState            // atomic: disconnected|connecting|connected

    // per-transport state
    transportStates map[string]*transportState

    cmdCh      chan peerCommand      // external → goroutine
    resultCh   chan probeResult      // transport probe result → goroutine

    cancel     context.CancelFunc    // goroutine shutdown
    done       chan struct{}         // closed when goroutine exits
}

type transportState struct {
    name           string
    subState       TransportSubState
    conn           mesh.PeerConn
    latency        latencyEWMA         // EWMA-smoothed latency
    failures       int                 // consecutive failure count
    recentFailures []time.Time         // failure timestamps for lookback window
    recentAttempts int                 // total attempts in lookback window
    quarantineN    int                 // quarantine cycle count (for backoff)
    quarantinedAt  time.Time           // when quarantine started (for LRQ)
    cooldownTimer  *time.Timer
}
```

### 7.3 Select-loop skeleton

```go
func (pc *PeerConnection) run() {
    defer close(pc.done)

    for {
        select {
        case cmd := <-pc.cmdCh:
            pc.handleCommand(cmd)

        case result := <-pc.resultCh:
            pc.handleProbeResult(result)

        case <-pc.probeTicker.C: // active probing for idle transports
            pc.probeIdleTransports()

        case <-pc.quarantineTimerCh():
            pc.retryQuarantined()
        }
    }
}
```

### 7.4 Command set

```go
type peerCommand int

const (
    cmdConnect        peerCommand = iota // start connecting
    cmdDisconnect                         // graceful disconnect
    cmdReconnect                          // force reconnect (escape blackout, reset quarantine)
    cmdShutdown                           // permanent shutdown + cleanup
    cmdHealthCheck                        // external health query → response channel
)
```

Commands carry a response channel so callers can await completion:

```go
type peerCommandMsg struct {
    cmd    peerCommand
    respCh chan peerCommandResult
}

type peerCommandResult struct {
    err   error
    state PeerState
}
```

### 7.5 Concurrency model

- **One goroutine per peer.** All transport operations (Connect, Listen,
  LatencyProbe) are initiated from within this goroutine.
- **Transport interface is concurrency-safe** (§5.1 of TRANSPORT_CONTRACT.md),
  so the goroutine can call `IsHealthy()` without locking.
- **External API is synchronous from the caller's perspective** — the caller
  sends a command and blocks on the response channel until the goroutine
  processes it.
- **No shared mutable state between peer goroutines.** Each PeerConnection's
  fields are only accessed from within its own goroutine.

---

## 8. Config Model

### 8.1 PeerManagerConfig (top-level)

```go
// PeerManagerConfig holds per-peer PeerManager settings.
// This is the config for a single PeerConnection.
type PeerManagerConfig struct {
    // PeerID identifies this peer (e.g., public key).
    PeerID string

    // Addr is the remote address for this peer.
    Addr string

    // TransportNames is the ordered list of transport names to try,
    // in priority order (e.g., ["udp", "reality", "websocket", "relay"]).
    TransportNames []string

    // QuarantineThreshold is the number of consecutive failures before
    // a transport enters quarantine. Default: 3 for UDP/relay, 2 for
    // reality/websocket. Differentiated by transport name.
    QuarantineThreshold map[string]int

    // QuarantineBaseCooldown is the initial quarantine duration.
    // Default: 30s. Exponential backoff: 30→60→120→240→300s cap.
    QuarantineBaseCooldown time.Duration

    // QuarantineMaxCooldown caps the exponential backoff.
    // Default: 300s.
    QuarantineMaxCooldown time.Duration

    // HedgeDelay is how long to wait before starting a parallel
    // fallback dial for slow transports. Default: 5s.
    HedgeDelay time.Duration

    // SlowTransports is the set of transport names classified as "slow"
    // (trigger hedging via Happy Eyeballs). E.g., ["reality", "websocket"].
    SlowTransports map[string]bool

    // ProbeInterval is how often to probe latency when idle.
    // Default: 30s.
    ProbeInterval time.Duration

    // ProbeIntervalQuarantinedReality is the probe interval for
    // quarantined Reality transports (to avoid GFW detection).
    // Default: 5min.
    ProbeIntervalQuarantinedReality time.Duration

    // FailureLookback is the time window for counting recent failures
    // in the path-selection scoring formula.
    // Default: 60s.
    FailureLookback time.Duration

    // ── EWMA parameters ──────────────────────────────────────────────

    // EWMARiseAlpha is the weight for a new sample when latency rises.
    // Default: 0.7 (fast detection of degradation).
    EWMARiseAlpha float64

    // EWMAFallAlpha is the weight for a new sample when latency falls.
    // Default: 0.3 (slow recovery, prevents flapping).
    EWMAFallAlpha float64

    // ── Path selection parameters ────────────────────────────────────

    // HysteresisBonus is the score discount fraction for the currently
    // active transport. Default: 0.10 (10%).
    HysteresisBonus float64

    // ScoreSwitchThreshold is the percentage improvement needed to switch
    // active transports. Default: 0.25 (25%).
    ScoreSwitchThreshold float64

    // ScoreStableProbes is the number of consecutive probe cycles a
    // better alternative must remain better before switching. Default: 3.
    ScoreStableProbes int
}
```

### 8.2 DefaultPeerManagerConfig

```go
func DefaultPeerManagerConfig() PeerManagerConfig {
    return PeerManagerConfig{
        QuarantineThreshold: map[string]int{
            "udp":       3,
            "reality":   2,
            "websocket": 2,
            "relay":     3,
        },
        QuarantineBaseCooldown:          30 * time.Second,
        QuarantineMaxCooldown:           300 * time.Second,
        HedgeDelay:                      5 * time.Second,
        SlowTransports:                  map[string]bool{"reality": true, "websocket": true},
        ProbeInterval:                   30 * time.Second,
        ProbeIntervalQuarantinedReality: 5 * time.Minute,
        FailureLookback:                 60 * time.Second,
        EWMARiseAlpha:                   0.7,
        EWMAFallAlpha:                   0.3,
        HysteresisBonus:                 0.10,
        ScoreSwitchThreshold:            0.25,
        ScoreStableProbes:               3,
    }
}
```

---

## 9. Interface

PeerManager exposes a single public type with methods. Internal per-peer
management is encapsulated in unexported `peerConnection`.

```go
package mesh

// PeerManager manages per-peer transport connectivity, health, and path
// selection. It sits above the Transport layer and below WireGuard.
//
// Naming: This is mesh.PeerManager — the transport-level connection
// lifecycle manager. It is distinct from p2p.PeerManager, which is the
// WireGuard device-level peer lifecycle interface (AddDynamicPeer,
// RemoveDynamicPeer, etc.). See §14.2.
type PeerManager struct {
    // unexported fields
}

// NewPeerManager creates a PeerManager backed by the given TransportRegistry.
func NewPeerManager(registry *TransportRegistry, cfg PeerManagerConfig) *PeerManager

// Connect starts connecting to the given peer. Returns immediately — the
// connection attempt runs in the peer's goroutine. Use the State method to
// observe progress.
func (pm *PeerManager) Connect(peerKey string, cfg PeerManagerConfig) error

// Disconnect gracefully disconnects from a peer and stops its goroutine.
func (pm *PeerManager) Disconnect(peerKey string) error

// Reconnect forces a reconnect for the given peer, resetting all quarantine
// state. Useful as an escape hatch from blackout.
func (pm *PeerManager) Reconnect(peerKey string) error

// State returns the current peer-level state for the given key.
func (pm *PeerManager) State(peerKey string) (PeerState, error)

// TransportState returns the sub-state for a specific transport on a peer.
func (pm *PeerManager) TransportState(peerKey, transportName string) (TransportSubState, error)

// Shutdown disconnects all peers and stops all goroutines.
func (pm *PeerManager) Shutdown(ctx context.Context) error

// ActiveTransport returns the name of the currently active transport for a
// peer, or empty string if the peer is not connected.
func (pm *PeerManager) ActiveTransport(peerKey string) string

// Latency returns the EWMA-smoothed latency for the active transport.
func (pm *PeerManager) Latency(peerKey string) time.Duration
```

---

## 10. Types

```go
// PeerState represents the peer-level connection state.
type PeerState int

const (
    PeerDisconnected PeerState = iota
    PeerConnecting
    PeerConnected
)

// TransportSubState represents per-transport sub-states within a peer.
type TransportSubState int

const (
    TransportSubActive      TransportSubState = iota // actively connected
    TransportSubConnecting                            // dial in progress
    TransportSubProbing                               // latency probe in progress
    TransportSubQuarantined                           // in quarantine cooldown
    TransportSubFailed                                // permanently failed
)

// TransportPeerState describes a transport's status for a specific peer.
type TransportPeerState struct {
    Name              string
    SubState          TransportSubState
    LatencyEWMA       time.Duration     // EWMA-smoothed latency
    LatencySamples    int               // number of samples fed into EWMA
    ConsecutiveFailures int
    QuarantineCycles  int
    QuarantinedAt     time.Time         // zero if not quarantined (for LRQ)
    CooldownRemaining time.Duration     // 0 if not quarantined
    Score             float64           // current path selection score
}
```

---

## 11. Error Handling and Logging

### 11.1 Error classification

PeerManager uses the existing `mesh.TransportError` classification
(`IsRetryable()`) from the Transport contract (§4 of TRANSPORT_CONTRACT.md):

- **Transient errors:** increment the failure counter, start/continue cooldown.
- **Permanent errors:** log a warning, transition transport to `failed`
  sub-state. Do not quarantine — a bad cert won't fix itself with retries.

### 11.2 Log levels

| Event | Level | Message example |
|---|---|---|
| Transport switch | Info | `peer abc123: switched active transport udp→reality (score 7.5→13.5)` |
| Enter quarantine | Warn | `peer abc123: reality transport quarantined after 2 failures (cooldown 30s, cycle 0)` |
| Blackout escape | Warn | `peer abc123: ALL transports quarantined — blackout escape, trying LRQ udp` |
| Blackout escape fail | Error | `peer abc123: LRQ udp failed — trying next LRQ reality` |
| Happy Eyeballs race | Info | `peer abc123: racing fallback websocket after 5s primary timeout` |
| Successful probe | Debug | `peer abc123: reality EWMA latency 12ms (raw 11ms, samples=5)` |
| EWMA spike | Info | `peer abc123: udp EWMA jump 5ms→45ms (fast-rise α=0.7)` |

---

## 12. Integration Points

### 12.1 With WireGuard

PeerManager does NOT manage the WireGuard device directly. It manages the
**transport connection** underneath WireGuard. The integration point:

1. PeerManager establishes a `PeerConn` (transport-level socket).
2. The `PeerConn` is passed to the existing WireGuard binding layer
   (`obfuscatingBind`), which uses it as the underlying connection for
   WireGuard handshake and data traffic.
3. When PeerManager switches transports, it calls a callback to update the
   WireGuard binding with the new `PeerConn`.

### 12.2 With P2P gossip

Dynamic peers discovered via gossip (`internal/p2p/`) use PeerManager through
the existing `p2p.PeerManager` interface in `internal/p2p/wg_delegate.go`.
Note: `p2p.PeerManager` is a distinct interface from `mesh.PeerManager` — see
§14.2. The `WireGuardDelegate` wraps `mesh.PeerManager` and translates gossip
events:

- `NotifyJoin` → `mesh.PeerManager.Connect(peerKey, cfg)`
- `NotifyLeave` → `mesh.PeerManager.Disconnect(peerKey)`
- Endpoint update → handled by PeerManager via transport-level reconnect

### 12.3 With config

On startup, `MeshNode` iterates over `config.Peers` and calls
`PeerManager.Connect()` for each peer with `pm_enabled: true`. Peers without
`pm_enabled` use the existing static WireGuard path (backward compatible).

---

## 13. Acceptance Criteria

For the developer implementing t_72aaf915:

| ID | Criterion | Verification |
|---|---|---|
| AC-1 | `PeerManager.Connect()` spawns a per-peer goroutine that transitions through `disconnected → connecting → connected` | Unit test: call Connect, poll State until Connected |
| AC-2 | Transport enters `quarantined` after N consecutive failures (UDP=3, WS/Reality=2, relay=3) | Unit test: inject failures via mock Transport, verify TransportSubQuarantined |
| AC-3 | Cooldown duration follows exponential backoff: 30s → 60s → 120s → 240s → 300s cap | Unit test: use real timer, verify duration for each cycle |
| AC-4 | Blackout escape: when ALL transports quarantined, bypass quarantine and try LRQ | Unit test: quarantine all transports, verify LRQ is tried immediately |
| AC-5 | Happy Eyeballs races fallback after 5s primary timeout | Unit test: primary Transport delays 6s, fallback responds in 100ms → fallback wins |
| AC-6 | EWMA split-alpha: fast rise (α=0.7) and slow fall (α=0.3) | Unit test: feed rising samples, verify fast convergence; feed falling samples, verify slow convergence |
| AC-7 | Path selection score: `score = e_lat + s_pen - h_bonus` | Unit test: two transports with known EWMA latencies and failure counts |
| AC-8 | Hysteresis bonus: active transport gets 10% score discount | Unit test: same latency, same failures — active transport wins |
| AC-9 | Active transport switches when alternative is >25% better for 3 probe cycles | Unit test: inject degrading latency, verify switch after 3 probes |
| AC-10 | `PeerManager.Reconnect()` resets quarantine state and forces immediate dial | Unit test: quarantined transport → Reconnect → transport transitions to connecting |
| AC-11 | `PeerManager.Shutdown()` stops all goroutines and drains connections | Unit test: 3 peers connected → Shutdown → all goroutines exited |
| AC-12 | Config model round-trips through YAML (marshal/unmarshal preserves values) | Unit test: DefaultPeerManagerConfig → yaml → unmarshal → equal |
| AC-13 | Backward compat: peers without `pm_enabled: true` use existing static WireGuard path | Integration test: config with mixed pm_enabled peers |
| AC-14 | Permanent errors transition transport to `failed` sub-state, not `quarantined` | Unit test: inject permanent error, verify TransportSubFailed |
| AC-15 | 5 sub-states: active, connecting, probing, quarantined, failed all reachable | Unit test: exercise each transition in the diagram (§2.4) |

---

## 14. Open Design Decisions

### 14.1 EWMA alpha: 0.3 vs 0.7/0.3 split

**Decision:** Split alpha — α_rise=0.7, α_fall=0.3.

**Alternatives considered:**

| Option | α_rise | α_fall | Pros | Cons |
|---|---|---|---|---|
| A: Single slow | 0.3 | 0.3 | Simple. Low noise. | Slow to detect degradation (~6 samples to converge 90%). Peer stays on a bad path for 3+ minutes. |
| B: Single fast | 0.7 | 0.7 | Fast detection. Simple. | Noisy. Every spike triggers a path re-evaluation. Flapping risk. |
| **C: Split (chosen)** | **0.7** | **0.3** | Fast degradation detection. Slow recovery prevents flapping. Standard in TCP RTT estimation (RFC 6298 style). | Slightly more code. Asymmetric behavior may surprise at first read. |

**Why not 0.5/0.5?** Symmetric EWMA with α=0.5 is "moderate" on both rise and
fall. It detects degradation in ~4 samples and recovers in ~4 samples. The
problem is that recovery should be SLOWER than detection — you want to switch
away fast but switch back slowly. 0.5/0.5 gives equal speed in both directions,
which means you'd flap between two paths with similar latency. The asymmetry
(0.7/0.3) encodes the hysteresis directly into the signal, reducing dependency
on the score-switch logic to prevent flapping.

### 14.2 PeerManager naming collision

**Problem:** Three different types called "PeerManager" / "PeerConnection":

1. `p2p.PeerManager` (interface in `internal/p2p/wg_delegate.go`) — WireGuard
   device peer lifecycle: `AddDynamicPeer`, `RemoveDynamicPeer`, `IsHealthy`.
2. `mesh.PeerManager` (struct in design doc v1.0) — transport-level connection
   lifecycle manager for all peers.
3. `mesh.PeerConnection` (struct in design doc v1.0 §7) — per-peer goroutine
   managing one peer's transports.

**Decision:**

| Name | Package | Kind | Scope |
|---|---|---|---|
| `PeerManager` | `p2p` | Interface | WG device-level peer CRUD. **Unchanged.** |
| `PeerManager` | `mesh` | Struct | Multi-peer transport lifecycle coordinator. Public API. |
| `peerConnection` | `mesh` | Struct (unexported) | Per-peer goroutine. Internal implementation detail. |

`p2p.PeerManager` and `mesh.PeerManager` are in different packages, so there
is no Go-level name collision. However, the conceptual similarity creates
confusion for readers. Resolution:

- The `p2p.PeerManager` interface is described in comments as
  "WireGuard-level peer lifecycle." Its doc comment explicitly states it is
  distinct from `mesh.PeerManager`.
- The `mesh.PeerManager` struct is described as "transport connectivity and
  path selection." Its doc comment references the design spec.
- `WireGuardDelegate` in `internal/p2p/` holds a reference to
  `mesh.PeerManager` and translates between the two concepts.

No rename is needed at the package level — the package-scoped names provide
sufficient disambiguation. The test file's temporary `PeerManager` struct
stub is removed when the real `mesh.PeerManager` is implemented.

---

## 15. Race-Condition Audit & Concurrency Correctness

This section records the verified correctness guarantees from the
race-condition audit conducted as part of motion-9a4b680ec39a. The audit
systematically examined all concurrent access paths in PeerManager and the
underlying TransportRegistry to confirm thread safety or document gaps.

### 15.1 Audit scope

The audit examined:
- PeerManager per-peer goroutine architecture (§7)
- External read methods (`State`, `TransportState`, `CurrentTransport`, `Latency`, `IsHealthy`, `TransportStates`)
- Spawned dial goroutines (`startDial`) and their result channel communication
- Config mutation paths (`triggerSwitch` → `reorderTransports`)
- Quarantine expiry and probe tick handling (§3–§5)
- TransportRegistry (`Register`, `Get`, `SetFallbackOrder`, `List`, `getFactoryExact`, `Dial`)

### 15.2 Verified correctness guarantees

Each guarantee was verified by tracing every field access in the implementation
(`internal/mesh/peer_manager.go`) and confirming synchronization coverage.

**G1: Peer-level state reads are lock-free and consistent.**

`atomic.Int32` (`stateAtomic`) stores the `PeerState`. All writes use `.Store()`
inside the per-peer goroutine; all external reads use `.Load()`. No lock
contention, no stale reads — the atomic store/load provides sequential
consistency for this field.

**G2: `transportStates` map is safe for concurrent reads.**

`s.RWMutex` protects all access. External read methods (`TransportState`,
`CurrentTransport`, `Latency`, `TransportStates`) take `RLock()`. All mutations
(`handleDialResult`, `checkQuarantineExpiry`, `cleanup`, `handleReconnect`,
`onProbeTick`) take `Lock()` and run inside the per-peer goroutine. No
concurrent writers exist, and map iteration never happens while a write is in
progress.

**G3: Dial goroutines communicate results via channels, not shared state.**

`startDial` spawns a goroutine that creates a `dialResult`, sends it on
`dialResultCh` (buffered, cap 4), and exits. The main goroutine receives in
`handleDialResult`. The spawned goroutine never accesses `peerManager` fields
directly — its only interaction is the channel send.

**G4: Stale dial results are safely discarded.**

Each connect cycle increments `connectGen`. Dial results carry a `gen` field.
`handleDialResult` compares `result.gen != pm.connectGen` — if they differ,
the result is from a cancelled cycle, the stale connection is `ForceClose()`d,
and the result is discarded. This prevents a late-arriving success from
overwriting the state of a newer cycle.

**G5: `inFlight` map is goroutine-local.**

`inFlight` tracks which transports have active dial goroutines. It is
only read/written by methods that run in the per-peer goroutine:
`startDial`, `handleDialResult`, `cancelInFlight`, and `startFallbackDial`.
No external access path exists. No synchronization needed.

**G6: `cfg.TransportNames` reordering is goroutine-local.**

`triggerSwitch` calls `reorderTransports` to promote a better alternative
to the front of the fallback order. All callers (`evaluatePathSwitching` →
`probeAndEvaluate` → `onProbeTick` → `run`) are in the per-peer goroutine.
Subsequent `candidateTransports()` calls that read `cfg.TransportNames` also
run in the goroutine. No concurrent access.

**G7: `started` flag is protected by `startMu`.**

`startMu.Lock()` guards the `started` boolean in `Start()`, `Stop()`, and
`Reconnect()`. Prevents double-start (`Start` returns error if already
started) and ensures `Stop` is idempotent (returns nil if not started).

**G8: `probeAndEvaluate` copies state under lock before I/O.**

`probeAndEvaluate` acquires `mu.Lock()`, copies transport state into a local
map, releases the lock, and then performs latency probes (which may block
on network I/O). This avoids holding the lock during potentially slow
operations. Individual latency updates are written back under `mu.Lock()`.

**G9: `latencyEWMA` fields are single-goroutine-mutated.**

`latencyEWMA.push()` and `latencyEWMA.current()` are only called from
methods that run in the per-peer goroutine (`handleDialResult`,
`probeAndEvaluate`, `computeScore`). No concurrent read/write on the EWMA
internal fields (`value`, `hasValue`, `count`).

**G10: `TransportStates()` snapshot is internally consistent.**

The method holds `mu.RLock()` for the entire snapshot construction — reading
all `transportState` fields, computing `cooldownRemaining`, and building the
result map. External callers see a point-in-time consistent view. No partial
updates are visible.

**G11: `Stop()` drains goroutine with timeout.**

`Stop()` signals shutdown via `cancel()`, then waits on `done` channel with a
5-second timeout. If the goroutine is stuck (e.g., blocked on a network call),
the timeout prevents indefinite blocking. The `startMu` ensures `Stop()` and
`Start()` cannot race.

### 15.3 External reader safety

The following methods are safe to call from any goroutine (dashboard,
monitoring, health checks):

| Method | Synchronization | Notes |
|---|---|---|
| `State()` | `atomic.Load` | Lock-free; returns the last-stored peer state |
| `IsHealthy()` | `atomic.Load` | Equivalent to `State() == PeerConnected` |
| `TransportState(name)` | `mu.RLock` | Protects map read of `transportStates[name].subState` |
| `CurrentTransport()` | `mu.RLock` | Protects read of `currentTransport` string |
| `Latency()` | `mu.RLock` | Protects read of `lastLatency` duration |
| `TransportStates()` | `mu.RLock` | Holds lock for full snapshot construction |

No external caller can cause a data race — all reads are protected by either
the atomic pattern or the `RWMutex`. All state mutations only occur inside the
per-peer goroutine.

### 15.4 TransportRegistry: concurrency gap (known issue)

**Finding:** `TransportRegistry`'s doc comment states "Concurrency: safe for
concurrent use" but the struct lacks a mutex. The `factories` map and
`fallbackOrder` slice are accessed without synchronization across `Register`,
`Get`, `getByFallback`, `List`, `FallbackOrder`, `SetFallbackOrder`,
`ShutdownAll`, `getFactoryExact`, and `Dial`.

**Impact:** In practice, registrations happen during startup before any
goroutines call `Get()` or `Dial()`, so this gap does not manifest in normal
operation. However, dynamic registration at runtime (e.g., hot-reloading
transports) would cause data races on the `factories` map.

**Status:** Acknowledged, not fixed (filed at
`internal/mesh/failover_test.go:519-529`). The fix requires adding a
`s.RWMutex` to `TransportRegistry` and locking in all mutation + read methods.
Not blocking for PeerManager because all PeerManager calls to
`TransportRegistry` are read-only after startup.

**Acceptable mitigation:** PeerManager only calls `Dial()` and `Get()` from
within the per-peer goroutine — never `Register()` or `SetFallbackOrder()`.
Combined with the single-goroutine model, no actual data race occurs between
PeerManager and TransportRegistry. The gap is a pre-existing issue outside
PeerManager's scope.

### 15.5 Audit methodology

The audit was conducted by:

1. Tracing every field access in `PeerManager` and classifying it as:
   goroutine-local, channel-communicated, mutex-protected, or atomic
2. Verifying that no field is both written by one goroutine and read by
   another without synchronization
3. Examining `go test -race` coverage (peer_manager_test.go has build tag
   coverage for the race detector)
4. Reviewing all spawned goroutines (`startDial` closures) and their
   communication back to the main select-loop
5. Cross-referencing the implementation against the design spec's
   concurrency model (§7.5)

### 15.6 Summary

PeerManager's concurrency model is **verified correct**. All 11 guarantees
in §15.2 hold — each field access is accounted for with an appropriate
synchronization mechanism. The per-peer goroutine + channel architecture
eliminates whole categories of race conditions (no shared mutable state
between peer goroutines). The sole gap — TransportRegistry's missing mutex
(§15.4) — is a pre-existing issue outside PeerManager's scope that does not
create races under current usage patterns.

---

## 16. Out of Scope

1. **Dynamic routing (gossip-based path propagation).** Per ARCHITECTURE_REFACTOR.md
   Phase 4, this is a separate component built on top of PeerManager.
2. **Relay transport type.** PeerManager manages existing transports (UDP, WS,
   Reality). Relay as a separate transport type is a future addition.
3. **Per-peer bandwidth throttling.** PeerManager selects paths, it does not
   shape traffic.
4. **Dashboard UI for PeerManager state.** The data model (§10) is designed for
   dashboard consumption, but the UI implementation is a separate task.

---

## 17. Related Documents

- `docs/TRANSPORT_CONTRACT.md` — Transport interface contract (PeerConn,
  Transport, TransportFactory, TransportRegistry)
- `docs/TRANSPORT_CAPABILITY_MATRIX.md` — Per-implementation feature support
- `docs/ARCHITECTURE_REFACTOR.md` — Overall architecture and phase plan
- `docs/PROXY_DESIGN.md` — Multi-path dispersed anonymous proxy design
- `internal/mesh/transport.go` — Transport interface implementation (~532 lines)
- `internal/mesh/peer_manager_test.go` — TDD test contract (this spec's verification)
- `internal/p2p/wg_delegate.go` — Existing p2p.PeerManager interface and
  WireGuardDelegate
- `internal/config/config.go` — Config model (PeerConfig to be extended)
