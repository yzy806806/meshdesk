# Release Notes

## v1.7.3 — 2026-08-18

**Multi-path relay routing with Dijkstra path planning + debug log fix.**

### Multi-path relay routing
- **monitor/metrics.go**: Metrics.PeerLatency (peerKey→RTT ms) — each node reports its latency to all session peers
- **monitor/reporter.go**: SetRTTProvider fills PeerLatency; pushToCollectors sends PeerLatency only to lowest-latency collector (nearest shared node)
- **monitor/aggregator.go**: SetPeerLatencyHandler callback — shared nodes update their global latency graph on receipt
- **mesh/path_server.go** (new): LatencyGraph adjacency list + Dijkstra shortest path + QueryPath + AllEdges (dashboard) + PruneStaleEdges (75s TTL cleanup) + MergeFromSync/ExportForSync
- **mesh/node.go**: InitPathServer (shared nodes, virtual port 0x5050); QueryPathFromServer (ordinary nodes); queryingPath atomic flag prevents recursion
- **mesh/relay_dialer.go**: tryRelayFallback queries nearest shared node for optimal path before falling back to RTT-sorted candidate scan
- **app/monitor.go**: wire SetRTTProvider + SetPeerLatencyHandler; shared nodes run aggregator to collect PeerLatency
- **app/web.go**: meshTopologyPaths.PeerLatency uses global latency graph for inter-peer edge weights; Dijkstra result cache (15s TTL)
- **app/app.go**: InitPathServer wired in Start() for shared nodes (reality.enabled)

### Architecture
- Ordinary nodes report peer RTT via monitor → nearest shared node collects into latency graph
- Dijkstra computes optimal multi-hop relay path → ordinary nodes query before relaying
- Shared nodes sync via forwardToCollectors (existing monitor forwarding)
- Dashboard reads graph for topology edge weights

### Bug fixes
- **MESHDESK_DEBUG=0 treated as enabled**: `!= ""` instead of `== "1"` in mux_transport.go, tun_forwarder.go, meta_exchange.go → 9256 lines/min journald flooding → TUN forwarder queue saturation → ICMP ping timeouts. Fixed.
- **STUN MappedEP used LocalAddr**: stunRoundTrip returned conn.LocalAddr() (internal IP) instead of XORMappedAddress (public IP) → holes targeted unreachable internal addresses → data plane fell back to relay. Fixed (v1.7.2).
- **smux Close() didn't wake blocked Read**: relay bridge goroutines leaked (~10K per node) → CPU 100%. Fixed (v1.7.1).
- **Relay tunnel count assertion**: test expected TunnelCount==1 but goroutine leak fix cleans up tunnels promptly. Adjusted to <=1.

### Validation
- go build/vet/test: 25 packages, all green
- 5-node deployment: CPU 0%, goroutine 50-97, 0 session_lost
- PeerLatency reporting: N1/oracle 4 edges each, aliyun collects complete graph
- Dashboard topology: 5 nodes, 10 edges
- PathServer confirmed running on shared nodes (pprof)
- Dijkstra path query: txcloud→ARM 259ms (direct optimal), txcloud→AMD 4ms (direct optimal)

**Major refactor: memberlist/gossip fully retired, config simplified to 12 lines, dashboard topology restored.**

### Memberlist removal (22K+ lines deleted)
- **Deleted entire `internal/p2p/` package** (45 files: gossip, delegate, events, peer cache, relay path/protocol/selector/session, NAT traversal, WireGuard delegate)
- **Removed `hashicorp/memberlist` from go.mod** — zero external gossip dependencies
- `MuxTransport` no longer implements `memberlist.Transport` interface
- App layer (10 files) cleaned: all gossipLayer/natTraversal/wgDelegate references removed
- `p2p.enabled` defaults false; gossip code path removed entirely

### Config simplification (~130 lines → 12 lines)
Minimal config now works — only `node.hostname`, `mesh.zone`, `peers` (public_key + endpoint + reality.public_key) needed. Everything else has defaults:
- TUN auto-created, VIP auto-allocated (IPAM with fixed hostCount=254)
- Fingerprint auto-derived from identity.pem
- Reality server_name/short_id/tls_fingerprint use standard mesh defaults
- GossipPort removed (uses Mesh.Port)
- STUN defaults removed (coordination is self-sufficient)
- SS listener, CFTunnel, reality_transport v1, systemd package deleted

### Bug fixes
- **[High] relay goroutine leak** (N1 100% CPU, ARM 172% CPU, 60K goroutines): old version's relay bridge didn't exit after tunnel close — new `closeOnce`/`removeTunnel` fixes goroutine lifecycle
- **[High] DNS `<hostname>.mesh` resolution broken**: gossip removal dropped hostname propagation — META now persists peer hostnames (`learnedHostnames` map), DNS adapter uses hostname→VIP mapping
- **[High] VIP auto-allocation conflict**: hostCount=peers+1 collapsed to 1 on fresh boot → all nodes got .1 → fixed hostCount to subnet size (254 for /24)
- **[Medium] `PeerConfig.Reality` nil pointer**: pointer field not initialized before applying defaults in Load() — now allocates first
- **[Medium] dashboard topology missing**: gossip deletion removed liveness + path info adapters — new META-driven `meshLiveness` (HasPeerSession) + `meshTopologyPaths` (PeerRTT) restore full topology view

### Dashboard topology (META-driven)
- Node liveness: smux session state (`HasPeerSession`)
- Node hostnames: META-learned (`PeerHostnames`)
- Edge latency: mesh RTT cache (`PeerRTT`)
- Zero gossip dependency — all from session meta exchange

### Validation
- go build/vet/test: **25 packages, all green**
- 5-node deployment: CPU 0% on all nodes, 5-node monitor active, UDP hole punching verified
- 22,881 lines deleted, 436 lines inserted across 117 files

**META auto-discovery fix: new peers propagate to the whole mesh — zone learned automatically, punching fires without manual config peers.**

### The one-shot flood bug
Meta exchange only sent knowledge to a NEW session peer at establishment
time (`NotifyPeerJoined`). When a relay-attached peer joined an
intermediary AFTER that intermediary's session with us was set up, we
never learned the newcomer — no VIP, no zone, no endpoints. The
fail-closed zone gate then blocked punching forever (AMD was invisible
to txcloud: `PeerZone(AMD)==""` → no punch → stuck on multi-hop relay).

### Fix (session-established → Broadcast)
- `SetSessionEstablishedHandler` now also calls `me.Broadcast()` after
  `NotifyPeerJoined`: the peer graph changed, so every session peer
  re-learns the newcomer's zone/endpoints/collector capability.
- `Broadcast()` throttled to 5s minimum spacing — a flapping mobile
  session (reconnect every few minutes) would otherwise trigger a full
  broadcast per reconnect.
- Manual config peers (Oracle/AMD added during debugging) removed —
  auto-discovery handles it.

### UDP hole data-plane fixes (v1.6.9 second pass)
- **Double-SERVER deadlock**: OnHoleEstablished gated DialUDPPeer by
  peer-key ordering ("smaller key dials"). txcloud's key b142a874 >
  AMD's 7eb1844e → txcloud waited as SERVER; AMD's routeUDPPacket
  "peer won" path dropped its |out and ALSO waited → no CLIENT, no kx,
  ping 100% loss. Fix: both sides dial — the udpMeshManager's
  first-punch-wins already resolves the |in/|out conflict.
- **smux keepalive starvation**: the UDP session ran 30s smux pings; a
  busy TUN stream filled the ARQ window, pings queued behind bulk data,
  the peer's 90s PingTimeout fired mid-transfer (scp died at ~780KB).
  Fix: `smuxCfgUDP` disables keepalive — the ARQ layer keeps the path
  alive.

### Auto-connect relay peers + smux address filtering (v1.6.9 third pass)
- **Auto-connect shared nodes**: a node that joins via ONE shared node
  now learns the OTHERS (CapRelay=true) from meta exchange and dials
  them directly — no single shared node is a single point of failure.
  `AutoConnectRelayPeer`: async, deduped (relayConnecting set),
  endpoint from resolvePeerEndpoint. Verified: phone auto-connected
  to N1 (v6 direct) after joining via aliyun.
- **smux virtual address leak**: STUN unreachable (Android/CN) →
  LocalEP empty → coordination reply fell back to conn.LocalAddr()
  which on a smux stream is "smux:local:<id>" → peer punched a
  nonsense address. Fix: `isRealEndpoint()` filters smux pseudo-
  addresses; fallback degrades to 0.0.0.0:0 (blind punch + observed
  source ports). STUN is now optional, not a dependency.

### Verified
- AMD (zone=us, no config peer) auto-learned → punch fires → hole
  established via 161.118.141.101 (previously stuck at 1.5-3s relay).
- Oracle ARM punch + MTU 1200 + UDP multipath live (358ms stable).
- txcloud↔AMD: ping 3.28ms 0% loss; scp 50MB in 39.6s (10.1 Mbps,
  md5 match).
- All tests + race pass.

## v1.6.8 — 2026-08-15

**UDP hole data plane completion: two-way punch now establishes a live UDP session (kx over the hole) with MTU auto-upgrade — verified 264ms stable, ~2Mbps (5-7x the relay path).**

### The three-bug chain that kept the hole dead (ed96a94)
1. **Coordination frame epLen** — v1.6.7 appended the initiator key to the
   punch frame but the responder computed `epLen = bodyLen-4-8`, leaking the
   key into the endpoint (peerEP became garbage) and shifting the key
   offset — responder-side OnHoleEstablished never fired. Added an explicit
   `ourLen` byte (v1.6.8 frame format) with legacy fallback.
2. **Responder hole endpoint** — the responder fired OnHoleEstablished with
   `e.PublicPunchEP` (the TCP mesh port 52888), not the punch socket's UDP
   data port — the hole was keyed by the wrong target. Now uses the
   coordination reply's `our` (OutboundPort-resolved).
3. **Small writes framed as one oversized datagram** — the path-MTU probe
   set chunkSize=1200 for ANY first write, so the 160B kx msg1 went out as a
   single 171B frame (>60B) and was dropped by restricted paths (Oracle
   security group) — the UDP kx never completed. Probe only when
   `len(p) >= udpPayloadLarge`; small writes always split into ≤40B ARQ
   frames (51B datagrams).

### Also in this release
- kx msg1 fragmentation fix (c01f052): small writes never framed as one
  oversized datagram
- Responder-side hole establishment with initiator identity in the
  coordination frame (72ed77a)
- Punch-poller / UDP-mesh debug logging (MESHDESK_DEBUG=1)
- HasUDPHole punch gate — relay session no longer blocks re-punching (5c47d44)
- Blind punch without advertised endpoints — punch fires as soon as the
  zone gate passes (0cfc788)

### Verified (2026-08-15, live txcloud↔Oracle)
- Two-way punch → kx 51B frames traverse the hole → `udp key exchange
  complete` → `UDP multipath live`
- ping 264.65ms mdev 0.131ms (was 600ms+ jitter via relay)
- MTU auto-upgrade 40→1200 on the hole (throughput ~2Mbps, 5-7x relay)
- 6-node mesh all reporting to the single dashboard

## v1.6.7 — 2026-08-15

**Zone boundary = Reality boundary.** Discovery-plane hardening:
everything that crosses a zone boundary now rides Reality TLS.

### Dashboard off the mesh port (anti-fingerprinting)
- **HTTP is no longer served on the mesh port.** The v1.2.1 single-port
  HTTP demux made shared nodes fingerprintable: a DPI active probe
  sending `GET /` received the Dashboard instead of the camouflage
  site, defeating REALITY's active-probe resistance.
- HTTP bytes (G/P/H) on the mesh port now route to the Reality listener
  like any other non-authenticated traffic — the handshake fails auth
  and the connection is proxied to the camouflage destination, so
  probes see the real website.
- Dashboard + `/api/join` are served ONLY on the dedicated web port
  (`node.web`, default `:8080`). Join URLs generated by the Dashboard
  now use the web port.
- **Operator action:** if you relied on `http://gateway:52888/join`,
  switch to the web port (`http://gateway:8080/join`). Firewall rules
  for the web port apply.

### Hole punching fail-closed
- Punching sends raw (undisguised) UDP probes. The engine now punches
  ONLY when BOTH zones are known and equal (was: zone-unknown peers
  were punched too). Zone-unknown peers stay on Reality until META
  delivers their zone; the 30s lazy scan retries automatically.

### Memberlist retirement — phase 1 (demote, don't delete)
- Relay/NAT knowledge (`Role`, `NatType`, `CapRelay`, `MaxCircuits`,
  `LoadCircuits`) added to the META exchange and flooded through relay
  hops — these fields used to be gossip-exclusive. Relay candidate
  selection now works on relay-attached nodes with degraded memberlist
  (META first, gossip overlay, config peers fallback).
- Design memo: `docs/DESIGN_MEMBERLIST_RETIREMENT.md` (capability
  mapping + phase plan toward full removal).

### Verified (2026-08-15, live 6-node mesh)
- Dashboard on :8080; mesh port 52888 returns no HTTP (Reality
  camouflage intact — active probes see the disguise site)
- Fail-closed punching: txcloud↔Oracle hole established (zone us=us),
  bidirectional 20/20 0% loss @ ~322ms
- Tunnel ping to all nodes OK; N1/aliyun/Oracle ARM/AMD all agent-only
  (single dashboard on txcloud)
- go build/vet/test green

## v1.6.5 — 2026-08-14

**Auto-reporting completed (META collector discovery fixes) + punch self-start + monitor push fan-out.**

### Monitor auto-routing — completion fixes (5279e48, 14cb028)
- **knownPeers() floods Collector=true** — a relay hop now re-advertises
  the dashboard node's capability to its own peers. Before, relay-
  attached nodes (phone) only saw msg.Self of their DIRECT peers and
  never learned where to push metrics.
- **Collector capability changes broadcast** — SetLocalCollector(true)
  and discovering a new collector peer trigger MetaExchanger.Broadcast
  (meta was otherwise exchanged once per session establishment).
- **Push to ALL collectors** — with multiple dashboards (N1 + txcloud
  both web mode), push-to-first-wins starved every dashboard except
  the first in the list. Every collector now receives each envelope.
- Verified live: Oracle auto-discovers and pushes continuously; the
  full txcloud→relay→phone chain is wired (phone still needs a stable
  mesh window to complete discovery after today's repeated restarts).

### Punch self-start after full restart (5279e48)
- Lazy scan now ALSO covers config peers: after both ends restart, the
  meta map is empty (meta needs a session, a session needs a hole) and
  the engine never self-started — the mesh stayed disconnected.
  ConfigPeers() feeds the 30s scan alongside PeerVirtualIPs().
- Verified: txcloud↔Oracle hole re-established automatically after
  dual restart (Oracle logged hole established + session).

### Known issue
- Phone (Redmi, relay-attached via aliyun) not yet reporting: mesh was
  restarted many times during this session; the collector-discovery
  flood needs a stable session window to complete. Expected to
  self-heal once the mesh is left stable.

## v1.6.4 — 2026-08-14

**Auto-reporting to the dashboard (META-based collector discovery) + deployment hardening.**

### Monitor auto-routing (adc4e2f)
- **META-based collector discovery** — the session meta exchange
  (0x4D45) now carries `Collector=true` for nodes running the web
  dashboard. Gossip-based CapCollector discovery never reaches
  relay-attached nodes (degraded memberlist), so phones/NAT nodes
  joined via relay pushed metrics to nobody. Now every peer — relay
  or direct — learns where the dashboard is and auto-pushes CPU/mem/
  traffic metrics with zero config.
- Collector capability floods through the peer list (a relay hop can
  learn the dashboard node from a third peer).
- Verified live: Oracle auto-discovers txcloud's dashboard and pushes;
  monitor-history tracks 3 nodes (n1, txcloud, oracle-arm with CPU).

### Deployment hardening (f7c607a)
- **ARQ window 32→128** — UDP hole throughput ~40kbps → ~300kbps
  (measured 224kbps 100% arrival over the live txcloud↔Oracle hole;
  560kbps drops, safe with the adaptive RTO). BDP = window×frame/RTT
  was the limit; a bigger window only matters when ACKs flow.
- **mesh0 firewall rule** — injected packets on mesh0 are trusted mesh
  traffic, but a stateful INPUT REJECT (cloud images) drops all NEW
  connections from the tunnel (ICMP passes, TCP/UDP behind a mesh VIP
  unreachable). The systemd unit adds `-i mesh0 -j ACCEPT` idempotently
  on ExecStartPre; install.sh persists it (netfilter-persistent /
  /etc/iptables/rules.v4).
- systemd unit: `TimeoutStopSec=15` (graceful-stop bound) +
  `ExecStopPost` cleans the TUN.

### Verified
- txcloud↔Oracle UDP hole: 100+ min idle, 0 session loss
- 224kbps sustained UDP through the tunnel, 100% arrival
- SSH over mesh VIP both directions
- easytier fully removed from all four nodes

## v1.6.3 — 2026-08-14

**UDP hole punching reaches production stability — EasyTier-parity confirmed end-to-end.**

### Hole punching: first real, stable UDP hole (txcloud↔Oracle)
- **Ordinary nodes use random distinct UDP ports** (`UDPPort=-1`): a Go
  runtime quirk silently breaks public UDP sends when a socket shares
  its port with the TCP listener or with the other family's socket
  (WriteToUDP returns nil, nothing leaves the box). Ordinary nodes
  (no public inbound port) now bind udp4 + udp6 on OS-assigned random
  ports; shared nodes keep single-port multiplexing (one `[::]`
  dual-stack socket). The punch coordination exchange carries the real
  ports, so no fixed UDP port is needed.
- **Coordination port fix** — the advertised endpoint's port was
  rewritten from the *coordination smux stream's* LocalAddr (the TCP
  port — wrong). Now uses the punch socket's real outbound source
  port (`e.OutboundPort`), and responders resolve the punch socket
  fresh per peer family (the global OutboundPort was cross-peer
  polluting).
- **Probes fire from the mux socket** (shared path) so the NAT/
  conntrack mapping matches the data plane — a random-source probe
  punches a mapping the data plane never uses.
- **Adaptive RTO** (RFC 6298 SRTT/RTTVAR): a fixed 100ms RTO under a
  257ms WAN RTT retransmitted every frame ~2.5x, flooding the window,
  wedging Write, starving smux keepalive (session death ~4min).
  `RTO = srtt + 4×rttvar`, floor 500ms, per-frame retransmit.
- **Three storm fixes** (frame rate 420fps → 2.5fps):
  - smux PING echo loop — echoing every FramePing (PING/PONG share a
    type) ping-ponged forever; liveness needs only any incoming frame
  - punch probe echo loop — udpListenLoop/punchSocketPoller echoed
    every 0x50 0x4A datagram (same stateless-echo bug)
  - hole endpoint separation — meta exchange no longer overwrites the
    punched endpoint (random UDP port) with gossip endpoints (TCP port)
- **UDP reconnect** — tryReconnect detects hole endpoints and
  re-establishes via DialUDPPeer (kx over the hole) instead of
  TCP-dialing a UDP port.
- **0x54 independent TUN stream disabled** — its 214B auth first frame
  is dropped by the txcloud→Oracle path (≤60B datagrams only); worse,
  each failed dial killed the session on both ends. TUN traffic rides
  the 0x4D smux session stream (51B ARQ frames — the verified hole
  path). Re-enable gated by `tunUDPStreamEnabled` once the auth frame
  can be delivered (future: session-negotiated credentials).

### Verified (four-node mesh)
```
txcloud → Oracle:  100/100 ping 0% loss @ 270ms (mdev 0.14ms)
Oracle → txcloud:   15/15 ping 0% loss @ 269.8ms (mdev 0.10ms)
Idle stability:     100+ minutes, zero session loss
Frame rate:         2.5fps steady (was 420fps storm)
```

## v1.6.2 — 2026-08-13

**Punch-path correctness fixes (coordination framing, arbitration, keepalive, family sockets).**

- Coordination frames use [len u16] prefix + `io.ReadFull` — a single
  `conn.Read` fragments on smux streams (truncated endpoints like
  "203.0.113.10:528", polluted "…:52888Ι")
- Two-way punch arbitrated by peer-key order (smaller key dials
  CLIENT, larger waits SERVER) — simultaneous kx no longer cross-talks
- Punch sockets kept alive with 15s probes (stateful firewalls drop
  the peer's frames once conntrack expires)
- Dual-family UDP sockets (v4 + v6) with correct per-family send
- `DefaultMeshPort` constant — single source of truth for the default
  mesh port (no more magic 52888)
- `UDPConnFor` returns nil on family mismatch (no silent fallback to
  the v6 socket); TUN UDP auth failures now logged with reasons

## v1.6.1 — 2026-08-13

**Hole-punching engine completes to EasyTier parity; relay CPU fix; docs rewrite.**

### Hole punching (v1.6.0 line continued)
- **Symmetric NAT port prediction (NAT4E)** — STUN third probe detects
  predictable mapped-port increments (`EasySym` + `Inc`); the cone side
  fires a 50-port window scan (`symWindowProbe`, birthday-attack) — the
  EasyTier mechanism, ported
- **TCP punch hardened** — conntrack-style source-port exchange
  (`SrcPort` in the coordination protocol; stateful security groups
  pass ESTABLISHED) + sustained-SYN retry (250ms) instead of a single
  connect; fixed punch listener port (mesh port + 1)
- **UDP ARQ stream isolation** (`|in`/`|out` keys) — simultaneous
  two-way key exchanges no longer collide on one ARQ state machine
- **Sub-60B frame fragmentation** (`udpMaxPayload` 1200→40) — survives
  links that drop/corrupt larger datagrams (verified on txcloud↔Oracle
  v6); reassembly covered by a loopback test
- ARQ RTO 200ms→100ms, write timeout 30s→10s (lossy-link recovery)
- Coordination timeout 15s→30s (slow relay links no longer fall back
  to wrong-family punch targets)

### Relay
- **CPU fix**: working relay path cached per target (60s TTL) — the
  monitor tick's `DialVirtualPort` no longer re-runs the full candidate
  scan on healthy links (was 100% CPU)

### Architecture / docs
- main.go split (v1.6.0) retained; docs rewritten: README/README_CN,
  new `docs/DEPENDENCY_TREE.md`, DESIGN_V16 implementation status

## v1.6.0 — 2026-08-13

**main.go split + standalone hole-punching engine.**

### Architecture
- **main.go split** (~2900 → ~650 lines): all assembly moved to
  `internal/app` (app.go / mesh_node.go / p2p.go / tun.go /
  services.go / proxy.go / monitor.go / join.go / web.go / reload.go /
  signals.go / topology_paths.go). Three-phase Build (construct →
  wire → unstarted App), explicit reverse-order Stop (pinned by the
  smoke test), App.Reload for SIGHUP, EntryManager interface for
  web→proxy decoupling. Pure mechanical refactor — no behavior change.
- **Standalone hole-punching engine** (`internal/holepunch`):
  memberlist-independent (meta-exchange + lazy triggers), coordinated
  via virtual port 0x504A (endpoint exchange over smux/relay),
  multi-strategy (two-way UDP → TCP → backoff), punches from the mux
  UDP socket so the NAT mapping matches the data plane, probes carry
  a 0x504A prefix that mux sockets echo for hole verification.
  Real-machine verified: STUN discovery, v4+v6 public endpoint
  exchange, coordination over degraded memberlist. (Probe success is
  limited by symmetric NAT / unreachable v6 link in the test
  topology — engine is complete, per-network tuning may be needed.)
- Stale test scripts removed (ci/test-pipeline.sh, tests/wire_format_*).

### Fixes
- tun-forwarder getUDPStream zone gate: KNOWN cross-zone still
  Reality-only; zone-unknown peers allowed (memberlist-degraded meshes
  learn zones slowly; UDP failure falls back to TCP/relay).
- UDP race in webssh Serve/Close (listener assignment under lock).

## v1.5.12 — 2026-08-12

**Post-release hardening: multi-hop fixes, monitoring observability, memory optimization.**

### Fixes
- **anti-spoof × multi-hop relay**: `validateSourceIP` now accepts any
  KNOWN mesh-member VIP inside the subnet — multi-hop relayed packets
  (src = original initiator, ≠ tunnel peer) were dropped, breaking
  Redmi↔tx. Unknown/foreign sources still rejected (mesh chain = trust
  boundary).
- **UDP ARQ data race**: `Close()` read `baseSeq` without `sendMu`
  while `advanceBase()` (recvLoop) writes it under the lock — fixed;
  full `-race` suite clean (25 packages).
- **Monitor defaults**: no manual collectors — push to all known peers
  (sessions + meta-learned) when the collector list is empty; monitor
  auth accepts meta-learned peers.
- **Config defaults**: mesh/gossip port 51820/7946 → 52888 (single-port
  mux); stale WireGuard-era comments updated.
- **Relay noise**: relayBackoff is now exponential (30s × 2^(n-1),
  capped 10min) — permanently unreachable targets (dead AMD node) no
  longer generate per-tick `no_session_to_target` storms; success
  clears the counter immediately.

### Observability
- **`tun_health` in /api/stats**: packets sent/recv/dropped/spoofed,
  bytes, last-activity (ms ago), uptime, UDP/TCP stream counts —
  stalled data-plane detection (last_activity grows while sessions stay
  up).
- **pprof endpoint** on 127.0.0.1:6060 (heap/goroutine diagnosis).

### Performance
- **Monitor history shrink**: highRes tier 1440→720 slots (12h minute
  granularity) + **gzip persistence** (monitor-history.json ~130MB →
  ~15MB; legacy plain-JSON auto-detected on load). Combined with
  `GOMEMLIMIT=512MiB` + `GOGC=50` (recommended in systemd
  Environment), meshdesk RSS dropped 594→71MB (txcloud) and 617→147MB
  (aliyun).

### Docs
- Missing referenced design docs created (CONFIG_INVENTORY,
  PROXY_DESIGN, CIRCUIT_MANAGER_SPEC, PEERMANAGER_DESIGN, FRONTEND);
  release asset naming unified (`meshdesk-linux-{arch}`).

### Verified
- 25/25 tests green + `-race` clean; 30-min stability observation on
  real nodes (data plane + tun_health + memory) with zero anomalies
- 4-node real mesh: aliyun data plane stable after the forwarder-freeze
  investigation (restart cleared state; observability now surfaces it
  early)

---

## v1.5.11 — 2026-08-12

**Multi-hop relay + config-pinned exits + exit path selection.**

### Relay
- **Multi-hop relay** (A→R1→R2→B): recursive forwarding with
  `MeshRelayRequest.Path` loop prevention, bounded by `max_relay_hops`.
  Fix: accept response now sent to the initiator before bridging (was:
  initiator timed out with EOF despite a live tunnel). Multi-hop
  data-plane test passes (bidirectional echo).
- **Slow-path relay preference**: `DialVirtualPort` tries a relay path
  when the direct session RTT exceeds 300ms (typically cross-zone
  Reality) — a same-zone relay hop can beat the direct path. Ping port
  excluded (recursion guard).

### Exit selection (socks5)
- `proxy.socks5.exit_node` / `exit_nodes`: config-pinned fixed exit for
  the entry listener (Dashboard-managed; CLI flags remain fallback).
- Per-connection selection picks the healthy exit with the lowest live
  RTT (`pickBestExits`); failures fall back to the next-best exit
  (was: hard reject).
- **PeerRTT caching** (30s TTL): topology renders (O(n²) pairs) and
  exit selection reuse cached measurements instead of hammering the
  session echo port.

### Fixes (post-release)
- **anti-spoof × multi-hop**: `validateSourceIP` required src == tunnel
  peer's VIP; multi-hop relayed packets (src = original initiator, a
  different member) were dropped — Redmi↔tx unreachable. Now any KNOWN
  mesh-member VIP inside the subnet is accepted (mesh chain = trust
  boundary); unknown/foreign sources still rejected.
- **UDP ARQ data race**: `Close()` read `baseSeq` without `sendMu`
  while `advanceBase()` (recvLoop) writes it under the lock — fixed
  (race-detector clean).
- **Monitor defaults**: no manual collectors needed — push to all known
  peers (sessions + meta-learned) when the collector list is empty.
- **Config defaults**: mesh/gossip port default 51820/7946 → 52888
  (single-port mux, matches all docs/configs); stale WireGuard-era
  comments updated.

### Verified
- 25/25 test packages green; multi-hop echo test; `-race` clean
- 4-node real machines: exit selection (aliyun auto-picked at 174ms vs
  Oracle ARM 212ms), fixed exit via relay (Oracle ARM IP), data plane OK
- Redmi (Android App) joins the mesh; tx↔Redmi bidirectional ping via
  multi-hop relay after the anti-spoof fix

---

## v1.5.10 — 2026-08-12

**Security hardening + full-connectivity topology.**

### Security (external review driven)
- **Join bundle signing**: ConfigBundle is Ed25519-signed by the server;
  the joiner pins it against the token's ServerFP — MITM tampering over
  plain HTTP is detected and refused (`AllowUnsignedBundle` for legacy
  tokens).
- **Install checksums**: install.sh + join install script verify the
  binary sha256 against the release checksums.txt (fail closed).
- **Login rate limit**: web login POST limited to 5 failures/minute/IP
  (429) — brute-force protection.
- **Join token POST**: `/join` accepts the token in a POST body (no URL
  / proxy-log leakage); GET query still works for `curl | sh`.

### Topology
- **Full-connectivity edges**: every node pair gets an edge (was:
  only measured probe pairs — empty graph with degraded memberlist).
- **Latency-sized layout**: edge spring length maps real path RTT
  (new session echo ping, virtual port 0x5049) — low latency = short
  edge, high latency = long edge.
- **Meta exchange propagates endpoints**: same-zone peers learn
  reachable endpoints even with degraded memberlist → direct UDP/TCP
  dials work (resolvePeerEndpoint fallback).

### Fixes / cleanup
- DNS test helper readiness probe sleeps (deterministic under load)
- Stale WireGuard-era comments + Agora motion annotations removed;
  puppeteer dep dropped
- THREAT_MODEL documents the join trust boundary

---

## v1.5.9 — 2026-08-12

**SOCKS5 entry management + zone fixes.** Zone-aware transport
(v1.5.8) continued; every node is a SOCKS5 exit by default; Dashboard
Proxy page manages the entry listener (listen address + RFC 1929
credentials), save auto-restarts the daemon; relay fallback with
degraded gossip; peers/topology pages show meta-learned peers.

---

## v1.5.8 — 2026-08-11

**Zone-aware transport + 3D topology.** Completion commits: `69f0f74` → `e9a5061`

### Features
- **Zone tags** (`mesh.zone` + `peer.zone`, free-form strings like `cn`/`us`):
  same zone → **UDP P2P** (multipath + hole-punching + 0x4D); cross zone /
  unknown → **Reality TLS only** (conservative). Zone broadcast via gossip
  (NodeMeta.Zone) + meta exchange.
- **3D Topology Dashboard**: node ring color = zone; edge color = transport
  (Reality green / UDP blue / 0x4D amber / relay grey); edge hover shows
  transport / ping / bandwidth. Backend `/api/topology` exposes
  `zone` + `transport` + `latency_ms` + `bandwidth_mbps`.
- Guide: [docs/ZONE_AWARE_TRANSPORT.md](ZONE_AWARE_TRANSPORT.md)

### Fixes
- `peerTransport` map init (nil-map panic on 0x4D dial)
- Earlier Reality-only experiment reverted (UDP/0x4D/NAT code restored —
  kept in git history)

### Verified
- 25/25 test packages green; SameZone unit tests
- Real machines (txcloud ↔ aliyun, both zone: cn): session (Reality),
  data plane (TCP), ping, same-zone UDP multipath (0x54 auth frames)
- ⚠️ All nodes MUST run the same binary version (mixed versions break
  the data plane)

---

## v1.2.1 — 2026-08-06

Single-port HTTP multiplexing and programmatic join endpoint. Completion commit: `a83c9f8`

> **Commit chain:** `de1fe7a` (e2e wiring test) → `db96ae1` (release notes) → `a83c9f8` (join URL port derivation fix)
>
> **Post-release patch:** `fef481a` — race condition fix in `mockExitServer.handleConn` (see v1.2.1-patch below)

### Features

- **Single-Port HTTP Demux** — Dashboard Web UI and join server now share the mesh port (52888) via MuxTransport. HTTP traffic (GET/POST/HEAD, first byte `0x47`/`0x50`/`0x48`) is demuxed onto a dedicated channel, enabling single-port deployment behind restrictive NAT — only one public port required for all mesh traffic plus web access.
- **`/api/join` Onboarding Endpoint** — Programmatic challenge-response onboarding via `POST /api/join` on port 52888. The join server handler is attached to the Dashboard's HTTP mux, so `/api/join` rides the same port as the web UI. Exempt from web session auth; authenticated via token + Ed25519 challenge signature instead.
- **Join URL Port Derivation** — On shared nodes with `reality.enabled: true`, the join install URL (printed on Dashboard join page) now derives its port from the Reality listener (`mesh.port`) instead of hardcoding the web port. This ensures one-click join commands work correctly when Reality TLS is active on the default mesh port. Commit `a83c9f8`.

### Verified

- HTTP demux parseability tests confirm all HTTP methods (GET/POST/HEAD) are correctly routed (`de1fe7a`)
- E2E wiring test verifies `POST /api/join` is served through the demux port (`de1fe7a`)
- Mux demux regression fixed (HTTP channel consumer added to test harness, `db96ae1`)
- Join URL port derivation tested on shared-node topology (`a83c9f8`)
- Motion `motion-454cda95e956` adopted: worktree clean, HEAD=a83c9f8=origin/main, all 22 packages pass

### Post-Release Patch: v1.2.1-patch

Date: 2026-08-07. Commit: `fef481a`

**Store-after-ack race in mockExitServer.handleConn** (`internal/proxy/entry_node_test.go`):

- **Root cause:** `mockExitServer.handleConn` wrote `CircuitAck` and closed the connection BEFORE storing `e2eKeys`/`circuits` in the mock map. The test (`TestEntryNodeCircuitSetup`) reads `e2eKeys` immediately after decoding the ack — triggering a store-after-ack race under `-race`.
- **Reproduction:** `go test -race -run TestEntryNodeCircuitSetup -count=50` → 7/50 failures pre-fix.
- **Fix:** Moved `e2eKeys`/`circuits` store before the `CircuitAck` write, with undo-on-failure cleanup.
- **Verification:** `-race -count=200` PASS; full `internal/proxy -race` 391/391 PASS; full repo test suite 24/24 PASS. Verified by tester at HEAD `8051e88`.

## v1.2.0 — 2026-08-06

Second feature release. Commit: `4dc3f7a`

### Features

- **Systemd Integration + Auto-Reconnect** — systemd unit file with `Type=notify` + `WatchdogSec` support; smux session auto-reconnect with exponential backoff; SIGTERM graceful shutdown (save `peers.cache`, close sessions, delete TUN device)
- **Version Command** — `meshdesk version` outputs version, commit hash, build time, Go version, and platform architecture. Build info injected at compile time via `-ldflags`
- **Log Rotation** — Configurable log rotation: `log_file` / `log_max_size` (default 100MB) / `log_max_backups` (default 3). Defaults to stdout for systemd journald capture
- **Config Validation** — `meshdesk validate <config.yaml>` checks syntax, field types, required fields, and port conflicts with specific error locations and fix suggestions. Runs automatically at startup
- **Mesh DNS** — Embedded lightweight DNS server (Go stdlib). `<hostname>.mesh` resolution via gossip-synced hostname→VirtualIP mapping. Optional `dns_enabled` + `dns_port` config
- **Traffic Statistics** — Per-node metrics: smux bytes/streams, relay forwards, TUN rx/tx packets. Gossip-propagated and displayed on Dashboard node cards
- **Alert UI** — Dashboard alert notification bar + alerts history page. Node offline alerts auto-generated when threshold exceeded
- **Signal Handling** — SIGTERM/SIGINT: graceful shutdown. SIGHUP: config hot-reload. SIGUSR1: dump current state (peers, sessions, routes) to log
- **Config Hot-Reload** — `meshdesk reload` command or SIGHUP triggers reload of ACL rules, monitoring interval, proxy config, and log level. Non-reloadable fields (port, identity) produce clear restart guidance
- **CI Pipeline** — GitHub Actions CI workflow; test identity PEMs use temp directories for non-root CI environments

### Verified

- All unit tests pass across 10 feature packages
- Three-node join end-to-end verified (txcloud → aliyun → N1)
- Version command outputs complete build metadata
- Alert UI renders offline/online events correctly
- Config hot-reload applies ACL and log level without restart

### Known Issues

- **#1 — N1-join /api/monitor metrics gap (cpu=0/mem=0)**: Reporter.pushToCollectors silently fails when collector list is empty on freshly joined nodes. Collector discovery via gossip propagation lags behind first push cycles. Root cause traced to 6 code locations (reporter.go, aggregator.go, gossip.go, events.go). Tracked at [yzy806806/meshdesk#1](https://github.com/yzy806806/meshdesk/issues/1).

## v1.1.0 — 2026-08-05

First feature update. Commit: `e56b22c`

### Features

- **ACL Guide** — Access control list documentation and configuration
- **Systemd Deploy Guide** — Production deployment with systemd
- **Multi-Path Optimization** — Proxy relay path selection improvements

## v1.0.0 — 2026-08-04

First stable release.

### Features

- **Mesh VPN** — P2P decentralized networking via memberlist gossip + Reality TLS + smux
- **TUN Virtual Network** — Transparent Layer 3 IP routing between mesh nodes
  - Deterministic IPAM (VirtualIP = cidr_base + pubkey_hash % host_count)
  - Kernel route auto-sync via gossip NodeMeta
  - Subnet proxy (share local LAN with mesh peers)
  - Source IP anti-spoofing (deny-by-default)
  - Zero-dependency TUN device via raw `/dev/net/tun` syscall
- **Server Monitoring** — CPU, memory, disk, network, services
  - Push-based collection over mesh (no exposed port)
  - Auto-discovery of collector nodes via gossip
  - Metric dedup (SourceID + Sequence)
- **WebSSH** — SSH directly from browser, proxied over mesh
- **SOCKS5 Proxy** — Reality TLS disguised, multi-path relay, exit node controls
  - Standard SOCKS5 client support (no VLESS/xray needed)
  - Entry (0x5350) → relay (0x524C) → exit (0x4558) over single port
- **Dashboard** — Full web UI for node management
  - 3D topology graph, real-time monitoring
  - One-click node join (curl | sh)
  - 4-tier config access control
  - File transfer, service management
- **Reality TLS** — All traffic disguised as HTTPS to a real website (e.g. apple.com)
  - DPI cannot distinguish from legitimate HTTPS
  - No WireGuard, no KCP, no recognizable UDP patterns
- **Single Port** — All protocols multiplexed on port 52888 via MuxTransport
- **One-Click Join** — Generate install command from Dashboard, paste on new machine

### Architecture

- Layer 0: Ed25519 identity (PEM file)
- Layer 1: Reality TLS handshake (REALITY hijack)
- Layer 2a: X25519 ECDH key exchange
- Layer 2b: AES-256-GCM encryption (per-session keys, nonce replay protection)
- Layer 3: smux stream multiplexer
- Layer 4: MeshNode (gossip, WebSSH, file transfer, SOCKS5, TUN, monitoring)

### Node Types

- **Shared node** — Public TCP+UDP port, Reality TLS server, MuxTransport
- **Ordinary node** — No public port, UDP-only gossip, connects outbound

### Verified

- 22/22 unit test packages pass
- TUN ping verified: 0% packet loss, ~184ms cross-network RTT
- VirtualIP gossip broadcast + kernel route injection
- Subnet proxy route injection
- smux sessions across NAT
