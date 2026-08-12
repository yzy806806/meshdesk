# Circuit Manager Spec

**Version:** 1.0 — matches v1.5.11

The circuit manager (`internal/proxy/circuit_manager.go`) tracks
multi-hop proxy circuits through the mesh and maintains a latency
matrix for path selection.

## Circuit lifecycle

- **Circuits** are end-to-end proxy paths (entry → relay chain → exit),
  each identified by a circuit ID.
- Lifecycle parameters (`proxy.circuit`): `idle_timeout` (300s),
  `keepalive_interval` (30s), `nack_timeout` (5s), `orphan_timeout`
  (30s), `max_reassembly_window` (256).
- Idle circuits are reaped; keepalives keep active ones alive.
- NACK/retransmit handling tolerates lossy UDP segments (the TUN
  multi-path ARQ layer).

## Latency matrix

- `UpdateLatencyMatrix(edges)` merges latency data from probes/gossip
  (AC-IN-04): used by path selection to prefer low-latency relay
  candidates.
- `PathProbeCache` (`internal/proxy/path_state.go`) stores per-pair
  latency; the topology adapter reads it for edge rendering.

## Chunking

- `ChunkerStrategy`: `fixed-16k` or `bounded-4k-64k` (default).
  Chunking bounds per-frame size for smux/relay framing efficiency.
