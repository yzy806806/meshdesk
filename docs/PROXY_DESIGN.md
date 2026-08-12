# Proxy Design (SOCKS5 / Relay / Path)

**Version:** 1.0 — matches v1.5.11

## SOCKS5 exit (every node, by default)

- Every node registers the SOCKS5 server on **virtual port `0x5350`**
  (`SOCKS5VirtualPort`, "SP" mnemonic). No configuration needed.
- Destination ports default to 80/443 (`AllowedPorts`); extend via
  `proxy.socks5.allowed_ports` / `allow_all_ports`.
- `RequireMeshPeer` / `AllowedPeers` restrict which mesh peers may use
  the exit (default: any mesh peer — mesh membership is the trust
  boundary).

## Entry listener

- `proxy.socks5.entry_listen` (or `--socks5-listen`) starts a local TCP
  listener. Clients authenticate with RFC 1929 username/password when
  `entry_username`/`entry_password` are set (REQUIRED for non-loopback).
- Per CONNECT the entry picks the best configured exit
  (`exit_node`/`exit_nodes`) — healthy, lowest live RTT (`pickBestExits`,
  RTT from the session echo ping, cached 30s). Failures fall back to the
  next-best exit.

## Relay (0x524C, "RL")

- `RelayHandler` bridges initiator streams to target virtual ports.
- Single hop: the relay must have a session to the target.
- **Multi-hop** (v1.5.11): `multiHopRelay` recursively forwards through
  another relay when the target is unreachable — `MeshRelayRequest.Path`
  carries the traversed chain (loop prevention), bounded by
  `p2p.max_relay_hops`. The accept response is sent to the initiator
  before bridging.
- `DialVirtualPort` prefers a relay path when the direct session RTT is
  slow (>300ms, `relaySlowPathThresholdMs` — typically cross-zone
  Reality); direct is the fallback on relay failure.

## Path latency

- `PeerRTT` measures round-trip over the session echo port (`0x5049`,
  "PI") — the measured path IS the real data path (Reality for
  cross-zone, UDP for same-zone direct, relay for bridged). Results are
  cached 30s (`rttCache`) for topology O(n²) renders and exit selection.
