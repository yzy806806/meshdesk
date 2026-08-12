# PeerManager Design

**Version:** 1.0 — matches v1.5.11

The peer manager (`internal/mesh/peer_manager.go`) handles per-peer
gossip and session lifecycle in the mesh layer.

## Responsibilities

- **Per-peer metadata**: hostname, endpoints, zone, capabilities —
  exchanged via the gossip layer (NodeMeta) and the meta exchange
  (0x4D45, `meta_exchange.go`). Zone and endpoints are cached
  independently of memberlist health so transport selection and direct
  dials keep working when memberlist degrades.
- **Session lifecycle**: tracks `PeerManager` per peer; session
  established/closed events drive the routing table and auto-connect.
- **Endpoints**: `advertise_endpoints` (config) are propagated via meta
  exchange so same-zone peers can dial UDP/TCP directly even without
  memberlist.

## Key APIs

- `PeerZone(peerKey)` / `SetLearnedZone`: config → meta-learned →
  gossip fallback.
- `PeerEndpoints(peerKey)` / `SetLearnedEndpoints`: config first,
  meta-learned fallback (used by `resolvePeerEndpoint`).
- `PeerTransport(peerKey)`: how the session was established
  (reality / 0x4d / udp) for topology display.
- `PeerRTT(peerKey)`: session echo ping, cached 30s.
