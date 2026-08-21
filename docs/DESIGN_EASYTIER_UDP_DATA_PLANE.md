# EasyTier-style UDP Data Plane Design

## Problem

MeshDesk's current UDP data plane requires a full X25519 ECDH key exchange
over the punched UDP hole (`DialUDPPeer`). The kx messages (msg1/msg2) are
~160B, which exceeds the ~60B UDP packet length filter on Oracle Cloud VCN.
Small punch probes (6B) pass conntrack but large kx frames are dropped.

EasyTier does NOT do key exchange over the UDP hole. Instead:
1. Punch probes ARE the data — the UDP socket becomes a transport directly.
2. Protocol upgrade happens on the established UDP socket (not a separate kx).
3. No separate large kx messages needed.

## Design: Remove kx-over-UDP, use punched socket as transport

### Current flow (broken on VCN):
1. Hole punch coordination → exchange mapped endpoints
2. `OnHoleEstablished` → `DialUDPPeer` → send 0x4D marker + X25519 kx
3. kx msg1 (~160B) dropped by VCN → key exchange EOF → retry loop

### New flow (EasyTier-style):
1. Hole punch coordination → exchange mapped endpoints
2. `OnHoleEstablished` → register punched UDP socket as `udpStreamConn`
3. TUN forwarder writes IP packets directly to the `udpStreamConn`
4. No key exchange over UDP — data plane is authenticated by the hole
   punch coordination (both sides verified identity via the smux session
   used for coordination)

### Key changes:

#### 1. Remove `DialUDPPeer` from `OnHoleEstablished`
- Don't call `DialUDPPeer` (no 0x4D marker + kx over UDP)
- Instead, register the punched socket directly with the UDP mesh manager
- The `udpStreamConn` (ARQ layer) handles reliable delivery

#### 2. UDP stream authentication via coordination
- The hole punch coordination runs over an existing smux session (authenticated)
- The coordination message carries the initiator's identity key
- The responder verifies the initiator's identity during coordination
- After coordination succeeds, the UDP path is trusted — no separate kx needed

#### 3. TUN forwarder uses punched UDP socket
- `getOutboundStream(peerKey)` checks for a punched UDP socket first
- If found, writes IP packets as ARQ frames over the `udpStreamConn`
- If not found, falls back to smux session (TCP relay)

#### 4. Inbound: punch socket reader feeds IP packets to TUN
- `punchSocketPoller` already reads from punched sockets
- Route data frames (not probes) to TUN forwarder's inbound path
- The ARQ layer handles reassembly/retransmit

### Why this is safe (no kx over UDP):
- Both sides already have authenticated smux sessions (via Reality TLS or 0x4D)
- The coordination exchange carries and verifies identity keys
- The UDP path is only used for same-zone peers (zone gate)
- Cross-zone traffic stays on Reality TLS (TCP) — no raw UDP exposure

### What changes in code:

| Component | Current | New |
|-----------|---------|-----|
| `OnHoleEstablished` | `DialUDPPeer` (kx over UDP) | Register punched socket as transport |
| `DialUDPPeer` | 0x4D marker + X25519 kx + smux | Not called for punched holes |
| `udpMeshManager` | Creates streams on dial | Also accepts punched sockets |
| `punchSocketPoller` | Reads + routes to udpMesh | Also feeds ARQ data to TUN |
| `getOutboundStream` | Always via smux DialVirtualPort | Check punched socket first |
| `DialUDPStream` | Creates + kx over UDP | Register pre-authenticated socket |

### What stays the same:
- Hole punch coordination (0x504A) — unchanged
- ARQ layer (udpStreamConn) — unchanged, handles retransmit
- TUN forwarder — unchanged, writes framed IP packets
- smux sessions — unchanged, used for relay and coordination
- Reality TLS — unchanged, cross-zone traffic

## Implementation plan:
1. Add `RegisterPunchedStream(peerKey, conn, peerAddr)` to `udpMeshManager`
2. Modify `OnHoleEstablished` to call `RegisterPunchedStream` instead of `DialUDPPeer`
3. Modify `getOutboundStream` to check punched streams first
4. Modify `punchSocketPoller` to route data frames via ARQ
5. Remove key-based arbitration (no longer needed — no kx conflict)
6. Remove "peer won" logic (already done)
7. Remove `DialUDPStream` ACK confirmation (no longer needed — pre-authenticated)
