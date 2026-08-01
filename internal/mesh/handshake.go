package mesh

import (
	"context"
	"time"
)

// PeerHandshakeInfo holds parsed handshake status for a single peer.
// Populated from the smux session map — session establishment time is
// the handshake completion time.
type PeerHandshakeInfo struct {
	PublicKey           string
	LastHandshakeNano   int64
	LastHandshakeTime   time.Time
	TxBytes             int64
	RxBytes             int64
	PersistentKeepalive int64
}

// GetPeerHandshakeInfo returns the handshake status for a specific peer.
// In v2, this reads from the smux session map: if an active smux session
// exists for the peer, the session establishment time is treated as the
// handshake completion time.
func (n *MeshNode) GetPeerHandshakeInfo(publicKey string) *PeerHandshakeInfo {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()

	sess, ok := n.sessions[publicKey]
	if !ok || sess == nil || sess.IsClosed() {
		return nil
	}

	establishedAt, ok := n.sessionEstablishedAt[publicKey]
	if !ok {
		// Session exists but no timestamp — treat as just established.
		establishedAt = time.Now()
		n.sessionEstablishedAt[publicKey] = establishedAt
	}

	return &PeerHandshakeInfo{
		PublicKey:         publicKey,
		LastHandshakeNano: establishedAt.UnixNano(),
		LastHandshakeTime: establishedAt,
		// TxBytes/RxBytes: smux does not expose per-session byte counters
		// in the current API. These remain zero until byte accounting is
		// added to the smux Session.
		// PersistentKeepalive: not applicable (no WireGuard keepalive).
	}
}

// isPeerHandshaked returns true if the peer has a completed handshake
// within the last staleAfter duration.
func isPeerHandshaked(info *PeerHandshakeInfo, staleAfter time.Duration) bool {
	if info == nil {
		return false
	}
	if info.LastHandshakeNano == 0 {
		return false
	}
	return time.Since(info.LastHandshakeTime) < staleAfter
}

// WaitForPeerHandshake blocks until the given peer has a completed
// handshake, or ctx is cancelled.
// TODO(v2): implement using the new HandshakeLayer.
func (n *MeshNode) WaitForPeerHandshake(ctx context.Context, publicKey string, pollInterval, staleAfter time.Duration) error {
	if pollInterval <= 0 {
		pollInterval = 200 * time.Millisecond
	}
	if staleAfter <= 0 {
		staleAfter = 2 * time.Minute
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		info := n.GetPeerHandshakeInfo(publicKey)
		if isPeerHandshaked(info, staleAfter) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// loop and check again
		}
	}
}
