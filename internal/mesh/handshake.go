package mesh

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"
)

// PeerHandshakeInfo holds parsed WireGuard handshake status for a single peer.
type PeerHandshakeInfo struct {
	PublicKey           string
	LastHandshakeNano   int64
	LastHandshakeTime   time.Time
	TxBytes             int64
	RxBytes             int64
	PersistentKeepalive int64
}

// parsePeerHandshake parses the output of WireGuard's IpcGet() operation
// and returns a map of publicKey (hex) → PeerHandshakeInfo.
//
// The IpcGet output looks like:
//
//	private_key=...
//	listen_port=51820
//	public_key=<hex>
//	preshared_key=<hex>
//	protocol_version=1
//	endpoint=1.2.3.4:51820
//	last_handshake_time_sec=1234567890
//	last_handshake_time_nsec=123456789
//	tx_bytes=1024
//	rx_bytes=2048
//	persistent_keepalive_interval=10
//	allowed_ip=10.10.1.1/32
//	public_key=<hex>
//	...
func parsePeerHandshake(ipcOutput string) map[string]*PeerHandshakeInfo {
	result := make(map[string]*PeerHandshakeInfo)
	var current *PeerHandshakeInfo

	scanner := bufio.NewScanner(strings.NewReader(ipcOutput))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		switch key {
		case "public_key":
			// Start a new peer block.
			current = &PeerHandshakeInfo{PublicKey: value}
			result[value] = current
		case "last_handshake_time_sec":
			if current == nil {
				continue
			}
			var secs int64
			fmt.Sscanf(value, "%d", &secs)
			current.LastHandshakeNano += secs * int64(time.Second)
		case "last_handshake_time_nsec":
			if current == nil {
				continue
			}
			var nsec int64
			fmt.Sscanf(value, "%d", &nsec)
			current.LastHandshakeNano += nsec
			if current.LastHandshakeNano > 0 {
				current.LastHandshakeTime = time.Unix(0, current.LastHandshakeNano)
			}
		case "tx_bytes":
			if current == nil {
				continue
			}
			fmt.Sscanf(value, "%d", &current.TxBytes)
		case "rx_bytes":
			if current == nil {
				continue
			}
			fmt.Sscanf(value, "%d", &current.RxBytes)
		case "persistent_keepalive_interval":
			if current == nil {
				continue
			}
			fmt.Sscanf(value, "%d", &current.PersistentKeepalive)
		}
	}

	return result
}

// GetPeerHandshakeInfo returns the handshake status for a specific peer
// (by hex public key), or nil if the peer is not known to WireGuard.
func (n *MeshNode) GetPeerHandshakeInfo(publicKey string) *PeerHandshakeInfo {
	output, err := n.dev.IpcGet()
	if err != nil {
		return nil
	}
	peers := parsePeerHandshake(output)
	return peers[publicKey]
}

// isPeerHandshaked returns true if the peer identified by publicKey has a
// completed WireGuard handshake within the last staleAfter duration.
// A zero-value handshake time means the handshake has never completed.
func isPeerHandshaked(info *PeerHandshakeInfo, staleAfter time.Duration) bool {
	if info == nil {
		return false
	}
	if info.LastHandshakeNano == 0 {
		return false
	}
	return time.Since(info.LastHandshakeTime) < staleAfter
}

// WaitForPeerHandshake blocks until the given peer (by hex public key) has
// a completed WireGuard handshake, or ctx is cancelled. It polls the
// WireGuard device's IpcGet at pollInterval and considers a handshake
// fresh if it occurred within staleAfter.
//
// This is used by MeshTransport.DialTimeout to ensure the Noise_IKpsk2
// handshake has completed before issuing a gVisor TCP dial — otherwise
// the TCP SYN is staged in WireGuard's queue and never encrypted/sent,
// causing the dial to hang or time out.
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

// WaitForMeshIPHandshake resolves a mesh IP to its peer public key via the
// routing table, then delegates to WaitForPeerHandshake. This is the
// convenience variant for callers that have a mesh IP but not the peer's
// public key.
func (n *MeshNode) WaitForMeshIPHandshake(ctx context.Context, meshIP string, pollInterval, staleAfter time.Duration) error {
	peerID, ok := n.routes.ResolveRoute(meshIP)
	if !ok {
		return fmt.Errorf("no peer found for mesh IP %s", meshIP)
	}
	return n.WaitForPeerHandshake(ctx, peerID, pollInterval, staleAfter)
}
