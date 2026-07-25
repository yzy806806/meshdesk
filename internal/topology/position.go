package topology

import (
	"crypto/sha256"
	"encoding/binary"
)

// DerivePosition computes a deterministic 3D display position from a
// peer's public key (hex string). The position is stable across restarts
// and does not change unless the peer ID changes.
//
// The SHA-256 hash is split into three 8-byte segments, each interpreted
// as a big-endian uint64, then scaled to the range [-500, 500].
//
// This implements Tier 2 of the positioning strategy (TOPOLOGY_API_SPEC §6):
// "When no manual position is set, derive from the SHA-256 of the public key."
func DerivePosition(peerID string) (x, y, z float64) {
	h := sha256.Sum256([]byte(peerID))
	x = scaleToRange(binary.BigEndian.Uint64(h[0:8]))
	y = scaleToRange(binary.BigEndian.Uint64(h[8:16]))
	z = scaleToRange(binary.BigEndian.Uint64(h[16:24]))
	return
}

// scaleToRange maps a uint64 to the range [-500, 500].
// We use >>1 to avoid overflow, then scale by the ratio of
// (2^63 - 1) to 1000, and shift to center on zero.
//
// Formula: (val >> 1) / 9.2233720368547758e18 * 1000 - 500
// Simplified to avoid floating point edge cases.
func scaleToRange(val uint64) float64 {
	// Use the top 53 bits (mantissa width for float64) to avoid precision loss.
	scaled := float64(val>>11) / float64(1<<53) // [0, 1)
	return scaled*1000 - 500                    // [-500, 500)
}
