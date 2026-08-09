package web

import (
	"net/http"
	"time"
)

// handleStats returns structured traffic statistics (T3.3):
// aggregates + per-peer breakdown from the mesh node's sessions.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if s.node == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "mesh node not available")
		return
	}

	agg := s.node.TrafficStats()

	// Per-peer breakdown.
	peers := s.node.PerPeerTrafficStats()

	writeJSON(w, http.StatusOK, map[string]any{
		"aggregate": map[string]any{
			"in_bytes":       agg.InBytes,
			"out_bytes":      agg.OutBytes,
			"smux_streams":   agg.SmuxStreams,
			"relay_forwards": agg.RelayForwards,
			"tun_rx_packets": agg.TunRxPackets,
			"tun_tx_packets": agg.TunTxPackets,
			"peer_count":     agg.PeerCount,
		},
		"per_peer":  peers,
		"collected": time.Now().Format(time.RFC3339),
	})
}
