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

	// TUN forwarder health snapshot (stalled data-plane detection).
	var tunHealth map[string]any
	if ts := s.node.TunForwarderStats(); ts != nil {
		tunHealth = map[string]any{
			"packets_sent":         ts.PacketsSent,
			"packets_received":     ts.PacketsReceived,
			"packets_dropped":      ts.PacketsDropped,
			"packets_spoofed":      ts.PacketsSpoofed,
			"bytes_sent":           ts.BytesSent,
			"bytes_received":       ts.BytesReceived,
			"last_activity_ms_ago": ts.LastActivityMs,
			"uptime_sec":           ts.UptimeSec,
			"udp_streams":          ts.UDPStreams,
			"tcp_streams":          ts.TCPStreams,
		}
	}

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
		"per_peer":   peers,
		"tun_health": tunHealth,
		"collected":  time.Now().Format(time.RFC3339),
	})
}
