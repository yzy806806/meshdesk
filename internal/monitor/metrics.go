package monitor

import (
	"encoding/json"
	"time"
)

// Metrics is the full snapshot of a node's system metrics at a point in time.
// It is the unit of collection, storage, and transmission in the monitoring system.
type Metrics struct {
	Timestamp time.Time `json:"timestamp"`

	NodeID   string `json:"node_id"`
	Hostname string `json:"hostname"`

	CPU     CPUMetrics     `json:"cpu"`
	Memory  MemoryMetrics  `json:"memory"`
	Disk    []DiskMetrics  `json:"disk"`
	Network []NetMetrics   `json:"network"`
	LoadAvg LoadAvgMetrics `json:"load_avg"`
	Uptime  int64          `json:"uptime_seconds"`

	// Traffic holds mesh-internal traffic statistics (smux bytes, relay
	// tunnels, TUN packets). These are populated by the reporter from
	// the mesh node's TrafficStats() method before pushing to collectors.
	Traffic TrafficMetrics `json:"traffic"`

	// PeerLatency maps peer public key → RTT in milliseconds for all
	// peers this node has an active session with. Collected from the
	// mesh node's PeerRTT cache. Used by shared nodes to build a global
	// latency graph for multi-path relay routing.
	PeerLatency map[string]int `json:"peer_latency,omitempty"`
}

// TrafficMetrics holds mesh-internal traffic statistics collected from
// the local node. These are pushed alongside system metrics to collectors
// and displayed on the Dashboard.
type TrafficMetrics struct {
	// InBytes is the total inbound bytes at the smux session level
	// (sum of all peer sessions' bytesReceived).
	InBytes uint64 `json:"in_bytes"`

	// OutBytes is the total outbound bytes at the smux session level
	// (sum of all peer sessions' bytesSent).
	OutBytes uint64 `json:"out_bytes"`

	// SmuxStreams is the total number of active smux streams across all
	// peer sessions.
	SmuxStreams int `json:"smux_streams"`

	// RelayForwards is the number of active relay tunnels being forwarded
	// by this node. Zero when relay mode is not enabled.
	RelayForwards int `json:"relay_forwards"`

	// TunRxPackets is the total number of packets received on the TUN device.
	TunRxPackets uint64 `json:"tun_rx_packets"`

	// TunTxPackets is the total number of packets sent through the TUN device.
	TunTxPackets uint64 `json:"tun_tx_packets"`

	// PeerCount is the number of connected peer sessions.
	PeerCount int `json:"peer_count"`
}

// CPUMetrics holds CPU utilisation as percentages.
type CPUMetrics struct {
	// UsagePercent is the overall CPU utilisation (0–100).
	UsagePercent float64 `json:"usage_percent"`
	// PerCore holds per-core utilisation (0–100).
	PerCore []float64 `json:"per_core,omitempty"`
	// CoreCount is the number of logical CPU cores.
	CoreCount int `json:"core_count"`
}

// MemoryMetrics holds memory statistics in bytes.
type MemoryMetrics struct {
	Total     uint64 `json:"total"`
	Used      uint64 `json:"used"`
	Available uint64 `json:"available"`
	// SwapTotal and SwapFree are swap stats; SwapTotal=0 means no swap configured.
	SwapTotal uint64 `json:"swap_total"`
	SwapUsed  uint64 `json:"swap_used"`
}

// DiskMetrics holds per-mount disk statistics.
type DiskMetrics struct {
	Device     string `json:"device"`
	MountPoint string `json:"mount_point"`
	FSType     string `json:"fs_type"`
	Total      uint64 `json:"total"`
	Used       uint64 `json:"used"`
	Free       uint64 `json:"free"`
	// InodePercent is the percentage of inodes used (0–100).
	InodePercent float64 `json:"inode_percent"`
}

// NetMetrics holds per-interface network statistics.
type NetMetrics struct {
	Name      string `json:"name"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	// SpeedMbps is the interface link speed (0 if unknown).
	SpeedMbps int `json:"speed_mbps"`
}

// LoadAvgMetrics holds the 1/5/15-minute load averages.
type LoadAvgMetrics struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

// Encode serialises Metrics to JSON bytes.
func (m *Metrics) Encode() ([]byte, error) {
	return json.Marshal(m)
}

// DecodeMetrics deserialises Metrics from JSON bytes.
func DecodeMetrics(data []byte) (*Metrics, error) {
	var m Metrics
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// MetricEnvelope wraps a Metrics payload for the push protocol.
// The SourceID identifies the originating node; the Sequence is a
// monotonically increasing counter per source for deduplication.
type MetricEnvelope struct {
	SourceID  string   `json:"source_id"`
	Sequence  uint64   `json:"sequence"`
	Forwarded bool     `json:"forwarded,omitempty"`
	Metrics   *Metrics `json:"metrics"`
}
