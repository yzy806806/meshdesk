package topology

// TopologyNode represents a single node in the topology graph.
// JSON tags match the contract in TOPOLOGY_API_SPEC.md §2.1.
type TopologyNode struct {
	ID       string  `json:"id"`
	Role     string  `json:"role"`
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	Z        float64 `json:"z"`
	CPU      float64 `json:"cpu"`
	Mem      float64 `json:"mem"`
	Hostname string  `json:"hostname"`
	Status   string  `json:"status"`
}

// TopologyEdge represents a connection between two nodes.
// JSON tags match the contract in TOPOLOGY_API_SPEC.md §2.1.
type TopologyEdge struct {
	Source        string  `json:"source"`
	Target        string  `json:"target"`
	LatencyMs     float64 `json:"latency_ms"`
	BandwidthMbps float64 `json:"bandwidth_mbps"`
}

// TopologySnapshot is the full topology response for GET /api/topology
// and the SSE "topology" event payload.
type TopologySnapshot struct {
	Nodes []TopologyNode `json:"nodes"`
	Edges []TopologyEdge `json:"edges"`
}
