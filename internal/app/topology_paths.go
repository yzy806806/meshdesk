package app

import (
	"time"

	"github.com/yzy806806/meshdesk/internal/p2p"
)

// linkMapTopologyPaths implements topology.TopologyPathInfo backed by
// the P1 PeerLinkMap (global topology link state). Edges in the 3D
// topology view are drawn from measured direct links.
type linkMapTopologyPaths struct {
	lm *p2p.PeerLinkMap
}

// PeerLatency returns the measured RTT between two nodes in ms.
// Returns -1 if no direct link is known.
func (a *linkMapTopologyPaths) PeerLatency(sourceID, targetID string) float64 {
	if a.lm == nil {
		return -1
	}
	ms := a.lm.PeerLatencyMs(sourceID, targetID)
	if ms < 0 {
		return -1
	}
	return float64(ms)
}

// DirectLink reports whether source→target is a known direct link.
func (a *linkMapTopologyPaths) DirectLink(sourceID, targetID string) bool {
	return a.lm != nil && a.lm.HasLink(sourceID, targetID)
}

// LatencyAge returns how long ago the link was last measured.
func (a *linkMapTopologyPaths) LatencyAge(sourceID, targetID string) time.Duration {
	if a.lm == nil {
		return time.Hour
	}
	return a.lm.LinkAge(sourceID, targetID)
}
