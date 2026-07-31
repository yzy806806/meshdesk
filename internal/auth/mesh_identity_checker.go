package auth

import (
	"log"
	"time"
)

// MeshIdentityAuthChecker implements monitor.AuthChecker by verifying
// that the pushing peer is a known mesh member. This is mesh
// identity-based authorization: any peer that has successfully joined
// the mesh (and thus appears in the routing table) is authorized to
// push monitoring data. Peers not in the routing table are rejected.
//
// This checker is the v2 replacement for the capability-engine-based
// MonitorAuthChecker. In v2 with mesh-internal connections, peers join
// via gossip + authorized_keys and may not have explicit capability
// grants in config.yaml. Mesh identity (routing table membership) is
// the correct trust boundary: if a peer is in the mesh, it is trusted
// to push its own monitoring data.
//
// If finer-grained control is needed (e.g. restricting monitor_write
// to a subset of mesh peers), the capability-engine-based
// MonitorAuthChecker can be used instead by configuring explicit
// capabilities in config.yaml.
type MeshIdentityAuthChecker struct {
	// localPublicKey is this node's own hex-encoded public key.
	// Self-pushes are always allowed (the node collects its own
	// metrics and may push them to itself when acting as both
	// reporter and aggregator).
	localPublicKey string

	// isKnownPeer returns true if the given peer ID (hex public key)
	// is a known mesh member (i.e. present in the routing table).
	isKnownPeer func(peerID string) bool

	// audit is the structured audit logger. Every AuthorizeMonitorWrite
	// call produces an audit entry regardless of outcome. May be nil
	// (no audit logging).
	audit *AuditLogger
}

// NewMeshIdentityAuthChecker creates a mesh identity-based auth checker
// for the monitor aggregator. The isKnownPeer function should return
// true for peers that are currently in the mesh routing table. The
// localPublicKey is this node's own public key (self-pushes are always
// allowed). The audit logger may be nil.
func NewMeshIdentityAuthChecker(localPublicKey string, isKnownPeer func(peerID string) bool, audit *AuditLogger) *MeshIdentityAuthChecker {
	return &MeshIdentityAuthChecker{
		localPublicKey: localPublicKey,
		isKnownPeer:    isKnownPeer,
		audit:          audit,
	}
}

// AuthorizeMonitorWrite checks whether sourcePeer is authorized to push
// monitoring data. Returns true if:
//   - sourcePeer is the local node itself (self-push), or
//   - sourcePeer is a known mesh peer (present in the routing table)
//
// Returns false (fail-closed) for unknown peers. Every call produces an
// audit log entry if an audit logger is configured.
func (m *MeshIdentityAuthChecker) AuthorizeMonitorWrite(sourcePeer string) bool {
	if sourcePeer == "" {
		m.logAudit(sourcePeer, false, "empty_peer_id")
		return false
	}

	// Self-push is always allowed.
	if sourcePeer == m.localPublicKey {
		m.logAudit(sourcePeer, true, "self")
		return true
	}

	// Check mesh membership.
	if m.isKnownPeer != nil && m.isKnownPeer(sourcePeer) {
		m.logAudit(sourcePeer, true, "mesh_member")
		return true
	}

	m.logAudit(sourcePeer, false, "unknown_peer")
	return false
}

// logAudit writes an audit entry if an audit logger is configured.
func (m *MeshIdentityAuthChecker) logAudit(sourcePeer string, allowed bool, reason string) {
	if m.audit == nil {
		// Still log to stderr for visibility.
		if !allowed {
			log.Printf("monitor auth: rejected metric push from peer %s (%s)", sourcePeer, reason)
		}
		return
	}

	entry := AuditEntry{
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		SourcePeer:          sourcePeer,
		RequestedCapability: CapMonitorWrite,
		Result:              allowDeny(allowed),
		Reason:              reason,
	}
	m.audit.Log(entry)

	if !allowed {
		log.Printf("monitor auth: rejected metric push from peer %s (%s)", sourcePeer, reason)
	}
}
