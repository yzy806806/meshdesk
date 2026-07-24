package auth

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
)

// PeerGrant holds the capabilities and scoped permissions granted to a
// single mesh peer (identified by WireGuard public key).
type PeerGrant struct {
	// PeerID is the hex-encoded WireGuard public key.
	PeerID string

	// Capabilities is the set of capabilities this peer has on us.
	Capabilities map[string]bool

	// ServiceScopes maps CapServiceManage to the specific service names
	// this peer can manage. Empty means "all services" (if service_manage
	// is in Capabilities).
	ServiceScopes map[string]bool

	// FileTransferPaths restricts file_transfer to directory prefixes.
	// Empty means no path restriction.
	FileTransferPaths []string

	// MonitorScopes restricts monitor_read/monitor_write to categories.
	// Empty means all metrics.
	MonitorScopes []string

	// GrantedAt records when the grant was created.
	GrantedAt time.Time
}

// AuthResult is the outcome of an authorization check.
type AuthResult struct {
	Allowed   bool
	Reason    string // "explicit_allow", "no_capability", "revoked", "path_denied", "service_not_scoped"
	Capability string
	Resource   string
	SourcePeer string
	Timestamp  time.Time
}

// CapabilityEngine is the core authorization engine. It maintains the
// per-peer capability whitelist, checks incoming requests against it,
// and logs every decision to the audit logger.
//
// The engine is thread-safe. All state is held in memory; persistence
// is handled by the config layer (config.yaml is the source of truth
// for grants, loaded at startup).
type CapabilityEngine struct {
	mu     sync.RWMutex
	grants map[string]*PeerGrant // peerID → grant

	// revoked tracks peers whose keys have been revoked. A revoked peer
	// is denied even if a grant still exists (belt-and-suspenders).
	revoked map[string]*RevocationEntry

	// audit is the structured audit logger. Every Authorize call
	// produces an audit entry regardless of outcome.
	audit *AuditLogger
}

// RevocationEntry records a key revocation.
type RevocationEntry struct {
	PeerID      string
	RevokedBy   string // the peer ID that issued the revocation
	RevokedAt   time.Time
	Signature   string // hex-encoded signature from the revoking node
	Reason      string
}

// NewCapabilityEngine creates an engine from a config. All peers in
// config.yaml with non-empty capabilities are loaded as grants. The
// engine starts with zero revoked peers.
func NewCapabilityEngine(cfg *config.Config, audit *AuditLogger) *CapabilityEngine {
	engine := &CapabilityEngine{
		grants:  make(map[string]*PeerGrant),
		revoked: make(map[string]*RevocationEntry),
		audit:   audit,
	}

	for _, peer := range cfg.Peers {
		if len(peer.Capabilities) == 0 {
			continue // zero-trust: no capabilities = no grant
		}
		engine.LoadPeerConfig(peer)
	}

	return engine
}

// LoadPeerConfig creates or updates a grant from a PeerConfig entry.
func (e *CapabilityEngine) LoadPeerConfig(peer config.PeerConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()

	grant := &PeerGrant{
		PeerID:        peer.PublicKey,
		Capabilities:  make(map[string]bool),
		ServiceScopes: make(map[string]bool),
		GrantedAt:     time.Now(),
	}

	for _, cap := range peer.Capabilities {
		grant.Capabilities[cap] = true
	}

	for _, svc := range peer.ServiceManage {
		grant.ServiceScopes[svc] = true
	}

	grant.FileTransferPaths = peer.FileTransferPaths
	grant.MonitorScopes = peer.MonitorScopes

	e.grants[peer.PublicKey] = grant
}

// Authorize checks whether sourcePeer is authorized for the given
// capability and resource. The resource parameter is interpreted
// contextually:
//   - ssh_proxy: resource is ignored (pass "")
//   - file_transfer: resource is the file path
//   - service_manage: resource is the service name
//   - monitor_read/monitor_write: resource is the metric category
//   - binary_upgrade: resource is ignored (nonce challenge handles it)
//
// Every call produces an audit log entry.
func (e *CapabilityEngine) Authorize(sourcePeer, capability, resource string) AuthResult {
	result := AuthResult{
		Capability: capability,
		Resource:   resource,
		SourcePeer: sourcePeer,
		Timestamp:  time.Now(),
	}

	// Check revocation first — revoked peers are always denied.
	e.mu.RLock()
	if _, revoked := e.revoked[sourcePeer]; revoked {
		e.mu.RUnlock()
		result.Allowed = false
		result.Reason = "revoked"
		e.logAudit(result)
		return result
	}

	grant, ok := e.grants[sourcePeer]
	if !ok {
		e.mu.RUnlock()
		result.Allowed = false
		result.Reason = "no_capability"
		e.logAudit(result)
		return result
	}

	if !grant.Capabilities[capability] {
		e.mu.RUnlock()
		result.Allowed = false
		result.Reason = "no_capability"
		e.logAudit(result)
		return result
	}

	// Capability is present; check resource scoping.
	allowed := true
	reason := "explicit_allow"

	switch capability {
	case CapServiceManage:
		if len(grant.ServiceScopes) > 0 && !grant.ServiceScopes[resource] {
			allowed = false
			reason = "service_not_scoped"
		}

	case CapFileTransfer:
		if len(grant.FileTransferPaths) > 0 {
			matched := false
			for _, prefix := range grant.FileTransferPaths {
				if strings.HasPrefix(resource, prefix) {
					matched = true
					break
				}
			}
			if !matched {
				allowed = false
				reason = "path_denied"
			}
		}

	case CapMonitorRead, CapMonitorWrite:
		if len(grant.MonitorScopes) > 0 && resource != "" {
			matched := false
			for _, scope := range grant.MonitorScopes {
				if scope == resource {
					matched = true
					break
				}
			}
			if !matched {
				allowed = false
				reason = "scope_denied"
			}
		}
	}

	e.mu.RUnlock()
	result.Allowed = allowed
	result.Reason = reason
	e.logAudit(result)
	return result
}

// Revoke marks a peer as revoked. The peer's grant is not deleted (so it
// can be re-instated), but all future Authorize calls for that peer
// return "revoked". The revocation entry includes the signing peer's
// identity for gossip propagation.
func (e *CapabilityEngine) Revoke(peerID, revokedBy, signature, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.revoked[peerID] = &RevocationEntry{
		PeerID:    peerID,
		RevokedBy: revokedBy,
		RevokedAt: time.Now(),
		Signature: signature,
		Reason:    reason,
	}
	return nil
}

// Reinstate removes a revocation for a peer, restoring its grant
// (if any). Used when a revocation was issued in error or the peer
// has been re-keyed and re-authorized.
func (e *CapabilityEngine) Reinstate(peerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.revoked, peerID)
}

// IsRevoked returns whether a peer is currently revoked.
func (e *CapabilityEngine) IsRevoked(peerID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, revoked := e.revoked[peerID]
	return revoked
}

// GetGrant returns the grant for a peer, or nil if none exists.
func (e *CapabilityEngine) GetGrant(peerID string) *PeerGrant {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if g, ok := e.grants[peerID]; ok {
		// Return a copy to prevent external mutation
		capsCopy := make(map[string]bool, len(g.Capabilities))
		for k, v := range g.Capabilities {
			capsCopy[k] = v
		}
		scopesCopy := make(map[string]bool, len(g.ServiceScopes))
		for k, v := range g.ServiceScopes {
			scopesCopy[k] = v
		}
		return &PeerGrant{
			PeerID:            g.PeerID,
			Capabilities:      capsCopy,
			ServiceScopes:     scopesCopy,
			FileTransferPaths: g.FileTransferPaths,
			MonitorScopes:     g.MonitorScopes,
			GrantedAt:         g.GrantedAt,
		}
	}
	return nil
}

// AllGrants returns a snapshot of all active grants (for admin display).
func (e *CapabilityEngine) AllGrants() []*PeerGrant {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*PeerGrant, 0, len(e.grants))
	for _, g := range e.grants {
		result = append(result, g)
	}
	return result
}

// AllRevocations returns a snapshot of all revocation entries.
func (e *CapabilityEngine) AllRevocations() []*RevocationEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*RevocationEntry, 0, len(e.revoked))
	for _, r := range e.revoked {
		result = append(result, r)
	}
	return result
}

// GrantCount returns the number of peers with active grants.
func (e *CapabilityEngine) GrantCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.grants)
}

// RevokedCount returns the number of revoked peers.
func (e *CapabilityEngine) RevokedCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.revoked)
}

// logAudit writes an audit entry if an audit logger is configured.
func (e *CapabilityEngine) logAudit(result AuthResult) {
	if e.audit == nil {
		return
	}
	entry := AuditEntry{
		Timestamp:           result.Timestamp.UTC().Format(time.RFC3339),
		SourcePeer:          result.SourcePeer,
		RequestedCapability: result.Capability,
		TargetResource:      result.Resource,
		Result:              allowDeny(result.Allowed),
		Reason:              result.Reason,
	}
	e.audit.Log(entry)
}

func allowDeny(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

// GrantSummary returns a human-readable summary of a peer's grants.
func (g *PeerGrant) Summary() string {
	caps := make([]string, 0, len(g.Capabilities))
	for cap := range g.Capabilities {
		caps = append(caps, cap)
	}
	return fmt.Sprintf("peer %s: capabilities=[%s]", g.PeerID[:min(8, len(g.PeerID))], strings.Join(caps, ", "))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
