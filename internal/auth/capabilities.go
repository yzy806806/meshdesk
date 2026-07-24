// Package auth implements the capability-scoped peer authorization model
// described in ARCHITECTURE.md Decision E.
//
// Core principle: mesh membership ≠ trust. WireGuard provides network-layer
// encryption and peer identity; we layer authorization on top. Each service
// access requires explicit, revocable authorization. A fresh node denies
// all incoming service requests from any peer until the admin explicitly
// grants capabilities (default-deny / zero-trust).
//
// Components:
//   - CapabilityEngine: per-peer capability whitelist with scoping
//   - AuditLogger: structured JSON audit log for every cross-node request
//   - RevocationTracker: tracks revoked peer keys and signed revocation notices
//   - NonceChallenge: cryptographic nonce-sign protocol for binary upgrades
package auth

// Capability constants — the set of operations a peer may be authorized
// to perform on the local node. These match ARCHITECTURE.md Decision E.
const (
	// CapSSHProxy allows a peer to proxy SSH sessions to this node.
	CapSSHProxy = "ssh_proxy"

	// CapFileTransfer allows push and pull of files (bidirectional v1).
	CapFileTransfer = "file_transfer"

	// CapMonitorRead allows a peer to read monitoring data from this node.
	CapMonitorRead = "monitor_read"

	// CapMonitorWrite allows a peer to push monitoring data (aggregator).
	CapMonitorWrite = "monitor_write"

	// CapServiceManage allows start/stop/restart of named services.
	// The specific service names are scoped per-peer.
	CapServiceManage = "service_manage"

	// CapBinaryUpgrade allows uploading and executing a new binary.
	// Requires an additional nonce-sign challenge beyond service_manage.
	CapBinaryUpgrade = "binary_upgrade"
)

// AllCapabilities is the full set of recognized capability strings.
var AllCapabilities = []string{
	CapSSHProxy,
	CapFileTransfer,
	CapMonitorRead,
	CapMonitorWrite,
	CapServiceManage,
	CapBinaryUpgrade,
}

// IsValidCapability returns true if cap is a recognized capability string.
func IsValidCapability(cap string) bool {
	for _, c := range AllCapabilities {
		if c == cap {
			return true
		}
	}
	return false
}
