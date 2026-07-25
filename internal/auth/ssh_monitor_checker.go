package auth

// MonitorAuthChecker implements monitor.AuthChecker by wrapping
// CapabilityEngine. It checks the monitor_write capability for
// incoming metric pushes, producing an audit log entry for every
// check (Decision E compliance).
//
// Note: WebSSHAuthChecker has been removed — the ssh_proxy capability
// check for WebSocket terminal sessions is now enforced by the shared
// RequireCapability HTTP middleware in the web server's route
// registration. This file retains only the MonitorAuthChecker, which
// is used by the monitor aggregator (a non-HTTP mesh protocol that
// cannot use HTTP middleware).
type MonitorAuthChecker struct {
	engine *CapabilityEngine
}

// NewMonitorAuthChecker creates an auth checker for the monitor
// aggregator. The engine must be non-nil.
func NewMonitorAuthChecker(engine *CapabilityEngine) *MonitorAuthChecker {
	return &MonitorAuthChecker{engine: engine}
}

// AuthorizeMonitorWrite checks whether sourcePeer has the monitor_write
// capability. Returns true if authorized, false otherwise. Every call
// produces an audit log entry via the engine.
func (m *MonitorAuthChecker) AuthorizeMonitorWrite(sourcePeer string) bool {
	if m.engine == nil {
		return false // fail-closed when no engine
	}
	result := m.engine.Authorize(sourcePeer, CapMonitorWrite, "")
	return result.Allowed
}
