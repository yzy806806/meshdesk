package auth

// WebSSHAuthChecker implements webssh.AuthChecker by wrapping
// CapabilityEngine. It checks the ssh_proxy capability for
// incoming WebSocket terminal requests, producing an audit log
// entry for every check (Decision E compliance).
type WebSSHAuthChecker struct {
	engine *CapabilityEngine
}

// NewWebSSHAuthChecker creates an auth checker for the webssh handler.
// The engine must be non-nil.
func NewWebSSHAuthChecker(engine *CapabilityEngine) *WebSSHAuthChecker {
	return &WebSSHAuthChecker{engine: engine}
}

// AuthorizeSSH checks whether peerID has the ssh_proxy capability.
// Returns true if authorized, false otherwise. Every call produces
// an audit log entry via the engine.
func (w *WebSSHAuthChecker) AuthorizeSSH(peerID string) bool {
	if w.engine == nil {
		return false // fail-closed when no engine
	}
	result := w.engine.Authorize(peerID, CapSSHProxy, "")
	return result.Allowed
}

// AuthorizeSSHWithIP is like AuthorizeSSH but also records the source
// IP address in the audit entry for traceability.
func (w *WebSSHAuthChecker) AuthorizeSSHWithIP(peerID, sourceIP string) bool {
	if w.engine == nil {
		return false // fail-closed when no engine
	}
	result := w.engine.AuthorizeWithSourceIP(peerID, CapSSHProxy, "", sourceIP)
	return result.Allowed
}

// MonitorAuthChecker implements monitor.AuthChecker by wrapping
// CapabilityEngine. It checks the monitor_write capability for
// incoming metric pushes, producing an audit log entry for every
// check (Decision E compliance).
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
