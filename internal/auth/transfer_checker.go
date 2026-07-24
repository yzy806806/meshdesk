package auth

// TransferAuthChecker implements transfer.AuthChecker by wrapping
// CapabilityEngine. It checks the file_transfer capability for
// incoming file transfer requests, producing an audit log entry
// for every check (Decision E compliance).
type TransferAuthChecker struct {
	engine *CapabilityEngine
}

// NewTransferAuthChecker creates an auth checker for the file transfer
// receiver. The engine must be non-nil.
func NewTransferAuthChecker(engine *CapabilityEngine) *TransferAuthChecker {
	return &TransferAuthChecker{engine: engine}
}

// AuthorizeFileTransfer checks whether sourcePeer has the file_transfer
// capability. Returns true if authorized, false otherwise. Every call
// produces an audit log entry via the engine.
func (t *TransferAuthChecker) AuthorizeFileTransfer(sourcePeer string) bool {
	if t.engine == nil {
		return false // fail-closed when no engine
	}
	result := t.engine.Authorize(sourcePeer, CapFileTransfer, "")
	return result.Allowed
}
