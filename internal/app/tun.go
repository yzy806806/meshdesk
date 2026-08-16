package app

// integrateTUN wires the TUN layer with the gossip layer: peer
// VirtualIP route sync, auto-dial on join, subnet proxies, session
// death/reconnect cleanup.
//
// The gossip layer has been removed. TUN integration now relies on
// the mesh session meta exchange (META protocol) for peer VirtualIP
// propagation, and the session death/reconnect handlers are wired
// in the mesh node itself (wireMeshNodeCallbacks).
func (a *App) integrateTUN() {
	// No-op: gossip layer removed. TUN VirtualIP routing and subnet
	// proxy propagation are handled by the mesh session meta exchange
	// (META protocol) and the mesh node's internal callbacks.
}
