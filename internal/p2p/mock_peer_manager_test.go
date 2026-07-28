package p2p

import "sync"

// mockPeerManager is a test-only PeerManager that records v2 interface calls.
type mockPeerManager struct {
	mu sync.Mutex

	// Recordings of v2 calls.
	connects    map[string][]string // peerKey → endpoints passed to Connect
	disconnects []string            // peerKeys passed to Disconnect
	updatedEPs  map[string][]string // peerKey → endpoints passed to UpdateEndpoints

	// staticKeys tracks peers marked as static.
	staticKeys map[string]bool

	// relayTargets tracks AddRelayTarget calls.
	relayTargets map[string][]string // targetKey → endpoints

	// relayTargetRemovals tracks RemoveRelayTarget calls.
	relayTargetRemovals []string

	// Error injection.
	connectErr    error
	disconnectErr error

	// Connected state for IsConnected.
	connectedPeers map[string]bool
}

func newMockPeerManager() *mockPeerManager {
	return &mockPeerManager{
		connects:       make(map[string][]string),
		updatedEPs:     make(map[string][]string),
		staticKeys:     make(map[string]bool),
		relayTargets:   make(map[string][]string),
		connectedPeers: make(map[string]bool),
	}
}

// --- v2 PeerManager interface ---

func (m *mockPeerManager) Connect(peerKey string, endpoints []string) error {
	if m.connectErr != nil {
		return m.connectErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connects[peerKey] = endpoints
	m.connectedPeers[peerKey] = true
	return nil
}

func (m *mockPeerManager) Disconnect(peerKey string) error {
	if m.disconnectErr != nil {
		return m.disconnectErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disconnects = append(m.disconnects, peerKey)
	delete(m.connectedPeers, peerKey)
	return nil
}

func (m *mockPeerManager) UpdateEndpoints(peerKey string, endpoints []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updatedEPs[peerKey] = endpoints
	return nil
}

func (m *mockPeerManager) IsConnected(peerKey string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connectedPeers[peerKey]
}

func (m *mockPeerManager) IsStaticPeer(peerKey string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.staticKeys[peerKey]
}

func (m *mockPeerManager) MarkStaticPeer(peerKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.staticKeys[peerKey] = true
}

func (m *mockPeerManager) AddRelayTarget(targetKey string, targetEndpoints []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.relayTargets[targetKey] = targetEndpoints
	m.connectedPeers[targetKey] = true
	return nil
}

func (m *mockPeerManager) RemoveRelayTarget(targetKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.relayTargetRemovals = append(m.relayTargetRemovals, targetKey)
	delete(m.connectedPeers, targetKey)
	return nil
}

// --- Helper accessors for test assertions ---

// GetConnectCount returns the number of Connect calls.
func (m *mockPeerManager) GetConnectCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.connects)
}

// GetConnectedPeers returns the slice of peer keys passed to Connect.
func (m *mockPeerManager) GetConnectedPeers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, 0, len(m.connects))
	for k := range m.connects {
		result = append(result, k)
	}
	return result
}

// WasConnected returns true if Connect was called for the given peer.
func (m *mockPeerManager) WasConnected(peerKey string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.connects[peerKey]
	return ok
}

// GetConnectedEndpoints returns the endpoints passed to Connect for a peer.
func (m *mockPeerManager) GetConnectedEndpoints(peerKey string) ([]string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	eps, ok := m.connects[peerKey]
	return eps, ok
}

// GetDisconnectCount returns the number of Disconnect calls.
func (m *mockPeerManager) GetDisconnectCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.disconnects)
}

// GetDisconnectedPeers returns the slice of peer keys passed to Disconnect.
func (m *mockPeerManager) GetDisconnectedPeers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, len(m.disconnects))
	copy(result, m.disconnects)
	return result
}

// WasDisconnected returns true if Disconnect was called for the given peer.
func (m *mockPeerManager) WasDisconnected(peerKey string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.disconnects {
		if k == peerKey {
			return true
		}
	}
	return false
}

// GetUpdatedEndpoints returns the endpoints passed to UpdateEndpoints for a peer.
func (m *mockPeerManager) GetUpdatedEndpoints(peerKey string) ([]string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	eps, ok := m.updatedEPs[peerKey]
	return eps, ok
}

// GetUpdatedEndpointCount returns the number of UpdateEndpoints calls.
func (m *mockPeerManager) GetUpdatedEndpointCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.updatedEPs)
}

// SetConnected marks a peer as connected (for IsConnected simulation).
func (m *mockPeerManager) SetConnected(peerKey string, connected bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if connected {
		m.connectedPeers[peerKey] = true
	} else {
		delete(m.connectedPeers, peerKey)
	}
}

// SetConnectError injects an error for Connect calls.
func (m *mockPeerManager) SetConnectError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectErr = err
}

// SetDisconnectError injects an error for Disconnect calls.
func (m *mockPeerManager) SetDisconnectError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disconnectErr = err
}

// GetRelayTargetEndpoints returns the endpoints passed to AddRelayTarget.
func (m *mockPeerManager) GetRelayTargetEndpoints(targetKey string) ([]string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	eps, ok := m.relayTargets[targetKey]
	return eps, ok
}

// WasRelayTargetRemoved returns true if RemoveRelayTarget was called for the given key.
func (m *mockPeerManager) WasRelayTargetRemoved(targetKey string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.relayTargetRemovals {
		if k == targetKey {
			return true
		}
	}
	return false
}
