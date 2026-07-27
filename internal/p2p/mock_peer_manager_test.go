package p2p

import "sync"

// mockPeerManager is a test-only PeerManager that records calls.
type mockPeerManager struct {
	mu             sync.Mutex
	addedPeers     []DynamicPeer
	removedPeers   []string
	updatedEPs     map[string]string
	staticKeys     map[string]bool
	healthyPeers   map[string]bool
	handshakeTimes map[string]int // publicKey → count of calls
	addErr         error
	removeErr      error
}

func newMockPeerManager() *mockPeerManager {
	return &mockPeerManager{
		updatedEPs:     make(map[string]string),
		staticKeys:     make(map[string]bool),
		healthyPeers:   make(map[string]bool),
		handshakeTimes: make(map[string]int),
	}
}

func (m *mockPeerManager) AddDynamicPeer(peer DynamicPeer) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addedPeers = append(m.addedPeers, peer)
	return nil
}

func (m *mockPeerManager) RemoveDynamicPeer(publicKey string) error {
	if m.removeErr != nil {
		return m.removeErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removedPeers = append(m.removedPeers, publicKey)
	return nil
}

func (m *mockPeerManager) UpdateEndpoint(publicKey, endpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updatedEPs[publicKey] = endpoint
	return nil
}

func (m *mockPeerManager) IsHealthy(publicKey string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthyPeers[publicKey]
}

func (m *mockPeerManager) UpdateHandshakeTime(publicKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handshakeTimes[publicKey]++
}

func (m *mockPeerManager) IsStaticPeer(publicKey string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.staticKeys[publicKey]
}

func (m *mockPeerManager) MarkStaticPeer(publicKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.staticKeys[publicKey] = true
}

// GetUpdatedEndpoint returns the recorded endpoint for a peer (thread-safe).
func (m *mockPeerManager) GetUpdatedEndpoint(publicKey string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ep, ok := m.updatedEPs[publicKey]
	return ep, ok
}

// GetHandshakeCount returns the handshake update count for a peer (thread-safe).
func (m *mockPeerManager) GetHandshakeCount(publicKey string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handshakeTimes[publicKey]
}

// SetHealthy marks a peer as healthy/unhealthy (thread-safe).
func (m *mockPeerManager) SetHealthy(publicKey string, healthy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthyPeers[publicKey] = healthy
}

// AddRelayTarget records a relay target addition (mock).
func (m *mockPeerManager) AddRelayTarget(targetKey, targetMeshIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addedPeers = append(m.addedPeers, DynamicPeer{
		PublicKey:  targetKey,
		AllowedIPs: []string{testMeshCIDR(targetMeshIP)},
		IsRelay:    true,
	})
	return nil
}

// AddRelayRoute records a relay route addition (mock).
func (m *mockPeerManager) AddRelayRoute(relayKey, targetMeshIP string) error {
	return nil
}

// RemoveRelayRoute records a relay route removal (mock).
func (m *mockPeerManager) RemoveRelayRoute(relayKey, targetMeshIP string) error {
	return nil
}
