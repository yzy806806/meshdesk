package webssh

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// KnownHostsStore is a thread-safe in-memory store of pinned SSH host keys.
//
// On first connection to a host, the server's public key is recorded.
// On subsequent connections, the key is compared — if it matches, the
// connection proceeds; if it differs, the connection is rejected as a
// potential MITM attack.
//
// This is the "trust on first use" (TOFU) model, which is appropriate for
// the mesh VPN context where the transport layer is already authenticated
// via Reality TLS + Ed25519 identity binding.
type KnownHostsStore struct {
	mu   sync.RWMutex
	keys map[string]string // host -> base64-encoded public key
}

// NewKnownHostsStore creates an empty known-hosts store.
func NewKnownHostsStore() *KnownHostsStore {
	return &KnownHostsStore{
		keys: make(map[string]string),
	}
}

// HostKeyCallback returns an ssh.HostKeyCallback that implements TOFU:
// on first connection, the key is pinned; on subsequent connections, the
// key must match the pinned one.
func (s *KnownHostsStore) HostKeyCallback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		keyB64 := base64.StdEncoding.EncodeToString(key.Marshal())
		host := normalizeHost(hostname)

		s.mu.Lock()
		defer s.mu.Unlock()

		pinned, exists := s.keys[host]
		if !exists {
			// First connection — pin the key.
			s.keys[host] = keyB64
			return nil
		}

		if pinned != keyB64 {
			return fmt.Errorf("webssh: host key mismatch for %s (possible MITM)", host)
		}

		return nil
	}
}

// Pin explicitly pins a host key for a host. This is used when the key is
// known in advance (e.g., from the mesh identity) and should not be learned
// via TOFU.
func (s *KnownHostsStore) Pin(host, keyB64 string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[normalizeHost(host)] = keyB64
}

// IsPinned returns true if the host has a pinned key.
func (s *KnownHostsStore) IsPinned(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.keys[normalizeHost(host)]
	return ok
}

// normalizeHost strips the port from a host string if present, since SSH
// host key callbacks receive "host:port" format.
func normalizeHost(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Only strip if it looks like a port (not an IPv6 address without port).
		// IPv6 addresses in brackets [::1]:22 — strip after ].
		if strings.HasPrefix(host, "[") {
			if closeIdx := strings.Index(host, "]"); closeIdx != -1 {
				return host[:closeIdx+1]
			}
		}
		return host[:idx]
	}
	return host
}
