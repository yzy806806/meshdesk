package service

import (
	"fmt"
	"io"

	"github.com/yzy806806/meshdesk/internal/auth"
)

// AuthorizedServiceManager wraps a ServiceManager with capability-based
// authorization. Every method call first checks that the requesting peer
// has the service_manage capability and is scoped to the requested
// service name.
//
// This is the integration point between the auth and service packages.
// The HTTP handler or mesh request handler creates an
// AuthorizedServiceManager with the caller's peer ID, then delegates
// all operations to it. Unauthorized calls return an error before
// touching the underlying ServiceManager.
type AuthorizedServiceManager struct {
	backend ServiceManager
	engine  *auth.CapabilityEngine
	peerID  string // the requesting peer's identity
}

// NewAuthorizedServiceManager wraps a backend with capability enforcement.
func NewAuthorizedServiceManager(backend ServiceManager, engine *auth.CapabilityEngine, peerID string) *AuthorizedServiceManager {
	return &AuthorizedServiceManager{
		backend: backend,
		engine:  engine,
		peerID:  peerID,
	}
}

// Start starts a service if the peer is authorized.
func (a *AuthorizedServiceManager) Start(name string) error {
	if !a.check(name) {
		return fmt.Errorf("unauthorized: peer %s cannot manage service %s", shortID(a.peerID), name)
	}
	return a.backend.Start(name)
}

// Stop stops a service if the peer is authorized.
func (a *AuthorizedServiceManager) Stop(name string) error {
	if !a.check(name) {
		return fmt.Errorf("unauthorized: peer %s cannot manage service %s", shortID(a.peerID), name)
	}
	return a.backend.Stop(name)
}

// Restart restarts a service if the peer is authorized.
func (a *AuthorizedServiceManager) Restart(name string) error {
	if !a.check(name) {
		return fmt.Errorf("unauthorized: peer %s cannot manage service %s", shortID(a.peerID), name)
	}
	return a.backend.Restart(name)
}

// Status queries service status if the peer is authorized.
func (a *AuthorizedServiceManager) Status(name string) (*ServiceStatus, error) {
	if !a.check(name) {
		return nil, fmt.Errorf("unauthorized: peer %s cannot manage service %s", shortID(a.peerID), name)
	}
	return a.backend.Status(name)
}

// Logs retrieves service logs if the peer is authorized.
func (a *AuthorizedServiceManager) Logs(name string, follow bool) (io.ReadCloser, error) {
	if !a.check(name) {
		return nil, fmt.Errorf("unauthorized: peer %s cannot manage service %s", shortID(a.peerID), name)
	}
	return a.backend.Logs(name, follow)
}

// List lists all services. This checks service_manage capability but
// does not scope to individual services (listing is informational).
func (a *AuthorizedServiceManager) List() ([]ServiceStatus, error) {
	// For List, we only check that the peer has service_manage capability,
	// not whether they're scoped to a specific service (listing is
	// informational — individual service actions are still scoped).
	grant := a.engine.GetGrant(a.peerID)
	if grant == nil || !grant.Capabilities[auth.CapServiceManage] {
		return nil, fmt.Errorf("unauthorized: peer %s lacks service_manage capability", shortID(a.peerID))
	}
	if a.engine.IsRevoked(a.peerID) {
		return nil, fmt.Errorf("unauthorized: peer %s is revoked", shortID(a.peerID))
	}
	return a.backend.List()
}

// check verifies that the peer has service_manage capability and is
// scoped to the given service name. Returns true if authorized.
func (a *AuthorizedServiceManager) check(serviceName string) bool {
	result := a.engine.Authorize(a.peerID, auth.CapServiceManage, serviceName)
	return result.Allowed
}

// shortID returns a truncated peer ID for display.
func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
