package service

import (
	"io"
	"strings"
)

// ErrNoSystemd is the sentinel error returned when systemd/systemctl is
// not available on the host. Callers can detect this with errors.Is
// to gracefully degrade (e.g., show "service management unavailable"
// in the web UI instead of crashing).
//
// This implements the Gap 5 fix from the codebase audit: the binary
// must start cleanly in containers and non-systemd environments.
var ErrNoSystemd = errNoSystemd{}

type errNoSystemd struct{}

func (errNoSystemd) Error() string { return "systemd not available on this node" }

// NullBackend implements ServiceManager with all methods returning
// ErrNoSystemd. It is used when NewExecBackend fails (systemctl not
// found) so the binary can continue running with service management
// disabled rather than crashing.
//
// The web UI can detect ErrNoSystemd via errors.Is and render disabled
// buttons with a tooltip explaining that systemd is not available.
type NullBackend struct{}

// NewNullBackend creates a ServiceManager that rejects all operations.
func NewNullBackend() *NullBackend { return &NullBackend{} }

func (NullBackend) Start(name string) error  { return ErrNoSystemd }
func (NullBackend) Stop(name string) error   { return ErrNoSystemd }
func (NullBackend) Restart(name string) error { return ErrNoSystemd }

func (NullBackend) Status(name string) (*ServiceStatus, error) {
	return nil, ErrNoSystemd
}

func (NullBackend) Logs(name string, follow bool) (io.ReadCloser, error) {
	return nil, ErrNoSystemd
}

func (NullBackend) List() ([]ServiceStatus, error) {
	return nil, ErrNoSystemd
}

// IsErrNoSystemd returns true if err is ErrNoSystemd. This is a
// convenience wrapper around errors.Is for callers that don't want
// to import the errors package.
func IsErrNoSystemd(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "systemd not available")
}
