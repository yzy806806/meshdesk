package service

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// MockBackend is an in-memory ServiceManager for testing. It simulates
// service state transitions without touching the real system.
type MockBackend struct {
	mu       sync.Mutex
	services map[string]*ServiceStatus
	logs     map[string]*strings.Builder
}

// NewMockBackend creates a mock backend with the given initial services.
// If no services are provided, a few defaults are added.
func NewMockBackend(services ...ServiceStatus) *MockBackend {
	mb := &MockBackend{
		services: make(map[string]*ServiceStatus),
		logs:     make(map[string]*strings.Builder),
	}
	if len(services) == 0 {
		// Default services for testing
		mb.services["nginx"] = &ServiceStatus{
			Name: "nginx", LoadState: "loaded", ActiveState: "active",
			SubState: "running", Description: "nginx web server",
		}
		mb.services["meshdesk"] = &ServiceStatus{
			Name: "meshdesk", LoadState: "loaded", ActiveState: "active",
			SubState: "running", Description: "MeshDesk agent",
		}
		mb.services["ssh"] = &ServiceStatus{
			Name: "ssh", LoadState: "loaded", ActiveState: "active",
			SubState: "running", Description: "OpenSSH daemon",
		}
	}
	for _, s := range services {
		s := s // copy
		mb.services[s.Name] = &s
	}
	// Initialize log buffers
	for name := range mb.services {
		mb.logs[name] = &strings.Builder{}
		mb.logs[name].WriteString(fmt.Sprintf("[%s] service %s started\n",
			time.Now().Format(time.RFC3339), name))
	}
	return mb
}

// Start simulates starting a service.
func (m *MockBackend) Start(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	svc, ok := m.services[name]
	if !ok {
		return fmt.Errorf("service %s not found", name)
	}
	svc.ActiveState = "active"
	svc.SubState = "running"
	svc.Timestamp = time.Now()
	m.appendLog(name, "service started")
	return nil
}

// Stop simulates stopping a service.
func (m *MockBackend) Stop(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	svc, ok := m.services[name]
	if !ok {
		return fmt.Errorf("service %s not found", name)
	}
	svc.ActiveState = "inactive"
	svc.SubState = "dead"
	svc.Timestamp = time.Now()
	m.appendLog(name, "service stopped")
	return nil
}

// Restart simulates restarting a service.
func (m *MockBackend) Restart(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	svc, ok := m.services[name]
	if !ok {
		return fmt.Errorf("service %s not found", name)
	}
	svc.ActiveState = "active"
	svc.SubState = "running"
	svc.Timestamp = time.Now()
	m.appendLog(name, "service restarted")
	return nil
}

// Status returns the status of a service.
func (m *MockBackend) Status(name string) (*ServiceStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	svc, ok := m.services[name]
	if !ok {
		return nil, fmt.Errorf("service %s not found", name)
	}
	// Return a copy
	s := *svc
	s.Timestamp = time.Now()
	return &s, nil
}

// Logs returns the accumulated logs for a service.
// The follow parameter is ignored in the mock — it returns all logs
// accumulated so far as a one-shot reader.
func (m *MockBackend) Logs(name string, follow bool) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	builder, ok := m.logs[name]
	if !ok {
		return nil, fmt.Errorf("service %s not found", name)
	}
	return io.NopCloser(strings.NewReader(builder.String())), nil
}

// List returns all known services.
func (m *MockBackend) List() ([]ServiceStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]ServiceStatus, 0, len(m.services))
	for _, svc := range m.services {
		s := *svc
		s.Timestamp = time.Now()
		result = append(result, s)
	}
	return result, nil
}

// AddService adds a service to the mock (for test setup).
func (m *MockBackend) AddService(svc ServiceStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services[svc.Name] = &svc
	if _, ok := m.logs[svc.Name]; !ok {
		m.logs[svc.Name] = &strings.Builder{}
	}
}

// RemoveService removes a service from the mock.
func (m *MockBackend) RemoveService(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.services, name)
	delete(m.logs, name)
}

// appendLog adds a log line. Caller must hold m.mu.
func (m *MockBackend) appendLog(name, message string) {
	builder, ok := m.logs[name]
	if !ok {
		builder = &strings.Builder{}
		m.logs[name] = builder
	}
	builder.WriteString(fmt.Sprintf("[%s] %s\n", time.Now().Format(time.RFC3339), message))
}
