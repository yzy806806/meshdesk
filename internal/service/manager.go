// Package service implements the ServiceManager interface from
// ARCHITECTURE.md Decision F.
//
// It provides a unified interface for managing system services (start,
// stop, restart, status, logs, list) with multiple backends:
//
//   - ExecBackend: uses systemctl/exec directly (production)
//   - MockBackend: in-memory backend for testing
//
// The capability layer (auth package) gates access: only peers with
// service_manage capability (and the right service scope) can invoke
// these operations. The ServiceManager itself does not check capabilities
// — that is the caller's responsibility (the HTTP handler or mesh
// request handler checks auth before calling ServiceManager methods).
package service

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ServiceStatus represents the current state of a managed service.
type ServiceStatus struct {
	Name        string    `json:"name"`
	LoadState   string    `json:"load_state"`   // "loaded", "masked", "not-found"
	ActiveState string    `json:"active_state"` // "active", "inactive", "failed", "activating"
	SubState    string    `json:"sub_state"`     // "running", "dead", "exited", etc.
	Description string    `json:"description"`
	ExecMainPID int       `json:"exec_main_pid"`
	MemoryBytes uint64    `json:"memory_bytes"`
	CPUTime     string    `json:"cpu_time"`
	Timestamp   time.Time `json:"timestamp"`
}

// ServiceManager is the interface for managing system services.
// This matches ARCHITECTURE.md Decision F.
type ServiceManager interface {
	Start(name string) error
	Stop(name string) error
	Restart(name string) error
	Status(name string) (*ServiceStatus, error)
	Logs(name string, follow bool) (io.ReadCloser, error)
	List() ([]ServiceStatus, error)
}

// ExecBackend implements ServiceManager using the systemctl command.
// This is the production backend. It requires the meshdesk binary to
// run as root (or with appropriate polkit/sudo permissions).
type ExecBackend struct {
	systemctlPath string
	timeout       time.Duration
}

// NewExecBackend creates a ServiceManager backed by systemctl.
// The systemctl binary is auto-detected if systemctlPath is empty.
func NewExecBackend(systemctlPath string, timeout time.Duration) (*ExecBackend, error) {
	if systemctlPath == "" {
		path, err := exec.LookPath("systemctl")
		if err != nil {
			return nil, fmt.Errorf("systemctl not found in PATH: %w", err)
		}
		systemctlPath = path
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &ExecBackend{
		systemctlPath: systemctlPath,
		timeout:       timeout,
	}, nil
}

// Start starts the named service via systemctl.
func (e *ExecBackend) Start(name string) error {
	return e.runSystemctl("start", name)
}

// Stop stops the named service via systemctl.
func (e *ExecBackend) Stop(name string) error {
	return e.runSystemctl("stop", name)
}

// Restart restarts the named service via systemctl.
func (e *ExecBackend) Restart(name string) error {
	return e.runSystemctl("restart", name)
}

// Status queries the status of a named service.
func (e *ExecBackend) Status(name string) (*ServiceStatus, error) {
	// systemctl show gives us structured output
	output, err := e.runSystemctlOutput("show", name)
	if err != nil {
		return nil, fmt.Errorf("systemctl show %s: %w", name, err)
	}

	status := parseSystemctlShow(output)
	status.Name = name
	status.Timestamp = time.Now()
	return status, nil
}

// Logs returns a reader for the service's journal logs.
// If follow is true, the reader stays open and streams new log entries
// (like `journalctl -f`). The caller must close the reader when done.
func (e *ExecBackend) Logs(name string, follow bool) (io.ReadCloser, error) {
	args := []string{"-u", name, "--no-pager", "-o", "short-iso"}
	if follow {
		args = append(args, "-f")
	}

	cmd := exec.Command("journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("journalctl pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		stdout.Close()
		return nil, fmt.Errorf("start journalctl: %w", err)
	}

	// Wrap in a reader that closes the process when done
	return &logReader{cmd: cmd, reader: stdout}, nil
}

// List lists all managed services (loaded units).
func (e *ExecBackend) List() ([]ServiceStatus, error) {
	// List all loaded service units
	output, err := e.runSystemctlOutput("list-units", "--type=service", "--all", "--no-legend", "--plain")
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}

	var services []ServiceStatus
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".service")
		loadState := fields[1]
		activeState := fields[2]
		subState := fields[3]
		description := ""
		if len(fields) > 4 {
			description = strings.Join(fields[4:], " ")
		}
		services = append(services, ServiceStatus{
			Name:        name,
			LoadState:   loadState,
			ActiveState: activeState,
			SubState:    subState,
			Description: description,
			Timestamp:   time.Now(),
		})
	}

	return services, nil
}

// runSystemctl executes a systemctl command and returns any error.
// The backend's configured timeout is enforced via context cancellation.
func (e *ExecBackend) runSystemctl(action, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.systemctlPath, action, name)
	cmd.Env = []string{"LC_ALL=C"} // ensure consistent output parsing
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("systemctl %s %s: timed out after %s", action, name, e.timeout)
		}
		return fmt.Errorf("systemctl %s %s: %w (output: %s)", action, name, err, string(output))
	}
	return nil
}

// runSystemctlOutput executes a systemctl command and returns stdout.
// The backend's configured timeout is enforced via context cancellation.
func (e *ExecBackend) runSystemctlOutput(action string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	fullArgs := append([]string{action}, args...)
	cmd := exec.CommandContext(ctx, e.systemctlPath, fullArgs...)
	cmd.Env = []string{"LC_ALL=C"}
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("systemctl %s: timed out after %s", action, e.timeout)
		}
		return "", fmt.Errorf("systemctl %s: %w (output: %s)", action, err, string(output))
	}
	return string(output), nil
}

// parseSystemctlShow parses the output of `systemctl show` into a ServiceStatus.
// systemctl show outputs key=value pairs, one per line.
func parseSystemctlShow(output string) *ServiceStatus {
	status := &ServiceStatus{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := parts[1]

		switch key {
		case "LoadState":
			status.LoadState = value
		case "ActiveState":
			status.ActiveState = value
		case "SubState":
			status.SubState = value
		case "Description":
			status.Description = value
		case "ExecMainPID":
			fmt.Sscanf(value, "%d", &status.ExecMainPID)
		case "MemoryCurrent":
			fmt.Sscanf(value, "%d", &status.MemoryBytes)
		}
	}
	return status
}

// logReader wraps a journalctl process, closing both the pipe and the
// process when Close() is called.
type logReader struct {
	cmd    *exec.Cmd
	reader io.Reader
	closed sync.Once
}

func (lr *logReader) Read(p []byte) (int, error) {
	return lr.reader.Read(p)
}

func (lr *logReader) Close() error {
	lr.closed.Do(func() {
		if lr.cmd != nil && lr.cmd.Process != nil {
			lr.cmd.Process.Kill()
		}
		lr.cmd.Wait()
	})
	return nil
}
