package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// CommandVirtualPort is the mesh virtual port for remote command
// execution (T2.1). The Dashboard (or any authorized peer) can run
// non-interactive commands on this node over the encrypted mesh
// channel — the backbone of one-click node updates.
const CommandVirtualPort = 0x1F5 // 501

// ──────────────────────────────────────────────────────────────────────────
// Command protocol (JSON frames over a mesh stream):
//
//   Request:  {"cmd":"md5sum /x","timeout":30}
//   Response: {"ok":true,"stdout":"...","stderr":"...","exit":0}
//   Response: {"ok":false,"error":"..."}
//
// Commands are run via /bin/sh -c. Executors are authenticated by the
// mesh session (smux chain) — anyone who can dial the port is a mesh
// peer; write-protection is the ACL/step-up layer in the Dashboard.
// ──────────────────────────────────────────────────────────────────────────

// CommandRequest is a remote command execution request.
type CommandRequest struct {
	Cmd     string `json:"cmd"`
	Timeout int    `json:"timeout"` // seconds, 0 = 30s
}

// CommandResponse is the result of a remote command.
type CommandResponse struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	Exit   int    `json:"exit"`
}

// CommandServer executes commands received on the command virtual port.
type CommandServer struct {
	listener net.Listener
	done     chan struct{}
	// MaxOutput caps captured stdout/stderr bytes (0 = 1MB).
	MaxOutput int64
}

// RegisterCommandServer registers the remote command executor.
func (n *MeshNode) RegisterCommandServer() (*CommandServer, error) {
	ln, err := n.ListenVirtualPort(CommandVirtualPort)
	if err != nil {
		return nil, fmt.Errorf("commandserver: register port 0x%x: %w", CommandVirtualPort, err)
	}
	cs := &CommandServer{
		listener: ln,
		done:     make(chan struct{}),
	}
	go cs.serve()
	log.Printf("[commandserver] listening on virtual port 0x%x", CommandVirtualPort)
	return cs, nil
}

// Close stops the command server.
func (cs *CommandServer) Close() error {
	select {
	case <-cs.done:
		return nil
	default:
		close(cs.done)
	}
	return cs.listener.Close()
}

func (cs *CommandServer) serve() {
	for {
		conn, err := cs.listener.Accept()
		if err != nil {
			select {
			case <-cs.done:
				return
			default:
			}
			continue
		}
		go cs.handle(conn)
	}
}

func (cs *CommandServer) handle(conn net.Conn) {
	defer conn.Close()

	var req CommandRequest
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		json.NewEncoder(conn).Encode(CommandResponse{OK: false, Error: "bad request: " + err.Error()})
		return
	}
	if req.Cmd == "" {
		json.NewEncoder(conn).Encode(CommandResponse{OK: false, Error: "empty command"})
		return
	}
	timeout := time.Duration(req.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", req.Cmd)
	// Kill the whole process group so child processes (e.g. `sleep`
	// forked by sh) die with the shell — otherwise the stdout pipe
	// stays open and cmd.Wait blocks until the child finishes.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Replace CommandContext's single-process kill with a group kill.
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			json.NewEncoder(conn).Encode(CommandResponse{OK: false, Error: err.Error()})
			return
		}
	}

	json.NewEncoder(conn).Encode(CommandResponse{
		OK:     true,
		Stdout: truncateOutput(stdout.String(), cs.MaxOutput),
		Stderr: truncateOutput(stderr.String(), cs.MaxOutput),
		Exit:   exit,
	})
}

func truncateOutput(s string, max int64) string {
	if max <= 0 {
		max = 1 << 20 // 1MB default
	}
	if int64(len(s)) > max {
		return s[:max] + "\n...[truncated]"
	}
	return s
}
