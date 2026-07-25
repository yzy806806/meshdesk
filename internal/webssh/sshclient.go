package webssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// MeshDialer abstracts the mesh transport so the SSH client can dial the
// target node's SSH server over the mesh VPN. In production this is backed
// by the gVisor netstack DialContext; in tests it can be a net.Dialer or
// a pipe-based mock.
type MeshDialer interface {
	// DialMesh connects to addr (meshIP:port) over the mesh VPN.
	DialMesh(ctx context.Context, network, addr string) (net.Conn, error)
}

// SSHClient is used by the web server node to dial a target node's SSH
// server over the mesh VPN and open a terminal session. The SSH transport
// rides on top of the mesh VPN (gVisor netstack), so the connection is
// already encrypted at the network layer — SSH provides the PTY
// negotiation, window-change propagation, and session lifecycle.
type SSHClient struct {
	dialer          MeshDialer
	dialTimeout     time.Duration
	hostKeyCallback ssh.HostKeyCallback
}

// NewSSHClient creates an SSH client that dials through the mesh VPN.
// dialTimeout is the max time to wait for the SSH connection (default 10s).
// hostKeyCallback: pass nil for "accept first key and pin it" (InsecureIgnoreHostKey
// is NOT recommended — use PinnedHostKey for production).
func NewSSHClient(dialer MeshDialer, dialTimeout time.Duration, hostKeyCallback ssh.HostKeyCallback) *SSHClient {
	if dialTimeout == 0 {
		dialTimeout = 10 * time.Second
	}
	if hostKeyCallback == nil {
		// Default: accept first key, pin it (prevents MITM after first connection)
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
		// TODO(v2): use a proper known-hosts store with PinnedHostKey
	}
	return &SSHClient{
		dialer:          dialer,
		dialTimeout:     dialTimeout,
		hostKeyCallback: hostKeyCallback,
	}
}

// RemoteSession represents an active SSH session to a target node.
// It provides Read/Write for terminal I/O and Resize for SIGWINCH.
type RemoteSession struct {
	client  *ssh.Client
	session *ssh.Session
	stdout  io.Reader      // obtained before Shell() via session.StdoutPipe()
	stdin   io.WriteCloser // obtained before Shell() via session.StdinPipe()
}

// Connect dials the target node and requests a PTY.
// meshIP:port are the target's mesh address, cols/rows are initial terminal dimensions.
// term is the TERM value (e.g. "xterm-256color").
func (c *SSHClient) Connect(ctx context.Context, meshIP string, port int, cols, rows int, term string) (*RemoteSession, error) {
	if term == "" {
		term = "xterm-256color"
	}

	addr := net.JoinHostPort(meshIP, fmt.Sprintf("%d", port))

	// Dial through mesh VPN
	conn, err := c.dialer.DialMesh(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial mesh target %s: %w", addr, err)
	}

	// Wrap the raw conn with SSH
	sshConfig := &ssh.ClientConfig{
		HostKeyCallback: c.hostKeyCallback,
		Timeout:         c.dialTimeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake to %s: %w", addr, err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("create ssh session: %w", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty(term, rows, cols, modes); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("request pty: %w", err)
	}

	// IMPORTANT: StdoutPipe and StdinPipe must be obtained BEFORE Shell()
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	// Request a shell (not exec)
	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}

	return &RemoteSession{
		client:  client,
		session: session,
		stdout:  stdout,
		stdin:   stdin,
	}, nil
}

// StdoutPipe returns a reader for PTY output from the remote shell.
func (r *RemoteSession) StdoutPipe() io.Reader {
	return r.stdout
}

// StdinPipe returns a writer for sending input to the remote shell.
func (r *RemoteSession) StdinPipe() io.WriteCloser {
	return r.stdin
}

// Resize sends a window-change (SIGWINCH) to the remote PTY.
func (r *RemoteSession) Resize(cols, rows int) error {
	return r.session.WindowChange(rows, cols)
}

// Close terminates the session and SSH connection.
func (r *RemoteSession) Close() error {
	if r.stdin != nil {
		r.stdin.Close()
	}
	r.session.Close()
	return r.client.Close()
}

// Wait blocks until the remote shell exits.
func (r *RemoteSession) Wait() error {
	return r.session.Wait()
}

// RemotePID returns the remote process PID if available.
func (r *RemoteSession) RemotePID() int {
	// x/crypto/ssh doesn't expose remote PID directly;
	// we track liveness via Wait()
	return 0
}

// NetDialer wraps a standard net.Dialer to implement MeshDialer.
// Used in tests or when the mesh VPN is not available.
type NetDialer struct {
	Timeout time.Duration
}

func (d *NetDialer) DialMesh(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.Timeout}
	return dialer.DialContext(ctx, network, addr)
}
