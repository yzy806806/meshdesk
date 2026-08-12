package webssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// ptyRequestMsg matches the SSH pty-req wire format (RFC 4254 Section 6.2).
type ptyRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

// windowChangeMsg matches the SSH window-change wire format (RFC 4254 Section 6.7).
type windowChangeMsg struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

// envRequestMsg matches the SSH env wire format (RFC 4254 Section 6.4).
type envRequestMsg struct {
	Name  string
	Value string
}

// SSHServer runs on the target node. It accepts SSH connections from the
// web server node over the mesh VPN, allocates a PTY, runs a shell, and
// handles SIGWINCH (terminal resize) propagation.
//
// All connections are mesh-internal — the server binds to the mesh IP
// (via the provided net.Listener) and does not expose itself to the
// public network.
type SSHServer struct {
	hostSigner ssh.Signer
	shell      string
	config     *ssh.ServerConfig
	listener   net.Listener

	mu       sync.Mutex
	sessions map[string]*ptySession
	closed   bool
}

// ptySession represents a single active PTY session on the target node.
type ptySession struct {
	ptyFile   *os.File
	cmd       *exec.Cmd
	sshConn   ssh.Conn
	closeOnce sync.Once
}

// NewSSHServer creates an SSH server. If hostKeyPEM is empty, an Ed25519 key
// is auto-generated. If shell is empty, it is auto-detected.
func NewSSHServer(hostKeyPEM, shell string) (*SSHServer, error) {
	var signer ssh.Signer
	var err error

	if hostKeyPEM != "" {
		signer, err = ssh.ParsePrivateKey([]byte(hostKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("parse host key: %w", err)
		}
	} else {
		signer, err = generateHostSigner()
		if err != nil {
			return nil, fmt.Errorf("generate host key: %w", err)
		}
	}

	if shell == "" {
		shell = detectShell()
	}

	srv := &SSHServer{
		hostSigner: signer,
		shell:      shell,
		sessions:   make(map[string]*ptySession),
	}

	srv.config = &ssh.ServerConfig{
		NoClientAuth: true, // auth is handled by mesh + capability layer
	}
	srv.config.AddHostKey(signer)

	return srv, nil
}

// HasNoClientAuth reports whether the SSH server is configured with
// NoClientAuth=true. This is the expected configuration for mesh-internal
// SSH servers — authentication is enforced at the mesh+capability layer
// (RequireCapability middleware at the WebSocket endpoint), not at the
// SSH protocol level. The SSH server only accepts connections that have
// already passed the capability check.
func (s *SSHServer) HasNoClientAuth() bool {
	return s.config.NoClientAuth
}

// Shell returns the configured shell path.
func (s *SSHServer) Shell() string { return s.shell }

// HostSignerPublicKey returns the SSH public key string for display/fingerprinting.
func (s *SSHServer) HostSignerPublicKey() string {
	return string(s.hostSigner.PublicKey().Marshal())
}

// Serve accepts SSH connections on the given listener until the context
// is cancelled or the server is closed.
func (s *SSHServer) Serve(ctx context.Context, listener net.Listener) error {
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("ssh server accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// Close shuts down the SSH server and all active sessions.
func (s *SSHServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true

	if s.listener != nil {
		s.listener.Close()
	}

	sessions := make([]*ptySession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()

	for _, sess := range sessions {
		sess.close()
	}
	return nil
}

// SessionCount returns the number of active PTY sessions.
func (s *SSHServer) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// handleConn processes a single SSH connection.
func (s *SSHServer) handleConn(conn net.Conn) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "only session channels supported")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go s.handleSession(sshConn, channel, requests)
	}
}

// handleSession processes a single SSH session channel.
// It handles pty-req, shell/exec, window-change (SIGWINCH), and environment requests.
func (s *SSHServer) handleSession(sshConn ssh.Conn, channel ssh.Channel, requests <-chan *ssh.Request) {
	var ptyFile *os.File
	var ptyFD int
	var cmd *exec.Cmd
	var closeOnce sync.Once
	var shellStarted bool

	cleanup := func() {
		closeOnce.Do(func() {
			if ptyFile != nil {
				ptyFile.Close()
			}
			if cmd != nil && cmd.Process != nil {
				cmd.Process.Kill()
			}
			channel.Close()
		})
	}
	defer cleanup()

	env := []string{
		"TERM=xterm-256color",
	}

	for req := range requests {
		switch req.Type {
		case "pty-req":
			if ptyFile != nil {
				req.Reply(false, nil)
				continue
			}

			var msg ptyRequestMsg
			if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
				req.Reply(false, nil)
				continue
			}

			c, err := s.startPty(int(msg.Columns), int(msg.Rows), env)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			ptyFile = c.ptyFile
			// Capture the raw FD once while no goroutines are touching
			// ptyFile. Using the FD directly in window-change below
			// avoids the data race between pty.Setsize (which calls
			// os.File.Fd()) and the io.Copy goroutines that read/write
			// the same *os.File.
			ptyFD = int(ptyFile.Fd())
			cmd = c.cmd
			req.Reply(true, nil)

		case "shell":
			if ptyFile == nil || cmd == nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)

			shellStarted = true

			// Bridge: channel ↔ PTY in goroutines
			done := make(chan struct{}, 2)
			go func() {
				io.Copy(channel, ptyFile)
				done <- struct{}{}
			}()
			go func() {
				io.Copy(ptyFile, channel)
				done <- struct{}{}
			}()

			<-done
			cleanup()

		case "exec":
			req.Reply(false, nil) // not supported in v1

		case "window-change":
			if ptyFile != nil {
				var wc windowChangeMsg
				if err := ssh.Unmarshal(req.Payload, &wc); err == nil {
					setPtySize(ptyFD, int(wc.Rows), int(wc.Columns))
				}
			}
			req.Reply(true, nil)

		case "env":
			var envReq envRequestMsg
			if err := ssh.Unmarshal(req.Payload, &envReq); err == nil {
				env = append(env, fmt.Sprintf("%s=%s", envReq.Name, envReq.Value))
			}
			req.Reply(true, nil)

		default:
			req.Reply(false, nil)
		}
	}

	// If the shell was started, wait for it to exit
	if shellStarted && cmd != nil {
		cmd.Wait()
	}
}

// ptyHandle bundles a started PTY+command.
type ptyHandle struct {
	ptyFile *os.File
	cmd     *exec.Cmd
}

// startPty creates a PTY and starts the shell process attached to it.
func (s *SSHServer) startPty(cols, rows int, env []string) (*ptyHandle, error) {
	cmd := exec.Command(s.shell)
	cmd.Env = append(os.Environ(), env...)

	ws := &pty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	}

	ptyFile, err := pty.StartWithSize(cmd, ws)
	if err != nil {
		return nil, fmt.Errorf("start pty: %w", err)
	}

	return &ptyHandle{ptyFile: ptyFile, cmd: cmd}, nil
}

// detectShell finds an appropriate shell. Priority: /etc/passwd entry for
// current user → $SHELL → /bin/bash → /bin/sh.
func detectShell() string {
	if u, err := user.Current(); err == nil {
		if passwd, err := os.ReadFile("/etc/passwd"); err == nil {
			for _, line := range strings.Split(string(passwd), "\n") {
				fields := strings.Split(line, ":")
				if len(fields) >= 7 && fields[0] == u.Username {
					shell := fields[6]
					if shell != "" {
						return shell
					}
				}
			}
		}
	}

	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}

	for _, candidate := range []string{"/bin/bash", "/bin/sh"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return candidate
		}
	}

	return "/bin/sh"
}

// generateHostSigner generates an Ed25519 key pair and returns an SSH signer.
func generateHostSigner() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create ssh signer: %w", err)
	}

	return signer, nil
}

// GenerateHostKeyPEM generates an Ed25519 key pair and returns the
// private key in PEM format (for storage in config).
func GenerateHostKeyPEM() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ed25519 key: %w", err)
	}

	keyPEM, err := pemEncode(priv)
	if err != nil {
		return "", err
	}

	return string(keyPEM), nil
}

// pemEncode converts an Ed25519 private key to OpenSSH PEM format.
func pemEncode(priv ed25519.PrivateKey) ([]byte, error) {
	key, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(key), nil
}

// close wraps ptySession cleanup for the SSHServer's use.
func (s *ptySession) close() {
	s.closeOnce.Do(func() {
		if s.ptyFile != nil {
			s.ptyFile.Close()
		}
		if s.cmd != nil && s.cmd.Process != nil {
			s.cmd.Process.Kill()
		}
		if s.sshConn != nil {
			s.sshConn.Close()
		}
	})
}

// setPtySize issues a TIOCSWINSZ ioctl on the given FD to set the
// PTY window size. It uses the raw FD directly instead of
// pty.Setsize(*os.File) to avoid the data race between
// os.File.Fd() (called by pty.Setsize) and concurrent io.Copy
// goroutines that read/write the same *os.File.
func setPtySize(fd, rows, cols int) {
	var ws struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	}
	ws.Row = uint16(rows)
	ws.Col = uint16(cols)
	const TIOCSWINSZ = 0x5414 // syscall.TIOCSWINSZ on Linux
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(TIOCSWINSZ),
		uintptr(unsafe.Pointer(&ws)),
	)
	// PTY resize failures are non-fatal; ignore errno to avoid
	// an "error value computed but not used" vet warning.
	_ = errno
}
