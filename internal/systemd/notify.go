// Package systemd provides a lightweight sd_notify client for MeshDesk.
//
// This package communicates with systemd via the NOTIFY_SOCKET environment
// variable, sending readiness notifications ("READY=1"), watchdog pings
// ("WATCHDOG=1"), and status updates ("STATUS=...") as specified by the
// systemd notification protocol (sd_notify(3)).
//
// When NOTIFY_SOCKET is not set (e.g., running outside systemd), all
// operations are no-ops — the Notifier is inert. This makes the package
// safe to use unconditionally: in production under systemd it reports
// health; in development or standalone mode it silently does nothing.
package systemd

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Notifier sends sd_notify messages to systemd via NOTIFY_SOCKET.
// A zero-value Notifier is inert (all methods are no-ops).
type Notifier struct {
	mu      sync.Mutex
	socket  string
	conn    net.Conn
	enabled bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewNotifier creates a Notifier from the NOTIFY_SOCKET environment variable.
// If NOTIFY_SOCKET is unset or empty, the returned Notifier is inert.
func NewNotifier() *Notifier {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return &Notifier{}
	}
	return &Notifier{
		socket:  socket,
		enabled: true,
		stopCh:  make(chan struct{}),
	}
}

// Enabled reports whether systemd notification is active (NOTIFY_SOCKET was set).
func (n *Notifier) Enabled() bool {
	return n.enabled
}

// Notify sends a raw sd_notify message. Multiple state assignments can be
// combined in a single message (newline-separated). This is the low-level
// primitive; prefer Ready(), Watchdog(), Status(), and Stopping() for
// specific use cases.
func (n *Notifier) Notify(state string) error {
	if !n.enabled {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()

	// (Re)connect if needed. NOTIFY_SOCKET may be an abstract Unix socket
	// (Linux: @/...) or a filesystem path.
	if n.conn == nil {
		var err error
		if len(n.socket) > 0 && n.socket[0] == '@' {
			// Abstract Unix socket: replace leading '@' with null byte.
			addr := &net.UnixAddr{Name: "\x00" + n.socket[1:], Net: "unixgram"}
			n.conn, err = net.DialUnix("unixgram", nil, addr)
		} else {
			addr := &net.UnixAddr{Name: n.socket, Net: "unixgram"}
			n.conn, err = net.DialUnix("unixgram", nil, addr)
		}
		if err != nil {
			return fmt.Errorf("systemd: connect NOTIFY_SOCKET: %w", err)
		}
	}

	_, err := n.conn.Write([]byte(state))
	if err != nil {
		// The systemd daemon may have restarted (NOTIFY_SOCKET peer
		// gone) — drop the dead conn so the next Notify reconnects.
		n.conn.Close()
		n.conn = nil
	}
	return err
}

// Ready sends "READY=1" to signal that the service has finished starting up.
// Must be called once after all initialization is complete.
func (n *Notifier) Ready() error {
	return n.Notify("READY=1")
}

// Watchdog sends "WATCHDOG=1" to reset the systemd watchdog timer.
// Call StartWatchdog to have this done automatically on a timer.
func (n *Notifier) Watchdog() error {
	return n.Notify("WATCHDOG=1")
}

// Status sends a human-readable status string that systemd displays in
// `systemctl status` output.
func (n *Notifier) Status(msg string) error {
	return n.Notify("STATUS=" + msg)
}

// Stopping sends "STOPPING=1" to inform systemd that the service is
// beginning an orderly shutdown. Call this at the start of the shutdown
// sequence.
func (n *Notifier) Stopping() error {
	return n.Notify("STOPPING=1")
}

// StartWatchdog begins a background goroutine that sends WATCHDOG=1 pings
// at half the configured WatchdogSec interval. The interval is derived
// from the WATCHDOG_USEC environment variable (set by systemd).
// If WATCHDOG_USEC is unset or zero, a default of 15s is used.
func (n *Notifier) StartWatchdog() {
	if !n.enabled {
		return
	}

	interval := 15 * time.Second
	if usec := os.Getenv("WATCHDOG_USEC"); usec != "" {
		var us uint64
		if _, err := fmt.Sscanf(usec, "%d", &us); err == nil && us > 0 {
			interval = time.Duration(us) * time.Microsecond / 2
			if interval < 2*time.Second {
				interval = 2 * time.Second
			}
		}
	}

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = n.Watchdog()
			case <-n.stopCh:
				return
			}
		}
	}()
}

// Close stops the watchdog goroutine and closes the socket connection.
// Safe to call multiple times.
func (n *Notifier) Close() {
	if !n.enabled {
		return
	}
	select {
	case <-n.stopCh:
		// already closed
	default:
		close(n.stopCh)
	}
	n.wg.Wait()

	n.mu.Lock()
	if n.conn != nil {
		n.conn.Close()
		n.conn = nil
	}
	n.mu.Unlock()
}
