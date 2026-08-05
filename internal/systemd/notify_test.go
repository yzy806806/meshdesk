package systemd

import (
	"net"
	"os"
	"testing"
	"time"
)

// TestNotifier_InertWhenNoSocket verifies that a Notifier created without
// NOTIFY_SOCKET set is inert — all methods are no-ops and Enabled() returns false.
func TestNotifier_InertWhenNoSocket(t *testing.T) {
	// Ensure NOTIFY_SOCKET is unset for this test.
	os.Unsetenv("NOTIFY_SOCKET")

	n := NewNotifier()
	if n.Enabled() {
		t.Fatal("Notifier should be disabled when NOTIFY_SOCKET is unset")
	}

	// All methods should be no-ops (no error, no panic).
	if err := n.Ready(); err != nil {
		t.Errorf("Ready() returned error on inert notifier: %v", err)
	}
	if err := n.Watchdog(); err != nil {
		t.Errorf("Watchdog() returned error on inert notifier: %v", err)
	}
	if err := n.Status("test"); err != nil {
		t.Errorf("Status() returned error on inert notifier: %v", err)
	}
	if err := n.Stopping(); err != nil {
		t.Errorf("Stopping() returned error on inert notifier: %v", err)
	}
	n.StartWatchdog() // should be no-op
	n.Close()         // should be no-op
}

// TestNotifier_ReadyMessage verifies that READY=1 is delivered to a real
// Unix datagram socket when NOTIFY_SOCKET is set.
func TestNotifier_ReadyMessage(t *testing.T) {
	// Create a Unix datagram socket to receive notifications.
	// Use an abstract namespace socket to avoid filesystem cleanup.
	addr := &net.UnixAddr{Name: "@meshdesk-test-notify-" + t.Name(), Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("failed to listen on unixgram: %v", err)
	}
	defer listener.Close()

	// Set NOTIFY_SOCKET to the abstract socket name (with leading @).
	os.Setenv("NOTIFY_SOCKET", addr.Name)
	defer os.Unsetenv("NOTIFY_SOCKET")

	n := NewNotifier()
	defer n.Close()
	if !n.Enabled() {
		t.Fatal("Notifier should be enabled when NOTIFY_SOCKET is set")
	}

	// Set a read deadline so we don't block forever.
	listener.SetReadDeadline(time.Now().Add(2 * time.Second))

	if err := n.Ready(); err != nil {
		t.Fatalf("Ready() returned error: %v", err)
	}

	buf := make([]byte, 256)
	nr, err := listener.Read(buf)
	if err != nil {
		t.Fatalf("failed to read notification: %v", err)
	}
	msg := string(buf[:nr])
	if msg != "READY=1" {
		t.Errorf("expected 'READY=1', got %q", msg)
	}
}

// TestNotifier_StatusMessage verifies that STATUS= messages are delivered.
func TestNotifier_StatusMessage(t *testing.T) {
	addr := &net.UnixAddr{Name: "@meshdesk-test-status-" + t.Name(), Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("failed to listen on unixgram: %v", err)
	}
	defer listener.Close()

	os.Setenv("NOTIFY_SOCKET", addr.Name)
	defer os.Unsetenv("NOTIFY_SOCKET")

	n := NewNotifier()
	defer n.Close()

	listener.SetReadDeadline(time.Now().Add(2 * time.Second))

	if err := n.Status("3 peers connected"); err != nil {
		t.Fatalf("Status() returned error: %v", err)
	}

	buf := make([]byte, 256)
	nr, _ := listener.Read(buf)
	msg := string(buf[:nr])
	if msg != "STATUS=3 peers connected" {
		t.Errorf("expected 'STATUS=3 peers connected', got %q", msg)
	}
}

// TestNotifier_StoppingMessage verifies that STOPPING=1 is delivered.
func TestNotifier_StoppingMessage(t *testing.T) {
	addr := &net.UnixAddr{Name: "@meshdesk-test-stopping-" + t.Name(), Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("failed to listen on unixgram: %v", err)
	}
	defer listener.Close()

	os.Setenv("NOTIFY_SOCKET", addr.Name)
	defer os.Unsetenv("NOTIFY_SOCKET")

	n := NewNotifier()
	defer n.Close()

	listener.SetReadDeadline(time.Now().Add(2 * time.Second))

	if err := n.Stopping(); err != nil {
		t.Fatalf("Stopping() returned error: %v", err)
	}

	buf := make([]byte, 256)
	nr, _ := listener.Read(buf)
	msg := string(buf[:nr])
	if msg != "STOPPING=1" {
		t.Errorf("expected 'STOPPING=1', got %q", msg)
	}
}

// TestNotifier_WatchdogPings verifies that StartWatchdog periodically sends
// WATCHDOG=1 messages.
func TestNotifier_WatchdogPings(t *testing.T) {
	addr := &net.UnixAddr{Name: "@meshdesk-test-wd-" + t.Name(), Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("failed to listen on unixgram: %v", err)
	}
	defer listener.Close()

	os.Setenv("NOTIFY_SOCKET", addr.Name)
	defer os.Unsetenv("NOTIFY_SOCKET")

	// Set a very short watchdog interval.
	os.Setenv("WATCHDOG_USEC", "4000000") // 4s → ping every 2s
	defer os.Unsetenv("WATCHDOG_USEC")

	n := NewNotifier()
	defer n.Close()

	n.StartWatchdog()

	// Wait for the first watchdog ping.
	listener.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	nr, _ := listener.Read(buf)
	msg := string(buf[:nr])
	if msg != "WATCHDOG=1" {
		t.Errorf("expected 'WATCHDOG=1', got %q", msg)
	}
}

// TestNotifier_CombinedState verifies that multiple state assignments can be
// sent in a single Notify call (newline-separated).
func TestNotifier_CombinedState(t *testing.T) {
	addr := &net.UnixAddr{Name: "@meshdesk-test-combined-" + t.Name(), Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("failed to listen on unixgram: %v", err)
	}
	defer listener.Close()

	os.Setenv("NOTIFY_SOCKET", addr.Name)
	defer os.Unsetenv("NOTIFY_SOCKET")

	n := NewNotifier()
	defer n.Close()

	listener.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Send READY=1 and STATUS= in one message.
	if err := n.Notify("READY=1\nSTATUS=started"); err != nil {
		t.Fatalf("Notify() returned error: %v", err)
	}

	buf := make([]byte, 256)
	nr, _ := listener.Read(buf)
	msg := string(buf[:nr])
	if msg != "READY=1\nSTATUS=started" {
		t.Errorf("expected combined message, got %q", msg)
	}
}
