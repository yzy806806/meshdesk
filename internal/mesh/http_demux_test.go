package mesh

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestMuxDemux_HTTPBytesRoutedToReality verifies the reality-discipline
// invariant: HTTP request bytes (GET/POST/HEAD — first byte 'G'/'P'/'H')
// arriving on the shared mesh port are NOT intercepted for a Dashboard
// (the Dashboard no longer rides the mesh port). They are routed to the
// Reality listener like any other non-authenticated traffic, so the
// REALITY handshake fails auth and forwards the connection to the
// camouflage destination — an active DPI probe sending GET / sees the
// real website, not a mesh fingerprint.
//
// The test proves two properties:
//
//  1. Routing: a connection whose first byte is an HTTP method byte is
//     delivered to RealityListener().Accept().
//  2. Byte integrity: the delivered stream replays the peeked first byte
//     plus all subsequent bytes, in order. A single bulk write is the
//     discriminating condition for the pre-read-beyond-peek regression:
//     if the peek implementation ever pre-reads beyond the first byte
//     while the replay restores only the peeked byte, the tail is lost.
func TestMuxDemux_HTTPBytesRoutedToReality(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	realityLn := mt.RealityListener()
	defer realityLn.Close()

	type accepted struct {
		conn net.Conn
	}
	realityCh := make(chan accepted, 8)
	go func() {
		for {
			conn, err := realityLn.Accept()
			if err != nil {
				close(realityCh)
				return
			}
			realityCh <- accepted{conn: conn}
		}
	}()

	requests := []struct {
		name string
		body string
	}{
		{"GET", "GET / HTTP/1.1\r\nHost: probe\r\n\r\n"},
		{"POST", "POST /api/join HTTP/1.1\r\nHost: probe\r\n\r\n"},
		{"HEAD", "HEAD /healthz HTTP/1.1\r\nHost: probe\r\n\r\n"},
	}

	for _, tt := range requests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			// Single bulk write — see doc comment.
			if _, err := conn.Write([]byte(tt.body)); err != nil {
				t.Fatalf("write request: %v", err)
			}

			var acc accepted
			var ok bool
			select {
			case acc, ok = <-realityCh:
				if !ok {
					t.Fatal("reality listener closed before accept")
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("HTTP request (first byte %q) was not routed to the Reality listener", tt.body[0])
			}
			defer acc.conn.Close()

			// Byte integrity: the Reality side must see the FULL request
			// including the replayed first byte.
			acc.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got := make([]byte, len(tt.body))
			if _, err := io.ReadFull(acc.conn, got); err != nil {
				t.Fatalf("read replayed request: %v", err)
			}
			if string(got) != tt.body {
				t.Fatalf("reality side saw %q, want %q", string(got), tt.body)
			}
		})
	}
}

// TestMuxDemux_HTTPSlowArrivalRoutedToReality verifies the same routing
// when the request arrives progressively: the first byte ('G') alone,
// then the remainder after a delay. The 1-byte peek must route on the
// first byte alone, and the replay must deliver the remaining bytes as
// they arrive from the socket.
func TestMuxDemux_HTTPSlowArrivalRoutedToReality(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	realityLn := mt.RealityListener()
	defer realityLn.Close()

	realityCh := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := realityLn.Accept()
			if err != nil {
				close(realityCh)
				return
			}
			realityCh <- conn
		}
	}()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// First byte only — must be enough to route the connection.
	if _, err := conn.Write([]byte{'G'}); err != nil {
		t.Fatalf("write first byte: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	var rconn net.Conn
	var ok bool
	select {
	case rconn, ok = <-realityCh:
		if !ok {
			t.Fatal("reality listener closed before accept")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first byte 'G' alone did not route to the Reality listener")
	}
	defer rconn.Close()

	// Rest of the request.
	rest := "ET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n"
	if _, err := conn.Write([]byte(rest)); err != nil {
		t.Fatalf("write rest of request: %v", err)
	}

	want := "G" + rest
	rconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(rconn, got); err != nil {
		t.Fatalf("read replayed request: %v", err)
	}
	if string(got) != want {
		t.Fatalf("reality side saw %q, want %q", string(got), want)
	}
}
