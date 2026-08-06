package mesh

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestMuxDemux_HTTPRequestParsedByServer verifies that a real HTTP request
// entering via the shared demux port is fully parseable by an http.Server
// served on HTTPListener(). It is the independent HTTP counterpart to the
// byte-level routing tests (TestMuxDemux_AllByteValues etc.): it exercises
// the complete chain
//
//	TCP dial → handleMuxConn 1-byte peek → bufferedConn(MultiReader(peek, conn))
//	→ httpCh → muxHTTPListener.Accept → http.Server.Serve
//
// and requires the server to parse the request line, headers, and body —
// not merely to deliver N bytes with the correct first byte.
//
// The critical condition: the full request is written in a SINGLE Write.
// If the peek implementation ever regresses to bufio.Peek(1) (which
// pre-reads up to its buffer size beyond the first byte) while the replay
// only restores the peeked byte, the pre-read remainder would be lost and
// the HTTP server could not parse the truncated request. A slow
// byte-by-byte client would not catch this — only a client that sends the
// whole request at once makes the pre-read observable.
func TestMuxDemux_HTTPRequestParsedByServer(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	httpLn := mt.HTTPListener()

	// Echo method/path/body so a successful parse is proven end-to-end.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "method=%s path=%s body=%s", r.Method, r.URL.Path, string(body))
	})

	srv := &http.Server{
		Handler:     handler,
		ReadTimeout: 10 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(httpLn)
	}()

	t.Cleanup(func() {
		// srv.Close() closes the muxHTTPListener (it is a tracked
		// listener of the server) and flips the shutdown flag, so the
		// blocked Accept returns and Serve exits with ErrServerClosed.
		srv.Close()
		select {
		case err := <-serveErr:
			if err != nil && err != http.ErrServerClosed {
				t.Errorf("http server serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("http server did not stop")
		}
	})

	tests := []struct {
		name    string
		request string // complete HTTP request, sent in ONE write
		want    string // body echoed by the handler ("" for HEAD)
	}{
		{
			name:    "GET /",
			request: "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
			want:    "method=GET path=/ body=",
		},
		{
			name:    "GET with query and extra headers",
			request: "GET /dashboard?src=1 HTTP/1.1\r\nHost: localhost\r\nUser-Agent: mux-test\r\nAccept: */*\r\nConnection: close\r\n\r\n",
			want:    "method=GET path=/dashboard body=",
		},
		{
			name:    "POST with body",
			request: "POST /api/join HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world",
			want:    "method=POST path=/api/join body=hello world",
		},
		{
			name:    "HEAD",
			request: "HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			// Single write — the discriminating condition for the
			// pre-read-beyond-peek regression (see doc comment).
			if _, err := conn.Write([]byte(tt.request)); err != nil {
				t.Fatalf("write request: %v", err)
			}

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected 200, got %d (body=%q)", resp.StatusCode, string(body))
			}
			if tt.want == "" {
				return // HEAD: no response body expected
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}
			if string(body) != tt.want {
				t.Fatalf("handler saw %q, want %q", string(body), tt.want)
			}
		})
	}
}

// TestMuxDemux_HTTPRequestSlowArrival verifies the HTTP demux path when the
// request arrives progressively: the first byte ('G') alone, then the
// remainder after a delay. The 1-byte peek must not wait for the full
// request, and the replay must deliver the remaining bytes as they arrive
// from the socket.
func TestMuxDemux_HTTPRequestSlowArrival(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	httpLn := mt.HTTPListener()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "method=%s path=%s", r.Method, r.URL.Path)
	})
	srv := &http.Server{Handler: handler}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(httpLn)
	}()
	t.Cleanup(func() {
		srv.Close()
		select {
		case err := <-serveErr:
			if err != nil && err != http.ErrServerClosed {
				t.Errorf("http server serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("http server did not stop")
		}
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// First byte only — must be enough to route the connection to httpCh.
	if _, err := conn.Write([]byte{'G'}); err != nil {
		t.Fatalf("write first byte: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Rest of the request.
	rest := "ET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(rest)); err != nil {
		t.Fatalf("write rest of request: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d (body=%q)", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "method=GET path=/slow" {
		t.Fatalf("handler saw %q, want %q", string(body), "method=GET path=/slow")
	}
}
