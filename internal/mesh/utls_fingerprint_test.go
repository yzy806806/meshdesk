package mesh

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// --- utls fingerprint verification tests ---

// rawClientHelloServer listens on a TCP port and captures the raw ClientHello
// bytes sent by the client. It does NOT complete the TLS handshake — it just
// reads the first record (which is always the ClientHello) and closes.
type rawClientHelloServer struct {
	listener net.Listener
	ch       chan []byte
}

func newRawClientHelloServer() (*rawClientHelloServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &rawClientHelloServer{
		listener: ln,
		ch:       make(chan []byte, 1),
	}
	go s.acceptLoop()
	return s, nil
}

func (s *rawClientHelloServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			// Read the TLS record header: 5 bytes (1 type + 2 version + 2 length)
			header := make([]byte, 5)
			if _, err := io.ReadFull(c, header); err != nil {
				s.ch <- nil
				return
			}
			// header[0] = content type (0x16 = handshake)
			// header[1:3] = TLS version
			// header[3:5] = record length
			recordLen := int(binary.BigEndian.Uint16(header[3:5]))
			if recordLen > 16384 {
				recordLen = 16384 // cap at max TLS record
			}
			record := make([]byte, recordLen)
			if _, err := io.ReadFull(c, record); err != nil {
				s.ch <- nil
				return
			}
			// The full ClientHello is header + record.
			// record[0] = handshake type (0x01 = ClientHello)
			s.ch <- append(header, record...)
		}(conn)
	}
}

func (s *rawClientHelloServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *rawClientHelloServer) WaitClientHello(timeout time.Duration) []byte {
	select {
	case data := <-s.ch:
		return data
	case <-time.After(timeout):
		return nil
	}
}

func (s *rawClientHelloServer) Close() {
	s.listener.Close()
}

// TestDialUTLSProducesBrowserFingerprint verifies that dialUTLS sends a
// ClientHello that is NOT the Go standard library fingerprint. We do this
// by capturing the raw ClientHello bytes and checking:
// 1. It's a valid TLS handshake record (content type 0x16, handshake type 0x01).
// 2. The SNI extension contains our configured domain.
// 3. The ClientHello is large enough to contain browser extensions (Go's
//    default ClientHello is ~200 bytes; Chrome's is ~500+).
func TestDialUTLSProducesBrowserFingerprint(t *testing.T) {
	server, err := newRawClientHelloServer()
	if err != nil {
		t.Fatalf("newRawClientHelloServer: %v", err)
	}
	defer server.Close()

	sni := "test.example.com"
	fingerprint := "chrome"

	// dialUTLS will attempt a handshake, but the server doesn't complete it.
	// The dial will fail with a handshake error — that's expected. We only
	// care about the ClientHello bytes the server captured.
	go func() {
		_, _ = dialUTLS(server.Addr(), sni, fingerprint, true)
	}()

	helloBytes := server.WaitClientHello(5 * time.Second)
	if helloBytes == nil {
		t.Fatal("timed out waiting for ClientHello from dialUTLS")
	}

	// Verify it's a TLS handshake record.
	if helloBytes[0] != 0x16 {
		t.Errorf("expected TLS content type 0x16 (handshake), got 0x%02x", helloBytes[0])
	}

	// Verify handshake type is ClientHello (0x01).
	// helloBytes[5] is the handshake type byte (first byte of the record body).
	if helloBytes[5] != 0x01 {
		t.Errorf("expected handshake type 0x01 (ClientHello), got 0x%02x", helloBytes[5])
	}

	// The record body length should be substantial — Chrome ClientHello
	// is typically 500+ bytes. Go's standard ClientHello is ~200 bytes.
	// A browser-mimicked ClientHello from utls should be significantly larger.
	recordLen := int(binary.BigEndian.Uint16(helloBytes[3:5]))
	if recordLen < 400 {
		t.Errorf("ClientHello record length %d is too small for a browser fingerprint (expected >= 400)", recordLen)
	}

	// Check that the SNI is present in the ClientHello.
	// We search for the SNI hostname as a raw string in the ClientHello bytes.
	// The SNI extension encodes the hostname as a length-prefixed string.
	sniFound := bytes.Contains(helloBytes, []byte(sni))
	if !sniFound {
		t.Errorf("SNI %q not found in ClientHello bytes", sni)
	}
}

// TestDialUTLSDifferentFingerprints verifies that different fingerprint
// choices produce different ClientHello bytes, confirming utls is actually
// selecting different browser profiles.
func TestDialUTLSDifferentFingerprints(t *testing.T) {
	fingerprints := []string{"chrome", "firefox"}

	helloSizes := make(map[string]int)

	for _, fp := range fingerprints {
		server, err := newRawClientHelloServer()
		if err != nil {
			t.Fatalf("newRawClientHelloServer: %v", err)
		}

		go func() {
			_, _ = dialUTLS(server.Addr(), "test.example.com", fp, true)
		}()

		helloBytes := server.WaitClientHello(5 * time.Second)
		server.Close()

		if helloBytes == nil {
			t.Fatalf("timed out waiting for ClientHello for fingerprint %q", fp)
		}

		recordLen := int(binary.BigEndian.Uint16(helloBytes[3:5]))
		helloSizes[fp] = recordLen
	}

	// Chrome and Firefox produce different ClientHello sizes. If they're
	// identical, utls isn't actually switching profiles.
	if helloSizes["chrome"] == helloSizes["firefox"] {
		t.Errorf("Chrome and Firefox ClientHello sizes are identical (%d bytes) — "+
			"utls may not be switching profiles", helloSizes["chrome"])
	}
}

// TestFingerprintToHelloID verifies the fingerprint string mapping.
func TestFingerprintToHelloID(t *testing.T) {
	tests := []struct {
		input    string
		expected string // the ClientHelloID.Client field (case-insensitive)
	}{
		{"", "chrome"},
		{"chrome", "chrome"},
		{"CHROME", "chrome"},
		{"Chrome", "chrome"},
		{"firefox", "firefox"},
		{"safari", "safari"},
		{"edge", "edge"},
		{"ios", "iOS"},
		{"android", "android"},
		{"unknown", "chrome"}, // defaults to chrome
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			id := fingerprintToHelloID(tc.input)
			got := strings.ToLower(id.Client)
			want := strings.ToLower(tc.expected)
			if got != want {
				t.Errorf("fingerprintToHelloID(%q) = Client %q, want %q",
					tc.input, id.Client, tc.expected)
			}
		})
	}
}

// TestDialUTLSNoTLS verifies that when useTLS is false, dialUTLS returns
// a plain TCP connection (no TLS wrapping).
func TestDialUTLSNoTLS(t *testing.T) {
	// Start a plain TCP echo server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Echo back whatever we receive.
		io.Copy(conn, conn)
	}()

	conn, err := dialUTLS(ln.Addr().String(), "", "", false)
	if err != nil {
		t.Fatalf("dialUTLS (no TLS): %v", err)
	}
	defer conn.Close()

	// Verify we can send and receive data.
	msg := []byte("hello-plain-tcp")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if !bytes.Equal(buf, msg) {
		t.Errorf("echo mismatch: got %q, want %q", buf, msg)
	}
}

// TestDialWebSocketNewSignature verifies that DialWebSocket with the new
// 4-arg signature works correctly for the non-TLS path.
func TestDialWebSocketNewSignature(t *testing.T) {
	// Start a plain TCP WebSocket listener.
	listener, err := ListenWebSocket("127.0.0.1:0", false, "", "")
	if err != nil {
		t.Fatalf("ListenWebSocket: %v", err)
	}
	defer listener.Close()
	addr := listener.listener.Addr().String()

	// Server goroutine: accept and echo frames.
	go func() {
		for {
			wt, err := listener.Accept()
			if err != nil {
				return
			}
			go func(wt *websocketTransport) {
				defer wt.conn.Close()
				for {
					payload, err := wt.wsConn.ReadFrame()
					if err != nil {
						return
					}
					_ = wt.wsConn.WriteFrame(payload)
				}
			}(wt)
		}
	}()

	// Dial with the new 4-arg signature: addr, useTLS=false, sni="", fingerprint=""
	wt, err := DialWebSocket(addr, false, "", "")
	if err != nil {
		t.Fatalf("DialWebSocket: %v", err)
	}
	defer wt.conn.Close()

	// Send a test frame and verify echo.
	pkt := []byte("utls-integration-test")
	if err := wt.wsConn.WriteFrame(pkt); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	echoed, err := wt.wsConn.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if !bytes.Equal(echoed, pkt) {
		t.Errorf("echo mismatch: got %d bytes, want %d bytes", len(echoed), len(pkt))
	}
}

// TestWSBindCarriesTLSConfig verifies that NewWSBind stores the TLS SNI and
// fingerprint config correctly.
func TestWSBindCarriesTLSConfig(t *testing.T) {
	wb := NewWSBind("", true, "cert.pem", "key.pem", "example.com", "firefox")

	if wb.tlsSni != "example.com" {
		t.Errorf("tlsSni = %q, want %q", wb.tlsSni, "example.com")
	}
	if wb.tlsFingerprint != "firefox" {
		t.Errorf("tlsFingerprint = %q, want %q", wb.tlsFingerprint, "firefox")
	}
	if !wb.useTLS {
		t.Error("useTLS = false, want true")
	}
	if wb.certFile != "cert.pem" {
		t.Errorf("certFile = %q, want %q", wb.certFile, "cert.pem")
	}
}

// writeTempFile writes data to a temp file and returns the path.
func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", "meshdesk-test-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}
