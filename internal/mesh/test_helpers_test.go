package mesh

import (
	"net"
	"strconv"
	"testing"
)

// newTestMuxTransport creates a MuxTransport on a random port for testing.
// Returns the transport, the TCP listener (for cleanup) and the bind address.
func newTestMuxTransport(t *testing.T) (*MuxTransport, net.Listener, string) {
	t.Helper()
	port := freePort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	mt, err := NewMuxTransport(MuxTransportConfig{
		TCPListener: ln,
		BindAddr:    "127.0.0.1",
		UDPPort:     -1,
	})
	if err != nil {
		ln.Close()
		t.Fatalf("NewMuxTransport: %v", err)
	}
	return mt, ln, addr
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
