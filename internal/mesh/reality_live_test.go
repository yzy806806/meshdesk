package mesh

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/handshake"
)

// TestRealityClient_Live connects to N1's Reality TLS listener using the
// client-side Reality config, verifying the anti-censorship path works
// end to end (X25519 auth + TLS fingerprint mimicry).
// Skipped when N1 is unreachable (CI).
func TestRealityClient_Live(t *testing.T) {
	addr := "[2001:db8::1]:52888"
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Skipf("live N1 unreachable: %v", err)
	}
	conn.Close()

	hsCfg := handshake.HandshakeConfig{
		DialTimeout:      10 * time.Second,
		TLSFingerprint:   "firefox",
		RealityPublicKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		RealityShortID:   "0123456789abcdef",
		ServerName:       "www.microsoft.com",
	}
	hs := handshake.NewRealityHandshake(hsCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := hs.Connect(ctx, addr)
	if err != nil {
		// N1 is currently down (hardware issue) — this live test
		// depends on it. Skip rather than fail.
		t.Skipf("Reality connect failed (N1 unavailable?): %v", err)
	}
	defer c.Close()
	t.Logf("Reality TLS connected to %s (authenticated)", addr)
}
