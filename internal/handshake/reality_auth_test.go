package handshake

// Hermetic REALITY authentication tests.
//
// Background: REALITY's failure mode is "proxy the connection to the
// camouflage destination". A client whose auth tag is rejected still completes
// a TLS handshake — with the *destination site*, not with its peer — so any
// test that only checks "Connect returned no error" or "bytes came back"
// passes while the mesh tunnel is entirely absent.
//
// These tests make that visible. The camouflage destination is a local TLS
// server under test control, and the assertion is that the **server-side
// application** receives the client's bytes. If auth fails the connection is
// proxied to the local dest instead, and the server-side app sees nothing.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// localCamouflageDest starts a TLS server that plays the role of the
// camouflage site and returns its address.
func localCamouflageDest(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("dest key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{Organization: []string{"Camouflage Dest"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"meshdesk.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("dest cert: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatalf("dest listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 16)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("camouflage-dest"))
			}(c)
		}
	}()
	return ln.Addr().String()
}

// TestRealityAuthReachesPeer is the assertion the old TestClientServerHandshake
// lacked: real application data must arrive at the server-side application.
//
// A regression in either direction shows up here — a fingerprint without
// X25519MLKEM768 (rejected by the server) or a client that accepts the
// camouflage certificate makes the server-side read time out, because the
// bytes went to the destination instead of the peer.
func TestRealityAuthReachesPeer(t *testing.T) {
	dest := localCamouflageDest(t)

	privKey, pubKey, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}

	server := NewRealityHandshake(HandshakeConfig{
		RealityPrivateKey:  privKey,
		RealityDest:        dest,
		RealityServerNames: []string{"meshdesk.test"},
		DialTimeout:        5 * time.Second,
	})
	client := NewRealityHandshake(HandshakeConfig{
		RealityPublicKey: pubKey,
		ServerName:       "meshdesk.test",
		DialTimeout:      5 * time.Second,
		TLSFingerprint:   "chrome",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ln, err := server.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server Listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptedCh := make(chan accepted, 1)
	go func() {
		c, aerr := ln.Accept()
		acceptedCh <- accepted{c, aerr}
	}()

	conn, err := client.Connect(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("client Connect failed — REALITY authentication did not complete: %v", err)
	}
	defer conn.Close()

	payload := []byte("mesh-auth-probe")
	go func() { _, _ = conn.Write(payload) }()

	select {
	case a := <-acceptedCh:
		if a.err != nil {
			t.Fatalf("server Accept: %v", a.err)
		}
		defer a.conn.Close()

		buf := make([]byte, len(payload))
		a.conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		n, rerr := io.ReadFull(a.conn, buf)
		if rerr != nil {
			t.Fatalf("server application received no data: the client's bytes went to the camouflage destination, "+
				"so REALITY authentication failed even though the client's TLS handshake succeeded (n=%d err=%v)", n, rerr)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("payload mismatch: got %q want %q", buf[:n], payload)
		}

	case <-time.After(15 * time.Second):
		t.Fatalf("server Accept never returned: the connection was proxied to the camouflage destination")
	}
}

// TestRealityRejectsCamouflageCertificate pins the client-side behaviour that
// makes an auth failure loud: when the server proxies the connection to the
// camouflage destination, the peer is a genuine TLS server with a valid
// certificate — and the client must still refuse it, because accepting it
// would silently send mesh traffic to the wrong host.
func TestRealityRejectsCamouflageCertificate(t *testing.T) {
	dest := localCamouflageDest(t)

	// A key the server does NOT hold: every auth attempt fails, so the
	// connection is proxied to dest.
	_, wrongPub, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	serverPriv, _, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}

	server := NewRealityHandshake(HandshakeConfig{
		RealityPrivateKey:  serverPriv,
		RealityDest:        dest,
		RealityServerNames: []string{"meshdesk.test"},
		DialTimeout:        5 * time.Second,
	})
	client := NewRealityHandshake(HandshakeConfig{
		RealityPublicKey: wrongPub,
		ServerName:       "meshdesk.test",
		DialTimeout:      5 * time.Second,
		TLSFingerprint:   "chrome",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ln, err := server.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() { <-time.After(3 * time.Second); c.Close() }()
		}
	}()

	conn, cerr := client.Connect(ctx, ln.Addr().String())
	if cerr == nil {
		conn.Close()
		t.Fatal("client accepted a peer that could not authenticate — it must reject the camouflage destination's certificate")
	}
	var he *HandshakeError
	if !errors.As(cerr, &he) {
		t.Logf("connect error (not HandshakeError, acceptable): %v", cerr)
	}
	t.Logf("correctly rejected: %v", cerr)
}

// TestFingerprintCapability is the guard for the X25519MLKEM768 requirement.
// The REALITY server rejects ClientHellos without the hybrid key share, so a
// fingerprint that cannot emit one is unusable — it must be reported as a
// config error up front, not discovered as a failed handshake.
func TestFingerprintCapability(t *testing.T) {
	cases := map[string]bool{
		"":        true, // defaults to chrome
		"chrome":  true,
		"firefox": false, // utls Firefox 120 predates MLKEM
		"safari":  false, // Safari 16.0 predates MLKEM
		"edge":    false, // Edge 85/106 predate MLKEM
		"ios":     false, // iOS 14 predates MLKEM
		"android": false, // OkHttp fingerprint has no TLS 1.3 key share at all
	}
	for fp, want := range cases {
		fp, want := fp, want
		t.Run("fp="+fp, func(t *testing.T) {
			ok, err := fingerprintAdvertisesMLKEM(fingerprintToHelloID(fp))
			if err != nil {
				t.Fatalf("probe failed for %q: %v", fp, err)
			}
			if ok != want {
				t.Fatalf("fingerprint %q MLKEM capability = %v, want %v", fp, ok, want)
			}
		})
	}

	// The unusable ones must fail before dialling, with a config error
	// naming the field rather than a handshake error.
	h := NewRealityHandshake(HandshakeConfig{
		RealityPublicKey: "00",
		ServerName:       "meshdesk.test",
		TLSFingerprint:   "firefox",
	})
	_, err := h.Connect(context.Background(), "127.0.0.1:1")
	if err == nil {
		t.Fatal("Connect with an MLKEM-incapable fingerprint must fail")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "TLSFingerprint" {
		t.Fatalf("want ConfigError on TLSFingerprint, got %v", err)
	}
}
