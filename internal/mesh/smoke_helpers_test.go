//go:build smoke
// +build smoke

package mesh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	cryptopkg "github.com/yzy806806/meshdesk/internal/crypto"
)

const testKeySize = 32

// newLocalTLSPipe creates an in-process TLS client+server pair using
// net.Pipe() and a self-signed ECDSA certificate. Returns (clientConn,
// serverConn) where both ends are *tls.Conn instances that have completed
// the TLS 1.3 handshake.
func newLocalTLSPipe(t *testing.T) (client, server net.Conn) {
	t.Helper()

	cert := generateSelfSignedCert(t)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	clientConf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	cPipe, sPipe := net.Pipe()

	// Do the TLS handshake in parallel.
	errCh := make(chan error, 2)
	var clientConn *tls.Conn
	var serverConn *tls.Conn

	go func() {
		s := tls.Server(sPipe, tlsConfig)
		err := s.Handshake()
		errCh <- err
		serverConn = s
	}()

	go func() {
		c := tls.Client(cPipe, clientConf)
		err := c.Handshake()
		errCh <- err
		clientConn = c
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("TLS handshake failed: %v", err)
		}
	}

	return clientConn, serverConn
}

// generateSelfSignedCert creates a self-signed ECDSA certificate valid for
// localhost, suitable for TLS testing.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

// newAEADPipe wraps a net.Pipe() pair with SecureConn using the given key
// for both send and receive directions. Returns (clientAEAD, serverAEAD).
func newAEADPipe(t *testing.T, key []byte) (client, server net.Conn) {
	t.Helper()

	if len(key) != testKeySize {
		t.Fatalf("key must be %d bytes, got %d", testKeySize, len(key))
	}

	cPipe, sPipe := net.Pipe()

	c, err := cryptopkg.NewSecureConn(cPipe, key, key)
	if err != nil {
		cPipe.Close()
		sPipe.Close()
		t.Fatalf("client NewSecureConn: %v", err)
	}

	s, err := cryptopkg.NewSecureConn(sPipe, key, key)
	if err != nil {
		c.Close()
		sPipe.Close()
		t.Fatalf("server NewSecureConn: %v", err)
	}

	return c, s
}

// newTLSThenAEADPipe chains TLS handshake → AES-GCM wrapping over
// net.Pipe(). Returns (client, server) where both ends are net.Conn
// that have TLS + AES-GCM applied.
func newTLSThenAEADPipe(t *testing.T, aesKey []byte) (client, server net.Conn) {
	t.Helper()

	cTLS, sTLS := newLocalTLSPipe(t)

	c, err := cryptopkg.NewSecureConn(cTLS, aesKey, aesKey)
	if err != nil {
		cTLS.Close()
		sTLS.Close()
		t.Fatalf("client NewSecureConn over TLS: %v", err)
	}

	s, err := cryptopkg.NewSecureConn(sTLS, aesKey, aesKey)
	if err != nil {
		c.Close()
		sTLS.Close()
		t.Fatalf("server NewSecureConn over TLS: %v", err)
	}

	return c, s
}
