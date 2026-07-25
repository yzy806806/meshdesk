package mesh

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ============================================================================
// Micro-benchmarks: WrapOutbound / UnwrapInbound per mode
// ============================================================================

func BenchmarkNoneWrapOutbound(b *testing.B) {
	o := noneObfuscator{}
	pkt := makeInitiationPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.WrapOutbound(pkt)
	}
}

func BenchmarkNoneUnwrapInbound(b *testing.B) {
	o := noneObfuscator{}
	pkt := makeInitiationPacket()
	out, _ := o.WrapOutbound(pkt)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.UnwrapInbound(out)
	}
}

func BenchmarkNoneRoundTrip(b *testing.B) {
	o := noneObfuscator{}
	pkt := makeInitiationPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ := o.WrapOutbound(pkt)
		o.UnwrapInbound(out)
	}
}

func BenchmarkPaddedWrapOutbound(b *testing.B) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0 // disable jitter for benchmark
	o := newPaddedObfuscator(cfg)
	pkt := makeInitiationPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.WrapOutbound(pkt)
	}
}

func BenchmarkPaddedUnwrapInbound(b *testing.B) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)
	pkt := makeInitiationPacket()
	out, _ := o.WrapOutbound(pkt)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.UnwrapInbound(out)
	}
}

func BenchmarkPaddedRoundTrip(b *testing.B) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)
	pkt := makeInitiationPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ := o.WrapOutbound(pkt)
		o.UnwrapInbound(out)
	}
}

func BenchmarkPaddedWrapOutboundWithPSK(b *testing.B) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	cfg.PSK = hex.EncodeToString([]byte("bench-psk-32-bytes-padding-padding!"))
	o := newPaddedObfuscator(cfg)
	pkt := makeInitiationPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.WrapOutbound(pkt)
	}
}

func BenchmarkPaddedUnwrapInboundWithPSK(b *testing.B) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	cfg.PSK = hex.EncodeToString([]byte("bench-psk-32-bytes-padding-padding!"))
	o := newPaddedObfuscator(cfg)
	pkt := makeInitiationPacket()
	out, _ := o.WrapOutbound(pkt)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.UnwrapInbound(out)
	}
}

func BenchmarkWebsocketWrapOutbound(b *testing.B) {
	o := newWebsocketObfuscator(true) // client side (masked)
	pkt := makeInitiationPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.WrapOutbound(pkt)
	}
}

func BenchmarkWebsocketUnwrapInbound(b *testing.B) {
	server := newWebsocketObfuscator(false)
	client := newWebsocketObfuscator(true)
	pkt := makeInitiationPacket()
	frame, _ := client.WrapOutbound(pkt)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.UnwrapInbound(frame)
	}
}

func BenchmarkWebsocketRoundTrip(b *testing.B) {
	server := newWebsocketObfuscator(false)
	client := newWebsocketObfuscator(true)
	pkt := makeInitiationPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame, _ := client.WrapOutbound(pkt)
		server.UnwrapInbound(frame)
	}
}

// ============================================================================
// Pipeline benchmarks: obfuscatingBind Send path
// ============================================================================

func BenchmarkObfuscatingBindSendNone(b *testing.B) {
	cb := &capturingBind{}
	ob := NewObfuscatingBind(cb)
	ob.SetObfuscator("peer-none", ObfuscationNone)
	ep := &testEndpoint{addr: "peer-none"}
	pkt := makeInitiationPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ob.Send([][]byte{pkt}, ep)
	}
}

func BenchmarkObfuscatingBindSendPadded(b *testing.B) {
	cb := &capturingBind{}
	ob := NewObfuscatingBind(cb)
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	ob.SetObfuscatorWithConfig("peer-padded", ObfuscationPadded, cfg, true)
	ep := &testEndpoint{addr: "peer-padded"}
	pkt := makeInitiationPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ob.Send([][]byte{pkt}, ep)
	}
}

func BenchmarkObfuscatingBindSendWebsocket(b *testing.B) {
	cb := &capturingBind{}
	ob := NewObfuscatingBind(cb)
	cfg := DefaultObfuscationConfig()
	ob.SetObfuscatorWithConfig("peer-ws", ObfuscationWebSocket, cfg, true)
	ep := &testEndpoint{addr: "peer-ws"}
	pkt := makeInitiationPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ob.Send([][]byte{pkt}, ep)
	}
}

// ============================================================================
// Concurrent benchmarks: thread-safety and contention
// ============================================================================

func BenchmarkObfuscatingBindConcurrentSend(b *testing.B) {
	cb := &capturingBind{}
	ob := NewObfuscatingBind(cb)
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	ob.SetObfuscatorWithConfig("peer-conc", ObfuscationPadded, cfg, true)
	ep := &testEndpoint{addr: "peer-conc"}
	pkt := makeInitiationPacket()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ob.Send([][]byte{pkt}, ep)
		}
	})
}

func BenchmarkObfuscatorRegistryConcurrentGet(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ObfuscatorRegistry.Get("padded")
		}
	})
}

func BenchmarkConcurrentPaddedRoundTrip(b *testing.B) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)
	pkt := makeInitiationPacket()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			out, _ := o.WrapOutbound(pkt)
			o.UnwrapInbound(out)
		}
	})
}

// ============================================================================
// Throughput benchmarks: simulate WireGuard packet stream
// ============================================================================

func BenchmarkPaddedThroughput1K(b *testing.B) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)
	pkt := makePacketWithType(wgMsgTransport) // transport packets: variable size, common in data planes

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ := o.WrapOutbound(pkt)
		o.UnwrapInbound(out)
	}
}

func BenchmarkPaddedThroughputInitiation(b *testing.B) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)
	pkt := makeInitiationPacket() // 148 bytes — handshake

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ := o.WrapOutbound(pkt)
		o.UnwrapInbound(out)
	}
}

// ============================================================================
// Overhead measurement: wire size comparison
// ============================================================================

func BenchmarkObfuscationOverhead(b *testing.B) {
	cfg := DefaultObfuscationConfig()
	cfg.S1 = 0
	cfg.S2 = 0
	cfg.S3 = 0
	cfg.S4 = 0
	cfg.JitterMaxMs = 0
	o := newPaddedObfuscator(cfg)

	pkt := makeInitiationPacket() // 148 bytes raw WG
	var totalOut, totalIn int64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ := o.WrapOutbound(pkt)
		totalOut += int64(len(out))
		back, _ := o.UnwrapInbound(out)
		totalIn += int64(len(back))
	}
	b.ReportMetric(float64(totalOut)/float64(b.N), "avg-wrap-bytes")
	b.ReportMetric(float64(totalIn)/float64(b.N), "avg-unwrap-bytes")
}

// ============================================================================
// uTLS real-TLS validation tests (not benchmarks — empirical validation)
// ============================================================================

// TestDialUTLSAgainstRealTLSServer verifies that dialUTLS can successfully
// complete a TLS handshake against a real TLS server. This is the critical
// empirical test: if the Go utls ClientHello is accepted by real servers,
// it will look like legitimate Chrome/Firefox traffic to any DPI system.
func TestDialUTLSAgainstRealTLSServer(t *testing.T) {
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	fingerprints := []string{"chrome", "firefox", "safari", "edge", "ios", "android"}

	for _, fp := range fingerprints {
		t.Run(fp, func(t *testing.T) {
			tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
			ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
			if err != nil {
				t.Fatalf("TLS listen: %v", err)
			}
			defer ln.Close()
			addr := ln.Addr().String()

			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				tlsConn := conn.(*tls.Conn)
				tlsConn.Handshake()
				conn.Close()
			}()

			conn, err := testDialUTLSInsecure(addr, "localhost", fp)
			if err != nil {
				t.Fatalf("dialUTLS(%s): %v", fp, err)
			}
			conn.Close()
		})
	}
}

// TestDialUTLSAgainstRealTLSServerConcurrent verifies concurrent uTLS dials
// against multiple TLS server instances — simulating a mesh with many peers.
func TestDialUTLSAgainstRealTLSServerConcurrent(t *testing.T) {
	numServers := 4
	numClientsPerServer := 3

	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Skipf("failed to parse test cert: %v", err)
	}

	var wg sync.WaitGroup

	for s := 0; s < numServers; s++ {
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
		if err != nil {
			t.Fatalf("TLS listen: %v", err)
		}
		defer ln.Close()
		addr := ln.Addr().String()

		// Server goroutine
		go func() {
			for i := 0; i < numClientsPerServer; i++ {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				tlsConn := conn.(*tls.Conn)
				tlsConn.Handshake()
				conn.Close()
			}
		}()

		// Client goroutines
		for c := 0; c < numClientsPerServer; c++ {
			wg.Add(1)
			go func(addr string, ci int) {
				defer wg.Done()
				conn, err := testDialUTLSInsecure(addr, "localhost", "chrome")
				if err != nil {
					t.Errorf("concurrent dialUTLS failed (server %s, client %d): %v", addr, ci, err)
					return
				}
				conn.Close()
			}(addr, c)
		}
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All concurrent dials succeeded.
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for concurrent dials")
	}
}

// ============================================================================
// uTLS fingerprint diversity validation
// ============================================================================

// TestUTLSFingerprintDiversity verifies that each fingerprint profile produces
// a meaningfully different ClientHello. This is an extension of the existing
// TestDialUTLSDifferentFingerprints but tests ALL supported fingerprints.
func TestUTLSFingerprintDiversity(t *testing.T) {
	fingerprints := []string{"chrome", "firefox", "safari", "edge", "ios", "android"}

	type fpRecord struct {
		fp   string
		size int
		data []byte
	}
	var records []fpRecord

	for _, fp := range fingerprints {
		server, err := newRawClientHelloServer()
		if err != nil {
			t.Fatalf("newRawClientHelloServer: %v", err)
		}

		go func() {
			_, _ = dialUTLS(server.Addr(), "diversity-test.local", fp, true)
		}()

		helloBytes := server.WaitClientHello(5 * time.Second)
		server.Close()

		if helloBytes == nil {
			t.Fatalf("timeout waiting for ClientHello for %s", fp)
		}

		records = append(records, fpRecord{
			fp:   fp,
			size: len(helloBytes),
			data: helloBytes,
		})
	}

	// Verify all fingerprints produce different ClientHello data.
	for i := 0; i < len(records); i++ {
		for j := i + 1; j < len(records); j++ {
			if bytes.Equal(records[i].data, records[j].data) {
				t.Errorf("fingerprints %s and %s produce identical ClientHello — utls not differentiating", records[i].fp, records[j].fp)
			}
		}
	}

	// Log sizes for informational purposes.
	for _, r := range records {
		t.Logf("%s ClientHello: %d bytes", r.fp, r.size)
	}
}

// ============================================================================
// HTTP with uTLS — mimic real browser traffic end-to-end
// ============================================================================

// TestUTLSHTTPRequest verifies that dialUTLS can be used to make real HTTP
// requests over TLS with a browser-mimicked ClientHello. This is the scenario
// that GFW DPI sees — an HTTP request that looks exactly like Chrome.
func TestUTLSHTTPRequest(t *testing.T) {
	// Start a simple HTTPS server.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Skipf("failed to parse test cert: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("TLS listen: %v", err)
	}
	defer ln.Close()

	go func() {
		http.Serve(ln, mux)
	}()

	addr := ln.Addr().String()

	fingerprints := []string{"chrome", "firefox", "safari"}

	for _, fp := range fingerprints {
		t.Run(fp, func(t *testing.T) {
			conn, err := testDialUTLSInsecure(addr, "localhost", fp)
			if err != nil {
				t.Fatalf("dialUTLS(%s) failed: %v", fp, err)
			}
			defer conn.Close()

			// Make a real HTTP request through the uTLS connection.
			req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
			req.Host = "localhost"
			if err := req.Write(conn); err != nil {
				t.Fatalf("HTTP request write (%s): %v", fp, err)
			}

			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, req)
			if err != nil {
				t.Fatalf("HTTP response read (%s): %v", fp, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				t.Errorf("expected 200, got %d (%s)", resp.StatusCode, fp)
			}
		})
	}
}

// ============================================================================
// Self-signed certificate for local TLS testing
// Generated with: go run crypto/tls/generate_cert.go --host localhost
// ============================================================================

// testDialUTLSInsecure is like dialUTLS but with InsecureSkipVerify for testing
// against self-signed certificates.
func testDialUTLSInsecure(addr, tlsSni, fingerprint string) (net.Conn, error) {
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	sni := tlsSni
	if sni == "" {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			sni = host
		}
	}
	helloID := fingerprintToHelloID(fingerprint)
	tlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, helloID)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}
func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

// ============================================================================
// Performance summary test (collects and prints benchmark-style results)
// ============================================================================

// TestPerformanceSummary runs a comprehensive performance characterization
// of the obfuscation pipeline. It's NOT a benchmark (runs once) but produces
// human-readable timing results for all modes and operation types.
func TestPerformanceSummary(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0

	modes := []struct {
		name   string
		wrap   func()
		unwrap func()
	}{
		{
			name: "none",
			wrap: func() {
				o := noneObfuscator{}
				o.WrapOutbound(makeInitiationPacket())
			},
			unwrap: func() {
				o := noneObfuscator{}
				pkt := makeInitiationPacket()
				out, _ := o.WrapOutbound(pkt)
				o.UnwrapInbound(out)
			},
		},
		{
			name: "padded",
			wrap: func() {
				o := newPaddedObfuscator(cfg)
				o.WrapOutbound(makeInitiationPacket())
			},
			unwrap: func() {
				o := newPaddedObfuscator(cfg)
				pkt := makeInitiationPacket()
				out, _ := o.WrapOutbound(pkt)
				o.UnwrapInbound(out)
			},
		},
		{
			name: "padded+psk",
			wrap: func() {
				cfg2 := cfg
				cfg2.PSK = hex.EncodeToString([]byte("perf-psk-32-bytes-padding-padding!"))
				o := newPaddedObfuscator(cfg2)
				o.WrapOutbound(makeInitiationPacket())
			},
			unwrap: func() {
				cfg2 := cfg
				cfg2.PSK = hex.EncodeToString([]byte("perf-psk-32-bytes-padding-padding!"))
				o := newPaddedObfuscator(cfg2)
				pkt := makeInitiationPacket()
				out, _ := o.WrapOutbound(pkt)
				o.UnwrapInbound(out)
			},
		},
		{
			name: "websocket",
			wrap: func() {
				o := newWebsocketObfuscator(true)
				o.WrapOutbound(makeInitiationPacket())
			},
			unwrap: func() {
				client := newWebsocketObfuscator(true)
				server := newWebsocketObfuscator(false)
				pkt := makeInitiationPacket()
				frame, _ := client.WrapOutbound(pkt)
				server.UnwrapInbound(frame)
			},
		},
	}

	iterations := 50000

	t.Logf("=== Performance Summary (%d iterations per test) ===", iterations)

	for _, m := range modes {
		// Warm up
		for i := 0; i < 1000; i++ {
			m.wrap()
		}
		start := time.Now()
		for i := 0; i < iterations; i++ {
			m.wrap()
		}
		wrapDuration := time.Since(start)
		wrapPerOp := wrapDuration / time.Duration(iterations)

		// Warm up unwrap
		for i := 0; i < 1000; i++ {
			m.unwrap()
		}
		start = time.Now()
		for i := 0; i < iterations; i++ {
			m.unwrap()
		}
		unwrapDuration := time.Since(start)
		unwrapPerOp := unwrapDuration / time.Duration(iterations)

		t.Logf("%-14s: Wrap=%s/op  Unwrap=%s/op  (total: %d wrap=%v unwrap=%v)",
			m.name, wrapPerOp, unwrapPerOp, iterations,
			wrapDuration.Round(time.Microsecond),
			unwrapDuration.Round(time.Microsecond),
		)
	}

	// Pipeline test
	t.Log("")
	t.Log("=== Pipeline Test (obfuscatingBind Send) ===")
	cb := &capturingBind{}
	ob := NewObfuscatingBind(cb)
	ob.SetObfuscatorWithConfig("peer-padded", ObfuscationPadded, cfg, true)
	ep := &testEndpoint{addr: "peer-padded"}
	pkt := makeInitiationPacket()

	for i := 0; i < 1000; i++ {
		ob.Send([][]byte{pkt}, ep)
	}
	start := time.Now()
	for i := 0; i < iterations; i++ {
		ob.Send([][]byte{pkt}, ep)
	}
	pipelineDuration := time.Since(start)
	t.Logf("padded pipeline: %s/op  (total: %v for %d ops)",
		pipelineDuration/time.Duration(iterations), pipelineDuration.Round(time.Microsecond), iterations)
}

// ============================================================================
// Overhead characterization: byte-level analysis
// ============================================================================

// TestOverheadCharacterization measures the byte-level overhead of each
// obfuscation mode — how many extra bytes are added to WireGuard packets.
func TestOverheadCharacterization(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.JitterMaxMs = 0

	tests := []struct {
		name      string
		createObf func() Obfuscator
		pktMaker  func() []byte
		pktName   string
	}{
		{"none/initation", func() Obfuscator { return noneObfuscator{} }, makeInitiationPacket, "initiation (148)"},
		{"padded/initiation", func() Obfuscator { return newPaddedObfuscator(cfg) }, makeInitiationPacket, "initiation (148)"},
		{"padded/transport", func() Obfuscator { return newPaddedObfuscator(cfg) }, func() []byte { return makePacketWithType(wgMsgTransport) }, "transport (64)"},
		{"websocket/client/initiation", func() Obfuscator { return newWebsocketObfuscator(true) }, makeInitiationPacket, "initiation (148)"},
		{"websocket/client/transport", func() Obfuscator { return newWebsocketObfuscator(true) }, func() []byte { return makePacketWithType(wgMsgTransport) }, "transport (64)"},
	}

	t.Log("=== Byte Overhead Characterization ===")
	t.Log("Mode                     | Pkt Type        | Input | Output (avg) | Overhead")
	t.Log("-------------------------|-----------------|-------|--------------|--------")

	for _, tt := range tests {
		o := tt.createObf()
		pkt := tt.pktMaker()
		inputLen := len(pkt)

		var totalOutput int
		samples := 100
		for i := 0; i < samples; i++ {
			out, err := o.WrapOutbound(pkt)
			if err != nil {
				t.Fatalf("%s WrapOutbound: %v", tt.name, err)
			}
			totalOutput += len(out)
		}
		avgOutput := totalOutput / samples
		overhead := avgOutput - inputLen
		t.Logf("%-25s| %-15s| %5d | %12d | %+9d", tt.name, tt.pktName, inputLen, avgOutput, overhead)
	}
}
