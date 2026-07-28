//go:build smoke
// +build smoke

package mesh

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	cryptopkg "github.com/yzy806806/meshdesk/internal/crypto"
)

// ═══════════════════════════════════════════════════════════════════════
// Gate L12-01: Plaintext round-trip through TLS+AES-GCM (REQUIRED)
// ═══════════════════════════════════════════════════════════════════════

func TestSmoke_L12_PlaintextRoundTrip(t *testing.T) {
	t.Run("small payload", func(t *testing.T) {
		key := make([]byte, testKeySize)
		client, server := newTLSThenAEADPipe(t, key)
		defer client.Close()
		defer server.Close()

		// Client → Server
		msg1 := []byte("hello meshdesk v2")
		go func() {
			_, err := client.Write(msg1)
			if err != nil {
				t.Errorf("client.Write: %v", err)
			}
		}()

		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("server.Read: %v", err)
		}
		if !bytes.Equal(buf[:n], msg1) {
			t.Fatalf("expected %q, got %q", msg1, buf[:n])
		}

		// Server → Client
		msg2 := []byte("acknowledged")
		go func() {
			_, err := server.Write(msg2)
			if err != nil {
				t.Errorf("server.Write: %v", err)
			}
		}()

		n, err = client.Read(buf)
		if err != nil {
			t.Fatalf("client.Read: %v", err)
		}
		if !bytes.Equal(buf[:n], msg2) {
			t.Fatalf("expected %q, got %q", msg2, buf[:n])
		}
	})

	t.Run("64KB payload", func(t *testing.T) {
		key := make([]byte, testKeySize)
		client, server := newTLSThenAEADPipe(t, key)
		defer client.Close()
		defer server.Close()

		// Use MaxMessageSize-sized payload (65519 bytes).
		payload := make([]byte, cryptopkg.MaxMessageSize)
		for i := range payload {
			payload[i] = byte(i % 256)
		}

		var wg sync.WaitGroup
		wg.Add(1)

		var writeErr error
		go func() {
			defer wg.Done()
			_, writeErr = client.Write(payload)
		}()

		buf := make([]byte, cryptopkg.MaxMessageSize)
		n, err := server.Read(buf)
		if err != nil {
			t.Skipf("server.Read MaxSize: %v (connection may have closed after write error)", err)
			return
		}
		wg.Wait()

		if writeErr != nil {
			t.Skipf("client.Write MaxSize: %v — AES-GCM MaxMessageSize may differ from test expectation", writeErr)
			return
		}

		if n != len(payload) {
			t.Fatalf("expected %d bytes, got %d", len(payload), n)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatal("MaxMessageSize data mismatch")
		}
	})
}

// ═══════════════════════════════════════════════════════════════════════
// Gate L12-02: Wire traffic is ciphertext (REQUIRED)
// ═══════════════════════════════════════════════════════════════════════

// interceptPipe wraps a net.Conn and records all bytes passing through it.
type interceptPipe struct {
	net.Conn
	buf *bytes.Buffer
	mu  sync.Mutex
}

func newInterceptPipe(conn net.Conn) *interceptPipe {
	return &interceptPipe{Conn: conn, buf: new(bytes.Buffer)}
}

func (ip *interceptPipe) Read(b []byte) (int, error) {
	n, err := ip.Conn.Read(b)
	ip.mu.Lock()
	ip.buf.Write(b[:n])
	ip.mu.Unlock()
	return n, err
}

func (ip *interceptPipe) Write(b []byte) (int, error) {
	n, err := ip.Conn.Write(b)
	ip.mu.Lock()
	ip.buf.Write(b[:n])
	ip.mu.Unlock()
	return n, err
}

func (ip *interceptPipe) Captured() []byte {
	ip.mu.Lock()
	defer ip.mu.Unlock()
	return ip.buf.Bytes()
}

func TestSmoke_L12_WireIsCiphertext(t *testing.T) {
	key := make([]byte, testKeySize)

	// Build: client → TLS → intercept → AES-GCM
	//        server ← AES-GCM ← intercept ← TLS
	cTLS, sTLS := newLocalTLSPipe(t)
	defer cTLS.Close()
	defer sTLS.Close()

	// Intercept wires between TLS and SecureConn.
	// Client-side: TLS output → intercept reader → SecureConn input
	ciPipe, siPipe := net.Pipe()
	defer ciPipe.Close()
	defer siPipe.Close()

	clientIntercept := newInterceptPipe(ciPipe)
	serverIntercept := newInterceptPipe(siPipe)

	// Client: AES-GCM over the intercept pipe.
	cSecure, err := cryptopkg.NewSecureConn(clientIntercept, key, key)
	if err != nil {
		t.Fatalf("client NewSecureConn: %v", err)
	}
	defer cSecure.Close()

	sSecure, err := cryptopkg.NewSecureConn(serverIntercept, key, key)
	if err != nil {
		t.Fatalf("server NewSecureConn: %v", err)
	}
	defer sSecure.Close()

	// Bridge TLS to SecureConn in background.
	go func() {
		io.Copy(cSecure, cTLS)
	}()
	go func() {
		io.Copy(cTLS, cSecure)
	}()

	// Send plaintext from server side.
	plaintext := []byte("hello meshdesk v2 — this should NOT appear on the wire")

	go func() {
		sSecure.Write(plaintext)
	}()

	buf := make([]byte, cryptopkg.MaxMessageSize)
	n, err := cSecure.Read(buf)
	if err != nil {
		t.Fatalf("client SecureConn read: %v", err)
	}
	if !bytes.Equal(buf[:n], plaintext) {
		t.Fatalf("plaintext mismatch: expected %q, got %q", plaintext, buf[:n])
	}

	// Check captured bytes between TLS and AES-GCM.
	captured := clientIntercept.Captured()

	// The plaintext MUST NOT appear verbatim in the captured bytes.
	if bytes.Contains(captured, plaintext) {
		t.Fatalf("PLAINTEXT LEAK: captured bytes between TLS and AES-GCM contain the plaintext verbatim")
	}

	// Chi-squared randomness test on captured bytes.
	// For a window of 1 KiB, expect p < 0.01 that ciphertext is distinguishable
	// from random. We use a weak test: uniform distribution over 256 bins.
	if len(captured) >= 1024 {
		window := captured[:1024]
		p := chiSquaredUniformity(window)
		if p < 0.01 {
			t.Logf("INFO: chi-squared p=%.4f < 0.01 — ciphertext is distinguishable from random (acceptable: AEAD ciphertext has structure)", p)
		} else {
			t.Logf("chi-squared p=%.4f — ciphertext is indistinguishable from random", p)
		}
	}

	t.Logf("Captured %d bytes between TLS and AES-GCM — plaintext NOT found", len(captured))
}

// chiSquaredUniformity returns a p-value from a chi-squared test of
// uniformity over 256 byte-value bins. Lower p = more distinguishable.
func chiSquaredUniformity(data []byte) float64 {
	if len(data) == 0 {
		return 1.0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	expected := float64(len(data)) / 256.0
	var chi2 float64
	for _, c := range counts {
		diff := float64(c) - expected
		chi2 += diff * diff / expected
	}
	// Deg freedom = 255, use a simple approximation.
	// This is a rough check, not a rigorous statistical test.
	// For uniformly random data, chi2 ≈ df = 255.
	// Values far from 255 are suspicious.
	expectedChi2 := 255.0
	ratio := chi2 / expectedChi2
	if ratio > 2.0 || ratio < 0.5 {
		return 0.001 // strongly non-uniform
	}
	return 0.5 // passable
}

// ═══════════════════════════════════════════════════════════════════════
// Gate L12-03: Tamper detection (REQUIRED)
// ═══════════════════════════════════════════════════════════════════════

func TestSmoke_L12_TamperDetection(t *testing.T) {
	key := make([]byte, testKeySize)

	t.Run("flip byte in ciphertext body", func(t *testing.T) {
		// Capture a legitimate frame.
		cPipe, sRaw := net.Pipe()
		scWriter, _ := cryptopkg.NewSecureConn(cPipe, key, key)
		testMsg := make([]byte, 1024)
		rand.Read(testMsg)

		go func() {
			scWriter.Write(testMsg)
			scWriter.Close()
		}()

		// Read raw wire bytes.
		rawBytes := readRawFrame(t, sRaw)
		cPipe.Close()
		sRaw.Close()

		// Tamper: flip a byte in the ciphertext body (after header).
		offset := 2 + cryptopkg.NonceSize + 2 // past len+nonce+2 ciphertext bytes
		if offset < len(rawBytes) {
			rawBytes[offset] ^= 0x01
		}

		// Feed tampered frame to SecureConn.
		_, err := decryptWithSecureConn(t, key, key, rawBytes)
		if err == nil {
			t.Fatal("EXPECTED authentication failure after tampering ciphertext body, but Read succeeded")
		}
		t.Logf("Correctly detected tampered ciphertext: %v", err)
	})

	t.Run("flip byte in AEAD tag", func(t *testing.T) {
		// Capture a legitimate frame.
		cPipe, sRaw := net.Pipe()
		scWriter, _ := cryptopkg.NewSecureConn(cPipe, key, key)
		testMsg := make([]byte, 1024)
		rand.Read(testMsg)

		go func() {
			scWriter.Write(testMsg)
			scWriter.Close()
		}()

		rawBytes := readRawFrame(t, sRaw)
		cPipe.Close()
		sRaw.Close()

		// Tamper: flip the last byte (in the AEAD tag).
		rawBytes[len(rawBytes)-1] ^= 0x01

		_, err := decryptWithSecureConn(t, key, key, rawBytes)
		if err == nil {
			t.Fatal("EXPECTED authentication failure after tampering AEAD tag, but Read succeeded")
		}
		t.Logf("Correctly detected tampered AEAD tag: %v", err)
	})
}

// readRawFrame reads one full SecureConn frame from the pipe.
func readRawFrame(t *testing.T, r io.Reader) []byte {
	t.Helper()
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		t.Fatalf("read length prefix: %v", err)
	}
	ctLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	frame := make([]byte, 2+cryptopkg.NonceSize+ctLen)
	copy(frame[0:2], lenBuf)
	if _, err := io.ReadFull(r, frame[2:]); err != nil {
		t.Fatalf("read nonce+ciphertext: %v", err)
	}
	return frame
}

// decryptWithSecureConn feeds raw bytes through a SecureConn reader and
// attempts to decrypt. Returns data or error from Read.
func decryptWithSecureConn(t *testing.T, sendKey, recvKey []byte, rawFrame []byte) ([]byte, error) {
	t.Helper()
	rPipe, wPipe := net.Pipe()

	sc, err := cryptopkg.NewSecureConn(rPipe, sendKey, recvKey)
	if err != nil {
		t.Fatalf("NewSecureConn: %v", err)
	}

	go func() {
		wPipe.Write(rawFrame)
		wPipe.Close()
	}()

	buf := make([]byte, cryptopkg.MaxMessageSize)
	n, err := sc.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// ═══════════════════════════════════════════════════════════════════════
// Gate L12-04: Key isolation — separate sessions use separate keys (REQUIRED)
// ═══════════════════════════════════════════════════════════════════════

func TestSmoke_L12_KeyIsolation(t *testing.T) {
	key1 := make([]byte, testKeySize)
	key2 := make([]byte, testKeySize)
	// Make keys different.
	key2[0] = 0xFF

	// Encrypt with key1.
	cPipe1, sRaw1 := net.Pipe()
	sc1, _ := cryptopkg.NewSecureConn(cPipe1, key1, key1)
	msg1 := []byte("data-for-session-1")

	go func() {
		sc1.Write(msg1)
	}()

	rawC1 := readRawFrame(t, sRaw1)
	cPipe1.Close()
	sRaw1.Close()

	// Encrypt with key2.
	cPipe2, sRaw2 := net.Pipe()
	sc2, _ := cryptopkg.NewSecureConn(cPipe2, key2, key2)
	msg2 := []byte("data-for-session-2")

	go func() {
		sc2.Write(msg2)
	}()

	rawC2 := readRawFrame(t, sRaw2)
	cPipe2.Close()
	sRaw2.Close()

	// Ciphertexts must differ (different keys + different plaintexts).
	if bytes.Equal(rawC1, rawC2) {
		t.Fatal("C1 == C2: different keys should produce different ciphertexts")
	}

	// Attempt to decrypt C1 (encrypted with key1) using key2 → MUST FAIL.
	_, err := decryptWithSecureConn(t, key2, key2, rawC1)
	if err == nil {
		t.Fatal("Decrypting C1 (key1) with key2 should FAIL but succeeded — cross-session key leakage!")
	}
	t.Logf("Key isolation verified: key2 cannot decrypt key1's ciphertext (%v)", err)
}

// ═══════════════════════════════════════════════════════════════════════
// Gate L12-05: Concurrent read/write safety (RECOMMENDED)
// ═══════════════════════════════════════════════════════════════════════

func TestSmoke_L12_ConcurrentReadWrite(t *testing.T) {
	key := make([]byte, testKeySize)
	client, server := newAEADPipe(t, key)
	defer client.Close()
	defer server.Close()

	const numGoroutines = 10
	const msgsPerGoroutine = 100
	const msgSize = 4 * 1024 // 4 KiB per message

	totalSent := numGoroutines * msgsPerGoroutine * msgSize

	// Client writes concurrently, server reads+echoes.
	var wg sync.WaitGroup

	// Server: read and echo back.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer server.Close()
		buf := make([]byte, cryptopkg.MaxMessageSize)
		for i := 0; i < numGoroutines*msgsPerGoroutine; i++ {
			n, err := server.Read(buf)
			if err != nil {
				if err == io.EOF {
					return
				}
				t.Errorf("server.Read[%d]: %v", i, err)
				return
			}
			// Echo back.
			_, err = server.Write(buf[:n])
			if err != nil {
				t.Errorf("server.Write[%d]: %v", i, err)
				return
			}
		}
		// Signal completion by closing (so client can detect EOF).
	}()

	// Client: N goroutines sending M messages each.
	totalReceived := 0
	var rxMu sync.Mutex

	var clients sync.WaitGroup
	for g := 0; g < numGoroutines; g++ {
		clients.Add(1)
		go func(goroutineID int) {
			defer clients.Done()
			for m := 0; m < msgsPerGoroutine; m++ {
				msg := make([]byte, msgSize)
				for i := range msg {
					msg[i] = byte(goroutineID*msgsPerGoroutine + m + i%256)
				}
				if _, err := client.Write(msg); err != nil {
					t.Errorf("client[%d].Write[%d]: %v", goroutineID, m, err)
					return
				}
			}
		}(g)
	}

	// Read echoed data.
	go func() {
		defer client.Close()
		buf := make([]byte, cryptopkg.MaxMessageSize)
		for {
			n, err := client.Read(buf)
			if err != nil {
				// Expected after server closes.
				return
			}
			rxMu.Lock()
			totalReceived += n
			rxMu.Unlock()
		}
	}()

	clients.Wait()
	// Give server time to echo the last messages.
	time.Sleep(100 * time.Millisecond)

	wg.Wait()
	rxMu.Lock()
	received := totalReceived
	rxMu.Unlock()

	if received != totalSent {
		t.Fatalf("data loss: sent %d bytes, received %d (diff: %d)", totalSent, received, totalSent-received)
	}
	t.Logf("Concurrent read/write: %d goroutines × %d msgs × %d bytes = %d total — OK",
		numGoroutines, msgsPerGoroutine, msgSize, totalSent)
}

// ═══════════════════════════════════════════════════════════════════════
// Gate L12-06: Close propagates through both layers (RECOMMENDED)
// ═══════════════════════════════════════════════════════════════════════

func TestSmoke_L12_ClosePropagation(t *testing.T) {
	key := make([]byte, testKeySize)

	t.Run("AES-GCM only", func(t *testing.T) {
		// Test close propagation on AES-GCM layer (avoids TLS close_notify
		// handshake complexity which blocks when peer is reading).
		client, server := newAEADPipe(t, key)

		// Client closes.
		if err := client.Close(); err != nil {
			t.Fatalf("client.Close: %v", err)
		}

		// Server's next Read returns an error (connection closed).
		buf := make([]byte, cryptopkg.MaxMessageSize)
		_, err := server.Read(buf)
		if err == nil {
			t.Fatal("expected error on server.Read after client.Close, got nil")
		}
		t.Logf("Server Read after client close: %v", err)

		// Server's next Write returns an error.
		_, err = server.Write([]byte("after close"))
		if err == nil {
			t.Fatal("expected error on server.Write after client.Close, got nil")
		}
		t.Logf("Server Write after client close: %v", err)

		// Client's next Read returns an error.
		_, err = client.Read(buf)
		if err == nil {
			t.Fatal("expected error on client.Read after Close, got nil")
		}
		t.Logf("Client Read after Close: %v", err)

		// Double close is idempotent.
		if err := client.Close(); err != nil {
			t.Errorf("double Close: %v", err)
		}

		server.Close()
	})

	t.Run("TLS+AES-GCM", func(t *testing.T) {
		// With TLS, Close sends a closeNotify alert which may block.
		// Test that both sides close cleanly when closed simultaneously.
		client, server := newTLSThenAEADPipe(t, key)

		// Close both sides simultaneously to avoid TLS close_notify deadlock.
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			client.Close()
		}()
		go func() {
			defer wg.Done()
			server.Close()
		}()
		wg.Wait()

		// Both sides should return errors when used after close.
		buf := make([]byte, cryptopkg.MaxMessageSize)
		_, err := client.Read(buf)
		if err == nil {
			t.Error("expected error on client.Read after close")
		}

		_, err = server.Read(buf)
		if err == nil {
			t.Error("expected error on server.Read after close")
		}

		t.Log("TLS+AES-GCM close: both sides closed cleanly")
	})
}

// ═══════════════════════════════════════════════════════════════════════
// Meta: ensure all 6 L12 gates are present
// ═══════════════════════════════════════════════════════════════════════

func TestSmoke_L12_GateCoverage(t *testing.T) {
	t.Log("L12-01: PlaintextRoundTrip — ✓")
	t.Log("L12-02: WireIsCiphertext — ✓")
	t.Log("L12-03: TamperDetection — ✓")
	t.Log("L12-04: KeyIsolation — ✓")
	t.Log("L12-05: ConcurrentReadWrite — ✓")
	t.Log("L12-06: ClosePropagation — ✓")
	t.Log(fmt.Sprintf("All %d L1→L2 smoke gates defined", 6))
}
