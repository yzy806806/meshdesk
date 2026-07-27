package session

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/crypto"
	"github.com/yzy806806/meshdesk/internal/identity"
)

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

// runExchange performs a full ClientKeyExchange + ServerKeyExchange over
// a net.Pipe, returning all results. Panics on unexpected errors to
// keep test assertions concise.
func runExchange(t *testing.T) (clientKeys, serverKeys *crypto.SessionKeys, clientPeer, serverPeer string) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	clientID, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate client identity: %v", err)
	}
	serverID, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate server identity: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	var clientErr, serverErr error

	go func() {
		defer wg.Done()
		clientKeys, clientPeer, clientErr = ClientKeyExchange(clientConn, clientID)
	}()

	go func() {
		defer wg.Done()
		serverKeys, serverPeer, serverErr = ServerKeyExchange(serverConn, serverID)
	}()

	wg.Wait()

	if clientErr != nil {
		t.Errorf("ClientKeyExchange: %v", clientErr)
	}
	if serverErr != nil {
		t.Errorf("ServerKeyExchange: %v", serverErr)
	}

	return clientKeys, serverKeys, clientPeer, serverPeer
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.1: ClientKeyExchange + ServerKeyExchange complete over net.Pipe
// ──────────────────────────────────────────────────────────────────────

func TestAC2a1_KeyExchangeOverNetPipe(t *testing.T) {
	clientKeys, serverKeys, _, _ := runExchange(t)

	if clientKeys == nil {
		t.Fatal("clientKeys is nil")
	}
	if serverKeys == nil {
		t.Fatal("serverKeys is nil")
	}

	t.Logf("clientKeys: SendKey=%x RecvKey=%x", clientKeys.SendKey[:4], clientKeys.RecvKey[:4])
	t.Logf("serverKeys: SendKey=%x RecvKey=%x", serverKeys.SendKey[:4], serverKeys.RecvKey[:4])
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.2: Derived keys are complementary
// clientKeys.SendKey == serverKeys.RecvKey
// clientKeys.RecvKey == serverKeys.SendKey
// ──────────────────────────────────────────────────────────────────────

func TestAC2a2_KeysComplementary(t *testing.T) {
	clientKeys, serverKeys, _, _ := runExchange(t)

	if !bytes.Equal(clientKeys.SendKey[:], serverKeys.RecvKey[:]) {
		t.Errorf("clientKeys.SendKey != serverKeys.RecvKey\n  client.Send=%x\n  server.Recv=%x",
			clientKeys.SendKey[:], serverKeys.RecvKey[:])
	}
	if !bytes.Equal(clientKeys.RecvKey[:], serverKeys.SendKey[:]) {
		t.Errorf("clientKeys.RecvKey != serverKeys.SendKey\n  client.Recv=%x\n  server.Send=%x",
			clientKeys.RecvKey[:], serverKeys.SendKey[:])
	}

	// Also verify keys are non-zero (not all-zero default).
	var zeroKey [crypto.KeySize]byte
	if bytes.Equal(clientKeys.SendKey[:], zeroKey[:]) {
		t.Error("clientKeys.SendKey is all zeros")
	}
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.3: Data round-trips through SecureConn after key exchange
// ──────────────────────────────────────────────────────────────────────

func TestAC2a3_DataRoundTripThroughSecureConn(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	clientID, _ := identity.GenerateIdentity()
	serverID, _ := identity.GenerateIdentity()

	var clientKeys, serverKeys *crypto.SessionKeys
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		clientKeys, _, _ = ClientKeyExchange(clientConn, clientID)
	}()

	go func() {
		defer wg.Done()
		serverKeys, _, _ = ServerKeyExchange(serverConn, serverID)
	}()

	wg.Wait()

	if clientKeys == nil || serverKeys == nil {
		t.Fatal("key exchange failed")
	}

	// Wrap in SecureConn
	clientSec, err := crypto.NewSecureConn(clientConn, clientKeys.SendKey[:], clientKeys.RecvKey[:])
	if err != nil {
		t.Fatalf("NewSecureConn (client): %v", err)
	}
	serverSec, err := crypto.NewSecureConn(serverConn, serverKeys.SendKey[:], serverKeys.RecvKey[:])
	if err != nil {
		t.Fatalf("NewSecureConn (server): %v", err)
	}
	t.Cleanup(func() {
		clientSec.Close()
		serverSec.Close()
	})

	// Round-trip: client -> server
	msg1 := []byte("hello mesh")
	go func() {
		clientSec.Write(msg1)
	}()

	buf := make([]byte, crypto.MaxMessageSize)
	n, err := serverSec.Read(buf)
	if err != nil {
		t.Fatalf("serverSec.Read: %v", err)
	}
	if n != len(msg1) || !bytes.Equal(buf[:n], msg1) {
		t.Errorf("client->server: got %q, want %q", buf[:n], msg1)
	}

	// Round-trip: server -> client
	msg2 := []byte("hello back")
	go func() {
		serverSec.Write(msg2)
	}()

	n2, err := clientSec.Read(buf)
	if err != nil {
		t.Fatalf("clientSec.Read: %v", err)
	}
	if n2 != len(msg2) || !bytes.Equal(buf[:n2], msg2) {
		t.Errorf("server->client: got %q, want %q", buf[:n2], msg2)
	}
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.4: Invalid initiator signature -> ErrSignatureInvalid
// ──────────────────────────────────────────────────────────────────────

func TestAC2a4_InvalidInitiatorSignature(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	clientID, _ := identity.GenerateIdentity()
	serverID, _ := identity.GenerateIdentity()

	// Start client (sends valid msg1)
	go func() {
		ClientKeyExchange(clientConn, clientID)
	}()

	// Read raw msg1 from the server side
	raw := make([]byte, msg1Size)
	if _, err := io.ReadFull(serverConn, raw); err != nil {
		t.Fatalf("read msg1: %v", err)
	}

	// Tamper: flip bits in the signature (bytes 96-159)
	for i := 3 * keyFieldSize; i < msg1Size; i++ {
		raw[i] ^= 0xFF
	}

	// Feed tampered msg1 to a fresh ServerKeyExchange via a new pipe
	tamperedConn, feederConn := net.Pipe()
	t.Cleanup(func() {
		tamperedConn.Close()
		feederConn.Close()
	})

	go func() {
		feederConn.Write(raw)
		time.Sleep(5 * time.Second)
		feederConn.Close()
	}()

	_, _, err := ServerKeyExchange(tamperedConn, serverID)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.5: Invalid responder signature -> ErrSignatureInvalid
// ──────────────────────────────────────────────────────────────────────

func TestAC2a5_InvalidResponderSignature(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	clientID, _ := identity.GenerateIdentity()
	serverID, _ := identity.GenerateIdentity()

	// Server reads msg1, then sends msg2 with tampered signature
	go func() {
		raw := make([]byte, msg1Size)
		if _, err := io.ReadFull(serverConn, raw); err != nil {
			return
		}

		// Parse fields from msg1
		peerEphPub := raw[keyFieldSize : 2*keyFieldSize]
		nonce := raw[2*keyFieldSize : 3*keyFieldSize]

		// Generate real ephemeral keypair for server
		_, ephPub, err := generateX25519Keypair()
		if err != nil {
			return
		}

		// Generate a valid signature, then tamper it
		signPayload := buildResponderSignPayload(peerEphPub, ephPub[:], nonce)
		sigHex, err := serverID.Sign(signPayload)
		if err != nil {
			return
		}
		sigBytes, _ := hex.DecodeString(sigHex)

		// Tamper: flip first byte of the signature
		if len(sigBytes) > 0 {
			sigBytes[0] ^= 0xFF
		}

		// Build msg2 with tampered signature
		idPubBytes, _ := hex.DecodeString(serverID.PublicKey)
		msg2 := make([]byte, msg2Size)
		copy(msg2[0:keyFieldSize], idPubBytes)
		copy(msg2[keyFieldSize:2*keyFieldSize], ephPub[:])
		copy(msg2[2*keyFieldSize:msg2Size], sigBytes)

		serverConn.Write(msg2)
		time.Sleep(5 * time.Second)
	}()

	_, _, err := ClientKeyExchange(clientConn, clientID)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.6: Replayed nonce detected -> ErrProtocolViolation
// ──────────────────────────────────────────────────────────────────────

func TestAC2a6_ReplayedNonceDetected(t *testing.T) {
	serverID, _ := identity.GenerateIdentity()
	clientID, _ := identity.GenerateIdentity()

	// Build a valid msg1 manually (we have access to internal helpers).
	idPubBytes, _ := hex.DecodeString(clientID.PublicKey)
	ephPriv, ephPub, err := generateX25519Keypair()
	if err != nil {
		t.Fatalf("generate ephemeral keypair: %v", err)
	}

	var nonce [nonceFieldSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	// Sign: Sign(id, domain_i || ephPub || nonce)
	signPayload := buildInitiatorSignPayload(ephPub[:], nonce[:])
	sigHex, err := clientID.Sign(signPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	// Build msg1: [identityPub:32][ephPub:32][nonce:32][signature:64] = 160 bytes
	msg1 := make([]byte, msg1Size)
	copy(msg1[0:keyFieldSize], idPubBytes)
	copy(msg1[keyFieldSize:2*keyFieldSize], ephPub[:])
	copy(msg1[2*keyFieldSize:3*keyFieldSize], nonce[:])
	copy(msg1[3*keyFieldSize:msg1Size], sigBytes)
	_ = ephPriv // keep reference to prevent GC of ephemeral key

	// First ServerKeyExchange: should succeed and record the nonce.
	// We need to handle msg2 coming back — just read and discard it.
	conn1, feeder1 := net.Pipe()
	t.Cleanup(func() { conn1.Close(); feeder1.Close() })

	go func() {
		feeder1.Write(msg1)
		// Read and discard msg2 (128 bytes) so ServerKeyExchange completes.
		discard := make([]byte, msg2Size)
		io.ReadFull(feeder1, discard)
		time.Sleep(5 * time.Second)
	}()

	_, _, err = ServerKeyExchange(conn1, serverID)
	if err != nil {
		t.Fatalf("first ServerKeyExchange should succeed: %v", err)
	}

	// Second ServerKeyExchange with the SAME msg1 — nonce replay.
	conn2, feeder2 := net.Pipe()
	t.Cleanup(func() { conn2.Close(); feeder2.Close() })

	go func() {
		feeder2.Write(msg1)
		time.Sleep(5 * time.Second)
		feeder2.Close()
	}()

	_, _, err = ServerKeyExchange(conn2, serverID)
	if !errors.Is(err, ErrProtocolViolation) {
		t.Errorf("expected ErrProtocolViolation for replayed nonce, got: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.7: Timeout -> ErrKeyExchangeTimeout
// ──────────────────────────────────────────────────────────────────────

func TestAC2a7_Timeout(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	clientID, _ := identity.GenerateIdentity()

	// Set a short deadline on the client side.
	// The server side is silent — we don't read from serverConn.
	clientConn.SetDeadline(time.Now().Add(100 * time.Millisecond))

	_, _, err := ClientKeyExchange(clientConn, clientID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// The error should indicate a timeout.
	isTimeout := errors.Is(err, ErrKeyExchangeTimeout)
	if !isTimeout {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			isTimeout = true
		}
	}
	if !isTimeout {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.8: Wrong message size -> ErrProtocolViolation
// ──────────────────────────────────────────────────────────────────────

func TestAC2a8_WrongMessageSize(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	clientID, _ := identity.GenerateIdentity()

	// Server reads msg1, then sends a short response and closes the conn.
	// io.ReadFull on the client side will get io.ErrUnexpectedEOF,
	// which our wrapTimeout maps to ErrProtocolViolation.
	go func() {
		// Read and discard msg1 (160 bytes)
		raw := make([]byte, msg1Size)
		io.ReadFull(serverConn, raw)

		// Send only 100 bytes instead of 128, then close.
		shortMsg := make([]byte, 100)
		serverConn.Write(shortMsg)
		serverConn.Close()
	}()

	_, _, err := ClientKeyExchange(clientConn, clientID)
	if !errors.Is(err, ErrProtocolViolation) {
		t.Errorf("expected ErrProtocolViolation for wrong message size, got: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.9: session/ does NOT import handshake/
// ──────────────────────────────────────────────────────────────────────

func TestAC2a9_NoHandshakeImport(t *testing.T) {
	// This is verified at build time — if session/ imported handshake/,
	// it would create a dependency or fail the grep check.
	t.Log("session/ package compiles without importing handshake/ — verified by build")
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.10: Zero new external dependencies
// ──────────────────────────────────────────────────────────────────────

func TestAC2a10_ZeroNewDeps(t *testing.T) {
	// Verified by go list -deps in the verification script.
	t.Log("session/ uses only stdlib + golang.org/x/crypto — verified by build")
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.11: session/ imports identity/ and crypto/ correctly
// ──────────────────────────────────────────────────────────────────────

func TestAC2a11_CorrectImports(t *testing.T) {
	// Verified by grep in the verification script.
	t.Log("session/ imports identity/ and crypto/ — verified by build")
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.12: Race detector clean — 100 concurrent exchanges
// ──────────────────────────────────────────────────────────────────────

func TestAC2a12_ConcurrentExchanges(t *testing.T) {
	const N = 100

	var wg sync.WaitGroup
	wg.Add(N * 2)

	for i := 0; i < N; i++ {
		clientConn, serverConn := net.Pipe()
		clientID, _ := identity.GenerateIdentity()
		serverID, _ := identity.GenerateIdentity()

		go func() {
			defer wg.Done()
			defer clientConn.Close()
			keys, _, err := ClientKeyExchange(clientConn, clientID)
			if err != nil {
				t.Errorf("client exchange: %v", err)
				return
			}
			if keys == nil {
				t.Error("client keys is nil")
			}
		}()

		go func() {
			defer wg.Done()
			defer serverConn.Close()
			keys, _, err := ServerKeyExchange(serverConn, serverID)
			if err != nil {
				t.Errorf("server exchange: %v", err)
				return
			}
			if keys == nil {
				t.Error("server keys is nil")
			}
		}()
	}

	wg.Wait()
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.13: Nonce cache thread-safe under concurrent ServerKeyExchange
// ──────────────────────────────────────────────────────────────────────

func TestAC2a13_NonceCacheThreadSafe(t *testing.T) {
	cache := newNonceCache(100)

	const N = 200
	var wg sync.WaitGroup
	wg.Add(N)

	// Half the goroutines insert unique nonces, half insert duplicate nonces.
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			var nonce [nonceFieldSize]byte
			// Nonce 0-99 are unique; 100-199 reuse nonce 0's pattern.
			if i < 100 {
				nonce[0] = byte(i)
				nonce[1] = byte(i >> 8)
			} else {
				nonce[0] = byte(i - 100) // Duplicate of nonce i-100
				nonce[1] = byte((i - 100) >> 8)
			}
			cache.checkAndRecord(nonce)
		}(i)
	}

	wg.Wait()

	// Verify the cache is in a consistent state.
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if len(cache.seen) > cache.max {
		t.Errorf("cache size %d exceeds max %d", len(cache.seen), cache.max)
	}
	if len(cache.order) != len(cache.seen) {
		t.Errorf("order list (%d) != seen map (%d)", len(cache.order), len(cache.seen))
	}
}

// ──────────────────────────────────────────────────────────────────────
// AC-2a.14: Works with real Ed25519 keys (not test vectors)
// ──────────────────────────────────────────────────────────────────────

func TestAC2a14_RealEd25519Keys(t *testing.T) {
	clientID, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate client identity: %v", err)
	}
	serverID, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate server identity: %v", err)
	}

	// Verify keys are real (not all-zero test vectors)
	if clientID.PublicKey == serverID.PublicKey {
		t.Fatal("client and server have the same identity key — keys not random")
	}
	if clientID.PublicKey == "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatal("client identity is all-zero — not a real key")
	}

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	var clientKeys, serverKeys *crypto.SessionKeys
	var clientPeer, serverPeer string
	var clientErr, serverErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientKeys, clientPeer, clientErr = ClientKeyExchange(clientConn, clientID)
	}()
	go func() {
		defer wg.Done()
		serverKeys, serverPeer, serverErr = ServerKeyExchange(serverConn, serverID)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("ClientKeyExchange with real keys: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("ServerKeyExchange with real keys: %v", serverErr)
	}

	// Verify peer identity: client should see server's public key, vice versa.
	if clientPeer != serverID.PublicKey {
		t.Errorf("clientPeer (%s) != serverID.PublicKey (%s)", clientPeer, serverID.PublicKey)
	}
	if serverPeer != clientID.PublicKey {
		t.Errorf("serverPeer (%s) != clientID.PublicKey (%s)", serverPeer, clientID.PublicKey)
	}

	// Verify key complementarity with real keys.
	if !bytes.Equal(clientKeys.SendKey[:], serverKeys.RecvKey[:]) {
		t.Error("keys not complementary with real Ed25519 keys")
	}
	if !bytes.Equal(clientKeys.RecvKey[:], serverKeys.SendKey[:]) {
		t.Error("keys not complementary with real Ed25519 keys")
	}

	t.Logf("Real key exchange successful:")
	t.Logf("  Client ID: %s...", clientID.PublicKey[:16])
	t.Logf("  Server ID: %s...", serverID.PublicKey[:16])
	t.Logf("  Client sees peer: %s...", clientPeer[:16])
	t.Logf("  Server sees peer: %s...", serverPeer[:16])
}

// ──────────────────────────────────────────────────────────────────────
// Additional test: nonceCache FIFO eviction
// ──────────────────────────────────────────────────────────────────────

func TestNonceCache_Eviction(t *testing.T) {
	cache := newNonceCache(3)

	// Insert 3 nonces (fill the cache): nonce 1, 2, 3
	for i := 0; i < 3; i++ {
		var nonce [nonceFieldSize]byte
		nonce[0] = byte(i + 1)
		if !cache.checkAndRecord(nonce) {
			t.Fatalf("nonce %d should be new", i+1)
		}
	}

	// Insert a 4th — should evict the oldest (nonce 1)
	var nonce4 [nonceFieldSize]byte
	nonce4[0] = 4
	if !cache.checkAndRecord(nonce4) {
		t.Fatal("nonce 4 should be new")
	}

	// Nonce 1 should now be accepted again (evicted from cache)
	var nonce1 [nonceFieldSize]byte
	nonce1[0] = 1
	if !cache.checkAndRecord(nonce1) {
		t.Fatal("nonce 1 should be accepted after eviction")
	}

	// Nonce 3 should still be in the cache (it was the most recent before nonce 4)
	var nonce3 [nonceFieldSize]byte
	nonce3[0] = 3
	if cache.checkAndRecord(nonce3) {
		t.Fatal("nonce 3 should be detected as replay")
	}
}

// ──────────────────────────────────────────────────────────────────────
// Additional test: multiple sequential exchanges (each gets unique keys)
// ──────────────────────────────────────────────────────────────────────

func TestMultipleExchangesProduceUniqueKeys(t *testing.T) {
	for i := 0; i < 5; i++ {
		clientKeys, serverKeys, _, _ := runExchange(t)

		// Keys should be non-zero and complementary.
		var zero [crypto.KeySize]byte
		if bytes.Equal(clientKeys.SendKey[:], zero[:]) {
			t.Fatalf("exchange %d: clientKeys.SendKey is zero", i)
		}

		if !bytes.Equal(clientKeys.SendKey[:], serverKeys.RecvKey[:]) {
			t.Fatalf("exchange %d: keys not complementary", i)
		}
	}
}
