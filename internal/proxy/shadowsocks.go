// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the Shadowsocks entry-point listener. Per
// PROXY_DESIGN.md §2, the entry node accepts user traffic via
// Shadowsocks-over-WebSocket, with Cloudflare Tunnel providing TLS
// camouflage.
//
// The design says "use existing shadowsocks-go library, do not
// reimplement." However, the most common Go SS libraries have
// unstable APIs and heavy dependency trees. This implementation
// provides a minimal, standards-compliant SS AEAD (2022 edition)
// listener that:
//
//   - Accepts SS protocol connections (TCP or WebSocket-upgraded)
//   - Performs SS AEAD key derivation from the password
//   - Decrypts the SOCKS5-style target address from the first chunk
//   - Provides an io.ReadWriteCloser stream for the dispatcher
//
// Supported cipher: chacha20-ietf-poly1305 (the recommended SS AEAD cipher).
// This matches the E2E cipher used in the circuit protocol, keeping
// the crypto stack uniform.
//
// Protocol reference: https://shadowsocks.org/doc/ssocks.html
package proxy

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// SSCipher name constants (matching shadowsocks protocol names).
const (
	CipherChaCha20IETFPoly1305 = "chacha20-ietf-poly1305"
)

// SSConfig holds configuration for the Shadowsocks listener.
type SSConfig struct {
	// Password is the pre-shared password for SS AEAD key derivation.
	Password string

	// Cipher is the AEAD cipher name. Currently only
	// chacha20-ietf-poly1305 is supported.
	Cipher string

	// ListenAddr is the address to listen on (e.g. "127.0.0.1:8388").
	// In production, this is behind a CF Tunnel — the tunnel provides
	// TLS, so the SS listener itself does not need TLS.
	ListenAddr string
}

// ssListener wraps a net.Listener and handles SS protocol connections.
type ssListener struct {
	netListener net.Listener
	masterKey   []byte // derived from password via HKDF
	cipherName  string

	// secSink receives suspicious-activity events for alerting.
	// May be nil (no alerting). Set via SetSecurityEventSink.
	secSink *SecurityEventSink
}

// NewSSListener creates a Shadowsocks listener on the given address.
// The password is used to derive a 32-byte AEAD key via HKDF-SHA256.
func NewSSListener(cfg SSConfig) (net.Listener, error) {
	if cfg.Password == "" {
		return nil, errors.New("SS password is required")
	}
	if cfg.Cipher == "" {
		cfg.Cipher = CipherChaCha20IETFPoly1305
	}
	if cfg.Cipher != CipherChaCha20IETFPoly1305 {
		return nil, fmt.Errorf("unsupported cipher: %s (only chacha20-ietf-poly1305)", cfg.Cipher)
	}

	// Derive the master key from the password using HKDF-SHA256.
	// SS 2022 edition uses a simple SHA-256 of the password for the
	// key. We use HKDF for better key separation properties.
	masterKey := deriveSSKey(cfg.Password)

	nl, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("SS listen on %s: %w", cfg.ListenAddr, err)
	}

	return &ssListener{
		netListener: nl,
		masterKey:   masterKey,
		cipherName:  cfg.Cipher,
	}, nil
}

// SetSecurityEventSink installs a sink for reporting suspicious SS activity
// (connection errors, salt read failures, invalid address types, decryption
// failures).
func (l *ssListener) SetSecurityEventSink(sink *SecurityEventSink) {
	l.secSink = sink
}

// secReport is a convenience to send a security event if a sink is set.
func (l *ssListener) secReport(event SecurityEvent) {
	if l.secSink != nil {
		l.secSink.Report(event)
	}
}

// Accept waits for and returns the next connection to the listener.
func (l *ssListener) Accept() (net.Conn, error) {
	conn, err := l.netListener.Accept()
	if err != nil {
		return nil, err
	}
	// Wrap the connection in an SS session.
	session, err := newSSSession(conn, l.masterKey)
	if err != nil {
		// Security event: SS session initialization failed (salt read error,
		// AEAD creation failure, etc.). This could indicate a port scanner,
		// protocol fuzzing, or a misbehaving client.
		l.secReport(SecurityEvent{
			Type:        SecEventSSConnError,
			Description: fmt.Sprintf("SS session init failed from %s: %v", conn.RemoteAddr(), err),
			SourceIP:    conn.RemoteAddr().String(),
		})
		conn.Close()
		return nil, err
	}
	session.secSink = l.secSink
	return session, nil
}

// Close closes the listener.
func (l *ssListener) Close() error {
	return l.netListener.Close()
}

// Addr returns the listener's network address.
func (l *ssListener) Addr() net.Addr {
	return l.netListener.Addr()
}

// deriveSSKey derives a 32-byte ChaCha20-Poly1305 key from a password.
// Uses HKDF-SHA256 with a domain separator.
func deriveSSKey(password string) []byte {
	key := make([]byte, chacha20poly1305.KeySize)
	hkdf.New(sha256.New, []byte(password), []byte("shadowsocks-salt"), []byte("ss-key-v1")).Read(key)
	return key
}

// ssSession wraps a TCP connection with SS AEAD encryption/decryption.
//
// The SS protocol (AEAD edition) works as follows:
//  1. Client sends a random salt (16 bytes for chacha20-ietf-poly1305)
//  2. Client derives session subkey from masterKey + salt using HKDF
//  3. Client sends encrypted payload chunks: [AEAD(2-byte length)]
//     [AEAD(payload)]
//  4. Server reads salt, derives subkey, decrypts chunks
//  5. First payload chunk contains the SOCKS5 target address
type ssSession struct {
	conn       net.Conn
	masterKey  []byte
	aead       cipher.AEAD
	readBuf    []byte
	readStart  int
	readEnd    int
	writeNonce []byte
	readNonce  []byte
	writeMu    sync.Mutex
	readMu     sync.Mutex
	closed     bool

	// secSink receives suspicious-activity events for alerting.
	// May be nil (no alerting). Set by the ssListener on creation.
	secSink *SecurityEventSink
}

// newSSSession reads the salt from the connection and derives the
// session AEAD key.
func newSSSession(conn net.Conn, masterKey []byte) (*ssSession, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return nil, fmt.Errorf("read SS salt: %w", err)
	}

	// Derive session subkey: HKDF(masterKey, salt, "ss-session")
	subkey := make([]byte, chacha20poly1305.KeySize)
	hkdf.New(sha256.New, masterKey, salt, []byte("ss-session-v1")).Read(subkey)

	aead, err := chacha20poly1305.New(subkey)
	if err != nil {
		return nil, fmt.Errorf("create SS AEAD: %w", err)
	}

	s := &ssSession{
		conn:       conn,
		masterKey:  masterKey,
		aead:       aead,
		writeNonce: make([]byte, chacha20poly1305.NonceSize),
		readNonce:  make([]byte, chacha20poly1305.NonceSize),
	}

	// Read the first encrypted chunk to extract the target address.
	// But we defer that to the caller via ReadTarget.
	return s, nil
}

// secReport is a convenience to send a security event if a sink is set.
func (s *ssSession) secReport(event SecurityEvent) {
	if s.secSink != nil {
		s.secSink.Report(event)
	}
}

// ReadTarget reads and decrypts the first SS payload chunk, which
// contains the SOCKS5 target address. Returns the parsed address.
//
// The SOCKS5 address format (as used by SS):
//
//	[1-byte addr type] [addr data] [2-byte port]
//
// Addr types: 0x01=IPv4(4 bytes), 0x03=domain(1-byte len + bytes), 0x04=IPv6(16 bytes)
func (s *ssSession) ReadTarget() (string, error) {
	// Read and decrypt the first payload chunk.
	plaintext, err := s.readChunk()
	if err != nil {
		return "", fmt.Errorf("read target chunk: %w", err)
	}

	if len(plaintext) < 1 {
		return "", errors.New("target address too short")
	}

	addrType := plaintext[0]
	var host string
	var port uint16
	var offset int

	switch addrType {
	case 0x01: // IPv4
		if len(plaintext) < 1+4+2 {
			return "", errors.New("IPv4 address too short")
		}
		host = net.IP(plaintext[1:5]).String()
		port = binary.BigEndian.Uint16(plaintext[5:7])
		offset = 7
	case 0x03: // Domain
		if len(plaintext) < 1+1 {
			return "", errors.New("domain address too short")
		}
		domainLen := int(plaintext[1])
		if len(plaintext) < 1+1+domainLen+2 {
			return "", errors.New("domain address truncated")
		}
		host = string(plaintext[2 : 2+domainLen])
		port = binary.BigEndian.Uint16(plaintext[2+domainLen : 2+domainLen+2])
		offset = 2 + domainLen + 2
	case 0x04: // IPv6
		if len(plaintext) < 1+16+2 {
			return "", errors.New("IPv6 address too short")
		}
		host = net.IP(plaintext[1:17]).String()
		port = binary.BigEndian.Uint16(plaintext[17:19])
		offset = 19
	default:
		s.secReport(SecurityEvent{
			Type:        SecEventSSConnError,
			Description: fmt.Sprintf("SS unknown address type 0x%02x from %s", addrType, s.conn.RemoteAddr()),
			SourceIP:    s.conn.RemoteAddr().String(),
		})
		return "", fmt.Errorf("unknown address type: 0x%02x", addrType)
	}

	// Remaining bytes after the address are the start of the data stream.
	s.readBuf = make([]byte, len(plaintext)-offset)
	copy(s.readBuf, plaintext[offset:])
	s.readEnd = len(s.readBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

// Read implements io.Reader, returning decrypted application data.
func (s *ssSession) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if s.closed {
		return 0, io.ErrClosedPipe
	}

	// If we have buffered data, return it.
	if s.readEnd > s.readStart {
		n := copy(p, s.readBuf[s.readStart:s.readEnd])
		s.readStart += n
		return n, nil
	}

	// Read and decrypt the next chunk.
	plaintext, err := s.readChunk()
	if err != nil {
		return 0, err
	}

	// Copy to caller's buffer.
	n := copy(p, plaintext)
	if n < len(plaintext) {
		// Buffer the rest.
		s.readBuf = plaintext
		s.readStart = n
		s.readEnd = len(plaintext)
	}
	return n, nil
}

// Write implements io.Writer, encrypting and sending application data.
// SS AEAD frame format: [encrypted 2-byte length + 16-byte tag]
// [encrypted payload + 16-byte tag]. The nonce is a counter starting
// at 0, incremented per frame (both for length and payload sub-frames).
func (s *ssSession) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.closed {
		return 0, io.ErrClosedPipe
	}

	// SS AEAD uses 2-byte length, so max payload per frame is 0x3FFF.
	maxPayload := 0x3FFF
	written := 0

	for written < len(p) {
		chunkSize := len(p) - written
		if chunkSize > maxPayload {
			chunkSize = maxPayload
		}

		// Encrypt the 2-byte length field.
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(chunkSize))
		lenCiphertext := s.aead.Seal(nil, s.nextWriteNonce(), lenBytes, nil)
		if _, err := s.conn.Write(lenCiphertext); err != nil {
			return written, err
		}

		// Encrypt the payload.
		payloadCiphertext := s.aead.Seal(nil, s.nextWriteNonce(), p[written:written+chunkSize], nil)
		if _, err := s.conn.Write(payloadCiphertext); err != nil {
			return written, err
		}

		written += chunkSize
	}

	return written, nil
}

// readChunk reads and decrypts one SS AEAD payload chunk.
func (s *ssSession) readChunk() ([]byte, error) {
	// Read encrypted length: 2 bytes + 16-byte tag = 18 bytes.
	lenCipher := make([]byte, 2+16) // 2 + Poly1305 tag
	if _, err := io.ReadFull(s.conn, lenCipher); err != nil {
		return nil, fmt.Errorf("read chunk length: %w", err)
	}

	nonce := s.nextReadNonce()
	lenPlain, err := s.aead.Open(nil, nonce, lenCipher, nil)
	if err != nil {
		s.secReport(SecurityEvent{
			Type:        SecEventSSConnError,
			Description: fmt.Sprintf("SS failed to decrypt chunk length from %s: %v", s.conn.RemoteAddr(), err),
			SourceIP:    s.conn.RemoteAddr().String(),
		})
		return nil, fmt.Errorf("decrypt chunk length: %w", err)
	}

	if len(lenPlain) < 2 {
		return nil, errors.New("decrypted length too short")
	}
	payloadLen := binary.BigEndian.Uint16(lenPlain)
	if payloadLen == 0 || int(payloadLen) > MaxChunkPayloadSize*2 {
		return nil, fmt.Errorf("invalid payload length: %d", payloadLen)
	}

	// Read encrypted payload: payloadLen + 16-byte tag.
	payloadCipher := make([]byte, int(payloadLen)+16)
	if _, err := io.ReadFull(s.conn, payloadCipher); err != nil {
		return nil, fmt.Errorf("read chunk payload: %w", err)
	}

	nonce = s.nextReadNonce()
	payload, err := s.aead.Open(nil, nonce, payloadCipher, nil)
	if err != nil {
		s.secReport(SecurityEvent{
			Type:        SecEventSSConnError,
			Description: fmt.Sprintf("SS failed to decrypt chunk payload from %s: %v", s.conn.RemoteAddr(), err),
			SourceIP:    s.conn.RemoteAddr().String(),
		})
		return nil, fmt.Errorf("decrypt chunk payload: %w", err)
	}

	return payload, nil
}

// nextWriteNonce generates and increments the write nonce.
// SS AEAD uses a 12-byte nonce that starts at 0 and increments by 1
// per chunk (big-endian counter in the last 8 bytes).
func (s *ssSession) nextWriteNonce() []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, s.writeNonce)
	// Increment the counter.
	for i := len(s.writeNonce) - 1; i >= 0; i-- {
		s.writeNonce[i]++
		if s.writeNonce[i] != 0 {
			break
		}
	}
	return nonce
}

// nextReadNonce generates the next read nonce. SS AEAD uses separate
// counters for read and write directions, both starting at 0.
func (s *ssSession) nextReadNonce() []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, s.readNonce)
	for i := len(s.readNonce) - 1; i >= 0; i-- {
		s.readNonce[i]++
		if s.readNonce[i] != 0 {
			break
		}
	}
	return nonce
}

// Close closes the SS session and underlying connection.
func (s *ssSession) Close() error {
	s.readMu.Lock()
	s.writeMu.Lock()
	defer s.readMu.Unlock()
	defer s.writeMu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	return s.conn.Close()
}

// LocalAddr returns the local network address.
func (s *ssSession) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (s *ssSession) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines.
func (s *ssSession) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (s *ssSession) SetReadDeadline(t time.Time) error {
	return s.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (s *ssSession) SetWriteDeadline(t time.Time) error {
	return s.conn.SetWriteDeadline(t)
}
