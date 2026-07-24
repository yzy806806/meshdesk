// Package mesh provides the WireGuard mesh VPN core: device management,
// gVisor netstack integration, routing, and the pluggable obfuscation shim.
package mesh

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// ObfuscationMode selects the obfuscation strategy for a peer.
type ObfuscationMode int

const (
	ObfuscationNone       ObfuscationMode = iota // pass-through, no transformation
	ObfuscationPadded                            // random padding + timing jitter
	ObfuscationWebSocket                         // wrap in WebSocket frames over TCP
)

// ParseObfuscationMode converts a string to an ObfuscationMode.
// Default is ObfuscationPadded for unknown strings (fail-safe for GFW resistance).
func ParseObfuscationMode(s string) ObfuscationMode {
	switch s {
	case "none":
		return ObfuscationNone
	case "padded", "":
		return ObfuscationPadded
	case "websocket":
		return ObfuscationWebSocket
	default:
		return ObfuscationPadded
	}
}

// String returns the mode as a config string.
func (m ObfuscationMode) String() string {
	switch m {
	case ObfuscationNone:
		return "none"
	case ObfuscationPadded:
		return "padded"
	case ObfuscationWebSocket:
		return "websocket"
	default:
		return "padded"
	}
}

// --- Obfuscator interface ---

// Obfuscator transforms WireGuard packets before network I/O and reverses
// the transform on received packets. Each mode implements this interface.
type Obfuscator interface {
	// WrapOutbound transforms a WireGuard packet before it goes on the wire.
	WrapOutbound(packet []byte) ([]byte, error)
	// UnwrapInbound reverses the transform on a received packet.
	UnwrapInbound(data []byte) ([]byte, error)
	// Mode returns the obfuscation mode.
	Mode() ObfuscationMode
}

// --- none mode ---

// noneObfuscator passes packets through unchanged.
type noneObfuscator struct{}

func (noneObfuscator) WrapOutbound(packet []byte) ([]byte, error)  { return packet, nil }
func (noneObfuscator) UnwrapInbound(data []byte) ([]byte, error)  { return data, nil }
func (noneObfuscator) Mode() ObfuscationMode                       { return ObfuscationNone }

// --- padded mode ---

// Padding range constants for the padded obfuscation mode.
// Based on AmneziaWG design: random padding to break DPI fingerprinting.
const (
	paddedMinPadding = 16   // minimum extra bytes
	paddedMaxPadding = 64   // maximum extra bytes
	paddedMinJitter  = 2    // minimum timing jitter in milliseconds
	paddedMaxJitter  = 20   // maximum timing jitter in milliseconds
)

// paddedObfuscator adds random-length padding to each packet and introduces
// timing jitter. The padding is framed with a 4-byte length prefix so the
// receiver can strip it. This defeats DPI fingerprinting of WireGuard's
// fixed-size handshake messages (148-byte init, 92-byte response).
type paddedObfuscator struct {
	rng *rand.Rand
	mu  sync.Mutex
}

func newPaddedObfuscator() *paddedObfuscator {
	return &paddedObfuscator{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (p *paddedObfuscator) WrapOutbound(packet []byte) ([]byte, error) {
	p.mu.Lock()
	paddingLen := p.rng.Intn(paddedMaxPadding-paddedMinPadding) + paddedMinPadding
	p.mu.Unlock()

	// Frame: [4-byte big-endian original length][padding_len bytes of random][original packet]
	frame := make([]byte, 4+paddingLen+len(packet))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(packet)))
	p.mu.Lock()
	_, _ = p.rng.Read(frame[4 : 4+paddingLen]) // random padding
	p.mu.Unlock()
	copy(frame[4+paddingLen:], packet)

	// Timing jitter — delay before the packet is actually sent.
	// The caller (obfuscatingBind.Send) applies this as a sleep.
	p.mu.Lock()
	jitter := time.Duration(p.rng.Intn(paddedMaxJitter-paddedMinJitter)+paddedMinJitter) * time.Millisecond
	p.mu.Unlock()
	time.Sleep(jitter)

	return frame, nil
}

func (p *paddedObfuscator) UnwrapInbound(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("padded unwrap: frame too short (%d bytes)", len(data))
	}
	origLen := binary.BigEndian.Uint32(data[:4])
	if int(origLen) > len(data)-4 {
		return nil, fmt.Errorf("padded unwrap: declared length %d exceeds data %d", origLen, len(data)-4)
	}
	// The padding is everything between the 4-byte header and the original packet.
	paddingLen := len(data) - 4 - int(origLen)
	if paddingLen < 0 {
		return nil, fmt.Errorf("padded unwrap: negative padding length")
	}
	packet := make([]byte, origLen)
	copy(packet, data[4+paddingLen:])
	return packet, nil
}

func (p *paddedObfuscator) Mode() ObfuscationMode { return ObfuscationPadded }

// --- websocket mode ---

// wsFrameType is a simple WebSocket-like binary frame type.
const wsFrameType = 0x82 // binary frame opcode

// websocketObfuscator wraps WireGuard packets in a minimal WebSocket-like
// binary frame over TCP. This is for environments where UDP is throttled
// or blocked. The frame format follows RFC 6455 Section 5.2 (simplified):
//   - 1 byte FIN+opcode (0x82 for binary)
//   - 1 byte mask bit + payload length (7-bit, or extended)
//   - Optional extended length (2 bytes for 126-65535, 8 bytes for >65535)
//   - 4-byte masking key (if masked, which we don't use outbound)
//   - Payload
type websocketObfuscator struct{}

func newWebsocketObfuscator() *websocketObfuscator {
	return &websocketObfuscator{}
}

func (w *websocketObfuscator) WrapOutbound(packet []byte) ([]byte, error) {
	plen := len(packet)
	var buf []byte

	if plen <= 125 {
		// FIN=1, opcode=2 (binary) → 0x82; no mask → 0x80 bit clear
		buf = make([]byte, 2+plen)
		buf[0] = wsFrameType
		buf[1] = byte(plen)
		copy(buf[2:], packet)
	} else if plen <= 65535 {
		buf = make([]byte, 4+plen)
		buf[0] = wsFrameType
		buf[1] = 126 // extended payload length (16-bit)
		binary.BigEndian.PutUint16(buf[2:4], uint16(plen))
		copy(buf[4:], packet)
	} else {
		buf = make([]byte, 10+plen)
		buf[0] = wsFrameType
		buf[1] = 127 // extended payload length (64-bit)
		binary.BigEndian.PutUint64(buf[2:10], uint64(plen))
		copy(buf[10:], packet)
	}
	return buf, nil
}

func (w *websocketObfuscator) UnwrapInbound(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("websocket unwrap: frame too short")
	}
	if data[0] != wsFrameType {
		return nil, fmt.Errorf("websocket unwrap: unexpected opcode 0x%02x", data[0])
	}
	masked := data[1]&0x80 != 0
	payloadLen := int(data[1] & 0x7F)
	offset := 2

	switch payloadLen {
	case 126:
		if len(data) < 4 {
			return nil, fmt.Errorf("websocket unwrap: extended length truncated")
		}
		payloadLen = int(binary.BigEndian.Uint16(data[2:4]))
		offset = 4
	case 127:
		if len(data) < 10 {
			return nil, fmt.Errorf("websocket unwrap: extended length truncated")
		}
		payloadLen = int(binary.BigEndian.Uint64(data[2:10]))
		offset = 10
	}

	if masked {
		offset += 4 // skip masking key
	}

	if offset+payloadLen > len(data) {
		return nil, fmt.Errorf("websocket unwrap: payload %d exceeds data %d", payloadLen, len(data)-offset)
	}
	packet := make([]byte, payloadLen)
	copy(packet, data[offset:offset+payloadLen])
	return packet, nil
}

func (w *websocketObfuscator) Mode() ObfuscationMode { return ObfuscationWebSocket }

// --- Obfuscator factory ---

// NewObfuscator creates an Obfuscator for the given mode.
func NewObfuscator(mode ObfuscationMode) Obfuscator {
	switch mode {
	case ObfuscationNone:
		return noneObfuscator{}
	case ObfuscationPadded:
		return newPaddedObfuscator()
	case ObfuscationWebSocket:
		return newWebsocketObfuscator()
	default:
		return newPaddedObfuscator()
	}
}

// --- Obfuscating Bind (conn.Bind wrapper) ---

// obfuscatingBind wraps a conn.Bind to apply per-peer obfuscation transforms
// on all outbound and inbound packets. This is the integration point between
// the obfuscation shim and wireguard-go's networking layer.
type obfuscatingBind struct {
	inner      conn.Bind
	obfuscators map[string]Obfuscator // keyed by hex public key
	mu         sync.RWMutex
}

// NewObfuscatingBind wraps an inner conn.Bind with per-peer obfuscation.
func NewObfuscatingBind(inner conn.Bind) *obfuscatingBind {
	return &obfuscatingBind{
		inner:      inner,
		obfuscators: make(map[string]Obfuscator),
	}
}

// SetObfuscator associates an obfuscator with a peer (by hex public key).
func (b *obfuscatingBind) SetObfuscator(peerKey string, mode ObfuscationMode) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.obfuscators[peerKey] = NewObfuscator(mode)
}

// GetObfuscator returns the obfuscator for a peer, defaulting to padded mode.
func (b *obfuscatingBind) GetObfuscator(peerKey string) Obfuscator {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if o, ok := b.obfuscators[peerKey]; ok {
		return o
	}
	return NewObfuscator(ObfuscationPadded)
}

// Open delegates to the inner bind.
func (b *obfuscatingBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, port, err := b.inner.Open(uport)
	if err != nil {
		return nil, 0, err
	}
	// Wrap each receive function to de-obfuscate inbound packets.
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = b.wrapReceiveFunc(fn)
	}
	return wrapped, port, nil
}

// Close delegates to the inner bind.
func (b *obfuscatingBind) Close() error {
	return b.inner.Close()
}

// SetMark delegates to the inner bind.
func (b *obfuscatingBind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

// Send applies the peer's obfuscation transform before delegating to inner Send.
func (b *obfuscatingBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	// We need to determine which peer this endpoint corresponds to.
	// In the wireguard-go model, endpoints are identified by their DstToString.
	// For obfuscation we key by the endpoint's string representation.
	peerKey := endpoint.DstToString()
	o := b.GetObfuscator(peerKey)

	transformed := make([][]byte, len(bufs))
	for i, buf := range bufs {
		data, err := o.WrapOutbound(buf)
		if err != nil {
			return fmt.Errorf("obfuscate outbound: %w", err)
		}
		transformed[i] = data
	}
	return b.inner.Send(transformed, endpoint)
}

// ParseEndpoint delegates to the inner bind.
func (b *obfuscatingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}

// BatchSize delegates to the inner bind.
func (b *obfuscatingBind) BatchSize() int {
	return b.inner.BatchSize()
}

// wrapReceiveFunc wraps a ReceiveFunc to de-obfuscate inbound packets.
func (b *obfuscatingBind) wrapReceiveFunc(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		if err != nil {
			return n, err
		}
		// De-obfuscate each received packet.
		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			peerKey := ""
			if eps[i] != nil {
				peerKey = eps[i].DstToString()
			}
			o := b.GetObfuscator(peerKey)
			data, err := o.UnwrapInbound(packets[i][:sizes[i]])
			if err != nil {
				// If de-obfuscation fails, skip this packet rather than
				// killing the entire receive batch.
				sizes[i] = 0
				continue
			}
			copy(packets[i], data)
			sizes[i] = len(data)
		}
		return n, nil
	}
}

// --- TCP transport for websocket mode ---

// wsConn wraps a net.TCPConn to implement the streaming frame reader
// needed for WebSocket obfuscation mode (which operates over TCP, not UDP).
type wsConn struct {
	conn   net.Conn
	reader *bufio.Reader
}

// newWSConn wraps a TCP connection for WebSocket-frame streaming.
func newWSConn(c net.Conn) *wsConn {
	return &wsConn{
		conn:   c,
		reader: bufio.NewReader(c),
	}
}

// ReadFrame reads a single WebSocket binary frame from the stream.
func (w *wsConn) ReadFrame() ([]byte, error) {
	// Read first 2 bytes of the frame header.
	header := make([]byte, 2)
	if _, err := io.ReadFull(w.reader, header); err != nil {
		return nil, fmt.Errorf("ws read header: %w", err)
	}
	if header[0] != wsFrameType {
		return nil, fmt.Errorf("ws unexpected opcode 0x%02x", header[0])
	}
	masked := header[1]&0x80 != 0
	payloadLen := int(header[1] & 0x7F)
	offset := 0

	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(w.reader, ext); err != nil {
			return nil, fmt.Errorf("ws read ext length: %w", err)
		}
		payloadLen = int(binary.BigEndian.Uint16(ext))
		offset = 2
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(w.reader, ext); err != nil {
			return nil, fmt.Errorf("ws read ext length: %w", err)
		}
		payloadLen = int(binary.BigEndian.Uint64(ext))
		offset = 8
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(w.reader, maskKey); err != nil {
			return nil, fmt.Errorf("ws read mask: %w", err)
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(w.reader, payload); err != nil {
		return nil, fmt.Errorf("ws read payload: %w", err)
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	_ = offset // offset is implicitly used above
	return payload, nil
}

// WriteFrame writes a single WebSocket binary frame to the connection.
func (w *wsConn) WriteFrame(data []byte) error {
	frame, err := newWebsocketObfuscator().WrapOutbound(data)
	if err != nil {
		return err
	}
	_, err = w.conn.Write(frame)
	return err
}

// Close closes the underlying connection.
func (w *wsConn) Close() error {
	return w.conn.Close()
}

// hexEncode is a helper for encoding raw bytes to hex.
func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}
