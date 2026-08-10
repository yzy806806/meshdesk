package smux

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame types (§3.2).
const (
	FrameData   uint8 = 0x00
	FrameSyn    uint8 = 0x01
	FrameFin    uint8 = 0x02
	FrameRst    uint8 = 0x03
	FramePing   uint8 = 0x04
	FrameGoAway uint8 = 0x05
)

// Flags (§3.4).
const (
	FlagSyn uint16 = 0x0001
	FlagFin uint16 = 0x0002
	FlagRst uint16 = 0x0004
	FlagAck uint16 = 0x0008
)

// HeaderSize is the fixed frame header size in bytes.
const HeaderSize = 12

// ProtocolVersion is the current smux wire format version.
const ProtocolVersion uint8 = 1

// MaxStreamID is the maximum stream ID (2^31 - 1). Stream IDs are uint32
// but must not exceed 2^31-1 to keep the allocation space symmetric
// between odd (client) and even (server) ranges.
const MaxStreamID uint32 = 0x7FFFFFFF

// frame represents a parsed smux frame.
type frame struct {
	Version  uint8
	Type     uint8
	Flags    uint16
	StreamID uint32
	Length   uint32 // payload length in bytes
	Payload  []byte // optional: DATA payload, RST/GO_AWAY/PING error code
}

// encodeHeader writes the 12-byte header into dst.
// dst must be at least HeaderSize bytes.
func (f *frame) encodeHeader(dst []byte) {
	dst[0] = f.Version
	dst[1] = f.Type
	binary.BigEndian.PutUint16(dst[2:4], f.Flags)
	binary.BigEndian.PutUint32(dst[4:8], f.StreamID)
	binary.BigEndian.PutUint32(dst[8:12], f.Length)
}

// readFrame reads one complete frame from r (header + payload).
// It allocates the payload buffer if Length > 0.
func readFrame(r io.Reader, maxPayload int) (*frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	f := &frame{
		Version:  hdr[0],
		Type:     hdr[1],
		Flags:    binary.BigEndian.Uint16(hdr[2:4]),
		StreamID: binary.BigEndian.Uint32(hdr[4:8]),
		Length:   binary.BigEndian.Uint32(hdr[8:12]),
	}

	// The length is attacker-controlled wire data. Cap the allocation
	// at the configured max frame size — a claimed Length=0xFFFFFFFF
	// would otherwise trigger a ~4GB make() → OOM crash.
	if maxPayload > 0 && f.Length > uint32(maxPayload) {
		return nil, fmt.Errorf("smux: frame length %d exceeds max %d", f.Length, maxPayload)
	}

	if f.Length > 0 {
		f.Payload = make([]byte, f.Length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
	}

	return f, nil
}

// writeFrame writes a complete frame (header + payload) to w in a single call.
func writeFrame(w io.Writer, f *frame) error {
	buf := make([]byte, HeaderSize+len(f.Payload))
	f.encodeHeader(buf[:HeaderSize])
	copy(buf[HeaderSize:], f.Payload)
	_, err := w.Write(buf)
	return err
}

// newDataFrame creates a DATA frame for the given stream.
func newDataFrame(streamID uint32, payload []byte) *frame {
	return &frame{
		Version:  ProtocolVersion,
		Type:     FrameData,
		Flags:    0,
		StreamID: streamID,
		Length:   uint32(len(payload)),
		Payload:  payload,
	}
}

// newSynFrame creates a SYN frame for the given stream ID.
func newSynFrame(streamID uint32, ack bool) *frame {
	flags := FlagSyn
	if ack {
		flags = FlagSyn | FlagAck
	}
	return &frame{
		Version:  ProtocolVersion,
		Type:     FrameSyn,
		Flags:    flags,
		StreamID: streamID,
		Length:   0,
	}
}

// newFinFrame creates a FIN frame for the given stream ID.
func newFinFrame(streamID uint32) *frame {
	return &frame{
		Version:  ProtocolVersion,
		Type:     FrameFin,
		Flags:    FlagFin,
		StreamID: streamID,
		Length:   0,
	}
}

// newRstFrame creates an RST frame with an error code payload (4 bytes BE).
func newRstFrame(streamID uint32, code uint32) *frame {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, code)
	return &frame{
		Version:  ProtocolVersion,
		Type:     FrameRst,
		Flags:    FlagRst,
		StreamID: streamID,
		Length:   4,
		Payload:  payload,
	}
}

// newPingFrame creates a PING frame on stream 0 with an opaque 4-byte payload.
func newPingFrame(opaque uint32) *frame {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, opaque)
	return &frame{
		Version:  ProtocolVersion,
		Type:     FramePing,
		Flags:    0,
		StreamID: 0,
		Length:   4,
		Payload:  payload,
	}
}

// newGoAwayFrame creates a GO_AWAY frame on stream 0 with an error code.
func newGoAwayFrame(code uint32) *frame {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, code)
	return &frame{
		Version:  ProtocolVersion,
		Type:     FrameGoAway,
		Flags:    0,
		StreamID: 0,
		Length:   4,
		Payload:  payload,
	}
}

// String returns a human-readable description of the frame for debugging.
func (f *frame) String() string {
	typeName := fmt.Sprintf("0x%02x", f.Type)
	switch f.Type {
	case FrameData:
		typeName = "DATA"
	case FrameSyn:
		typeName = "SYN"
	case FrameFin:
		typeName = "FIN"
	case FrameRst:
		typeName = "RST"
	case FramePing:
		typeName = "PING"
	case FrameGoAway:
		typeName = "GO_AWAY"
	}
	return fmt.Sprintf("frame{ver=%d type=%s flags=0x%04x stream=%d len=%d}",
		f.Version, typeName, f.Flags, f.StreamID, f.Length)
}
