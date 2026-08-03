package mesh

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// ─── Framing tests ───

func TestWriteFramedPacket(t *testing.T) {
	var buf bytes.Buffer
	packet := []byte("hello world")

	if err := writeFramedPacket(&buf, packet); err != nil {
		t.Fatalf("writeFramedPacket: %v", err)
	}

	// First 4 bytes should be the length.
	if buf.Len() < 4 {
		t.Fatalf("buffer too short: %d bytes", buf.Len())
	}

	length := binary.BigEndian.Uint32(buf.Bytes()[:4])
	if length != uint32(len(packet)) {
		t.Fatalf("framed length = %d; want %d", length, len(packet))
	}

	// Rest should be the payload.
	payload := buf.Bytes()[4:]
	if !bytes.Equal(payload, packet) {
		t.Fatalf("payload mismatch: got %q; want %q", payload, packet)
	}
}

func TestReadFramedPacket(t *testing.T) {
	packet := []byte("hello world")
	var buf bytes.Buffer
	if err := writeFramedPacket(&buf, packet); err != nil {
		t.Fatalf("writeFramedPacket: %v", err)
	}

	got, err := readFramedPacket(&buf)
	if err != nil {
		t.Fatalf("readFramedPacket: %v", err)
	}

	if !bytes.Equal(got, packet) {
		t.Fatalf("readFramedPacket mismatch: got %q; want %q", got, packet)
	}
}

func TestReadFramedPacket_Empty(t *testing.T) {
	var buf bytes.Buffer
	// Write length = 0.
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 0)
	buf.Write(header[:])

	_, err := readFramedPacket(&buf)
	if err == nil {
		t.Fatal("readFramedPacket should fail on zero-length")
	}
}

func TestReadFramedPacket_TooLarge(t *testing.T) {
	var buf bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxTunPacketSize+1)
	buf.Write(header[:])

	_, err := readFramedPacket(&buf)
	if err == nil {
		t.Fatal("readFramedPacket should fail on oversized length")
	}
}

func TestFramedPacket_RoundTrip(t *testing.T) {
	// Test multiple packets in sequence.
	var buf bytes.Buffer

	packets := [][]byte{
		[]byte("first packet"),
		[]byte("second"),
		[]byte("third packet with more data"),
	}

	for _, p := range packets {
		if err := writeFramedPacket(&buf, p); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	for i, expected := range packets {
		got, err := readFramedPacket(&buf)
		if err != nil {
			t.Fatalf("read[%d]: %v", i, err)
		}
		if !bytes.Equal(got, expected) {
			t.Fatalf("read[%d] mismatch: got %q; want %q", i, got, expected)
		}
	}
}

// ─── IP parsing tests ───

func TestParseDstIP_IPv4(t *testing.T) {
	// Build a minimal IPv4 packet.
	// Version/IHL = 0x45 (IPv4, 20-byte header).
	// Total length = 20 (just header, no payload).
	packet := make([]byte, 20)
	packet[0] = 0x45
	// Set destination IP at offset 16-19.
	dst := net.ParseIP("10.10.0.5").To4()
	copy(packet[16:20], dst)

	got, err := parseDstIP(packet)
	if err != nil {
		t.Fatalf("parseDstIP: %v", err)
	}
	if !got.Equal(dst) {
		t.Fatalf("parseDstIP = %s; want %s", got, dst)
	}
}

func TestParseSrcIP_IPv4(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45
	src := net.ParseIP("10.10.0.3").To4()
	copy(packet[12:16], src)
	dst := net.ParseIP("10.10.0.5").To4()
	copy(packet[16:20], dst)

	gotSrc, err := parseSrcIP(packet)
	if err != nil {
		t.Fatalf("parseSrcIP: %v", err)
	}
	if !gotSrc.Equal(src) {
		t.Fatalf("parseSrcIP = %s; want %s", gotSrc, src)
	}

	gotDst, err := parseDstIP(packet)
	if err != nil {
		t.Fatalf("parseDstIP: %v", err)
	}
	if !gotDst.Equal(dst) {
		t.Fatalf("parseDstIP = %s; want %s", gotDst, dst)
	}
}

func TestParseDstIP_IPv6(t *testing.T) {
	// Build a minimal IPv6 packet (40-byte header).
	packet := make([]byte, 40)
	packet[0] = 0x60 // Version 6

	dst := net.ParseIP("fd00::5")
	copy(packet[24:40], dst)

	got, err := parseDstIP(packet)
	if err != nil {
		t.Fatalf("parseDstIP: %v", err)
	}
	if !got.Equal(dst) {
		t.Fatalf("parseDstIP = %s; want %s", got, dst)
	}
}

func TestParseSrcIP_IPv6(t *testing.T) {
	packet := make([]byte, 40)
	packet[0] = 0x60

	src := net.ParseIP("fd00::3")
	copy(packet[8:24], src)

	got, err := parseSrcIP(packet)
	if err != nil {
		t.Fatalf("parseSrcIP: %v", err)
	}
	if !got.Equal(src) {
		t.Fatalf("parseSrcIP = %s; want %s", got, src)
	}
}

func TestParseDstIP_TooShort(t *testing.T) {
	// IPv4 with less than 20 bytes.
	packet := []byte{0x45, 0x00, 0x00}
	_, err := parseDstIP(packet)
	if err == nil {
		t.Fatal("parseDstIP should fail on short packet")
	}
}

func TestParseDstIP_Empty(t *testing.T) {
	_, err := parseDstIP([]byte{})
	if err == nil {
		t.Fatal("parseDstIP should fail on empty packet")
	}
}

func TestParseDstIP_UnknownVersion(t *testing.T) {
	// Version 5 (neither IPv4 nor IPv6).
	packet := make([]byte, 40)
	packet[0] = 0x50
	_, err := parseDstIP(packet)
	if err == nil {
		t.Fatal("parseDstIP should fail on unknown version")
	}
}

// ─── Utility tests ───

func TestShortKey(t *testing.T) {
	// Short key (≤16 chars).
	short := "abcdef1234567890"
	if got := shortKey(short); got != short {
		t.Fatalf("shortKey(%q) = %q; want %q", short, got, short)
	}

	// Long key.
	long := "abcdef1234567890abcdef1234567890abcdef"
	got := shortKey(long)
	if len(got) < 16 {
		t.Fatalf("shortKey result too short: %q", got)
	}
	if got[:16] != long[:16] {
		t.Fatalf("shortKey prefix mismatch: got %q; want %q", got[:16], long[:16])
	}
}

// ─── TunForwarder construction tests ───

func TestNewTunForwarder_MissingDevice(t *testing.T) {
	_, err := NewTunForwarder(TunForwarderConfig{
		Router:   nil,
		MeshNode: nil,
	})
	if err == nil {
		t.Fatal("NewTunForwarder should fail without Device")
	}
}

func TestNewTunForwarder_NilConfig(t *testing.T) {
	_, err := NewTunForwarder(TunForwarderConfig{})
	if err == nil {
		t.Fatal("NewTunForwarder should fail with empty config")
	}
}

// ─── readFramedPacket with truncated data ───

func TestReadFramedPacket_Truncated(t *testing.T) {
	// Write length = 100 but only provide 10 bytes.
	var buf bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 100)
	buf.Write(header[:])
	buf.Write(make([]byte, 10))

	_, err := readFramedPacket(&buf)
	if err == nil {
		t.Fatal("readFramedPacket should fail on truncated data")
	}
	if err != io.ErrUnexpectedEOF && err != io.EOF {
		// io.ReadFull returns ErrUnexpectedEOF when partial data is read.
		// Either is acceptable.
	}
}
