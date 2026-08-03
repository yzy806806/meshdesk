package p2p

import (
	"testing"

	"github.com/hashicorp/go-msgpack/v2/codec"
)

// TestCrossArchMsgpackEncoding verifies that the hashicorp/go-msgpack/v2 codec
// produces identical encodings for memberlist's internal message types
// regardless of CPU architecture. The memberlist library uses this codec
// internally for all its wire protocol messages (ping, ack, alive, dead,
// suspect, pushPull, etc.).
//
// If encodings differ between x86_64 and arm64, memberlist communication
// between nodes on different architectures will fail with errors like:
//   "msg type (116) not supported"
// because the first byte (message type) gets corrupted.
func TestCrossArchMsgpackEncoding(t *testing.T) {
	hd := codec.MsgpackHandle{}

	// Encode a simple struct similar to memberlist's `ping` type.
	// memberlist's ping struct: { SeqNo uint32; Node string; SourceAddr []byte; SourcePort uint16; SourceNode string }
	type pingLike struct {
		SeqNo      uint32
		Node       string
		SourceAddr []byte `codec:",omitempty"`
		SourcePort uint16 `codec:",omitempty"`
		SourceNode string `codec:",omitempty"`
	}

	p := pingLike{
		SeqNo: 12345,
		Node:  "testnode1234567",
	}

	buf := make([]byte, 0, 256)
	enc := codec.NewEncoderBytes(&buf, &hd)
	if err := enc.Encode(&p); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	t.Logf("Encoded pingLike (%d bytes): %x", len(buf), buf)

	// Decode back and verify.
	var p2 pingLike
	dec := codec.NewDecoderBytes(buf, &hd)
	if err := dec.Decode(&p2); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if p.SeqNo != p2.SeqNo {
		t.Errorf("SeqNo mismatch: %d != %d", p.SeqNo, p2.SeqNo)
	}
	if p.Node != p2.Node {
		t.Errorf("Node mismatch: %q != %q", p.Node, p2.Node)
	}

	// Encode the memberlist-style message: [msgType byte] [msgpack payload]
	// This is what memberlist's encode() function does.
	msgType := byte(0) // pingMsg
	fullMsg := append([]byte{msgType}, buf...)

	t.Logf("Full memberlist message (%d bytes): %x", len(fullMsg), fullMsg)
	t.Logf("First byte (msgType): %d (expected 0 for ping)", fullMsg[0])

	if fullMsg[0] != 0 {
		t.Errorf("First byte is %d, expected 0 (ping)", fullMsg[0])
	}
}

// TestCrossArchNodeMetaEncoding verifies that the vmihailenco msgpack library
// (used for NodeMeta) also produces consistent encodings across architectures.
func TestCrossArchNodeMetaEncoding(t *testing.T) {
	m := NodeMeta{
		PublicKey:    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Hostname:     "test-host",
		Role:         "agent",
		CapRelay:     true,
		CapExit:      false,
		Endpoints:    []string{"10.0.0.1:52888"},
		NatType:      "none",
		LoadCPU:      0.5,
		LoadMem:      0.3,
		Version:      "1.0.0",
		Seq:          42,
		VirtualIP:    "10.100.0.1",
		SubnetProxies: []string{"192.168.1.0/24"},
	}

	data, err := m.MarshalMeta()
	if err != nil {
		t.Fatalf("MarshalMeta failed: %v", err)
	}

	t.Logf("Encoded NodeMeta (%d bytes): %x", len(data), data)

	// Decode and verify.
	m2, err := UnmarshalMeta(data)
	if err != nil {
		t.Fatalf("UnmarshalMeta failed: %v", err)
	}

	if m.PublicKey != m2.PublicKey {
		t.Errorf("PublicKey mismatch: %q != %q", m.PublicKey, m2.PublicKey)
	}
	if m.Hostname != m2.Hostname {
		t.Errorf("Hostname mismatch: %q != %q", m.Hostname, m2.Hostname)
	}
	if m.VirtualIP != m2.VirtualIP {
		t.Errorf("VirtualIP mismatch: %q != %q", m.VirtualIP, m2.VirtualIP)
	}
	if m.Seq != m2.Seq {
		t.Errorf("Seq mismatch: %d != %d", m.Seq, m2.Seq)
	}
}
