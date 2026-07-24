package mesh

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// --- Junk train integration tests ---

// capturingBind is a test conn.Bind that records all packets sent through it.
type capturingBind struct {
	mu        sync.Mutex
	sent      [][]byte
	endpoints []conn.Endpoint
}

func (c *capturingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// Return a no-op receive func.
	return []conn.ReceiveFunc{func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		time.Sleep(10 * time.Millisecond)
		return 0, nil
	}}, port, nil
}
func (c *capturingBind) Close() error              { return nil }
func (c *capturingBind) SetMark(mark uint32) error { return nil }
func (c *capturingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, bufs...)
	for range bufs {
		c.endpoints = append(c.endpoints, ep)
	}
	return nil
}
func (c *capturingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &testEndpoint{addr: s}, nil
}
func (c *capturingBind) BatchSize() int { return 1 }

func (c *capturingBind) getSent() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.sent))
	copy(out, c.sent)
	return out
}

// testEndpoint implements conn.Endpoint for tests.
type testEndpoint struct {
	addr string
}

func (e *testEndpoint) ClearSrc()           {}
func (e *testEndpoint) SrcToString() string { return "" }
func (e *testEndpoint) DstToString() string { return e.addr }
func (e *testEndpoint) DstToBytes() []byte  { return []byte(e.addr) }
func (e *testEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *testEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// TestJunkTrainWiredInSend verifies that when Jc > 0 and the first packet is
// a handshake initiation, junk packets are sent before the real packet.
func TestJunkTrainWiredInSend(t *testing.T) {
	cb := &capturingBind{}
	ob := NewObfuscatingBind(cb)

	// Configure a peer with junk train enabled.
	cfg := DefaultObfuscationConfig()
	cfg.Jc = 5
	cfg.Jmin = 32
	cfg.Jmax = 128
	cfg.JitterMaxMs = 0 // disable jitter for deterministic test
	ob.SetObfuscatorWithConfig("peer-junk", ObfuscationPadded, cfg, true)

	// Create a handshake initiation packet.
	initPkt := makeInitiationPacket()
	ep := &testEndpoint{addr: "peer-junk"}

	// Send through the obfuscating bind.
	err := ob.Send([][]byte{initPkt}, ep)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}

	sent := cb.getSent()
	// Should have 5 junk packets + 1 real packet = 6 total.
	if len(sent) != 6 {
		t.Fatalf("expected 6 packets (5 junk + 1 real), got %d", len(sent))
	}

	// Verify the real packet (last one) round-trips through the obfuscator.
	realObf := ob.GetObfuscator("peer-junk")
	deobf, err := realObf.UnwrapInbound(sent[5])
	if err != nil {
		t.Fatalf("unwrap real packet: %v", err)
	}
	if !bytes.Equal(deobf, initPkt) {
		t.Error("real packet should round-trip after obfuscation")
	}
}

// TestJunkTrainDisabledWhenJcZero verifies no junk packets are sent when Jc=0.
func TestJunkTrainDisabledWhenJcZero(t *testing.T) {
	cb := &capturingBind{}
	ob := NewObfuscatingBind(cb)

	cfg := DefaultObfuscationConfig()
	cfg.Jc = 0 // disabled
	cfg.JitterMaxMs = 0
	ob.SetObfuscatorWithConfig("peer-nojunk", ObfuscationPadded, cfg, true)

	initPkt := makeInitiationPacket()
	ep := &testEndpoint{addr: "peer-nojunk"}

	err := ob.Send([][]byte{initPkt}, ep)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}

	sent := cb.getSent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 packet (no junk), got %d", len(sent))
	}
}

// TestJunkTrainOnlyBeforeInitiation verifies junk is only prepended for
// initiation packets, not for transport or other packet types.
func TestJunkTrainOnlyBeforeInitiation(t *testing.T) {
	cb := &capturingBind{}
	ob := NewObfuscatingBind(cb)

	cfg := DefaultObfuscationConfig()
	cfg.Jc = 3
	cfg.JitterMaxMs = 0
	ob.SetObfuscatorWithConfig("peer-transport", ObfuscationPadded, cfg, true)

	// Send a transport packet (not initiation).
	transportPkt := makePacketWithType(wgMsgTransport)
	ep := &testEndpoint{addr: "peer-transport"}

	err := ob.Send([][]byte{transportPkt}, ep)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}

	sent := cb.getSent()
	// Should have exactly 1 packet (no junk for transport).
	if len(sent) != 1 {
		t.Fatalf("expected 1 packet (no junk for transport), got %d", len(sent))
	}
}

// --- WebSocket transport integration tests ---

// TestWSBindSendReceive tests the full wsBind send and receive pipeline.
// A server wsListener accepts connections, reads WS frames, and enqueues
// them. A client wsBind sends packets through the obfuscatingBind, which
// routes them via wsBind.send(). We verify the packets arrive on the server.
func TestWSBindSendReceive(t *testing.T) {
	// Start a wsListener server (no TLS for testing).
	wsListener, err := ListenWebSocket("127.0.0.1:0", false, "", "")
	if err != nil {
		t.Fatalf("ListenWebSocket: %v", err)
	}
	defer wsListener.Close()
	addr := wsListener.listener.Addr().String()

	// Server-side: create a wsBind to hold received packets.
	serverWB := NewWSBind("", false, "", "", "", "")

	// Server goroutine: accept connections, read frames, enqueue packets.
	go func() {
		for {
			wt, err := wsListener.Accept()
			if err != nil {
				return
			}
			go func(wt *websocketTransport) {
				defer wt.conn.Close()
				for {
					payload, err := wt.wsConn.ReadFrame()
					if err != nil {
						return
					}
					serverWB.enqueueInbound(payload, wt.conn.RemoteAddr().String())
				}
			}(wt)
		}
	}()

	// Client-side: create a wsBind and wire it into an obfuscatingBind.
	clientWB := NewWSBind("", false, "", "", "", "")
	cb := &capturingBind{}
	ob := NewObfuscatingBind(cb)
	ob.SetWSBind(clientWB)

	// Set up the peer with websocket mode. The peer key must match what
	// endpoint.DstToString() returns — in this case, the address.
	cfg := DefaultObfuscationConfig()
	ob.SetObfuscatorWithConfig(addr, ObfuscationWebSocket, cfg, true)

	// Create test packet.
	pkt := makeInitiationPacket()
	ep := &testEndpoint{addr: addr}

	// Send through obfuscatingBind — should route through wsBind.
	err = ob.Send([][]byte{pkt}, ep)
	if err != nil {
		t.Fatalf("Send through wsBind: %v", err)
	}

	// Wait briefly for the server to receive and enqueue the packet.
	time.Sleep(200 * time.Millisecond)

	// Drain the server's receive queue.
	serverWB.recvMu.Lock()
	received := serverWB.recvQueue
	serverWB.recvQueue = nil
	serverWB.recvEPs = nil
	serverWB.recvMu.Unlock()

	if len(received) != 1 {
		t.Fatalf("expected 1 received packet, got %d", len(received))
	}

	// Verify the received packet matches what we sent.
	if !bytes.Equal(received[0], pkt) {
		t.Errorf("received packet mismatch: got %d bytes, want %d bytes", len(received[0]), len(pkt))
	}
}

// TestWSBindMultiplePackets verifies multiple packets can be sent through
// the wsBind in sequence.
func TestWSBindMultiplePackets(t *testing.T) {
	wsListener, err := ListenWebSocket("127.0.0.1:0", false, "", "")
	if err != nil {
		t.Fatalf("ListenWebSocket: %v", err)
	}
	defer wsListener.Close()
	addr := wsListener.listener.Addr().String()

	serverWB := NewWSBind("", false, "", "", "", "")

	go func() {
		for {
			t, err := wsListener.Accept()
			if err != nil {
				return
			}
			go func(wt *websocketTransport) {
				defer wt.conn.Close()
				for {
					payload, err := wt.wsConn.ReadFrame()
					if err != nil {
						return
					}
					serverWB.enqueueInbound(payload, wt.conn.RemoteAddr().String())
				}
			}(t)
		}
	}()

	clientWB := NewWSBind("", false, "", "", "", "")
	cb := &capturingBind{}
	ob := NewObfuscatingBind(cb)
	ob.SetWSBind(clientWB)

	cfg := DefaultObfuscationConfig()
	ob.SetObfuscatorWithConfig(addr, ObfuscationWebSocket, cfg, true)

	ep := &testEndpoint{addr: addr}

	// Send 3 different packets.
	packets := [][]byte{
		makeInitiationPacket(),
		makePacketWithType(wgMsgResponse),
		[]byte("test-data-12345"),
	}

	for _, pkt := range packets {
		err := ob.Send([][]byte{pkt}, ep)
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	// Wait for all packets to arrive.
	time.Sleep(300 * time.Millisecond)

	serverWB.recvMu.Lock()
	received := serverWB.recvQueue
	serverWB.recvQueue = nil
	serverWB.recvEPs = nil
	serverWB.recvMu.Unlock()

	if len(received) != 3 {
		t.Fatalf("expected 3 received packets, got %d", len(received))
	}

	for i, pkt := range packets {
		if !bytes.Equal(received[i], pkt) {
			t.Errorf("packet %d mismatch: got %d bytes, want %d bytes", i, len(received[i]), len(pkt))
		}
	}
}

// TestWSEndpointMethods verifies the wsEndpoint implements conn.Endpoint correctly.
func TestWSEndpointMethods(t *testing.T) {
	ep := &wsEndpoint{addr: "127.0.0.1:8080"}

	if ep.DstToString() != "127.0.0.1:8080" {
		t.Errorf("DstToString = %q, want %q", ep.DstToString(), "127.0.0.1:8080")
	}
	if len(ep.DstToBytes()) == 0 {
		t.Error("DstToBytes should not be empty")
	}
	ep.ClearSrc() // should not panic
	if ep.SrcToString() != "" {
		t.Error("SrcToString should be empty")
	}
}

// TestWSBindParseEndpoint verifies wsBind.ParseEndpoint creates a wsEndpoint.
func TestWSBindParseEndpoint(t *testing.T) {
	wb := NewWSBind("", false, "", "", "", "")
	ep, err := wb.ParseEndpoint("1.2.3.4:443")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if ep.DstToString() != "1.2.3.4:443" {
		t.Errorf("endpoint addr = %q, want %q", ep.DstToString(), "1.2.3.4:443")
	}
}

// TestWSBindBatchSizeAndSetMark verifies basic conn.Bind interface methods.
func TestWSBindBatchSizeAndSetMark(t *testing.T) {
	wb := NewWSBind("", false, "", "", "", "")
	if wb.BatchSize() != 1 {
		t.Errorf("BatchSize = %d, want 1", wb.BatchSize())
	}
	if err := wb.SetMark(0); err != nil {
		t.Errorf("SetMark: %v", err)
	}
}

// --- obfuscatingBind GetConfig test ---

// TestObfuscatingBindGetConfig verifies the GetConfig method returns the
// correct config for a peer.
func TestObfuscatingBindGetConfig(t *testing.T) {
	bind := NewObfuscatingBind(nil)
	cfg := DefaultObfuscationConfig()
	cfg.Jc = 7
	cfg.Jmin = 100
	cfg.Jmax = 500
	bind.SetObfuscatorWithConfig("peer-cfg", ObfuscationPadded, cfg, true)

	got := bind.GetConfig("peer-cfg")
	if got.Jc != 7 {
		t.Errorf("Jc = %d, want 7", got.Jc)
	}
	if got.Jmin != 100 {
		t.Errorf("Jmin = %d, want 100", got.Jmin)
	}
	if got.Jmax != 500 {
		t.Errorf("Jmax = %d, want 500", got.Jmax)
	}

	// Unknown peer should return default config.
	def := bind.GetConfig("unknown-peer")
	if def.Jc != 0 {
		t.Errorf("default Jc = %d, want 0", def.Jc)
	}
}

// Compile-time interface compliance checks.
var _ conn.Bind = (*capturingBind)(nil)
var _ conn.Endpoint = (*testEndpoint)(nil)
var _ conn.Endpoint = (*wsEndpoint)(nil)

// Suppress unused import (bufio, fmt used only in websocket test helpers
// in obfuscation.go; referenced here via wsConn which uses *bufio.Reader).
var _ = bufio.NewReader
var _ = fmt.Sprintf
var _ = binary.LittleEndian
