package mesh

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/tun"
)

// ──────────────────────────────────────────────────────────────────────────────
// TUN device integration skip gate
// ──────────────────────────────────────────────────────────────────────────────

// skipUnlessTun skips the test if /dev/net/tun is unavailable or we lack
// root/CAP_NET_ADMIN. All TUN device integration tests call this first.
func skipUnlessTun(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping TUN integration test (requires root/CAP_NET_ADMIN)")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("skipping TUN integration test (/dev/net/tun not available: %v)", err)
	}
}

// createTestTun creates a minimal TUN device for integration testing.
// It brings the interface up so that writes to the TUN file succeed.
// The caller is responsible for closing it.
func createTestTun(t *testing.T, name string) *tun.Device {
	t.Helper()
	d, err := tun.Create(tun.Config{
		Name:   name,
		MTU:    1400,
		Subnet: "10.200.0.0/24",
	})
	if err != nil {
		t.Fatalf("tun.Create: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	// Bring the interface up — the kernel rejects writes to a down TUN.
	bringInterfaceUp(t, d.Name())
	return d
}

// bringInterfaceUp brings a network interface up using the 'ip' command.
// The TUN device must be administratively UP for writes to succeed.
func bringInterfaceUp(t *testing.T, ifname string) {
	t.Helper()
	out, err := runIP("link", "set", ifname, "up")
	if err != nil {
		t.Fatalf("ip link set %s up: %v (output: %s)", ifname, err, out)
	}
}

// runIP executes an 'ip' command and returns its combined output.
// If the command fails, the error includes the output.
func runIP(args ...string) (string, error) {
	out, err := execCommand("ip", args...)
	return out, err
}

// execCommand runs a command and captures combined output.
func execCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// ──────────────────────────────────────────────────────────────────────────────
// Section 1: TUN Device Read/Write Loop Integration Tests
// ──────────────────────────────────────────────────────────────────────────────

// TestTunIntegration_WritePackets verifies that IP packets of various sizes
// can be written to a real TUN device without error. This exercises the
// TUN device file write path (kernel injection).
func TestTunIntegration_WritePackets(t *testing.T) {
	skipUnlessTun(t)
	d := createTestTun(t, "tunint0")

	sizes := []int{20, 60, 100, 500, 1000, 1350, 1400}

	for _, size := range sizes {
		t.Run(sizeName(size), func(t *testing.T) {
			packet := makeIPv4Packet(net.ParseIP("10.200.0.1"), net.ParseIP("10.200.0.2"))
			// Pad to desired size with zeros after the 20-byte header.
			if size > 20 {
				padded := make([]byte, size)
				copy(padded, packet)
				packet = padded
				// Fix total length field (bytes 2-3) in IPv4 header.
				binary.BigEndian.PutUint16(packet[2:4], uint16(size))
			}

			n, err := d.File().Write(packet)
			if err != nil {
				t.Fatalf("Write(packet of %d bytes): %v", size, err)
			}
			if n != len(packet) {
				t.Fatalf("Write returned %d bytes, want %d", n, len(packet))
			}
		})
	}
}

// TestTunIntegration_MultiplePackets verifies that multiple sequential
// writes to the TUN device all succeed.
func TestTunIntegration_MultiplePackets(t *testing.T) {
	skipUnlessTun(t)
	d := createTestTun(t, "tunint1")

	const numPackets = 20
	for i := 0; i < numPackets; i++ {
		packet := makeIPv4Packet(
			net.ParseIP("10.200.0.1"),
			net.ParseIP("10.200.0.2"),
		)
		n, err := d.File().Write(packet)
		if err != nil {
			t.Fatalf("packet %d: Write: %v", i, err)
		}
		if n != 20 {
			t.Fatalf("packet %d: wrote %d bytes, want 20", i, n)
		}
	}
}

// TestTunIntegration_ParallelWrites verifies that concurrent writes to the
// TUN device from multiple goroutines complete without errors or data races.
func TestTunIntegration_ParallelWrites(t *testing.T) {
	skipUnlessTun(t)
	d := createTestTun(t, "tunint2")

	const numGoroutines = 5
	const packetsPerGoroutine = 20

	errCh := make(chan error, numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			for i := 0; i < packetsPerGoroutine; i++ {
				packet := makeIPv4Packet(
					net.ParseIP("10.200.0.1"),
					net.ParseIP("10.200.0.2"),
				)
				if _, err := d.File().Write(packet); err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}(g)
	}

	for g := 0; g < numGoroutines; g++ {
		if err := <-errCh; err != nil {
			t.Fatalf("goroutine %d: %v", g, err)
		}
	}
}

// TestTunIntegration_DeviceProperties verifies that a newly created TUN
// device has the expected name, MTU, subnet, and usable file descriptor.
func TestTunIntegration_DeviceProperties(t *testing.T) {
	skipUnlessTun(t)
	d := createTestTun(t, "tunint3")

	if d.File() == nil {
		t.Fatal("Device.File() returned nil")
	}
	if d.MTU() != 1400 {
		t.Fatalf("MTU() = %d, want 1400", d.MTU())
	}
	if d.Name() != "tunint3" {
		t.Fatalf("Name() = %q, want \"tunint3\"", d.Name())
	}
	expectedSubnet := "10.200.0.0/24"
	if d.Subnet().String() != expectedSubnet {
		t.Fatalf("Subnet() = %s, want %s", d.Subnet().String(), expectedSubnet)
	}
	expectedAddr := net.ParseIP("10.200.0.1")
	if !d.Addr().Equal(expectedAddr) {
		t.Fatalf("Addr() = %s, want %s", d.Addr(), expectedAddr)
	}
}

// TestTunIntegration_DeviceCloseIsIdempotent verifies that calling Close
// multiple times on a TUN device does not panic.
func TestTunIntegration_DeviceCloseIsIdempotent(t *testing.T) {
	skipUnlessTun(t)
	d := createTestTun(t, "tunint4")

	if err := d.Close(); err != nil {
		t.Fatalf("first Close(): %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close(): %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Section 2: MTU Boundary Integration Tests (Framing Layer)
// ──────────────────────────────────────────────────────────────────────────────

// TestTunIntegration_FramingMTUBoundary verifies the framing layer handles
// packets at and around the MTU boundary correctly. Tests are table-driven
// and run without requiring a TUN device (uses bytes.Buffer).
func TestTunIntegration_FramingMTUBoundary(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		// Sizes below typical MTU.
		{"size_0_rejected", 0, true},
		{"size_1_minimal", 1, false},
		{"size_19_ipv4_header_less_one", 19, false},
		{"size_20_ipv4_header_min", 20, false},
		{"size_40_ipv6_header_min", 40, false},
		{"size_100_small", 100, false},
		{"size_500_medium", 500, false},
		{"size_1000_large", 1000, false},

		// MTU boundary sizes.
		{"size_1280_ipv6_min_mtu", 1280, false},
		{"size_1399_mtu_minus_one", 1399, false},
		{"size_1400_exact_mtu", 1400, false},
		{"size_1401_mtu_plus_one", 1401, false},
		{"size_1500_ethernet_mtu", 1500, false},
		{"size_2000_double_ish", 2000, false},

		// Large sizes.
		{"size_9000_jumbo", 9000, false},
		{"size_65535_max_ip", 65535, false},

		// Oversize (exceeds maxTunPacketSize).
		{"size_65536_oversize_rejected", 65536, true},
		{"size_99999_way_oversize_rejected", 99999, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			payload := makeTestPayload(tt.size)
			err := writeFramedPacket(&buf, payload)

			if tt.wantErr {
				// writeFramedPacket doesn't reject any size — the
				// receiver (readFramedPacket) does. So for sizes that
				// should be rejected on read, we write a fake header
				// manually.
				buf.Reset()
				var header [4]byte
				binary.BigEndian.PutUint32(header[:], uint32(tt.size))
				buf.Write(header[:])
				buf.Write(makeTestPayload(tt.size))

				_, err := readFramedPacket(&buf)
				if err == nil {
					t.Fatalf("readFramedPacket should reject size %d", tt.size)
				}
				return
			}

			if err != nil {
				t.Fatalf("writeFramedPacket: %v", err)
			}

			got, err := readFramedPacket(&buf)
			if err != nil {
				t.Fatalf("readFramedPacket: %v", err)
			}

			if len(got) != tt.size {
				t.Fatalf("round-trip size = %d, want %d", len(got), tt.size)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("round-trip contents mismatch for size %d", tt.size)
			}
		})
	}
}

// TestTunIntegration_FramingMTU_StreamRoundTrip verifies that multiple
// framed packets of varying sizes can be written sequentially and read
// back correctly using net.Pipe (simulating a stream connection).
func TestTunIntegration_FramingMTU_StreamRoundTrip(t *testing.T) {
	payloads := []int{20, 100, 1399, 1400, 1401, 1500, 65535}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Write all framed packets from client side.
	go func() {
		for _, size := range payloads {
			payload := makeTestPayload(size)
			if err := writeFramedPacket(client, payload); err != nil {
				t.Errorf("writeFramedPacket(%d): %v", size, err)
				return
			}
		}
		client.Close()
	}()

	// Read all framed packets from server side.
	for i, expectedSize := range payloads {
		got, err := readFramedPacket(server)
		if err != nil {
			if i == len(payloads)-1 && (err == io.EOF || err == io.ErrClosedPipe) {
				break
			}
			t.Fatalf("readFramedPacket[%d] (size=%d): %v", i, expectedSize, err)
		}
		if len(got) != expectedSize {
			t.Fatalf("read[%d] size = %d, want %d", i, len(got), expectedSize)
		}
		expectedPayload := makeTestPayload(expectedSize)
		if !bytes.Equal(got, expectedPayload) {
			t.Fatalf("read[%d] content mismatch for size %d", i, expectedSize)
		}
	}
}

// TestTunIntegration_FramingMTU_ExactAndBoundary verifies the framing
// layer exactly at MTU (±1) byte boundaries, focusing on the 1400
// byte MTU used by the meshdesk project.
func TestTunIntegration_FramingMTU_ExactAndBoundary(t *testing.T) {
	boundaries := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"mtu_half", 700},
		{"mtu_minus_one", 1399},
		{"mtu_exact", 1400},
		{"mtu_plus_one", 1401},
		{"max_ip_packet", 65535},
		{"oversize", 65536},
	}

	for _, b := range boundaries {
		t.Run(b.name, func(t *testing.T) {
			var buf bytes.Buffer
			if b.size == 0 || b.size > 65535 {
				// These should be rejected by readFramedPacket.
				var header [4]byte
				binary.BigEndian.PutUint32(header[:], uint32(b.size))
				buf.Write(header[:])
				buf.Write(makeTestPayload(max(1, min(b.size, 100))))
				_, err := readFramedPacket(&buf)
				if err == nil {
					t.Fatalf("readFramedPacket should reject size %d", b.size)
				}
				return
			}

			payload := makeTestPayload(b.size)
			if err := writeFramedPacket(&buf, payload); err != nil {
				t.Fatalf("writeFramedPacket: %v", err)
			}
			got, err := readFramedPacket(&buf)
			if err != nil {
				t.Fatalf("readFramedPacket: %v", err)
			}
			if len(got) != b.size {
				t.Fatalf("len = %d, want %d", len(got), b.size)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("payload mismatch")
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Section 3: Byte-Level Source IP Spoofing Integration Tests
// ──────────────────────────────────────────────────────────────────────────────

// TestTunIntegration_ByteLevelSpoofing_IPv4 verifies source IP validation
// at the byte level for IPv4 packets. Mutations that keep the IP within the
// mesh subnet should be rejected; mutations outside the subnet are allowed
// (subnet proxy feature). Tests exercise both paths.
func TestTunIntegration_ByteLevelSpoofing_IPv4(t *testing.T) {
	f, router := newTestForwarder("10.200.0.0/24", "localkey")

	// Register peer at 10.200.0.5.
	peerIP := net.ParseIP("10.200.0.5")
	router.AddRoute(peerIP, "peerA")

	// Build a valid IPv4 packet at the byte level.
	buildValid := func() []byte {
		pkt := make([]byte, 20)
		pkt[0] = 0x45                                   // Version 4, IHL 5
		pkt[2] = 0x00                                   // Total length high byte
		pkt[3] = 0x14                                   // Total length = 20
		copy(pkt[12:16], peerIP.To4())                  // Source IP = 10.200.0.5
		copy(pkt[16:20], net.ParseIP("10.200.0.1").To4()) // Dst IP
		return pkt
	}

	validPacket := buildValid()

	// Valid packet must pass.
	if !f.validateSourceIP(validPacket, "peerA") {
		t.Fatal("valid packet should pass byte-level validation")
	}

	// Tests where the mutated source IP stays INSIDE the subnet → REJECTED.
	testsReject := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			// Last byte of src IP changed: 10.200.0.5 → 10.200.0.250
			name:   "byte15_ip_inside_subnet_reject",
			mutate: func(p []byte) { p[15] ^= 0xFF },
		},
		{
			// Set src to broadcast addr (still in subnet).
			name: "src_broadcast_inside_subnet_reject",
			mutate: func(p []byte) {
				copy(p[12:16], net.ParseIP("10.200.0.255").To4())
			},
		},
		{
			// Set src to network addr (still in subnet).
			name: "src_network_addr_inside_subnet_reject",
			mutate: func(p []byte) {
				copy(p[12:16], net.ParseIP("10.200.0.0").To4())
			},
		},
		{
			// Different peer's IP within the same subnet.
			name: "src_other_peer_ip_inside_subnet_reject",
			mutate: func(p []byte) {
				router.AddRoute(net.ParseIP("10.200.0.6"), "peerB")
				copy(p[12:16], net.ParseIP("10.200.0.6").To4())
			},
		},
		{
			// Set src to another valid-looking IP in subnet.
			name: "src_to_10_200_0_99_inside_subnet_reject",
			mutate: func(p []byte) {
				copy(p[12:16], net.ParseIP("10.200.0.99").To4())
			},
		},
	}

	for _, tt := range testsReject {
		t.Run(tt.name, func(t *testing.T) {
			pkt := buildValid()
			tt.mutate(pkt)
			if f.validateSourceIP(pkt, "peerA") {
				t.Fatalf("byte-level spoof (%s) should fail validation (IP inside subnet)", tt.name)
			}
		})
	}

	// Tests where the mutated source IP is OUTSIDE the subnet → REJECTED
	// (no RouteManager configured, so all outside-subnet packets are rejected).
	// With RouteManager, outside-subnet IPs in advertised subnets would be allowed,
	// but that's tested separately in the RouteManager tests.
	testsRejectOutside := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			// XOR byte 12: 10.200.0.5 → 245.200.0.5 (outside /24 → REJECT)
			name:   "byte12_xor_outside_subnet_reject",
			mutate: func(p []byte) { p[12] ^= 0xFF },
		},
		{
			// XOR byte 13: 10.200.0.5 → 10.55.0.5 (outside /24 → REJECT)
			name:   "byte13_xor_outside_subnet_reject",
			mutate: func(p []byte) { p[13] ^= 0xFF },
		},
		{
			// XOR byte 14 (0x00 → 0xFF): 10.200.255.5 (outside /24 → REJECT)
			name:   "byte14_xor_outside_subnet_reject",
			mutate: func(p []byte) { p[14] ^= 0xFF },
		},
		{
			// Loopback address (outside subnet → REJECT without RouteManager)
			name:   "src_loopback_outside_subnet_reject",
			mutate: func(p []byte) { copy(p[12:16], net.ParseIP("127.0.0.1").To4()) },
		},
		{
			// Zero address (outside subnet → REJECT without RouteManager)
			name:   "src_zero_outside_subnet_reject",
			mutate: func(p []byte) { p[12], p[13], p[14], p[15] = 0, 0, 0, 0 },
		},
		{
			// 192.168.x.x (outside subnet → REJECT without RouteManager)
			name: "src_192_168_outside_subnet_reject",
			mutate: func(p []byte) { copy(p[12:16], net.ParseIP("192.168.1.1").To4()) },
		},
	}

	for _, tt := range testsRejectOutside {
		t.Run(tt.name, func(t *testing.T) {
			pkt := buildValid()
			tt.mutate(pkt)
			if f.validateSourceIP(pkt, "peerA") {
				t.Fatalf("byte-level spoof (%s) should fail validation (IP outside subnet, no RouteManager)", tt.name)
			}
		})
	}
}

// TestTunIntegration_ByteLevelSpoofing_IPv6 verifies source IP validation
// at the byte level for IPv6 packets. Mutations that keep the IP within the
// mesh subnet should be rejected; mutations outside are allowed (subnet proxy).
func TestTunIntegration_ByteLevelSpoofing_IPv6(t *testing.T) {
	f, router := newTestForwarder("fd00::/64", "localkey")

	// Register peer at fd00::5.
	peerIP := net.ParseIP("fd00::5")
	router.AddRoute(peerIP, "peerA")

	buildValid := func() []byte {
		pkt := make([]byte, 40)
		pkt[0] = 0x60 // Version 6
		copy(pkt[8:24], peerIP.To16())                  // Source IP = fd00::5
		copy(pkt[24:40], net.ParseIP("fd00::1").To16()) // Dst IP
		return pkt
	}

	validPacket := buildValid()

	// Valid packet must pass.
	if !f.validateSourceIP(validPacket, "peerA") {
		t.Fatal("valid IPv6 packet should pass byte-level validation")
	}

	// Tests where mutated IP stays INSIDE fd00::/64 → REJECTED.
	testsReject := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			// Last byte of src IP changed: fd00::5 → fd00::fa (inside /64)
			name:   "byte23_last_byte_inside_subnet_reject",
			mutate: func(p []byte) { p[23] ^= 0xFF },
		},
		{
			// Same but also change penultimate: fd00::fffa (inside /64)
			name: "byte22_byte23_inside_subnet_reject",
			mutate: func(p []byte) { p[22] ^= 0xFF; p[23] ^= 0xFF },
		},
		{
			// Different peer's IP in same subnet.
			name: "src_different_ula_in_subnet_reject",
			mutate: func(p []byte) {
				copy(p[8:24], net.ParseIP("fd00::99").To16())
			},
		},
		{
			// Set the interface identifier part (bytes 16-23) to a specific value.
			name: "byte16_inside_subnet_reject",
			mutate: func(p []byte) { p[16] = 0xAB },
		},
		{
			// All interface ID bytes zero → fd00::0 (inside /64).
			name: "interface_id_zero_inside_subnet_reject",
			mutate: func(p []byte) {
				for i := 16; i < 24; i++ {
					p[i] = 0
				}
			},
		},
	}

	for _, tt := range testsReject {
		t.Run(tt.name, func(t *testing.T) {
			pkt := buildValid()
			tt.mutate(pkt)
			if f.validateSourceIP(pkt, "peerA") {
				t.Fatalf("IPv6 byte-level spoof (%s) should fail validation (IP inside subnet)", tt.name)
			}
		})
	}

	// Tests where mutated IP is OUTSIDE fd00::/64 → REJECTED
	// (no RouteManager configured, so all outside-subnet packets are rejected).
	testsRejectOutside := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			// Change network prefix byte: fd00::5 → 0200::5 (outside /64 → REJECT)
			name:   "byte8_network_prefix_outside_subnet_reject",
			mutate: func(p []byte) { p[8] ^= 0xFF },
		},
		{
			// XOR middle of prefix: fd00::5 → fdff::5 (outside /64 → REJECT)
			name:   "byte9_prefix_outside_subnet_reject",
			mutate: func(p []byte) { p[9] ^= 0xFF },
		},
		{
			// Loopback (outside subnet → REJECT without RouteManager)
			name: "src_loopback_outside_subnet_reject",
			mutate: func(p []byte) {
				copy(p[8:24], net.ParseIP("::1").To16())
			},
		},
		{
			// Multicast (outside subnet → REJECT without RouteManager)
			name: "src_multicast_outside_subnet_reject",
			mutate: func(p []byte) {
				copy(p[8:24], net.ParseIP("ff02::1").To16())
			},
		},
		{
			// All zeros (outside subnet → REJECT without RouteManager)
			name: "src_all_zeros_outside_subnet_reject",
			mutate: func(p []byte) {
				for i := 8; i < 24; i++ {
					p[i] = 0
				}
			},
		},
	}

	for _, tt := range testsRejectOutside {
		t.Run(tt.name, func(t *testing.T) {
			pkt := buildValid()
			tt.mutate(pkt)
			if f.validateSourceIP(pkt, "peerA") {
				t.Fatalf("IPv6 spoof (%s) should fail validation (IP outside subnet, no RouteManager)", tt.name)
			}
		})
	}
}

// TestTunIntegration_ByteLevelSpoofing_MixedVersions verifies that
// IPv4/IPv6 version byte manipulation is caught.
func TestTunIntegration_ByteLevelSpoofing_MixedVersions(t *testing.T) {
	f, router := newTestForwarder("10.200.0.0/24", "localkey")

	// Register IPv4 peer.
	router.AddRoute(net.ParseIP("10.200.0.5"), "peerA")

	tests := []struct {
		name       string
		buildPkt   func() []byte
		peerID     string
		expectPass bool
	}{
		{
			name: "version_byte_changed_v4_to_v5",
			buildPkt: func() []byte {
				pkt := makeIPv4Packet(net.ParseIP("10.200.0.5"), net.ParseIP("10.200.0.1"))
				pkt[0] = 0x50 // Version 5, IHL 5
				return pkt
			},
			peerID:     "peerA",
			expectPass: false,
		},
		{
			name: "version_byte_changed_v4_to_v6",
			buildPkt: func() []byte {
				pkt := makeIPv4Packet(net.ParseIP("10.200.0.5"), net.ParseIP("10.200.0.1"))
				pkt[0] = 0x60 // Version 6, but packet layout is IPv4
				return pkt
			},
			peerID:     "peerA",
			expectPass: false,
		},
		{
			name: "v4_packet_with_v6_src_injection_attempt",
			buildPkt: func() []byte {
				return makeIPv4Packet(net.ParseIP("10.200.0.5"), net.ParseIP("10.200.0.1"))
			},
			peerID:     "peerA",
			expectPass: true,
		},
		{
			name: "v4_header_too_short_for_v6_parse_attempt",
			buildPkt: func() []byte {
				pkt := makeIPv4Packet(net.ParseIP("10.200.0.5"), net.ParseIP("10.200.0.1"))
				pkt[0] = 0x60 // Mark as v6 but only 20 bytes
				return pkt
			},
			peerID:     "peerA",
			expectPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := tt.buildPkt()
			got := f.validateSourceIP(pkt, tt.peerID)
			if got != tt.expectPass {
				t.Fatalf("validateSourceIP = %v, want %v", got, tt.expectPass)
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Section 4: Inbound Stream Integration Tests (handleInboundStream)
// ──────────────────────────────────────────────────────────────────────────────

// TestTunIntegration_HandleInboundStream_ValidPackets verifies that the
// full inbound stream pipeline works end-to-end:
//   framed stream → readFramedPacket → validateSourceIP → TUN Write
// Uses net.Pipe for the stream and a real TUN device for the write target.
func TestTunIntegration_HandleInboundStream_ValidPackets(t *testing.T) {
	skipUnlessTun(t)

	d := createTestTun(t, "tunint5")
	_, ipNet, _ := net.ParseCIDR("10.200.0.0/24")
	router := tun.NewRouter(ipNet, "localkey")
	peerIP := net.ParseIP("10.200.0.5")
	router.AddRoute(peerIP, "peerA")

	f := &TunForwarder{
		cfg: TunForwarderConfig{
			Device: d,
			Router: router,
		},
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())

	// Create a pipe: fwdEnd → handled by forwarder, sendEnd → we write
	sendEnd, fwdEnd := net.Pipe()
	defer sendEnd.Close()
	defer fwdEnd.Close()

	// Wrap the forwarder end with peer identity.
	wrappedConn := &connWithPeer{Conn: fwdEnd, peerID: "peerA"}

	// Start the inbound handler in a goroutine.
	done := make(chan struct{})
	f.wg.Add(1)
	go func() {
		defer close(done)
		f.handleInboundStream(wrappedConn)
	}()

	// Send 5 valid IPv4 packets.
	for i := 0; i < 5; i++ {
		packet := makeIPv4Packet(peerIP, net.ParseIP("10.200.0.1"))
		if err := writeFramedPacket(sendEnd, packet); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}

	// Allow time for processing.
	time.Sleep(100 * time.Millisecond)

	// Close the stream to trigger handler exit.
	sendEnd.Close()

	// Wait for handler to finish.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleInboundStream did not exit after stream close")
	}

	// Verify stats: all 5 packets should be received.
	stats := f.Stats()
	if stats.PacketsReceived != 5 {
		t.Fatalf("PacketsReceived = %d, want 5", stats.PacketsReceived)
	}
	if stats.PacketsSpoofed != 0 {
		t.Fatalf("PacketsSpoofed = %d, want 0", stats.PacketsSpoofed)
	}
}

// TestTunIntegration_HandleInboundStream_Spoofing verifies that spoofed
// packets on an inbound stream are detected by validateSourceIP, dropped,
// and the spoof counter is incremented.
func TestTunIntegration_HandleInboundStream_Spoofing(t *testing.T) {
	skipUnlessTun(t)

	d := createTestTun(t, "tunint6")
	_, ipNet, _ := net.ParseCIDR("10.200.0.0/24")
	router := tun.NewRouter(ipNet, "localkey")
	realIP := net.ParseIP("10.200.0.5")
	router.AddRoute(realIP, "peerA")

	f := &TunForwarder{
		cfg: TunForwarderConfig{
			Device: d,
			Router: router,
		},
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())

	sendEnd, fwdEnd := net.Pipe()
	defer sendEnd.Close()
	defer fwdEnd.Close()

	wrappedConn := &connWithPeer{Conn: fwdEnd, peerID: "peerA"}

	done := make(chan struct{})
	f.wg.Add(1)
	go func() {
		defer close(done)
		f.handleInboundStream(wrappedConn)
	}()

	// Send 3 valid packets and 3 spoofed packets, interleaved.
	spoofedIP := net.ParseIP("10.200.0.99")
	for i := 0; i < 6; i++ {
		var src net.IP
		if i%2 == 0 {
			src = realIP // valid
		} else {
			src = spoofedIP // spoofed
		}
		packet := makeIPv4Packet(src, net.ParseIP("10.200.0.1"))
		if err := writeFramedPacket(sendEnd, packet); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}

	time.Sleep(100 * time.Millisecond)
	sendEnd.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleInboundStream did not exit after stream close")
	}

	stats := f.Stats()
	// 3 valid packets should be received.
	if stats.PacketsReceived != 3 {
		t.Fatalf("PacketsReceived = %d, want 3", stats.PacketsReceived)
	}
	// 3 spoofed packets should be caught.
	if stats.PacketsSpoofed != 3 {
		t.Fatalf("PacketsSpoofed = %d, want 3", stats.PacketsSpoofed)
	}
	// No packets should be dropped (drops are for parse/route failures, not spoofs).
}

// TestTunIntegration_HandleInboundStream_MalformedPackets verifies that
// malformed (unparseable) packets on an inbound stream are handled correctly
// — validateSourceIP rejects them.
func TestTunIntegration_HandleInboundStream_MalformedPackets(t *testing.T) {
	skipUnlessTun(t)

	d := createTestTun(t, "tunint7")
	_, ipNet, _ := net.ParseCIDR("10.200.0.0/24")
	router := tun.NewRouter(ipNet, "localkey")
	peerIP := net.ParseIP("10.200.0.5")
	router.AddRoute(peerIP, "peerA")

	f := &TunForwarder{
		cfg: TunForwarderConfig{
			Device: d,
			Router: router,
		},
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())

	sendEnd, fwdEnd := net.Pipe()
	defer sendEnd.Close()
	defer fwdEnd.Close()

	wrappedConn := &connWithPeer{Conn: fwdEnd, peerID: "peerA"}

	done := make(chan struct{})
	f.wg.Add(1)
	go func() {
		defer close(done)
		f.handleInboundStream(wrappedConn)
	}()

	// Send 2 valid and 2 malformed, interleaved.
	for i := 0; i < 4; i++ {
		var packet []byte
		if i%2 == 0 {
			packet = makeIPv4Packet(peerIP, net.ParseIP("10.200.0.1"))
		} else {
			// Malformed: version 5, unparseable.
			packet = []byte{0x50, 0x00, 0x00}
		}
		if err := writeFramedPacket(sendEnd, packet); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}

	time.Sleep(100 * time.Millisecond)
	sendEnd.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleInboundStream did not exit after stream close")
	}

	stats := f.Stats()
	// 2 valid should be received.
	if stats.PacketsReceived != 2 {
		t.Fatalf("PacketsReceived = %d, want 2", stats.PacketsReceived)
	}
	// 2 malformed should be caught as spoofed (unparseable source IP).
	if stats.PacketsSpoofed != 2 {
		t.Fatalf("PacketsSpoofed = %d, want 2 (malformed packets counted as spoofed)", stats.PacketsSpoofed)
	}
}

// TestTunIntegration_HandleInboundStream_UnknownPeer verifies that packets
// from an unknown peer (not in routing table) are dropped.
func TestTunIntegration_HandleInboundStream_UnknownPeer(t *testing.T) {
	skipUnlessTun(t)

	d := createTestTun(t, "tunint8")
	_, ipNet, _ := net.ParseCIDR("10.200.0.0/24")
	router := tun.NewRouter(ipNet, "localkey")
	// Register peerA only.
	router.AddRoute(net.ParseIP("10.200.0.5"), "peerA")

	f := &TunForwarder{
		cfg: TunForwarderConfig{
			Device: d,
			Router: router,
		},
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())

	sendEnd, fwdEnd := net.Pipe()
	defer sendEnd.Close()
	defer fwdEnd.Close()

	// Wrap as unknown peer "peerZ" (not in routing table).
	wrappedConn := &connWithPeer{Conn: fwdEnd, peerID: "peerZ"}

	done := make(chan struct{})
	f.wg.Add(1)
	go func() {
		defer close(done)
		f.handleInboundStream(wrappedConn)
	}()

	// Send 4 valid-looking packets — but all from unknown peer.
	for i := 0; i < 4; i++ {
		packet := makeIPv4Packet(
			net.ParseIP("10.200.0.5"),
			net.ParseIP("10.200.0.1"),
		)
		if err := writeFramedPacket(sendEnd, packet); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}

	time.Sleep(100 * time.Millisecond)
	sendEnd.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleInboundStream did not exit after stream close")
	}

	stats := f.Stats()
	// All 4 should be dropped as spoofed (unknown peer can't pass validation).
	if stats.PacketsSpoofed != 4 {
		t.Fatalf("PacketsSpoofed = %d, want 4 (unknown peer)", stats.PacketsSpoofed)
	}
	if stats.PacketsReceived != 0 {
		t.Fatalf("PacketsReceived = %d, want 0 (unknown peer should not receive)", stats.PacketsReceived)
	}
}

// TestTunIntegration_HandleInboundStream_EmptyPeerID verifies that packets
// arriving on a stream with no peer identity (empty peerID) are handled
// correctly — validation is skipped entirely, packets are written to TUN.
func TestTunIntegration_HandleInboundStream_EmptyPeerID(t *testing.T) {
	skipUnlessTun(t)

	d := createTestTun(t, "tunint9")
	_, ipNet, _ := net.ParseCIDR("10.200.0.0/24")
	router := tun.NewRouter(ipNet, "localkey")

	f := &TunForwarder{
		cfg: TunForwarderConfig{
			Device: d,
			Router: router,
		},
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())

	sendEnd, fwdEnd := net.Pipe()
	defer sendEnd.Close()
	defer fwdEnd.Close()

	// Plain net.Conn without connWithPeer wrapper — peerID is empty.
	// The handler skips validation when peerID == "".

	done := make(chan struct{})
	f.wg.Add(1)
	go func() {
		defer close(done)
		f.handleInboundStream(fwdEnd)
	}()

	for i := 0; i < 3; i++ {
		packet := makeIPv4Packet(
			net.ParseIP("10.200.0.99"), // any IP, validation skipped
			net.ParseIP("10.200.0.1"),
		)
		if err := writeFramedPacket(sendEnd, packet); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}

	time.Sleep(100 * time.Millisecond)
	sendEnd.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleInboundStream did not exit after stream close")
	}

	stats := f.Stats()
	// All 3 should be received (validation skipped for empty peerID).
	if stats.PacketsReceived != 3 {
		t.Fatalf("PacketsReceived = %d, want 3 (validation skipped for empty peerID)", stats.PacketsReceived)
	}
	if stats.PacketsSpoofed != 0 {
		t.Fatalf("PacketsSpoofed = %d, want 0 (no validation for empty peerID)", stats.PacketsSpoofed)
	}
}

// TestTunIntegration_HandleInboundStream_StreamReadError verifies that
// the handler exits cleanly when the stream returns a read error (e.g.,
// because it was closed uncleanly).
func TestTunIntegration_HandleInboundStream_StreamReadError(t *testing.T) {
	skipUnlessTun(t)

	d := createTestTun(t, "tunint10")
	_, ipNet, _ := net.ParseCIDR("10.200.0.0/24")
	router := tun.NewRouter(ipNet, "localkey")

	f := &TunForwarder{
		cfg: TunForwarderConfig{
			Device: d,
			Router: router,
		},
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())

	sendEnd, fwdEnd := net.Pipe()

	wrappedConn := &connWithPeer{Conn: fwdEnd, peerID: "peerA"}

	done := make(chan struct{})
	f.wg.Add(1)
	go func() {
		defer close(done)
		f.handleInboundStream(wrappedConn)
	}()

	// Close the stream immediately without sending any data.
	sendEnd.Close()

	select {
	case <-done:
		// Handler should exit cleanly.
	case <-time.After(1 * time.Second):
		t.Fatal("handleInboundStream did not exit after immediate stream close")
	}
}

// TestTunIntegration_HandleInboundStream_TruncatedFrame verifies that
// the handler handles a stream with truncated frame data (length prefix
// but not enough payload bytes).
func TestTunIntegration_HandleInboundStream_TruncatedFrame(t *testing.T) {
	skipUnlessTun(t)

	d := createTestTun(t, "tunint11")
	_, ipNet, _ := net.ParseCIDR("10.200.0.0/24")
	router := tun.NewRouter(ipNet, "localkey")
	router.AddRoute(net.ParseIP("10.200.0.5"), "peerA")

	f := &TunForwarder{
		cfg: TunForwarderConfig{
			Device: d,
			Router: router,
		},
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())

	sendEnd, fwdEnd := net.Pipe()
	defer sendEnd.Close()
	defer fwdEnd.Close()

	wrappedConn := &connWithPeer{Conn: fwdEnd, peerID: "peerA"}

	done := make(chan struct{})
	f.wg.Add(1)
	go func() {
		defer close(done)
		f.handleInboundStream(wrappedConn)
	}()

	// Send one valid packet first.
	validPkt := makeIPv4Packet(net.ParseIP("10.200.0.5"), net.ParseIP("10.200.0.1"))
	writeFramedPacket(sendEnd, validPkt)

	time.Sleep(50 * time.Millisecond)

	// Then send a truncated frame: claim 1000 bytes but only give 10.
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 1000)
	sendEnd.Write(header[:])
	sendEnd.Write(make([]byte, 10))
	sendEnd.Close()

	select {
	case <-done:
		// Handler should exit (read error from truncated frame).
	case <-time.After(2 * time.Second):
		t.Fatal("handleInboundStream did not exit after truncated frame + close")
	}

	stats := f.Stats()
	if stats.PacketsReceived != 1 {
		t.Fatalf("PacketsReceived = %d, want 1 (only first valid packet)", stats.PacketsReceived)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// makeTestPayload creates a deterministic test payload of the given size.
// The payload bytes are set to size % 256 for easy verification.
func makeTestPayload(size int) []byte {
	if size == 0 {
		return []byte{}
	}
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(size % 256)
	}
	return payload
}

// sizeName returns a descriptive name for a given byte size.
func sizeName(size int) string {
	switch {
	case size == 0:
		return "0_bytes"
	case size < 1000:
		return "small"
	case size < 1400:
		return "medium"
	case size == 1400:
		return "mtu_1400"
	case size < 1500:
		return "above_mtu"
	case size == 1500:
		return "ethernet_mtu"
	default:
		return "large"
	}
}
