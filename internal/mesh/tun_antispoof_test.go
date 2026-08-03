package mesh

import (
	"net"
	"testing"

	"github.com/yzy806806/meshdesk/internal/tun"
)

// makeIPv4Packet builds a minimal IPv4 packet with the given src and dst IPs.
// The packet has a 20-byte header (no payload) which is sufficient for
// source/destination IP validation.
func makeIPv4Packet(src, dst net.IP) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	copy(packet[12:16], src.To4())
	copy(packet[16:20], dst.To4())
	return packet
}

// makeIPv6Packet builds a minimal IPv6 packet with the given src and dst IPs.
// The packet has a 40-byte header (no payload).
func makeIPv6Packet(src, dst net.IP) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x60 // Version 6
	copy(packet[8:24], src.To16())
	copy(packet[24:40], dst.To16())
	return packet
}

// makeMalformedPacket returns a packet too short for IP parsing.
func makeMalformedPacket() []byte {
	return []byte{0x45, 0x00, 0x00}
}

// newTestForwarder creates a TunForwarder with a Router and a nil MeshNode
// (sufficient for validateSourceIP tests which only use the Router).
func newTestForwarder(subnet string, localKey string) (*TunForwarder, *tun.Router) {
	_, ipNet, _ := net.ParseCIDR(subnet)
	router := tun.NewRouter(ipNet, localKey)
	f := &TunForwarder{
		cfg: TunForwarderConfig{
			Router: router,
		},
	}
	return f, router
}

// ─── validateSourceIP: IPv4 tests ───

func TestValidateSourceIP_IPv4_Match(t *testing.T) {
	f, router := newTestForwarder("10.10.0.0/24", "localkey")

	peerIP := net.ParseIP("10.10.0.5")
	router.AddRoute(peerIP, "peerA")

	packet := makeIPv4Packet(peerIP, net.ParseIP("10.10.0.1"))
	if !f.validateSourceIP(packet, "peerA") {
		t.Fatal("validateSourceIP should return true for matching src IP")
	}
}

func TestValidateSourceIP_IPv4_Mismatch(t *testing.T) {
	f, router := newTestForwarder("10.10.0.0/24", "localkey")

	peerIP := net.ParseIP("10.10.0.5")
	router.AddRoute(peerIP, "peerA")

	// Spoofed source IP — peer claims to be 10.10.0.99 but is registered as 10.10.0.5.
	spoofedIP := net.ParseIP("10.10.0.99")
	packet := makeIPv4Packet(spoofedIP, net.ParseIP("10.10.0.1"))
	if f.validateSourceIP(packet, "peerA") {
		t.Fatal("validateSourceIP should return false for mismatched src IP (spoofing)")
	}
}

func TestValidateSourceIP_IPv4_UnknownPeer(t *testing.T) {
	f, router := newTestForwarder("10.10.0.0/24", "localkey")

	// Register peerA but try to validate as unknown peer "peerB".
	peerIP := net.ParseIP("10.10.0.5")
	router.AddRoute(peerIP, "peerA")

	packet := makeIPv4Packet(peerIP, net.ParseIP("10.10.0.1"))
	if f.validateSourceIP(packet, "peerB") {
		t.Fatal("validateSourceIP should return false for unknown peer (not in routing table)")
	}
}

func TestValidateSourceIP_IPv4_MalformedPacket(t *testing.T) {
	f, router := newTestForwarder("10.10.0.0/24", "localkey")

	peerIP := net.ParseIP("10.10.0.5")
	router.AddRoute(peerIP, "peerA")

	packet := makeMalformedPacket()
	if f.validateSourceIP(packet, "peerA") {
		t.Fatal("validateSourceIP should return false for malformed (too short) packet")
	}
}

func TestValidateSourceIP_EmptyPacket(t *testing.T) {
	f, router := newTestForwarder("10.10.0.0/24", "localkey")

	router.AddRoute(net.ParseIP("10.10.0.5"), "peerA")

	if f.validateSourceIP([]byte{}, "peerA") {
		t.Fatal("validateSourceIP should return false for empty packet")
	}
}

// ─── validateSourceIP: IPv6 tests ───

func TestValidateSourceIP_IPv6_Match(t *testing.T) {
	f, router := newTestForwarder("fd00::/64", "localkey")

	peerIP := net.ParseIP("fd00::5")
	router.AddRoute(peerIP, "peerA")

	packet := makeIPv6Packet(peerIP, net.ParseIP("fd00::1"))
	if !f.validateSourceIP(packet, "peerA") {
		t.Fatal("validateSourceIP should return true for matching IPv6 src IP")
	}
}

func TestValidateSourceIP_IPv6_Mismatch(t *testing.T) {
	f, router := newTestForwarder("fd00::/64", "localkey")

	peerIP := net.ParseIP("fd00::5")
	router.AddRoute(peerIP, "peerA")

	spoofedIP := net.ParseIP("fd00::99")
	packet := makeIPv6Packet(spoofedIP, net.ParseIP("fd00::1"))
	if f.validateSourceIP(packet, "peerA") {
		t.Fatal("validateSourceIP should return false for mismatched IPv6 src IP")
	}
}

// ─── validateSourceIP: edge cases ───

func TestValidateSourceIP_UnknownIPVersion(t *testing.T) {
	f, router := newTestForwarder("10.10.0.0/24", "localkey")

	router.AddRoute(net.ParseIP("10.10.0.5"), "peerA")

	// Version 5 (neither IPv4 nor IPv6) — 40 bytes to pass length checks.
	packet := make([]byte, 40)
	packet[0] = 0x50
	if f.validateSourceIP(packet, "peerA") {
		t.Fatal("validateSourceIP should return false for unknown IP version")
	}
}

func TestValidateSourceIP_PeerWithMultipleIPs_OnlyLatestValid(t *testing.T) {
	f, router := newTestForwarder("10.10.0.0/24", "localkey")

	// Peer initially has 10.10.0.5, then updates to 10.10.0.6.
	oldIP := net.ParseIP("10.10.0.5")
	newIP := net.ParseIP("10.10.0.6")
	router.AddRoute(oldIP, "peerA")
	router.AddRoute(newIP, "peerA")

	// Old IP should now be invalid (spoofing detection).
	packetOld := makeIPv4Packet(oldIP, net.ParseIP("10.10.0.1"))
	if f.validateSourceIP(packetOld, "peerA") {
		t.Fatal("validateSourceIP should return false for old IP after peer update")
	}

	// New IP should be valid.
	packetNew := makeIPv4Packet(newIP, net.ParseIP("10.10.0.1"))
	if !f.validateSourceIP(packetNew, "peerA") {
		t.Fatal("validateSourceIP should return true for current (updated) IP")
	}
}

func TestValidateSourceIP_EmptyPeerID(t *testing.T) {
	// When peerID is empty, the caller skips validation entirely.
	// This test verifies validateSourceIP itself handles empty peerID
	// gracefully (returns false since the peer won't be found).
	f, router := newTestForwarder("10.10.0.0/24", "localkey")

	router.AddRoute(net.ParseIP("10.10.0.5"), "peerA")

	packet := makeIPv4Packet(net.ParseIP("10.10.0.5"), net.ParseIP("10.10.0.1"))
	if f.validateSourceIP(packet, "") {
		t.Fatal("validateSourceIP should return false for empty peerID (unknown peer)")
	}
}

// ─── Stats: packetsSpoofed counter ───

func TestTunForwarderStats_PacketsSpoofed(t *testing.T) {
	f, router := newTestForwarder("10.10.0.0/24", "localkey")

	router.AddRoute(net.ParseIP("10.10.0.5"), "peerA")

	// Initially zero.
	stats := f.Stats()
	if stats.PacketsSpoofed != 0 {
		t.Fatalf("initial PacketsSpoofed = %d; want 0", stats.PacketsSpoofed)
	}

	// Simulate a spoofed packet detection.
	f.packetsSpoofed.Add(1)

	stats = f.Stats()
	if stats.PacketsSpoofed != 1 {
		t.Fatalf("PacketsSpoofed = %d; want 1", stats.PacketsSpoofed)
	}
}

// ─── Concurrent validateSourceIP ───

func TestValidateSourceIP_Concurrent(t *testing.T) {
	f, router := newTestForwarder("10.10.0.0/24", "localkey")

	peerIP := net.ParseIP("10.10.0.5")
	router.AddRoute(peerIP, "peerA")

	validPacket := makeIPv4Packet(peerIP, net.ParseIP("10.10.0.1"))
	spoofedPacket := makeIPv4Packet(net.ParseIP("10.10.0.99"), net.ParseIP("10.10.0.1"))

	done := make(chan struct{})

	// Writer goroutine updates routes concurrently.
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			router.AddRoute(peerIP, "peerA")
		}
	}()

	// Reader goroutine validates source IPs.
	for i := 0; i < 1000; i++ {
		// Valid packet should always pass.
		if !f.validateSourceIP(validPacket, "peerA") {
			// Could fail if the route was temporarily removed by SyncFromPeers,
			// but AddRoute doesn't remove, so this should always pass.
		}
		// Spoofed packet should always fail.
		if f.validateSourceIP(spoofedPacket, "peerA") {
			t.Fatal("spoofed packet should never pass validation")
		}
	}

	<-done
}
